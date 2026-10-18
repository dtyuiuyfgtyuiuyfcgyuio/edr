/*
 * webhook_notifier_tests.cpp - Unit tests. All transports are injected:
 * no test in this suite performs real network I/O.
 */
#include "webhook_notifier_tests.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "json_lite.h"
#include "webhook_notifier.h"

namespace {

#define WH_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "webhook notifier test failed at line " +
            std::to_string(line) + ": " + expression);
}

/* Poll until pred() holds or the timeout elapses (never hangs the suite). */
template <typename Pred>
bool WaitFor(const Pred& pred, int timeoutMs) {
    for (int waited = 0; waited < timeoutMs; waited += 5) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

struct RecordedCall {
    std::string url;
    std::string contentType;
    std::string body;
    uint32_t timeoutMs = 0;
};

/* Shared state for the injected transports: records call arguments, can be
 * switched to always-fail, and can pin the worker inside the transport on a
 * gate so queue/backpressure behaviour is deterministic. */
struct TransportState {
    mutable std::mutex mutex;
    std::vector<RecordedCall> calls;

    std::atomic<bool> failAll{false};
    bool useGate = false;
    std::atomic<bool> gateOpen{false};
    std::atomic<int> entered{0};
    std::mutex gateMutex;
    std::condition_variable gateCv;

    size_t Count() const {
        std::lock_guard<std::mutex> lock(mutex);
        return calls.size();
    }
    std::vector<RecordedCall> Calls() const {
        std::lock_guard<std::mutex> lock(mutex);
        return calls;
    }
};

edr::WebhookNotifier::TransportFn MakeTransport(TransportState* state) {
    return [state](const std::string& url, const std::string& contentType,
                   const std::string& body, uint32_t timeoutMs,
                   std::string* err) -> bool {
        state->entered.fetch_add(1);
        state->gateCv.notify_all(); /* wake tests waiting for entry */
        if (state->useGate) {
            /* Bounded wait: a failed assertion must not hang the destructor
             * join (the worker stays pinned here until the gate opens). */
            std::unique_lock<std::mutex> lock(state->gateMutex);
            state->gateCv.wait_for(lock, std::chrono::milliseconds(10000),
                                   [&] { return state->gateOpen.load(); });
        }
        if (state->failAll.load()) {
            if (err != nullptr) *err = "boom (injected failure)";
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->calls.push_back({url, contentType, body, timeoutMs});
        }
        return true;
    };
}

} // namespace

void RunWebhookNotifierTests() {
    std::fprintf(stderr, "[webhook] TestBuildEnvelopeValidObject\n");
    {
        std::string envelope = edr::WebhookNotifier::BuildEnvelope(
            "{\"rule\":\"EDR-001\",\"severity\":\"high\"}");
        static const char kPrefix[] =
            "{\"kind\":\"alert\",\"source\":\"edr-agent\",\"host\":\"";
        WH_CHECK(envelope.compare(0, sizeof(kPrefix) - 1, kPrefix) == 0);
        const size_t hostStart = sizeof(kPrefix) - 1;
        const size_t hostEnd = envelope.find("\",\"ts\":\"", hostStart);
        WH_CHECK(hostEnd != std::string::npos && hostEnd > hostStart);
        /* Host must be present and unescaped-hostname shaped (non-empty). */
        WH_CHECK(!envelope.substr(hostStart, hostEnd - hostStart).empty());
        WH_CHECK(envelope.find(
                     ",\"alert\":{\"rule\":\"EDR-001\",\"severity\":\"high\"}}") ==
                 envelope.size() - strlen(
                     ",\"alert\":{\"rule\":\"EDR-001\",\"severity\":\"high\"}}"));
        /* Full JSON round-trip: envelope parses and the alert is an object. */
        jsonlite::Value parsed = jsonlite::parse(envelope);
        WH_CHECK(parsed.type == jsonlite::Type::Object);
        const jsonlite::Value* kind = parsed.find("kind");
        WH_CHECK(kind != nullptr && kind->str == "alert");
        const jsonlite::Value* source = parsed.find("source");
        WH_CHECK(source != nullptr && source->str == "edr-agent");
        const jsonlite::Value* host = parsed.find("host");
        WH_CHECK(host != nullptr && host->type == jsonlite::Type::String &&
                 !host->str.empty());
        const jsonlite::Value* ts = parsed.find("ts");
        WH_CHECK(ts != nullptr && ts->type == jsonlite::Type::String &&
                 !ts->str.empty());
        const jsonlite::Value* alert = parsed.find("alert");
        WH_CHECK(alert != nullptr && alert->type == jsonlite::Type::Object);
        const jsonlite::Value* rule = alert == nullptr ? nullptr
                                                       : alert->find("rule");
        WH_CHECK(rule != nullptr && rule->str == "EDR-001");
    }
    std::fprintf(stderr, "[webhook] TestBuildEnvelopeRawFallback\n");
    {
        /* Leading whitespace is tolerated; the object path is taken. */
        WH_CHECK(edr::WebhookNotifier::BuildEnvelope("  {\"a\":1}")
                     .find(",\"alert\":  {\"a\":1}}") != std::string::npos);
        /* Not an object (quotes/backslash/control chars/newline): goes to
         * alert_raw with correct JSON string escaping. The \x01 escape is
         * written as a separate literal so the hex escape cannot swallow the
         * following characters. */
        std::string raw = std::string("say \"ok\"\\tmp") + "\x01" + "end\nline2";
        std::string envelope = edr::WebhookNotifier::BuildEnvelope(raw);
        WH_CHECK(envelope.find("\"alert_raw\":\"") != std::string::npos);
        WH_CHECK(envelope.find("\"alert\":") == std::string::npos);
        /* Direct escape tokens: quote, backslash, control byte, newline. */
        WH_CHECK(envelope.find("\\\"") != std::string::npos);
        WH_CHECK(envelope.find("\\\\") != std::string::npos);
        WH_CHECK(envelope.find("\\u0001") != std::string::npos);
        WH_CHECK(envelope.find("\\n") != std::string::npos);
        /* Round-trip: the escaped string decodes back to the exact input. */
        jsonlite::Value parsed = jsonlite::parse(envelope);
        const jsonlite::Value* rawVal = parsed.find("alert_raw");
        WH_CHECK(rawVal != nullptr && rawVal->type == jsonlite::Type::String);
        WH_CHECK(rawVal != nullptr && rawVal->str == raw);
        /* Empty payload also takes the raw path. */
        std::string emptyEnvelope = edr::WebhookNotifier::BuildEnvelope("");
        WH_CHECK(emptyEnvelope.find("\"alert_raw\":\"\"") !=
                 std::string::npos);
    }
    std::fprintf(stderr, "[webhook] TestEnvelopeHasTimestamp\n");
    {
        std::string envelope = edr::WebhookNotifier::BuildEnvelope("{}");
        const size_t tsStart = envelope.find("\"ts\":\"");
        WH_CHECK(tsStart != std::string::npos);
        const size_t valueStart = tsStart + strlen("\"ts\":\"");
        const size_t valueEnd = envelope.find('"', valueStart);
        WH_CHECK(valueEnd != std::string::npos);
        /* ISO-8601 UTC shape "YYYY-MM-DDTHH:MM:SS.mmmZ" is 24 characters. */
        WH_CHECK(valueEnd - valueStart == 24);
        std::string ts = envelope.substr(valueStart, 24);
        WH_CHECK(ts[10] == 'T' && ts[23] == 'Z');
    }
    std::fprintf(stderr, "[webhook] TestDisabledIsSilentNoop\n");
    {
        TransportState state;
        edr::WebhookNotifier notifier(false, "http://collector.local/hook", 5,
                                      16, MakeTransport(&state));
        notifier.Notify("{\"rule\":\"X\"}");
        notifier.Notify("not json at all");
        WH_CHECK(state.Count() == 0);
        WH_CHECK(notifier.QueuedCount() == 0);
        WH_CHECK(notifier.DeliveredCount() == 0);
        WH_CHECK(notifier.DroppedCount() == 0);
        WH_CHECK(notifier.FailedCount() == 0);
    }
    std::fprintf(stderr, "[webhook] TestEmptyUrlIsSilentNoop\n");
    {
        TransportState state;
        edr::WebhookNotifier notifier(true, "", 5, 16, MakeTransport(&state));
        notifier.Notify("{\"rule\":\"X\"}");
        notifier.Notify("{\"rule\":\"Y\"}");
        WH_CHECK(state.Count() == 0);
        WH_CHECK(notifier.QueuedCount() == 0);
        WH_CHECK(notifier.DeliveredCount() == 0);
        WH_CHECK(notifier.DroppedCount() == 0);
        WH_CHECK(notifier.FailedCount() == 0);
    }
    std::fprintf(stderr, "[webhook] TestDeliveryRecordsArguments\n");
    {
        TransportState state;
        edr::WebhookNotifier notifier(true, "http://collector.local/hook", 5,
                                      16, MakeTransport(&state));
        notifier.Notify("{\"rule\":\"EDR-004\",\"severity\":\"medium\"}");
        WH_CHECK(WaitFor([&] { return notifier.DeliveredCount() == 1; },
                         5000));
        std::vector<RecordedCall> calls = state.Calls();
        WH_CHECK(calls.size() == 1);
        WH_CHECK(calls[0].url == "http://collector.local/hook");
        WH_CHECK(calls[0].contentType == "application/json");
        /* Body is the full envelope, and 5s became 5000ms on the transport. */
        WH_CHECK(calls[0].timeoutMs == 5000);
        WH_CHECK(calls[0].body.find(
                     "{\"kind\":\"alert\",\"source\":\"edr-agent\"") == 0);
        WH_CHECK(calls[0].body.find(
                     "\"alert\":{\"rule\":\"EDR-004\",\"severity\":\"medium\""
                     "}}") != std::string::npos);
        WH_CHECK(notifier.DroppedCount() == 0);
        WH_CHECK(notifier.FailedCount() == 0);
        WH_CHECK(notifier.QueuedCount() == 0);
    }
    std::fprintf(stderr, "[webhook] TestBackpressureDropsOldest\n");
    {
        /* Drop semantics (documented in webhook_notifier.h): overflow evicts
         * the OLDEST queued envelope and always admits the newest, matching
         * EventBus::Push / Reporter::Enqueue. Deterministic setup: the worker
         * is first pinned inside the transport holding marker 1 (queue now
         * empty), then 5 more alerts race into the capacity-2 queue: markers
         * 2,3,4 are evicted (dropped=3) and markers 5,6 remain queued. */
        TransportState state;
        state.useGate = true;
        edr::WebhookNotifier notifier(true, "http://collector.local/hook", 5,
                                      2, MakeTransport(&state));
        notifier.Notify("{\"marker\":1}");
        WH_CHECK(WaitFor([&] { return state.entered.load() >= 1; }, 5000));
        for (int i = 2; i <= 6; ++i) {
            notifier.Notify("{\"marker\":" + std::to_string(i) + "}");
        }
        WH_CHECK(notifier.DroppedCount() == 3);
        WH_CHECK(notifier.QueuedCount() == 2);
        WH_CHECK(notifier.DeliveredCount() == 0);
        /* Set the flag under gateMutex so the pinned worker cannot miss the
         * wakeup (its predicate check happens under the same mutex). */
        {
            std::lock_guard<std::mutex> lock(state.gateMutex);
            state.gateOpen.store(true);
        }
        state.gateCv.notify_all();
        /* The pinned marker 1 plus the two newest (5,6) get delivered. */
        WH_CHECK(WaitFor([&] { return notifier.DeliveredCount() == 3; },
                         5000));
        std::vector<RecordedCall> calls = state.Calls();
        WH_CHECK(calls.size() == 3);
        bool saw1 = false, saw5 = false, saw6 = false, sawStale = false;
        for (const RecordedCall& call : calls) {
            if (call.body.find("\"marker\":1}") != std::string::npos) saw1 = true;
            if (call.body.find("\"marker\":5}") != std::string::npos) saw5 = true;
            if (call.body.find("\"marker\":6}") != std::string::npos) saw6 = true;
            if (call.body.find("\"marker\":2}") != std::string::npos ||
                call.body.find("\"marker\":3}") != std::string::npos ||
                call.body.find("\"marker\":4}") != std::string::npos) {
                sawStale = true;
            }
        }
        WH_CHECK(saw1 && saw5 && saw6 && !sawStale);
        WH_CHECK(notifier.FailedCount() == 0);
    }
    std::fprintf(stderr, "[webhook] TestFailureCountingAndNoPoisoning\n");
    {
        /* Transport always fails: counters go up, nothing is thrown, the
         * queue drains, and later alerts are still accepted and consumed
         * (no poisoning). Reaching the final checks proves Notify and the
         * worker survived the failures. */
        TransportState state;
        state.failAll.store(true);
        edr::WebhookNotifier notifier(true, "http://collector.local/hook", 5,
                                      16, MakeTransport(&state));
        notifier.Notify("{\"marker\":1}");
        notifier.Notify("{\"marker\":2}");
        WH_CHECK(WaitFor([&] { return notifier.FailedCount() == 2; }, 5000));
        WH_CHECK(notifier.DeliveredCount() == 0);
        WH_CHECK(notifier.QueuedCount() == 0);
        notifier.Notify("{\"marker\":3}");
        WH_CHECK(WaitFor([&] { return notifier.FailedCount() == 3; }, 5000));
        WH_CHECK(notifier.DeliveredCount() == 0);
        WH_CHECK(notifier.QueuedCount() == 0);
    }
    std::fprintf(stderr, "[webhook] TestDestructorFlushesQueue\n");
    {
        /* Declared destructor semantics: remaining queued envelopes are
         * flushed before the worker exits (bounded drain), so an instant
         * transport observes every undropped notification. */
        TransportState state;
        {
            edr::WebhookNotifier notifier(true, "http://collector.local/hook",
                                          5, 16, MakeTransport(&state));
            notifier.Notify("{\"marker\":1}");
            notifier.Notify("{\"marker\":2}");
            notifier.Notify("{\"marker\":3}");
            /* Destroy immediately; no waiting for the worker first. */
        }
        WH_CHECK(state.Count() == 3);
        std::vector<RecordedCall> calls = state.Calls();
        bool saw1 = false, saw2 = false, saw3 = false;
        for (const RecordedCall& call : calls) {
            if (call.body.find("\"marker\":1}") != std::string::npos) saw1 = true;
            if (call.body.find("\"marker\":2}") != std::string::npos) saw2 = true;
            if (call.body.find("\"marker\":3}") != std::string::npos) saw3 = true;
        }
        WH_CHECK(saw1 && saw2 && saw3);
    }
    std::fprintf(stderr, "[webhook] all passed\n");
}
