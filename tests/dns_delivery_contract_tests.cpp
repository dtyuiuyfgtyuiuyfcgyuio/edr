#include "doh_abuse_detector.h"
#include "edr_event.h"
#include "event_bus.h"

#include <windows.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr uint64_t kTicksPerMillisecond = 10000ULL;
uint64_t gProcessStartTime100ns = 0;

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error("DNS delivery contract failed at line " +
                                 std::to_string(line) + ": " + expression);
    }
}

#define DNS_CHECK(condition) Check((condition), #condition, __LINE__)

uint64_t Now100ns() {
    FILETIME now{};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

std::string Field(const edr::Event& event, const char* name) {
    const auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

edr::Event Dns(uint64_t timestamp, const std::string& source,
               const std::string& endpoint, const char* phase,
               const char* eventId, edr::EventDisposition disposition) {
    edr::Event event;
    event.type = EDR_EVT_DNS_QUERY;
    event.ts100ns = timestamp;
    event.pid = 4812;
    event.processStartTime100ns = gProcessStartTime100ns;
    event.source = source;
    event.disposition = disposition;
    event.fields[edr::field::kType] = "DNS_QUERY";
    event.fields[edr::field::kSource] = source;
    event.fields[edr::field::kEndpointId] = endpoint;
    event.fields[edr::field::kImage] = "C:\\Temp\\resolver-client.exe";
    event.fields[edr::field::kDnsQueryName] = "dns.google";
    event.fields[edr::field::kDnsQueryType] = "A";
    event.fields[edr::field::kDnsServerIp] = "8.8.8.8";
    event.fields[edr::field::kTargetHost] = "dns.google";
    if (phase != nullptr) event.fields["dns_phase"] = phase;
    if (eventId != nullptr) event.fields["dns_event_id"] = eventId;
    return event;
}

edr::Event FileCreate(uint64_t timestamp) {
    edr::Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.ts100ns = timestamp;
    event.pid = 4812;
    event.processStartTime100ns = gProcessStartTime100ns;
    event.source = "sysmon";
    event.fields[edr::field::kType] = "FILE_CREATE";
    event.fields[edr::field::kSource] = "sysmon";
    event.fields[edr::field::kEndpointId] = "host-a";
    event.fields[edr::field::kFilePath] = "C:\\Temp\\same.tmp";
    return event;
}

struct Delivery {
    uint16_t type = 0;
    edr::EventDisposition disposition = edr::EventDisposition::ReportAndEvaluate;
    std::string source;
    std::string endpoint;
    std::string phase;
    std::string queryCount;
    std::string score;
};

class DetectorSink final : public edr::ISink {
public:
    void OnEvent(const edr::Event& original) override {
        edr::Event enriched(original);
        detector.Enrich(enriched);

        Delivery delivery;
        delivery.type = original.type;
        delivery.disposition = original.disposition;
        delivery.source = original.source;
        delivery.endpoint = Field(original, edr::field::kEndpointId);
        delivery.phase = Field(original, "dns_phase");
        delivery.queryCount = Field(enriched, edr::field::kDohAbuseQueryCount);
        delivery.score = Field(enriched, edr::field::kDohAbuseScore);
        {
            std::lock_guard<std::mutex> lock(mutex);
            deliveries.push_back(std::move(delivery));
        }
        condition.notify_all();
    }

    edr::DohAbuseDetector detector{true, 300, 64, 3};
    std::mutex mutex;
    std::condition_variable condition;
    std::vector<Delivery> deliveries;
};

void TestDnsLifecycleAndRepeatedQueryDelivery() {
    DetectorSink sink;
    edr::EventBus bus(32);
    bus.Start(&sink);

    const uint64_t base = Now100ns();
    gProcessStartTime100ns = base - 100 * kTicksPerMillisecond;
    std::vector<edr::Event> input;
    for (uint32_t pair = 0; pair < 3; ++pair) {
        const uint64_t timestamp = base + pair * 10 * kTicksPerMillisecond;
        input.push_back(Dns(timestamp, "dns_etw", "host-a", "started", "3009",
                            edr::EventDisposition::ReportOnly));
        input.push_back(Dns(timestamp + kTicksPerMillisecond, "dns_etw", "host-a",
                            "completed", "3008",
                            edr::EventDisposition::ReportAndEvaluate));
    }

    // DNS source and endpoint scopes are distinct semantic observations even
    // when the process and query contents match inside the dedup interval.
    input.push_back(Dns(base + 40 * kTicksPerMillisecond, "dns_sysmon", "host-a",
                        "completed", "3008", edr::EventDisposition::ReportAndEvaluate));
    input.push_back(Dns(base + 50 * kTicksPerMillisecond, "dns_etw", "host-b",
                        "completed", "3008", edr::EventDisposition::ReportAndEvaluate));

    // Preserve semantic de-duplication for event types where repeated identical
    // observations are not separate DNS query samples.
    input.push_back(FileCreate(base + 60 * kTicksPerMillisecond));
    input.push_back(FileCreate(base + 70 * kTicksPerMillisecond));

    std::mutex ackMutex;
    std::condition_variable ackCondition;
    size_t acknowledged = 0;
    bool acknowledgementsAccepted = true;
    for (edr::Event& event : input) {
        event.onConsumed = [&](bool accepted) {
            {
                std::lock_guard<std::mutex> lock(ackMutex);
                acknowledgementsAccepted = acknowledgementsAccepted && accepted;
                ++acknowledged;
            }
            ackCondition.notify_one();
        };
        DNS_CHECK(bus.Push(event));
    }

    bool allAcknowledged = false;
    {
        std::unique_lock<std::mutex> lock(ackMutex);
        allAcknowledged = ackCondition.wait_for(
            lock, std::chrono::seconds(10), [&] { return acknowledged == input.size(); });
    }
    bus.Stop(); // Drains queued work before returning.
    DNS_CHECK(allAcknowledged);
    DNS_CHECK(acknowledgementsAccepted);
    DNS_CHECK(bus.SnapshotStats().consumerFailed == 0);

    std::vector<Delivery> delivered;
    {
        std::lock_guard<std::mutex> lock(sink.mutex);
        delivered = sink.deliveries;
    }

    std::vector<Delivery> primary;
    for (const Delivery& delivery : delivered) {
        if (delivery.type == EDR_EVT_DNS_QUERY && delivery.endpoint == "host-a" &&
            delivery.source == "dns_etw") {
            primary.push_back(delivery);
        }
    }
    DNS_CHECK(primary.size() == 6);
    for (size_t pair = 0; pair < 3; ++pair) {
        const Delivery& started = primary[pair * 2];
        const Delivery& completed = primary[pair * 2 + 1];
        DNS_CHECK(started.disposition == edr::EventDisposition::ReportOnly);
        DNS_CHECK(started.phase == "started");
        DNS_CHECK(started.queryCount.empty());
        DNS_CHECK(completed.disposition == edr::EventDisposition::ReportAndEvaluate);
        DNS_CHECK(completed.phase == "completed");
        DNS_CHECK(completed.queryCount == std::to_string(pair + 1));
    }
    DNS_CHECK(primary.back().score == "80");

    size_t sourceSeparated = 0;
    size_t endpointSeparated = 0;
    size_t fileCreates = 0;
    for (const Delivery& delivery : delivered) {
        if (delivery.type == EDR_EVT_DNS_QUERY && delivery.source == "dns_sysmon") {
            ++sourceSeparated;
            DNS_CHECK(delivery.queryCount == "1");
        }
        if (delivery.type == EDR_EVT_DNS_QUERY && delivery.endpoint == "host-b") {
            ++endpointSeparated;
            DNS_CHECK(delivery.queryCount == "1");
        }
        if (delivery.type == EDR_EVT_FILE_CREATE) ++fileCreates;
    }
    DNS_CHECK(sourceSeparated == 1);
    DNS_CHECK(endpointSeparated == 1);
    DNS_CHECK(fileCreates == 1);
    DNS_CHECK(bus.SnapshotStats().deduplicated >= 1);
}

} // namespace

int main() {
    try {
        TestDnsLifecycleAndRepeatedQueryDelivery();
        std::cout << "DNS delivery contract passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
