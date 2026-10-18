/*
 * End-to-end local event delivery receipt tests. Reporter, EventBus,
 * RuleEngine, bookmark persistence and token groups are real; only the WinEvt
 * API boundary is controlled so no live Event Log is changed or required.
 */
#include "telemetry_delivery_integration_tests.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winevt.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cwchar>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "event_bus.h"
#include "event_log_bookmark.h"
#include "owner_only_sd.h"
#include "reporter.h"
#include "reporter_spool.h"
#include "rule_engine.h"
#include "telemetry_delivery.h"

namespace {

#define TDI_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error("telemetry delivery integration test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

std::string Utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    TDI_CHECK(bytes > 0);
    std::string result(static_cast<size_t>(bytes), '\0');
    TDI_CHECK(WideCharToMultiByte(CP_UTF8, 0, value.data(),
        static_cast<int>(value.size()), result.data(), bytes, nullptr,
        nullptr) == bytes);
    return result;
}

struct FakeEvent {
    std::wstring channel;
    uint64_t recordId = 0;
};

class FakeWinEvt {
public:
    edr::EventLogBookmarkStore::WinEvtApi Api() {
        edr::EventLogBookmarkStore::WinEvtApi api;
        api.createBookmark = [this](const wchar_t* xml) {
            const EVT_HANDLE handle = NewHandle();
            m_bookmarks.emplace(handle, xml == nullptr ? std::wstring() : xml);
            return handle;
        };
        api.updateBookmark = [this](EVT_HANDLE bookmark, EVT_HANDLE event) {
            const auto foundEvent = m_events.find(event);
            const auto foundBookmark = m_bookmarks.find(bookmark);
            if (foundEvent == m_events.end() || foundBookmark == m_bookmarks.end())
                return false;
            foundBookmark->second = RenderXml(foundEvent->second);
            return true;
        };
        api.renderBookmark = [this](EVT_HANDLE bookmark, std::wstring& xml) {
            const auto found = m_bookmarks.find(bookmark);
            if (found == m_bookmarks.end() || found->second.empty()) return false;
            xml = found->second;
            return true;
        };
        api.eventIdentity = [this](EVT_HANDLE event, std::wstring& channel,
                                   uint64_t& recordId) {
            const auto found = m_events.find(event);
            if (found == m_events.end()) return false;
            channel = found->second.channel;
            recordId = found->second.recordId;
            return true;
        };
        api.close = [this](EVT_HANDLE handle) { m_bookmarks.erase(handle); };
        return api;
    }

    EVT_HANDLE AddEvent(uint64_t recordId) {
        const EVT_HANDLE handle = NewHandle();
        m_events.emplace(handle, FakeEvent{L"Application", recordId});
        return handle;
    }

private:
    EVT_HANDLE NewHandle() {
        return reinterpret_cast<EVT_HANDLE>(++m_nextHandle * 16u + 1u);
    }

    static std::wstring RenderXml(const FakeEvent& event) {
        return L"<BookmarkList><Bookmark Channel=\"" + event.channel +
            L"\" RecordId=\"" + std::to_wstring(event.recordId) +
            L"\" IsCurrent=\"true\"/></BookmarkList>";
    }

    uintptr_t m_nextHandle = 0x3000;
    std::map<EVT_HANDLE, FakeEvent> m_events;
    std::map<EVT_HANDLE, std::wstring> m_bookmarks;
};

class Fixture {
public:
    Fixture() {
        wchar_t temp[MAX_PATH] = {};
        TDI_CHECK(GetTempPathW(MAX_PATH, temp) != 0);
        /* Pin the owner to the token user: the bookmark store verifies
         * owner == token user and the platform default owner is the
         * Administrators group for elevated tokens. */
        std::string sdError;
        PSECURITY_DESCRIPTOR descriptor = edr::CreateOwnerOnlyDescriptor(sdError);
        TDI_CHECK(descriptor != nullptr);
        SECURITY_ATTRIBUTES attributes{};
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = descriptor;
        DWORD createError = ERROR_ALREADY_EXISTS;
        for (unsigned int attempt = 0; attempt < 128; ++attempt) {
            m_root = std::wstring(temp) + L"edr-telemetry-delivery-" +
                std::to_wstring(GetCurrentProcessId()) + L"-" +
                std::to_wstring(s_next.fetch_add(1));
            if (CreateDirectoryW(m_root.c_str(), &attributes)) {
                m_rootCreated = true;
                createError = ERROR_SUCCESS;
                break;
            }
            createError = GetLastError();
            if (createError != ERROR_ALREADY_EXISTS) break;
        }
        LocalFree(descriptor);
        TDI_CHECK(m_rootCreated);
    }

    ~Fixture() {
        if (!m_rootCreated) return;
        const std::wstring spool = m_root + L"\\spool";
        WIN32_FIND_DATAW data{};
        HANDLE find = FindFirstFileW((spool + L"\\*").c_str(), &data);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(data.cFileName, L".") == 0 ||
                    wcscmp(data.cFileName, L"..") == 0) continue;
                DeleteFileW((spool + L"\\" + data.cFileName).c_str());
            } while (FindNextFileW(find, &data));
            FindClose(find);
        }
        RemoveDirectoryW(spool.c_str());
        DeleteFileW(BookmarkPath().c_str());
        DeleteFileW(RulesPath().c_str());
        RemoveDirectoryW(m_root.c_str());
    }

    std::wstring BookmarkPath() const { return m_root + L"\\checkpoint.bin"; }
    std::wstring RulesPath() const { return m_root + L"\\rules.json"; }
    std::wstring SpoolPath() const { return m_root + L"\\spool"; }

    void WriteRules() const {
        const char json[] =
            "{\"rules\":[{\"id\":\"TDI-001\",\"severity\":\"low\","
            "\"action\":\"log\",\"match\":{\"image\":{"
            "\"eq\":\"receipt-probe.exe\"}}}]}";
        HANDLE file = CreateFileW(RulesPath().c_str(), GENERIC_WRITE, 0,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        TDI_CHECK(file != INVALID_HANDLE_VALUE);
        DWORD written = 0;
        const bool ok = WriteFile(file, json, sizeof(json) - 1, &written,
                                  nullptr) != FALSE && written == sizeof(json) - 1;
        CloseHandle(file);
        TDI_CHECK(ok);
    }

private:
    inline static std::atomic<unsigned long> s_next{1};
    std::wstring m_root;
    bool m_rootCreated = false;
};

class Receipts {
public:
    void Record(bool accepted) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_results.push_back(accepted);
        m_cv.notify_all();
    }

    bool WaitFor(size_t count) {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_cv.wait_for(lock, std::chrono::seconds(5), [&] {
            return m_results.size() >= count;
        });
    }

    bool Result(size_t index) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return index < m_results.size() && m_results[index];
    }

private:
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<bool> m_results;
};

class ReleaseBlockedPost {
public:
    ReleaseBlockedPost(std::mutex& mutex, std::condition_variable& cv,
                       bool& released)
        : m_mutex(mutex), m_cv(cv), m_released(released) {}
    ~ReleaseBlockedPost() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_released = true;
        }
        m_cv.notify_all();
    }

private:
    std::mutex& m_mutex;
    std::condition_variable& m_cv;
    bool& m_released;
};

class DeliverySink final : public edr::ISink {
public:
    DeliverySink(edr::Reporter* reporter, edr::RuleEngine* rules)
        : m_reporter(reporter), m_rules(rules) {}

    void OnEvent(const edr::Event& event) override {
        edr::DeliverTelemetryEvent(event, m_reporter, true, m_rules);
    }

private:
    edr::Reporter* m_reporter;
    edr::RuleEngine* m_rules;
};

std::shared_ptr<edr::EventLogBookmarkStore> MakeStore(
    const Fixture& fixture, const std::shared_ptr<FakeWinEvt>& fake) {
    auto store = std::make_shared<edr::EventLogBookmarkStore>(
        fixture.BookmarkPath(), L"Application", true, 16, fake->Api());
    TDI_CHECK(store->Open());
    return store;
}

edr::Event MakeEvent(uint64_t timestamp, const char* image,
                     edr::EventDisposition disposition =
                         edr::EventDisposition::ReportAndEvaluate) {
    edr::Event event;
    event.type = 1;
    event.ts100ns = timestamp;
    event.pid = static_cast<uint32_t>(timestamp);
    event.processStartTime100ns = timestamp * 10;
    event.source = "integration-test";
    event.disposition = disposition;
    event.fields[edr::field::kImage] = image;
    return event;
}

void AttachToken(edr::Event& event,
                 const std::shared_ptr<edr::EventLogBookmarkStore>& store,
                 const std::shared_ptr<FakeWinEvt>& fake,
                 uint64_t recordId) {
    edr::EventLogBookmarkStore::Token token = 0;
    TDI_CHECK(store->Capture(fake->AddEvent(recordId), token));
    edr::EventLogBookmarkTokenGroup group(store);
    TDI_CHECK(group.Add(token));
    TDI_CHECK(group.Attach(event));
}

void TestAcceptedLocalSpoolCommitsGroupedReportOnlyReceipt() {
    Fixture fixture;
    fixture.WriteRules();
    auto fake = std::make_shared<FakeWinEvt>();
    auto store = MakeStore(fixture, fake);
    std::atomic<unsigned> alerts{0};
    edr::RuleEngine rules;
    rules.LoadFromFile(Utf8(fixture.RulesPath()));
    rules.SetAlertCallback([&](const edr::Alert&) { ++alerts; });
    edr::ReporterSpoolOptions spool;
    spool.directory = Utf8(fixture.SpoolPath());
    edr::Reporter reporter("https://collector.test/ingest", "", 8,
        [](const std::string&) { return true; }, spool);
    TDI_CHECK(reporter.Start());

    DeliverySink sink(&reporter, &rules);
    edr::EventBus bus(8);
    Receipts receipts;
    edr::Event reportOnly = MakeEvent(100, "receipt-probe.exe",
        edr::EventDisposition::ReportOnly);
    edr::EventLogBookmarkStore::Token first = 0, second = 0;
    TDI_CHECK(store->Capture(fake->AddEvent(1), first));
    TDI_CHECK(store->Capture(fake->AddEvent(2), second));
    edr::EventLogBookmarkTokenGroup group(store);
    TDI_CHECK(group.Add(first));
    TDI_CHECK(group.Add(second));
    TDI_CHECK(group.Attach(reportOnly));
    reportOnly.onConsumed = [&receipts, callback = reportOnly.onConsumed](bool ok) {
        callback(ok);
        receipts.Record(ok);
    };

    edr::Event evaluated = MakeEvent(101, "receipt-probe.exe");
    AttachToken(evaluated, store, fake, 3);
    const auto evaluatedReceipt = evaluated.onConsumed;
    evaluated.onConsumed = [&receipts, callback = evaluatedReceipt](bool ok) {
        callback(ok);
        receipts.Record(ok);
    };

    bus.Start(&sink);
    TDI_CHECK(bus.Push(reportOnly));
    TDI_CHECK(bus.Push(evaluated));
    TDI_CHECK(receipts.WaitFor(2));
    bus.Stop();
    reporter.Stop();

    TDI_CHECK(receipts.Result(0) && receipts.Result(1));
    TDI_CHECK(alerts.load() == 1);
    const auto status = store->GetStatus();
    TDI_CHECK(status.state == edr::EventLogBookmarkStore::State::Ready);
    TDI_CHECK(status.pending == 0 && status.lastCommittedRecordId == 3);
    TDI_CHECK(reporter.GetSpoolStatus() == "ready");
}

void TestQueueRejectionStillEvaluatesAndBlocksLaterBookmarkCommit() {
    Fixture fixture;
    fixture.WriteRules();
    auto fake = std::make_shared<FakeWinEvt>();
    auto store = MakeStore(fixture, fake);
    std::atomic<unsigned> alerts{0};
    edr::RuleEngine rules;
    rules.LoadFromFile(Utf8(fixture.RulesPath()));
    rules.SetAlertCallback([&](const edr::Alert&) { ++alerts; });
    std::mutex postMutex;
    std::condition_variable postCv;
    bool postEntered = false;
    bool releasePost = false;
    edr::Reporter reporter("https://collector.test/ingest", "", 1,
        [&](const std::string&) {
            std::unique_lock<std::mutex> lock(postMutex);
            postEntered = true;
            postCv.notify_all();
            postCv.wait(lock, [&] { return releasePost; });
            return true;
        });
    TDI_CHECK(reporter.Start());

    DeliverySink sink(&reporter, &rules);
    edr::EventBus bus(8);
    ReleaseBlockedPost unblockOnExit(postMutex, postCv, releasePost);
    Receipts receipts;
    edr::Event first = MakeEvent(200, "receipt-probe.exe");
    AttachToken(first, store, fake, 10);
    const auto firstCallback = first.onConsumed;
    first.onConsumed = [&receipts, callback = firstCallback](bool ok) {
        callback(ok);
        receipts.Record(ok);
    };
    edr::Event rejected = MakeEvent(201, "receipt-probe.exe");
    AttachToken(rejected, store, fake, 11);
    const auto rejectedCallback = rejected.onConsumed;
    rejected.onConsumed = [&receipts, callback = rejectedCallback](bool ok) {
        callback(ok);
        receipts.Record(ok);
    };

    bus.Start(&sink);
    TDI_CHECK(bus.Push(first));
    {
        std::unique_lock<std::mutex> lock(postMutex);
        TDI_CHECK(postCv.wait_for(lock, std::chrono::seconds(5), [&] {
            return postEntered;
        }));
    }
    TDI_CHECK(receipts.WaitFor(1));
    TDI_CHECK(receipts.Result(0));
    TDI_CHECK(store->GetStatus().lastCommittedRecordId == 10);
    TDI_CHECK(bus.Push(rejected));
    TDI_CHECK(receipts.WaitFor(2));
    bus.Stop();
    {
        std::lock_guard<std::mutex> lock(postMutex);
        releasePost = true;
    }
    postCv.notify_all();
    reporter.Stop();

    TDI_CHECK(!receipts.Result(1));
    TDI_CHECK(alerts.load() == 2);
    const auto status = store->GetStatus();
    TDI_CHECK(status.state == edr::EventLogBookmarkStore::State::Gap);
    TDI_CHECK(status.lastCommittedRecordId == 10);
}

void TestThrowingRuleCallbackMakesNegativeReceiptAfterQueueAcceptance() {
    Fixture fixture;
    fixture.WriteRules();
    auto fake = std::make_shared<FakeWinEvt>();
    auto store = MakeStore(fixture, fake);
    edr::RuleEngine rules;
    rules.LoadFromFile(Utf8(fixture.RulesPath()));
    rules.SetAlertCallback([](const edr::Alert&) {
        throw std::runtime_error("simulated detection consumer failure");
    });
    edr::Reporter reporter("https://collector.test/ingest", "", 8,
        [](const std::string&) { return true; });
    TDI_CHECK(reporter.Start());
    DeliverySink sink(&reporter, &rules);
    edr::EventBus bus(4);
    Receipts receipts;
    edr::Event event = MakeEvent(300, "receipt-probe.exe");
    AttachToken(event, store, fake, 20);
    const auto sourceReceipt = event.onConsumed;
    event.onConsumed = [&receipts, callback = sourceReceipt](bool ok) {
        callback(ok);
        receipts.Record(ok);
    };

    bus.Start(&sink);
    TDI_CHECK(bus.Push(event));
    TDI_CHECK(receipts.WaitFor(1));
    bus.Stop();
    reporter.Stop();

    TDI_CHECK(!receipts.Result(0));
    TDI_CHECK(reporter.DroppedCount() == 0);
    TDI_CHECK(store->GetStatus().state == edr::EventLogBookmarkStore::State::Gap);
    TDI_CHECK(store->GetStatus().lastCommittedRecordId == 0);
}

void TestFailedReporterStartIsRetainedAsNegativeSourceReceipt() {
    Fixture fixture;
    fixture.WriteRules();
    auto fake = std::make_shared<FakeWinEvt>();
    auto store = MakeStore(fixture, fake);
    std::atomic<unsigned> alerts{0};
    edr::RuleEngine rules;
    rules.LoadFromFile(Utf8(fixture.RulesPath()));
    rules.SetAlertCallback([&](const edr::Alert&) { ++alerts; });

    /* Keep the failed, configured Reporter object attached to delivery. This
     * is the production startup path that must not turn a failed Start into a
     * null Reporter and silently accept source checkpoints. */
    edr::Reporter failedReporter("", "", 8);
    TDI_CHECK(!failedReporter.Start());
    DeliverySink sink(&failedReporter, &rules);
    edr::EventBus bus(4);
    Receipts receipts;
    edr::Event event = MakeEvent(400, "receipt-probe.exe");
    AttachToken(event, store, fake, 30);
    const auto sourceReceipt = event.onConsumed;
    event.onConsumed = [&receipts, callback = sourceReceipt](bool ok) {
        callback(ok);
        receipts.Record(ok);
    };

    bus.Start(&sink);
    TDI_CHECK(bus.Push(event));
    TDI_CHECK(receipts.WaitFor(1));
    bus.Stop();

    TDI_CHECK(!receipts.Result(0));
    TDI_CHECK(alerts.load() == 1);
    TDI_CHECK(failedReporter.DroppedCount() == 1);
    TDI_CHECK(store->GetStatus().state == edr::EventLogBookmarkStore::State::Gap);
    TDI_CHECK(store->GetStatus().lastCommittedRecordId == 0);
}

} // namespace

void RunTelemetryDeliveryIntegrationTests() {
    TestAcceptedLocalSpoolCommitsGroupedReportOnlyReceipt();
    TestQueueRejectionStillEvaluatesAndBlocksLaterBookmarkCommit();
    TestThrowingRuleCallbackMakesNegativeReceiptAfterQueueAcceptance();
    TestFailedReporterStartIsRetainedAsNegativeSourceReceipt();
}
