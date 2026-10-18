#include "reporter_delivery_tests.h"

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include "reporter.h"

namespace {

#define RD_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond) {
        throw std::runtime_error("reporter delivery test failed at line " +
                                 std::to_string(line) + ": " + expr);
    }
}

template <typename Predicate>
void WaitFor(std::condition_variable& cv, std::unique_lock<std::mutex>& lock,
             Predicate predicate) {
    RD_CHECK(cv.wait_for(lock, std::chrono::seconds(5), predicate));
}

void TestReporterOverflowDuringSuccessfulPost() {
    std::mutex mutex;
    std::condition_variable cv;
    bool releaseA = false;
    std::vector<std::string> sent;
    edr::Reporter reporter("", "", 2, [&](const std::string& body) {
        std::unique_lock<std::mutex> lock(mutex);
        sent.push_back(body);
        cv.notify_all();
        if (body == "A") {
            if (!cv.wait_for(lock, std::chrono::seconds(5),
                             [&] { return releaseA; })) {
                return false;
            }
        }
        return true;
    });

    reporter.Enqueue("A");
    RD_CHECK(reporter.Start());
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return !sent.empty(); });
        RD_CHECK(sent[0] == "A");
    }
    reporter.Enqueue("B");
    reporter.Enqueue("C");
    RD_CHECK(reporter.DroppedCount() == 1);
    RD_CHECK(reporter.QueuedCount() == 2);
    {
        std::lock_guard<std::mutex> lock(mutex);
        releaseA = true;
    }
    cv.notify_all();
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return sent.size() >= 2; });
        RD_CHECK(sent[1] == "C");
    }
    reporter.Stop();
    RD_CHECK(reporter.QueuedCount() == 0);
    RD_CHECK(reporter.DroppedCount() == 1);
}

void TestReporterFailureRetriesSameIdentity() {
    std::mutex mutex;
    std::condition_variable cv;
    bool releaseFirstA = false;
    std::vector<std::string> sent;
    edr::Reporter reporter("", "", 2, [&](const std::string& body) {
        std::unique_lock<std::mutex> lock(mutex);
        sent.push_back(body);
        cv.notify_all();
        if (body == "A" && sent.size() == 1) {
            if (!cv.wait_for(lock, std::chrono::seconds(5),
                             [&] { return releaseFirstA; })) {
                return false;
            }
            return false;
        }
        return true;
    });

    reporter.Enqueue("A");
    RD_CHECK(reporter.Start());
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return !sent.empty(); });
        RD_CHECK(sent[0] == "A");
    }
    reporter.Enqueue("B");
    reporter.Enqueue("C");
    RD_CHECK(reporter.QueuedCount() == 2);
    RD_CHECK(reporter.DroppedCount() == 1);
    {
        std::lock_guard<std::mutex> lock(mutex);
        releaseFirstA = true;
    }
    cv.notify_all();
    {
        std::unique_lock<std::mutex> lock(mutex);
        WaitFor(cv, lock, [&] { return sent.size() >= 3; });
        RD_CHECK(sent[1] == "A");
        RD_CHECK(sent[2] == "C");
    }
    reporter.Stop();
    RD_CHECK(reporter.QueuedCount() == 0);
    RD_CHECK(reporter.DroppedCount() == 1);
}

void TestReporterCapacityBoundariesAndStop() {
    {
        edr::Reporter reporter("", "", 3, [](const std::string&) {
            return true;
        });
        RD_CHECK(reporter.QueuedCount() == 0);
        RD_CHECK(reporter.DroppedCount() == 0);
    }
    {
        edr::Reporter reporter("", "", 0, [](const std::string&) {
            return true;
        });
        reporter.Enqueue("discarded");
        RD_CHECK(reporter.QueuedCount() == 0);
        RD_CHECK(reporter.DroppedCount() == 1);
    }
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool releaseA = false;
        bool entered = false;
        edr::Reporter reporter("", "", 1, [&](const std::string& body) {
            std::unique_lock<std::mutex> lock(mutex);
            RD_CHECK(body == "A");
            entered = true;
            cv.notify_all();
            if (!cv.wait_for(lock, std::chrono::seconds(5),
                             [&] { return releaseA; })) {
                return false;
            }
            return true;
        });
        reporter.Enqueue("A");
        RD_CHECK(reporter.Start());
        {
            std::unique_lock<std::mutex> lock(mutex);
            WaitFor(cv, lock, [&] { return entered; });
        }
        reporter.Enqueue("B");
        RD_CHECK(reporter.QueuedCount() == 1);
        RD_CHECK(reporter.DroppedCount() == 1);
        {
            std::lock_guard<std::mutex> lock(mutex);
            releaseA = true;
        }
        cv.notify_all();
        reporter.Stop();
        RD_CHECK(reporter.QueuedCount() == 0);
        RD_CHECK(reporter.DroppedCount() == 1);
    }
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool releaseA = false;
        bool entered = false;
        edr::Reporter reporter("", "", 2, [&](const std::string& body) {
            std::unique_lock<std::mutex> lock(mutex);
            RD_CHECK(body == "A");
            entered = true;
            cv.notify_all();
            if (!cv.wait_for(lock, std::chrono::seconds(5),
                             [&] { return releaseA; })) {
                return false;
            }
            return false;
        });
        reporter.Enqueue("A");
        RD_CHECK(reporter.Start());
        {
            std::unique_lock<std::mutex> lock(mutex);
            WaitFor(cv, lock, [&] { return entered; });
        }
        std::thread stopper([&] { reporter.Stop(); });
        for (unsigned attempt = 0; attempt < 500 &&
             reporter.GetRuntimeState() != "stopping"; ++attempt) Sleep(1);
        RD_CHECK(reporter.GetRuntimeState() == "stopping");
        RD_CHECK(!reporter.Enqueue("B"));
        {
            std::lock_guard<std::mutex> lock(mutex);
            releaseA = true;
        }
        cv.notify_all();
        stopper.join();
        RD_CHECK(reporter.GetRuntimeState() == "stopped");
        RD_CHECK(reporter.QueuedCount() == 1);
        RD_CHECK(reporter.DroppedCount() == 1);
    }
}

void TestReporterDoesNotAcceptAfterFailedStartOrStop() {
    edr::Reporter failedStart("", "", 2);
    RD_CHECK(!failedStart.Start());
    RD_CHECK(failedStart.GetRuntimeState() == "start_failed");
    RD_CHECK(!failedStart.Enqueue("must-not-be-queued-after-failed-start"));
    RD_CHECK(failedStart.QueuedCount() == 0);

    edr::Reporter stopped("https://example.invalid/ingest", "", 2,
                          [](const std::string&) { return true; });
    RD_CHECK(stopped.Start());
    RD_CHECK(stopped.GetRuntimeState() == "started");
    stopped.Stop();
    RD_CHECK(stopped.GetRuntimeState() == "stopped");
    RD_CHECK(!stopped.Enqueue("must-not-be-queued-after-stop"));
    RD_CHECK(stopped.QueuedCount() == 0);
}

void TestEventReporterUrlPreservesQueryAndOnlyRewritesIngestPath() {
    RD_CHECK(edr::EventReporterUrl("https://collector.test/ingest") ==
             "https://collector.test/ingest/events");
    RD_CHECK(edr::EventReporterUrl(
                 "https://collector.test/ingest?tenant=a%2Fb&mode=fast") ==
             "https://collector.test/ingest/events?tenant=a%2Fb&mode=fast");
    RD_CHECK(edr::EventReporterUrl("https://collector.test/api/v3/events") ==
             "https://collector.test/api/v3/events");
    RD_CHECK(edr::EventReporterUrl("https://collector.test/ingest%23archive") ==
             "https://collector.test/ingest%23archive");
}

} // namespace

void RunReporterDeliveryTests() {
    std::fprintf(stderr, "[reporter_delivery] TestReporterOverflowDuringSuccessfulPost\n");
    TestReporterOverflowDuringSuccessfulPost();
    std::fprintf(stderr, "[reporter_delivery] TestReporterFailureRetriesSameIdentity\n");
    TestReporterFailureRetriesSameIdentity();
    std::fprintf(stderr, "[reporter_delivery] TestReporterCapacityBoundariesAndStop\n");
    TestReporterCapacityBoundariesAndStop();
    std::fprintf(stderr, "[reporter_delivery] TestReporterDoesNotAcceptAfterFailedStartOrStop\n");
    TestReporterDoesNotAcceptAfterFailedStartOrStop();
    std::fprintf(stderr, "[reporter_delivery] TestEventReporterUrlPreservesQueryAndOnlyRewritesIngestPath\n");
    TestEventReporterUrlPreservesQueryAndOnlyRewritesIngestPath();
}
