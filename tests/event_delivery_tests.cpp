#include <windows.h>
#include <atomic>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include "event_bus.h"

namespace {
void Check(bool value) {
    if (!value) throw std::runtime_error("event consumption acknowledgment failed");
}
class Sink final : public edr::ISink {
public:
    void OnEvent(const edr::Event&) override {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        cv.notify_all();
        cv.wait(lock, [&] { return released; });
        if (throws) throw std::runtime_error("consumer failed");
    }
    std::mutex mutex;
    std::condition_variable cv;
    bool entered = false;
    bool released = false;
    bool throws = false;
};
void Run() {
    edr::EventBus bus(1);
    std::atomic<int> lost{0}, accepted{0};
    edr::Event first;
    first.onConsumed = [&](bool ok) { Check(!ok); ++lost; };
    Check(bus.Push(first));
    edr::Event next;
    next.onConsumed = [&](bool ok) { if (ok) ++accepted; else ++lost; };
    Check(!bus.Push(next));
    Check(lost == 1 && accepted == 0);
    const auto overflowing = bus.SnapshotStats();
    Check(overflowing.capacity == 1 && overflowing.pending == 1);
    Check(overflowing.highWatermark == 1 && overflowing.inFlight == 0);
    Check(overflowing.overflowDropped == 1 && overflowing.consumerFailed == 0);
    Check(overflowing.dropped == 1 && overflowing.abandoned == 0);
    Sink sink;
    bus.Start(&sink);
    {
        std::unique_lock<std::mutex> lock(sink.mutex);
        Check(sink.cv.wait_for(lock, std::chrono::seconds(5), [&] { return sink.entered; }));
        Check(accepted == 0); // Removed from queue is not consumed yet.
        const auto busy = bus.SnapshotStats();
        Check(busy.pending == 0 && busy.inFlight == 1 && busy.consumed == 0);
        Check(busy.oldestPendingMs == 0);
        sink.released = true;
    }
    sink.cv.notify_all();
    bus.Stop();
    Check(accepted == 1 && lost == 1);
    const auto delivered = bus.SnapshotStats();
    Check(delivered.consumed == 1 && delivered.inFlight == 0);
    Check(delivered.consumerFailed == 0 && delivered.dropped == 1);

    edr::EventBus failed(2);
    Sink throwing;
    throwing.released = true;
    throwing.throws = true;
    failed.Push(next);
    failed.Start(&throwing);
    failed.Stop();
    Check(lost == 2 && accepted == 1);
    Check(failed.SnapshotStats().consumerFailed == 1);
    Check(failed.SnapshotStats().dropped == 1);

    edr::EventBus zero(0);
    Check(!zero.Push(next));
    Check(zero.Pending() == 0 && zero.DroppedCount() == 1 && lost == 3);
    Check(zero.SnapshotStats().overflowDropped == 1);
    Check(zero.SnapshotStats().highWatermark == 0);

    edr::EventBus noSink(2);
    noSink.Push(next);
    noSink.Start(nullptr);
    noSink.Stop();
    Check(lost == 4);
    Check(noSink.SnapshotStats().consumerFailed == 1);
    Check(noSink.DroppedCount() == 1);
    edr::Event callbackThrows;
    callbackThrows.onConsumed = [](bool) { throw std::runtime_error("checkpoint callback failed"); };
    edr::EventBus callbackBus(0);
    Check(!callbackBus.Push(callbackThrows)); // Callback exceptions stay contained.

    class RetrySink final : public edr::ISink {
    public:
        void OnEvent(const edr::Event&) override {
            if (++attempts == 1) throw std::runtime_error("first delivery failed");
        }
        int attempts = 0;
    } retrySink;
    edr::Event retry;
    retry.type = 1;
    retry.pid = 123;
    retry.processStartTime100ns = 133000000000000001ULL;
    retry.ts100ns = 133000000000000002ULL;
    retry.fields[edr::field::kImage] = "owned.exe";
    int retryAccepted = 0, retryFailed = 0;
    retry.onConsumed = [&](bool ok) { if (ok) ++retryAccepted; else ++retryFailed; };
    edr::EventBus retryBus(4);
    Check(retryBus.Push(retry));
    Check(retryBus.Push(retry));
    Check(retryBus.Push(retry));
    retryBus.Start(&retrySink);
    retryBus.Stop();
    Check(retrySink.attempts == 2 && retryAccepted == 2 && retryFailed == 1);
    const auto retried = retryBus.SnapshotStats();
    Check(retried.consumed == 2 && retried.deduplicated == 1);
    Check(retried.consumerFailed == 1 && retried.inFlight == 0);

    edr::EventBus abandoned(1);
    abandoned.Push(next);
    abandoned.Stop(); // Never-started queued events must receive failure.
    Check(lost == 5);
    Check(abandoned.SnapshotStats().abandoned == 1);
    Check(abandoned.DroppedCount() == 1 && abandoned.Pending() == 0);

    // Event timestamps may be untrusted or replayed; backlog uses enqueue time.
    edr::Event future;
    future.ts100ns = UINT64_MAX;
    future.onConsumed = [&](bool ok) {
        Check(!ok);
        Check(abandoned.SnapshotStats().abandoned == 2); // No mutex held in callback.
    };
    Check(abandoned.Push(future));
    Check(abandoned.SnapshotStats().oldestPendingMs < 5000);
    abandoned.Stop();
    Check(abandoned.SnapshotStats().inFlight == 0);
}
}
int main() {
    try { Run(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    std::cout << "event delivery tests passed\n";
    return 0;
}
