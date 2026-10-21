/* Syslog lifecycle and loss accounting. All native traffic stays on loopback. */
#include <winsock2.h>
#include <ws2tcpip.h>

#include "syslog_forwarder.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
#define CHECK(condition) Check((condition), #condition, __LINE__)
void Check(bool condition, const char* expression, int line) {
    if (!condition) throw std::runtime_error("syslog line " +
        std::to_string(line) + ": " + expression);
}

void TestInvalidDestinationFailsStart() {
    edr::SyslogForwarder forwarder("invalid host !", 514, 16, "test");
    const bool started = forwarder.Start();
    forwarder.Stop();
    CHECK(!started);
}

#ifndef SYSLOG_BASELINE_RED
using Forwarder = edr::SyslogForwarder;

void CheckAccounting(const Forwarder::Stats& stats) {
    CHECK(stats.enqueued == stats.sent + stats.failed + stats.dropped +
          stats.pending + stats.inflight);
    CHECK(stats.pending + stats.inflight <= stats.capacity);
    CHECK(stats.inflight <= 1);
}

struct TransportState {
    std::mutex mutex;
    std::condition_variable cv;
    bool initializeOk = true;
    bool blockInitialize = false;
    bool initializeEntered = false;
    bool blockSend = false;
    bool sendOk = true;
    unsigned initialized = 0;
    unsigned shutdowns = 0;
    std::vector<std::string> datagrams;
};

class ControlledTransport final : public Forwarder::Transport {
public:
    explicit ControlledTransport(std::shared_ptr<TransportState> state)
        : m_state(std::move(state)) {}
    bool Initialize(const std::string&, uint16_t, int& error) noexcept override {
        std::unique_lock<std::mutex> lock(m_state->mutex);
        ++m_state->initialized;
        m_state->initializeEntered = true;
        m_state->cv.notify_all();
        if (!m_state->cv.wait_for(lock, std::chrono::seconds(5), [&] {
            return !m_state->blockInitialize;
        })) { error = WSAETIMEDOUT; return false; }
        error = m_state->initializeOk ? 0 : WSASYSNOTREADY;
        return m_state->initializeOk;
    }
    bool Send(const std::string& datagram, int& error) noexcept override {
        std::unique_lock<std::mutex> lock(m_state->mutex);
        m_state->datagrams.push_back(datagram);
        m_state->cv.notify_all();
        if (!m_state->cv.wait_for(lock, std::chrono::seconds(5), [&] {
            return !m_state->blockSend;
        })) { error = WSAETIMEDOUT; return false; }
        error = m_state->sendOk ? 0 : WSAEACCES;
        return m_state->sendOk;
    }
    void Shutdown() noexcept override {
        std::lock_guard<std::mutex> lock(m_state->mutex);
        ++m_state->shutdowns;
    }
private:
    std::shared_ptr<TransportState> m_state;
};

std::unique_ptr<Forwarder::Transport> Transport(
    const std::shared_ptr<TransportState>& state) {
    return std::make_unique<ControlledTransport>(state);
}
void WaitForSend(const std::shared_ptr<TransportState>& state, size_t count) {
    std::unique_lock<std::mutex> lock(state->mutex);
    CHECK(state->cv.wait_for(lock, std::chrono::seconds(5), [&] {
        return state->datagrams.size() >= count;
    }));
}
struct ReleaseOnExit {
    std::shared_ptr<TransportState> state;
    ~ReleaseOnExit() {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->blockSend = false;
        state->blockInitialize = false;
        state->cv.notify_all();
    }
};

void TestInitializationFailureIsSynchronousAndRetryable() {
    auto state = std::make_shared<TransportState>();
    state->initializeOk = false;
    Forwarder forwarder("127.0.0.1", 514, 16, "test", 2, Transport(state));
    CHECK(!forwarder.Start());
    auto stats = forwarder.GetStatsSnapshot();
    CHECK(stats.state == "start_failed" && !stats.running);
    CHECK(stats.startFailures == 1 && stats.lastError == WSASYSNOTREADY);
    CHECK(!forwarder.Enqueue("high", "EDR-001", "rejected"));
    CHECK(forwarder.GetStatsSnapshot().rejected == 1);
    forwarder.Stop();
    CHECK(forwarder.GetStatsSnapshot().state == "start_failed");
    state->initializeOk = true;
    CHECK(forwarder.Start());
    CHECK(forwarder.Enqueue("high", "EDR-001", "accepted"));
    forwarder.Stop();
    stats = forwarder.GetStatsSnapshot();
    CHECK(stats.state == "stopped" && stats.sent == 1 && !stats.running);
    CHECK(stats.startFailures == 1 && stats.lastError == 0);
    CheckAccounting(stats);
}

void TestStartingRejectsUntilInitializationCompletes() {
    auto state = std::make_shared<TransportState>();
    state->blockInitialize = true;
    Forwarder forwarder("127.0.0.1", 514, 16, "test", 2, Transport(state));
    ReleaseOnExit release{state};
    bool started = false;
    std::thread starter([&] { started = forwarder.Start(); });
    {
        std::unique_lock<std::mutex> lock(state->mutex);
        const bool entered = state->cv.wait_for(lock, std::chrono::seconds(5), [&] {
            return state->initializeEntered;
        });
        if (!entered) { state->blockInitialize = false; state->cv.notify_all(); }
    }
    auto stats = forwarder.GetStatsSnapshot();
    const bool rejected = !forwarder.Enqueue("low", "EDR-001", "starting");
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->blockInitialize = false;
        state->cv.notify_all();
    }
    starter.join();
    CHECK(stats.state == "starting" && !stats.running);
    CHECK(rejected && started);
    forwarder.Stop();
    CHECK(forwarder.GetStatsSnapshot().rejected == 1);
}

void TestDuplicateStartStopAndRestartPreserveCounters() {
    auto state = std::make_shared<TransportState>();
    Forwarder forwarder("127.0.0.1", 514, 16, "test", 2, Transport(state));
    CHECK(!forwarder.Enqueue("low", "EDR-001", "before-start"));
    CHECK(forwarder.GetStatsSnapshot().state == "not_started");
    CHECK(forwarder.Start());
    CHECK(forwarder.Start());
    CHECK(state->initialized == 1);
    CHECK(forwarder.Enqueue("medium", "EDR-001", "first"));
    forwarder.Stop();
    forwarder.Stop();
    CHECK(!forwarder.Enqueue("low", "EDR-001", "after-stop"));
    CHECK(forwarder.Start());
    CHECK(forwarder.Enqueue("critical", "EDR-002", "second"));
    forwarder.Stop();
    const auto stats = forwarder.GetStatsSnapshot();
    CHECK(stats.sent == 2 && stats.enqueued == 2 && stats.rejected == 2);
    CHECK(state->initialized == 2 && state->shutdowns == 2);
    CheckAccounting(stats);
}

void TestZeroCapacityRejectsWithoutQueueAccess() {
    auto state = std::make_shared<TransportState>();
    Forwarder forwarder("127.0.0.1", 514, 16, "test", 0, Transport(state));
    CHECK(forwarder.Start());
    CHECK(!forwarder.Enqueue("high", "EDR-001", "zero"));
    forwarder.Stop();
    const auto stats = forwarder.GetStatsSnapshot();
    CHECK(stats.rejected == 1 && stats.enqueued == 0 && stats.dropped == 0);
    CHECK(state->datagrams.empty());
    CheckAccounting(stats);
}

void TestOverflowDropsOldestPendingAndStopDrains() {
    auto state = std::make_shared<TransportState>();
    state->blockSend = true;
    Forwarder forwarder("127.0.0.1", 514, 16, "test", 3, Transport(state));
    ReleaseOnExit release{state};
    CHECK(forwarder.Start());
    CHECK(forwarder.Enqueue("high", "EDR-001", "first"));
    WaitForSend(state, 1);
    CHECK(forwarder.Enqueue("high", "EDR-002", "oldest-pending"));
    CHECK(forwarder.Enqueue("high", "EDR-003", "retained-pending"));
    CHECK(forwarder.Enqueue("high", "EDR-004", "newest-pending"));
    auto stats = forwarder.GetStatsSnapshot();
    CHECK(stats.inflight == 1 && stats.pending == 2 && stats.dropped == 1);
    CHECK(stats.enqueued == 4);
    CheckAccounting(stats);
    std::thread stopper([&] { forwarder.Stop(); });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (forwarder.GetStatsSnapshot().state != "stopping" &&
           std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
    stats = forwarder.GetStatsSnapshot();
    const bool rejected = !forwarder.Enqueue("high", "EDR-005", "stopping");
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->blockSend = false;
        state->cv.notify_all();
    }
    stopper.join();
    CHECK(stats.state == "stopping" && stats.running && rejected);
    stats = forwarder.GetStatsSnapshot();
    CHECK(stats.sent == 3 && stats.rejected == 1 && stats.dropped == 1);
    CHECK(stats.pending == 0 && stats.inflight == 0 && !stats.running);
    CHECK(state->datagrams.size() == 3);
    CHECK(state->datagrams[1].find("retained-pending") != std::string::npos);
    CHECK(state->datagrams[2].find("newest-pending") != std::string::npos);
    CheckAccounting(stats);
}

void TestInFlightAtCapacityRejectsNewAndRecordsSendFailure() {
    auto state = std::make_shared<TransportState>();
    state->blockSend = true;
    state->sendOk = false;
    Forwarder forwarder("127.0.0.1", 514, 16, "test", 1, Transport(state));
    ReleaseOnExit release{state};
    CHECK(forwarder.Start());
    CHECK(forwarder.Enqueue("high", "EDR-001", "failing"));
    WaitForSend(state, 1);
    CHECK(!forwarder.Enqueue("high", "EDR-002", "rejected"));
    auto stats = forwarder.GetStatsSnapshot();
    CHECK(stats.inflight == 1 && stats.pending == 0 && stats.rejected == 1);
    CheckAccounting(stats);
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->blockSend = false;
        state->cv.notify_all();
    }
    forwarder.Stop();
    stats = forwarder.GetStatsSnapshot();
    CHECK(stats.failed == 1 && stats.sent == 0 && stats.lastError == WSAEACCES);
    CheckAccounting(stats);
}

void TestConcurrentSnapshotsRemainConsistent() {
    auto state = std::make_shared<TransportState>();
    Forwarder forwarder("127.0.0.1", 514, 16, "test", 8, Transport(state));
    CHECK(forwarder.Start());
    std::atomic<bool> done{false};
    std::atomic<bool> consistent{true};
    std::thread observer([&] {
        while (!done.load()) {
            const auto stats = forwarder.GetStatsSnapshot();
            if (stats.enqueued != stats.sent + stats.failed + stats.dropped +
                stats.pending + stats.inflight ||
                stats.pending + stats.inflight > stats.capacity)
                consistent.store(false);
        }
    });
    std::vector<std::thread> producers;
    for (int i = 0; i < 4; ++i) {
        producers.emplace_back([&] {
            for (int j = 0; j < 500; ++j)
                forwarder.Enqueue("high", "EDR-001", "concurrent");
        });
    }
    for (auto& producer : producers) producer.join();
    forwarder.Stop();
    done.store(true);
    observer.join();
    const auto stats = forwarder.GetStatsSnapshot();
    CHECK(consistent.load());
    CHECK(stats.enqueued + stats.rejected == 2000);
    CHECK(stats.pending == 0 && stats.inflight == 0 && stats.failed == 0);
    CheckAccounting(stats);
}

class LoopbackReceiver {
public:
    LoopbackReceiver() {
        WSADATA data{};
        CHECK(WSAStartup(MAKEWORD(2, 2), &data) == 0);
        m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        CHECK(m_socket != INVALID_SOCKET);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(m_socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        int length = sizeof(address);
        CHECK(getsockname(m_socket, reinterpret_cast<sockaddr*>(&address), &length) == 0);
        m_port = ntohs(address.sin_port);
        DWORD timeout = 5000;
        CHECK(setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO,
                        reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0);
    }
    ~LoopbackReceiver() { closesocket(m_socket); WSACleanup(); }
    uint16_t Port() const { return m_port; }
    std::string Receive() {
        char data[16384]{};
        const int length = recvfrom(m_socket, data, sizeof(data), 0, nullptr, nullptr);
        CHECK(length > 0);
        return std::string(data, static_cast<size_t>(length));
    }
private:
    SOCKET m_socket = INVALID_SOCKET;
    uint16_t m_port = 0;
};

void TestNativeLoopbackDatagramAndCounters() {
    LoopbackReceiver receiver;
    Forwarder forwarder("127.0.0.1", receiver.Port(), 16, "test", 4);
    CHECK(forwarder.Start());
    CHECK(forwarder.Enqueue("high", "EDR-123", "loopback-payload\nnext"));
    const auto datagram = receiver.Receive();
    forwarder.Stop();
    CHECK(datagram.rfind("<131>1 ", 0) == 0);
    CHECK(datagram.find(" test edr-agent - EDR-123 ") != std::string::npos);
    CHECK(datagram.find("loopback-payload next") != std::string::npos);
    const auto stats = forwarder.GetStatsSnapshot();
    CHECK(stats.sent == 1 && stats.failed == 0);
    CheckAccounting(stats);
}

void TestInvalidConfigurationIsVisible() {
    Forwarder forwarder("", 0, 16, "test");
    CHECK(!forwarder.Start());
    CHECK(!forwarder.Enqueue("high", "EDR-001", "invalid"));
    const auto stats = forwarder.GetStatsSnapshot();
    CHECK(stats.state == "start_failed" && stats.startFailures == 1);
    CHECK(stats.lastError != 0 && stats.rejected == 1 && !stats.running);
    CheckAccounting(stats);
}
#endif
} // namespace

int main() {
    try {
        TestInvalidDestinationFailsStart();
#ifndef SYSLOG_BASELINE_RED
        TestInitializationFailureIsSynchronousAndRetryable();
        TestStartingRejectsUntilInitializationCompletes();
        TestDuplicateStartStopAndRestartPreserveCounters();
        TestZeroCapacityRejectsWithoutQueueAccess();
        TestOverflowDropsOldestPendingAndStopDrains();
        TestInFlightAtCapacityRejectsNewAndRecordsSendFailure();
        TestConcurrentSnapshotsRemainConsistent();
        TestNativeLoopbackDatagramAndCounters();
        TestInvalidConfigurationIsVisible();
#endif
        std::puts("syslog_forwarder_tests: PASS (10 scenarios)");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
