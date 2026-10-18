/*
 * nonstandard_port_egress_detector_tests.cpp - Unit tests for
 * NonstandardPortEgressDetector (T1095 Non-Application Layer Protocol,
 * T1571 Non-Standard Port).
 */
#include "nonstandard_port_egress_detector_tests.h"
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include "edr_event.h"
#include "event_bus.h"
#include "nonstandard_port_egress_detector.h"

namespace {
#define NP_CHECK(c) Check((c), #c, __LINE__)
void Check(bool c, const char* e, int l) {
    if (!c) throw std::runtime_error(std::string("CHECK failed at ") + std::to_string(l) + ": " + e);
}

constexpr uint64_t kTick = 10000000ULL;

/* Builds a NET_CONNECT event. protocol may be null. */
edr::Event NetEvent(uint64_t ts, uint32_t pid, const char* image,
                    const char* ip, const char* port, const char* protocol) {
    edr::Event ev;
    ev.type = EDR_EVT_NET_CONNECT;
    ev.ts100ns = ts;
    ev.pid = pid;
    ev.fields[edr::field::kType] = "NET_CONNECT";
    if (image) ev.fields[edr::field::kImage] = image;
    if (ip) ev.fields[edr::field::kDstIp] = ip;
    if (port) ev.fields[edr::field::kDstPort] = port;
    if (protocol) ev.fields[edr::field::kProtocol] = protocol;
    return ev;
}

std::string Field(const edr::Event& e, const char* name) {
    auto it = e.fields.find(name);
    return it == e.fields.end() ? std::string() : it->second;
}
std::string Score(const edr::Event& e) { return Field(e, edr::field::kNonstandardPortScore); }
std::string Verdict(const edr::Event& e) { return Field(e, edr::field::kNonstandardPortVerdict); }
std::string Signals(const edr::Event& e) { return Field(e, edr::field::kNonstandardPortSignals); }
std::string Hosts(const edr::Event& e) { return Field(e, edr::field::kNonstandardPortHostCount); }
std::string Ports(const edr::Event& e) { return Field(e, edr::field::kNonstandardPortPortCount); }
std::string Conns(const edr::Event& e) { return Field(e, edr::field::kNonstandardPortConnectionCount); }

/* Feeds one connection and returns it so the caller can inspect the stamp. */
edr::Event Feed(edr::NonstandardPortEgressDetector& d, uint64_t ts, uint32_t pid,
                const char* image, const char* ip, const char* port,
                const char* protocol) {
    edr::Event ev = NetEvent(ts, pid, image, ip, port, protocol);
    d.Enrich(ev);
    return ev;
}

std::string Has(const std::string& list, const char* name) {
    size_t pos = 0;
    while ((pos = list.find(name, pos)) != std::string::npos) {
        const bool leftOk = (pos == 0) || list[pos - 1] == ',';
        const size_t end = pos + std::string(name).size();
        const bool rightOk = (end == list.size()) || list[end] == ',';
        if (leftOk && rightOk) return std::string("yes");
        pos = end;
    }
    return std::string();
}
} // namespace

void RunNonstandardPortEgressDetectorTests() {
    std::fprintf(stderr, "[nsport] TestDisabled\n");
    {
        /* A full beacon shape must stay silent when the detector is off. */
        edr::NonstandardPortEgressDetector d(false, 55, 300, 0, 1024);
        const uint64_t base = 1000000000ULL;
        const char* hosts[] = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"};
        const char* ports[] = {"443", "80", "22", "4444", "53"};
        for (int i = 0; i < 5; ++i) {
            auto ev = Feed(d, base + static_cast<uint64_t>(i) * kTick, 4242,
                           "C:\\evil\\beacon.exe", hosts[i], ports[i], "tcp");
            NP_CHECK(Score(ev).empty());
        }
        NP_CHECK(d.StateCount() == 0);
    }

    std::fprintf(stderr, "[nsport] TestInspects\n");
    {
        NP_CHECK(edr::NonstandardPortEgressDetector::Inspects(EDR_EVT_NET_CONNECT));
        NP_CHECK(!edr::NonstandardPortEgressDetector::Inspects(EDR_EVT_PROCESS_START));
    }

    std::fprintf(stderr, "[nsport] TestSingleUnusualPortSilent\n");
    {
        /* One high port is only unusual_port (+25): below the 55 floor. */
        edr::NonstandardPortEgressDetector d(true, 55, 300, 0, 1024);
        auto ev = Feed(d, 2000000000ULL, 4242, "C:\\Users\\Public\\tool.exe",
                       "10.20.30.40", "9999", "tcp");
        NP_CHECK(Score(ev).empty());
        NP_CHECK(d.StateCount() == 1);
    }

    std::fprintf(stderr, "[nsport] TestManyHostsAndPortsFloor\n");
    {
        /* 5 well-known hosts + 4 well-known ports. unusual_port never fires
         * (21/22/80/443 are all on the silent list) and "tcp" is not raw,
         * so the natural sum is many_hosts 25 + many_ports 20 = 45 and the
         * fan-out floor lifts it to exactly kSuspiciousFloor = 55. */
        edr::NonstandardPortEgressDetector d(true, 55, 300, 0, 1024);
        const uint64_t base = 3000000000ULL;
        const char* img = "C:\\Program Files\\updater\\upd.exe";
        const char* ips[] = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"};
        const char* pts[] = {"21", "22", "80", "443", "22"};
        edr::Event last;
        for (int i = 0; i < 5; ++i) {
            last = Feed(d, base + static_cast<uint64_t>(i) * kTick, 4243, img,
                        ips[i], pts[i], "tcp");
        }
        NP_CHECK(Score(last) == "55");
        NP_CHECK(Verdict(last) == "suspicious");
        NP_CHECK(Signals(last) == "many_hosts,many_ports");
        NP_CHECK(Hosts(last) == "5");
        NP_CHECK(Ports(last) == "4");
        NP_CHECK(Conns(last) == "5");
    }

    std::fprintf(stderr, "[nsport] TestBeaconShapeMalicious\n");
    {
        /* 4444 is off the silent list (unusual_port +25) and is also a raw
         * port, so raw_protocol fires too: 25 + 25 + 20 + 25 = 95 >= 75. */
        edr::NonstandardPortEgressDetector d(true, 55, 300, 0, 1024);
        const uint64_t base = 4000000000ULL;
        const char* img = "C:\\Users\\Public\\beacon.exe";
        const char* ips[] = {"10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4", "10.1.0.5"};
        const char* pts[] = {"443", "80", "22", "53", "4444"};
        edr::Event last;
        for (int i = 0; i < 5; ++i) {
            last = Feed(d, base + static_cast<uint64_t>(i) * kTick, 4244, img,
                        ips[i], pts[i], "tcp");
        }
        NP_CHECK(Score(last) == "95");
        NP_CHECK(Verdict(last) == "malicious");
        NP_CHECK(Has(Signals(last), "unusual_port") == "yes");
        NP_CHECK(Has(Signals(last), "many_hosts") == "yes");
        NP_CHECK(Has(Signals(last), "many_ports") == "yes");
        NP_CHECK(Has(Signals(last), "raw_protocol") == "yes");
        NP_CHECK(Hosts(last) == "5");
        NP_CHECK(Ports(last) == "5");
    }

    std::fprintf(stderr, "[nsport] TestHighVolumeAloneSilent\n");
    {
        /* 14 connections to one well-known host/port: high_volume (+15) is the
         * only signal, and one host/one port never triggers the fan-out floor. */
        edr::NonstandardPortEgressDetector d(true, 55, 300, 0, 1024);
        const uint64_t base = 5000000000ULL;
        const char* img = "C:\\Windows\\System32\\svchost.exe";
        for (int i = 0; i < 14; ++i) {
            auto ev = Feed(d, base + static_cast<uint64_t>(i) * kTick, 4245, img,
                           "10.2.0.1", "443", "tcp");
            NP_CHECK(Score(ev).empty());
        }
        NP_CHECK(d.StateCount() == 1);
    }

    std::fprintf(stderr, "[nsport] TestWellKnownPortSilent\n");
    {
        edr::NonstandardPortEgressDetector d(true, 55, 300, 0, 1024);
        auto ev443 = Feed(d, 6000000000ULL, 4246, "C:\\browser\\chrome.exe",
                          "10.3.0.1", "443", "tcp");
        NP_CHECK(Score(ev443).empty());
        NP_CHECK(Has(Signals(ev443), "unusual_port").empty());

        edr::NonstandardPortEgressDetector d2(true, 55, 300, 0, 1024);
        auto ev8080 = Feed(d2, 6000000000ULL, 4246, "C:\\browser\\chrome.exe",
                           "10.3.0.1", "8080", "http");
        NP_CHECK(Score(ev8080).empty());
        NP_CHECK(Has(Signals(ev8080), "unusual_port").empty());

        /* 8443 is on the well-known list and absent from IsRawPort, so it is
         * neither unusual nor raw on its own. */
        edr::NonstandardPortEgressDetector d3(true, 55, 300, 0, 1024);
        auto ev8443 = Feed(d3, 6000000000ULL, 4246, "C:\\browser\\chrome.exe",
                           "10.3.0.1", "8443", "tls");
        NP_CHECK(Score(ev8443).empty());
        NP_CHECK(Has(Signals(ev8443), "unusual_port").empty());
    }

    std::fprintf(stderr, "[nsport] TestRawPortSignal\n");
    {
        /* 4444 with an explicit "raw" token: unusual_port and raw_protocol
         * both set, still only 25 + 25 = 50, so no stamp yet. */
        edr::NonstandardPortEgressDetector d(true, 55, 300, 0, 1024);
        const uint64_t base = 7000000000ULL;
        auto ev = Feed(d, base, 4247, "C:\\Users\\Public\\raw.exe",
                       "10.4.0.1", "4444", "raw");
        NP_CHECK(Score(ev).empty());

        /* Confirm both signals are recorded once breadth pushes it over. */
        edr::NonstandardPortEgressDetector d2(true, 55, 300, 0, 1024);
        const char* img = "C:\\Users\\Public\\raw.exe";
        const char* ips[] = {"10.4.0.1", "10.4.0.2", "10.4.0.3", "10.4.0.4", "10.4.0.5"};
        const char* pts[] = {"443", "80", "22", "53", "4444"};
        edr::Event last;
        for (int i = 0; i < 5; ++i) {
            last = Feed(d2, base + static_cast<uint64_t>(i) * kTick, 4247, img,
                        ips[i], pts[i], "raw");
        }
        NP_CHECK(Has(Signals(last), "raw_protocol") == "yes");
        NP_CHECK(Has(Signals(last), "unusual_port") == "yes");
        NP_CHECK(Score(last) == "95");
    }

    std::fprintf(stderr, "[nsport] TestProtocolParsing\n");
    {
        /* "443/tcp" parses to port 443 (ParsePort stops at the '/'), and
         * "tcp" is explicitly not raw, so no unusual_port and no stamp. */
        edr::NonstandardPortEgressDetector d(true, 55, 300, 0, 1024);
        const uint64_t base = 8000000000ULL;
        const char* img = "C:\\browser\\firefox.exe";
        auto ev = Feed(d, base, 4248, img, "10.5.0.1", "443/tcp", "tcp");
        NP_CHECK(Score(ev).empty());
        NP_CHECK(Has(Signals(ev), "unusual_port").empty());

        /* The parsed port is really 443: five hosts on 443 keep a single
         * distinct port, so many_ports never fires and the floor is not met. */
        const char* ips[] = {"10.5.0.1", "10.5.0.2", "10.5.0.3", "10.5.0.4", "10.5.0.5"};
        edr::Event last;
        for (int i = 0; i < 5; ++i) {
            last = Feed(d, base + static_cast<uint64_t>(i + 1) * kTick, 4248, img,
                        ips[i], "443/tcp", "tcp");
        }
        NP_CHECK(Score(last).empty());
        NP_CHECK(Ports(last).empty());
    }

    std::fprintf(stderr, "[nsport] TestLoopbackIgnored\n");
    {
        /* IsLocalDestination: 127.0.0.0/8, ::1, "::", 0.0.0.0 and empty all
         * return before any state is created. */
        edr::NonstandardPortEgressDetector d(true, 55, 300, 0, 1024);
        Feed(d, 9000000000ULL, 4249, "C:\\evil\\beacon.exe", "127.0.0.1", "4444", "raw");
        Feed(d, 9001000000ULL, 4249, "C:\\evil\\beacon.exe", "127.1.2.3", "4444", "raw");
        Feed(d, 9002000000ULL, 4249, "C:\\evil\\beacon.exe", "::1", "4444", "raw");
        Feed(d, 9003000000ULL, 4249, "C:\\evil\\beacon.exe", "::", "4444", "raw");
        Feed(d, 9004000000ULL, 4249, "C:\\evil\\beacon.exe", "0.0.0.0", "4444", "raw");
        Feed(d, 9005000000ULL, 4249, "C:\\evil\\beacon.exe", "", "4444", "raw");
        NP_CHECK(d.StateCount() == 0);

        auto ev = Feed(d, 9006000000ULL, 4249, "C:\\evil\\beacon.exe",
                       "10.9.9.9", "4444", "raw");
        NP_CHECK(Score(ev).empty());
        NP_CHECK(d.StateCount() == 1);
    }

    std::fprintf(stderr, "[nsport] TestMinScoreGate\n");
    {
        /* The same fan-out shape scores 55; a minScore of 90 suppresses it. */
        edr::NonstandardPortEgressDetector d(true, 90, 300, 0, 1024);
        const uint64_t base = 10000000000ULL;
        const char* img = "C:\\Program Files\\updater\\upd.exe";
        const char* ips[] = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"};
        const char* pts[] = {"21", "22", "80", "443", "22"};
        edr::Event last;
        for (int i = 0; i < 5; ++i) {
            last = Feed(d, base + static_cast<uint64_t>(i) * kTick, 4250, img,
                        ips[i], pts[i], "tcp");
        }
        NP_CHECK(Score(last).empty());
        NP_CHECK(d.StateCount() == 1);
    }

    std::fprintf(stderr, "[nsport] TestOutOfOrderTimestampRejected\n");
    {
        /* After the fan-out stamp at T0, an event older than the last seen
         * timestamp is dropped before it can extend the window or restamp. */
        edr::NonstandardPortEgressDetector d(true, 55, 300, 0, 1024);
        const uint64_t base = 11000000000ULL;
        const char* img = "C:\\Users\\Public\\beacon.exe";
        const char* ips[] = {"10.6.0.1", "10.6.0.2", "10.6.0.3", "10.6.0.4", "10.6.0.5"};
        const char* pts[] = {"21", "22", "80", "443", "22"};
        edr::Event last;
        for (int i = 0; i < 5; ++i) {
            last = Feed(d, base + static_cast<uint64_t>(i) * kTick, 4251, img,
                        ips[i], pts[i], "tcp");
        }
        NP_CHECK(Score(last) == "55");

        /* Earlier than lastSeen: rejected outright, no stamp. */
        auto stale = Feed(d, base, 4251, img, "10.6.0.6", "21", "tcp");
        NP_CHECK(Score(stale).empty());

        /* The rejected event never reached the state map, so it added no
         * host: the next in-window connection counts 6 hosts, not 7. With a
         * zero dedup window the "cooled" predicate is always true, so this
         * connection does re-stamp at the same pinned 55. */
        auto sixth = Feed(d, base + 6 * kTick, 4251, img, "10.6.0.7", "21", "tcp");
        NP_CHECK(Score(sixth) == "55");
        NP_CHECK(Hosts(sixth) == "6");
        NP_CHECK(Ports(sixth) == "4");
        NP_CHECK(d.StateCount() == 1);
    }

    std::fprintf(stderr, "[nsport] TestWindowExpiry\n");
    {
        /* windowSeconds=30. The fan-out shape stamps at 55, then a burst
         * past the window resets the actor and drops back below the floor. */
        edr::NonstandardPortEgressDetector d(true, 55, 30, 0, 1024);
        const uint64_t base = 12000000000ULL;
        const uint64_t window = 30ULL * kTick;
        const char* img = "C:\\Users\\Public\\beacon.exe";
        const char* ips[] = {"10.7.0.1", "10.7.0.2", "10.7.0.3", "10.7.0.4", "10.7.0.5"};
        const char* pts[] = {"21", "22", "80", "443", "22"};
        edr::Event last;
        for (int i = 0; i < 5; ++i) {
            last = Feed(d, base + static_cast<uint64_t>(i) * kTick, 4252, img,
                        ips[i], pts[i], "tcp");
        }
        NP_CHECK(Score(last) == "55");
        NP_CHECK(d.StateCount() == 1);

        /* Past window+lastSeen: PurgeExpired erases the actor outright. */
        auto expired = Feed(d, base + window + 10ULL * kTick, 4252, img,
                            "10.7.0.9", "21", "tcp");
        NP_CHECK(Score(expired).empty());
        NP_CHECK(d.StateCount() == 1);
        NP_CHECK(Ports(expired).empty());
        NP_CHECK(Hosts(expired).empty());
    }

    std::fprintf(stderr, "[nsport] TestDedupCooldown\n");
    {
        /* dedupWindowSeconds=120, score pinned at 55 by the fan-out floor so
         * the score never "widens"; after the first stamp every in-cooldown
         * connection is suppressed until the dedup window elapses. */
        edr::NonstandardPortEgressDetector d(true, 55, 300, 120, 1024);
        const uint64_t base = 13000000000ULL;
        const uint64_t dedup = 120ULL * kTick;
        const char* img = "C:\\Users\\Public\\beacon.exe";
        const char* ips[] = {"10.8.0.1", "10.8.0.2", "10.8.0.3", "10.8.0.4", "10.8.0.5"};
        const char* pts[] = {"21", "22", "80", "443", "22"};
        edr::Event last;
        for (int i = 0; i < 5; ++i) {
            last = Feed(d, base + static_cast<uint64_t>(i) * kTick, 4253, img,
                        ips[i], pts[i], "tcp");
        }
        NP_CHECK(Score(last) == "55");

        /* Inside the dedup cooldown: no restamp even though the shape holds. */
        auto during = Feed(d, base + 30ULL * kTick, 4253, img, "10.8.0.6", "21", "tcp");
        NP_CHECK(Score(during).empty());
        auto during2 = Feed(d, base + 60ULL * kTick, 4253, img, "10.8.0.7", "21", "tcp");
        NP_CHECK(Score(during2).empty());

        /* Cooldown elapsed: stamped again. */
        auto after = Feed(d, base + dedup + 5ULL * kTick, 4253, img, "10.8.0.8", "21", "tcp");
        NP_CHECK(Score(after) == "55");
        NP_CHECK(Verdict(after) == "suspicious");
    }

    std::fprintf(stderr, "[nsport] TestCapacityReset\n");
    {
        /* Capacity 16 with 64 distinct pids: the map is cleared wholesale once
         * the size exceeds capacity, so StateCount() stays bounded and no
         * connection is ever stamped (each actor holds a single connection). */
        edr::NonstandardPortEgressDetector d(true, 55, 300, 0, 16);
        const uint64_t base = 14000000000ULL;
        for (int i = 0; i < 64; ++i) {
            auto ev = Feed(d, base + static_cast<uint64_t>(i) * kTick,
                           static_cast<uint32_t>(5000 + i),
                           "C:\\Users\\Public\\multi.exe", "10.9.0.1", "4444", "raw");
            NP_CHECK(Score(ev).empty());
            NP_CHECK(d.StateCount() <= 17);
        }
        NP_CHECK(d.StateCount() <= 17);
    }

    std::fprintf(stderr, "[nsport] TestStateCountAccessor\n");
    {
        edr::NonstandardPortEgressDetector d(true, 55, 300, 0, 1024);
        NP_CHECK(d.StateCount() == 0);
        /* Same pid+image is one key; a different image is a different key. */
        Feed(d, 15000000000ULL, 4254, "C:\\a\\one.exe", "10.10.0.1", "443", "tcp");
        NP_CHECK(d.StateCount() == 1);
        Feed(d, 15000000000ULL, 4254, "C:\\a\\one.exe", "10.10.0.2", "443", "tcp");
        NP_CHECK(d.StateCount() == 1);
        Feed(d, 15000000000ULL, 4254, "C:\\a\\two.exe", "10.10.0.3", "443", "tcp");
        NP_CHECK(d.StateCount() == 2);
        Feed(d, 15000000000ULL, 4255, "C:\\a\\two.exe", "10.10.0.4", "443", "tcp");
        NP_CHECK(d.StateCount() == 3);
        /* pid 0 is ignored before any key is built. */
        Feed(d, 15000000000ULL, 0, "C:\\a\\three.exe", "10.10.0.5", "443", "tcp");
        NP_CHECK(d.StateCount() == 3);
    }

    std::fprintf(stderr, "[nsport] all passed\n");
}
