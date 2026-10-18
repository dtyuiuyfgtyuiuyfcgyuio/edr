/*
 * net_etw_parser_tests.cpp - Unit tests for the ETW network-collector fixed-
 * offset payload parser (collector_net_etw.cpp).
 *
 * Synthetic payloads are built with a helper that writes the PID (host order
 * at 0), a plausible packet-size field (host order at 4, which the parser must
 * IGNORE when discriminating IPv4 from IPv6), then addresses/ports in NETWORK
 * byte order at the template offsets.
 */
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "collector_net_etw.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"

using namespace edr;

namespace {

int g_failures = 0;

#define CHECK(expression) do { \
    if (!(expression)) { \
        std::cerr << "check failed at line " << __LINE__ << ": " \
                  << #expression << "\n"; \
        ++g_failures; \
    } \
} while (0)

/* v4 template: pid@0, size@4, daddr@8, saddr@12, dport@16, sport@18 */
std::vector<uint8_t> PayloadV4(uint32_t pid, uint32_t size,
                               const uint8_t daddr[4], const uint8_t saddr[4],
                               uint16_t dport, uint16_t sport, size_t extra) {
    std::vector<uint8_t> p(20 + extra);
    std::memcpy(p.data(), &pid, 4);
    std::memcpy(p.data() + 4, &size, 4);
    std::memcpy(p.data() + 8, daddr, 4);
    std::memcpy(p.data() + 12, saddr, 4);
    uint16_t ndport = htons(dport);
    uint16_t nsport = htons(sport);
    std::memcpy(p.data() + 16, &ndport, 2);
    std::memcpy(p.data() + 18, &nsport, 2);
    return p;
}

/* v6 template: pid@0, size@4, daddr[16]@8, saddr[16]@24, dport@40, sport@42 */
std::vector<uint8_t> PayloadV6(uint32_t pid, uint32_t size,
                               const uint8_t daddr[16], const uint8_t saddr[16],
                               uint16_t dport, uint16_t sport, size_t extra) {
    std::vector<uint8_t> p(44 + extra);
    std::memcpy(p.data(), &pid, 4);
    std::memcpy(p.data() + 4, &size, 4);
    std::memcpy(p.data() + 8, daddr, 16);
    std::memcpy(p.data() + 24, saddr, 16);
    uint16_t ndport = htons(dport);
    uint16_t nsport = htons(sport);
    std::memcpy(p.data() + 40, &ndport, 2);
    std::memcpy(p.data() + 42, &nsport, 2);
    return p;
}

void TestKeep() {
    CHECK(IsNetEtwKeepEvent(12, false));
    CHECK(IsNetEtwKeepEvent(15, false));
    CHECK(IsNetEtwKeepEvent(28, false));
    CHECK(IsNetEtwKeepEvent(31, false));
    CHECK(!IsNetEtwKeepEvent(42, false));
    CHECK(!IsNetEtwKeepEvent(43, false));
    CHECK(!IsNetEtwKeepEvent(58, false));
    CHECK(!IsNetEtwKeepEvent(59, false));
    CHECK(IsNetEtwKeepEvent(42, true));
    CHECK(IsNetEtwKeepEvent(43, true));
    CHECK(IsNetEtwKeepEvent(58, true));
    CHECK(IsNetEtwKeepEvent(59, true));
    CHECK(!IsNetEtwKeepEvent(13, false));
    CHECK(!IsNetEtwKeepEvent(16, false));
    CHECK(!IsNetEtwKeepEvent(32, false));
    CHECK(!IsNetEtwKeepEvent(13, true));
}

void TestTcpV4Connect() {
    const uint8_t daddr[4] = {0xC0, 0xA8, 0x64, 0x07}; /* 192.168.100.7 */
    const uint8_t saddr[4] = {0x0A, 0x00, 0x00, 0x05}; /* 10.0.0.5 */
    /* full 44-byte payload; size field 40 (packet size, must be ignored) */
    std::vector<uint8_t> p = PayloadV4(1234, 40, daddr, saddr, 4444, 0x1234, 24);
    NetConnectInfo info;
    CHECK(ParseNetConnectPayload(12, p.data(), (uint32_t)p.size(), info));
    CHECK(!info.ipv6);
    CHECK(!info.udp);
    CHECK(info.pid == 1234);
    CHECK(NetIpToString(false, info.daddr) == "192.168.100.7");
    CHECK(NetIpToString(false, info.saddr) == "10.0.0.5");
    CHECK(ntohs(info.dport) == 4444);
    CHECK(ntohs(info.sport) == 0x1234);
}

void TestTcpV4Accept() {
    const uint8_t daddr[4] = {0xC0, 0xA8, 0x64, 0x07}; /* 192.168.100.7 */
    const uint8_t saddr[4] = {0, 0, 0, 0};             /* 0.0.0.0 */
    std::vector<uint8_t> p = PayloadV4(555, 40, daddr, saddr, 8080, 2000, 24);
    NetConnectInfo info;
    CHECK(ParseNetConnectPayload(15, p.data(), (uint32_t)p.size(), info));
    CHECK(!info.ipv6);
    CHECK(!info.udp);
    CHECK(NetIpToString(false, info.saddr) == "0.0.0.0");
    CHECK(NetIpToString(false, info.daddr) == "192.168.100.7");
    CHECK(ntohs(info.dport) == 8080);
    CHECK(info.pid == 555);
}

void TestTcpV6Connect() {
    const uint8_t daddr[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 1}; /* ::1 */
    const uint8_t saddr[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 1}; /* 2001:db8::1 */
    /* full 68-byte payload; size field 60 (must be ignored) */
    std::vector<uint8_t> p = PayloadV6(999, 60, daddr, saddr, 443, 0x0412, 24);
    NetConnectInfo info;
    CHECK(ParseNetConnectPayload(28, p.data(), (uint32_t)p.size(), info));
    CHECK(info.ipv6);
    CHECK(!info.udp);
    CHECK(info.pid == 999);
    CHECK(NetIpToString(true, info.daddr) == "::1");
    CHECK(NetIpToString(true, info.saddr) == "2001:db8::1");
    CHECK(ntohs(info.dport) == 443);
    CHECK(ntohs(info.sport) == 0x0412);
}

void TestTcpV6Accept() {
    const uint8_t daddr[16] = {0x26, 0x00, 0x00, 0x00, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 1}; /* 2600::1 */
    const uint8_t saddr[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0}; /* :: */
    std::vector<uint8_t> p = PayloadV6(321, 60, daddr, saddr, 443, 0x0412, 24);
    NetConnectInfo info;
    CHECK(ParseNetConnectPayload(31, p.data(), (uint32_t)p.size(), info));
    CHECK(info.ipv6);
    CHECK(!info.udp);
    CHECK(NetIpToString(true, info.daddr) == "2600::1");
    CHECK(NetIpToString(true, info.saddr) == "::");
    CHECK(ntohs(info.dport) == 443);
}

void TestUdpV4() {
    const uint8_t daddr[4] = {0x08, 0x08, 0x08, 0x08}; /* 8.8.8.8 */
    const uint8_t saddr[4] = {0x0A, 0x00, 0x00, 0x01}; /* 10.0.0.1 */
    /* v4 UDP template min is 28 bytes */
    std::vector<uint8_t> p = PayloadV4(777, 20, daddr, saddr, 53, 53000, 8);
    NetConnectInfo info;
    CHECK(ParseNetConnectPayload(42, p.data(), (uint32_t)p.size(), info));
    CHECK(info.udp);
    CHECK(!info.ipv6);
    CHECK(info.pid == 777);
    CHECK(NetIpToString(false, info.daddr) == "8.8.8.8");
    CHECK(NetIpToString(false, info.saddr) == "10.0.0.1");
    CHECK(ntohs(info.dport) == 53);
    CHECK(ntohs(info.sport) == 53000);
}

void TestUdpV6() {
    const uint8_t daddr[16] = {0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0x53}; /* 2001:4860::53 */
    const uint8_t saddr[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 1}; /* 2001:db8::1 */
    /* v6 UDP template min is 52 bytes */
    std::vector<uint8_t> p = PayloadV6(4242, 40, daddr, saddr, 53, 40000, 8);
    NetConnectInfo info;
    CHECK(ParseNetConnectPayload(58, p.data(), (uint32_t)p.size(), info));
    CHECK(info.udp);
    CHECK(info.ipv6);
    CHECK(NetIpToString(true, info.daddr) == "2001:4860::53");
    CHECK(ntohs(info.dport) == 53);
}

void TestSizeFieldIgnored() {
    /* v4 id12 with a large size field: must still parse as IPv4. */
    const uint8_t daddr[4] = {0xC0, 0xA8, 0x64, 0x07};
    const uint8_t saddr[4] = {0x0A, 0x00, 0x00, 0x05};
    std::vector<uint8_t> p4 = PayloadV4(11, 1000, daddr, saddr, 80, 100, 24);
    NetConnectInfo info4;
    CHECK(ParseNetConnectPayload(12, p4.data(), (uint32_t)p4.size(), info4));
    CHECK(!info4.ipv6);
    CHECK(NetIpToString(false, info4.daddr) == "192.168.100.7");

    /* v6 id=28 with a small size field: must still parse as IPv6. */
    const uint8_t saddr6[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 1};
    std::vector<uint8_t> p6 = PayloadV6(22, 20, saddr6, saddr6, 443, 300, 24);
    NetConnectInfo info6;
    CHECK(ParseNetConnectPayload(28, p6.data(), (uint32_t)p6.size(), info6));
    CHECK(info6.ipv6);
    CHECK(NetIpToString(true, info6.daddr) == "::1");
}

void TestTruncation() {
    NetConnectInfo info;
    std::vector<uint8_t> t19(19);
    CHECK(!ParseNetConnectPayload(12, t19.data(), (uint32_t)t19.size(), info));
    std::vector<uint8_t> t43(43);
    CHECK(!ParseNetConnectPayload(28, t43.data(), (uint32_t)t43.size(), info));
    std::vector<uint8_t> t7(7);
    CHECK(!ParseNetConnectPayload(42, t7.data(), (uint32_t)t7.size(), info));
    std::vector<uint8_t> t8(8);
    CHECK(!ParseNetConnectPayload(12, t8.data(), (uint32_t)t8.size(), info));
    CHECK(!ParseNetConnectPayload(12, nullptr, 44, info));
}

void TestUnknownId() {
    const uint8_t daddr[4] = {0xC0, 0xA8, 0x64, 0x07};
    const uint8_t saddr[4] = {0x0A, 0x00, 0x00, 0x05};
    std::vector<uint8_t> p = PayloadV4(1, 40, daddr, saddr, 80, 100, 24);
    NetConnectInfo info;
    CHECK(!ParseNetConnectPayload(13, p.data(), (uint32_t)p.size(), info));
    CHECK(!ParseNetConnectPayload(16, p.data(), (uint32_t)p.size(), info));
    CHECK(!ParseNetConnectPayload(17, p.data(), (uint32_t)p.size(), info));
}

void TestIpToStringEdges() {
    const uint32_t zero[4] = {0, 0, 0, 0};
    CHECK(NetIpToString(false, zero) == "0.0.0.0");
    CHECK(NetIpToString(true, zero) == "::");
}

void WriteConfig(const char* json) {
    std::ofstream output("edr-net-etw-test-config.json", std::ios::binary);
    output << json;
}

void TestConfig() {
    Config defaults;
    CHECK(defaults.enableNetEtw);
    CHECK(!defaults.netEtwUdp);

    std::string error;
    WriteConfig(R"({"enable_net_etw":false,"net_etw_udp":true})");
    Config valid;
    CHECK(LoadConfigFile("edr-net-etw-test-config.json", valid, error));
    CHECK(!valid.enableNetEtw && valid.netEtwUdp);

    for (const char* json : {
        R"({"enable_net_etw":"true"})",
        R"({"net_etw_udp":5})"}) {
        WriteConfig(json);
        Config unchanged;
        CHECK(!LoadConfigFile(
            "edr-net-etw-test-config.json", unchanged, error));
        CHECK(unchanged.enableNetEtw && !unchanged.netEtwUdp);
    }
    DeleteFileA("edr-net-etw-test-config.json");
}

void TestProductionRules() {
    RuleEngine engine;
    try {
        engine.LoadFromFile("..\\rules\\rules.json");
    } catch (const std::exception& error) {
        std::cerr << "production rule load failed: " << error.what() << "\n";
        ++g_failures;
        return;
    }
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) {
        hits.push_back(alert.ruleId);
    });
    auto matched = [&](const Event& event, const char* ruleId) {
        hits.clear();
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), ruleId) != hits.end();
    };

    Event even;
    even.type = EDR_EVT_NET_CONNECT;
    even.fields[field::kType] = "NET_CONNECT";
    even.fields[field::kSrcPort] = "20000";
    CHECK(matched(even, "EDR-137"));

    Event odd = even;
    odd.fields[field::kSrcPort] = "20001";
    CHECK(!matched(odd, "EDR-137"));

    Event udp;
    udp.type = EDR_EVT_NET_CONNECT;
    udp.fields[field::kType] = "NET_CONNECT";
    udp.fields[field::kProtocol] = "udp";
    udp.fields[field::kDstIp] = "192.168.200.55";
    CHECK(matched(udp, "EDR-138"));

    Event tcp = udp;
    tcp.fields[field::kProtocol] = "tcp";
    CHECK(!matched(tcp, "EDR-138"));

    Event c2;
    c2.type = EDR_EVT_NET_CONNECT;
    c2.fields[field::kType] = "NET_CONNECT";
    c2.fields[field::kDstPort] = "4444";
    CHECK(matched(c2, "EDR-005"));

    Event benign = c2;
    benign.fields[field::kDstPort] = "80";
    CHECK(!matched(benign, "EDR-005"));
}

} // namespace

int main() {
    TestKeep();
    TestTcpV4Connect();
    TestTcpV4Accept();
    TestTcpV6Connect();
    TestTcpV6Accept();
    TestUdpV4();
    TestUdpV6();
    TestSizeFieldIgnored();
    TestTruncation();
    TestUnknownId();
    TestIpToStringEdges();
    TestConfig();
    TestProductionRules();
    if (g_failures != 0) return 1;
    std::cout << "net_etw parser tests passed\n";
    return 0;
}
