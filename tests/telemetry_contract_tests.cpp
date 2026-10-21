#include "telemetry_contract_tests.h"

#include <windows.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>

#include "dns_etw_parser.h"
#include "security_log_parser.h"
#include "security_log_subscription.h"
#include "telemetry_delivery.h"
#include "rule_engine.h"
#include "reporter.h"
#include "attack_chain_detector.h"
#include "alerter.h"

namespace {
#define TC_CHECK(value) do { if (!(value)) throw std::runtime_error( \
    "telemetry contract failure at line " + std::to_string(__LINE__) + ": " #value); } while (0)
using Properties = std::map<std::wstring, std::vector<uint8_t>>;

std::vector<uint8_t> Wide(const std::wstring& value) {
    std::vector<uint8_t> bytes((value.size() + 1) * sizeof(wchar_t));
    std::memcpy(bytes.data(), value.c_str(), bytes.size());
    return bytes;
}
std::vector<uint8_t> Number(uint32_t value) {
    std::vector<uint8_t> bytes(sizeof(value));
    std::memcpy(bytes.data(), &value, sizeof(value));
    return bytes;
}
bool Parse(uint16_t id, uint8_t version, const Properties& properties,
           edr::Event& event) {
    return edr::ParseDnsEtwEvent(id, version, 600, 123456789,
        [&](const wchar_t* name, std::vector<uint8_t>& bytes) {
            const auto found = properties.find(name);
            if (found == properties.end()) return edr::DnsPropertyStatus::Missing;
            bytes = found->second;
            return edr::DnsPropertyStatus::Present;
        }, event);
}

void TestSecuritySubscriptionMatchesEveryParserId() {
    const auto& query = edr::SecurityLogSubscriptionQuery();
    TC_CHECK(query.rfind(L"<QueryList><Query Id=\"0\" Path=\"Security\">", 0) == 0);
    TC_CHECK(query.substr(query.size() - 20) == L"</Query></QueryList>");
    std::set<uint32_t> selected;
    size_t selectorCount = 0;
    size_t cursor = 0;
    while ((cursor = query.find(L"<Select Path=\"Security\">", cursor)) != std::wstring::npos) {
        const size_t start = query.find(L'>', cursor) + 1;
        const size_t end = query.find(L"</Select>", start);
        TC_CHECK(end != std::wstring::npos);
        const auto selector = query.substr(start, end - start);
        TC_CHECK(selector.rfind(L"*[System[(", 0) == 0);
        TC_CHECK(selector.substr(selector.size() - 3) == L")]]");
        size_t idCursor = 0;
        size_t count = 0;
        while ((idCursor = selector.find(L"EventID=", idCursor)) != std::wstring::npos) {
            idCursor += 8;
            size_t consumed = 0;
            const auto id = std::stoul(selector.substr(idCursor), &consumed);
            TC_CHECK(consumed != 0 && id <= 65535 && selected.insert(static_cast<uint32_t>(id)).second);
            idCursor += consumed;
            ++count;
        }
        TC_CHECK(count > 0 && count <= 10);
        ++selectorCount;
        cursor = end + 9;
    }
    TC_CHECK(selectorCount == 3 && selected.size() == edr::kSecurityLogEventIds.size());
    for (uint32_t id = 0; id <= 65535; ++id) {
        edr::Event event;
        const auto xml = L"<Event><System><EventID>" + std::to_wstring(id) +
            L"</EventID><TimeCreated SystemTime='2026-10-05T00:00:00.0000000Z'/>"
            L"</System><EventData><Data Name='TaskName'>\\EDR-Contract</Data>"
            L"</EventData></Event>";
        const bool supported = std::find(edr::kSecurityLogEventIds.begin(),
            edr::kSecurityLogEventIds.end(), id) != edr::kSecurityLogEventIds.end();
        TC_CHECK(edr::ParseSecurityLogXml(xml, event) == supported);
        TC_CHECK((selected.count(id) != 0) == supported);
        if (supported) {
            TC_CHECK(query.find(L"EventID=" + std::to_wstring(id)) != std::wstring::npos);
            TC_CHECK(event.fields.at(edr::field::kSecurityEventId) == std::to_string(id));
            TC_CHECK(event.source == "security_log");
            TC_CHECK(event.ts100ns != 0);
        }
    }
    puts("PASS security subscription/parser parity for all 65536 IDs");
}

void TestDnsProviderVersionsAndPhase() {
    Properties data{{L"QueryName", Wide(L"Example.test")},
        {L"ClientPID", Number(42)}, {L"DNSServerAddress", Wide(L"192.0.2.53")},
        {L"LocalAddress", Wide(L"192.0.2.10")}};
    for (uint8_t version = 0; version <= 2; ++version) {
        edr::Event event;
        TC_CHECK(Parse(3009, version, data, event));
        TC_CHECK(event.pid == (version == 0 ? 600u : 42u));
        TC_CHECK(event.source == "dns_etw");
        TC_CHECK(event.ts100ns == 123456789);
        TC_CHECK(event.fields.at("dns_phase") == "started");
        TC_CHECK(event.fields.at("dns_provider_pid") == "600");
        TC_CHECK(event.fields.at(edr::field::kType) == "DNS_QUERY");
        TC_CHECK(event.fields.at(edr::field::kDnsServerIp) == "192.0.2.53");
        TC_CHECK(event.disposition == edr::EventDisposition::ReportOnly);
        if (version) TC_CHECK(event.fields.at(edr::field::kSourcePid) == "42");
        else TC_CHECK(event.fields.count(edr::field::kSourcePid) == 0);
    }
    data[L"QueryType"] = Number(16);
    data[L"QueryStatus"] = Number(0);
    data[L"QueryResults"] = Wide(L"answer");
    edr::Event complete;
    TC_CHECK(Parse(3008, 0, data, complete));
    TC_CHECK(complete.disposition == edr::EventDisposition::ReportAndEvaluate);
    TC_CHECK(complete.fields.at("dns_phase") == "completed");
    TC_CHECK(complete.fields.at(edr::field::kDnsQueryType) == "TXT");
    TC_CHECK(complete.fields.at(edr::field::kDnsQueryStatus) == "0");
    TC_CHECK(complete.fields.at(edr::field::kDnsAnswers) == "answer");
    TC_CHECK(complete.fields.at(edr::field::kDnsSubdomainCount) == "2");
    TC_CHECK(complete.fields.at(edr::field::kDnsMaxLabelLength) == "7");
    TC_CHECK(std::stod(complete.fields.at(edr::field::kDnsEntropy)) > 0);
    puts("PASS DNS 3008/v0 and 3009/v0-v2 schema, attribution, phase and disposition");
}

void TestReportOnlyDeliveryPrecedesStatefulAnalysis() {
    edr::AttackChainDetector detector(16, 60);
    edr::RuleEngine rules;
    unsigned alerts = 0;
    rules.SetAlertCallback([&](const edr::Alert&) { ++alerts; });
    // A strong persistence event normally creates an attack-chain state.
    edr::Event event;
    event.pid = 42;
    event.processStartTime100ns = 100;
    event.ts100ns = 123456789;
    event.type = EDR_EVT_REG_WRITE;
    event.fields[edr::field::kRegKey] =
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\probe";
    event.disposition = edr::EventDisposition::ReportOnly;
    auto dispatch = [&](edr::Event value, edr::Reporter* reporter = nullptr) {
        if (edr::DeliverReportOnlyEvent(value, reporter, true, &rules)) return;
        detector.Enrich(value);
        edr::DeliverTelemetryEvent(value, reporter, true, &rules);
    };
    dispatch(event);
    TC_CHECK(detector.StateCount() == 0 && alerts == 0);
    std::mutex mutex;
    std::condition_variable delivered;
    std::vector<std::string> bodies;
    edr::Reporter reporter("http://127.0.0.1/unused", "", 4,
        [&](const std::string& body) {
            std::lock_guard<std::mutex> lock(mutex);
            bodies.push_back(body);
            delivered.notify_all();
            return true;
        });
    TC_CHECK(reporter.Start());
    dispatch(event, &reporter);
    {
        std::unique_lock<std::mutex> lock(mutex);
        TC_CHECK(delivered.wait_for(lock, std::chrono::seconds(5),
            [&] { return !bodies.empty(); }));
    }
    reporter.Stop();
    TC_CHECK(bodies.size() == 1 && bodies.front() == edr::EventToJsonLine(event, true));
    TC_CHECK(detector.StateCount() == 0 && alerts == 0);
    event.disposition = edr::EventDisposition::ReportAndEvaluate;
    dispatch(event);
    TC_CHECK(detector.StateCount() == 1);
    // A report-only event must preserve failure receipts when reporting fails.
    event.disposition = edr::EventDisposition::ReportOnly;
    bool rejected = false;
    try { dispatch(event, &reporter); }
    catch (const std::exception&) { rejected = true; }
    TC_CHECK(rejected && detector.StateCount() == 1);
    puts("PASS report-only forwarding skips state and preserves reporting failures");
}

void TestDnsMalformedPropertiesAndFallback() {
    Properties base{{L"QueryName", Wide(L"example.test")}};
    edr::Event event;
    TC_CHECK(Parse(3009, 1, base, event));
    TC_CHECK(event.pid == 600 && event.fields.at("dns_pid_provenance") == "event_header");
    base[L"ClientPID"] = Number(0);
    TC_CHECK(Parse(3009, 2, base, event) && event.pid == 600);
    for (size_t size : {size_t(0), size_t(1), size_t(2), size_t(3), size_t(5), size_t(8)}) {
        base[L"ClientPID"] = std::vector<uint8_t>(size, 1);
        TC_CHECK(!Parse(3009, 1, base, event));
    }
    base[L"ClientPID"] = Number(0xffffffffu);
    TC_CHECK(!Parse(3009, 2, base, event));
    base.erase(L"ClientPID");
    TC_CHECK(!Parse(3009, 3, base, event));
    TC_CHECK(!Parse(3008, 1, base, event));
    TC_CHECK(!Parse(3010, 0, base, event));
    TC_CHECK(!Parse(3008, 0, {}, event));
    for (const auto& value : {std::wstring(), std::wstring(L"a\0b", 3),
                              std::wstring(1025, L'a'), std::wstring(1, wchar_t(0xd800))}) {
        base[L"QueryName"] = Wide(value);
        TC_CHECK(!Parse(3008, 0, base, event));
    }
    base[L"QueryName"] = Wide(L"example.test");
    base[L"QueryName"].pop_back();
    TC_CHECK(!Parse(3008, 0, base, event));
    base[L"QueryName"] = Wide(L"example.test");
    base[L"QueryName"].resize(base[L"QueryName"].size() - sizeof(wchar_t));
    TC_CHECK(!Parse(3008, 0, base, event));
    base[L"QueryName"] = Wide(std::wstring(1024, L'a'));
    TC_CHECK(Parse(3008, 0, base, event));
    base[L"QueryStatus"] = std::vector<uint8_t>(8, 0);
    TC_CHECK(!Parse(3008, 0, base, event));
    base.erase(L"QueryStatus");
    base[L"QueryResults"] = Wide(std::wstring(16385, L'a'));
    TC_CHECK(!Parse(3008, 0, base, event));
    event.pid = 77;
    TC_CHECK(!edr::ParseDnsEtwEvent(3008, 0, 600, 1,
        [](const wchar_t*, std::vector<uint8_t>&) -> edr::DnsPropertyStatus {
            throw std::runtime_error("TDH failed");
        }, event));
    TC_CHECK(event.pid == 77);
    puts("PASS DNS missing/zero PID fallback, bad versions, widths, NUL, Unicode and bounds");
}
} // namespace

void RunTelemetryContractTests() {
    TestSecuritySubscriptionMatchesEveryParserId();
    TestDnsProviderVersionsAndPhase();
    TestDnsMalformedPropertiesAndFallback();
    TestReportOnlyDeliveryPrecedesStatefulAnalysis();
}
