/*
 * network_sniffing_detector_tests.cpp - Unit tests for
 * NetworkSniffingDetector (T1040).
 */
#include "network_sniffing_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "network_sniffing_detector.h"

namespace {

#define NS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "network sniffing detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcEvent(uint64_t ts100ns, const char* image,
                     const char* commandLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kNetworkSniffingScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunNetworkSniffingDetectorTests() {
    std::fprintf(stderr, "[net-sniff] TestDisabled\n");
    {
        edr::NetworkSniffingDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\netsh.exe",
            "netsh trace start capture=yes");
        detector.Enrich(event);
        NS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[net-sniff] TestNetshTraceStart\n");
    {
        edr::NetworkSniffingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\netsh.exe",
            "netsh trace start capture=yes tracefile=C:\\Temp\\cap.etl");
        detector.Enrich(event);
        NS_CHECK(Score(event) == "85");
        NS_CHECK(event.fields.at(edr::field::kNetworkSniffingVerdict) ==
                 "malicious");
        NS_CHECK(event.fields.at(edr::field::kNetworkSniffingSignals)
                     .find("netsh trace") != std::string::npos);
    }
    std::fprintf(stderr, "[net-sniff] TestPktmonStart\n");
    {
        edr::NetworkSniffingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\pktmon.exe",
            "pktmon start --etw -p 0 -f C:\\Temp\\cap.etl");
        detector.Enrich(event);
        NS_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[net-sniff] TestCaptureTool\n");
    {
        edr::NetworkSniffingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Tools\\tshark.exe",
            "tshark -i 1 -w C:\\Temp\\traffic.pcapng");
        detector.Enrich(event);
        NS_CHECK(Score(event) == "80");
        NS_CHECK(event.fields.at(edr::field::kNetworkSniffingVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[net-sniff] TestNpcapInstall\n");
    {
        edr::NetworkSniffingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
            "msiexec /i npcap-1.7.1.exe /q");
        detector.Enrich(event);
        NS_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[net-sniff] TestRawSocketPowerShell\n");
    {
        edr::NetworkSniffingDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_POWERSHELL_SCRIPT;
        event.ts100ns = 1000 * kSecond;
        event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        event.fields[edr::field::kScriptBlockText] =
            "$s.IOControl([System.Net.Sockets.IOControlCode]::"
            "ReceiveAll, ...)";
        detector.Enrich(event);
        NS_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[net-sniff] TestTraceConvertSuspicious\n");
    {
        edr::NetworkSniffingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\netsh.exe",
            "netsh trace convert input=C:\\Temp\\cap.etl output=cap.pcapng");
        detector.Enrich(event);
        NS_CHECK(Score(event) == "60");
        NS_CHECK(event.fields.at(edr::field::kNetworkSniffingVerdict) ==
                 "suspicious");
    }
    std::fprintf(stderr, "[net-sniff] TestStatusQueriesSilent\n");
    {
        edr::NetworkSniffingDetector detector(true, 55, 300, 1024);
        edr::Event show = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\netsh.exe",
            "netsh trace show status");
        detector.Enrich(show);
        NS_CHECK(Score(show).empty());
        edr::Event status = ProcEvent(
            1001 * kSecond, "C:\\Windows\\System32\\pktmon.exe",
            "pktmon status");
        detector.Enrich(status);
        NS_CHECK(Score(status).empty());
    }
    std::fprintf(stderr, "[net-sniff] TestUnrelatedNetshSilent\n");
    {
        edr::NetworkSniffingDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\netsh.exe",
            "netsh interface portproxy add v4tov4");
        detector.Enrich(event);
        NS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[net-sniff] TestDedupWindow\n");
    {
        edr::NetworkSniffingDetector detector(true, 55, 60, 1024);
        const char* cmd = "netsh trace start capture=yes";
        edr::Event first = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\netsh.exe", cmd);
        detector.Enrich(first);
        NS_CHECK(!Score(first).empty());
        /* Same command inside the 60s dedup window is suppressed. */
        edr::Event second = ProcEvent(
            1030 * kSecond, "C:\\Windows\\System32\\netsh.exe", cmd);
        detector.Enrich(second);
        NS_CHECK(Score(second).empty());
        /* Outside the window it alerts again. */
        edr::Event third = ProcEvent(
            1100 * kSecond, "C:\\Windows\\System32\\netsh.exe", cmd);
        detector.Enrich(third);
        NS_CHECK(!Score(third).empty());
    }
    std::fprintf(stderr, "[net-sniff] all passed\n");
}
