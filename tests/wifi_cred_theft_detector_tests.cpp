/*
 * wifi_cred_theft_detector_tests.cpp - Unit tests for
 * WifiCredTheftDetector.
 */
#include "wifi_cred_theft_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "wifi_cred_theft_detector.h"

namespace {

#define CHECK_WIFI(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "wifi credential theft detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcessStart(uint32_t pid, const char* image,
                        const char* commandLine, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.pid = pid;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kWifiTheftScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunWifiCredTheftDetectorTests() {
    std::fprintf(stderr, "[wifi-theft] TestDisabled\n");
    {
        edr::WifiCredTheftDetector detector(false, 300, 2048, 3);
        edr::Event event = ProcessStart(
            9101, "C:\\Windows\\System32\\netsh.exe",
            "netsh wlan export profile key=clear", 1000 * kSecond);
        detector.Enrich(event);
        CHECK_WIFI(!HasScore(event));
    }
    std::fprintf(stderr, "[wifi-theft] TestKeyClearExport\n");
    {
        edr::WifiCredTheftDetector detector(true, 300, 2048, 3);
        edr::Event event = ProcessStart(
            9102, "C:\\Windows\\System32\\netsh.exe",
            "netsh wlan export profile key=clear folder=C:\\Temp",
            1000 * kSecond);
        detector.Enrich(event);
        CHECK_WIFI(HasScore(event));
        /* wifi_profile_export(60) + wifi_key_clear(30) = 90. */
        CHECK_WIFI(event.fields.at(edr::field::kWifiTheftScore) == "90");
        CHECK_WIFI(event.fields.at(edr::field::kWifiTheftVerdict) ==
                   "MALICIOUS");
        CHECK_WIFI(event.fields.at(edr::field::kWifiTheftSignals)
                       .find("wifi_key_clear") != std::string::npos);
        CHECK_WIFI(event.fields.at(edr::field::kWifiTheftTools)
                       .find("netsh_key_clear") != std::string::npos);
    }
    std::fprintf(stderr, "[wifi-theft] TestPlainExportSuspicious\n");
    {
        edr::WifiCredTheftDetector detector(true, 300, 2048, 3);
        edr::Event event = ProcessStart(
            9103, "C:\\Windows\\System32\\netsh.exe",
            "netsh wlan export profile folder=C:\\Temp",
            1000 * kSecond);
        detector.Enrich(event);
        CHECK_WIFI(HasScore(event));
        CHECK_WIFI(event.fields.at(edr::field::kWifiTheftScore) == "60");
        CHECK_WIFI(event.fields.at(edr::field::kWifiTheftVerdict) ==
                   "SUSPICIOUS");
    }
    std::fprintf(stderr, "[wifi-theft] TestVaultEnum\n");
    {
        edr::WifiCredTheftDetector detector(true, 300, 2048, 3);
        edr::Event event = ProcessStart(
            9104, "C:\\Windows\\System32\\vaultcmd.exe",
            "VaultCmd /listcreds:\"Windows Credential Manager\"", 1000 *
                                                                    kSecond);
        detector.Enrich(event);
        CHECK_WIFI(HasScore(event));
        CHECK_WIFI(event.fields.at(edr::field::kWifiTheftScore) == "75");
        CHECK_WIFI(event.fields.at(edr::field::kWifiTheftSignals)
                       .find("vault_enum") != std::string::npos);
    }
    std::fprintf(stderr, "[wifi-theft] TestCmdkeyEnumRepeat\n");
    {
        edr::WifiCredTheftDetector detector(true, 300, 2048, 3);
        edr::Event last;
        for (uint32_t i = 0; i < 3; ++i) {
            last = ProcessStart(
                9105, "C:\\Windows\\System32\\cmdkey.exe",
                "cmdkey /list", (1000 + i) * kSecond);
            detector.Enrich(last);
        }
        CHECK_WIFI(HasScore(last));
        /* cmdkey_enum(55) + enum_repeat(15) = 70. */
        CHECK_WIFI(last.fields.at(edr::field::kWifiTheftScore) == "70");
        CHECK_WIFI(last.fields.at(edr::field::kWifiTheftSignals)
                       .find("enum_repeat") != std::string::npos);
        CHECK_WIFI(last.fields.at(edr::field::kWifiTheftEnumCount) == "3");
    }
    std::fprintf(stderr, "[wifi-theft] TestRdpSavedCreds\n");
    {
        edr::WifiCredTheftDetector detector(true, 300, 2048, 3);
        edr::Event event = ProcessStart(
            9106, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
                  "powershell.exe",
            "powershell.exe -c \"cmdkey /list | findstr /i domain\"",
            1000 * kSecond);
        detector.Enrich(event);
        CHECK_WIFI(HasScore(event));
        CHECK_WIFI(event.fields.at(edr::field::kWifiTheftScore) == "75");
        CHECK_WIFI(event.fields.at(edr::field::kWifiTheftSignals)
                       .find("rdp_saved_creds") != std::string::npos);
    }
    std::fprintf(stderr, "[wifi-theft] TestUnrelatedNetshIgnored\n");
    {
        edr::WifiCredTheftDetector detector(true, 300, 2048, 3);
        edr::Event event = ProcessStart(
            9107, "C:\\Windows\\System32\\netsh.exe",
            "netsh interface portproxy add v4tov4", 1000 * kSecond);
        detector.Enrich(event);
        CHECK_WIFI(!HasScore(event));
    }
    std::fprintf(stderr, "[wifi-theft] TestNormalProcessIgnored\n");
    {
        edr::WifiCredTheftDetector detector(true, 300, 2048, 3);
        edr::Event event = ProcessStart(
            9108, "C:\\Windows\\System32\\tasklist.exe",
            "tasklist.exe /v", 1000 * kSecond);
        detector.Enrich(event);
        CHECK_WIFI(!HasScore(event));
    }
    std::fprintf(stderr, "[wifi-theft] All tests passed\n");
}
