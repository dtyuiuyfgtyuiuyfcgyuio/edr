/*
 * dpapi_abuse_detector_tests.cpp - Unit tests for DpapiAbuseDetector.
 */
#include "dpapi_abuse_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "dpapi_abuse_detector.h"

namespace {

#define DA_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "dpapi abuse detector test failed at line " +
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

/* House contract: a POWERSHELL_SCRIPT event carries its body ONLY in
 * kScriptBlockText - never kCommandLine/kImage. */
edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptBody) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptBody;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kDpapiAbuseScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunDpapiAbuseDetectorTests() {
    std::fprintf(stderr, "[dpapi-abuse] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::DpapiAbuseDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond,
            "C:\\Tools\\SharpDPAPI.exe", "SharpDPAPI triage");
        detector.Enrich(event);
        DA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[dpapi-abuse] TestToolingInvoked\n");
    {
        edr::DpapiAbuseDetector detector(true, 55, 300, 1024);
        /* SharpDPAPI / mimikatz dpapi module -> 90 malicious. */
        edr::Event sharp = ProcEvent(1000 * kSecond,
                                     "C:\\Tools\\SharpDPAPI.exe",
                                     "SharpDPAPI triage -mkfile mk.txt");
        detector.Enrich(sharp);
        DA_CHECK(Score(sharp) == "90");
        DA_CHECK(sharp.fields.at(edr::field::kDpapiAbuseVerdict) ==
                 "malicious");

        edr::Event mimi = ProcEvent(1010 * kSecond,
                                    "C:\\Temp\\mimikatz.exe",
                                    "mimikatz # sekurlsa::dpapi");
        detector.Enrich(mimi);
        DA_CHECK(Score(mimi) == "90");
    }
    std::fprintf(stderr, "[dpapi-abuse] TestMasterkeyFlow\n");
    {
        edr::DpapiAbuseDetector detector(true, 55, 300, 1024);
        /* dpapi + masterkey primitives -> 85. */
        edr::Event flow = ScriptEvent(
            1000 * kSecond,
            "[System.Security.Cryptography.ProtectedData]::Unprotect("
            "$blob, $null, 'CurrentUser')  # dpapi masterkey sha1 "
            "recovery");
        detector.Enrich(flow);
        DA_CHECK(Score(flow) == "85");

        /* Browser store + masterkey decryption -> 85. */
        edr::Event browser = ScriptEvent(
            1010 * kSecond,
            "Copy-Item .\\Login Data .\\loot; dpapi masterkey decrypt");
        detector.Enrich(browser);
        DA_CHECK(Score(browser) == "85");
    }
    std::fprintf(stderr, "[dpapi-abuse] TestBrowserStoreDecrypt\n");
    {
        edr::DpapiAbuseDetector detector(true, 55, 300, 1024);
        /* Browser credential store + decrypt primitive -> 75. */
        edr::Event chrome = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "type \"AppData\\Local\\Google\\Chrome\\User Data\\"
            "Local State\" && findstr cryptunprotect");
        detector.Enrich(chrome);
        DA_CHECK(Score(chrome) == "75");
        DA_CHECK(chrome.fields.at(edr::field::kDpapiAbuseVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[dpapi-abuse] TestVaultAndCmdkey\n");
    {
        edr::DpapiAbuseDetector detector(true, 55, 300, 1024);
        /* vaultcmd enumeration -> 65 suspicious. */
        edr::Event vault = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\vaultcmd.exe",
            "vaultcmd /listcreds:\"Windows Credentials\"");
        detector.Enrich(vault);
        DA_CHECK(Score(vault) == "65");
        DA_CHECK(vault.fields.at(edr::field::kDpapiAbuseVerdict) ==
                 "suspicious");

        /* cmdkey /list -> 60 suspicious. */
        edr::Event cmdkey = ProcEvent(
            1001 * kSecond, "C:\\Windows\\System32\\cmdkey.exe",
            "cmdkey /list");
        detector.Enrich(cmdkey);
        DA_CHECK(Score(cmdkey) == "60");
    }
    std::fprintf(stderr, "[dpapi-abuse] TestBelowThresholdSuppressed\n");
    {
        /* A high min_score suppresses the low bands but keeps the
         * tooling band - independent instances per case (min_score
         * isolation lesson). */
        edr::DpapiAbuseDetector strict(true, 90, 300, 1024);
        edr::Event cmdkey = ProcEvent(1000 * kSecond,
                                      "C:\\Windows\\System32\\cmdkey.exe",
                                      "cmdkey /list");
        strict.Enrich(cmdkey);
        DA_CHECK(Score(cmdkey).empty());

        edr::Event sharp = ProcEvent(1010 * kSecond,
                                     "C:\\Tools\\SharpDPAPI.exe",
                                     "SharpDPAPI triage");
        strict.Enrich(sharp);
        DA_CHECK(Score(sharp) == "90");
    }
    std::fprintf(stderr, "[dpapi-abuse] TestDedupWindow\n");
    {
        edr::DpapiAbuseDetector detector(true, 55, 60, 1024);
        const char* cmd = "cmdkey /list";
        edr::Event first = ProcEvent(1000 * kSecond,
                                     "C:\\Windows\\System32\\cmdkey.exe",
                                     cmd);
        detector.Enrich(first);
        DA_CHECK(!Score(first).empty());

        /* Same text inside the dedup window is suppressed. */
        edr::Event second = ProcEvent(1030 * kSecond,
                                      "C:\\Windows\\System32\\cmdkey.exe",
                                      cmd);
        detector.Enrich(second);
        DA_CHECK(Score(second).empty());

        /* Outside the window the alert re-arms. */
        edr::Event third = ProcEvent(1100 * kSecond,
                                     "C:\\Windows\\System32\\cmdkey.exe",
                                     cmd);
        detector.Enrich(third);
        DA_CHECK(!Score(third).empty());
    }
    std::fprintf(stderr, "[dpapi-abuse] TestCleanTrafficSilent\n");
    {
        edr::DpapiAbuseDetector detector(true, 55, 300, 1024);
        edr::Event clean = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\notepad.exe",
            "notepad readme.txt");
        detector.Enrich(clean);
        DA_CHECK(Score(clean).empty());
        /* No verdict field below 55 (house contract). */
        DA_CHECK(clean.fields.find(edr::field::kDpapiAbuseVerdict) ==
                 clean.fields.end());
    }
    std::fprintf(stderr, "[dpapi-abuse] all passed\n");
}
