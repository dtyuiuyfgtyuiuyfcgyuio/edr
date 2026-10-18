/*
 * sip_hijack_detector_tests.cpp - Unit tests for SipHijackDetector
 * (T1553.003 SIP and Trust Provider Hijacking).
 */
#include "sip_hijack_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "sip_hijack_detector.h"

namespace {

#define SIP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "sip hijack detector test failed at line " +
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

edr::Event RegEvent(uint64_t ts100ns, const char* regKey,
                    const char* regValue) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = regKey;
    if (regValue != nullptr)
        event.fields[edr::field::kRegValue] = regValue;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kSipHijackScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunSipHijackDetectorTests() {
    std::fprintf(stderr, "[sip-hijack] TestDisabled\n");
    {
        edr::SipHijackDetector detector(false, 55, 300, 1024);
        edr::Event event = RegEvent(
            1000 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\"
            "CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-"
            "00C04FC295EE}",
            "Dll");
        detector.Enrich(event);
        SIP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[sip-hijack] TestVerifyIndirectDataRepoint\n");
    {
        edr::SipHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            1000 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\"
            "CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-"
            "00C04FC295EE}",
            "C:\\Temp\\evilsip.dll");
        detector.Enrich(event);
        SIP_CHECK(Score(event) == "90");
        SIP_CHECK(event.fields.at(
            edr::field::kSipHijackVerdict) == "malicious");
    }
    std::fprintf(stderr, "[sip-hijack] TestTrustProviderFinalPolicy\n");
    {
        edr::SipHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            1001 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\"
            "FinalPolicy\\{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}",
            "$DLL");
        detector.Enrich(event);
        SIP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[sip-hijack] TestCommandPlaneRegAdd\n");
    {
        edr::SipHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1002 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\"
            "EncodingType 0\\CryptSIPDllGetSignedDataMsg\\{603BCC1F-4B59-"
            "4E08-B724-D2C6297EF351}\" /v Dll /t REG_SZ /d "
            "C:\\Temp\\bad.dll /f");
        detector.Enrich(event);
        SIP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[sip-hijack] TestScriptPlaneIsMyFileType\n");
    {
        edr::SipHijackDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_POWERSHELL_SCRIPT;
        event.ts100ns = 1003 * kSecond;
        event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        event.fields[edr::field::kImage] =
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        event.fields[edr::field::kScriptBlockText] =
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\"
            "Cryptography\\OID\\EncodingType 0\\CryptSIPDllIsMyFileType2\\"
            "{DE2B1F9C}' -Name Dll -Value C:\\Temp\\sip.dll";
        detector.Enrich(event);
        SIP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[sip-hijack] TestRegsvr32SipRegistration\n");
    {
        edr::SipHijackDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1004 * kSecond, "C:\\Windows\\System32\\regsvr32.exe",
            "regsvr32.exe /s C:\\Temp\\mysip.dll");
        detector.Enrich(event);
        SIP_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[sip-hijack] TestDedupWindow\n");
    {
        edr::SipHijackDetector detector(true, 55, 60, 1024);
        auto make = [](uint64_t ts) {
            return RegEvent(ts,
                "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\"
                "Initialization\\{GUID}", "C:\\Temp\\x.dll");
        };
        edr::Event first = make(2000 * kSecond);
        detector.Enrich(first);
        SIP_CHECK(Score(first) == "90");

        edr::Event repeat = make(2010 * kSecond);
        detector.Enrich(repeat);
        SIP_CHECK(Score(repeat).empty());

        edr::Event later = make(2100 * kSecond);
        detector.Enrich(later);
        SIP_CHECK(Score(later) == "90");
    }
    std::fprintf(stderr, "[sip-hijack] TestBenignSilent\n");
    {
        edr::SipHijackDetector detector(true, 55, 300, 1024);
        /* Read-only inspection of the same subtree. */
        edr::Event query = ProcEvent(
            1005 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query \"HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\"
            "EncodingType 0\\CryptSIPDllVerifyIndirectData\"");
        detector.Enrich(query);
        SIP_CHECK(Score(query).empty());

        /* Unrelated cryptography key. */
        edr::Event unrelated = RegEvent(
            1006 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid",
            "abcdef");
        detector.Enrich(unrelated);
        SIP_CHECK(Score(unrelated).empty());

        /* Ordinary regsvr32 with no SIP/wintrust hint. */
        edr::Event ocx = ProcEvent(
            1007 * kSecond, "C:\\Windows\\System32\\regsvr32.exe",
            "regsvr32.exe /s C:\\Program Files\\App\\grid.ocx");
        detector.Enrich(ocx);
        SIP_CHECK(Score(ocx).empty());
    }
    std::fprintf(stderr, "[sip-hijack] all passed\n");
}
