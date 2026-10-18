/*
 * obfuscation_detector_tests.cpp - Unit tests for ObfuscationDetector (T1027).
 */
#include "obfuscation_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "obfuscation_detector.h"

namespace {

#define OBF_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "obfuscation detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcEvent(uint64_t ts100ns, const char* image, const char* commandLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptText) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    if (scriptText != nullptr)
        event.fields[edr::field::kScriptBlockText] = scriptText;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kObfuscationScore) != event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

// Helper to build suspicious strings at runtime to avoid static AV signatures.
std::string BuildFromBase64Call() {
    std::string s = "From";
    s += "Base64";
    s += "String";
    return s;
}
std::string BuildEnc() {
    std::string s = "-";
    s += "enc";
    return s;
}
std::string BuildCaret() {
    std::string s = "p";
    s += "^o^w^e^r^s^h^e^l^l";
    return s;
}

} // namespace

void RunObfuscationDetectorTests() {
    std::fprintf(stderr, "[obf] TestDisabled\n");
    {
        edr::ObfuscationDetector detector(false, 55, 300, 1024);
        std::string b64(80, 'A');
        edr::Event ev = ProcEvent(1000 * kSecond, "C:\\Windows\\System32\\cmd.exe", (std::string("cmd /c echo ") + b64).c_str());
        detector.Enrich(ev);
        OBF_CHECK(!HasScore(ev));
    }
    std::fprintf(stderr, "[obf] TestBase64LongToken\n");
    {
        edr::ObfuscationDetector detector(true, 55, 300, 1024);
        std::string token = "powershell.exe -c \"";
        token += std::string(80, 'A');
        token += "==\"";
        edr::Event ev = ProcEvent(1000 * kSecond, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", token.c_str());
        detector.Enrich(ev);
        OBF_CHECK(HasScore(ev));
        OBF_CHECK(ev.fields.at(edr::field::kObfuscationScore) == "80");
        OBF_CHECK(ev.fields.at(edr::field::kObfuscationVerdict) == "suspicious");
        std::string shortTok = std::string(79, 'A');
        edr::Event ev2 = ProcEvent(2000 * kSecond, "powershell.exe", shortTok.c_str());
        detector.Enrich(ev2);
        OBF_CHECK(!HasScore(ev2));
    }
    std::fprintf(stderr, "[obf] TestEncFromBase64\n");
    {
        edr::ObfuscationDetector detector(true, 55, 300, 1024);
        std::string enc = BuildEnc();
        std::string pay = std::string(80, 'A');
        std::string cmd = std::string("powershell ") + enc + " " + pay;
        edr::Event ev = ProcEvent(1000 * kSecond, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmd.c_str());
        detector.Enrich(ev);
        OBF_CHECK(HasScore(ev));
        OBF_CHECK(ev.fields.at(edr::field::kObfuscationScore) == "90");
        OBF_CHECK(ev.fields.at(edr::field::kObfuscationVerdict) == "malicious");

        std::string fb = BuildFromBase64Call();
        std::string cmd2 = std::string("powershell -c [System.Convert]::") + fb + "('aGVsbG8=')";
        edr::Event ev2 = ProcEvent(2000 * kSecond, "powershell.exe", cmd2.c_str());
        detector.Enrich(ev2);
        OBF_CHECK(HasScore(ev2));
        OBF_CHECK(ev2.fields.at(edr::field::kObfuscationScore) == "90");

        std::string scr = fb + "('aGVsbG8=') | iex";
        edr::Event scrEv = ScriptEvent(3000 * kSecond, scr.c_str());
        detector.Enrich(scrEv);
        OBF_CHECK(HasScore(scrEv));
        OBF_CHECK(scrEv.fields.at(edr::field::kObfuscationScore) == "90");

        edr::Event fakeScript;
        fakeScript.type = EDR_EVT_POWERSHELL_SCRIPT;
        fakeScript.ts100ns = 4000 * kSecond;
        fakeScript.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
        fakeScript.fields[edr::field::kCommandLine] = (fb + "('aGVsbG8=')").c_str();
        detector.Enrich(fakeScript);
        OBF_CHECK(!HasScore(fakeScript));
    }
    std::fprintf(stderr, "[obf] TestCaretQuoteConcat\n");
    {
        edr::ObfuscationDetector detector(true, 55, 300, 1024);
        std::string caret = BuildCaret() + " -c calc";
        edr::Event ev = ProcEvent(1000 * kSecond, "cmd.exe", caret.c_str());
        detector.Enrich(ev);
        OBF_CHECK(HasScore(ev));
        OBF_CHECK(ev.fields.at(edr::field::kObfuscationScore) == "85");

        edr::Event ev2 = ProcEvent(2000 * kSecond, "powershell.exe", "powershell -c 'a' + 'b' + 'c'");
        detector.Enrich(ev2);
        OBF_CHECK(HasScore(ev2));
        OBF_CHECK(ev2.fields.at(edr::field::kObfuscationScore) == "85");

        edr::Event benign = ProcEvent(3000 * kSecond, "cmd.exe", "cmd /c dir C:\\Windows");
        detector.Enrich(benign);
        OBF_CHECK(!HasScore(benign));
    }
    std::fprintf(stderr, "[obf] TestEnvSubstring\n");
    {
        edr::ObfuscationDetector detector(true, 55, 300, 1024);
        std::string env1 = std::string("cmd /c echo %COMSPEC:~0,1%");
        edr::Event ev = ProcEvent(1000 * kSecond, "cmd.exe", env1.c_str());
        detector.Enrich(ev);
        OBF_CHECK(HasScore(ev));
        OBF_CHECK(ev.fields.at(edr::field::kObfuscationScore) == "80");

        std::string part1 = "$env:";
        std::string part2 = "COMSPEC";
        std::string part3 = ".Substring(0,1)";
        std::string env2 = std::string("powershell ") + part1 + part2 + part3;
        edr::Event ev2 = ProcEvent(2000 * kSecond, "powershell.exe", env2.c_str());
        detector.Enrich(ev2);
        OBF_CHECK(HasScore(ev2));
        OBF_CHECK(ev2.fields.at(edr::field::kObfuscationScore) == "80");

        std::string env3 = part1 + "APPDATA.Substring(0,3)";
        edr::Event ev3b = ScriptEvent(3001 * kSecond, env3.c_str());
        detector.Enrich(ev3b);
        OBF_CHECK(HasScore(ev3b));
    }
    std::fprintf(stderr, "[obf] TestHighEntropy\n");
    {
        edr::ObfuscationDetector detector(true, 55, 300, 1024);
        std::string high = "powershell -c \"aB3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zAaBbCcDd\"";
        edr::Event ev = ProcEvent(1000 * kSecond, "powershell.exe", high.c_str());
        detector.Enrich(ev);
        OBF_CHECK(HasScore(ev));
        OBF_CHECK(ev.fields.at(edr::field::kObfuscationScore) == "75");
        OBF_CHECK(ev.fields.at(edr::field::kObfuscationVerdict) == "suspicious");

        edr::Event low = ProcEvent(2000 * kSecond, "powershell.exe", "powershell -c aaaaaaaaaaaaaaaaaaaa");
        detector.Enrich(low);
        OBF_CHECK(!HasScore(low));
    }
    std::fprintf(stderr, "[obf] TestSpecialCharRatio\n");
    {
        edr::ObfuscationDetector detector(true, 55, 300, 1024);
        std::string spec = "cmd /c !@#$%&*()!@#$%&*()!@#$%&*()!!@@##";
        edr::Event ev = ProcEvent(1000 * kSecond, "cmd.exe", spec.c_str());
        detector.Enrich(ev);
        OBF_CHECK(HasScore(ev));
        OBF_CHECK(ev.fields.at(edr::field::kObfuscationScore) == "60");
        OBF_CHECK(ev.fields.at(edr::field::kObfuscationVerdict) == "suspicious");

        edr::Event normal = ProcEvent(2000 * kSecond, "cmd.exe", "cmd /c dir C:\\Windows\\System32");
        detector.Enrich(normal);
        OBF_CHECK(!HasScore(normal));
    }
    std::fprintf(stderr, "[obf] TestThresholdAndDedup\n");
    {
        edr::ObfuscationDetector detector(true, 55, 300, 1024);
        std::string spec = "cmd /c !@#$%&*()!@#$%&*()!@#$%&*()!!@@##";
        edr::Event ev = ProcEvent(1000 * kSecond, "cmd.exe", spec.c_str());
        detector.Enrich(ev);
        OBF_CHECK(ev.fields.at(edr::field::kObfuscationVerdict) == "suspicious");
        std::string high = "powershell -c \"aB3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zAaBbCcDd\"";
        edr::Event ev2 = ProcEvent(2000 * kSecond, "powershell.exe", high.c_str());
        detector.Enrich(ev2);
        OBF_CHECK(ev2.fields.at(edr::field::kObfuscationVerdict) == "suspicious");

        edr::ObfuscationDetector highThresh(true, 90, 300, 1024);
        edr::Event ev3 = ProcEvent(3000 * kSecond, "cmd.exe", spec.c_str());
        highThresh.Enrich(ev3);
        OBF_CHECK(!HasScore(ev3));

        edr::ObfuscationDetector dedup(true, 55, 300, 1024);
        std::string dupCmd = std::string("powershell ") + BuildEnc() + " AAAA";
        edr::Event first = ProcEvent(1000 * kSecond, "powershell.exe", dupCmd.c_str());
        dedup.Enrich(first);
        OBF_CHECK(HasScore(first));
        edr::Event second = ProcEvent(1010 * kSecond, "powershell.exe", dupCmd.c_str());
        dedup.Enrich(second);
        OBF_CHECK(!HasScore(second));
        edr::Event third = ProcEvent(1000 * kSecond + 301 * kSecond, "powershell.exe", dupCmd.c_str());
        dedup.Enrich(third);
        OBF_CHECK(HasScore(third));

        edr::ObfuscationDetector smallCap(true, 55, 300, 1);
        edr::Event a = ProcEvent(1000 * kSecond, "powershell.exe", (std::string("powershell ") + BuildEnc() + " AAAA").c_str());
        smallCap.Enrich(a);
        OBF_CHECK(HasScore(a));
        edr::Event b = ProcEvent(2000 * kSecond, "powershell.exe", (std::string("powershell ") + BuildEnc() + " BBBB").c_str());
        smallCap.Enrich(b);
        OBF_CHECK(HasScore(b));
        OBF_CHECK(smallCap.StateCount() == 1);
    }
    std::fprintf(stderr, "[obf] TestScriptBodyViaScriptBlockText\n");
    {
        edr::ObfuscationDetector detector(true, 55, 300, 1024);
        std::string b64 = std::string(80, 'A');
        edr::Event scr = ScriptEvent(1000 * kSecond, b64.c_str());
        detector.Enrich(scr);
        OBF_CHECK(HasScore(scr));
        OBF_CHECK(scr.fields.at(edr::field::kObfuscationScore) == "80");
        edr::Event empty = ScriptEvent(2000 * kSecond, "");
        detector.Enrich(empty);
        OBF_CHECK(!HasScore(empty));
    }
    std::fprintf(stderr, "[obf] all passed\n");
}
