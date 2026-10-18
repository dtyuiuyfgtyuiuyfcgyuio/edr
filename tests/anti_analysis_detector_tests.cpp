#include "anti_analysis_detector_tests.h"

#include <stdexcept>
#include <string>
#include <cstdlib>

#include "edr_event.h"
#include "event_bus.h"
#include "anti_analysis_detector.h"

namespace {

#define AA_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond)
        throw std::runtime_error(
            "anti-analysis test failed at line " +
            std::to_string(line) + ": " + expr);
}

edr::Event ProcStart(const std::string& image, const std::string& cmd,
                     const std::string& parent, uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.pid = pid;
    ev.ts100ns = ts;
    ev.fields[edr::field::kImage] = image;
    ev.fields[edr::field::kCommandLine] = cmd;
    ev.fields[edr::field::kParentImage] = parent;
    return ev;
}

void TestVmDetectionArgs() {
    edr::AntiAnalysisDetector det(true, 300, 4096);
    const uint64_t base = 1000000000ULL;
    edr::Event ev = ProcStart(
        "C:\\malware\\sample.exe",
        "sample.exe --check-vm VMware VirtualBox qemu",
        "C:\\Windows\\explorer.exe", 10001, base);
    det.Enrich(ev);
    AA_CHECK(ev.fields.count(edr::field::kAntiAnalysisScore) > 0);
    AA_CHECK(ev.fields.at(edr::field::kAntiAnalysisScore) == "35");
    AA_CHECK(ev.fields.at(edr::field::kAntiAnalysisSignals).find("vm_check") !=
             std::string::npos);
}

void TestDebuggerDetectionArgs() {
    edr::AntiAnalysisDetector det(true, 300, 4096);
    const uint64_t base = 2000000000ULL;
    edr::Event ev = ProcStart(
        "C:\\malware\\sample.exe",
        "sample.exe --check IsDebuggerPresent BeingDebugged",
        "C:\\Windows\\explorer.exe", 10002, base);
    det.Enrich(ev);
    AA_CHECK(ev.fields.count(edr::field::kAntiAnalysisScore) > 0);
    AA_CHECK(ev.fields.at(edr::field::kAntiAnalysisScore) == "30");
    AA_CHECK(ev.fields.at(edr::field::kAntiAnalysisSignals).find("debugger_check") !=
             std::string::npos);
}

void TestAnalysisToolParent() {
    edr::AntiAnalysisDetector det(true, 300, 4096);
    const uint64_t base = 3000000000ULL;
    edr::Event ev = ProcStart(
        "C:\\malware\\sample.exe", "sample.exe",
        "C:\\Tools\\x64dbg.exe", 10003, base);
    det.Enrich(ev);
    AA_CHECK(ev.fields.count(edr::field::kAntiAnalysisScore) > 0);
    AA_CHECK(ev.fields.at(edr::field::kAntiAnalysisScore) == "20");
    AA_CHECK(ev.fields.at(edr::field::kAntiAnalysisSignals).find("analysis_tool_parent") !=
             std::string::npos);
}

void TestMultiSignalCorrelation() {
    edr::AntiAnalysisDetector det(true, 300, 4096);
    const uint64_t base = 4000000000ULL;
    edr::Event ev = ProcStart(
        "C:\\malware\\sample.exe",
        "sample.exe --vm VMware --debugger IsDebuggerPresent systeminfo",
        "C:\\Tools\\ida.exe", 10004, base);
    det.Enrich(ev);
    const uint32_t score = static_cast<uint32_t>(
        std::atoi(ev.fields.at(edr::field::kAntiAnalysisScore).c_str()));
    AA_CHECK(score >= 75);
    AA_CHECK(ev.fields.at(edr::field::kAntiAnalysisVerdict) == "MALICIOUS");
}

void TestCleanProcessNoStamp() {
    edr::AntiAnalysisDetector det(true, 300, 4096);
    const uint64_t base = 5000000000ULL;
    edr::Event ev = ProcStart(
        "C:\\Windows\\System32\\notepad.exe", "notepad.exe",
        "C:\\Windows\\explorer.exe", 10005, base);
    det.Enrich(ev);
    AA_CHECK(ev.fields.find(edr::field::kAntiAnalysisScore) == ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::AntiAnalysisDetector det(false, 300, 4096);
    const uint64_t base = 6000000000ULL;
    edr::Event ev = ProcStart(
        "C:\\malware\\sample.exe",
        "sample.exe --check-vm VMware",
        "C:\\Windows\\explorer.exe", 10006, base);
    det.Enrich(ev);
    AA_CHECK(ev.fields.find(edr::field::kAntiAnalysisScore) == ev.fields.end());
}

} // namespace

void RunAntiAnalysisDetectorTests() {
    TestVmDetectionArgs();
    TestDebuggerDetectionArgs();
    TestAnalysisToolParent();
    TestMultiSignalCorrelation();
    TestCleanProcessNoStamp();
    TestDisabledNoStamp();
}
