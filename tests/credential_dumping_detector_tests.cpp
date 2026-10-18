#include "credential_dumping_detector_tests.h"

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "credential_dumping_detector.h"

namespace {

#define CD_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond)
        throw std::runtime_error(
            "credential dumping test failed at line " +
            std::to_string(line) + ": " + expr);
}

edr::Event ProcAccess(const std::string& targetImage,
                      const std::string& accessMask,
                      uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_ACCESS;
    ev.pid = pid;
    ev.ts100ns = ts;
    ev.fields[edr::field::kTargetImage] = targetImage;
    ev.fields[edr::field::kAccessMask] = accessMask;
    return ev;
}

edr::Event FileRead(const std::string& path, uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_FILE_READ;
    ev.pid = pid;
    ev.ts100ns = ts;
    ev.fields[edr::field::kFilePath] = path;
    return ev;
}

edr::Event RegWrite(const std::string& key, uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_REG_WRITE;
    ev.pid = pid;
    ev.ts100ns = ts;
    ev.fields[edr::field::kRegKey] = key;
    return ev;
}

edr::Event NamedPipe(const std::string& name, uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_NAMED_PIPE;
    ev.ts100ns = ts;
    ev.fields[edr::field::kPid] = std::to_string(pid);
    ev.fields[edr::field::kPipeName] = name;
    ev.fields[edr::field::kPipeOperation] = "created";
    return ev;
}

/* A lone weak signal scores below 55 and therefore must NOT be stamped:
 * the house scoring contract defines no verdict below 55, and every rule band
 * in rules.json starts at 55, so a stamped 25/30/35/40/50 field would be a
 * dead letter that no rule can ever consume. */

void TestLsassAccessAloneIsSubThreshold() {
    edr::CredentialDumpingDetector det(true, 300, 4096);
    const uint64_t base = 1000000000ULL;
    edr::Event ev = ProcAccess("C:\\Windows\\System32\\lsass.exe", "1f0fff",
                               5001, base);
    det.Enrich(ev);
    /* lsass_access alone = 50, one point under the SUSPICIOUS floor. */
    CD_CHECK(ev.fields.count(edr::field::kCredentialDumpScore) == 0);
    CD_CHECK(ev.fields.count(edr::field::kCredentialDumpVerdict) == 0);
}

void TestSamFileAloneIsSubThreshold() {
    edr::CredentialDumpingDetector det(true, 300, 4096);
    const uint64_t base = 2000000000ULL;
    edr::Event ev = FileRead(
        "C:\\Windows\\System32\\config\\SAM", 5002, base);
    det.Enrich(ev);
    /* sam_file alone = 35. */
    CD_CHECK(ev.fields.count(edr::field::kCredentialDumpScore) == 0);
}

void TestNtdsDitAloneIsSubThreshold() {
    edr::CredentialDumpingDetector det(true, 300, 4096);
    const uint64_t base = 3000000000ULL;
    edr::Event ev = FileRead(
        "C:\\Windows\\NTDS\\ntds.dit", 5003, base);
    det.Enrich(ev);
    /* ntds_dit alone = 40. */
    CD_CHECK(ev.fields.count(edr::field::kCredentialDumpScore) == 0);
}

void TestRegSaveAloneIsSubThreshold() {
    edr::CredentialDumpingDetector det(true, 300, 4096);
    const uint64_t base = 4000000000ULL;
    edr::Event ev = RegWrite("HKLM\\SAM", 5004, base);
    det.Enrich(ev);
    /* reg_save alone = 30. */
    CD_CHECK(ev.fields.count(edr::field::kCredentialDumpScore) == 0);
}

void TestSuspiciousPipeAloneIsSubThreshold() {
    edr::CredentialDumpingDetector det(true, 300, 4096);
    const uint64_t base = 5000000000ULL;
    edr::Event ev = NamedPipe("\\\\.\\pipe\\mimikatz", 5005, base);
    det.Enrich(ev);
    /* pipe alone = 25. */
    CD_CHECK(ev.fields.count(edr::field::kCredentialDumpScore) == 0);
}

void TestPipePlusImageLoadIsSubThreshold() {
    edr::CredentialDumpingDetector det(true, 300, 4096);
    const uint64_t base = 5500000000ULL;
    edr::Event pipe = NamedPipe("\\\\.\\pipe\\mimikatz", 5055, base);
    det.Enrich(pipe);
    edr::Event image;
    image.type = EDR_EVT_IMAGE_LOAD;
    image.pid = 5055;
    image.ts100ns = base + 10000000;
    image.fields[edr::field::kPid] = "5055";
    image.fields[edr::field::kTargetImage] =
        "C:\\Windows\\System32\\lsass.exe";
    image.fields[edr::field::kImageLoaded] = "C:\\Temp\\mimilib.dll";
    det.Enrich(image);
    /* pipe(25) + image_load(20) + 2-signal bonus(15) = 60 -> clears the bar. */
    CD_CHECK(image.fields.count(edr::field::kCredentialDumpScore) > 0);
    CD_CHECK(image.fields.at(edr::field::kCredentialDumpScore) == "60");
    CD_CHECK(image.fields.at(edr::field::kCredentialDumpVerdict) ==
             "SUSPICIOUS");
    const std::string signals =
        image.fields.at(edr::field::kCredentialDumpSignals);
    CD_CHECK(signals.find("pipe") != std::string::npos);
    CD_CHECK(signals.find("image_load") != std::string::npos);
}

/* The 55 floor sits exactly at a reachable value: sam_file(35) + reg_save(30)
 * + 2-signal bonus(15) = 80, while a single weak signal must stay silent. */
void TestScoreFloorBoundary() {
    edr::CredentialDumpingDetector det(true, 300, 4096);
    const uint64_t base = 5600000000ULL;
    edr::Event sam = FileRead("C:\\Windows\\System32\\config\\SAM", 5060, base);
    det.Enrich(sam);
    edr::Event ev = RegWrite("HKLM\\SECURITY", 5060, base + 10000000);
    det.Enrich(ev);
    CD_CHECK(ev.fields.at(edr::field::kCredentialDumpScore) == "80");
    CD_CHECK(ev.fields.at(edr::field::kCredentialDumpVerdict) == "MALICIOUS");
}

void TestMultiSignalCorrelation() {
    edr::CredentialDumpingDetector det(true, 300, 4096);
    const uint64_t base = 6000000000ULL;
    edr::Event lsass = ProcAccess("C:\\Windows\\System32\\lsass.exe",
                                  "1f0fff", 5006, base);
    det.Enrich(lsass);
    edr::Event ev = FileRead(
        "C:\\Windows\\System32\\config\\SAM", 5006, base + 10000000);
    det.Enrich(ev);
    CD_CHECK(ev.fields.at(edr::field::kCredentialDumpScore) == "100");
    CD_CHECK(ev.fields.at(edr::field::kCredentialDumpVerdict) == "MALICIOUS");
}

void TestNonLsassNoStamp() {
    edr::CredentialDumpingDetector det(true, 300, 4096);
    const uint64_t base = 7000000000ULL;
    edr::Event ev = ProcAccess("C:\\Windows\\System32\\notepad.exe", "1f0fff",
                               5007, base);
    det.Enrich(ev);
    CD_CHECK(ev.fields.find(edr::field::kCredentialDumpScore) ==
             ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::CredentialDumpingDetector det(false, 300, 4096);
    const uint64_t base = 8000000000ULL;
    edr::Event ev = ProcAccess("C:\\Windows\\System32\\lsass.exe", "1f0fff",
                               5008, base);
    det.Enrich(ev);
    CD_CHECK(ev.fields.find(edr::field::kCredentialDumpScore) ==
             ev.fields.end());
}

} // namespace

void RunCredentialDumpingDetectorTests() {
    TestLsassAccessAloneIsSubThreshold();
    TestSamFileAloneIsSubThreshold();
    TestNtdsDitAloneIsSubThreshold();
    TestRegSaveAloneIsSubThreshold();
    TestSuspiciousPipeAloneIsSubThreshold();
    TestPipePlusImageLoadIsSubThreshold();
    TestScoreFloorBoundary();
    TestMultiSignalCorrelation();
    TestNonLsassNoStamp();
    TestDisabledNoStamp();
}
