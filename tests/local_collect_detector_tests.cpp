/*
 * local_collect_detector_tests.cpp - Unit tests for LocalCollectDetector (T1005).
 */
#include "local_collect_detector_tests.h"

#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "local_collect_detector.h"

namespace {

#define LC_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error(
            "local_collect detector test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

constexpr uint64_t kSecond = 10000000ULL;

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

edr::Event FileCreate(const std::string& path, uint32_t pid, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_FILE_CREATE;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kType] = "FILE_CREATE";
    ev.fields[edr::field::kFilePath] = path;
    ev.fields[edr::field::kFileAction] = "added";
    return ev;
}

edr::Event FileRead(const std::string& path, uint32_t pid, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_FILE_READ;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kType] = "FILE_READ";
    ev.fields[edr::field::kFilePath] = path;
    return ev;
}

bool Has(const edr::Event& ev, const char* name) {
    return ev.fields.find(name) != ev.fields.end();
}

/* Feed n FILE_READ events of document files under a profile dir for one pid. */
edr::Event FeedDocReads(edr::LocalCollectDetector& d, uint32_t pid,
                        uint64_t baseTs, size_t n) {
    edr::Event last;
    for (size_t i = 0; i < n; ++i) {
        std::string path = "C:\\Users\\bob\\Documents\\doc" +
                           std::to_string(i) + ".pdf";
        last = FileRead(path, pid, baseTs + static_cast<uint64_t>(i) * kSecond);
        d.Enrich(last);
    }
    return last;
}

void TestInspectsWhitelist() {
    std::fprintf(stderr, "[local_collect] TestInspectsWhitelist\n");
    LC_CHECK(edr::LocalCollectDetector::Inspects(EDR_EVT_FILE_CREATE));
    LC_CHECK(edr::LocalCollectDetector::Inspects(EDR_EVT_FILE_READ));
    LC_CHECK(edr::LocalCollectDetector::Inspects(EDR_EVT_PROCESS_START));
    LC_CHECK(!edr::LocalCollectDetector::Inspects(EDR_EVT_NET_CONNECT));
    LC_CHECK(!edr::LocalCollectDetector::Inspects(EDR_EVT_REG_WRITE));
    LC_CHECK(!edr::LocalCollectDetector::Inspects(EDR_EVT_FILE_DELETE));
    LC_CHECK(!edr::LocalCollectDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
}

void TestProfileEnumCopy() {
    std::fprintf(stderr, "[local_collect] TestProfileEnumCopy\n");
    edr::LocalCollectDetector d(true, 55, 300, 1024);
    const uint64_t base = 1000 * kSecond;
    d.Enrich(ProcessStart("cmd.exe",
        "cmd /c dir /s C:\\Users\\bob\\Documents", 1001, base));
    edr::Event ev = FileCreate(
        "C:\\Users\\bob\\AppData\\Local\\Temp\\coll\\notes.docx", 1001,
        base + 10 * kSecond);
    d.Enrich(ev);
    LC_CHECK(Has(ev, edr::field::kLocalCollectScore));
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectScore) == "60");
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectVerdict) == "suspicious");
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectSignals)
                 .find("profile_enumeration") != std::string::npos);
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectSignals)
                 .find("staging_copy") != std::string::npos);
}

void TestProfileEnumFullImagePath() {
    std::fprintf(stderr, "[local_collect] TestProfileEnumFullImagePath\n");
    edr::LocalCollectDetector d(true, 55, 300, 1024);
    const uint64_t base = 1750 * kSecond;
    d.Enrich(ProcessStart("C:\\Windows\\System32\\cmd.exe",
        "cmd /c dir /s C:\\Users\\bob\\Documents", 1007, base));
    edr::Event ev = FileCreate(
        "C:\\Users\\bob\\AppData\\Local\\Temp\\coll\\notes.docx",
        1007, base + 10 * kSecond);
    d.Enrich(ev);
    LC_CHECK(Has(ev, edr::field::kLocalCollectScore));
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectScore) == "60");
}

void TestCompressArchiveProfile() {
    std::fprintf(stderr, "[local_collect] TestCompressArchiveProfile\n");
    edr::LocalCollectDetector d(true, 55, 300, 1024);
    const uint64_t base = 2000 * kSecond;
    d.Enrich(ProcessStart("powershell.exe",
        "powershell -Command Compress-Archive -Path C:\\Users\\bob\\Documents "
        "-DestinationPath C:\\Users\\bob\\AppData\\Local\\Temp\\docs.zip",
        1002, base));
    edr::Event ev = ProcessStart("cmd.exe",
        "cmd /c dir /s C:\\Users\\bob\\Documents", 1002,
        base + 10 * kSecond);
    d.Enrich(ev);
    LC_CHECK(Has(ev, edr::field::kLocalCollectScore));
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectScore) == "75");
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectVerdict) == "malicious");
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectSignals)
                 .find("archive_packaging") != std::string::npos);
}

void TestStagingLanding() {
    std::fprintf(stderr, "[local_collect] TestStagingLanding\n");
    edr::LocalCollectDetector d(true, 55, 300, 1024);
    const uint64_t base = 3000 * kSecond;
    FeedDocReads(d, 1003, base, 10);
    edr::Event ev = FileCreate(
        "C:\\Users\\bob\\AppData\\Local\\Temp\\coll\\doc0.pdf", 1003,
        base + 20 * kSecond);
    d.Enrich(ev);
    LC_CHECK(Has(ev, edr::field::kLocalCollectScore));
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectScore) == "65");
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectVerdict) == "suspicious");
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectSignals)
                 .find("staging_landing") != std::string::npos);
}

void TestDocBurstHit() {
    std::fprintf(stderr, "[local_collect] TestDocBurstHit\n");
    edr::LocalCollectDetector d(true, 55, 300, 1024);
    const uint64_t base = 4000 * kSecond;
    FeedDocReads(d, 1004, base, 20);
    edr::Event ev = FileCreate(
        "C:\\Users\\bob\\AppData\\Local\\Temp\\coll\\doc0.pdf", 1004,
        base + 30 * kSecond);
    d.Enrich(ev);
    LC_CHECK(Has(ev, edr::field::kLocalCollectScore));
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectScore) == "75");
    LC_CHECK(ev.fields.at(edr::field::kLocalCollectVerdict) == "malicious");
}

void TestNormalSingleRead() {
    std::fprintf(stderr, "[local_collect] TestNormalSingleRead\n");
    edr::LocalCollectDetector d(true, 55, 300, 1024);
    edr::Event ev = FileRead(
        "C:\\Users\\bob\\Documents\\notes.txt", 1005, 5000 * kSecond);
    d.Enrich(ev);
    LC_CHECK(!Has(ev, edr::field::kLocalCollectScore));
    LC_CHECK(!Has(ev, edr::field::kLocalCollectVerdict));
}

void TestNormalArchivingSilent() {
    std::fprintf(stderr, "[local_collect] TestNormalArchivingSilent\n");
    edr::LocalCollectDetector d(true, 55, 300, 1024);
    edr::Event ev = ProcessStart("powershell.exe",
        "powershell -Command Compress-Archive -Path C:\\Projects\\myapp "
        "-DestinationPath C:\\Temp\\myapp.zip", 1006, 6000 * kSecond);
    d.Enrich(ev);
    LC_CHECK(!Has(ev, edr::field::kLocalCollectScore));
}

void TestDisabled() {
    std::fprintf(stderr, "[local_collect] TestDisabled\n");
    edr::LocalCollectDetector d(false, 55, 300, 1024);
    edr::Event ev = FileCreate(
        "C:\\Users\\bob\\AppData\\Local\\Temp\\coll\\notes.docx", 1007,
        7000 * kSecond);
    d.Enrich(ev);
    LC_CHECK(!Has(ev, edr::field::kLocalCollectScore));
    LC_CHECK(d.StateCount() == 0);
}

void TestBoundary54_55() {
    std::fprintf(stderr, "[local_collect] TestBoundary54_55\n");
    /* 54 doc reads (dedup disabled) -> 54, fully silent. */
    {
        edr::LocalCollectDetector d(true, 55, 0, 1024);
        edr::Event last = FeedDocReads(d, 2001, 8000 * kSecond, 54);
        LC_CHECK(!Has(last, edr::field::kLocalCollectScore));
        LC_CHECK(!Has(last, edr::field::kLocalCollectVerdict));
    }
    /* 55 doc reads -> exactly 55, suspicious. */
    {
        edr::LocalCollectDetector d(true, 55, 0, 1024);
        edr::Event last = FeedDocReads(d, 2002, 9000 * kSecond, 55);
        LC_CHECK(Has(last, edr::field::kLocalCollectScore));
        LC_CHECK(last.fields.at(edr::field::kLocalCollectScore) == "55");
        LC_CHECK(last.fields.at(edr::field::kLocalCollectVerdict) == "suspicious");
    }
}

void TestBoundary74_75() {
    std::fprintf(stderr, "[local_collect] TestBoundary74_75\n");
    /* 74 doc reads -> 74, suspicious. */
    {
        edr::LocalCollectDetector d(true, 55, 0, 1024);
        edr::Event last = FeedDocReads(d, 2003, 10000 * kSecond, 74);
        LC_CHECK(Has(last, edr::field::kLocalCollectScore));
        LC_CHECK(last.fields.at(edr::field::kLocalCollectScore) == "74");
        LC_CHECK(last.fields.at(edr::field::kLocalCollectVerdict) == "suspicious");
    }
    /* 75 doc reads -> 75, malicious. */
    {
        edr::LocalCollectDetector d(true, 55, 0, 1024);
        edr::Event last = FeedDocReads(d, 2004, 11000 * kSecond, 75);
        LC_CHECK(Has(last, edr::field::kLocalCollectScore));
        LC_CHECK(last.fields.at(edr::field::kLocalCollectScore) == "75");
        LC_CHECK(last.fields.at(edr::field::kLocalCollectVerdict) == "malicious");
    }
}

void TestDedupWindow() {
    std::fprintf(stderr, "[local_collect] TestDedupWindow\n");
    edr::LocalCollectDetector d(true, 55, 300, 1024);
    const uint64_t base = 12000 * kSecond;
    d.Enrich(ProcessStart("cmd.exe",
        "cmd /c dir /s C:\\Users\\bob\\Documents", 3001, base));
    edr::Event stamped = FileCreate(
        "C:\\Users\\bob\\AppData\\Local\\Temp\\coll\\a.docx", 3001,
        base + 10 * kSecond);
    d.Enrich(stamped);
    LC_CHECK(Has(stamped, edr::field::kLocalCollectScore));
    LC_CHECK(stamped.fields.at(edr::field::kLocalCollectScore) == "60");
    /* Within dedup window: re-stamp suppressed. */
    edr::Event suppressed = FileCreate(
        "C:\\Users\\bob\\AppData\\Local\\Temp\\coll\\b.docx", 3001,
        base + 20 * kSecond);
    d.Enrich(suppressed);
    LC_CHECK(!Has(suppressed, edr::field::kLocalCollectScore));
    /* After dedup window (and before state expiry): re-stamp again. */
    edr::Event restamped = FileCreate(
        "C:\\Users\\bob\\AppData\\Local\\Temp\\coll\\c.docx", 3001,
        base + 315 * kSecond);
    d.Enrich(restamped);
    LC_CHECK(Has(restamped, edr::field::kLocalCollectScore));
    LC_CHECK(restamped.fields.at(edr::field::kLocalCollectScore) == "60");
}

void TestStateCapacity() {
    std::fprintf(stderr, "[local_collect] TestStateCapacity\n");
    edr::LocalCollectDetector d(true, 55, 300, 4);
    for (uint32_t pid = 1; pid <= 6; ++pid) {
        d.Enrich(FileRead(
            "C:\\Users\\bob\\Documents\\f" + std::to_string(pid) + ".pdf",
            pid, (13000ULL + pid) * kSecond));
    }
    LC_CHECK(d.StateCount() <= 4);
}

void TestTimeBackward() {
    std::fprintf(stderr, "[local_collect] TestTimeBackward\n");
    edr::LocalCollectDetector d(true, 55, 300, 1024);
    const uint64_t base = 14000 * kSecond;
    d.Enrich(ProcessStart("cmd.exe",
        "cmd /c dir /s C:\\Users\\bob\\Documents", 4001, base));
    edr::Event stamped = FileCreate(
        "C:\\Users\\bob\\AppData\\Local\\Temp\\coll\\a.docx", 4001,
        base + 10 * kSecond);
    d.Enrich(stamped);
    LC_CHECK(Has(stamped, edr::field::kLocalCollectScore));
    /* Out-of-order (future lastSeen) event must be ignored. */
    edr::Event backward = FileCreate(
        "C:\\Users\\bob\\AppData\\Local\\Temp\\coll\\b.docx", 4001, base);
    d.Enrich(backward);
    LC_CHECK(!Has(backward, edr::field::kLocalCollectScore));
    LC_CHECK(d.StateCount() == 1);
}

void TestMinScoreConfig() {
    std::fprintf(stderr, "[local_collect] TestMinScoreConfig\n");
    /* minScore 90: a 75-point detection is still silent. */
    edr::LocalCollectDetector d(true, 90, 300, 1024);
    const uint64_t base = 15000 * kSecond;
    d.Enrich(ProcessStart("powershell.exe",
        "powershell -Command Compress-Archive -Path C:\\Users\\bob\\Documents "
        "-DestinationPath C:\\Users\\bob\\AppData\\Local\\Temp\\docs.zip",
        5001, base));
    edr::Event ev = ProcessStart("cmd.exe",
        "cmd /c dir /s C:\\Users\\bob\\Documents", 5001,
        base + 10 * kSecond);
    d.Enrich(ev);
    LC_CHECK(!Has(ev, edr::field::kLocalCollectScore));
}

} // namespace

void RunLocalCollectDetectorTests() {
    TestInspectsWhitelist();
    TestProfileEnumCopy();
    TestProfileEnumFullImagePath();
    TestCompressArchiveProfile();
    TestStagingLanding();
    TestDocBurstHit();
    TestNormalSingleRead();
    TestNormalArchivingSilent();
    TestDisabled();
    TestBoundary54_55();
    TestBoundary74_75();
    TestDedupWindow();
    TestStateCapacity();
    TestTimeBackward();
    TestMinScoreConfig();
    std::fprintf(stderr, "[local_collect] all passed\n");
}
