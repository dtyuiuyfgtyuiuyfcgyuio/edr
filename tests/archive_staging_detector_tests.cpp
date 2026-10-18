#include "archive_staging_detector_tests.h"

#include <algorithm>
#include <cstdlib>
#include <stdexcept>
#include <string>

#include "archive_staging_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define AS_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond) {
        throw std::runtime_error(
            "archive staging detector test failed at line " +
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
                      uint32_t pid, uint64_t ts100ns, const char* action = "added") {
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

edr::Event FileRead(const std::string& path, const std::string& image,
                    uint32_t pid, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_FILE_READ;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kType] = "FILE_READ";
    ev.fields[edr::field::kFilePath] = path;
    ev.fields[edr::field::kImage] = image;
    return ev;
}

edr::Event FileRename(const std::string& oldPath, const std::string& image,
                      uint32_t pid, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_FILE_RENAME;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kType] = "FILE_RENAME";
    ev.fields[edr::field::kOldFilePath] = oldPath;
    ev.fields[edr::field::kImage] = image;
    return ev;
}

void TestArchiveToolStart() {
    edr::ArchiveStagingDetector detector(true, 300, 1024);
    edr::Event ev = ProcessStart(
        "C:\\Program Files\\7-Zip\\7z.exe",
        "7z.exe x C:\\Users\\bob\\Downloads\\payload.zip -oC:\\Users\\bob\\AppData\\Local\\Temp",
        9001, 1000000000ULL);
    detector.Enrich(ev);
    /* Tool start with explicit extraction flags scores 25 (tool) + 25
     * (extraction), still below the 55 alerting band. */
    AS_CHECK(ev.fields.at(edr::field::kArchiveStagingScore) == "50");
    AS_CHECK(ev.fields.at(edr::field::kArchiveStagingTools).find("7z.exe") != std::string::npos);
    AS_CHECK(ev.fields.find(edr::field::kArchiveStagingVerdict) ==
             ev.fields.end());
}

void TestArchiveReadAndTempExtraction() {
    edr::ArchiveStagingDetector detector(true, 300, 1024);
    const uint64_t base = 2000000000ULL;
    detector.Enrich(FileRead(
        "C:\\Users\\bob\\Downloads\\payload.zip",
        "C:\\Program Files\\7-Zip\\7z.exe", 9002, base));
    edr::Event ev = FileCreate(
        "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe",
        "C:\\Program Files\\7-Zip\\7z.exe", 9002, base + 10000000ULL);
    detector.Enrich(ev);
    AS_CHECK(ev.fields.at(edr::field::kArchiveStagingScore) == "60");
    AS_CHECK(ev.fields.at(edr::field::kArchiveStagingVerdict) == "SUSPICIOUS");
    AS_CHECK(ev.fields.at(edr::field::kArchiveStagingSignals).find("archive_read") != std::string::npos);
    AS_CHECK(ev.fields.at(edr::field::kArchiveStagingSignals).find("temp_extract") != std::string::npos);
}

void TestArchiveRenameExtraction() {
    edr::ArchiveStagingDetector detector(true, 300, 1024);
    const uint64_t base = 3000000000ULL;
    detector.Enrich(FileRename(
        "C:\\Users\\bob\\Downloads\\payload.rar",
        "C:\\Program Files\\WinRAR\\winrar.exe", 9003, base));
    edr::Event ev = FileCreate(
        "C:\\Users\\bob\\Downloads\\stage\\evil.dll",
        "C:\\Program Files\\WinRAR\\winrar.exe", 9003, base + 10000000ULL);
    detector.Enrich(ev);
    /* Archive rename (create 20) + suspicious-location writes by an
     * extraction tool (temp-extract 20 + extraction 25) = 65. */
    AS_CHECK(ev.fields.at(edr::field::kArchiveStagingScore) == "65");
    AS_CHECK(ev.fields.at(edr::field::kArchiveStagingVerdict) == "SUSPICIOUS");
    AS_CHECK(ev.fields.at(edr::field::kArchiveStagingExtractedCount) == "2");
}

void TestNonArchiveNoStamp() {
    edr::ArchiveStagingDetector detector(true, 300, 1024);
    edr::Event ev = FileCreate(
        "C:\\Users\\bob\\Documents\\notes.txt",
        "C:\\Windows\\System32\\notepad.exe", 9004, 4000000000ULL);
    detector.Enrich(ev);
    AS_CHECK(ev.fields.find(edr::field::kArchiveStagingScore) == ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::ArchiveStagingDetector detector(false, 300, 1024);
    edr::Event ev = ProcessStart(
        "C:\\Program Files\\7-Zip\\7z.exe",
        "7z.exe x payload.zip", 9005, 5000000000ULL);
    detector.Enrich(ev);
    AS_CHECK(ev.fields.find(edr::field::kArchiveStagingScore) == ev.fields.end());
}

} // namespace

void RunArchiveStagingDetectorTests() {
    TestArchiveToolStart();
    TestArchiveReadAndTempExtraction();
    TestArchiveRenameExtraction();
    TestNonArchiveNoStamp();
    TestDisabledNoStamp();
}
