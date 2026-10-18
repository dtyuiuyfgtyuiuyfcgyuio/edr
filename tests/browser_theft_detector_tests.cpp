#include "browser_theft_detector_tests.h"

#include <stdexcept>
#include <string>
#include <cstdlib>

#include "edr_event.h"
#include "event_bus.h"
#include "browser_theft_detector.h"

namespace {

#define BT_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond)
        throw std::runtime_error(
            "browser theft test failed at line " +
            std::to_string(line) + ": " + expr);
}

edr::Event FileRead(const std::string& path, const std::string& image,
                    uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_FILE_READ;
    ev.pid = pid;
    ev.ts100ns = ts;
    ev.fields[edr::field::kFilePath] = path;
    ev.fields[edr::field::kImage] = image;
    return ev;
}

void TestChromeLoginDataAccess() {
    edr::BrowserTheftDetector det(true, 300, 2048);
    const uint64_t base = 1000000000ULL;
    edr::Event ev = FileRead(
        "C:\\Users\\test\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        "C:\\malware\\stealer.exe", 8001, base);
    det.Enrich(ev);
    BT_CHECK(ev.fields.count(edr::field::kBrowserTheftScore) > 0);
    BT_CHECK(ev.fields.at(edr::field::kBrowserTheftScore) == "40");
    BT_CHECK(ev.fields.at(edr::field::kBrowserTheftBrowsers) == "chromium");
    BT_CHECK(ev.fields.at(edr::field::kBrowserTheftDataTypes) == "login_data");
    /* Score 40 stays below the 55 alerting band, so a single Login Data
     * access is stamped for correlation but carries no verdict yet. */
    BT_CHECK(ev.fields.find(edr::field::kBrowserTheftVerdict) ==
             ev.fields.end());
}

void TestFirefoxKeyDbAccess() {
    edr::BrowserTheftDetector det(true, 300, 2048);
    const uint64_t base = 2000000000ULL;
    edr::Event ev = FileRead(
        "C:\\Users\\test\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abc.default\\key4.db",
        "C:\\malware\\stealer.exe", 8002, base);
    det.Enrich(ev);
    BT_CHECK(ev.fields.count(edr::field::kBrowserTheftScore) > 0);
    BT_CHECK(ev.fields.at(edr::field::kBrowserTheftBrowsers) == "firefox");
    BT_CHECK(ev.fields.at(edr::field::kBrowserTheftDataTypes) == "key4_db");
}

void TestCookieAndLocalStateChain() {
    edr::BrowserTheftDetector det(true, 300, 2048);
    const uint64_t base = 3000000000ULL;
    det.Enrich(FileRead(
        "C:\\Users\\test\\AppData\\Local\\Google\\Chrome\\User Data\\Local State",
        "C:\\malware\\stealer.exe", 8003, base));
    edr::Event ev = FileRead(
        "C:\\Users\\test\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies",
        "C:\\malware\\stealer.exe", 8003, base + 10000000);
    det.Enrich(ev);
    const uint32_t score = static_cast<uint32_t>(
        std::atoi(ev.fields.at(edr::field::kBrowserTheftScore).c_str()));
    BT_CHECK(score >= 55);
    BT_CHECK(ev.fields.at(edr::field::kBrowserTheftVerdict) == "SUSPICIOUS");
}

void TestBrowserProcessNoStamp() {
    edr::BrowserTheftDetector det(true, 300, 2048);
    const uint64_t base = 4000000000ULL;
    edr::Event ev = FileRead(
        "C:\\Users\\test\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        "C:\\Program Files\\Google\\Chrome\\chrome.exe", 8004, base);
    det.Enrich(ev);
    BT_CHECK(ev.fields.find(edr::field::kBrowserTheftScore) == ev.fields.end());
}

void TestNonBrowserFileNoStamp() {
    edr::BrowserTheftDetector det(true, 300, 2048);
    const uint64_t base = 5000000000ULL;
    edr::Event ev = FileRead(
        "C:\\Users\\test\\Documents\\report.docx",
        "C:\\malware\\stealer.exe", 8005, base);
    det.Enrich(ev);
    BT_CHECK(ev.fields.find(edr::field::kBrowserTheftScore) == ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::BrowserTheftDetector det(false, 300, 2048);
    const uint64_t base = 6000000000ULL;
    edr::Event ev = FileRead(
        "C:\\Users\\test\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        "C:\\malware\\stealer.exe", 8006, base);
    det.Enrich(ev);
    BT_CHECK(ev.fields.find(edr::field::kBrowserTheftScore) == ev.fields.end());
}

} // namespace

void RunBrowserTheftDetectorTests() {
    TestChromeLoginDataAccess();
    TestFirefoxKeyDbAccess();
    TestCookieAndLocalStateChain();
    TestBrowserProcessNoStamp();
    TestNonBrowserFileNoStamp();
    TestDisabledNoStamp();
}
