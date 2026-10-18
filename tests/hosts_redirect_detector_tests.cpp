/*
 * hosts_redirect_detector_tests.cpp - Unit tests for
 * HostsRedirectDetector (T1565.001).
 */
#include "hosts_redirect_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "hosts_redirect_detector.h"

namespace {

#define HR_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "hosts redirect detector test failed at line " +
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

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kHostsRedirectScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunHostsRedirectDetectorTests() {
    std::fprintf(stderr, "[hosts-redirect] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::HostsRedirectDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "echo 10.0.0.1 update.microsoft.com "
            ">> C:\\Windows\\System32\\drivers\\etc\\hosts");
        detector.Enrich(event);
        HR_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[hosts-redirect] TestAppendMapping\n");
    {
        edr::HostsRedirectDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "echo 10.0.0.5 intranet.corp.local "
            ">> C:\\Windows\\System32\\drivers\\etc\\hosts");
        detector.Enrich(event);
        HR_CHECK(Score(event) == "85");
        HR_CHECK(event.fields.at(
            edr::field::kHostsRedirectVerdict) == "malicious");
    }
    std::fprintf(stderr, "[hosts-redirect] TestVendorDomainPin\n");
    {
        /* Security-vendor update domains pinned to fixed IPs blind
         * AV/EDR updates - highest-confidence signal. */
        edr::HostsRedirectDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3001 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell"
            "\\v1.0\\powershell.exe",
            "Add-Content $env:WINDIR\\System32\\drivers\\etc\\hosts "
            "\"'6.6.6.6 definitions.update.microsoft.com'\"");
        detector.Enrich(event);
        HR_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[hosts-redirect] TestGenericAppend\n");
    {
        edr::HostsRedirectDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            3002 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "attrib -r C:\\Windows\\System32\\drivers\\etc\\hosts");
        detector.Enrich(event);
        HR_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[hosts-redirect] TestFilePlaneModified\n");
    {
        /* FILE_INTEGRITY plane: hosts modified / removed. */
        edr::HostsRedirectDetector detector(true, 55, 300, 1024);
        edr::Event modified;
        modified.type = EDR_EVT_FILE_INTEGRITY;
        modified.ts100ns = 3003 * kSecond;
        modified.fields[edr::field::kType] = "FILE_INTEGRITY";
        modified.fields[edr::field::kFimAction] = "modified";
        modified.fields[edr::field::kFimPath] =
            "C:\\Windows\\System32\\drivers\\etc\\hosts";
        detector.Enrich(modified);
        HR_CHECK(Score(modified) == "70");

        edr::Event removed;
        removed.type = EDR_EVT_FILE_INTEGRITY;
        removed.ts100ns = 3004 * kSecond;
        removed.fields[edr::field::kType] = "FILE_INTEGRITY";
        removed.fields[edr::field::kFimAction] = "removed";
        removed.fields[edr::field::kFimPath] =
            "C:\\Windows\\System32\\drivers\\etc\\hosts";
        detector.Enrich(removed);
        HR_CHECK(Score(removed) == "80");
    }
    std::fprintf(stderr, "[hosts-redirect] TestFilePlaneOtherWatchedFile\n");
    {
        /* The FIM watch list carries files other than hosts (the shipped
         * config also watches ...\drivers\etc\networks). Those must never
         * be attributed to a hosts redirect. */
        edr::HostsRedirectDetector detector(true, 55, 300, 1024);
        edr::Event networks;
        networks.type = EDR_EVT_FILE_INTEGRITY;
        networks.ts100ns = 3010 * kSecond;
        networks.fields[edr::field::kType] = "FILE_INTEGRITY";
        networks.fields[edr::field::kFimAction] = "modified";
        networks.fields[edr::field::kFimPath] =
            "C:\\Windows\\System32\\drivers\\etc\\networks";
        detector.Enrich(networks);
        HR_CHECK(Score(networks).empty());

        edr::Event unrelated;
        unrelated.type = EDR_EVT_FILE_INTEGRITY;
        unrelated.ts100ns = 3011 * kSecond;
        unrelated.fields[edr::field::kType] = "FILE_INTEGRITY";
        unrelated.fields[edr::field::kFimAction] = "removed";
        unrelated.fields[edr::field::kFimPath] =
            "C:\\Program Files\\App\\config.ini";
        detector.Enrich(unrelated);
        HR_CHECK(Score(unrelated).empty());
    }
    std::fprintf(stderr, "[hosts-redirect] TestFilePlaneDedup\n");
    {
        /* A polling FIM collector re-reporting the same file must not
         * re-alert inside the dedup window, and must alert again once it
         * has elapsed. */
        edr::HostsRedirectDetector detector(true, 55, 60, 1024);
        auto fimEvent = [](uint64_t ts) {
            edr::Event event;
            event.type = EDR_EVT_FILE_INTEGRITY;
            event.ts100ns = ts;
            event.fields[edr::field::kType] = "FILE_INTEGRITY";
            event.fields[edr::field::kFimAction] = "modified";
            event.fields[edr::field::kFimPath] =
                "C:\\Windows\\System32\\drivers\\etc\\hosts";
            return event;
        };
        edr::Event first = fimEvent(4000 * kSecond);
        detector.Enrich(first);
        HR_CHECK(Score(first) == "70");

        edr::Event repeat = fimEvent(4010 * kSecond);
        detector.Enrich(repeat);
        HR_CHECK(Score(repeat).empty());

        edr::Event later = fimEvent(4100 * kSecond);
        detector.Enrich(later);
        HR_CHECK(Score(later) == "70");
    }
    std::fprintf(stderr, "[hosts-redirect] TestReadOnlySilent\n");
    {
        /* Read-only display never scores. */
        edr::HostsRedirectDetector detector(true, 55, 300, 1024);
        edr::Event typeIt = ProcEvent(
            3005 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "type C:\\Windows\\System32\\drivers\\etc\\hosts");
        detector.Enrich(typeIt);
        HR_CHECK(Score(typeIt).empty());

        edr::Event otherFile = ProcEvent(
            3006 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "echo 10.0.0.1 app.internal >> C:\\Temp\\app-hosts.txt");
        detector.Enrich(otherFile);
        HR_CHECK(Score(otherFile).empty());
    }
    std::fprintf(stderr, "[hosts-redirect] all passed\n");
}
