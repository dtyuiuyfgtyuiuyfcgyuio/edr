/*
 * ticket_cache_abuse_detector_tests.cpp - Unit tests for
 * TicketCacheAbuseDetector.
 */
#include "ticket_cache_abuse_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "ticket_cache_abuse_detector.h"

namespace {

#define TC_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "ticket cache abuse detector test failed at line " +
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

edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptBody) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptBody;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kTicketCacheAbuseScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunTicketCacheAbuseDetectorTests() {
    std::fprintf(stderr, "[ticket-cache] TestDisabled\n");
    {
        edr::TicketCacheAbuseDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond,
            "C:\\Tools\\Rubeus.exe",
            "Rubeus ptt /ticket:evil.kirbi");
        detector.Enrich(event);
        TC_CHECK(Score(event).empty());
    }

    std::fprintf(stderr, "[ticket-cache] TestPttTooling\n");
    {
        edr::TicketCacheAbuseDetector detector(true, 55, 300, 1024);
        edr::Event rubeus = ProcEvent(
            1000 * kSecond,
            "C:\\Tools\\Rubeus.exe",
            "Rubeus ptt /ticket:evil.kirbi");
        detector.Enrich(rubeus);
        TC_CHECK(Score(rubeus) == "90");
        TC_CHECK(rubeus.fields.at(edr::field::kTicketCacheAbuseVerdict) ==
                 "malicious");

        edr::Event mimi = ScriptEvent(
            1010 * kSecond,
            "kerberos::ptt /ticket:evil.kirbi");
        detector.Enrich(mimi);
        TC_CHECK(Score(mimi) == "90");
    }

    std::fprintf(stderr, "[ticket-cache] TestPurgeAndTicketFiles\n");
    {
        edr::TicketCacheAbuseDetector detector(true, 55, 300, 1024);
        edr::Event purge = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\klist.exe",
            "klist purge");
        detector.Enrich(purge);
        TC_CHECK(Score(purge) == "65");

        edr::Event file = ProcEvent(
            1010 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "copy C:\\Temp\\ticket.kirbi C:\\Temp\\loot.bin");
        detector.Enrich(file);
        TC_CHECK(Score(file) == "75");

        edr::Event hinted = ProcEvent(
            1020 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "set KRB5CCNAME=C:\\Temp\\krb5cc");
        detector.Enrich(hinted);
        TC_CHECK(Score(hinted) == "60");
    }

    std::fprintf(stderr, "[ticket-cache] TestCleanTrafficSilent\n");
    {
        edr::TicketCacheAbuseDetector detector(true, 55, 300, 1024);
        edr::Event clean = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\klist.exe",
            "klist tickets");
        detector.Enrich(clean);
        TC_CHECK(Score(clean).empty());
        TC_CHECK(clean.fields.find(edr::field::kTicketCacheAbuseVerdict) ==
                 clean.fields.end());
    }

    std::fprintf(stderr, "[ticket-cache] TestDedupWindow\n");
    {
        edr::TicketCacheAbuseDetector detector(true, 55, 60, 1024);
        const char* cmd = "Rubeus ptt /ticket:evil.kirbi";
        edr::Event first = ProcEvent(1000 * kSecond,
                                     "C:\\Tools\\Rubeus.exe",
                                     cmd);
        detector.Enrich(first);
        TC_CHECK(!Score(first).empty());

        edr::Event second = ProcEvent(1030 * kSecond,
                                      "C:\\Tools\\Rubeus.exe",
                                      cmd);
        detector.Enrich(second);
        TC_CHECK(Score(second).empty());

        edr::Event third = ProcEvent(1100 * kSecond,
                                     "C:\\Tools\\Rubeus.exe",
                                     cmd);
        detector.Enrich(third);
        TC_CHECK(!Score(third).empty());
    }

    std::fprintf(stderr, "[ticket-cache] all passed\n");
}
