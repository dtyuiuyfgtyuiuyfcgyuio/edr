/* Regressions for strong endpoint/process-instance identity normalization. */
#include "endpoint_identity_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "sysmon_parser.h"

namespace {

#define EI_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond) {
        throw std::runtime_error(
            "endpoint identity test failed at line " +
            std::to_string(line) + ": " + expr);
    }
}

uint64_t FileTimeFor(WORD year, WORD month, WORD day, WORD hour, WORD minute,
                     WORD second, DWORD fraction100ns) {
    SYSTEMTIME st = {};
    st.wYear = year;
    st.wMonth = month;
    st.wDay = day;
    st.wHour = hour;
    st.wMinute = minute;
    st.wSecond = second;
    FILETIME ft = {};
    EI_CHECK(SystemTimeToFileTime(&st, &ft) != FALSE);
    return ((static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime) +
           fraction100ns;
}

std::wstring ProcessStartXml(const wchar_t* utcTime) {
    return L"<Event><System><EventID>1</EventID>"
           L"<TimeCreated SystemTime=\"2026-10-03T12:34:56.7654321Z\"/>"
           L"</System><EventData>"
           L"<Data Name=\"UtcTime\">" + std::wstring(utcTime) +
           L"</Data><Data Name=\"ProcessGuid\">{sysmon-guid}</Data>"
           L"<Data Name=\"ProcessId\">101</Data>"
           L"<Data Name=\"Image\">C:\\Windows\\sample.exe</Data>"
           L"</EventData></Event>";
}

void TestSysmonStartTimeIsSeparatedFromReceiptTime() {
    edr::Event event;
    EI_CHECK(edr::ParseSysmonXml(
        ProcessStartXml(L"2026-10-03 12:34:56.1234567"), event));
    const uint64_t expected = FileTimeFor(2026, 10, 3, 12, 34, 56, 1234567);
    EI_CHECK(event.processStartTime100ns == expected);
    EI_CHECK(event.ts100ns != expected);
    EI_CHECK(event.processIdentity == "{sysmon-guid}");
}

void TestRoundedSysmonStartTimeDoesNotInventPreciseIdentity() {
    edr::Event event;
    EI_CHECK(edr::ParseSysmonXml(
        ProcessStartXml(L"2026-10-03 12:34:56.123"), event));
    EI_CHECK(event.processStartTime100ns == 0);
    EI_CHECK(event.processIdentity == "{sysmon-guid}");
}

edr::Event ProcessEvent(const char* identity, uint64_t creation,
                        const char* endpoint = "endpoint-a") {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.pid = 101;
    event.processIdentity = identity;
    event.processStartTime100ns = creation;
    event.fields[edr::field::kEndpointId] = endpoint;
    event.fields[edr::field::kImage] = "C:\\Windows\\sample.exe";
    event.fields[edr::field::kPpid] = "4";
    return event;
}

void TestCrossSourceUsesCanonicalPidAndExactCreationTime() {
    edr::SemanticDeduplicator deduplicator;
    edr::Event sysmon = ProcessEvent("{sysmon-guid}", 987654321);
    EI_CHECK(!deduplicator.IsDuplicate(sysmon));
    edr::Event etw = ProcessEvent("sequence@77", 987654321);
    etw.source = "etw";
    EI_CHECK(deduplicator.IsDuplicate(etw));
}

void TestProcessReuseAndEndpointBoundaryAreNotDeduplicated() {
    edr::SemanticDeduplicator deduplicator;
    edr::Event first = ProcessEvent("{same-guid}", 987654321);
    EI_CHECK(!deduplicator.IsDuplicate(first));

    edr::Event reusedPid = ProcessEvent("{same-guid}", 987654322);
    EI_CHECK(!deduplicator.IsDuplicate(reusedPid));

    edr::Event otherEndpoint = ProcessEvent("{same-guid}", 987654321,
                                            "endpoint-b");
    EI_CHECK(!deduplicator.IsDuplicate(otherEndpoint));
}

void TestOpaqueIdentityFallbackStaysProviderScoped() {
    edr::SemanticDeduplicator deduplicator;
    edr::Event sysmon = ProcessEvent("opaque-token", 0);
    sysmon.source = "sysmon";
    EI_CHECK(!deduplicator.IsDuplicate(sysmon));
    edr::Event etw = sysmon;
    etw.source = "etw";
    EI_CHECK(!deduplicator.IsDuplicate(etw));
    edr::Event sameSource = sysmon;
    EI_CHECK(deduplicator.IsDuplicate(sameSource));
}

void TestReceiptTimeAndBarePidDoNotBecomeProcessIdentity() {
    edr::SemanticDeduplicator deduplicator;
    edr::Event first;
    first.type = EDR_EVT_PROCESS_START;
    first.pid = 101;
    first.ts100ns = 987654321;
    first.fields[edr::field::kImage] = "same.exe";
    EI_CHECK(!deduplicator.IsDuplicate(first));
    edr::Event second = first;
    second.ts100ns += 1;
    EI_CHECK(!deduplicator.IsDuplicate(second));
}

} // namespace

void RunEndpointIdentityTests() {
    TestSysmonStartTimeIsSeparatedFromReceiptTime();
    TestRoundedSysmonStartTimeDoesNotInventPreciseIdentity();
    TestCrossSourceUsesCanonicalPidAndExactCreationTime();
    TestProcessReuseAndEndpointBoundaryAreNotDeduplicated();
    TestOpaqueIdentityFallbackStaysProviderScoped();
    TestReceiptTimeAndBarePidDoNotBecomeProcessIdentity();
}
