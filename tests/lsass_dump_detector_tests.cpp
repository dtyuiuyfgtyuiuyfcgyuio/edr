/*
 * lsass_dump_detector_tests.cpp - Unit tests for LsassDumpDetector.
 */
#include "lsass_dump_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "lsass_dump_detector.h"

namespace {

#define LS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "lsass dump detector test failed at line " +
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

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kLsassDumpScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunLsassDumpDetectorTests() {
    std::fprintf(stderr, "[lsass-dump] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::LsassDumpDetector detector(false, 55, 300, 1024);
        edr::Event event =
            ProcEvent(1000 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
                      "rundll32 C:\\Windows\\System32\\comsvcs.dll, "
                      "MiniDump 700 C:\\temp\\out.dmp full");
        detector.Enrich(event);
        LS_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[lsass-dump] TestComsvcsMiniDump\n");
    {
        /* comsvcs MiniDump one-liner -> 90 malicious. */
        edr::LsassDumpDetector detector(true, 55, 300, 1024);
        edr::Event event =
            ProcEvent(1000 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
                      "rundll32.exe C:\\Windows\\System32\\comsvcs.dll,"
                      "#+MiniDump 716 c:\\temp\\lsass.dmp full");
        detector.Enrich(event);
        LS_CHECK(HasScore(event));
        LS_CHECK(event.fields.at(edr::field::kLsassDumpScore) == "90");
        LS_CHECK(event.fields.at(edr::field::kLsassDumpVerdict) ==
                 "malicious");
        LS_CHECK(event.fields.at(edr::field::kLsassDumpSignals) ==
                 "comsvcs MiniDump one-liner");
    }
    {
        /* comsvcs alone (COM+ hosting) never fires. */
        edr::LsassDumpDetector detector(true, 55, 300, 1024);
        edr::Event event =
            ProcEvent(1000 * kSecond, "C:\\Windows\\System32\\rundll32.exe",
                      "rundll32.exe C:\\Windows\\System32\\comsvcs.dll "
                      "SomeEntry arg");
        detector.Enrich(event);
        LS_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[lsass-dump] TestToolTokens\n");
    {
        edr::LsassDumpDetector detector(true, 55, 300, 1024);
        /* mimikatz token alone -> 90. */
        edr::Event mk = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "cmd /c mimikatz.exe \"sekurlsa::logonpasswords\"");
        detector.Enrich(mk);
        LS_CHECK(HasScore(mk));

        /* secretsdump (Impacket) -> 90. */
        edr::Event sd = ProcEvent(
            2000 * kSecond,
            "C:\\Python312\\python.exe",
            "python secretsdump.py -just-dc-ntlm CORP/dc$@dc.corp.local");
        detector.Enrich(sd);
        LS_CHECK(HasScore(sd));
        LS_CHECK(sd.fields.at(edr::field::kLsassDumpScore) == "90");

        /* pypykatz -> 90. */
        edr::Event pk = ProcEvent(
            3000 * kSecond, "C:\\Python312\\python.exe",
            "pypykatz live lsa");
        detector.Enrich(pk);
        LS_CHECK(HasScore(pk));
    }
    std::fprintf(stderr, "[lsass-dump] TestProcdumpTargeting\n");
    {
        edr::LsassDumpDetector detector(true, 55, 300, 1024);
        /* procdump with lsass target -> 85. */
        edr::Event hit = ProcEvent(
            1000 * kSecond, "C:\\tools\\procdump64.exe",
            "procdump64.exe -accepteula -ma lsass.exe c:\\temp\\ls.dmp");
        detector.Enrich(hit);
        LS_CHECK(HasScore(hit));
        LS_CHECK(hit.fields.at(edr::field::kLsassDumpScore) == "85");

        /* procdump on a benign process never fires. */
        edr::Event miss = ProcEvent(
            2000 * kSecond, "C:\\tools\\procdump64.exe",
            "procdump64.exe -accepteula notepad.exe c:\\temp\\np.dmp");
        detector.Enrich(miss);
        LS_CHECK(!HasScore(miss));
    }
    std::fprintf(stderr, "[lsass-dump] TestPowerShellDumpApi\n");
    {
        edr::LsassDumpDetector detector(true, 55, 300, 1024);
        /* .Dump() on Get-Process lsass -> 80. */
        edr::Event ps = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\WindowsPowerShell"
            "\\v1.0\\powershell.exe",
            "powershell -c (Get-Process lsass).Dump()");
        detector.Enrich(ps);
        LS_CHECK(HasScore(ps));
        LS_CHECK(ps.fields.at(edr::field::kLsassDumpScore) == "80");

        /* lsass-named .dmp output from a custom dumper -> 80. */
        edr::Event custom = ProcEvent(
            2000 * kSecond, "C:\\Users\\alice\\dumper.exe",
            "dumper.exe --name lsass --out C:\\Users\\Public\\a.dmp");
        detector.Enrich(custom);
        LS_CHECK(HasScore(custom));

        /* Pure file operations against an existing dump stay under the
         * malicious band (60, "referenced" not "written"). */
        edr::Event copy = ProcEvent(
            3000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "cmd /c copy C:\\temp\\lsass.dmp \\\\fileserver\\share\\");
        detector.Enrich(copy);
        LS_CHECK(HasScore(copy));
        LS_CHECK(copy.fields.at(edr::field::kLsassDumpScore) == "60");
        LS_CHECK(copy.fields.at(edr::field::kLsassDumpVerdict) ==
                 "suspicious");

        /* A min_score above the reference band suppresses it entirely. */
        edr::LsassDumpDetector strictDetector(true, 65, 300, 1024);
        edr::Event strict = ProcEvent(
            4000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "cmd /c move C:\\temp\\lsass.dmp D:\\archive\\");
        strictDetector.Enrich(strict);
        LS_CHECK(!HasScore(strict));
    }
    std::fprintf(stderr, "[lsass-dump] TestDedupAndBelowMin\n");
    {
        /* Identical command inside the dedup window fires once. */
        edr::LsassDumpDetector detector(true, 55, 300, 1024);
        const char* cmd =
            "rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump "
            "716 out.dmp full";
        edr::Event first = ProcEvent(1000 * kSecond, "rundll32.exe", cmd);
        detector.Enrich(first);
        LS_CHECK(HasScore(first));

        edr::Event second = ProcEvent(1010 * kSecond, "rundll32.exe", cmd);
        detector.Enrich(second);
        LS_CHECK(!HasScore(second));
    }
    {
        /* min_score above all family scores suppresses stamping. */
        edr::LsassDumpDetector detector(true, 95, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "cmd /c mimikatz.exe privilege::debug");
        detector.Enrich(event);
        LS_CHECK(!HasScore(event));
    }
}
