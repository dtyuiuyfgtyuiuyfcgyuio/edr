/*
 * svc_path_abuse_detector_tests.cpp - Unit tests for
 * SvcPathAbuseDetector (T1574.009 Path Interception by Unquoted Path,
 * T1574.010 Services File Permissions Weakness).
 */
#include "svc_path_abuse_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "svc_path_abuse_detector.h"

namespace {

#define SP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "svc path abuse detector test failed at line " +
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

edr::Event ServiceEvent(uint64_t ts100ns, const char* imagePath) {
    edr::Event event;
    event.type = EDR_EVT_SERVICE_CHANGE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "SERVICE_CHANGE";
    event.fields[edr::field::kServiceImagePath] = imagePath;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kSvcPathAbuseScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunSvcPathAbuseDetectorTests() {
    std::fprintf(stderr, "[svc-path] TestUnquotedPathPredicate\n");
    {
        /* The predicate is the crux of T1574.009: only an unquoted path
         * that contains a space is exploitable. Exercise it directly so
         * the boundary is pinned independently of the scoring bands. */
        using edr::SvcPathAbuseDetector;

        /* Exploitable: unquoted, space before the .exe token. */
        SP_CHECK(SvcPathAbuseDetector::IsExploitableUnquotedPath(
            "C:\\Program Files\\App\\svc.exe"));
        SP_CHECK(SvcPathAbuseDetector::IsExploitableUnquotedPath(
            "C:\\Program Files (x86)\\Vendor\\agent.exe -k netsvcs"));

        /* Properly quoted: safe by construction. */
        SP_CHECK(!SvcPathAbuseDetector::IsExploitableUnquotedPath(
            "\"C:\\Program Files\\App\\svc.exe\""));
        SP_CHECK(!SvcPathAbuseDetector::IsExploitableUnquotedPath(
            "   \"C:\\Program Files\\App\\svc.exe\" -k netsvcs"));

        /* Unquoted but no space in the path: nothing to pre-empt. The
         * trailing argument space must not be mistaken for a hook. */
        SP_CHECK(!SvcPathAbuseDetector::IsExploitableUnquotedPath(
            "C:\\Windows\\System32\\svchost.exe -k netsvcs"));
        SP_CHECK(!SvcPathAbuseDetector::IsExploitableUnquotedPath(
            "C:\\Windows\\System32\\drivers\\driver.sys"));

        SP_CHECK(!SvcPathAbuseDetector::IsExploitableUnquotedPath(""));
    }
    std::fprintf(stderr, "[svc-path] TestDisabled\n");
    {
        edr::SvcPathAbuseDetector detector(false, 55, 300, 1024);
        edr::Event event = ServiceEvent(
            9000 * kSecond, "C:\\Program Files\\App\\svc.exe");
        detector.Enrich(event);
        SP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[svc-path] TestServicePlaneUnquoted\n");
    {
        edr::SvcPathAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ServiceEvent(
            9000 * kSecond, "C:\\Program Files\\App\\svc.exe");
        detector.Enrich(event);
        SP_CHECK(Score(event) == "85");
        SP_CHECK(event.fields.at(
            edr::field::kSvcPathAbuseVerdict) == "malicious");
    }
    std::fprintf(stderr, "[svc-path] TestServicePlaneWritableDir\n");
    {
        edr::SvcPathAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ServiceEvent(
            9001 * kSecond, "\"C:\\Users\\bob\\AppData\\Local\\svc.exe\"");
        detector.Enrich(event);
        SP_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[svc-path] TestAclWeakened\n");
    {
        edr::SvcPathAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9002 * kSecond, "C:\\Windows\\System32\\icacls.exe",
            "icacls \"C:\\Program Files\\App\\svc.exe\" /grant Everyone:F");
        detector.Enrich(event);
        SP_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[svc-path] TestBinPathRepointed\n");
    {
        edr::SvcPathAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9003 * kSecond, "C:\\Windows\\System32\\sc.exe",
            "sc config MyService binPath= C:\\Users\\Public\\evil.exe");
        detector.Enrich(event);
        SP_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[svc-path] TestCommandPlaneQuotingBoundary\n");
    {
        /* The command plane must judge the ASSIGNED VALUE, not the whole
         * command line. A command line always contains spaces (tool, flags,
         * service name), so feeding it to the unquoted-path predicate makes
         * that predicate unconditionally true and alerts on correctly quoted
         * writes too. These cases pin the boundary. */
        edr::SvcPathAbuseDetector detector(true, 55, 300, 1024);

        /* Exploitable: unquoted value containing a space. */
        edr::Event unquoted = ProcEvent(
            9020 * kSecond, "C:\\Windows\\System32\\sc.exe",
            "sc config MySvc binPath= C:\\Program Files\\App\\svc.exe");
        detector.Enrich(unquoted);
        SP_CHECK(Score(unquoted) == "85");

        /* Correctly quoted value: safe, must stay silent. */
        edr::Event quoted = ProcEvent(
            9021 * kSecond, "C:\\Windows\\System32\\sc.exe",
            "sc config MySvc binPath= \"C:\\Program Files\\App\\svc.exe\"");
        detector.Enrich(quoted);
        SP_CHECK(Score(quoted).empty());

        /* Unquoted but no space in the value: unexploitable. */
        edr::Event noSpace = ProcEvent(
            9022 * kSecond, "C:\\Windows\\System32\\sc.exe",
            "sc config MySvc binPath= C:\\Windows\\System32\\svc.exe");
        detector.Enrich(noSpace);
        SP_CHECK(Score(noSpace).empty());

        /* Environment-variable form with no space: also unexploitable. */
        edr::Event envVar = ProcEvent(
            9023 * kSecond, "C:\\Windows\\System32\\sc.exe",
            "sc config MySvc binPath= %SystemRoot%\\system32\\svc.exe");
        detector.Enrich(envVar);
        SP_CHECK(Score(envVar).empty());

        /* reg add writing ImagePath: same rule on both quoting shapes. */
        edr::Event regAddUnquoted = ProcEvent(
            9024 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\MySvc "
            "/v ImagePath /t REG_EXPAND_SZ "
            "/d C:\\Program Files\\App\\svc.exe /f");
        detector.Enrich(regAddUnquoted);
        SP_CHECK(Score(regAddUnquoted) == "85");

        edr::Event regAddQuoted = ProcEvent(
            9025 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\MySvc "
            "/v ImagePath /t REG_EXPAND_SZ "
            "/d \"C:\\Program Files\\App\\svc.exe\" /f");
        detector.Enrich(regAddQuoted);
        SP_CHECK(Score(regAddQuoted).empty());
    }
    std::fprintf(stderr, "[svc-path] TestRegImagePathUnquoted\n");    {
        edr::SvcPathAbuseDetector detector(true, 55, 300, 1024);
        edr::Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.ts100ns = 9004 * kSecond;
        event.fields[edr::field::kType] = "REG_WRITE";
        event.fields[edr::field::kRegKey] =
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MySvc\\ImagePath";
        event.fields[edr::field::kRegValue] =
            "C:\\Program Files\\Vendor\\agent.exe";
        detector.Enrich(event);
        SP_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[svc-path] TestBenignSilent\n");
    {
        edr::SvcPathAbuseDetector detector(true, 55, 300, 1024);
        /* Correctly quoted service path in a normal location. */
        edr::Event quoted = ServiceEvent(
            9005 * kSecond, "\"C:\\Program Files\\App\\svc.exe\" -k net");
        detector.Enrich(quoted);
        SP_CHECK(Score(quoted).empty());

        /* Inbox svchost: unquoted but no space in the path. */
        edr::Event svchost = ServiceEvent(
            9006 * kSecond, "C:\\Windows\\System32\\svchost.exe -k netsvcs");
        detector.Enrich(svchost);
        SP_CHECK(Score(svchost).empty());

        /* Read-only service query. */
        edr::Event query = ProcEvent(
            9007 * kSecond, "C:\\Windows\\System32\\sc.exe",
            "sc qc MyService");
        detector.Enrich(query);
        SP_CHECK(Score(query).empty());

        /* icacls granting to an admin principal is normal hardening. */
        edr::Event adminGrant = ProcEvent(
            9008 * kSecond, "C:\\Windows\\System32\\icacls.exe",
            "icacls \"C:\\Program Files\\App\\svc.exe\" "
            "/grant Administrators:F");
        detector.Enrich(adminGrant);
        SP_CHECK(Score(adminGrant).empty());

        /* Installer writing a service binary is expected. */
        edr::Event installer = ProcEvent(
            9009 * kSecond, "C:\\Windows\\System32\\msiexec.exe",
            "msiexec /i app.msi && sc config App binPath= "
            "C:\\Users\\Public\\stage.exe");
        detector.Enrich(installer);
        SP_CHECK(Score(installer).empty());

        /* An unrelated REG_WRITE outside the services subtree. */
        edr::Event unrelated;
        unrelated.type = EDR_EVT_REG_WRITE;
        unrelated.ts100ns = 9010 * kSecond;
        unrelated.fields[edr::field::kType] = "REG_WRITE";
        unrelated.fields[edr::field::kRegKey] =
            "HKCU\\Software\\Vendor\\Settings";
        unrelated.fields[edr::field::kRegValue] =
            "C:\\Program Files\\Vendor\\tool.exe";
        detector.Enrich(unrelated);
        SP_CHECK(Score(unrelated).empty());
    }
    std::fprintf(stderr, "[svc-path] TestDedupWindow\n");
    {
        edr::SvcPathAbuseDetector detector(true, 55, 60, 1024);
        auto make = [](uint64_t ts) {
            return ProcEvent(ts, "C:\\Windows\\System32\\icacls.exe",
                "icacls \"C:\\Program Files\\App\\svc.exe\" "
                "/grant Users:M");
        };
        edr::Event first = make(9100 * kSecond);
        detector.Enrich(first);
        SP_CHECK(Score(first) == "85");

        edr::Event repeat = make(9110 * kSecond);
        detector.Enrich(repeat);
        SP_CHECK(Score(repeat).empty());

        edr::Event later = make(9200 * kSecond);
        detector.Enrich(later);
        SP_CHECK(Score(later) == "85");
    }
    std::fprintf(stderr, "[svc-path] all passed\n");
}
