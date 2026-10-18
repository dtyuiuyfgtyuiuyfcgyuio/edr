/*
 * cert_abuse_detector_tests.cpp - Unit tests for CertAbuseDetector.
 */
#include "cert_abuse_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "cert_abuse_detector.h"

namespace {

#define CA_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "cert abuse detector test failed at line " +
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

/* House contract: a POWERSHELL_SCRIPT event carries its body ONLY in
 * kScriptBlockText - never kCommandLine/kImage. */
edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptBody) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptBody;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kCertAbuseScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunCertAbuseDetectorTests() {
    std::fprintf(stderr, "[cert-abuse] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::CertAbuseDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\certutil.exe",
            "certutil -addstore Root evil.cer");
        detector.Enrich(event);
        CA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[cert-abuse] TestRootStoreInstall\n");
    {
        edr::CertAbuseDetector detector(true, 55, 300, 1024);
        /* certutil -addstore Root -> 90 malicious. */
        edr::Event addstore = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\certutil.exe",
            "certutil -addstore -f Root C:\\Temp\\evil.cer");
        detector.Enrich(addstore);
        CA_CHECK(Score(addstore) == "90");
        CA_CHECK(addstore.fields.at(edr::field::kCertAbuseVerdict) ==
                 "malicious");

        /* Enterprise addstore -> 90. */
        edr::Event enterprise = ProcEvent(
            1010 * kSecond, "C:\\Windows\\System32\\certutil.exe",
            "certutil -enterprise -addstore AuthRoot evil.cer");
        detector.Enrich(enterprise);
        CA_CHECK(Score(enterprise) == "90");

        /* PowerShell Import-Certificate into LocalMachine\Root -> 90. */
        edr::Event import = ScriptEvent(
            1020 * kSecond,
            "Import-Certificate -FilePath .\\evil.cer "
            "-CertStoreLocation Cert:\\LocalMachine\\Root");
        detector.Enrich(import);
        CA_CHECK(Score(import) == "90");
    }
    std::fprintf(stderr, "[cert-abuse] TestNonTrustStoreSilent\n");
    {
        edr::CertAbuseDetector detector(true, 55, 300, 1024);
        /* Disallowed store is a revoke, not a trust install. */
        edr::Event disallowed = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\certutil.exe",
            "certutil -addstore Disallowed bad.cer");
        detector.Enrich(disallowed);
        CA_CHECK(Score(disallowed).empty());
    }
    std::fprintf(stderr, "[cert-abuse] TestPrivateKeyExport\n");
    {
        edr::CertAbuseDetector detector(true, 55, 300, 1024);
        /* certutil -exportPfx -> 70 suspicious. */
        edr::Event exportPfx = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\certutil.exe",
            "certutil -exportPfx -p pass123 My cert.pfx");
        detector.Enrich(exportPfx);
        CA_CHECK(Score(exportPfx) == "70");

        /* Export-PfxCertificate with password in script plane -> 70. */
        edr::Event psExport = ScriptEvent(
            1010 * kSecond,
            "$pwd = ConvertTo-SecureString -String 's3cret' -AsPlainText"
            " -Force; Export-PfxCertificate -Cert $cert -FilePath"
            " loot.pfx -Password $pwd");
        detector.Enrich(psExport);
        CA_CHECK(Score(psExport) == "70");
    }
    std::fprintf(stderr, "[cert-abuse] TestSelfSignedCreation\n");
    {
        edr::CertAbuseDetector detector(true, 55, 300, 1024);
        /* New-SelfSignedCertificate -> 60 suspicious. */
        edr::Event selfSign = ScriptEvent(
            1000 * kSecond,
            "New-SelfSignedCertificate -DnsName evil.local "
            "-CertStoreLocation Cert:\\CurrentUser\\My");
        detector.Enrich(selfSign);
        CA_CHECK(Score(selfSign) == "60");
        CA_CHECK(selfSign.fields.at(edr::field::kCertAbuseVerdict) ==
                 "suspicious");
    }
    std::fprintf(stderr, "[cert-abuse] TestBelowThresholdSuppressed\n");
    {
        /* High min_score suppresses creation/export bands but keeps
         * trust installs (min_score isolation lesson). */
        edr::CertAbuseDetector strict(true, 90, 300, 1024);
        edr::Event selfSign = ScriptEvent(
            1000 * kSecond,
            "New-SelfSignedCertificate -DnsName evil.local");
        strict.Enrich(selfSign);
        CA_CHECK(Score(selfSign).empty());

        edr::Event addstore = ProcEvent(
            1010 * kSecond, "C:\\Windows\\System32\\certutil.exe",
            "certutil -addstore Root evil.cer");
        strict.Enrich(addstore);
        CA_CHECK(Score(addstore) == "90");
    }
    std::fprintf(stderr, "[cert-abuse] TestDedupWindow\n");
    {
        edr::CertAbuseDetector detector(true, 55, 60, 1024);
        const char* cmd = "certutil -addstore -f Root evil.cer";
        edr::Event first = ProcEvent(1000 * kSecond,
                                     "C:\\Windows\\System32\\certutil.exe",
                                     cmd);
        detector.Enrich(first);
        CA_CHECK(!Score(first).empty());

        /* Same text inside the dedup window is suppressed. */
        edr::Event second = ProcEvent(1030 * kSecond,
                                      "C:\\Windows\\System32\\certutil.exe",
                                      cmd);
        detector.Enrich(second);
        CA_CHECK(Score(second).empty());

        /* Outside the window the alert re-arms. */
        edr::Event third = ProcEvent(1100 * kSecond,
                                     "C:\\Windows\\System32\\certutil.exe",
                                     cmd);
        detector.Enrich(third);
        CA_CHECK(!Score(third).empty());
    }
    std::fprintf(stderr, "[cert-abuse] TestCleanTrafficSilent\n");
    {
        edr::CertAbuseDetector detector(true, 55, 300, 1024);
        edr::Event clean = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\certutil.exe",
            "certutil -verifystore My");
        detector.Enrich(clean);
        CA_CHECK(Score(clean).empty());
        /* No verdict field below 55 (house contract). */
        CA_CHECK(clean.fields.find(edr::field::kCertAbuseVerdict) ==
                 clean.fields.end());
    }
    std::fprintf(stderr, "[cert-abuse] all passed\n");
}
