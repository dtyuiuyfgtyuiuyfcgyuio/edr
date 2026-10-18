/*
 * lateral_transfer_detector_tests.cpp - Unit tests for LateralTransferDetector.
 *
 * Boundary discipline: the ladder intentionally spans 54/55 and 74/75 so the
 * house threshold behaviour is directly asserted on both sides.
 */
#include "lateral_transfer_detector_tests.h"

#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "lateral_transfer_detector.h"

using namespace edr;

namespace {

#define LT_CHECK(condition) Check((condition), #condition, __LINE__)

constexpr uint64_t kSecond = 10000000ULL;

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "lateral_transfer detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcessStart(const std::string& image,
                        const std::string& commandLine,
                        uint64_t ts100ns, uint32_t pid = 100) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.pid = pid;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

edr::Event FileCreate(const std::string& path, uint64_t ts100ns,
                      uint32_t pid = 100) {
    edr::Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.pid = pid;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "FILE_CREATE";
    event.fields[edr::field::kFilePath] = path;
    return event;
}

bool Has(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

std::string Get(const edr::Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

/* --- tests --------------------------------------------------------- */

void TestInspectsWhitelist() {
    std::fprintf(stderr, "[lateral_transfer] TestInspectsWhitelist\n");
    LT_CHECK(LateralTransferDetector::Inspects(EDR_EVT_PROCESS_START));
    LT_CHECK(LateralTransferDetector::Inspects(EDR_EVT_FILE_CREATE));
    LT_CHECK(!LateralTransferDetector::Inspects(EDR_EVT_NET_CONNECT));
    LT_CHECK(!LateralTransferDetector::Inspects(EDR_EVT_REG_WRITE));
    LT_CHECK(!LateralTransferDetector::Inspects(EDR_EVT_FILE_DELETE));
    LT_CHECK(!LateralTransferDetector::Inspects(EDR_EVT_FILE_READ));
    LT_CHECK(!LateralTransferDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
}

void TestUncParse() {
    std::fprintf(stderr, "[lateral_transfer] TestUncParse\n");
    UncLocation admin = FindUncLocation("copy \\\\dc01\\c$\\tools\\psexec.exe .");
    LT_CHECK(admin.found);
    LT_CHECK(admin.host == "dc01");
    LT_CHECK(admin.share == "c$");
    LT_CHECK(admin.adminShare);
    LT_CHECK(admin.tail == "\\tools\\psexec.exe");

    UncLocation plain = FindUncLocation("robocopy \\\\fs01\\tools .");
    LT_CHECK(plain.found);
    LT_CHECK(plain.host == "fs01");
    LT_CHECK(plain.share == "tools");
    LT_CHECK(!plain.adminShare);
    LT_CHECK(plain.tail.empty());

    /* \\host alone is an authentication path owned by lateral_movement. */
    LT_CHECK(!FindUncLocation("net use \\\\dc01").found);
    /* Verbatim device prefixes are not network shares. */
    LT_CHECK(!FindUncLocation("dir \\\\?\\c:\\windows").found);
    LT_CHECK(!FindUncLocation("dir \\\\.\\pipe\\x").found);
}

void TestClassifier() {
    std::fprintf(stderr, "[lateral_transfer] TestClassifier\n");
    LT_CHECK(ClassifyLateralTransfer(
                 "C:\\Windows\\System32\\cmd.exe",
                 "cmd /c copy \\\\dc01\\c$\\tools\\tool.exe C:\\Windows\\Temp\\") ==
             "admin_share_transfer");
    LT_CHECK(ClassifyLateralTransfer(
                 "C:\\Windows\\System32\\robocopy.exe",
                 "robocopy \\\\fs01\\tools C:\\stage\\tools /E") ==
             "share_transfer_exec");
    LT_CHECK(ClassifyLateralTransfer(
                 "C:\\Windows\\System32\\cmd.exe",
                 "cmd /c copy \\\\fs01\\data\\a.dat C:\\stage\\") ==
             "share_transfer");
    LT_CHECK(ClassifyLateralTransfer(
                 "C:\\Windows\\System32\\esentutl.exe",
                 "esentutl /y \\\\dc01\\c$\\tools\\x.dll /d C:\\stage\\x.dll") ==
             "esentutl_unc");
    LT_CHECK(ClassifyLateralTransfer(
                 "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                 "powershell -Command Copy-Item -Path "
                 "\\\\fs01\\tools\\agent.ps1 -Destination C:\\stage\\") ==
             "share_transfer_exec");
    LT_CHECK(ClassifyLateralTransfer(
                 "\\\\dc01\\c$\\tools\\psexec.exe", "psexec.exe \\\\host cmd") ==
             "remote_exec");
    /* Reference-only ladder */
    LT_CHECK(ClassifyLateralTransfer(
                 "C:\\Windows\\System32\\cmd.exe",
                 "cmd /c dir \\\\dc01\\c$\\tools\\psexec.exe") ==
             "admin_share_reference");
    LT_CHECK(ClassifyLateralTransfer(
                 "C:\\Windows\\System32\\cmd.exe",
                 "cmd /c dir \\\\fs01\\tools\\psexec.exe") ==
             "share_reference_exec");
    LT_CHECK(ClassifyLateralTransfer(
                 "C:\\Windows\\System32\\cmd.exe",
                 "cmd /c dir \\\\fs01\\tools") == "share_reference");
    /* Silent cases: local copies and non-transfer tools. */
    LT_CHECK(ClassifyLateralTransfer("C:\\Windows\\System32\\cmd.exe",
                                     "cmd /c copy a.txt b.txt").empty());
    LT_CHECK(ClassifyLateralTransfer(
                 "C:\\Windows\\System32\\bitsadmin.exe",
                 "bitsadmin /transfer j /download http://x/y.exe C:\\y.exe")
                 .empty());
    LT_CHECK(ClassifyLateralTransfer("C:\\Windows\\System32\\net.exe",
                                     "net use \\\\dc01\\ipc$")
                 .empty());
}

void TestAdminSharePull() {
    std::fprintf(stderr, "[lateral_transfer] TestAdminSharePull\n");
    LateralTransferDetector d(true, 55, 300, 1024);
    edr::Event ev = ProcessStart(
        "C:\\Windows\\System32\\cmd.exe",
        "cmd /c copy \\\\dc01\\admin$\\tool.exe C:\\Windows\\Temp\\tool.exe",
        1000 * kSecond, 7001);
    d.Enrich(ev);
    LT_CHECK(Has(ev, edr::field::kLateralTransferScore));
    LT_CHECK(Get(ev, edr::field::kLateralTransferScore) == "90");
    LT_CHECK(Get(ev, edr::field::kLateralTransferVerdict) == "malicious");
}

void TestPlainShareTransfer() {
    std::fprintf(stderr, "[lateral_transfer] TestPlainShareTransfer\n");
    LateralTransferDetector d(true, 55, 300, 1024);
    edr::Event ev = ProcessStart(
        "C:\\Windows\\System32\\robocopy.exe",
        "robocopy \\\\fs01\\tools C:\\stage\\tools /E", 2000 * kSecond, 7002);
    d.Enrich(ev);
    LT_CHECK(Has(ev, edr::field::kLateralTransferScore));
    LT_CHECK(Get(ev, edr::field::kLateralTransferScore) == "85");
    LT_CHECK(Get(ev, edr::field::kLateralTransferVerdict) == "malicious");
}

void TestRemoteExecImage() {
    std::fprintf(stderr, "[lateral_transfer] TestRemoteExecImage\n");
    LateralTransferDetector d(true, 55, 300, 1024);
    edr::Event ev = ProcessStart("\\\\fs01\\share\\payload.exe", "",
                                 3000 * kSecond, 7003);
    d.Enrich(ev);
    LT_CHECK(Has(ev, edr::field::kLateralTransferScore));
    LT_CHECK(Get(ev, edr::field::kLateralTransferScore) == "90");
}

void TestRemoteToolPush() {
    std::fprintf(stderr, "[lateral_transfer] TestRemoteToolPush\n");
    LateralTransferDetector d(true, 55, 300, 1024);
    edr::Event admin =
        FileCreate("\\\\dc01\\c$\\Users\\Public\\tool.exe", 4000 * kSecond, 7004);
    d.Enrich(admin);
    LT_CHECK(Get(admin, edr::field::kLateralTransferScore) == "90");

    LateralTransferDetector d2(true, 55, 0, 1024);
    edr::Event plain =
        FileCreate("\\\\fs01\\drop\\agent.ps1", 4100 * kSecond, 7005);
    d2.Enrich(plain);
    LT_CHECK(Get(plain, edr::field::kLateralTransferScore) == "85");

    /* A generic file written to a remote share is not a tool transfer. */
    LateralTransferDetector d3(true, 55, 0, 1024);
    edr::Event generic =
        FileCreate("\\\\fs01\\drop\\notes.txt", 4200 * kSecond, 7006);
    d3.Enrich(generic);
    LT_CHECK(!Has(generic, edr::field::kLateralTransferScore));
}

void TestBoundary54_55() {
    std::fprintf(stderr, "[lateral_transfer] TestBoundary54_55\n");
    /* 54: generic remote share reference -> fully silent. */
    {
        LateralTransferDetector d(true, 55, 0, 1024);
        edr::Event ev = ProcessStart("C:\\Windows\\System32\\cmd.exe",
                                     "cmd /c dir \\\\fs01\\tools",
                                     5000 * kSecond, 7007);
        d.Enrich(ev);
        LT_CHECK(!Has(ev, edr::field::kLateralTransferScore));
        LT_CHECK(!Has(ev, edr::field::kLateralTransferVerdict));
    }
    /* 55: remote share reference to an executable -> suspicious. */
    {
        LateralTransferDetector d(true, 55, 0, 1024);
        edr::Event ev = ProcessStart("C:\\Windows\\System32\\cmd.exe",
                                     "cmd /c dir \\\\fs01\\tools\\psexec.exe",
                                     5100 * kSecond, 7008);
        d.Enrich(ev);
        LT_CHECK(Get(ev, edr::field::kLateralTransferScore) == "55");
        LT_CHECK(Get(ev, edr::field::kLateralTransferVerdict) == "suspicious");
    }
}

void TestBoundary74_75() {
    std::fprintf(stderr, "[lateral_transfer] TestBoundary74_75\n");
    /* 74: admin-share reference to an executable -> suspicious. */
    {
        LateralTransferDetector d(true, 55, 0, 1024);
        edr::Event ev = ProcessStart("C:\\Windows\\System32\\cmd.exe",
                                     "cmd /c dir \\\\dc01\\c$\\tools\\psexec.exe",
                                     6000 * kSecond, 7009);
        d.Enrich(ev);
        LT_CHECK(Get(ev, edr::field::kLateralTransferScore) == "74");
        LT_CHECK(Get(ev, edr::field::kLateralTransferVerdict) == "suspicious");
        LT_CHECK(!Has(ev, edr::field::kLateralTransferScore) == false);
    }
    /* 75: plain-share transfer of a generic file -> malicious. */
    {
        LateralTransferDetector d(true, 55, 0, 1024);
        edr::Event ev = ProcessStart("C:\\Windows\\System32\\cmd.exe",
                                     "cmd /c copy \\\\fs01\\data\\a.dat C:\\stage\\",
                                     6100 * kSecond, 7010);
        d.Enrich(ev);
        LT_CHECK(Get(ev, edr::field::kLateralTransferScore) == "75");
        LT_CHECK(Get(ev, edr::field::kLateralTransferVerdict) == "malicious");
    }
}

void TestPsSessionPull() {
    std::fprintf(stderr, "[lateral_transfer] TestPsSessionPull\n");
    LateralTransferDetector d(true, 55, 0, 1024);
    edr::Event ev = ProcessStart(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell -Command Copy-Item -FromSession $s C:\\stage\\",
        7000 * kSecond, 7011);
    d.Enrich(ev);
    LT_CHECK(Get(ev, edr::field::kLateralTransferScore) == "90");
}

void TestSilence() {
    std::fprintf(stderr, "[lateral_transfer] TestSilence\n");
    LateralTransferDetector d(true, 55, 0, 1024);
    /* Local copy: no remote share involved. */
    edr::Event local = ProcessStart("C:\\Windows\\System32\\cmd.exe",
                                    "cmd /c copy C:\\a.txt D:\\b.txt",
                                    8000 * kSecond, 7012);
    d.Enrich(local);
    LT_CHECK(!Has(local, edr::field::kLateralTransferScore));
    /* BITS transfer is owned by bits_abuse (T1105). */
    edr::Event bits = ProcessStart(
        "C:\\Windows\\System32\\bitsadmin.exe",
        "bitsadmin /transfer j /download \\\\fs01\\share\\x.exe C:\\x.exe",
        8100 * kSecond, 7013);
    d.Enrich(bits);
    LT_CHECK(!Has(bits, edr::field::kLateralTransferScore));
    /* Authenticated SMB session only: owned by lateral_movement (T1021). */
    edr::Event auth = ProcessStart("C:\\Windows\\System32\\net.exe",
                                   "net use \\\\dc01\\ipc$", 8200 * kSecond,
                                   7014);
    d.Enrich(auth);
    LT_CHECK(!Has(auth, edr::field::kLateralTransferScore));
    /* Non-inspected event type is ignored outright. */
    edr::Event other;
    other.type = EDR_EVT_REG_WRITE;
    other.ts100ns = 8300 * kSecond;
    other.fields[edr::field::kRegKey] = "\\\\dc01\\c$\\tools\\tool.exe";
    d.Enrich(other);
    LT_CHECK(!Has(other, edr::field::kLateralTransferScore));
}

void TestDedupWindow() {
    std::fprintf(stderr, "[lateral_transfer] TestDedupWindow\n");
    LateralTransferDetector d(true, 55, 300, 1024);
    const uint64_t base = 9000 * kSecond;

    edr::Event first = ProcessStart(
        "C:\\Windows\\System32\\cmd.exe",
        "cmd /c copy \\\\dc01\\c$\\tools\\t.exe C:\\t\\", base, 7015);
    d.Enrich(first);
    LT_CHECK(Has(first, edr::field::kLateralTransferScore));

    /* Same kind + same host inside the dedup window -> suppressed. */
    edr::Event second = ProcessStart(
        "C:\\Windows\\System32\\cmd.exe",
        "cmd /c copy \\\\dc01\\c$\\tools\\t.exe C:\\t\\", base + 10 * kSecond,
        7015);
    d.Enrich(second);
    LT_CHECK(!Has(second, edr::field::kLateralTransferScore));

    /* After the dedup window -> stamped again. */
    edr::Event third = ProcessStart(
        "C:\\Windows\\System32\\cmd.exe",
        "cmd /c copy \\\\dc01\\c$\\tools\\t.exe C:\\t\\", base + 400 * kSecond,
        7015);
    d.Enrich(third);
    LT_CHECK(Has(third, edr::field::kLateralTransferScore));
}

void TestBreadthEscalation() {
    std::fprintf(stderr, "[lateral_transfer] TestBreadthEscalation\n");
    LateralTransferDetector d(true, 55, 0, 1024);
    const uint64_t base = 10000 * kSecond;

    edr::Event one = ProcessStart("C:\\Windows\\System32\\cmd.exe",
                                  "cmd /c dir \\\\fs01\\tools",
                                  base, 7016);
    d.Enrich(one);
    LT_CHECK(!Has(one, edr::field::kLateralTransferScore)); /* 54 alone */

    /* A second, distinct remote host appears in the episode: 54 + 10 = 64. */
    edr::Event two = ProcessStart("C:\\Windows\\System32\\cmd.exe",
                                  "cmd /c dir \\\\fs02\\tools",
                                  base + 10 * kSecond, 7016);
    d.Enrich(two);
    LT_CHECK(Get(two, edr::field::kLateralTransferScore) == "64");
    LT_CHECK(Get(two, edr::field::kLateralTransferVerdict) == "suspicious");
}

void TestStateCapacity() {
    std::fprintf(stderr, "[lateral_transfer] TestStateCapacity\n");
    LateralTransferDetector d(true, 55, 0, 1);
    for (uint32_t i = 0; i < 4; ++i) {
        edr::Event ev = ProcessStart("C:\\Windows\\System32\\cmd.exe",
                                     "cmd /c copy \\\\dc0" + std::to_string(i) +
                                         "\\c$\\t.exe C:\\t\\",
                                     (11000ULL + i) * kSecond, 7020 + i);
        d.Enrich(ev);
    }
    LT_CHECK(d.StateCount() <= 1);
}

void TestDisabled() {
    std::fprintf(stderr, "[lateral_transfer] TestDisabled\n");
    LateralTransferDetector d(false, 55, 300, 1024);
    edr::Event ev = ProcessStart(
        "C:\\Windows\\System32\\cmd.exe",
        "cmd /c copy \\\\dc01\\c$\\tools\\t.exe C:\\t\\", 12000 * kSecond,
        7030);
    d.Enrich(ev);
    LT_CHECK(!Has(ev, edr::field::kLateralTransferScore));
    LT_CHECK(d.StateCount() == 0);
}

void TestMinScoreGate() {
    std::fprintf(stderr, "[lateral_transfer] TestMinScoreGate\n");
    /* minScore 90 must silence the 85-scoring plain-share tool transfer. */
    LateralTransferDetector d(true, 90, 0, 1024);
    edr::Event ev = ProcessStart(
        "C:\\Windows\\System32\\robocopy.exe",
        "robocopy \\\\fs01\\tools C:\\stage\\tools /E", 13000 * kSecond, 7031);
    d.Enrich(ev);
    LT_CHECK(!Has(ev, edr::field::kLateralTransferScore));

    /* ... while a 90-scoring admin-share pull still fires. */
    LateralTransferDetector d2(true, 90, 0, 1024);
    edr::Event admin = ProcessStart(
        "C:\\Windows\\System32\\cmd.exe",
        "cmd /c copy \\\\dc01\\c$\\tool.exe C:\\stage\\t.exe",
        13100 * kSecond, 7032);
    d2.Enrich(admin);
    LT_CHECK(Has(admin, edr::field::kLateralTransferScore));
}

void TestTimeBackward() {
    std::fprintf(stderr, "[lateral_transfer] TestTimeBackward\n");
    LateralTransferDetector d(true, 55, 0, 1024);
    const uint64_t base = 14000 * kSecond;
    edr::Event first = ProcessStart("C:\\Windows\\System32\\cmd.exe",
                                    "cmd /c dir \\\\fs01\\tools",
                                    base + 10 * kSecond, 7040);
    d.Enrich(first);
    /* Out-of-order (earlier than lastSeen) event must be ignored. */
    edr::Event backward = ProcessStart("C:\\Windows\\System32\\cmd.exe",
                                       "cmd /c dir \\\\fs02\\tools", base,
                                       7040);
    d.Enrich(backward);
    LT_CHECK(!Has(backward, edr::field::kLateralTransferScore));
}

void TestPsScriptBodyChannel() {
    std::fprintf(stderr, "[lateral_transfer] TestPsScriptBodyChannel\n");
    /* PS_SCRIPT bodies live only in kScriptBlockText: a script-host process
     * whose command line carries no transfer but whose script body does must
     * still be caught. */
    LateralTransferDetector d(true, 55, 0, 1024);
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.pid = 7050;
    ev.ts100ns = 15000 * kSecond;
    ev.fields[edr::field::kType] = "PROCESS_START";
    ev.fields[edr::field::kImage] =
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    ev.fields[edr::field::kScriptBlockText] =
        "Copy-Item -Path \\\\dc01\\c$\\tools\\agent.ps1 -Destination C:\\s\\";
    d.Enrich(ev);
    LT_CHECK(Get(ev, edr::field::kLateralTransferScore) == "90");
}

} // namespace

void RunLateralTransferDetectorTests() {
    TestInspectsWhitelist();
    TestUncParse();
    TestClassifier();
    TestAdminSharePull();
    TestPlainShareTransfer();
    TestRemoteExecImage();
    TestRemoteToolPush();
    TestBoundary54_55();
    TestBoundary74_75();
    TestPsSessionPull();
    TestSilence();
    TestDedupWindow();
    TestBreadthEscalation();
    TestStateCapacity();
    TestDisabled();
    TestMinScoreGate();
    TestTimeBackward();
    TestPsScriptBodyChannel();
    std::fprintf(stderr, "[lateral_transfer] all passed\n");
}
