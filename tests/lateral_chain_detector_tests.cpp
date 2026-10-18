/*
 * lateral_chain_detector_tests.cpp - Unit tests for LateralChainDetector.
 *
 * The chain is built by feeding one vector at a time to the same attribution
 * key, asserting the score band after each step so a weighting regression
 * shows up as the exact step where it broke.
 *
 * Weight reference: remote_service 20, remote_logon 20, admin_share 15,
 * remote_exec 15, session_reuse 10, discovery 10, +20 breadth at 4+ vectors.
 */
#include "lateral_chain_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "lateral_chain_detector.h"

namespace {

#define LC_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond) {
        throw std::runtime_error(
            "lateral chain detector test failed at line " +
            std::to_string(line) + ": " + expr);
    }
}

constexpr uint64_t kSecond = 10000000ULL;
const char* const kIdentity = "pid:6000";

edr::Event Base(uint16_t type, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = type;
    ev.pid = 6000;
    ev.ts100ns = ts100ns;
    ev.processIdentity = kIdentity;
    return ev;
}

edr::Event ServiceInstall(const std::string& imagePath, uint64_t ts100ns) {
    edr::Event ev = Base(EDR_EVT_SERVICE_INSTALL, ts100ns);
    ev.fields[edr::field::kType] = "SERVICE_INSTALL";
    ev.fields[edr::field::kServiceName] = "PSEXESVC";
    ev.fields[edr::field::kServiceImagePath] = imagePath;
    return ev;
}

edr::Event Logon(const std::string& logonType, const std::string& package,
                 const std::string& workstation, uint64_t ts100ns) {
    edr::Event ev = Base(EDR_EVT_LOGON, ts100ns);
    ev.fields[edr::field::kType] = "LOGON";
    ev.fields[edr::field::kLogonType] = logonType;
    if (!package.empty()) ev.fields[edr::field::kAuthPackage] = package;
    if (!workstation.empty())
        ev.fields[edr::field::kSourceWorkstation] = workstation;
    return ev;
}

edr::Event FileCreate(const std::string& path, uint64_t ts100ns) {
    edr::Event ev = Base(EDR_EVT_FILE_CREATE, ts100ns);
    ev.fields[edr::field::kType] = "FILE_CREATE";
    ev.fields[edr::field::kFilePath] = path;
    return ev;
}

edr::Event ProcessStart(const std::string& image, const std::string& command,
                        uint64_t ts100ns) {
    edr::Event ev = Base(EDR_EVT_PROCESS_START, ts100ns);
    ev.fields[edr::field::kType] = "PROCESS_START";
    ev.fields[edr::field::kImage] = image;
    ev.fields[edr::field::kCommandLine] = command;
    return ev;
}

edr::Event NetConnect(const std::string& ip, const std::string& port,
                      uint64_t ts100ns) {
    edr::Event ev = Base(EDR_EVT_NET_CONNECT, ts100ns);
    ev.fields[edr::field::kType] = "NET_CONNECT";
    ev.fields[edr::field::kDstIp] = ip;
    ev.fields[edr::field::kDstPort] = port;
    return ev;
}

std::string Field(const edr::Event& ev, const char* name) {
    auto found = ev.fields.find(name);
    return found == ev.fields.end() ? std::string() : found->second;
}

edr::LateralChainDetector Detector(bool enabled = true,
                                   uint32_t minScore = 55) {
    return edr::LateralChainDetector(enabled, minScore, 600, 300, 1024);
}

/* Two vectors: remote_service(20) + remote_logon(20) = 40, below the default
 * 55 bar, so nothing is annotated yet. A third vector crosses it. */
void TestChainRequiresMultipleVectors() {
    std::fprintf(stderr, "[lateral_chain] TestChainRequiresMultipleVectors\n");
    edr::LateralChainDetector detector = Detector();

    edr::Event service = ServiceInstall(
        "\\\\fileserver\\c$\\Windows\\PSEXESVC.exe", 100 * kSecond);
    detector.Enrich(service);
    LC_CHECK(Field(service, edr::field::kLateralChainScore).empty());

    edr::Event logon = Logon("3", "NTLM", "WORKSTATION7", 101 * kSecond);
    detector.Enrich(logon);
    LC_CHECK(Field(logon, edr::field::kLateralChainScore).empty());

    /* Third vector: admin_share(15) -> 20+20+15 = 55 >= 55. */
    edr::Event share = FileCreate("\\\\fileserver\\admin$\\payload.exe",
                                  102 * kSecond);
    detector.Enrich(share);
    LC_CHECK(Field(share, edr::field::kLateralChainScore) == "55");
    LC_CHECK(Field(share, edr::field::kLateralChainVerdict) == "SUSPICIOUS");
    LC_CHECK(Field(share, edr::field::kLateralChainVectorCount) == "3");
    LC_CHECK(Field(share, edr::field::kLateralChainSignals) ==
             "remote_service,remote_logon,admin_share");
}

/* Four vectors add the breadth bonus: 20+20+15+15 = 70, +20 = 90, which is
 * the MALICIOUS band. */
void TestBreadthBonusCrossesMaliciousBand() {
    std::fprintf(stderr,
                 "[lateral_chain] TestBreadthBonusCrossesMaliciousBand\n");
    edr::LateralChainDetector detector = Detector();

    edr::Event service = ServiceInstall(
        "\\\\fileserver\\c$\\Windows\\PSEXESVC.exe", 100 * kSecond);
    detector.Enrich(service);
    edr::Event logon = Logon("3", "NTLM", "WORKSTATION7", 101 * kSecond);
    detector.Enrich(logon);
    edr::Event share = FileCreate("\\\\fileserver\\admin$\\payload.exe",
                                  102 * kSecond);
    detector.Enrich(share);
    edr::Event exec = ProcessStart(
        "C:\\Windows\\System32\\psexec.exe",
        "psexec.exe \\\\fileserver -u admin cmd.exe", 103 * kSecond);
    detector.Enrich(exec);

    LC_CHECK(Field(exec, edr::field::kLateralChainScore) == "90");
    LC_CHECK(Field(exec, edr::field::kLateralChainVerdict) == "MALICIOUS");
    LC_CHECK(Field(exec, edr::field::kLateralChainVectorCount) == "4");
    LC_CHECK(Field(exec, edr::field::kLateralChainRemoteHost) == "fileserver");
}

/* A local service install must not be mistaken for a remote one. */
void TestLocalServiceInstallSilent() {
    std::fprintf(stderr, "[lateral_chain] TestLocalServiceInstallSilent\n");
    edr::LateralChainDetector detector = Detector();
    edr::Event ev = ServiceInstall(
        "C:\\Program Files\\Vendor\\service.exe", 100 * kSecond);
    detector.Enrich(ev);
    LC_CHECK(Field(ev, edr::field::kLateralChainScore).empty());
    LC_CHECK(detector.StateCount() == 0);
}

/* An interactive local logon (type 2) is not an inbound remote logon. */
void TestInteractiveLogonSilent() {
    std::fprintf(stderr, "[lateral_chain] TestInteractiveLogonSilent\n");
    edr::LateralChainDetector detector = Detector();
    edr::Event ev = Logon("2", "Negotiate", "", 100 * kSecond);
    detector.Enrich(ev);
    LC_CHECK(Field(ev, edr::field::kLateralChainScore).empty());
    LC_CHECK(detector.StateCount() == 0);
}

/* A plain local share (no UNC host) is not an administrative-share
 * reference. */
void TestLocalSharePathSilent() {
    std::fprintf(stderr, "[lateral_chain] TestLocalSharePathSilent\n");
    edr::LateralChainDetector detector = Detector();
    edr::Event ev = FileCreate("C:\\Users\\public\\notes.txt", 100 * kSecond);
    detector.Enrich(ev);
    LC_CHECK(Field(ev, edr::field::kLateralChainScore).empty());
}

/* A non-administrative UNC share is deliberately not counted: only the
 * admin-share family is an unambiguous lateral reference. */
void TestOrdinaryUncShareSilent() {
    std::fprintf(stderr, "[lateral_chain] TestOrdinaryUncShareSilent\n");
    edr::LateralChainDetector detector = Detector();
    edr::Event ev = FileCreate("\\\\fileserver\\public\\report.docx",
                               100 * kSecond);
    detector.Enrich(ev);
    LC_CHECK(Field(ev, edr::field::kLateralChainScore).empty());
}

/* Type 9 with NTLM is credential replay, which is its own (lighter) vector:
 * session_reuse(10) + remote_logon(20) + remote_service(20) + admin_share(15)
 * = 65, and it must be labelled session_reuse rather than remote_logon. */
void TestCredentialReplayVector() {
    std::fprintf(stderr, "[lateral_chain] TestCredentialReplayVector\n");
    edr::LateralChainDetector detector = Detector();
    edr::Event service = ServiceInstall(
        "\\\\fileserver\\c$\\Windows\\svc.exe", 100 * kSecond);
    detector.Enrich(service);
    edr::Event logon = Logon("10", "Negotiate", "PEER", 101 * kSecond);
    detector.Enrich(logon);
    edr::Event share = FileCreate("\\\\fileserver\\admin$\\x.exe",
                                  102 * kSecond);
    detector.Enrich(share);
    edr::Event replay = Logon("9", "NTLM", "PEER", 103 * kSecond);
    detector.Enrich(replay);

    /* 20+20+15+10 = 65, plus the +20 breadth bonus at four vectors = 85.
     * The header documents the breadth bonus as applying at 4+ vectors, so
     * this fourth vector triggers it. */
    LC_CHECK(Field(replay, edr::field::kLateralChainScore) == "85");
    LC_CHECK(Field(replay, edr::field::kLateralChainSignals) ==
             "remote_service,remote_logon,admin_share,session_reuse");
}

/* Evidence is accumulated for the graph and bounded per vector. */
void TestEvidenceAccumulated() {
    std::fprintf(stderr, "[lateral_chain] TestEvidenceAccumulated\n");
    edr::LateralChainDetector detector = Detector();
    edr::Event service = ServiceInstall(
        "\\\\fileserver\\c$\\Windows\\svc.exe", 100 * kSecond);
    detector.Enrich(service);
    edr::Event logon = Logon("3", "NTLM", "WORKSTATION7", 101 * kSecond);
    detector.Enrich(logon);
    edr::Event share = FileCreate("\\\\fileserver\\admin$\\x.exe",
                                  102 * kSecond);
    detector.Enrich(share);
    const std::string evidence = Field(share, edr::field::kLateralChainEvidence);
    /* ServiceInstall() sets kServiceName to "PSEXESVC"; the evidence must
     * name the service so an analyst can tell which one was staged. */
    LC_CHECK(evidence.find("PSEXESVC") != std::string::npos);
    LC_CHECK(evidence.find("WORKSTATION7") != std::string::npos);
    LC_CHECK(evidence.find("admin$") != std::string::npos);
}

/* The dedup window suppresses a repeat alert for the same chain, and a quiet
 * period longer than the window lets it fire again. */
void TestDedupWindowAndReArm() {
    std::fprintf(stderr, "[lateral_chain] TestDedupWindowAndReArm\n");
    edr::LateralChainDetector detector = Detector(true, 55);
    edr::Event service = ServiceInstall(
        "\\\\fileserver\\c$\\Windows\\svc.exe", 100 * kSecond);
    detector.Enrich(service);
    edr::Event logon = Logon("3", "NTLM", "PEER", 101 * kSecond);
    detector.Enrich(logon);
    edr::Event share = FileCreate("\\\\fileserver\\admin$\\x.exe",
                                  102 * kSecond);
    detector.Enrich(share);
    LC_CHECK(Field(share, edr::field::kLateralChainScore) == "55");

    /* Within the 300s dedup window: suppressed. */
    edr::Event again = FileCreate("\\\\fileserver\\admin$\\y.exe",
                                  110 * kSecond);
    detector.Enrich(again);
    LC_CHECK(Field(again, edr::field::kLateralChainScore).empty());

    /* Past the dedup window but still inside the 600s chain window: fires. */
    edr::Event later = FileCreate("\\\\fileserver\\admin$\\z.exe",
                                  (102 + 400) * kSecond);
    detector.Enrich(later);
    LC_CHECK(!Field(later, edr::field::kLateralChainScore).empty());
}

/* Distinct attribution keys do not share state, so one host's chain cannot
 * inflate another's score. */
void TestAttributionIsolation() {
    std::fprintf(stderr, "[lateral_chain] TestAttributionIsolation\n");
    edr::LateralChainDetector detector = Detector();

    edr::Event service = ServiceInstall(
        "\\\\fileserver\\c$\\Windows\\svc.exe", 100 * kSecond);
    detector.Enrich(service);
    edr::Event logon = Logon("3", "NTLM", "PEER", 101 * kSecond);
    detector.Enrich(logon);
    edr::Event share = FileCreate("\\\\fileserver\\admin$\\x.exe",
                                  102 * kSecond);
    detector.Enrich(share);
    LC_CHECK(Field(share, edr::field::kLateralChainScore) == "55");

    /* A different process contributes its first vector only. */
    edr::Event other = Base(EDR_EVT_FILE_CREATE, 103 * kSecond);
    other.pid = 7000;
    other.processIdentity = "pid:7000";
    other.fields[edr::field::kType] = "FILE_CREATE";
    other.fields[edr::field::kFilePath] = "\\\\fileserver\\admin$\\z.exe";
    detector.Enrich(other);
    LC_CHECK(Field(other, edr::field::kLateralChainScore).empty());
}

/* A disabled detector is inert. */
void TestDisabledDetectorInert() {
    std::fprintf(stderr, "[lateral_chain] TestDisabledDetectorInert\n");
    edr::LateralChainDetector detector = Detector(false);
    edr::Event service = ServiceInstall(
        "\\\\fileserver\\c$\\Windows\\svc.exe", 100 * kSecond);
    detector.Enrich(service);
    edr::Event logon = Logon("3", "NTLM", "PEER", 101 * kSecond);
    detector.Enrich(logon);
    edr::Event share = FileCreate("\\\\fileserver\\admin$\\x.exe",
                                  102 * kSecond);
    detector.Enrich(share);
    LC_CHECK(Field(share, edr::field::kLateralChainScore).empty());
    LC_CHECK(detector.StateCount() == 0);
}

/* Only the documented event types are inspected. */
void TestInspectsSet() {
    std::fprintf(stderr, "[lateral_chain] TestInspectsSet\n");
    LC_CHECK(edr::LateralChainDetector::Inspects(EDR_EVT_LOGON));
    LC_CHECK(edr::LateralChainDetector::Inspects(EDR_EVT_SERVICE_INSTALL));
    LC_CHECK(edr::LateralChainDetector::Inspects(EDR_EVT_FILE_CREATE));
    LC_CHECK(edr::LateralChainDetector::Inspects(EDR_EVT_PROCESS_START));
    LC_CHECK(edr::LateralChainDetector::Inspects(EDR_EVT_NET_CONNECT));
    LC_CHECK(!edr::LateralChainDetector::Inspects(EDR_EVT_DNS_QUERY));
    LC_CHECK(!edr::LateralChainDetector::Inspects(EDR_EVT_REG_WRITE));
}

/* A lateral port to a private peer alone is a single vector and stays silent
 * (that fan-out case belongs to lateral_movement_detector). */
void TestSingleNetworkVectorSilent() {
    std::fprintf(stderr, "[lateral_chain] TestSingleNetworkVectorSilent\n");
    edr::LateralChainDetector detector = Detector();
    edr::Event ev = NetConnect("10.0.0.5", "445", 100 * kSecond);
    detector.Enrich(ev);
    LC_CHECK(Field(ev, edr::field::kLateralChainScore).empty());
}

/* Loopback lateral ports are never counted. */
void TestLoopbackIgnored() {
    std::fprintf(stderr, "[lateral_chain] TestLoopbackIgnored\n");
    edr::LateralChainDetector detector = Detector();
    edr::Event ev = NetConnect("127.0.0.1", "445", 100 * kSecond);
    detector.Enrich(ev);
    LC_CHECK(detector.StateCount() == 0);
}

/* State is bounded by capacity under a long tail of distinct actors. */
void TestStateCapacityBounded() {
    std::fprintf(stderr, "[lateral_chain] TestStateCapacityBounded\n");
    edr::LateralChainDetector detector(true, 55, 600, 0, 4);
    for (uint32_t i = 0; i < 64; ++i) {
        edr::Event ev = Base(EDR_EVT_FILE_CREATE, (100 + i) * kSecond);
        ev.pid = 8000 + i;
        ev.processIdentity = "pid:" + std::to_string(8000 + i);
        ev.fields[edr::field::kType] = "FILE_CREATE";
        ev.fields[edr::field::kFilePath] = "\\\\fileserver\\admin$\\x.exe";
        detector.Enrich(ev);
    }
    LC_CHECK(detector.StateCount() <= 4);
}

/* Chain state expires once the window passes with no further activity, so
 * vectors seen hours apart do not accumulate. */
void TestWindowExpiry() {
    std::fprintf(stderr, "[lateral_chain] TestWindowExpiry\n");
    edr::LateralChainDetector detector = Detector(true, 55);

    edr::Event service = ServiceInstall(
        "\\\\fileserver\\c$\\Windows\\svc.exe", 100 * kSecond);
    detector.Enrich(service);
    edr::Event logon = Logon("3", "NTLM", "PEER", 101 * kSecond);
    detector.Enrich(logon);

    /* 700s later, past the 600s window: the earlier vectors are gone, so this
     * single admin_share hit does not reach the bar. */
    edr::Event share = FileCreate("\\\\fileserver\\admin$\\x.exe",
                                  (101 + 700) * kSecond);
    detector.Enrich(share);
    LC_CHECK(Field(share, edr::field::kLateralChainScore).empty());
}

} // namespace

void RunLateralChainDetectorTests() {
    TestChainRequiresMultipleVectors();
    TestBreadthBonusCrossesMaliciousBand();
    TestLocalServiceInstallSilent();
    TestInteractiveLogonSilent();
    TestLocalSharePathSilent();
    TestOrdinaryUncShareSilent();
    TestCredentialReplayVector();
    TestEvidenceAccumulated();
    TestDedupWindowAndReArm();
    TestAttributionIsolation();
    TestDisabledDetectorInert();
    TestInspectsSet();
    TestSingleNetworkVectorSilent();
    TestLoopbackIgnored();
    TestStateCapacityBounded();
    TestWindowExpiry();
    std::fprintf(stderr, "[lateral_chain] all passed\n");
}
