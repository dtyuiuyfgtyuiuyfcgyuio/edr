#include "privilege_escalation_detector_tests.h"

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "privilege_escalation_detector.h"

namespace {

#define PE_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond)
        throw std::runtime_error(
            "privilege escalation test failed at line " +
            std::to_string(line) + ": " + expr);
}

edr::Event ServiceInstall(const std::string& imagePath,
                          const std::string& name,
                          uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_SERVICE_INSTALL;
    ev.pid = pid;
    ev.ts100ns = ts;
    ev.fields[edr::field::kServiceImagePath] = imagePath;
    ev.fields[edr::field::kServiceName] = name;
    return ev;
}

edr::Event ProcAccess(const std::string& target, const std::string& mask,
                      uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_ACCESS;
    ev.pid = pid;
    ev.ts100ns = ts;
    ev.fields[edr::field::kTargetImage] = target;
    ev.fields[edr::field::kAccessMask] = mask;
    return ev;
}

edr::Event Privilege(const std::string& privs, uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_PRIVILEGE;
    ev.pid = pid;
    ev.ts100ns = ts;
    ev.fields[edr::field::kPrivileges] = privs;
    return ev;
}

void TestSuspiciousServiceInstall() {
    edr::PrivilegeEscalationDetector det(true, 300, 4096);
    const uint64_t base = 1000000000ULL;
    edr::Event ev = ServiceInstall(
        "C:\\Users\\Public\\evil.exe", "evil_svc", 7001, base);
    det.Enrich(ev);
    PE_CHECK(ev.fields.count(edr::field::kPrivEscScore) > 0);
    PE_CHECK(ev.fields.at(edr::field::kPrivEscScore) == "35");
    PE_CHECK(ev.fields.at(edr::field::kPrivEscSignals).find("service_install") !=
             std::string::npos);
}

void TestTokenManipulation() {
    edr::PrivilegeEscalationDetector det(true, 300, 4096);
    const uint64_t base = 2000000000ULL;
    edr::Event ev = ProcAccess(
        "C:\\Windows\\System32\\lsass.exe", "40", 7002, base);
    det.Enrich(ev);
    PE_CHECK(ev.fields.count(edr::field::kPrivEscScore) > 0);
    PE_CHECK(ev.fields.at(edr::field::kPrivEscScore) == "40");
    PE_CHECK(ev.fields.at(edr::field::kPrivEscSignals).find("token_manipulation") !=
             std::string::npos);
}

void TestSuspiciousPrivilege() {
    edr::PrivilegeEscalationDetector det(true, 300, 4096);
    const uint64_t base = 3000000000ULL;
    edr::Event ev = Privilege(
        "SeDebugPrivilege,SeImpersonatePrivilege", 7003, base);
    det.Enrich(ev);
    PE_CHECK(ev.fields.count(edr::field::kPrivEscScore) > 0);
    PE_CHECK(ev.fields.at(edr::field::kPrivEscScore) == "30");
}

void TestMultiSignalCorrelation() {
    edr::PrivilegeEscalationDetector det(true, 300, 4096);
    const uint64_t base = 4000000000ULL;
    det.Enrich(ServiceInstall("C:\\Temp\\evil.exe", "svc", 7004, base));
    edr::Event ev = Privilege("SeDebugPrivilege", 7004, base + 10000000);
    det.Enrich(ev);
    const uint32_t score = static_cast<uint32_t>(
        std::atoi(ev.fields.at(edr::field::kPrivEscScore).c_str()));
    PE_CHECK(score >= 80);
    PE_CHECK(ev.fields.at(edr::field::kPrivEscVerdict) == "MALICIOUS");
}

void TestStandardServicePathNoStamp() {
    edr::PrivilegeEscalationDetector det(true, 300, 4096);
    const uint64_t base = 5000000000ULL;
    edr::Event ev = ServiceInstall(
        "C:\\Windows\\System32\\svchost.exe", "svc", 7005, base);
    det.Enrich(ev);
    PE_CHECK(ev.fields.find(edr::field::kPrivEscScore) == ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::PrivilegeEscalationDetector det(false, 300, 4096);
    const uint64_t base = 6000000000ULL;
    edr::Event ev = ServiceInstall(
        "C:\\Temp\\evil.exe", "svc", 7006, base);
    det.Enrich(ev);
    PE_CHECK(ev.fields.find(edr::field::kPrivEscScore) == ev.fields.end());
}

} // namespace

void RunPrivilegeEscalationDetectorTests() {
    TestSuspiciousServiceInstall();
    TestTokenManipulation();
    TestSuspiciousPrivilege();
    TestMultiSignalCorrelation();
    TestStandardServicePathNoStamp();
    TestDisabledNoStamp();
}
