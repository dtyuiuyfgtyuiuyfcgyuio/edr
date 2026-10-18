/*
 * driver_load_detector_tests.cpp - Unit tests for DriverLoadDetector.
 */
#include "driver_load_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "driver_load_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define DL_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "driver load detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ServiceInstall(uint64_t ts100ns, const char* serviceName,
                          const char* imagePath) {
    edr::Event event;
    event.type = EDR_EVT_SERVICE_INSTALL;
    event.ts100ns = ts100ns;
    event.pid = 999;
    event.fields[edr::field::kType] = "SERVICE_INSTALL";
    event.fields[edr::field::kServiceName] = serviceName;
    event.fields[edr::field::kServiceImagePath] = imagePath;
    return event;
}

edr::Event ImageLoad(uint64_t ts100ns, const char* imagePath,
                     const char* signatureStatus,
                     const char* signer = nullptr) {
    edr::Event event;
    event.type = EDR_EVT_IMAGE_LOAD;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "IMAGE_LOAD";
    event.fields[edr::field::kImageLoadType] = "load";
    event.fields[edr::field::kImageLoaded] = imagePath;
    event.fields[edr::field::kSignatureStatus] = signatureStatus;
    if (signer != nullptr)
        event.fields[edr::field::kSignerSubject] = signer;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

bool HasDriverFields(const edr::Event& event) {
    return HasField(event, edr::field::kDriverScanScore) &&
           HasField(event, edr::field::kDriverVerdict) &&
           HasField(event, edr::field::kDriverImagePath);
}

bool HasNoDriverFields(const edr::Event& event) {
    return !HasField(event, edr::field::kDriverScanScore) &&
           !HasField(event, edr::field::kDriverVerdict);
}

void TestDisabled() {
    edr::DriverLoadDetector detector(false, 55, 300, 1024);
    edr::Event event = ServiceInstall(100000000000ULL, "cheat",
        "c:\\users\\alice\\rtcore64.sys");
    detector.Enrich(event);
    DL_CHECK(HasNoDriverFields(event));
    DL_CHECK(detector.StateCount() == 0);
}

void TestKnownVulnerableDriver() {
    /* RTCore64 is a well-known vulnerable driver (CVE-2019-16098). */
    edr::DriverLoadDetector detector(true, 55, 300, 1024);
    edr::Event event = ServiceInstall(100000000000ULL, "msi",
        "c:\\windows\\temp\\rtcore64.sys");
    detector.Enrich(event);
    DL_CHECK(HasDriverFields(event));
    DL_CHECK(event.fields.at(edr::field::kDriverScanScore) == "60");
    DL_CHECK(event.fields.at(edr::field::kDriverVerdict) == "malicious");
    DL_CHECK(detector.StateCount() == 1);
}

void TestUnsignedDriverFromUserLocation() {
    /* Unsigned + user-writable location: 40+30 = 70. */
    edr::DriverLoadDetector detector(true, 55, 300, 1024);
    edr::Event event = ServiceInstall(100000000000ULL, "svc",
        "c:\\users\\alice\\appdata\\local\\temp\\mydriver.sys");
    event.fields[edr::field::kSignatureStatus] = "unsigned";
    detector.Enrich(event);
    DL_CHECK(HasDriverFields(event));
    DL_CHECK(event.fields.at(edr::field::kDriverScanScore) == "70");
    DL_CHECK(detector.StateCount() == 1);
}

void TestNonDriverServiceIgnored() {
    /* A .exe service is not a driver load. */
    edr::DriverLoadDetector detector(true, 55, 300, 1024);
    edr::Event event = ServiceInstall(100000000000ULL, "svc",
        "c:\\program files\\app\\app.exe");
    detector.Enrich(event);
    DL_CHECK(HasNoDriverFields(event));
    DL_CHECK(detector.StateCount() == 0);
}

void TestSysmonKnownVulnerableDriver() {
    edr::DriverLoadDetector detector(true, 55, 300, 1024);
    edr::Event event = ImageLoad(
        100000000000ULL,
        "c:\\windows\\system32\\drivers\\rtcore64.sys",
        "trusted", "Micro-Star International");
    event.fields[edr::field::kSource] = "sysmon";
    event.fields[edr::field::kSysmonEventId] = "6";
    detector.Enrich(event);
    DL_CHECK(HasDriverFields(event));
    DL_CHECK(event.fields.at(edr::field::kDriverScanScore) == "60");
    DL_CHECK(event.fields.at(edr::field::kDriverSigner) ==
             "Micro-Star International");
    DL_CHECK(event.fields.at(edr::field::kDriverSigned) == "true");
}

void TestSysmonUnsignedUserDriver() {
    edr::DriverLoadDetector detector(true, 55, 300, 1024);
    edr::Event event = ImageLoad(
        100000000000ULL,
        "c:\\users\\alice\\appdata\\local\\temp\\evil.sys",
        "unsigned");
    event.fields[edr::field::kSource] = "sysmon";
    event.fields[edr::field::kSysmonEventId] = "6";
    detector.Enrich(event);
    DL_CHECK(HasDriverFields(event));
    DL_CHECK(event.fields.at(edr::field::kDriverScanScore) == "70");
    DL_CHECK(event.fields.at(edr::field::kDriverSigned) == "false");
}

void TestInspectsTypes() {
    DL_CHECK(edr::DriverLoadDetector::Inspects(EDR_EVT_SERVICE_INSTALL));
    DL_CHECK(edr::DriverLoadDetector::Inspects(EDR_EVT_SERVICE_CHANGE));
    DL_CHECK(edr::DriverLoadDetector::Inspects(EDR_EVT_IMAGE_LOAD));
    DL_CHECK(!edr::DriverLoadDetector::Inspects(EDR_EVT_REG_WRITE));
}

} // namespace

void RunDriverLoadDetectorTests() {
    TestDisabled();
    TestKnownVulnerableDriver();
    TestUnsignedDriverFromUserLocation();
    TestNonDriverServiceIgnored();
    TestSysmonKnownVulnerableDriver();
    TestSysmonUnsignedUserDriver();
    TestInspectsTypes();
}
