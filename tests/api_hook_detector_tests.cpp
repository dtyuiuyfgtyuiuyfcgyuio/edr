/*
 * api_hook_detector_tests.cpp - Unit tests for ApiHookDetector.
 */
#include "api_hook_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "api_hook_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define AH_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "api hook detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event EtwTamper(uint64_t ts100ns, uint32_t pid, const char* tamperType,
                     const char* providerGuid, const char* detail) {
    edr::Event event;
    event.type = EDR_EVT_ETW_TAMPER;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = "ETW_TAMPER";
    event.fields[edr::field::kEtwTamperType] = tamperType;
    event.fields[edr::field::kEtwProviderGuid] = providerGuid;
    event.fields[edr::field::kEtwTamperDetail] = detail;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

bool HasHookFields(const edr::Event& event) {
    return HasField(event, edr::field::kApiHookScore) &&
           HasField(event, edr::field::kApiHookVerdict) &&
           HasField(event, edr::field::kApiHookFunctions);
}

bool HasNoHookFields(const edr::Event& event) {
    return !HasField(event, edr::field::kApiHookScore) &&
           !HasField(event, edr::field::kApiHookVerdict);
}

void TestDisabled() {
    edr::ApiHookDetector detector(false, 55, 300, 1024);
    edr::Event event = EtwTamper(100000000000ULL, 1234, "patch",
        "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}", "EtwEventWrite patched");
    detector.Enrich(event);
    AH_CHECK(HasNoHookFields(event));
    AH_CHECK(detector.StateCount() == 0);
}

void TestProtectedEtwProviderPatch() {
    /* Protected provider disabled + EtwEventWrite patch = 45+30+40. */
    edr::ApiHookDetector detector(true, 55, 300, 1024);
    edr::Event event = EtwTamper(100000000000ULL, 1234, "provider_disable",
        "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}", "EtwEventWrite patched");
    detector.Enrich(event);
    AH_CHECK(HasHookFields(event));
    AH_CHECK(event.fields.at(edr::field::kApiHookVerdict) == "malicious");
    AH_CHECK(detector.StateCount() == 1);
}

void TestBenignTamperTypeIgnored() {
    /* A benign tamper type with no patch detail should not reach the
     * threshold. */
    edr::ApiHookDetector detector(true, 55, 300, 1024);
    edr::Event event = EtwTamper(100000000000ULL, 1234, "query",
        "{00000000-0000-0000-0000-000000000000}", "normal query");
    detector.Enrich(event);
    AH_CHECK(HasNoHookFields(event));
    AH_CHECK(detector.StateCount() == 1);
}

void TestInspectsTypes() {
    AH_CHECK(edr::ApiHookDetector::Inspects(EDR_EVT_ETW_TAMPER));
    AH_CHECK(edr::ApiHookDetector::Inspects(EDR_EVT_WINDOWS_HOOK));
    AH_CHECK(edr::ApiHookDetector::Inspects(EDR_EVT_IMAGE_LOAD));
    AH_CHECK(edr::ApiHookDetector::Inspects(EDR_EVT_PROCESS_ACCESS));
    AH_CHECK(!edr::ApiHookDetector::Inspects(EDR_EVT_REG_WRITE));
}

} // namespace

void RunApiHookDetectorTests() {
    TestDisabled();
    TestProtectedEtwProviderPatch();
    TestBenignTamperTypeIgnored();
    TestInspectsTypes();
}