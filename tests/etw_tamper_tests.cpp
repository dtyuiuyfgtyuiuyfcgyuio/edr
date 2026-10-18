/*
 * etw_tamper_tests.cpp - Unit tests for the ETW tampering collector's pure
 * classification helpers and the production rules they feed (EDR-238 through
 * EDR-240). The helpers require no live ETW state; the rule checks load the
 * production rules file and verify each ETW_TAMPER tamper type is alerted.
 */
#include <windows.h>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "collector_etw_tamper.h"
#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"

namespace {

#define ET_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "etw tamper test failed at line " + std::to_string(line) +
            ": " + expression);
}

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

bool Has(const std::vector<std::string>& hits, const char* id) {
    return std::find(hits.begin(), hits.end(), id) != hits.end();
}

/* RuleEngine hit collector. */
std::vector<std::string> g_hits;

void OnAlert(const edr::Alert& alert) { g_hits.push_back(alert.ruleId); }

void TestGuidToName() {
    /* Canonical uppercase-with-braces forms. */
    ET_CHECK(edr::EtwTamperGuidToName(
                 "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}") ==
             "Microsoft-Windows-PowerShell");
    ET_CHECK(edr::EtwTamperGuidToName(
                 "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}") ==
             "Microsoft-Windows-Sysmon");
    ET_CHECK(edr::EtwTamperGuidToName(
                 "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}") ==
             "Microsoft-Windows-Kernel-Process");
    ET_CHECK(edr::EtwTamperGuidToName(
                 "{7DD42A49-5329-4832-8DFD-43D979153A88}") ==
             "Microsoft-Windows-Kernel-Network");
    ET_CHECK(edr::EtwTamperGuidToName(
                 "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}") ==
             "Microsoft-Windows-DNS-Client");
    ET_CHECK(edr::EtwTamperGuidToName(
                 "{EDD08927-9CC4-4E65-B970-C2560FB5C289}") ==
             "Microsoft-Windows-Kernel-File");
    ET_CHECK(edr::EtwTamperGuidToName(
                 "{2D576B3D-2CEC-4A63-84A6-523F4F0A5D1B}") ==
             "Microsoft-Antimalware-Scan-Interface (AMSI)");
    /* Lower-case, brace-less, and mixed-case inputs normalize identically. */
    ET_CHECK(edr::EtwTamperGuidToName(
                 "a0c1853b-5c40-4b15-8766-3cf1c58f985a") ==
             "Microsoft-Windows-PowerShell");
    ET_CHECK(edr::EtwTamperGuidToName(
                 "A0C1853B-5C40-4B15-8766-3cf1c58f985A") ==
             "Microsoft-Windows-PowerShell");
    /* Unknown GUID -> empty. */
    ET_CHECK(edr::EtwTamperGuidToName(
                 "{00000000-0000-0000-0000-000000000000}").empty());
    ET_CHECK(edr::EtwTamperGuidToName("").empty());
}

void TestPatchDetection() {
    const std::vector<uint8_t> pristine = {
        0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x89, 0x54, 0x24, 0x10, 0x57,
        0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8b};
    /* Identical prologue is not a patch. */
    ET_CHECK(!edr::EtwEventWriteLooksPatched(pristine, pristine));
    /* A leading 'ret' (0xC3) is the canonical patchETW byte. */
    std::vector<uint8_t> patched = pristine;
    patched[0] = 0xC3;
    ET_CHECK(edr::EtwEventWriteLooksPatched(patched, pristine));
    /* Empty pristine (no baseline) never reports a patch. */
    ET_CHECK(!edr::EtwEventWriteLooksPatched(patched, {}));
    /* Size mismatch is not a patch. */
    std::vector<uint8_t> shortObserved(patched.begin(), patched.begin() + 8);
    ET_CHECK(!edr::EtwEventWriteLooksPatched(shortObserved, pristine));
}

void TestHex() {
    const uint8_t bytes[] = {0x00, 0x48, 0xc3, 0xff};
    ET_CHECK(edr::EtwTamperHexBytes(bytes, 4) == "0048c3ff");
    ET_CHECK(edr::EtwTamperHexBytes(bytes, 0).empty());
}

void TestSessionName() {
    const uint32_t pid = 4242;
    ET_CHECK(edr::EtwTamperIsAgentSession(L"EDR-Proctrace-4242", pid));
    ET_CHECK(edr::EtwTamperIsAgentSession(L"EDR-NetTrace-4242", pid));
    ET_CHECK(edr::EtwTamperIsAgentSession(L"EDR-DnsTrace-4242", pid));
    ET_CHECK(edr::EtwTamperIsAgentSession(L"EDR-PipeTrace-4242", pid));
    /* Wrong pid, foreign names, and suffixes do not match. */
    ET_CHECK(!edr::EtwTamperIsAgentSession(L"EDR-Proctrace-9999", pid));
    ET_CHECK(!edr::EtwTamperIsAgentSession(L"EDR-Proctrace-42420", pid));
    ET_CHECK(!edr::EtwTamperIsAgentSession(L"Circus-4242", pid));
    ET_CHECK(!edr::EtwTamperIsAgentSession(L"EDR-Proctrace-4242-extra", pid));
    ET_CHECK(!edr::EtwTamperIsAgentSession(L"", pid));
}

void TestRulesMatchEtwTamper() {
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::printf("skipping rule checks: rules file not found (%s)\n", path);
        return;
    }
    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback(OnAlert);

    struct Case {
        const char* tamperType;
        const char* expectedRule;
    };
    const Case cases[] = {
        {"provider_disabled", "EDR-238"},
        {"etw_event_write_patched", "EDR-239"},
        {"session_stopped", "EDR-240"},
    };
    for (const Case& c : cases) {
        g_hits.clear();
        edr::Event ev;
        ev.type = EDR_EVT_ETW_TAMPER;
        ev.pid = 4242;
        ev.fields[edr::field::kType] = "ETW_TAMPER";
        ev.fields[edr::field::kEtwTamperType] = c.tamperType;
        ev.fields[edr::field::kEtwTamperDetail] = "test context";
        engine.OnEvent(ev);
        ET_CHECK(Has(g_hits, c.expectedRule));
    }

    /* An ETW_TAMPER event with an unknown tamper type must not hit any of the
     * new rules (silent no-op, not a wildcard). */
    g_hits.clear();
    edr::Event other;
    other.type = EDR_EVT_ETW_TAMPER;
    other.fields[edr::field::kType] = "ETW_TAMPER";
    other.fields[edr::field::kEtwTamperType] = "some_other_kind";
    engine.OnEvent(other);
    ET_CHECK(!Has(g_hits, "EDR-238"));
    ET_CHECK(!Has(g_hits, "EDR-239"));
    ET_CHECK(!Has(g_hits, "EDR-240"));
}

} // namespace

int main() {
    try {
        TestGuidToName();
        TestPatchDetection();
        TestHex();
        TestSessionName();
        TestRulesMatchEtwTamper();
        std::printf("etw tamper tests passed\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "etw tamper test failed: %s\n", e.what());
        return 1;
    }
}
