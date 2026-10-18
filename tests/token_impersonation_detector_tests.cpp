/*
 * token_impersonation_detector_tests.cpp - Unit tests for
 * TokenImpersonationDetector.
 */
#include "token_impersonation_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "token_impersonation_detector.h"

namespace {

#define TI_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "token impersonation detector test failed at line " +
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

edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptBody) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptBody;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kTokenImpersonationScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunTokenImpersonationDetectorTests() {
    std::fprintf(stderr, "[token-impersonation] TestDisabled\n");
    {
        edr::TokenImpersonationDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond,
            "C:\\Tools\\Rubeus.exe",
            "Rubeus ptt /ticket:evil.kirbi");
        detector.Enrich(event);
        TI_CHECK(Score(event).empty());
    }

    std::fprintf(stderr, "[token-impersonation] TestTooling\n");
    {
        edr::TokenImpersonationDetector detector(true, 55, 300, 1024);
        edr::Event rubeus = ProcEvent(
            1000 * kSecond,
            "C:\\Tools\\Rubeus.exe",
            "Rubeus ptt /ticket:evil.kirbi");
        detector.Enrich(rubeus);
        TI_CHECK(Score(rubeus) == "90");
        TI_CHECK(rubeus.fields.at(edr::field::kTokenImpersonationVerdict) ==
                 "malicious");

        edr::Event pot = ProcEvent(
            1010 * kSecond,
            "C:\\Tools\\PrintSpoofer.exe",
            "PrintSpoofer.exe -i -c cmd.exe");
        detector.Enrich(pot);
        TI_CHECK(Score(pot) == "90");
    }

    std::fprintf(stderr, "[token-impersonation] TestApiChain\n");
    {
        edr::TokenImpersonationDetector detector(true, 55, 300, 1024);
        edr::Event chain = ScriptEvent(
            1000 * kSecond,
            "OpenProcessToken(hProc, TOKEN_DUPLICATE, &hTok); "
            "DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, "
            "TokenPrimary, &hDup); ImpersonateLoggedOnUser(hDup); "
            "CreateProcessWithTokenW(hDup, 0, L'cmd.exe', NULL, 0, NULL, NULL, &si, &pi);");
        detector.Enrich(chain);
        TI_CHECK(Score(chain) == "90");
    }

    std::fprintf(stderr, "[token-impersonation] TestHelperCommands\n");
    {
        edr::TokenImpersonationDetector detector(true, 55, 300, 1024);
        edr::Event helper = ScriptEvent(
            1000 * kSecond,
            "Invoke-TokenManipulation -Token SYSTEM; Invoke-Impersonation");
        detector.Enrich(helper);
        TI_CHECK(Score(helper) == "75");
    }

    std::fprintf(stderr, "[token-impersonation] TestCleanTrafficSilent\n");
    {
        edr::TokenImpersonationDetector detector(true, 55, 300, 1024);
        edr::Event clean = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\whoami.exe",
            "whoami /all");
        detector.Enrich(clean);
        TI_CHECK(Score(clean).empty());
        TI_CHECK(clean.fields.find(edr::field::kTokenImpersonationVerdict) ==
                 clean.fields.end());
    }

    std::fprintf(stderr, "[token-impersonation] TestDedupWindow\n");
    {
        edr::TokenImpersonationDetector detector(true, 55, 60, 1024);
        const char* cmd = "Rubeus ptt /ticket:evil.kirbi";
        edr::Event first = ProcEvent(1000 * kSecond,
                                     "C:\\Tools\\Rubeus.exe",
                                     cmd);
        detector.Enrich(first);
        TI_CHECK(!Score(first).empty());

        edr::Event second = ProcEvent(1030 * kSecond,
                                      "C:\\Tools\\Rubeus.exe",
                                      cmd);
        detector.Enrich(second);
        TI_CHECK(Score(second).empty());

        edr::Event third = ProcEvent(1100 * kSecond,
                                     "C:\\Tools\\Rubeus.exe",
                                     cmd);
        detector.Enrich(third);
        TI_CHECK(!Score(third).empty());
    }

    std::fprintf(stderr, "[token-impersonation] all passed\n");
}
