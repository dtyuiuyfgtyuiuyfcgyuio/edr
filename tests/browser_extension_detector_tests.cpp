/*
 * browser_extension_detector_tests.cpp - Unit tests for
 * BrowserExtensionDetector (T1176).
 */
#include "browser_extension_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

#include "browser_extension_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define BE_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error(
            "browser extension detector test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

edr::Event ProcEvent(uint64_t ts100ns, const char* image,
                     const char* commandLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    if (image != nullptr) event.fields[edr::field::kImage] = image;
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

edr::Event ScriptEvent(uint64_t ts100ns, const char* commandLine,
                       const char* script) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kImage] =
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    if (script != nullptr)
        event.fields[edr::field::kScriptBlockText] = script;
    return event;
}

edr::Event RegEvent(uint64_t ts100ns, const char* key, const char* value,
                    const char* operation = nullptr) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = key;
    if (value != nullptr) event.fields[edr::field::kRegValue] = value;
    if (operation != nullptr)
        event.fields[edr::field::kRegOperation] = operation;
    return event;
}

std::string Score(const edr::Event& event) {
    const auto it = event.fields.find(edr::field::kBrowserExtensionScore);
    return it == event.fields.end() ? std::string() : it->second;
}

void CheckStamped(const edr::Event& event, const char* score) {
    BE_CHECK(Score(event) == score);
    BE_CHECK(event.fields.count(edr::field::kBrowserExtensionVerdict) == 1);
    BE_CHECK(event.fields.count(edr::field::kBrowserExtensionSignals) == 1);
    BE_CHECK(event.fields.count(edr::field::kBrowserExtensionEvidence) == 1);
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunBrowserExtensionDetectorTests() {
    std::fprintf(stderr, "[browser-extension] TestDisabled\n");
    {
        edr::BrowserExtensionDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9000 * kSecond,
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "chrome.exe --load-extension=C:\\Users\\bob\\Downloads\\addon");
        detector.Enrich(event);
        BE_CHECK(Score(event).empty());
        BE_CHECK(detector.StateCount() == 0);
    }

    std::fprintf(stderr, "[browser-extension] TestWritableLoadExtension\n");
    {
        edr::BrowserExtensionDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9001 * kSecond,
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "chrome.exe --load-extension=\"C:\\Users\\bob\\AppData\\Local\\Temp\\addon\"");
        detector.Enrich(event);
        CheckStamped(event, "80");
        BE_CHECK(event.fields.at(edr::field::kBrowserExtensionVerdict) ==
                 "malicious");

        edr::Event forwardSlashes = ProcEvent(
            9002 * kSecond,
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "chrome.exe --load-extension=C:/Users/bob/Downloads/addon");
        detector.Enrich(forwardSlashes);
        CheckStamped(forwardSlashes, "80");
    }

    std::fprintf(stderr, "[browser-extension] TestEdgeSwitchCombination\n");
    {
        edr::BrowserExtensionDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9002 * kSecond,
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "msedge.exe --disable-extensions-except=C:\\Tools\\payload "
            "--load-extension=C:\\Tools\\payload");
        detector.Enrich(event);
        CheckStamped(event, "70");

        edr::Event mismatched = ProcEvent(
            9003 * kSecond,
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "msedge.exe --disable-extensions-except=C:\\Tools\\approved "
            "--load-extension=C:\\Users\\bob\\Downloads\\payload");
        detector.Enrich(mismatched);
        CheckStamped(mismatched, "80");
        BE_CHECK(mismatched.fields.at(edr::field::kBrowserExtensionSignals) !=
                 "risky unpacked extension isolated by switch");
    }

    std::fprintf(stderr, "[browser-extension] TestChromiumLoadExtension\n");
    {
        edr::BrowserExtensionDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            9003 * kSecond, "C:\\Chromium\\chromium.exe",
            "chromium.exe --load-extension=C:\\Tools\\qa-addon");
        detector.Enrich(event);
        CheckStamped(event, "60");
        BE_CHECK(event.fields.at(edr::field::kBrowserExtensionVerdict) ==
                 "suspicious");
    }

    std::fprintf(stderr, "[browser-extension] TestForceListPolicyWrite\n");
    {
        edr::BrowserExtensionDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            9004 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\"
            "ExtensionInstallForcelist\\1",
            "abcdefghijklmnopabcdefghijklmnop;https://evil/update.xml");
        detector.Enrich(event);
        CheckStamped(event, "80");
    }

    std::fprintf(stderr, "[browser-extension] TestExtensionSettingsWrite\n");
    {
        edr::BrowserExtensionDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            9005 * kSecond,
            "HKCU\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionSettings",
            "{\"abcdefghijklmnopabcdefghijklmnop\":"
            "{\"installation_mode\":\"force_installed\"}}");
        detector.Enrich(event);
        CheckStamped(event, "80");

        edr::Event escaped = RegEvent(
            9006 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionSettings",
            R"({"ponmlkjihgfedcbaponmlkjihgfedcba":{"installation_mode":"force\u005finstalled"}})");
        detector.Enrich(escaped);
        CheckStamped(escaped, "70");
    }

    std::fprintf(stderr, "[browser-extension] TestHkuPolicyWrite\n");
    {
        edr::BrowserExtensionDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            9007 * kSecond,
            "HKU\\S-1-5-21-1-2-3-1001\\SOFTWARE\\Policies\\Google\\Chrome\\"
            "ExtensionInstallForcelist\\1",
            "abcdefghijklmnopabcdefghijklmnop");
        detector.Enrich(event);
        CheckStamped(event, "75");
    }

    std::fprintf(stderr, "[browser-extension] TestExternalExtensionWrite\n");
    {
        edr::BrowserExtensionDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            9006 * kSecond,
            "HKLM\\SOFTWARE\\Google\\Chrome\\Extensions\\"
            "abcdefghijklmnopabcdefghijklmnop",
            "C:\\Users\\bob\\AppData\\Local\\addon");
        detector.Enrich(event);
        CheckStamped(event, "90");
    }

    std::fprintf(stderr, "[browser-extension] TestPowerShellScriptField\n");
    {
        edr::BrowserExtensionDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            9007 * kSecond, "powershell.exe -NoProfile",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Chromium\\"
            "ExtensionInstallForcelist' -Name 1 -Value "
            "'abcdefghijklmnopabcdefghijklmnop;https://evil/update.xml'");
        detector.Enrich(event);
        CheckStamped(event, "90");
        BE_CHECK(event.fields.at(edr::field::kBrowserExtensionEvidence) ==
                 "forced browser extension policy written");
        BE_CHECK(event.fields.at(edr::field::kBrowserExtensionEvidence).find(
                     "https://evil") == std::string::npos);
    }

    std::fprintf(stderr, "[browser-extension] TestReadOnlyAndOrdinarySilent\n");
    {
        edr::BrowserExtensionDetector detector(true, 55, 300, 1024);
        edr::Event query = ProcEvent(
            9008 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\"
            "ExtensionInstallForcelist /s");
        detector.Enrich(query);
        BE_CHECK(Score(query).empty());

        edr::Event get = ScriptEvent(
            9009 * kSecond, nullptr,
            "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\"
            "Edge\\ExtensionSettings'");
        detector.Enrich(get);
        BE_CHECK(Score(get).empty());

        edr::Event ordinary = ProcEvent(
            9010 * kSecond,
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "chrome.exe https://intranet.example/");
        detector.Enrich(ordinary);
        BE_CHECK(Score(ordinary).empty());

        edr::Event unrelated = ProcEvent(
            9011 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "echo chrome.exe --load-extension=C:\\Users\\bob\\addon");
        detector.Enrich(unrelated);
        BE_CHECK(Score(unrelated).empty());

        edr::Event partialSwitch = ProcEvent(
            9012 * kSecond,
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "chrome.exe --load-extension-not=C:\\Users\\bob\\addon");
        detector.Enrich(partialSwitch);
        BE_CHECK(Score(partialSwitch).empty());

        edr::Event blocked = RegEvent(
            9013 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionSettings",
            "{\"*\":{\"installation_mode\":\"blocked\"}}");
        detector.Enrich(blocked);
        BE_CHECK(Score(blocked).empty());

        edr::Event unrelatedText = RegEvent(
            9014 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionSettings",
            R"({"abcdefghijklmnopabcdefghijklmnop":{"installation_mode":"blocked","blocked_install_message":"do not use force_installed here"}})");
        detector.Enrich(unrelatedText);
        BE_CHECK(Score(unrelatedText).empty());

        edr::Event malformed = RegEvent(
            9015 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionSettings",
            R"({"abcdefghijklmnopabcdefghijklmnop":{"installation_mode":"force_installed")");
        detector.Enrich(malformed);
        BE_CHECK(Score(malformed).empty());

        edr::Event inactiveRename = RegEvent(
            9016 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\"
            "ExtensionInstallForcelist.disabled\\1",
            "abcdefghijklmnopabcdefghijklmnop;https://evil/update.xml",
            "SnapshotChange");
        detector.Enrich(inactiveRename);
        BE_CHECK(Score(inactiveRename).empty());

        edr::Event backupRoot = RegEvent(
            9017 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\ChromeBackup\\"
            "ExtensionInstallForcelist\\1",
            "abcdefghijklmnopabcdefghijklmnop;https://evil/update.xml");
        detector.Enrich(backupRoot);
        BE_CHECK(Score(backupRoot).empty());

        edr::Event renameInto = RegEvent(
            9017 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\staged",
            nullptr, "RenameKey");
        renameInto.fields[edr::field::kRegNewTarget] =
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\"
            "ExtensionInstallForcelist";
        detector.Enrich(renameInto);
        CheckStamped(renameInto, "70");

        edr::Event renameOut = RegEvent(
            9018 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\"
            "ExtensionInstallForcelist",
            nullptr, "RenameKey");
        renameOut.fields[edr::field::kRegNewTarget] =
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\"
            "ExtensionInstallForcelist.disabled";
        detector.Enrich(renameOut);
        BE_CHECK(Score(renameOut).empty());

        /* Driver callbacks carry only the value name for this shape. That
         * limited evidence must stay below the default alert threshold. */
        edr::Event nameOnly = RegEvent(
            9014 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome",
            "ExtensionSettings");
        detector.Enrich(nameOnly);
        BE_CHECK(Score(nameOnly).empty());

        edr::Event deleted = RegEvent(
            9015 * kSecond,
            "HKCU\\SOFTWARE\\Policies\\Microsoft\\Edge\\"
            "ExtensionInstallForcelist\\1",
            "abcdefghijklmnopabcdefghijklmnop;https://evil/update.xml",
            "DeleteValue");
        detector.Enrich(deleted);
        BE_CHECK(Score(deleted).empty());
    }

    std::fprintf(stderr, "[browser-extension] TestAllowlistExactMatch\n");
    {
        const std::vector<std::string> allowlist = {
            "chrome:abcdefghijklmnopabcdefghijklmnop@clients2.google.com"};
        edr::BrowserExtensionDetector detector(
            true, 55, 300, 1024, allowlist);
        edr::Event approved = RegEvent(
            9016 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\"
            "ExtensionInstallForcelist\\1",
            "abcdefghijklmnopabcdefghijklmnop");
        detector.Enrich(approved);
        BE_CHECK(Score(approved).empty());

        edr::Event changedHost = RegEvent(
            9017 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\"
            "ExtensionInstallForcelist\\1",
            "abcdefghijklmnopabcdefghijklmnop;https://evil/update.xml");
        detector.Enrich(changedHost);
        CheckStamped(changedHost, "80");

        edr::Event prefixedUrl = ScriptEvent(
            9018 * kSecond, "powershell.exe -NoProfile",
            "Write-Output https://clients2.google.com; "
            "reg add HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\"
            "ExtensionInstallForcelist /v 1 /d "
            "'abcdefghijklmnopabcdefghijklmnop;https://evil.example/update'");
        detector.Enrich(prefixedUrl);
        CheckStamped(prefixedUrl, "90");

        edr::Event statementSeparator = ScriptEvent(
            9019 * kSecond, "powershell.exe -NoProfile",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Google\\"
            "Chrome\\ExtensionInstallForcelist' -Name 1 -Value "
            "'abcdefghijklmnopabcdefghijklmnop'; Write-Host done");
        detector.Enrich(statementSeparator);
        BE_CHECK(Score(statementSeparator).empty());

        /* An approved store host must not suppress a later local-path
         * sideload for the same extension ID. */
        edr::Event localPath = RegEvent(
            9018 * kSecond,
            "HKLM\\SOFTWARE\\Google\\Chrome\\Extensions\\"
            "abcdefghijklmnopabcdefghijklmnop",
            "C:\\Users\\bob\\AppData\\Local\\replacement");
        detector.Enrich(localPath);
        CheckStamped(localPath, "90");

        /* A matching first entry cannot hide another force-installed item
         * from the same ExtensionSettings JSON value. */
        edr::Event mixedPolicy = RegEvent(
            9019 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionSettings",
            R"({"abcdefghijklmnopabcdefghijklmnop":{"installation_mode":"force_installed","update_url":"https://clients2.google.com/service/update2/crx"},"ponmlkjihgfedcbaponmlkjihgfedcba":{"installation_mode":"force_installed","update_url":"https://evil.example/update"}})");
        detector.Enrich(mixedPolicy);
        CheckStamped(mixedPolicy, "85");

        edr::Event approvedPolicy = RegEvent(
            9020 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionSettings",
            R"({"abcdefghijklmnopabcdefghijklmnop":{"installation_mode":"force_installed"},"ponmlkjihgfedcbaponmlkjihgfedcba":{"installation_mode":"blocked"}})");
        detector.Enrich(approvedPolicy);
        BE_CHECK(Score(approvedPolicy).empty());

        /* A separate version write has no install location and must not turn
         * an approved deployment into an alert. */
        edr::Event versionOnly = RegEvent(
            9021 * kSecond,
            "HKLM\\SOFTWARE\\Google\\Chrome\\Extensions\\"
            "abcdefghijklmnopabcdefghijklmnop\\version",
            "1.2.3");
        detector.Enrich(versionOnly);
        BE_CHECK(Score(versionOnly).empty());
    }

    std::fprintf(stderr, "[browser-extension] TestMinimumScore\n");
    {
        edr::BrowserExtensionDetector detector(true, 85, 300, 1024);
        edr::Event below = RegEvent(
            9019 * kSecond,
            "HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\"
            "ExtensionInstallForcelist\\1",
            "abcdefghijklmnopabcdefghijklmnop;https://evil/update.xml");
        detector.Enrich(below);
        BE_CHECK(Score(below).empty());
        BE_CHECK(detector.StateCount() == 0);

        edr::Event above = ScriptEvent(
            9020 * kSecond, "powershell.exe -NoProfile",
            "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Chromium\\"
            "ExtensionInstallForcelist' -Name 1 -Value "
            "'abcdefghijklmnopabcdefghijklmnop;https://evil/update.xml'");
        detector.Enrich(above);
        CheckStamped(above, "100");
    }

    std::fprintf(stderr, "[browser-extension] TestDedupWindow\n");
    {
        edr::BrowserExtensionDetector detector(true, 55, 30, 1024);
        const char* command =
            "chrome.exe --load-extension=C:\\Users\\bob\\Downloads\\addon";
        edr::Event first = ProcEvent(
            9030 * kSecond, "C:\\Chrome\\chrome.exe", command);
        detector.Enrich(first);
        BE_CHECK(!Score(first).empty());

        edr::Event duplicate = ProcEvent(
            9035 * kSecond, "C:\\Chrome\\chrome.exe", command);
        detector.Enrich(duplicate);
        BE_CHECK(Score(duplicate).empty());
        BE_CHECK(detector.StateCount() == 1);

        edr::Event afterWindow = ProcEvent(
            9060 * kSecond, "C:\\Chrome\\chrome.exe", command);
        detector.Enrich(afterWindow);
        BE_CHECK(!Score(afterWindow).empty());
    }

    std::fprintf(stderr, "[browser-extension] TestStateCapacity\n");
    {
        edr::BrowserExtensionDetector detector(true, 55, 300, 2);
        for (uint32_t index = 0; index < 3; ++index) {
            const std::string command =
                "chrome.exe --load-extension=C:\\Users\\bob\\addon" +
                std::to_string(index);
            edr::Event event = ProcEvent(
                (9070 + index) * kSecond, "C:\\Chrome\\chrome.exe",
                command.c_str());
            detector.Enrich(event);
            BE_CHECK(!Score(event).empty());
            BE_CHECK(detector.StateCount() <= 2);
        }
        BE_CHECK(detector.StateCount() == 2);
    }

    std::fprintf(stderr, "[browser-extension] TestInspects\n");
    {
        BE_CHECK(edr::BrowserExtensionDetector::Inspects(
            EDR_EVT_PROCESS_START));
        BE_CHECK(edr::BrowserExtensionDetector::Inspects(
            EDR_EVT_POWERSHELL_SCRIPT));
        BE_CHECK(edr::BrowserExtensionDetector::Inspects(EDR_EVT_REG_WRITE));
        BE_CHECK(!edr::BrowserExtensionDetector::Inspects(EDR_EVT_FILE_READ));
    }

    std::fprintf(stderr, "[browser-extension] all passed\n");
}
