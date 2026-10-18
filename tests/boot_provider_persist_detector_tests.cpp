/*
 * boot_provider_persist_detector_tests.cpp - Unit tests for
 * BootProviderPersistDetector (T1547.003 Time Providers,
 * T1547.012 Print Processors).
 */
#include "boot_provider_persist_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "boot_provider_persist_detector.h"

namespace {

#define BP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "boot provider persist detector test failed at line " +
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

edr::Event RegEvent(uint64_t ts100ns, const char* regKey,
                    const char* regValue) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = regKey;
    if (regValue != nullptr)
        event.fields[edr::field::kRegValue] = regValue;
    return event;
}

edr::Event ScriptEvent(uint64_t ts100ns, const char* script) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kImage] =
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    event.fields[edr::field::kScriptBlockText] = script;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kBootProviderScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunBootProviderPersistDetectorTests() {
    std::fprintf(stderr, "[boot-provider] TestDisabled\n");
    {
        edr::BootProviderPersistDetector detector(false, 55, 300, 1024);
        edr::Event event = RegEvent(
            6000 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\"
            "TimeProviders\\EvilProvider",
            "DllName");
        detector.Enrich(event);
        BP_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[boot-provider] TestTimeProviderDll\n");
    {
        edr::BootProviderPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            6000 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\"
            "TimeProviders\\EvilProvider",
            "DllName");
        detector.Enrich(event);
        BP_CHECK(Score(event) == "90");
        BP_CHECK(event.fields.at(
            edr::field::kBootProviderVerdict) == "malicious");
    }
    std::fprintf(stderr, "[boot-provider] TestPrintProcessorDll\n");
    {
        edr::BootProviderPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            6001 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\"
            "Environments\\Windows x64\\Print Processors\\Backdoor",
            "Driver");
        detector.Enrich(event);
        BP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[boot-provider] TestCommandPlaneRegAdd\n");
    {
        edr::BootProviderPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            6002 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\"
            "TimeProviders\\Rogue\" /v DllName /t REG_SZ /d "
            "C:\\Temp\\evil.dll /f");
        detector.Enrich(event);
        BP_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[boot-provider] TestAddPrinterDriverApi\n");
    {
        /* Object-model registration scores 80, below the direct provider
         * subkey writes above: the API call is one step removed from the
         * registration that actually persists. */
        edr::BootProviderPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            6003 * kSecond,
            "Add-PrinterDriver -Name 'Rogue' -InfPath C:\\Temp\\p.inf; "
            "$null = AddPrintProcessor('C:\\Temp\\proc.dll')");
        detector.Enrich(event);
        BP_CHECK(Score(event) == "80");
    }
    std::fprintf(stderr, "[boot-provider] TestW32tmRegister\n");
    {
        edr::BootProviderPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            6004 * kSecond, "C:\\Windows\\System32\\w32tm.exe",
            "w32tm /register");
        detector.Enrich(event);
        BP_CHECK(Score(event) == "75");
    }
    std::fprintf(stderr, "[boot-provider] TestBareSubkeyLowerBand\n");
    {
        edr::BootProviderPersistDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            6005 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\"
            "TimeProviders\\Placeholder",
            "Enabled");
        detector.Enrich(event);
        BP_CHECK(Score(event) == "70");
        BP_CHECK(event.fields.at(
            edr::field::kBootProviderVerdict) == "suspicious");
    }
    std::fprintf(stderr, "[boot-provider] TestBenignSilent\n");
    {
        edr::BootProviderPersistDetector detector(true, 55, 300, 1024);
        /* Read-only enumeration of the provider registrations. */
        edr::Event query = ProcEvent(
            6006 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
            "W32Time\\TimeProviders\" /s");
        detector.Enrich(query);
        BP_CHECK(Score(query).empty());

        edr::Event w32tmQuery = ProcEvent(
            6007 * kSecond, "C:\\Windows\\System32\\w32tm.exe",
            "w32tm /query /status");
        detector.Enrich(w32tmQuery);
        BP_CHECK(Score(w32tmQuery).empty());

        /* An unrelated service subkey write. */
        edr::Event unrelated = RegEvent(
            6008 * kSecond,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Spooler",
            "Start");
        detector.Enrich(unrelated);
        BP_CHECK(Score(unrelated).empty());
    }
    std::fprintf(stderr, "[boot-provider] all passed\n");
}
