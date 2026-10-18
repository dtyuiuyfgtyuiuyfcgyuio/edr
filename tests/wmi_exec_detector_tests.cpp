/*
 * wmi_exec_detector_tests.cpp - Unit tests for WmiExecDetector (T1047).
 *
 * House debugging convention: every block prints "[wmi_exec] TestName" to stderr
 * before running, and "[wmi_exec] all passed" at the end.
 */
#include "wmi_exec_detector_tests.h"

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "wmi_exec_detector.h"

namespace {

#define WMI_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "wmi_exec detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

constexpr uint64_t kSecond = 10000000ULL;

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

edr::Event PsProcEvent(uint64_t ts100ns, const char* commandLine) {
    return ProcEvent(ts100ns,
                     "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                     commandLine);
}

edr::Event WmiEvent(uint64_t ts100ns, const char* operation,
                   const char* query) {
    edr::Event event;
    event.type = EDR_EVT_WMI_EVENT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "WMI_EVENT";
    event.fields[edr::field::kOperationType] = operation;
    if (query != nullptr) event.fields[edr::field::kWmiQuery] = query;
    return event;
}

edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptText) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    if (scriptText != nullptr)
        event.fields[edr::field::kScriptBlockText] = scriptText;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kWmiExecScore) != event.fields.end();
}

} // namespace

void RunWmiExecDetectorTests() {
    std::fprintf(stderr, "[wmi_exec] TestDisabled\n");
    {
        edr::WmiExecDetector detector(false, 55, 300, 1024);
        edr::Event ev = ProcEvent(1000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic process call create \"calc.exe\"");
        detector.Enrich(ev);
        WMI_CHECK(!HasScore(ev));
    }

    std::fprintf(stderr, "[wmi_exec] TestWmicProcessCallCreate\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        edr::Event ev = ProcEvent(1000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic process call create \"cmd.exe /c whoami\"");
        detector.Enrich(ev);
        WMI_CHECK(HasScore(ev));
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecScore) == "75");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecVerdict) == "malicious");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecSignals) ==
                  "wmic_process_call_create");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecTechniques) == "T1047");
    }

    std::fprintf(stderr, "[wmi_exec] TestWmicNodeRemote\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        edr::Event ev = ProcEvent(1000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic /node:192.168.1.5 os get name");
        detector.Enrich(ev);
        WMI_CHECK(HasScore(ev));
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecScore) == "55");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecVerdict) == "suspicious");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecSignals) ==
                  "wmic_node_remote");
    }

    std::fprintf(stderr, "[wmi_exec] TestWmiRemoteCreds\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        edr::Event ev = ProcEvent(1000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic /node:192.168.1.5 /user:admin /password:Secret123 os get name");
        detector.Enrich(ev);
        WMI_CHECK(HasScore(ev));
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecScore) == "74");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecVerdict) == "suspicious");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecSignals) ==
                  "wmic_remote_creds");
    }

    std::fprintf(stderr, "[wmi_exec] TestPsInvokeCreate\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        edr::Event ev = PsProcEvent(1000 * kSecond,
            "powershell.exe -Command \"Invoke-CimMethod -ClassName Win32_Process "
            "-MethodName Create -Arguments @{CommandLine='calc.exe'}\"");
        detector.Enrich(ev);
        WMI_CHECK(HasScore(ev));
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecScore) == "75");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecVerdict) == "malicious");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecSignals) ==
                  "ps_invoke_create");
    }

    std::fprintf(stderr, "[wmi_exec] TestPsGetWin32Create\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        edr::Event ev = PsProcEvent(1000 * kSecond,
            "powershell.exe -Command \"$p = Get-WmiObject Win32_Process; "
            "$p.Create('calc.exe')\"");
        detector.Enrich(ev);
        WMI_CHECK(HasScore(ev));
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecScore) == "75");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecVerdict) == "malicious");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecSignals) ==
                  "ps_getwin32_create");
    }

    std::fprintf(stderr, "[wmi_exec] TestHiddenWindow\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        edr::Event ev = PsProcEvent(1000 * kSecond,
            "powershell.exe -Command \"$s = [wmiclass]'Win32_ProcessStartup'; "
            "$s.ShowWindow = 0; $s.CreateFlags = 0x08000000; "
            "(Invoke-CimMethod -ClassName Win32_Process -MethodName Create)\"");
        detector.Enrich(ev);
        WMI_CHECK(HasScore(ev));
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecScore) == "75");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecVerdict) == "malicious");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecSignals).find(
                  "win32_processstartup_hidden") != std::string::npos);
    }

    std::fprintf(stderr, "[wmi_exec] TestNonSystem32Wmic\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        edr::Event ev = ProcEvent(1000 * kSecond,
            "C:\\Users\\Example\\AppData\\Local\\Temp\\wmic.exe",
            "wmic os get name");
        detector.Enrich(ev);
        WMI_CHECK(HasScore(ev));
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecScore) == "55");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecVerdict) == "suspicious");
        WMI_CHECK(ev.fields.at(edr::field::kWmiExecSignals) ==
                  "wmic_nonsystem32");
    }

    std::fprintf(stderr, "[wmi_exec] TestPureQuerySilent\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        edr::Event wmi = ProcEvent(1000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic os get name");  // no Create / no /node:
        detector.Enrich(wmi);
        WMI_CHECK(!HasScore(wmi));

        edr::Event ps = PsProcEvent(2000 * kSecond,
            "powershell.exe -Command \"Get-WmiObject Win32_ComputerSystem\"");
        detector.Enrich(ps);
        WMI_CHECK(!HasScore(ps));  // pure recon -> discovery_recon, not us
    }

    std::fprintf(stderr, "[wmi_exec] TestNonWmiProcessSilent\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        edr::Event notepad = ProcEvent(1000 * kSecond,
            "C:\\Windows\\System32\\notepad.exe", "notepad.exe");
        detector.Enrich(notepad);
        WMI_CHECK(!HasScore(notepad));

        edr::Event cmd = ProcEvent(2000 * kSecond,
            "C:\\Windows\\System32\\cmd.exe", "cmd /c dir C:\\Windows");
        detector.Enrich(cmd);
        WMI_CHECK(!HasScore(cmd));
    }

    std::fprintf(stderr, "[wmi_exec] TestPsScriptBodyNotInspected\n");
    {
        // PS WMI-exec content lives in kScriptBlockText, but this module does
        // NOT inspect POWERSHELL_SCRIPT, so it must stay silent (no overlap,
        // and we never read the script block for our inspected types).
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        edr::Event script = ScriptEvent(1000 * kSecond,
            "Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
            "-Arguments @{CommandLine='calc.exe'}");
        detector.Enrich(script);
        WMI_CHECK(!HasScore(script));

        // The same content reached via the powershell.exe command line hits.
        edr::Event ps = PsProcEvent(2000 * kSecond,
            "powershell.exe -Command \"Invoke-CimMethod -ClassName Win32_Process "
            "-MethodName Create -Arguments @{CommandLine='calc.exe'}\"");
        detector.Enrich(ps);
        WMI_CHECK(HasScore(ps));
    }

    std::fprintf(stderr, "[wmi_exec] TestInspectWhitelist\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);

        edr::Event file;
        file.type = EDR_EVT_FILE_CREATE;
        file.ts100ns = 1000 * kSecond;
        file.fields[edr::field::kType] = "FILE_CREATE";
        file.fields[edr::field::kImage] = "wmic.exe";
        file.fields[edr::field::kCommandLine] = "wmic process call create calc";
        detector.Enrich(file);
        WMI_CHECK(!HasScore(file));

        edr::Event net;
        net.type = EDR_EVT_NET_CONNECT;
        net.ts100ns = 2000 * kSecond;
        net.fields[edr::field::kType] = "NET_CONNECT";
        net.fields[edr::field::kImage] = "wmic.exe";
        net.fields[edr::field::kCommandLine] = "wmic process call create calc";
        detector.Enrich(net);
        WMI_CHECK(!HasScore(net));

        // Typical WMI subscription event -> belongs to wmi_persistence, silent here.
        edr::Event sub = WmiEvent(3000 * kSecond, "PERMANENT_EVENT_SUBSCRIPTION",
            "SELECT * FROM __InstanceModificationEvent WHERE TargetInstance ISA "
            "'Win32_PerfFormattedData'");
        detector.Enrich(sub);
        WMI_CHECK(!HasScore(sub));

        // POWERSHELL_SCRIPT type is also not inspected by this module.
        edr::Event script = ScriptEvent(4000 * kSecond,
            "wmic process call create calc");
        detector.Enrich(script);
        WMI_CHECK(!HasScore(script));
    }

    std::fprintf(stderr, "[wmi_exec] TestThreshold54vs55\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        // 54 (below floor) -> fully silent.
        edr::Event low = ProcEvent(1000 * kSecond,
            "C:\\Temp\\wm1c.exe",  // typosquat, low confidence
            "wm1c os get");
        detector.Enrich(low);
        WMI_CHECK(!HasScore(low));

        // 55 (suspicious floor) -> written.
        edr::Event high = ProcEvent(2000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic /node:10.0.0.9 os get name");
        detector.Enrich(high);
        WMI_CHECK(HasScore(high));
        WMI_CHECK(high.fields.at(edr::field::kWmiExecScore) == "55");
        WMI_CHECK(high.fields.at(edr::field::kWmiExecVerdict) == "suspicious");
    }

    std::fprintf(stderr, "[wmi_exec] TestThreshold74vs75\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        // 74 (suspicious, just below malicious) -> suspicious.
        edr::Event low = ProcEvent(1000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic /node:10.0.0.9 /user:admin /password:Secret123 os get name");
        detector.Enrich(low);
        WMI_CHECK(HasScore(low));
        WMI_CHECK(low.fields.at(edr::field::kWmiExecScore) == "74");
        WMI_CHECK(low.fields.at(edr::field::kWmiExecVerdict) == "suspicious");

        // 75 (malicious floor) -> malicious.
        edr::Event high = ProcEvent(2000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic process call create \"calc.exe\"");
        detector.Enrich(high);
        WMI_CHECK(HasScore(high));
        WMI_CHECK(high.fields.at(edr::field::kWmiExecScore) == "75");
        WMI_CHECK(high.fields.at(edr::field::kWmiExecVerdict) == "malicious");
    }

    std::fprintf(stderr, "[wmi_exec] TestMinScoreConfig\n");
    {
        // min_score above computed score -> silent.
        edr::WmiExecDetector detector(true, 90, 300, 1024);
        edr::Event ev = ProcEvent(1000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic process call create \"calc.exe\"");
        detector.Enrich(ev);
        WMI_CHECK(!HasScore(ev));
    }

    std::fprintf(stderr, "[wmi_exec] TestDedupWindow\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1024);
        const char* cmd = "wmic process call create \"calc.exe\"";
        edr::Event first = ProcEvent(1000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe", cmd);
        detector.Enrich(first);
        WMI_CHECK(HasScore(first));

        edr::Event second = ProcEvent(1010 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe", cmd);
        detector.Enrich(second);
        WMI_CHECK(!HasScore(second));  // within dedup window

        edr::Event third = ProcEvent(1000 * kSecond + 301 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe", cmd);
        detector.Enrich(third);
        WMI_CHECK(HasScore(third));  // window elapsed
    }

    std::fprintf(stderr, "[wmi_exec] TestStateCapacity\n");
    {
        edr::WmiExecDetector detector(true, 55, 300, 1);
        edr::Event a = ProcEvent(1000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic process call create \"calc.exe\"");
        detector.Enrich(a);
        WMI_CHECK(HasScore(a));
        edr::Event b = ProcEvent(2000 * kSecond,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "wmic /node:10.0.0.9 os get name");
        detector.Enrich(b);
        WMI_CHECK(HasScore(b));
        WMI_CHECK(detector.StateCount() == 1);  // capacity reset on overflow
    }

    std::fprintf(stderr, "[wmi_exec] all passed\n");
}
