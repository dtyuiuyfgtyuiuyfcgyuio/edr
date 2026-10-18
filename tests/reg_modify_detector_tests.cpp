/*
 * reg_modify_detector_tests.cpp - Unit tests for RegModifyDetector (T1112).
 */
#include "reg_modify_detector_tests.h"

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "reg_modify_detector.h"

namespace {

#define RM_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "reg_modify detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

constexpr uint64_t kSecond = 10000000ULL;

edr::Event RegEvent(uint64_t ts100ns, uint16_t type,
                   const char* key, const char* value,
                   const char* host = nullptr) {
    edr::Event ev;
    ev.type = type;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kRegKey] = key;
    if (value != nullptr) ev.fields[edr::field::kRegValue] = value;
    if (host != nullptr) ev.fields[edr::field::kTargetHost] = host;
    return ev;
}

bool HasScore(const edr::Event& ev) {
    return ev.fields.find(edr::field::kRegModifyScore) != ev.fields.end();
}

const std::string& Score(const edr::Event& ev) {
    return ev.fields.at(edr::field::kRegModifyScore);
}
const std::string& Verdict(const edr::Event& ev) {
    return ev.fields.at(edr::field::kRegModifyVerdict);
}

} // namespace

void RunRegModifyDetectorTests() {
    // ---------- Inspects() type whitelist ----------
    std::fprintf(stderr, "[reg_modify] TestInspectsWhitelist\n");
    {
        edr::RegModifyDetector det(true, 55, 300, 1024);
        edr::Event proc;
        proc.type = EDR_EVT_PROCESS_START;
        proc.ts100ns = 1 * kSecond;
        det.Enrich(proc);
        RM_CHECK(!HasScore(proc));

        edr::Event del = RegEvent(2 * kSecond, EDR_EVT_REG_DELETE,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "EnableLUA");
        det.Enrich(del);
        RM_CHECK(HasScore(del));  // REG_DELETE is inspected and hits
    }

    // ---------- Single tamper: score + verdict ----------
    std::fprintf(stderr, "[reg_modify] TestSingleTamperVerdict\n");
    {
        edr::RegModifyDetector det(true, 55, 300, 1024);
        edr::Event ev = RegEvent(1 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
            "0");
        det.Enrich(ev);
        RM_CHECK(HasScore(ev));
        RM_CHECK(Score(ev) == "75");
        RM_CHECK(Verdict(ev) == "malicious");

        edr::RegModifyDetector det2(true, 55, 300, 1024);
        edr::Event smart = RegEvent(1 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SmartScreen\\EnableSmartScreen",
            "0");
        det2.Enrich(smart);
        RM_CHECK(HasScore(smart));
        RM_CHECK(Score(smart) == "55");
        RM_CHECK(Verdict(smart) == "suspicious");
    }

    // ---------- Threshold 54 vs 55 ----------
    std::fprintf(stderr, "[reg_modify] TestThreshold54vs55\n");
    {
        // 55 side: single SmartScreen off -> 55 (suspicious)
        edr::RegModifyDetector det(true, 55, 300, 1024);
        edr::Event on = RegEvent(1 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SmartScreen\\EnableSmartScreen",
            "0");
        det.Enrich(on);
        RM_CHECK(HasScore(on));
        RM_CHECK(Score(on) == "55");

        // 54 side: benign snapshot (EnableLUA=1) -> silent
        edr::Event benign = RegEvent(2 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
            "1");
        det.Enrich(benign);
        RM_CHECK(!HasScore(benign));

        // 54 side: completely unrelated key -> silent
        edr::Event unrelated = RegEvent(3 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Vendor\\App\\Setting", "Foo");
        det.Enrich(unrelated);
        RM_CHECK(!HasScore(unrelated));
    }

    // ---------- Threshold 74 vs 75 ----------
    std::fprintf(stderr, "[reg_modify] TestThreshold74vs75\n");
    {
        // 75 side: single most-critical tamper (EnableLUA=0) -> 75 malicious
        edr::RegModifyDetector det75(true, 55, 300, 1024);
        edr::Event e75 = RegEvent(1 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
            "0");
        det75.Enrich(e75);
        RM_CHECK(HasScore(e75));
        RM_CHECK(Score(e75) == "75");
        RM_CHECK(Verdict(e75) == "malicious");

        // 74 side: two distinct low-base keys in window -> 55 + 19 = 74 (suspicious)
        edr::RegModifyDetector det74(true, 55, 300, 1024);
        edr::Event s1 = RegEvent(1 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SmartScreen\\EnableSmartScreen",
            "0");
        det74.Enrich(s1);
        RM_CHECK(Score(s1) == "55");
        edr::Event s2 = RegEvent(2 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature",
            "0");
        det74.Enrich(s2);
        RM_CHECK(HasScore(s2));
        RM_CHECK(Score(s2) == "74");
        RM_CHECK(Verdict(s2) == "suspicious");
    }

    // ---------- Dual shape: bare key vs full path both hit ----------
    std::fprintf(stderr, "[reg_modify] TestDualShape\n");
    {
        // driver/imonitor shape: kRegKey bare path, kRegValue = value name
        edr::RegModifyDetector drv(true, 55, 300, 1024);
        edr::Event d = RegEvent(1 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "EnableLUA");
        drv.Enrich(d);
        RM_CHECK(HasScore(d));
        RM_CHECK(Score(d) == "75");
        RM_CHECK(Verdict(d) == "malicious");

        // snapshot shape: kRegKey full path incl. value name, kRegValue = data
        edr::RegModifyDetector snap(true, 55, 300, 1024);
        edr::Event s = RegEvent(1 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
            "0");
        snap.Enrich(s);
        RM_CHECK(HasScore(s));
        RM_CHECK(Score(s) == "75");
        RM_CHECK(Verdict(s) == "malicious");

        // driver shape for ExecutionPolicy (value name == key leaf) still hits
        edr::RegModifyDetector ep(true, 55, 300, 1024);
        edr::Event epd = RegEvent(1 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy",
            "ExecutionPolicy");
        ep.Enrich(epd);
        RM_CHECK(HasScore(epd));
        RM_CHECK(Score(epd) == "65");
        RM_CHECK(Verdict(epd) == "suspicious");
    }

    // ---------- Multi-key breadth escalation ----------
    std::fprintf(stderr, "[reg_modify] TestMultiKeyBreadth\n");
    {
        edr::RegModifyDetector det(true, 55, 300, 1024);
        // 1st distinct key: SmartScreen (base 55) -> 55
        edr::Event e1 = RegEvent(1 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SmartScreen\\EnableSmartScreen",
            "0");
        det.Enrich(e1);
        RM_CHECK(HasScore(e1));
        RM_CHECK(Score(e1) == "55");

        // 2nd distinct key: SMB RequireSecuritySignature (base 55) -> 55 + 19 = 74
        edr::Event e2 = RegEvent(2 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature",
            "0");
        det.Enrich(e2);
        RM_CHECK(HasScore(e2));
        RM_CHECK(Score(e2) == "74");

        // 3rd distinct key: NoLMHash (base 60) -> peak 60 + 2*19 = 98 (malicious)
        edr::Event e3 = RegEvent(3 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash", "0");
        det.Enrich(e3);
        RM_CHECK(HasScore(e3));
        RM_CHECK(Score(e3) == "98");
        RM_CHECK(Verdict(e3) == "malicious");

        // 4th distinct key: LimitBlankPasswordUse (base 60) -> 60 + 3*19 = 117 -> cap 100
        edr::Event e4 = RegEvent(4 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse", "0");
        det.Enrich(e4);
        RM_CHECK(HasScore(e4));
        RM_CHECK(Score(e4) == "100");
        RM_CHECK(Verdict(e4) == "malicious");
    }

    // ---------- Dedup window: no repeat alert ----------
    std::fprintf(stderr, "[reg_modify] TestDedupWindow\n");
    {
        edr::RegModifyDetector det(true, 55, 300, 1024);
        edr::Event first = RegEvent(1000 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\...\\Explorer\\SmartScreen\\EnableSmartScreen", "0");
        det.Enrich(first);
        RM_CHECK(HasScore(first));

        edr::Event second = RegEvent(1010 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\...\\Explorer\\SmartScreen\\EnableSmartScreen", "0");
        det.Enrich(second);
        RM_CHECK(!HasScore(second));  // within 300s window -> suppressed

        edr::Event third = RegEvent(1000 * kSecond + 301 * kSecond,
                                    EDR_EVT_REG_WRITE,
            "HKLM\\...\\Explorer\\SmartScreen\\EnableSmartScreen", "0");
        det.Enrich(third);
        RM_CHECK(HasScore(third));  // window elapsed -> re-alert
    }

    // ---------- State capacity upper bound eviction ----------
    std::fprintf(stderr, "[reg_modify] TestStateCapacity\n");
    {
        edr::RegModifyDetector det(true, 55, 300, 1);  // capacity = 1 host
        edr::Event a = RegEvent(1 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\...\\Explorer\\SmartScreen\\EnableSmartScreen", "0", "hostA");
        det.Enrich(a);
        RM_CHECK(HasScore(a));
        RM_CHECK(det.StateCount() == 1);
        edr::Event b = RegEvent(2 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\...\\Explorer\\SmartScreen\\EnableSmartScreen", "0", "hostB");
        det.Enrich(b);
        RM_CHECK(HasScore(b));
        RM_CHECK(det.StateCount() == 1);  // oldest host evicted, stays at cap
    }

    // ---------- Explicit silence: normal writes must not hit ----------
    std::fprintf(stderr, "[reg_modify] TestExplicitSilence\n");
    {
        edr::RegModifyDetector det(true, 55, 300, 1024);
        // a Run-key autostart write (owned by registry_persistence, not us)
        edr::Event run = RegEvent(1 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MyApp",
            "C:\\Temp\\evil.exe");
        det.Enrich(run);
        RM_CHECK(!HasScore(run));

        // a benign config write
        edr::Event cfg = RegEvent(2 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SOFTWARE\\Vendor\\App\\Version", "2");
        det.Enrich(cfg);
        RM_CHECK(!HasScore(cfg));

        // WDigest SecurityProviders (EDR-260) must NOT match us
        edr::Event wd = RegEvent(3 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\SecurityProviders",
            "wdigest");
        det.Enrich(wd);
        RM_CHECK(!HasScore(wd));

        // LSA DisableRestrictedAdmin (EDR-298) must NOT match us
        edr::Event dra = RegEvent(4 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\DisableRestrictedAdmin",
            "1");
        det.Enrich(dra);
        RM_CHECK(!HasScore(dra));
    }

    // RunAsPPL=0 is a security-control downgrade (T1112), not a benign LSA
    // setting.  Keep this regression test to catch value-name normalization
    // regressions in both driver and snapshot event shapes.
    std::fprintf(stderr, "[reg_modify] TestRunAsPpl\n");
    {
        edr::RegModifyDetector det(true, 55, 300, 1024);
        edr::Event ev = RegEvent(5 * kSecond, EDR_EVT_REG_WRITE,
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL",
            "0");
        det.Enrich(ev);
        RM_CHECK(HasScore(ev));
        RM_CHECK(ev.fields.at(edr::field::kRegModifyScore) == "70");
        RM_CHECK(ev.fields.at(edr::field::kRegModifySignals) ==
                 "lsa_runasppl");
    }

    std::fprintf(stderr, "[reg_modify] all passed\n");
}
