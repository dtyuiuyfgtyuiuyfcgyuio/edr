/*
 * netprovider_persist_detector_tests.cpp - Unit tests for
 * NetProviderPersistDetector (T1556.008) and the production rule it feeds
 * (EDR-488).
 *
 * REG_WRITE events are built in BOTH house shapes (CLAUDE.md registry
 * contract):
 *   - driver/imonitor shape: kRegKey = bare key path, kRegValue = value
 *     name (no value data in the kernel event);
 *   - sysmon/reg_watch/reg_baseline snapshot shape: kRegKey = full path
 *     including the value name, kRegValue = the written data.
 * The Order-key signal is covered in both shapes; ProviderPath covers the
 * snapshot shape (90 / 85 / silent) and the driver shape (85).
 */
#include "netprovider_persist_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "netprovider_persist_detector.h"
#include "rule_engine.h"

namespace {

#define NP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "netprovider persist detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

constexpr uint64_t kSecond = 10000000ULL;

/* REG_WRITE constructor; both house shapes only differ in what the caller
 * passes for key/value (see file comment). ts100ns is always explicit. */
edr::Event RegWrite(const std::string& key, const std::string& value,
                    uint32_t pid, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.pid = pid;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = key;
    event.fields[edr::field::kRegValue] = value;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kNetProviderPersistScore);
    return it == event.fields.end() ? "" : it->second;
}

struct RuleHit {
    std::string ruleId;
    std::string severity;
    std::vector<std::string> mitre;
};

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

bool Has(const std::vector<RuleHit>& hits, const char* id) {
    for (const RuleHit& hit : hits) {
        if (hit.ruleId == id) return true;
    }
    return false;
}

const RuleHit* Find(const std::vector<RuleHit>& hits, const char* id) {
    for (const RuleHit& hit : hits) {
        if (hit.ruleId == id) return &hit;
    }
    return nullptr;
}

bool HasMitre(const RuleHit& hit, const char* technique) {
    return std::find(hit.mitre.begin(), hit.mitre.end(), technique) !=
           hit.mitre.end();
}

bool RulesTextContains(const char* path, const char* needle) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::string text((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    return text.find(needle) != std::string::npos;
}

void TestInspectsAndDisabled() {
    NP_CHECK(edr::NetProviderPersistDetector::Inspects(EDR_EVT_REG_WRITE));
    NP_CHECK(
        !edr::NetProviderPersistDetector::Inspects(EDR_EVT_PROCESS_START));
    NP_CHECK(!edr::NetProviderPersistDetector::Inspects(
        EDR_EVT_POWERSHELL_SCRIPT));

    edr::NetProviderPersistDetector detector(false, 55, 60, 1024);
    edr::Event event = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order",
        "ProviderOrder", 6001, 1000 * kSecond);
    detector.Enrich(event);
    NP_CHECK(Score(event).empty());
    NP_CHECK(event.fields.find(edr::field::kNetProviderPersistVerdict) ==
             event.fields.end());
}

/* Driver shape: kRegKey ends at ...\Control\NetworkProvider\Order and
 * kRegValue carries the value name. */
void TestOrderKeyWriteDriverShape() {
    edr::NetProviderPersistDetector detector(true, 55, 60, 1024);
    const std::string key =
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order";
    edr::Event event = RegWrite(key, "ProviderOrder", 6002, 1000 * kSecond);
    detector.Enrich(event);
    NP_CHECK(Score(event) == "85");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistVerdict) ==
             "malicious");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistSignals) ==
             "provider_order_key_write");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistKeys) == key);
    NP_CHECK(detector.StateCount() == 1);
}

/* Snapshot shape: the value name is the last key segment and kRegValue
 * carries the written data. */
void TestOrderKeyWriteSnapshotShape() {
    edr::NetProviderPersistDetector detector(true, 55, 60, 1024);
    const std::string key =
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order\\"
        "ProviderOrder";
    edr::Event event = RegWrite(key, "PdPolyWan", 6003, 1010 * kSecond);
    detector.Enrich(event);
    NP_CHECK(Score(event) == "85");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistSignals) ==
             "provider_order_key_write");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistVerdict) ==
             "malicious");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistKeys) == key);
}

/* Snapshot shape: ProviderPath data pointing outside the system
 * directories. Data casing is irrelevant. */
void TestProviderPathExternalDll() {
    edr::NetProviderPersistDetector detector(true, 55, 60, 1024);
    const std::string key =
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\evilnp\\NetworkProvider\\"
        "ProviderPath";
    edr::Event event = RegWrite(key, "C:\\ProgramData\\evil\\np.dll", 6004,
                                1020 * kSecond);
    detector.Enrich(event);
    NP_CHECK(Score(event) == "90");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistVerdict) ==
             "malicious");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistSignals) ==
             "provider_path_external_dll");

    edr::Event mixed = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\evilnp2\\NetworkProvider\\"
        "ProviderPath",
        "C:\\ProgramData\\Evil\\NP.DLL", 6004, 1030 * kSecond);
    detector.Enrich(mixed);
    NP_CHECK(Score(mixed) == "90");
    NP_CHECK(mixed.fields.at(edr::field::kNetProviderPersistSignals) ==
             "provider_path_external_dll");
}

/* Snapshot shape: ProviderPath data resolving to System32/SysWOW64 is a
 * legitimate provider install and must stay silent. */
void TestProviderPathSystemDirectorySilent() {
    edr::NetProviderPersistDetector detector(true, 55, 60, 1024);
    edr::Event literal = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\"
        "NetworkProvider\\ProviderPath",
        "C:\\Windows\\System32\\ntlanman.dll", 6005, 1040 * kSecond);
    detector.Enrich(literal);
    NP_CHECK(Score(literal).empty());
    NP_CHECK(literal.fields.find(edr::field::kNetProviderPersistVerdict) ==
             literal.fields.end());

    edr::Event envVar = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\"
        "NetworkProvider\\ProviderPath",
        "%SystemRoot%\\System32\\ntlanman.dll", 6005, 1050 * kSecond);
    detector.Enrich(envVar);
    NP_CHECK(Score(envVar).empty());

    edr::Event sysWow = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\RasMan\\NetworkProvider\\"
        "ProviderPath",
        "C:\\Windows\\SysWOW64\\rasapi32.dll", 6005, 1060 * kSecond);
    detector.Enrich(sysWow);
    NP_CHECK(Score(sysWow).empty());
    NP_CHECK(detector.StateCount() == 0); /* silence creates no dedup state */
}

/* Snapshot shape: the whitelist requires the system-directory needle to be
 * followed by a separator or end-of-string. "System32Malware" contains
 * "System32" but is NOT the system directory and must still be flagged. */
void TestProviderPathSystem32PrefixSpoofFlagged() {
    edr::NetProviderPersistDetector detector(true, 55, 60, 1024);
    const std::string key =
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\evilnp\\NetworkProvider\\"
        "ProviderPath";
    edr::Event spoof =
        RegWrite(key, "C:\\Windows\\System32Malware\\evil.dll", 6011,
                 1150 * kSecond);
    detector.Enrich(spoof);
    NP_CHECK(Score(spoof) == "90");
    NP_CHECK(spoof.fields.at(edr::field::kNetProviderPersistVerdict) ==
             "malicious");
    NP_CHECK(spoof.fields.at(edr::field::kNetProviderPersistSignals) ==
             "provider_path_external_dll");
}

/* "%%SystemRoot%%\System32\x.dll" stays silent (current behavior): with
 * '%' stripped the system-directory needle matches. An unexpanded env-var
 * path cannot be loaded by the provider manager anyway, so treating it as
 * a legitimate install is acceptable. */
void TestProviderPathDoublePercentUnexpandedSilent() {
    edr::NetProviderPersistDetector detector(true, 55, 60, 1024);
    edr::Event event = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\"
        "NetworkProvider\\ProviderPath",
        "%%SystemRoot%%\\System32\\x.dll", 6012, 1160 * kSecond);
    detector.Enrich(event);
    NP_CHECK(Score(event).empty());
    NP_CHECK(event.fields.find(edr::field::kNetProviderPersistVerdict) ==
             event.fields.end());
    NP_CHECK(detector.StateCount() == 0);
}

/* Driver shape: kRegKey ends at ...\NetworkProvider and kRegValue is the
 * value name; no value data exists in the kernel event, so the write is
 * kept as the mid-band signal for review. */
void TestProviderPathValueWriteDriverShape() {
    edr::NetProviderPersistDetector detector(true, 55, 60, 1024);
    const std::string key =
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\mysvc\\NetworkProvider";
    edr::Event event = RegWrite(key, "ProviderPath", 6006, 1070 * kSecond);
    detector.Enrich(event);
    NP_CHECK(Score(event) == "85");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistSignals) ==
             "provider_path_value_write");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistVerdict) ==
             "malicious");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistKeys) == key);
}

/* Snapshot shape whose data cannot be resolved to a path (no backslash):
 * malformed or hostile, mid-band write signal instead of a silent drop. */
void TestProviderPathValueWriteSnapshotUnparseableData() {
    edr::NetProviderPersistDetector detector(true, 55, 60, 1024);
    const std::string key =
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\badsvc\\NetworkProvider\\"
        "ProviderPath";
    edr::Event event = RegWrite(key, "npdll", 6007, 1080 * kSecond);
    detector.Enrich(event);
    NP_CHECK(Score(event) == "85");
    NP_CHECK(event.fields.at(edr::field::kNetProviderPersistSignals) ==
             "provider_path_value_write");
}

void TestUnrelatedRegistryWriteSilent() {
    edr::NetProviderPersistDetector detector(true, 55, 60, 1024);
    edr::Event runKey = RegWrite(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater",
        "C:\\Temp\\updater.exe", 6008, 1090 * kSecond);
    detector.Enrich(runKey);
    NP_CHECK(Score(runKey).empty());

    /* The value name ProviderPath outside a NetworkProvider key is not a
     * provider install. */
    edr::Event otherValue = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\"
        "Parameters",
        "ProviderPath", 6008, 1100 * kSecond);
    detector.Enrich(otherValue);
    NP_CHECK(Score(otherValue).empty());
    NP_CHECK(detector.StateCount() == 0);
}

/* min_score isolation: the 85 band is suppressed on a 90-threshold
 * instance and stamped on an independent 85-threshold instance. */
void TestMinScoreGate() {
    edr::NetProviderPersistDetector strict(true, 90, 60, 1024);
    edr::Event order = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order",
        "ProviderOrder", 6009, 1110 * kSecond);
    strict.Enrich(order);
    NP_CHECK(Score(order).empty());
    NP_CHECK(strict.StateCount() == 0);

    const uint64_t ts = 1120 * kSecond;
    edr::Event external = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\evilnp\\NetworkProvider\\"
        "ProviderPath",
        "C:\\ProgramData\\evil\\np.dll", 6009, ts);
    strict.Enrich(external);
    NP_CHECK(Score(external) == "90");

    edr::NetProviderPersistDetector relaxed(true, 85, 60, 1024);
    edr::Event allowed = RegWrite(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order",
        "ProviderOrder", 6009, ts);
    relaxed.Enrich(allowed);
    NP_CHECK(Score(allowed) == "85");
}

/* Dedup is per signal|lowered key inside the window: the same key is
 * suppressed (case-insensitively), a different key stamps, and the window
 * expiry re-arms the original key. */
void TestDedupWindow() {
    edr::NetProviderPersistDetector detector(true, 55, 60, 1024);
    const std::string key =
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order";
    const uint64_t base = 1000 * kSecond;

    edr::Event first = RegWrite(key, "ProviderOrder", 6010, base);
    detector.Enrich(first);
    NP_CHECK(!Score(first).empty());
    NP_CHECK(detector.StateCount() == 1);

    edr::Event sameKey = RegWrite(
        "HKLM\\system\\CURRENTCONTROLSET\\Control\\NETWORKPROVIDER\\ORDER",
        "ProviderOrder", 6010, base + 30 * kSecond);
    detector.Enrich(sameKey);
    NP_CHECK(Score(sameKey).empty());
    NP_CHECK(detector.StateCount() == 1);

    edr::Event otherKey = RegWrite(
        "HKLM\\SYSTEM\\ControlSet001\\Control\\NetworkProvider\\Order",
        "ProviderOrder", 6010, base + 45 * kSecond);
    detector.Enrich(otherKey);
    NP_CHECK(!Score(otherKey).empty());
    NP_CHECK(detector.StateCount() == 2);

    edr::Event expired = RegWrite(key, "ProviderOrder", 6010,
                                  base + 120 * kSecond);
    detector.Enrich(expired);
    NP_CHECK(!Score(expired).empty());
    NP_CHECK(detector.StateCount() == 2);
}

/* EDR-488 (T1556.008): netprovider_persist_score >=75 band, high/alert.
 * The production-rule section presets the score field manually and feeds
 * the RuleEngine - the detector itself is covered by the tests above. */
void TestNetProviderPersistProductionRules() {
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[netprovider] skipping production rules: rules file "
                     "not found (%s)\n",
                     path);
        return;
    }
    if (!RulesTextContains(path, "\"EDR-488\"")) {
        std::fprintf(stderr,
                     "[netprovider] skipping production rules: EDR-488 not "
                     "wired into rules.json yet\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    std::vector<RuleHit> hits;
    engine.SetAlertCallback([&hits](const edr::Alert& alert) {
        RuleHit hit;
        hit.ruleId = alert.ruleId;
        hit.severity = alert.severity;
        hit.mitre = alert.mitreAttack;
        hits.push_back(hit);
    });

    const uint64_t ts = 1000 * kSecond;
    auto scored = [&](const char* scoreText) {
        edr::Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.ts100ns = ts;
        event.fields[edr::field::kType] = "REG_WRITE";
        event.fields[edr::field::kNetProviderPersistScore] = scoreText;
        return event;
    };

    /* 85 and 90 both land in the >=75 band: EDR-488, high/alert. */
    hits.clear();
    edr::Event mid = scored("85");
    engine.OnEvent(mid);
    const RuleHit* midHit = Find(hits, "EDR-488");
    NP_CHECK(midHit != nullptr);
    NP_CHECK(midHit->severity == "high");
    NP_CHECK(HasMitre(*midHit, "T1556.008"));
    NP_CHECK(!Has(hits, "EDR-489"));
    NP_CHECK(!Has(hits, "EDR-490"));

    hits.clear();
    edr::Event high = scored("90");
    engine.OnEvent(high);
    NP_CHECK(Has(hits, "EDR-488"));

    /* 74 sits below the >=75 band and must not fire EDR-488. */
    hits.clear();
    edr::Event edge = scored("74");
    engine.OnEvent(edge);
    NP_CHECK(!Has(hits, "EDR-488"));

    /* Dead band: scores 50-54 (and anything <55) never hit any of the new
     * band rules. */
    for (const char* score : {"54", "50"}) {
        hits.clear();
        edr::Event dead = scored(score);
        engine.OnEvent(dead);
        NP_CHECK(!Has(hits, "EDR-488"));
        NP_CHECK(!Has(hits, "EDR-489"));
        NP_CHECK(!Has(hits, "EDR-490"));
    }

    /* A REG_WRITE without a score field never fires the band rule. */
    hits.clear();
    edr::Event clean;
    clean.type = EDR_EVT_REG_WRITE;
    clean.ts100ns = ts;
    clean.fields[edr::field::kType] = "REG_WRITE";
    engine.OnEvent(clean);
    NP_CHECK(!Has(hits, "EDR-488"));
}

} // namespace

void RunNetProviderPersistDetectorTests() {
    std::fprintf(stderr, "[netprovider] TestInspectsAndDisabled\n");
    TestInspectsAndDisabled();
    std::fprintf(stderr, "[netprovider] TestOrderKeyWriteDriverShape\n");
    TestOrderKeyWriteDriverShape();
    std::fprintf(stderr, "[netprovider] TestOrderKeyWriteSnapshotShape\n");
    TestOrderKeyWriteSnapshotShape();
    std::fprintf(stderr, "[netprovider] TestProviderPathExternalDll\n");
    TestProviderPathExternalDll();
    std::fprintf(stderr,
                 "[netprovider] TestProviderPathSystemDirectorySilent\n");
    TestProviderPathSystemDirectorySilent();
    std::fprintf(stderr,
                 "[netprovider] TestProviderPathSystem32PrefixSpoofFlagged\n");
    TestProviderPathSystem32PrefixSpoofFlagged();
    std::fprintf(
        stderr,
        "[netprovider] TestProviderPathDoublePercentUnexpandedSilent\n");
    TestProviderPathDoublePercentUnexpandedSilent();
    std::fprintf(stderr,
                 "[netprovider] TestProviderPathValueWriteDriverShape\n");
    TestProviderPathValueWriteDriverShape();
    std::fprintf(stderr,
                 "[netprovider] "
                 "TestProviderPathValueWriteSnapshotUnparseableData\n");
    TestProviderPathValueWriteSnapshotUnparseableData();
    std::fprintf(stderr, "[netprovider] TestUnrelatedRegistryWriteSilent\n");
    TestUnrelatedRegistryWriteSilent();
    std::fprintf(stderr, "[netprovider] TestMinScoreGate\n");
    TestMinScoreGate();
    std::fprintf(stderr, "[netprovider] TestDedupWindow\n");
    TestDedupWindow();
    std::fprintf(stderr,
                 "[netprovider] TestNetProviderPersistProductionRules\n");
    TestNetProviderPersistProductionRules();
    std::fprintf(stderr, "[netprovider] all passed\n");
}
