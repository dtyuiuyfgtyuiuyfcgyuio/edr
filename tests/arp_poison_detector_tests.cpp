/*
 * arp_poison_detector_tests.cpp - Unit tests for ArpPoisonDetector
 * (T1557.002) and the production rules that consume its score field.
 *
 * Detector tiers asserted here (per user/arp_poison_detector.cpp):
 *   80 arp_poison_tool        ettercap / bettercap / arpspoof across the
 *                             four realistic shapes: bare command, full
 *                             path, quoted path, PowerShell plane (body
 *                             ONLY in kScriptBlockText); .py/.exe and
 *                             kImage fallback shapes covered too.
 *   75 arp_static_table_load  arp -f / arp -F / arp.exe -f / quoted
 *                             "C:\...\arp.exe" -f (case-insensitive).
 *   every needle is token bounded on both edges (HasTokenBounded): the
 *   start edge (string beginning or a non-alphanumeric character before
 *   the stem) keeps letter-prefixed lookalikes ("xettercap",
 *   "myarpspoof", "DnsCap"/dnscap, "sharp.exe -f", "arpfile") silent, the
 *   tail edge (end of text or a next character outside [A-Za-z0-9_])
 *   keeps letter-continued words silent ("arpspoofing", "ettercapped",
 *   "bettercapped", "arp -fl"/"arp -file"), and the "ettercap" stem
 *   inside "bettercap" never mis-attributes the tool field.
 *   Normal operations (`arp -a` / `-d` / `-g`, bare `arp`, `getmac`)
 *   never score.
 *
 * Production rules (added to rules/rules.json by the wiring agent):
 *   EDR-493  arp_poison_score >= 75   high/alert  T1557.002
 *   EDR-494  arp_poison_score 55-74   medium/log  T1557.002
 * The 75 static-load tier deliberately lands in the >=75 high band, so
 * the production test asserts 75 -> EDR-493 (consistent with the tier
 * contract in user/arp_poison_detector.h). The production-rule block is
 * skipped while rules.json does not carry them yet (same policy as the
 * other production-rule suites).
 */
#include "arp_poison_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "arp_poison_detector.h"
#include "rule_engine.h"

namespace {

#define AP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "arp poison detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

constexpr uint64_t kSecond = 10000000ULL;

/* House contract: POWERSHELL_SCRIPT bodies live ONLY in kScriptBlockText
 * (never kCommandLine) and every test event carries an explicit ts100ns
 * (no FILETIME-now fallback). */
edr::Event PsScriptEvent(uint64_t ts, const char* scriptText) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptText;
    return event;
}

edr::Event ProcEvent(uint64_t ts, const char* image, const char* cmdLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (cmdLine != nullptr)
        event.fields[edr::field::kCommandLine] = cmdLine;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kArpPoisonScore) !=
           event.fields.end();
}

/* Events that share a dedup key must be spaced >300s apart (the default
 * window); every same-key series below uses 400s steps. */
void TestInspects() {
    AP_CHECK(edr::ArpPoisonDetector::Inspects(EDR_EVT_PROCESS_START));
    AP_CHECK(edr::ArpPoisonDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
    AP_CHECK(!edr::ArpPoisonDetector::Inspects(EDR_EVT_NET_LISTENER));
    AP_CHECK(!edr::ArpPoisonDetector::Inspects(EDR_EVT_REG_WRITE));
    AP_CHECK(!edr::ArpPoisonDetector::Inspects(EDR_EVT_FILE_CREATE));
}

void TestDisabled() {
    edr::ArpPoisonDetector detector(false, 55, 300, 1024);
    edr::Event ps = PsScriptEvent(
        1000 * kSecond, "ettercap -T -M arp:remote /192.0.2.1/");
    detector.Enrich(ps);
    AP_CHECK(!HasScore(ps));
    edr::Event proc = ProcEvent(
        1001 * kSecond, "C:\\Windows\\System32\\arp.exe",
        "arp -f C:\\Users\\admin\\arp_static.txt");
    detector.Enrich(proc);
    AP_CHECK(!HasScore(proc));
}

void TestEttercapTier80Forms() {
    edr::ArpPoisonDetector detector(true, 55, 300, 1024);

    /* Bare command form (tool at the start of the command line). */
    edr::Event bare = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "ettercap -T -M arp:remote /192.0.2.1/ /192.0.2.254/");
    detector.Enrich(bare);
    AP_CHECK(bare.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(bare.fields.at(edr::field::kArpPoisonVerdict) == "malicious");
    AP_CHECK(bare.fields.at(edr::field::kArpPoisonSignals) ==
             "arp_poison_tool");
    AP_CHECK(bare.fields.at(edr::field::kArpPoisonTools) == "ettercap");

    /* Full path form (tool preceded by a path separator). */
    edr::Event path = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "C:\\Tools\\Ettercap\\ettercap.exe -T -M arp:remote");
    detector.Enrich(path);
    AP_CHECK(path.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(path.fields.at(edr::field::kArpPoisonTools) == "ettercap");

    /* Quoted image form. */
    edr::Event quoted = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "\"C:\\Program Files\\Ettercap\\ettercap.exe\" -T -M arp:remote");
    detector.Enrich(quoted);
    AP_CHECK(quoted.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(quoted.fields.at(edr::field::kArpPoisonTools) == "ettercap");

    /* PowerShell plane: the body lives ONLY in kScriptBlockText - this
     * event proving the PS face reads it at all. */
    edr::Event ps = PsScriptEvent(
        2200 * kSecond,
        "Set-ExecutionPolicy Bypass -Scope Process; "
        ".\\ettercap.exe -T -M arp:remote");
    detector.Enrich(ps);
    AP_CHECK(ps.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(ps.fields.at(edr::field::kArpPoisonVerdict) == "malicious");
    AP_CHECK(ps.fields.at(edr::field::kArpPoisonSignals) ==
             "arp_poison_tool");

    /* kImage fallback: bare image name without a command line. */
    edr::Event image = ProcEvent(
        2600 * kSecond, "C:\\Tools\\ettercap\\ettercap.exe", nullptr);
    detector.Enrich(image);
    AP_CHECK(image.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(image.fields.at(edr::field::kArpPoisonSignals) ==
             "arp_poison_tool");
}

void TestBettercapArpspoofTier80() {
    edr::ArpPoisonDetector detector(true, 55, 300, 1024);

    /* bettercap, all four shapes. The first event also pins tool
     * attribution: the "ettercap" stem inside "bettercap" must not fire
     * (word-start guard), so the tools field says "bettercap". */
    edr::Event bare = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "bettercap -iface eth0 -caplet arp-spoof");
    detector.Enrich(bare);
    AP_CHECK(bare.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(bare.fields.at(edr::field::kArpPoisonVerdict) == "malicious");
    AP_CHECK(bare.fields.at(edr::field::kArpPoisonSignals) ==
             "arp_poison_tool");
    AP_CHECK(bare.fields.at(edr::field::kArpPoisonTools) == "bettercap");

    edr::Event path = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "C:\\Tools\\bettercap\\bettercap.exe -iface 192.0.2.5");
    detector.Enrich(path);
    AP_CHECK(path.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(path.fields.at(edr::field::kArpPoisonTools) == "bettercap");

    edr::Event quoted = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "\"C:\\Program Files\\bettercap\\bettercap.exe\" -iface 192.0.2.5");
    detector.Enrich(quoted);
    AP_CHECK(quoted.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(quoted.fields.at(edr::field::kArpPoisonTools) == "bettercap");

    edr::Event ps = PsScriptEvent(
        2200 * kSecond,
        "bettercap -iface eth0 -eval 'set arp.spoof.internal true'");
    detector.Enrich(ps);
    AP_CHECK(ps.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(ps.fields.at(edr::field::kArpPoisonTools) == "bettercap");

    /* arpspoof, all four shapes plus the .py suffix. */
    edr::Event spoof = ProcEvent(
        2600 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "arpspoof -i eth0 -t 192.0.2.10 192.0.2.1");
    detector.Enrich(spoof);
    AP_CHECK(spoof.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(spoof.fields.at(edr::field::kArpPoisonVerdict) == "malicious");
    AP_CHECK(spoof.fields.at(edr::field::kArpPoisonSignals) ==
             "arp_poison_tool");
    AP_CHECK(spoof.fields.at(edr::field::kArpPoisonTools) == "arpspoof");

    edr::Event spoofPath = ProcEvent(
        3000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "C:\\dsniff\\bin\\arpspoof.exe -i 5 -t 192.0.2.10 192.0.2.1");
    detector.Enrich(spoofPath);
    AP_CHECK(spoofPath.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(spoofPath.fields.at(edr::field::kArpPoisonTools) == "arpspoof");

    edr::Event spoofQuoted = ProcEvent(
        3400 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "\"C:\\dsniff\\bin\\arpspoof.exe\" -t 192.0.2.10 192.0.2.1");
    detector.Enrich(spoofQuoted);
    AP_CHECK(spoofQuoted.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(spoofQuoted.fields.at(edr::field::kArpPoisonTools) ==
             "arpspoof");

    edr::Event spoofPy = PsScriptEvent(
        3800 * kSecond,
        "python arpspoof.py -i eth0 -t 192.0.2.10 192.0.2.1");
    detector.Enrich(spoofPy);
    AP_CHECK(spoofPy.fields.at(edr::field::kArpPoisonScore) == "80");
    AP_CHECK(spoofPy.fields.at(edr::field::kArpPoisonTools) == "arpspoof");
}

void TestArpStaticTableLoadTier75() {
    edr::ArpPoisonDetector detector(true, 55, 300, 1024);

    /* Bare `arp -f` with a file argument. */
    edr::Event bare = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "arp -f C:\\Users\\admin\\arp_static.txt");
    detector.Enrich(bare);
    AP_CHECK(bare.fields.at(edr::field::kArpPoisonScore) == "75");
    AP_CHECK(bare.fields.at(edr::field::kArpPoisonVerdict) == "malicious");
    AP_CHECK(bare.fields.at(edr::field::kArpPoisonSignals) ==
             "arp_static_table_load");
    AP_CHECK(bare.fields.find(edr::field::kArpPoisonTools) ==
             bare.fields.end());

    /* Full path form: `arp.exe -f`. */
    edr::Event path = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\arp.exe -f");
    detector.Enrich(path);
    AP_CHECK(path.fields.at(edr::field::kArpPoisonScore) == "75");
    AP_CHECK(path.fields.at(edr::field::kArpPoisonSignals) ==
             "arp_static_table_load");

    /* Uppercase `ARP -F` (text is lowered first). */
    edr::Event upper = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\cmd.exe", "ARP -F");
    detector.Enrich(upper);
    AP_CHECK(upper.fields.at(edr::field::kArpPoisonScore) == "75");

    /* Quoted image path with the flag OUTSIDE the quotes. */
    edr::Event quoted = ProcEvent(
        2200 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "\"C:\\Windows\\System32\\arp.exe\" -f C:\\arp.txt");
    detector.Enrich(quoted);
    AP_CHECK(quoted.fields.at(edr::field::kArpPoisonScore) == "75");
    AP_CHECK(quoted.fields.at(edr::field::kArpPoisonSignals) ==
             "arp_static_table_load");

    /* `arp.exe -F` uppercase flag with full path. */
    edr::Event upperPath = ProcEvent(
        2600 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "arp.exe -F C:\\arp.txt");
    detector.Enrich(upperPath);
    AP_CHECK(upperPath.fields.at(edr::field::kArpPoisonScore) == "75");
}

void TestWordBoundaryNegatives() {
    edr::ArpPoisonDetector detector(true, 55, 300, 1024);

    /* A letter directly before a stem must keep every tier silent. */
    edr::Event xettercap = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "C:\\tools\\xettercap.exe --version");
    detector.Enrich(xettercap);
    AP_CHECK(!HasScore(xettercap));

    edr::Event myarpspoof = ProcEvent(
        1001 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "python myarpspoof.py -t 192.0.2.10 192.0.2.1");
    detector.Enrich(myarpspoof);
    AP_CHECK(!HasScore(myarpspoof));

    /* DnsCap (dnscap) is a DNS capture tool, not an ARP poisoner. */
    edr::Event dnscap = ProcEvent(
        1002 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "C:\\Tools\\dnscap\\dnscap.exe -i eth0 -w capture.pcap");
    detector.Enrich(dnscap);
    AP_CHECK(!HasScore(dnscap));

    /* "sharp.exe -f config.ini" embeds "arp.exe -f" after a letter:
     * the word-start boundary keeps the 75 tier silent. */
    edr::Event sharp = ProcEvent(
        1003 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "sharp.exe -f config.ini");
    detector.Enrich(sharp);
    AP_CHECK(!HasScore(sharp));

    /* Letter-glued "arpfile" has no "arp -f" needle at all. */
    edr::Event arpfile = ProcEvent(
        1004 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "type C:\\Users\\admin\\arpfile.txt");
    detector.Enrich(arpfile);
    AP_CHECK(!HasScore(arpfile));
}

void TestTokenTailBoundaryNegatives() {
    edr::ArpPoisonDetector detector(true, 55, 300, 1024);

    /* Letter continued onto each tool stem: "arpspoofing",
     * "ettercapped" and "bettercapped" are different words, the tail
     * edge must reject them all (the "ettercap" stem inside
     * "bettercapped" also fails via its own start edge). */
    edr::Event spoofing = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "arpspoofing the network");
    detector.Enrich(spoofing);
    AP_CHECK(!HasScore(spoofing));

    edr::Event ecapped = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "ettercapped traffic");
    detector.Enrich(ecapped);
    AP_CHECK(!HasScore(ecapped));

    edr::Event bcapped = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "bettercapped link");
    detector.Enrich(bcapped);
    AP_CHECK(!HasScore(bcapped));

    /* Letter glued to the flag: "arp -fl" is not "arp -f" - the flag
     * token must end right after the "f" (tail edge). */
    edr::Event arpFl = ProcEvent(
        2200 * kSecond, "C:\\Windows\\System32\\cmd.exe", "arp -fl");
    detector.Enrich(arpFl);
    AP_CHECK(!HasScore(arpFl));

    AP_CHECK(detector.StateCount() == 0);
}

void TestNormalOpsSilent() {
    edr::ArpPoisonDetector detector(true, 55, 300, 1024);

    const char* const kNormalOps[] = {
        "arp -a",
        "arp.exe -a",
        "arp -d *",
        "arp -d 192.0.2.1",
        "arp -g",
        "arp",
        "getmac /v",
    };
    for (int i = 0; i < 7; ++i) {
        edr::Event op = ProcEvent(
            (1000 + static_cast<uint64_t>(i)) * kSecond,
            "C:\\Windows\\System32\\cmd.exe", kNormalOps[i]);
        detector.Enrich(op);
        if (HasScore(op)) {
            std::fprintf(stderr, "[arp_poison] op scored: %s\n",
                         kNormalOps[i]);
        }
        AP_CHECK(!HasScore(op));
    }
    AP_CHECK(detector.StateCount() == 0);
}

void TestMinScoreGating() {
    /* min_score 80: the 75 static-load tier is filtered and, because the
     * gate runs before dedup bookkeeping, no key is inserted for it. */
    {
        edr::ArpPoisonDetector detector(true, 80, 300, 1024);
        edr::Event arpF = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\arp.exe",
            "arp -f C:\\arp.txt");
        detector.Enrich(arpF);
        AP_CHECK(!HasScore(arpF));
        AP_CHECK(detector.StateCount() == 0);

        /* The 80 tool tier passes the same instance. */
        edr::Event ettercap = ProcEvent(
            1001 * kSecond, "C:\\Windows\\System32\\cmd.exe",
            "ettercap -T -M arp:remote /192.0.2.1/");
        detector.Enrich(ettercap);
        AP_CHECK(ettercap.fields.at(edr::field::kArpPoisonScore) == "80");
        AP_CHECK(detector.StateCount() == 1);
    }
    /* min_score 55 (default): the 75 static-load tier survives - its
     * positive path lives on its own low-threshold instance. */
    {
        edr::ArpPoisonDetector detector(true, 55, 300, 1024);
        edr::Event arpF = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\arp.exe",
            "arp -f C:\\arp.txt");
        detector.Enrich(arpF);
        AP_CHECK(arpF.fields.at(edr::field::kArpPoisonScore) == "75");
    }
}

void TestToolDedup() {
    edr::ArpPoisonDetector detector(true, 55, 300, 1024);

    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "ettercap -T -M arp:remote /192.0.2.1/");
    detector.Enrich(first);
    AP_CHECK(HasScore(first));
    AP_CHECK(detector.StateCount() == 1);

    /* Same tool inside the window (key arp_poison_tool|ettercap) is
     * suppressed. */
    edr::Event repeat = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "ettercap -T -M arp:remote /192.0.2.1/");
    detector.Enrich(repeat);
    AP_CHECK(!HasScore(repeat));

    /* A different tool is a different key and passes. */
    edr::Event arpspoof = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "arpspoof -i eth0 -t 192.0.2.10 192.0.2.1");
    detector.Enrich(arpspoof);
    AP_CHECK(HasScore(arpspoof));
    AP_CHECK(detector.StateCount() == 2);

    /* Window expiry (300s) re-arms the first tool. */
    edr::Event late = ProcEvent(
        1000 * kSecond + 301 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "ettercap -T -M arp:remote /192.0.2.1/");
    detector.Enrich(late);
    AP_CHECK(HasScore(late));
    AP_CHECK(detector.StateCount() == 2);
}

void TestStaticLoadDedup() {
    edr::ArpPoisonDetector detector(true, 55, 300, 1024);

    edr::Event first = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "arp -f C:\\arp.txt");
    detector.Enrich(first);
    AP_CHECK(HasScore(first));
    AP_CHECK(detector.StateCount() == 1);

    /* Every static-load spelling shares the plain-signal key, so all of
     * them are suppressed inside the window. */
    edr::Event exeForm = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\arp.exe -f");
    detector.Enrich(exeForm);
    AP_CHECK(!HasScore(exeForm));

    edr::Event upperForm = ProcEvent(
        1200 * kSecond, "C:\\Windows\\System32\\cmd.exe", "ARP -F");
    detector.Enrich(upperForm);
    AP_CHECK(!HasScore(upperForm));

    /* Window expiry re-arms the tier. */
    edr::Event late = ProcEvent(
        1000 * kSecond + 301 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "arp -f C:\\arp.txt");
    detector.Enrich(late);
    AP_CHECK(HasScore(late));
    AP_CHECK(detector.StateCount() == 1);
}

void TestStateCapacityReset() {
    edr::ArpPoisonDetector detector(true, 55, 300, 1);
    edr::Event ettercap = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "ettercap -T -M arp:remote /192.0.2.1/");
    detector.Enrich(ettercap);
    AP_CHECK(HasScore(ettercap));
    AP_CHECK(detector.StateCount() == 1);

    /* Second distinct key over capacity: dedup state resets, no UB, and
     * the detector keeps stamping. */
    edr::Event arpspoof = ProcEvent(
        1100 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "arpspoof -i eth0 -t 192.0.2.10 192.0.2.1");
    detector.Enrich(arpspoof);
    AP_CHECK(HasScore(arpspoof));
    AP_CHECK(detector.StateCount() == 1);

    /* The reset re-arms the first tool (its key was cleared). */
    edr::Event again = ProcEvent(
        1200 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "ettercap -T -M arp:remote /192.0.2.1/");
    detector.Enrich(again);
    AP_CHECK(HasScore(again));
    AP_CHECK(detector.StateCount() == 1);

    edr::Event staticLoad = ProcEvent(
        1300 * kSecond, "C:\\Windows\\System32\\arp.exe",
        "arp -f C:\\arp.txt");
    detector.Enrich(staticLoad);
    AP_CHECK(HasScore(staticLoad));
    AP_CHECK(detector.StateCount() == 1);
}

void TestUnknownEventsSilent() {
    edr::ArpPoisonDetector detector(true, 55, 300, 1024);

    /* Uninspected event type carrying tool text in an unrelated field. */
    edr::Event reg;
    reg.type = EDR_EVT_REG_WRITE;
    reg.ts100ns = 1000 * kSecond;
    reg.fields[edr::field::kType] = "REG_WRITE";
    reg.fields[edr::field::kRegValue] = "ettercap -T -M arp:remote";
    detector.Enrich(reg);
    AP_CHECK(!HasScore(reg));

    /* POWERSHELL_SCRIPT without a script body (house contract: no
     * kCommandLine-on-PS_SCRIPT shape exists in production). */
    edr::Event ps;
    ps.type = EDR_EVT_POWERSHELL_SCRIPT;
    ps.ts100ns = 1001 * kSecond;
    ps.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    detector.Enrich(ps);
    AP_CHECK(!HasScore(ps));

    /* PROCESS_START without a poisoner on its image. */
    edr::Event proc = ProcEvent(1002 * kSecond,
                                "C:\\Windows\\System32\\cmd.exe", nullptr);
    detector.Enrich(proc);
    AP_CHECK(!HasScore(proc));

    /* Ordinary command line. */
    edr::Event echo = ProcEvent(
        1003 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "cmd.exe /c echo hello");
    detector.Enrich(echo);
    AP_CHECK(!HasScore(echo));
}

/* Production-rule consumer check: rules are evaluated by the RuleEngine
 * against a hand-set arp_poison_score field (the RuleEngine never calls
 * the detector itself). */
struct AlertRecord {
    std::string ruleId;
    std::string severity;
    std::string action;
    std::vector<std::string> mitre;
};

std::vector<AlertRecord> g_alerts;

bool HasAlert(const char* id) {
    for (const AlertRecord& a : g_alerts)
        if (a.ruleId == id) return true;
    return false;
}

const AlertRecord* FindAlert(const char* id) {
    for (const AlertRecord& a : g_alerts)
        if (a.ruleId == id) return &a;
    return nullptr;
}

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

std::string ReadAllText(const char* path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

void FeedScore(edr::RuleEngine* engine, const char* score) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.ts100ns = 1000 * kSecond;
    ev.fields[edr::field::kType] = "PROCESS_START";
    if (score != nullptr)
        ev.fields[edr::field::kArpPoisonScore] = score;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    /* EDR-493 (arp_poison_score >= 75, high/alert, T1557.002) and
     * EDR-494 (55-74, medium/log, T1557.002) are written to
     * rules/rules.json by the wiring agent. Until then skip the block. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[arp_poison] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-493") == std::string::npos ||
        rulesText.find("EDR-494") == std::string::npos) {
        std::fprintf(stderr,
                     "[arp_poison] EDR-493/EDR-494 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* High band: detector tiers 80 and 75 both land in >=75, so they hit
     * EDR-493 only. */
    FeedScore(&engine, "100");
    AP_CHECK(HasAlert("EDR-493"));
    AP_CHECK(!HasAlert("EDR-494"));
    const AlertRecord* high = FindAlert("EDR-493");
    AP_CHECK(high != nullptr);
    AP_CHECK(high->severity == "high");
    AP_CHECK(high->action == "alert");
    AP_CHECK(std::find(high->mitre.begin(), high->mitre.end(),
                       "T1557.002") != high->mitre.end());

    FeedScore(&engine, "80");
    AP_CHECK(HasAlert("EDR-493"));
    AP_CHECK(!HasAlert("EDR-494"));
    FeedScore(&engine, "75");
    AP_CHECK(HasAlert("EDR-493"));
    AP_CHECK(!HasAlert("EDR-494"));

    /* Mid band: 74 must NOT hit the >=75 rule; 65/55 hit EDR-494 only. */
    FeedScore(&engine, "74");
    AP_CHECK(HasAlert("EDR-494"));
    AP_CHECK(!HasAlert("EDR-493"));
    const AlertRecord* mid = FindAlert("EDR-494");
    AP_CHECK(mid != nullptr);
    AP_CHECK(mid->severity == "medium");
    AP_CHECK(mid->action == "log");
    AP_CHECK(std::find(mid->mitre.begin(), mid->mitre.end(),
                       "T1557.002") != mid->mitre.end());
    FeedScore(&engine, "65");
    AP_CHECK(HasAlert("EDR-494"));
    AP_CHECK(!HasAlert("EDR-493"));
    FeedScore(&engine, "55");
    AP_CHECK(HasAlert("EDR-494"));
    AP_CHECK(!HasAlert("EDR-493"));

    /* Dead band 50-54 and below: none of the new rules may fire. */
    FeedScore(&engine, "54");
    AP_CHECK(!HasAlert("EDR-493"));
    AP_CHECK(!HasAlert("EDR-494"));
    FeedScore(&engine, "52");
    AP_CHECK(!HasAlert("EDR-493"));
    AP_CHECK(!HasAlert("EDR-494"));
    FeedScore(&engine, "50");
    AP_CHECK(!HasAlert("EDR-493"));
    AP_CHECK(!HasAlert("EDR-494"));
    FeedScore(&engine, "40");
    AP_CHECK(!HasAlert("EDR-493"));
    AP_CHECK(!HasAlert("EDR-494"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedScore(&engine, nullptr);
    AP_CHECK(!HasAlert("EDR-493"));
    AP_CHECK(!HasAlert("EDR-494"));
}

} // namespace

void RunArpPoisonDetectorTests() {
    std::fprintf(stderr, "[arp_poison] TestInspects\n");
    TestInspects();
    std::fprintf(stderr, "[arp_poison] TestDisabled\n");
    TestDisabled();
    std::fprintf(stderr, "[arp_poison] TestEttercapTier80Forms\n");
    TestEttercapTier80Forms();
    std::fprintf(stderr, "[arp_poison] TestBettercapArpspoofTier80\n");
    TestBettercapArpspoofTier80();
    std::fprintf(stderr, "[arp_poison] TestArpStaticTableLoadTier75\n");
    TestArpStaticTableLoadTier75();
    std::fprintf(stderr, "[arp_poison] TestWordBoundaryNegatives\n");
    TestWordBoundaryNegatives();
    std::fprintf(stderr, "[arp_poison] TestTokenTailBoundaryNegatives\n");
    TestTokenTailBoundaryNegatives();
    std::fprintf(stderr, "[arp_poison] TestNormalOpsSilent\n");
    TestNormalOpsSilent();
    std::fprintf(stderr, "[arp_poison] TestMinScoreGating\n");
    TestMinScoreGating();
    std::fprintf(stderr, "[arp_poison] TestToolDedup\n");
    TestToolDedup();
    std::fprintf(stderr, "[arp_poison] TestStaticLoadDedup\n");
    TestStaticLoadDedup();
    std::fprintf(stderr, "[arp_poison] TestStateCapacityReset\n");
    TestStateCapacityReset();
    std::fprintf(stderr, "[arp_poison] TestUnknownEventsSilent\n");
    TestUnknownEventsSilent();
    std::fprintf(stderr, "[arp_poison] TestProductionRules\n");
    TestProductionRules();
    std::fprintf(stderr, "[arp_poison] all passed\n");
}
