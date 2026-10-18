/*
 * llmnr_poison_detector_tests.cpp - Unit tests for LlmnrPoisonDetector
 * (T1557.001) and the production rules that consume its score field.
 *
 * Detector tiers asserted here (per user/llmnr_poison_detector.cpp):
 *   listener plane (EDR_EVT_NET_LISTENER, action=added, protocol=udp):
 *     85 llmnr_udp_5355_listener   svchost.exe (any of the three ports)
 *     75 nbns_udp_137_listener     and mDNSResponder.exe (on 5353 only)
 *     65 mdns_udp_5353_listener    are whitelisted -> silent; an
 *                                  unresolvable owner (missing process)
 *                                  still alerts.
 *   command plane (PROCESS_START kCommandLine, PS plane kScriptBlockText,
 *   then kImage fallback):
 *     80 poison_tool_mitm6
 *     75 poison_tool_inveigh / poison_tool_responder / poison_tool_nbns_spoof
 *   every command-plane needle is token bounded on both edges
 *   (HasTokenBounded): the start edge (string beginning or a
 *   non-alphanumeric character before the stem) keeps "limitm6xx.exe"
 *   ("mitm6" mid-token) and vendor "DnsResponder.exe" (letter before the
 *   "responder" stem) silent; the tail edge (end of text or a next
 *   character outside [A-Za-z0-9_]) keeps the letter/digit/underscore
 *   continuation family silent - "nbns_spoofed", "nbns-poisoned",
 *   "mitm6_domain_scan" - while ".exe"/".py"/".psd1" dot suffixes, path
 *   separators, quotes, hyphens and spaces still pass.
 *
 * Production rules (added to rules/rules.json by the wiring agent):
 *   EDR-486  llmnr_poison_score >= 75   high/alert  T1557.001
 *   EDR-487  llmnr_poison_score 55-74   medium/log  T1557.001
 * The production-rule block is skipped while rules.json does not carry
 * them yet (same policy as the other production-rule suites).
 */
#include "llmnr_poison_detector_tests.h"

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
#include "llmnr_poison_detector.h"
#include "rule_engine.h"

namespace {

#define LP_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "llmnr poison detector test failed at line " +
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

/* Listener event shaped like collector_listener emits it: kListenerAction
 * added/removed, kListenerProtocol udp/tcp, decimal kListenerPort and the
 * owning process image (missing when unresolvable). */
edr::Event ListenerEvent(uint64_t ts, const char* process, const char* port,
                         const char* protocol = "udp",
                         const char* action = "added") {
    edr::Event event;
    event.type = EDR_EVT_NET_LISTENER;
    event.ts100ns = ts;
    event.fields[edr::field::kType] = "NET_LISTENER";
    event.fields[edr::field::kListenerAction] = action;
    event.fields[edr::field::kListenerProtocol] = protocol;
    event.fields[edr::field::kListenerPort] = port;
    if (process != nullptr)
        event.fields[edr::field::kListenerProcess] = process;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kLlmnrPoisonScore) !=
           event.fields.end();
}

void TestInspects() {
    LP_CHECK(edr::LlmnrPoisonDetector::Inspects(EDR_EVT_PROCESS_START));
    LP_CHECK(edr::LlmnrPoisonDetector::Inspects(EDR_EVT_POWERSHELL_SCRIPT));
    LP_CHECK(edr::LlmnrPoisonDetector::Inspects(EDR_EVT_NET_LISTENER));
    LP_CHECK(!edr::LlmnrPoisonDetector::Inspects(EDR_EVT_REG_WRITE));
    LP_CHECK(!edr::LlmnrPoisonDetector::Inspects(EDR_EVT_FILE_CREATE));
}

void TestDisabled() {
    edr::LlmnrPoisonDetector detector(false, 55, 300, 1024);
    edr::Event listener = ListenerEvent(1000 * kSecond,
                                        "C:\\Tools\\poisoner.exe", "5355");
    detector.Enrich(listener);
    LP_CHECK(!HasScore(listener));
    edr::Event tool = ProcEvent(1001 * kSecond,
                                "C:\\Windows\\System32\\cmd.exe",
                                "python.exe mitm6.py -d corp.local");
    detector.Enrich(tool);
    LP_CHECK(!HasScore(tool));
}

void TestLlmnrListenerTier85() {
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);
    edr::Event listener = ListenerEvent(
        1000 * kSecond, "C:\\Users\\dev\\tools\\poisoner.exe", "5355");
    detector.Enrich(listener);
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonScore) == "85");
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonVerdict) ==
             "malicious");
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonSignals) ==
             "llmnr_udp_5355_listener");
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonPorts) == "5355");
    LP_CHECK(listener.fields.find(edr::field::kLlmnrPoisonTools) ==
             listener.fields.end());
}

void TestNbnsListenerTier75() {
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);
    edr::Event listener = ListenerEvent(1000 * kSecond,
                                        "C:\\Tools\\spoof\\nbns_tool.exe",
                                        "137");
    detector.Enrich(listener);
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonScore) == "75");
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonVerdict) ==
             "malicious");
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonSignals) ==
             "nbns_udp_137_listener");
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonPorts) == "137");
}

void TestMdnsListenerTier65() {
    /* 65 is SUSPICIOUS, not MALICIOUS; min_score admits the tier. */
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);
    edr::Event listener = ListenerEvent(1000 * kSecond,
                                        "C:\\Tools\\spoof\\mdns_tool.exe",
                                        "5353");
    detector.Enrich(listener);
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonScore) == "65");
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonVerdict) ==
             "suspicious");
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonSignals) ==
             "mdns_udp_5353_listener");
    LP_CHECK(listener.fields.at(edr::field::kLlmnrPoisonPorts) == "5353");
}

void TestListenerWhitelistSilent() {
    /* svchost.exe hosts the genuine responders: silent on all three ports,
     * case-insensitively. */
    {
        edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);
        const char* ports[] = {"5355", "137", "5353"};
        for (int i = 0; i < 3; ++i) {
            edr::Event listener = ListenerEvent(
                1000 * kSecond + static_cast<uint64_t>(i) * kSecond,
                "C:\\Windows\\System32\\svchost.exe", ports[i]);
            detector.Enrich(listener);
            LP_CHECK(!HasScore(listener));
        }
        edr::Event upper = ListenerEvent(
            1010 * kSecond, "C:\\Windows\\System32\\SVCHOST.EXE", "5355");
        detector.Enrich(upper);
        LP_CHECK(!HasScore(upper));
    }
    /* Bonjour's mDNSResponder.exe legitimately owns UDP 5353 only. */
    {
        edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);
        edr::Event bonjour = ListenerEvent(
            1000 * kSecond,
            "C:\\Program Files\\Bonjour\\mDNSResponder.exe", "5353");
        detector.Enrich(bonjour);
        LP_CHECK(!HasScore(bonjour));
        edr::Event upper = ListenerEvent(
            1001 * kSecond,
            "C:\\Program Files\\Bonjour\\MDNSRESPONDER.EXE", "5353");
        detector.Enrich(upper);
        LP_CHECK(!HasScore(upper));
        /* The same binary on the LLMNR port is NOT whitelisted. */
        edr::Event foreign = ListenerEvent(
            1002 * kSecond,
            "C:\\Program Files\\Bonjour\\mDNSResponder.exe", "5355");
        detector.Enrich(foreign);
        LP_CHECK(HasScore(foreign));
        LP_CHECK(foreign.fields.at(edr::field::kLlmnrPoisonScore) == "85");
    }
    /* An unresolvable owner (no kListenerProcess) still alerts. */
    {
        edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);
        edr::Event orphan = ListenerEvent(1000 * kSecond, nullptr, "5355");
        detector.Enrich(orphan);
        LP_CHECK(HasScore(orphan));
        LP_CHECK(orphan.fields.at(edr::field::kLlmnrPoisonScore) == "85");
    }
}

void TestListenerIrrelevantSilent() {
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);

    /* A listener that disappeared is history, not an active poisoner. */
    edr::Event removed =
        ListenerEvent(1000 * kSecond, "C:\\Tools\\poisoner.exe", "5355",
                      "udp", "removed");
    detector.Enrich(removed);
    LP_CHECK(!HasScore(removed));

    /* TCP on a name-resolution port is not the poisoning signal. */
    edr::Event tcp =
        ListenerEvent(1001 * kSecond, "C:\\Tools\\poisoner.exe", "5355",
                      "tcp", "added");
    detector.Enrich(tcp);
    LP_CHECK(!HasScore(tcp));

    /* Unrelated UDP port. */
    edr::Event smb =
        ListenerEvent(1002 * kSecond, "C:\\Tools\\poisoner.exe", "445");
    detector.Enrich(smb);
    LP_CHECK(!HasScore(smb));

    /* Uppercase protocol still parses (lowered before compare). */
    edr::Event upper =
        ListenerEvent(1003 * kSecond, "C:\\Tools\\poisoner.exe", "5355",
                      "UDP", "added");
    detector.Enrich(upper);
    LP_CHECK(HasScore(upper));
    LP_CHECK(upper.fields.at(edr::field::kLlmnrPoisonScore) == "85");
}

void TestListenerDedup() {
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);

    edr::Event first =
        ListenerEvent(1000 * kSecond, "C:\\Tools\\poisoner.exe", "5355");
    detector.Enrich(first);
    LP_CHECK(HasScore(first));

    /* State-type surface: the same protocol|port inside the window never
     * re-alerts. */
    edr::Event repeat =
        ListenerEvent(1100 * kSecond, "C:\\Tools\\poisoner.exe", "5355");
    detector.Enrich(repeat);
    LP_CHECK(!HasScore(repeat));

    /* A different port is a different key and passes. */
    edr::Event nbns =
        ListenerEvent(1100 * kSecond, "C:\\Tools\\poisoner.exe", "137");
    detector.Enrich(nbns);
    LP_CHECK(HasScore(nbns));
    LP_CHECK(detector.StateCount() == 2);

    /* Window expiry (300s) re-arms the original port. */
    edr::Event late = ListenerEvent(1000 * kSecond + 301 * kSecond,
                                    "C:\\Tools\\poisoner.exe", "5355");
    detector.Enrich(late);
    LP_CHECK(HasScore(late));
}

void TestMitm6ToolTier80() {
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);

    edr::Event tool = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "python.exe mitm6.py -d corp.local -v");
    detector.Enrich(tool);
    LP_CHECK(tool.fields.at(edr::field::kLlmnrPoisonScore) == "80");
    LP_CHECK(tool.fields.at(edr::field::kLlmnrPoisonVerdict) == "malicious");
    LP_CHECK(tool.fields.at(edr::field::kLlmnrPoisonSignals) ==
             "poison_tool_mitm6");
    LP_CHECK(tool.fields.at(edr::field::kLlmnrPoisonTools) == "mitm6");
    LP_CHECK(tool.fields.find(edr::field::kLlmnrPoisonPorts) ==
             tool.fields.end());

    /* Image-name fallback: a bare mitm6.exe process start. Timestamp is
     * 400s after the command-plane event — beyond the 300s dedup window —
     * because both events carry the same per-tool key
     * (poison_tool_mitm6|mitm6) and the contract dedups inside the
     * window (TestListenerDedup covers that). */
    edr::Event image = ProcEvent(1400 * kSecond,
                                 "C:\\Tools\\mitm6\\mitm6.exe", nullptr);
    detector.Enrich(image);
    LP_CHECK(image.fields.at(edr::field::kLlmnrPoisonScore) == "80");
    LP_CHECK(image.fields.at(edr::field::kLlmnrPoisonSignals) ==
             "poison_tool_mitm6");
}

void TestInveighResponderNbnsToolsTier75() {
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);

    /* Inveigh on the PS plane (body in kScriptBlockText). */
    edr::Event inveigh = PsScriptEvent(
        1000 * kSecond,
        "Import-Module .\\Inveigh.psd1; Invoke-Inveigh -ConsoleOutput Y");
    detector.Enrich(inveigh);
    LP_CHECK(inveigh.fields.at(edr::field::kLlmnrPoisonScore) == "75");
    LP_CHECK(inveigh.fields.at(edr::field::kLlmnrPoisonVerdict) ==
             "malicious");
    LP_CHECK(inveigh.fields.at(edr::field::kLlmnrPoisonSignals) ==
             "poison_tool_inveigh");
    LP_CHECK(inveigh.fields.at(edr::field::kLlmnrPoisonTools) == "inveigh");

    /* All timestamps below are spaced 400s apart — beyond the 300s dedup
     * window — because the detector's command-plane keys are per tool:
     * responder's .py and .exe variants share poison_tool_responder and
     * the two nbns_spoof variants share their key, so the contract dedups
     * them inside the window (TestToolDedup covers that). */

    /* Responder via its .py launcher. */
    edr::Event responder = ProcEvent(
        1400 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "python.exe responder.py -I eth0");
    detector.Enrich(responder);
    LP_CHECK(responder.fields.at(edr::field::kLlmnrPoisonScore) == "75");
    LP_CHECK(responder.fields.at(edr::field::kLlmnrPoisonSignals) ==
             "poison_tool_responder");
    LP_CHECK(responder.fields.at(edr::field::kLlmnrPoisonTools) ==
             "responder");

    /* Responder via its .exe binary. */
    edr::Event responderExe = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "C:\\resp\\Responder.exe -i 192.0.2.5");
    detector.Enrich(responderExe);
    LP_CHECK(responderExe.fields.at(edr::field::kLlmnrPoisonScore) == "75");
    LP_CHECK(responderExe.fields.at(edr::field::kLlmnrPoisonSignals) ==
             "poison_tool_responder");

    /* NBNS spoofing variants. */
    edr::Event nbns = ProcEvent(
        2200 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "nbns_spoof.exe 192.0.2.1");
    detector.Enrich(nbns);
    LP_CHECK(nbns.fields.at(edr::field::kLlmnrPoisonScore) == "75");
    LP_CHECK(nbns.fields.at(edr::field::kLlmnrPoisonSignals) ==
             "poison_tool_nbns_spoof");
    LP_CHECK(nbns.fields.at(edr::field::kLlmnrPoisonTools) == "nbns_spoof");
    edr::Event nbnsDash = PsScriptEvent(2600 * kSecond,
                                        ".\\nbns-poison -ip 192.0.2.9");
    detector.Enrich(nbnsDash);
    LP_CHECK(nbnsDash.fields.at(edr::field::kLlmnrPoisonScore) == "75");
    LP_CHECK(nbnsDash.fields.at(edr::field::kLlmnrPoisonSignals) ==
             "poison_tool_nbns_spoof");

    /* mitm6 wins when several tool names share the text. */
    edr::Event both = ProcEvent(
        3000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "mitm6.exe --help (also see inveigh docs)");
    detector.Enrich(both);
    LP_CHECK(both.fields.at(edr::field::kLlmnrPoisonScore) == "80");
    LP_CHECK(both.fields.at(edr::field::kLlmnrPoisonSignals) ==
             "poison_tool_mitm6");

    /* Bare "responder" without .py/.exe/" -i" is not the tool. */
    edr::Event plain = PsScriptEvent(3400 * kSecond,
                                     "Get-Service ResponderService");
    detector.Enrich(plain);
    LP_CHECK(!HasScore(plain));
    edr::Event bare = ProcEvent(
        3800 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "C:\\tools\\responder --version");
    detector.Enrich(bare);
    LP_CHECK(!HasScore(bare));
}

void TestWordBoundaryNegatives() {
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);

    /* "mitm6" embedded mid-token: the letter before the stem must keep
     * this silent (word-start boundary, no EDR-486 80-point false
     * positive). */
    edr::Event limitm6 = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "C:\\tools\\limitm6xx.exe --version");
    detector.Enrich(limitm6);
    LP_CHECK(!HasScore(limitm6));

    /* Vendor responder names (a letter directly before the stem) are not
     * the Responder tool; the quoted full path shape must stay silent. */
    edr::Event vendor = ProcEvent(
        1001 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "\"C:\\Program Files\\Vendor\\DnsResponder.exe\" --service");
    detector.Enrich(vendor);
    LP_CHECK(!HasScore(vendor));
}

void TestTokenTailBoundaryNegatives() {
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);

    /* Letter suffix glued onto the "nbns_spoof" stem: "nbns_spoofed" is
     * a different word, the tail edge must reject it (no EDR-486 false
     * positive from the needle stem). */
    edr::Event spoofed = ProcEvent(
        1000 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "nbns_spoofed --help");
    detector.Enrich(spoofed);
    LP_CHECK(!HasScore(spoofed));

    /* Same tail family on the dash spelling. */
    edr::Event poisoned = PsScriptEvent(1400 * kSecond,
                                        "nbns-poisoned target");
    detector.Enrich(poisoned);
    LP_CHECK(!HasScore(poisoned));

    /* Underscore continuation: scan/flag-style identifiers glue onto the
     * stem, so "mitm6_domain_scan" must not fire the 80 mitm6 tier. */
    edr::Event scan = ProcEvent(
        1800 * kSecond, "C:\\Windows\\System32\\cmd.exe",
        "mitm6_domain_scan --targets corp.local");
    detector.Enrich(scan);
    LP_CHECK(!HasScore(scan));

    LP_CHECK(detector.StateCount() == 0);
}

void TestToolDedup() {
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);

    edr::Event first = PsScriptEvent(1000 * kSecond,
                                     "Invoke-Inveigh -ConsoleOutput Y");
    detector.Enrich(first);
    LP_CHECK(HasScore(first));

    /* Same tool inside the window is suppressed. */
    edr::Event repeat = PsScriptEvent(1100 * kSecond,
                                      "Invoke-Inveigh -ConsoleOutput Y");
    detector.Enrich(repeat);
    LP_CHECK(!HasScore(repeat));

    /* A different tool is a different key and passes. */
    edr::Event mitm6 = ProcEvent(1100 * kSecond,
                                 "C:\\Windows\\System32\\cmd.exe",
                                 "python.exe mitm6.py -d corp.local");
    detector.Enrich(mitm6);
    LP_CHECK(HasScore(mitm6));
    LP_CHECK(detector.StateCount() == 2);

    /* Window expiry re-arms the first tool. */
    edr::Event late = PsScriptEvent(1000 * kSecond + 301 * kSecond,
                                    "Invoke-Inveigh -ConsoleOutput Y");
    detector.Enrich(late);
    LP_CHECK(HasScore(late));
}

void TestMinScoreGating() {
    /* min_score 75: the 65 mDNS tier is filtered, 75 survives. */
    {
        edr::LlmnrPoisonDetector detector(true, 75, 300, 1024);
        edr::Event mdns = ListenerEvent(1000 * kSecond,
                                        "C:\\Tools\\spoof\\mdns_tool.exe",
                                        "5353");
        detector.Enrich(mdns);
        LP_CHECK(!HasScore(mdns));
        edr::Event nbns = ListenerEvent(1001 * kSecond,
                                        "C:\\Tools\\spoof\\nbns_tool.exe",
                                        "137");
        detector.Enrich(nbns);
        LP_CHECK(nbns.fields.at(edr::field::kLlmnrPoisonScore) == "75");
    }
    /* min_score 85: mitm6 (80) is filtered, the LLMNR tier survives. */
    {
        edr::LlmnrPoisonDetector detector(true, 85, 300, 1024);
        edr::Event tool = ProcEvent(1000 * kSecond,
                                    "C:\\Windows\\System32\\cmd.exe",
                                    "python.exe mitm6.py -d corp.local");
        detector.Enrich(tool);
        LP_CHECK(!HasScore(tool));
        edr::Event llmnr = ListenerEvent(1001 * kSecond,
                                         "C:\\Tools\\poisoner.exe", "5355");
        detector.Enrich(llmnr);
        LP_CHECK(llmnr.fields.at(edr::field::kLlmnrPoisonScore) == "85");
    }
    /* min_score 55 admits the 65 mDNS tier (low-score positive uses its
     * own low-threshold instance to avoid polluting the blocks above). */
    {
        edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);
        edr::Event mdns = ListenerEvent(1000 * kSecond,
                                        "C:\\Tools\\spoof\\mdns_tool.exe",
                                        "5353");
        detector.Enrich(mdns);
        LP_CHECK(mdns.fields.at(edr::field::kLlmnrPoisonScore) == "65");
    }
}

void TestStateCapacityReset() {
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1);
    edr::Event llmnr =
        ListenerEvent(1000 * kSecond, "C:\\Tools\\poisoner.exe", "5355");
    detector.Enrich(llmnr);
    LP_CHECK(HasScore(llmnr));
    LP_CHECK(detector.StateCount() == 1);

    /* Second distinct key over capacity: dedup state resets, no UB, and
     * the detector keeps stamping. */
    edr::Event nbns =
        ListenerEvent(1100 * kSecond, "C:\\Tools\\poisoner.exe", "137");
    detector.Enrich(nbns);
    LP_CHECK(HasScore(nbns));
    LP_CHECK(detector.StateCount() == 1);

    edr::Event again =
        ListenerEvent(1200 * kSecond, "C:\\Tools\\poisoner.exe", "5355");
    detector.Enrich(again);
    LP_CHECK(HasScore(again));
    LP_CHECK(detector.StateCount() == 1);

    edr::Event tool = ProcEvent(1300 * kSecond,
                                "C:\\Windows\\System32\\cmd.exe",
                                "python.exe mitm6.py -d corp.local");
    detector.Enrich(tool);
    LP_CHECK(HasScore(tool));
    LP_CHECK(detector.StateCount() == 1);
}

void TestUnknownEventsSilent() {
    edr::LlmnrPoisonDetector detector(true, 55, 300, 1024);

    /* Uninspected event type. */
    edr::Event reg;
    reg.type = EDR_EVT_REG_WRITE;
    reg.ts100ns = 1000 * kSecond;
    reg.fields[edr::field::kType] = "REG_WRITE";
    reg.fields[edr::field::kRegValue] = "mitm6.py -d corp.local";
    detector.Enrich(reg);
    LP_CHECK(!HasScore(reg));

    /* Listener event without a port field. */
    edr::Event noPort;
    noPort.type = EDR_EVT_NET_LISTENER;
    noPort.ts100ns = 1001 * kSecond;
    noPort.fields[edr::field::kType] = "NET_LISTENER";
    noPort.fields[edr::field::kListenerAction] = "added";
    noPort.fields[edr::field::kListenerProtocol] = "udp";
    noPort.fields[edr::field::kListenerProcess] = "C:\\Tools\\poisoner.exe";
    detector.Enrich(noPort);
    LP_CHECK(!HasScore(noPort));

    /* POWERSHELL_SCRIPT without a script body. */
    edr::Event ps;
    ps.type = EDR_EVT_POWERSHELL_SCRIPT;
    ps.ts100ns = 1002 * kSecond;
    ps.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    detector.Enrich(ps);
    LP_CHECK(!HasScore(ps));

    /* PROCESS_START without a poisoning tool on its image. */
    edr::Event proc = ProcEvent(1003 * kSecond,
                                "C:\\Windows\\System32\\cmd.exe", nullptr);
    detector.Enrich(proc);
    LP_CHECK(!HasScore(proc));
}

/* Production-rule consumer check: rules are evaluated by the RuleEngine
 * against a hand-set llmnr_poison_score field (the RuleEngine never calls
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
    ev.type = EDR_EVT_NET_LISTENER;
    ev.ts100ns = 1000 * kSecond;
    ev.fields[edr::field::kType] = "NET_LISTENER";
    if (score != nullptr)
        ev.fields[edr::field::kLlmnrPoisonScore] = score;
    g_alerts.clear();
    engine->OnEvent(ev);
}

void TestProductionRules() {
    /* EDR-486 (llmnr_poison_score >= 75, high/alert, T1557.001) and
     * EDR-487 (55-74, medium/log, T1557.001) are written to
     * rules/rules.json by the wiring agent. Until then skip the block. */
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
                     "[llmnr_poison] rules file not found; "
                     "skipping production rules\n");
        return;
    }
    const std::string rulesText = ReadAllText(path);
    if (rulesText.find("EDR-486") == std::string::npos ||
        rulesText.find("EDR-487") == std::string::npos) {
        std::fprintf(stderr,
                     "[llmnr_poison] EDR-486/EDR-487 not in rules yet; "
                     "skipping production rules\n");
        return;
    }

    edr::RuleEngine engine;
    engine.LoadFromFile(path);
    engine.SetAlertCallback([](const edr::Alert& alert) {
        g_alerts.push_back(
            {alert.ruleId, alert.severity, alert.action, alert.mitreAttack});
    });

    /* Positive >=75 band: detector tiers 85/80/75 hit EDR-486 only. */
    FeedScore(&engine, "85");
    LP_CHECK(HasAlert("EDR-486"));
    LP_CHECK(!HasAlert("EDR-487"));
    const AlertRecord* high = FindAlert("EDR-486");
    LP_CHECK(high != nullptr);
    LP_CHECK(high->severity == "high");
    LP_CHECK(high->action == "alert");
    LP_CHECK(std::find(high->mitre.begin(), high->mitre.end(),
                       "T1557.001") != high->mitre.end());

    FeedScore(&engine, "80");
    LP_CHECK(HasAlert("EDR-486"));
    LP_CHECK(!HasAlert("EDR-487"));
    FeedScore(&engine, "75");
    LP_CHECK(HasAlert("EDR-486"));
    LP_CHECK(!HasAlert("EDR-487"));
    FeedScore(&engine, "100");
    LP_CHECK(HasAlert("EDR-486"));
    LP_CHECK(!HasAlert("EDR-487"));

    /* Mid band: 74 must NOT hit the >=75 rule; 65 hits EDR-487 only. */
    FeedScore(&engine, "74");
    LP_CHECK(HasAlert("EDR-487"));
    LP_CHECK(!HasAlert("EDR-486"));
    FeedScore(&engine, "65");
    LP_CHECK(HasAlert("EDR-487"));
    LP_CHECK(!HasAlert("EDR-486"));
    const AlertRecord* mid = FindAlert("EDR-487");
    LP_CHECK(mid != nullptr);
    LP_CHECK(mid->severity == "medium");
    LP_CHECK(mid->action == "log");
    LP_CHECK(std::find(mid->mitre.begin(), mid->mitre.end(),
                       "T1557.001") != mid->mitre.end());
    FeedScore(&engine, "55");
    LP_CHECK(HasAlert("EDR-487"));
    LP_CHECK(!HasAlert("EDR-486"));

    /* Dead band 50-54 and below: none of the new rules may fire. */
    FeedScore(&engine, "54");
    LP_CHECK(!HasAlert("EDR-486"));
    LP_CHECK(!HasAlert("EDR-487"));
    FeedScore(&engine, "52");
    LP_CHECK(!HasAlert("EDR-486"));
    LP_CHECK(!HasAlert("EDR-487"));
    FeedScore(&engine, "50");
    LP_CHECK(!HasAlert("EDR-486"));
    LP_CHECK(!HasAlert("EDR-487"));
    FeedScore(&engine, "40");
    LP_CHECK(!HasAlert("EDR-486"));
    LP_CHECK(!HasAlert("EDR-487"));

    /* Missing score field: predicates on it are false (M3 semantics). */
    FeedScore(&engine, nullptr);
    LP_CHECK(!HasAlert("EDR-486"));
    LP_CHECK(!HasAlert("EDR-487"));
}

} // namespace

void RunLlmnrPoisonDetectorTests() {
    std::fprintf(stderr, "[llmnr_poison] TestInspects\n");
    TestInspects();
    std::fprintf(stderr, "[llmnr_poison] TestDisabled\n");
    TestDisabled();
    std::fprintf(stderr, "[llmnr_poison] TestLlmnrListenerTier85\n");
    TestLlmnrListenerTier85();
    std::fprintf(stderr, "[llmnr_poison] TestNbnsListenerTier75\n");
    TestNbnsListenerTier75();
    std::fprintf(stderr, "[llmnr_poison] TestMdnsListenerTier65\n");
    TestMdnsListenerTier65();
    std::fprintf(stderr, "[llmnr_poison] TestListenerWhitelistSilent\n");
    TestListenerWhitelistSilent();
    std::fprintf(stderr, "[llmnr_poison] TestListenerIrrelevantSilent\n");
    TestListenerIrrelevantSilent();
    std::fprintf(stderr, "[llmnr_poison] TestListenerDedup\n");
    TestListenerDedup();
    std::fprintf(stderr, "[llmnr_poison] TestMitm6ToolTier80\n");
    TestMitm6ToolTier80();
    std::fprintf(stderr, "[llmnr_poison] TestInveighResponderNbnsToolsTier75\n");
    TestInveighResponderNbnsToolsTier75();
    std::fprintf(stderr, "[llmnr_poison] TestWordBoundaryNegatives\n");
    TestWordBoundaryNegatives();
    std::fprintf(stderr,
                 "[llmnr_poison] TestTokenTailBoundaryNegatives\n");
    TestTokenTailBoundaryNegatives();
    std::fprintf(stderr, "[llmnr_poison] TestToolDedup\n");
    TestToolDedup();
    std::fprintf(stderr, "[llmnr_poison] TestMinScoreGating\n");
    TestMinScoreGating();
    std::fprintf(stderr, "[llmnr_poison] TestStateCapacityReset\n");
    TestStateCapacityReset();
    std::fprintf(stderr, "[llmnr_poison] TestUnknownEventsSilent\n");
    TestUnknownEventsSilent();
    std::fprintf(stderr, "[llmnr_poison] TestProductionRules\n");
    TestProductionRules();
    std::fprintf(stderr, "[llmnr_poison] all passed\n");
}
