/*
 * alerter_sink_tests.cpp - Unit tests for Alerter::SetSink / OnAlert sink
 * dispatch (the out-of-process mirror hook used by the webhook notifier).
 * Every test drives a real temp alerts.jsonl under %TEMP% (unique name,
 * deleted at the end); no network I/O and useEventLog=false, so no Event
 * Log source is registered.
 */
#include "alerter_sink_tests.h"

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include "alerter.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define AS_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond)
        throw std::runtime_error(
            "alerter sink test failed at line " + std::to_string(line) +
            ": " + expr);
}

/* Unique ledger path under %TEMP%: tag + pid + per-process counter keeps
 * concurrent suites from colliding; a stale file from a crashed earlier
 * run is removed up front because ResumeChainFromFile would otherwise
 * resume its chain instead of starting at seq 1. */
std::string TempLedgerPath(const char* tag) {
    char tempDir[MAX_PATH] = {};
    const DWORD n = GetTempPathA(MAX_PATH, tempDir);
    AS_CHECK(n > 0 && n < MAX_PATH);
    static unsigned counter = 0;
    std::string path = std::string(tempDir) + "alerter_sink_" + tag + "_" +
                       std::to_string(GetCurrentProcessId()) + "_" +
                       std::to_string(++counter) + ".jsonl";
    DeleteFileA(path.c_str());
    return path;
}

void RemoveQuietly(const std::string& path) { DeleteFileA(path.c_str()); }

std::vector<std::string> ReadLines(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    AS_CHECK(in.good());
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return lines;
}

std::string ReadAll(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
}

/* Minimal complete Alert. AlertToJsonLine always serializes
 * rule/severity/action plus the event's ts_100ns/pid/type/fields; the
 * MITRE lists exercise the optional mitre_attack/mitre_tactic sections.
 * alert.event must point at a live Event for the whole OnAlert call. */
struct Fixture {
    edr::Event ev;
    edr::Alert alert;
    Fixture() {
        ev.type = EDR_EVT_PROCESS_START;
        ev.ts100ns = 134000000000000000ULL;
        ev.pid = 4242;
        ev.source = "test";
        ev.fields[edr::field::kImage] = "C:\\Windows\\System32\\net.exe";
        ev.fields[edr::field::kCommandLine] = "net user backdoor /add";
        alert.ruleId = "EDR-326";
        alert.severity = "high";
        alert.action = "alert";
        alert.event = &ev;
        alert.mitreAttack.push_back("T1136.001");
        alert.mitreTactic.push_back("Persistence");
    }
};

/* A fresh ledger starts its hash chain from the all-zero prev digest. */
const std::string kZeroPrev(64, '0');

} // namespace

void RunAlerterSinkTests() {
    std::fprintf(stderr, "[alerter_sink] TestSinkReceivesLedgerLine\n");
    {
        const std::string path = TempLedgerPath("exact");
        std::string sinkLine;
        bool called = false;
        {
            edr::Alerter alerter(path, /*redact=*/false, /*useEventLog=*/false);
            AS_CHECK(alerter.Open());
            alerter.SetSink([&](const std::string& alertJson) {
                called = true;
                sinkLine = alertJson;
            });
            Fixture fx;
            alerter.OnAlert(fx.alert);
        } /* destructor closes the file before we compare on disk */
        AS_CHECK(called);
        AS_CHECK(!sinkLine.empty());
        const std::vector<std::string> lines = ReadLines(path);
        AS_CHECK(lines.size() == 1);
        /* Byte-for-byte: the sink got exactly the persisted ledger line,
         * chain fields (chain_seq/chain_prev/chain_hash) included. */
        AS_CHECK(sinkLine == lines[0]);
        AS_CHECK(sinkLine.find("\"rule\":\"EDR-326\"") != std::string::npos);
        AS_CHECK(sinkLine.find("\"severity\":\"high\"") != std::string::npos);
        AS_CHECK(sinkLine.find("\"action\":\"alert\"") != std::string::npos);
        AS_CHECK(sinkLine.find("\"type\":\"PROCESS_START\"") !=
                 std::string::npos);
        AS_CHECK(sinkLine.find("\"mitre_attack\":[\"T1136.001\"]") !=
                 std::string::npos);
        AS_CHECK(sinkLine.find("\"mitre_tactic\":[\"Persistence\"]") !=
                 std::string::npos);
        AS_CHECK(sinkLine.find("\"chain_seq\":1,") != std::string::npos);
        AS_CHECK(sinkLine.find("\"chain_prev\":\"" + kZeroPrev + "\"") !=
                 std::string::npos);
        AS_CHECK(sinkLine.find("\"chain_hash\":\"") != std::string::npos);
        RemoveQuietly(path);
    }

    std::fprintf(stderr, "[alerter_sink] TestSinkCalledOncePerAlert\n");
    {
        const std::string path = TempLedgerPath("count");
        std::vector<std::string> seen;
        {
            edr::Alerter alerter(path, false, false);
            AS_CHECK(alerter.Open());
            alerter.SetSink([&](const std::string& alertJson) {
                seen.push_back(alertJson);
            });
            Fixture fx1;
            alerter.OnAlert(fx1.alert);
            Fixture fx2;
            fx2.ev.pid = 4243;
            alerter.OnAlert(fx2.alert);
        }
        /* Exactly one sink call per alert, and the calls carry the two
         * distinct persisted lines in order. */
        AS_CHECK(seen.size() == 2);
        const std::vector<std::string> lines = ReadLines(path);
        AS_CHECK(lines.size() == 2);
        AS_CHECK(seen[0] == lines[0]);
        AS_CHECK(seen[1] == lines[1]);
        AS_CHECK(seen[0] != seen[1]);
        AS_CHECK(lines[0].find("\"chain_seq\":1,") != std::string::npos);
        AS_CHECK(lines[1].find("\"chain_seq\":2,") != std::string::npos);
        RemoveQuietly(path);
    }

    std::fprintf(stderr, "[alerter_sink] TestNoSinkIsFine\n");
    {
        const std::string path = TempLedgerPath("nosink");
        {
            edr::Alerter alerter(path, false, false);
            AS_CHECK(alerter.Open());
            /* No SetSink call: the optional sink stays empty. */
            Fixture fx;
            alerter.OnAlert(fx.alert);
        }
        const std::vector<std::string> lines = ReadLines(path);
        AS_CHECK(lines.size() == 1);
        AS_CHECK(lines[0].find("\"rule\":\"EDR-326\"") != std::string::npos);
        AS_CHECK(lines[0].find("\"chain_seq\":1,") != std::string::npos);
        RemoveQuietly(path);
    }

    std::fprintf(stderr, "[alerter_sink] TestThrowingSinkContained\n");
    {
        /* Alerter's contract (alerter.h): sink failures are CONTAINED at
         * the call site — the sink runs on the event consumer thread, so a
         * throwing sink must never escape OnAlert (a propagating throw
         * would take down event processing). The ledger write + flush
         * complete BEFORE the sink runs, so a throwing sink can neither
         * lose nor corrupt the persisted line and the hash-chain state
         * stays sound. Durable guarantees asserted: OnAlert returns
         * normally despite the throwing sink, the ledger line is on disk,
         * and later alerts still persist (failures logged once, counted
         * always — not asserted here beyond behavior). */
        const std::string path = TempLedgerPath("throw");
        {
            edr::Alerter alerter(path, false, false);
            AS_CHECK(alerter.Open());
            alerter.SetSink([](const std::string&) {
                throw std::runtime_error("sink exploded");
            });
            Fixture fx;
            alerter.OnAlert(fx.alert);
            const std::vector<std::string> lines = ReadLines(path);
            AS_CHECK(lines.size() == 1);
            AS_CHECK(lines[0].find("\"chain_seq\":1,") != std::string::npos);
            AS_CHECK(lines[0].find("\"rule\":\"EDR-326\"") !=
                     std::string::npos);
            /* Sink throws again: OnAlert still returns normally, the
             * ledger still advances and the chain sequence stays
             * contiguous. */
            Fixture fx2;
            fx2.ev.pid = 4243;
            alerter.OnAlert(fx2.alert);
            const std::vector<std::string> after = ReadLines(path);
            AS_CHECK(after.size() == 2);
            AS_CHECK(after[1].find("\"chain_seq\":2,") != std::string::npos);
        }
        RemoveQuietly(path);
    }

    std::fprintf(stderr, "[alerter_sink] TestLedgerFlushedBeforeSink\n");
    {
        const std::string path = TempLedgerPath("flush");
        {
            edr::Alerter alerter(path, false, false);
            AS_CHECK(alerter.Open());
            alerter.SetSink([&](const std::string& alertJson) {
                /* Read the same ledger from disk INSIDE the sink. The
                 * stream write+flush happen under the file mutex before
                 * the sink is invoked (outside it), so the line must
                 * already be durable here. Strongest form: the exact
                 * string handed to the sink is on disk, newline and all. */
                const std::string content = ReadAll(path);
                AS_CHECK(!content.empty());
                AS_CHECK(content.find(alertJson + "\n") != std::string::npos);
            });
            Fixture fx;
            alerter.OnAlert(fx.alert);
        }
        RemoveQuietly(path);
    }

    std::fprintf(stderr, "[alerter_sink] TestSinkSwap\n");
    {
        /* SetSink assigns (m_sink = std::move(sink)), i.e. replacement,
         * not stacking: after the second registration only the newest
         * sink observes alerts. Asserted against that actual behavior. */
        const std::string path = TempLedgerPath("swap");
        int firstCalls = 0;
        int secondCalls = 0;
        std::string secondLine;
        {
            edr::Alerter alerter(path, false, false);
            AS_CHECK(alerter.Open());
            alerter.SetSink([&](const std::string&) { ++firstCalls; });
            Fixture fx1;
            alerter.OnAlert(fx1.alert);
            alerter.SetSink([&](const std::string& alertJson) {
                ++secondCalls;
                secondLine = alertJson;
            });
            Fixture fx2;
            fx2.ev.pid = 4243;
            alerter.OnAlert(fx2.alert);
        }
        /* First sink saw only the pre-swap alert, second sink only the
         * post-swap one; both ledger lines were persisted regardless. */
        AS_CHECK(firstCalls == 1);
        AS_CHECK(secondCalls == 1);
        const std::vector<std::string> lines = ReadLines(path);
        AS_CHECK(lines.size() == 2);
        AS_CHECK(secondLine == lines[1]);
        RemoveQuietly(path);
    }

    std::fprintf(stderr, "[alerter_sink] all passed\n");
}
