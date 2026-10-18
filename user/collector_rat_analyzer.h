/*
 * collector_rat_analyzer.h - Remote-access-trojan behavior scan collector.
 *
 * Polls the live process table (Toolhelp32) on a bounded interval and scores
 * running processes against RAT-shaped heuristics: masquerading loader
 * binaries with abnormal parents (svchost.exe not parented by services.exe,
 * service-spawned conhost.exe hidden consoles, rundll32.exe with unusual
 * parents), known analysis / anti-debug tool presence (anti-VM, debugger,
 * network-sniffing and process-inspection utilities that RATs evade), and
 * execution from user-writable locations (Temp, AppData, ProgramData,
 * Public, Downloads, Desktop). Processes that reach the configured minimum
 * score are reported as EDR_EVT_RAT_ANALYZER events carrying rat_score /
 * rat_flags / rat_verdict.
 *
 * The collector is a bounded poll thread: one snapshot per scan interval,
 * per-process re-report limited by a dedup window (and immediate re-report
 * when the score increases). It never touches the filesystem, never
 * terminates processes, and Start never blocks.
 *
 * Pure scoring helpers are exposed for unit tests (they require no live
 * process state).
 */
#ifndef EDR_COLLECTOR_RAT_ANALYZER_H
#define EDR_COLLECTOR_RAT_ANALYZER_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "collector.h"

namespace edr {

struct RatAnalyzerConfig {
    bool enable = false;                 /* enable_rat_analyzer */
    uint32_t scanIntervalSeconds = 15;   /* rat_analyzer_scan_interval_seconds, 5..3600 */
    uint32_t minScore = 15;              /* rat_analyzer_min_score, 1..100 */
    uint32_t dedupWindowSeconds = 300;   /* rat_analyzer_dedup_window_seconds, 30..86400 */
    size_t stateCapacity = 4096;         /* rat_analyzer_state_capacity, 128..65536 */
};

/* Factory. Returns an ICollector that never blocks Start (false = unavailable). */
ICollector* CreateRatAnalyzerCollector(const RatAnalyzerConfig& cfg);

/* ---- Pure helpers (unit-testable, no live process state) -------------- */

/* Result of one process evaluation. */
struct RatScoreResult {
    int score = 0;                        /* 0..100, capped */
    std::vector<std::string> flags;       /* RAT_* reason tags */
};

/* Scores one process. Inputs must be lowercase: image is the process image
 * basename, parentImage the parent basename (may be empty), fullPath the
 * lowercase full image path (may be empty when unavailable; path-dependent
 * scoring is skipped then). Returns the capped score and reason flags. */
RatScoreResult RatAnalyzerScoreProcess(const std::string& image,
                                       const std::string& parentImage,
                                       const std::string& fullPath);

/* Verdict for a score: "MALICIOUS" (>= 55), "SUSPICIOUS" (>= 30), or
 * "MONITOR" (>= 1). */
const char* RatAnalyzerVerdict(int score);

} // namespace edr

#endif /* EDR_COLLECTOR_RAT_ANALYZER_H */
