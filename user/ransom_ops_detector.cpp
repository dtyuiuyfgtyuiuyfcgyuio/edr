/*
 * ransom_ops_detector.cpp - Business-destruction precursor (T1489/T1070.004).
 */
#include "ransom_ops_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/* Security / database / backup / VSS services that ransomware stops to
 * disable defenses and data integrity before detonation. */
const char* const kCriticalServices[] = {
    "windefend", "msmpeng", "msmpsvc", "securitycenter", "wscsvc",
    "sense", "csfalcon", "csagent", "cylancesvc", "cb", "carbonblack",
    "mcafee", "mcshield", "mfehavr", "mfemms", "mfeesp", "mbesvc",
    "mbae", "mbamservice", "sophos", "savservice", "sophossps",
    "kavsvc", "kaspersky", "klif", "symantec", "ccsvchst", "sep",
    "sepmanager", "bitdefender", "bdagent", "k7avf", "avp",
    "sqlservr", "mssqlserver", "sqlbrowser", "sqlwriter", "mongod",
    "mysqld", "oracleservice", "postgresql", "exchange", "w3svc",
    "iisadmin", "msftpsvc", "dns", "isadfsrv", "vss", "swprv",
    "sppsvc", "wbengine", "bestsvc", "gxsvc", "backup", "dfsr",
    "msdtc", "eventlog", "wsearch", "mep", "intelme", "smbw", "seclogon",
};

const char* const kDefensiveProcesses[] = {
    "msmpeng", "defender", "msascui", "sense", "csfalcon", "csagent",
    "carbonblack", "cb.exe", "cylance", "mcshield", "sophos", "kaspersky",
    "avp", "mbam", "mbae", "xcorr", "hipsvc",
};

bool IsStopContext(const std::string& lower) {
    return Contains(lower, "sc stop ") || Contains(lower, "sc.exe stop ") ||
           Contains(lower, "net stop ") || Contains(lower, "stop-service") ||
           Contains(lower, "sc stop\"") || Contains(lower, "net stop\"");
}

bool IsDisableContext(const std::string& lower) {
    return Contains(lower, "sc config ") ||
           Contains(lower, "sc.exe config ") ||
           Contains(lower, "set-service");
}

/* Extract the image-name target of a `taskkill /im <name>` segment so the
 * name is not also (mis)counted as a stopped service: a force-killed
 * process is scored separately as a defensive-process kill. */
std::string TaskKillTarget(const std::string& lower) {
    size_t pos = lower.find("/im ");
    if (pos == std::string::npos) pos = lower.find("-im ");
    if (pos == std::string::npos) return std::string();
    pos += 4;
    const size_t end = lower.find_first_of(" \t&", pos);
    std::string target = lower.substr(
        pos, end == std::string::npos ? std::string::npos : end - pos);
    /* Strip the trailing wildcard of broad kills (taskkill /im *.exe). */
    if (!target.empty() && target.back() == '*')
        target.pop_back();
    return target;
}

/* True when the taskkill target names the given service (with or without
 * an .exe suffix). */
bool KillTargetMatches(const std::string& killTarget, const char* service) {
    if (killTarget.empty()) return false;
    if (killTarget == service) return true;
    return killTarget == std::string(service) + ".exe";
}

} // namespace

RansomOpsDetector::RansomOpsDetector(bool enabled, uint32_t minScore,
                                     uint32_t dedupWindowSeconds,
                                     size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool RansomOpsDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool RansomOpsDetector::AnalyzeCommand(const std::string& lower,
                                       uint32_t* score,
                                       std::string* signals) const {
    const bool stopContext = IsStopContext(lower);
    const bool disableContext = IsDisableContext(lower);
    const bool explicitlyDisabled =
        Contains(lower, "start= disabled") || Contains(lower, "start=\"disabled\"");

    /* Stopping / disabling recognized critical services. */
    unsigned criticalStopCount = 0;
    unsigned criticalDisableCount = 0;
    if (stopContext || (disableContext && explicitlyDisabled)) {
        const std::string killTarget = TaskKillTarget(lower);
        for (const char* service : kCriticalServices) {
            if (Contains(lower, service)) {
                /* A name force-killed via taskkill is scored as a
                 * defensive-process kill, not as a stopped service. */
                if (stopContext && KillTargetMatches(killTarget, service))
                    continue;
                if (stopContext) ++criticalStopCount;
                else ++criticalDisableCount;
            }
        }
    }

    uint32_t bestScore = 0;
    std::string hitSignals;

    if (criticalStopCount > 0) {
        if (criticalStopCount >= 3) {
            bestScore = 90u;
            hitSignals = "multiple critical services stopped";
        } else if (criticalStopCount == 2) {
            bestScore = 85u;
            hitSignals = "two critical services stopped";
        } else {
            bestScore = 75u;
            hitSignals = "critical service stopped";
        }
    } else if (criticalDisableCount > 0) {
        bestScore = 75u;
        hitSignals = "critical service disabled";
    }

    /* Scheduled task deletion. */
    const bool taskDelete =
        Contains(lower, "schtasks") &&
        (Contains(lower, " /delete") || Contains(lower, " -delete") ||
         Contains(lower, " /del"));
    if (taskDelete) {
        if (bestScore < 65u) {
            bestScore = 65u;
            hitSignals = "scheduled task deleted";
        } else {
            hitSignals += ",scheduled task deleted";
        }
    }

    /* Force-killing a defensive process. */
    const bool forceKill =
        Contains(lower, "taskkill") &&
        (Contains(lower, " /f") || Contains(lower, " -f"));
    if (forceKill) {
        for (const char* proc : kDefensiveProcesses) {
            if (!Contains(lower, proc)) continue;
            if (bestScore < 70u) {
                bestScore = 70u;
                hitSignals = "defensive process force-killed";
            } else {
                hitSignals += ",defensive process force-killed";
            }
            break;
        }
    }

    /* Removing startup Run/RunOnce entries. */
    const bool startupWipe =
        Contains(lower, "currentversion\\run") ||
        Contains(lower, "currentversion\\runonce") ||
        Contains(lower, "startup\\") ||
        Contains(lower, "\\startup\\") ||
        Contains(lower, "startupapprove");
    if (startupWipe &&
        (Contains(lower, "reg delete") ||
         Contains(lower, "reg.exe delete") ||
         Contains(lower, "remove-itemproperty") ||
         Contains(lower, "remove-item ") ||
         Contains(lower, "del /f") ||
         Contains(lower, "erase /f"))) {
        if (bestScore < 70u) {
            bestScore = 70u;
            hitSignals = "startup entry removed";
        } else {
            hitSignals += ",startup entry removed";
        }
    }

    if (hitSignals.empty()) return false;

    /* Two or more distinct signals escalate +15 (capped at 100). */
    const bool combo = hitSignals.find(',') != std::string::npos;
    if (combo) bestScore = std::min(100u, bestScore + 15u);

    *score = bestScore;
    *signals = hitSignals;
    return true;
}

void RansomOpsDetector::Stamp(Event& event, uint32_t score,
                              const std::string& signals) {
    event.fields[field::kRansomOpsScore] = std::to_string(score);
    event.fields[field::kRansomOpsVerdict] =
        score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kRansomOpsSignals] = signals;
}

void RansomOpsDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty()) return;
    const std::string lower = ToLowerAscii(text);

    uint32_t score = 0;
    std::string signals;
    if (!AnalyzeCommand(lower, &score, &signals)) return;
    if (score < m_minScore) return;

    const uint64_t now = event.ts100ns;
    const std::string key = signals;
    auto it = m_lastAlert.find(key);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
            std::fprintf(stderr,
                "[edr-ransom-ops] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, score, signals);
}

} // namespace edr
