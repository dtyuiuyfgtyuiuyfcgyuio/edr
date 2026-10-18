/*
 * host_profile_detector.cpp - Per-actor host profiling breadth detector.
 * See host_profile_detector.h for the scoring model and rationale.
 */
#include "host_profile_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <initializer_list>
#include <vector>

namespace edr {
namespace {

constexpr size_t kActorKeyMax = 256;

std::string LowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

bool Contains(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& haystack,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (Contains(haystack, needle)) return true;
    }
    return false;
}

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string BaseName(const std::string& value) {
    const size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

bool LooksPrivileged(const std::string& lower) {
    return ContainsAny(lower, {"runas ", " /user:", "-verb runas",
                               "start-process -verb", "psexec", "/rl highest",
                               "schtasks /create"});
}

} // namespace

HostProfileDetector::HostProfileDetector(bool enabled, uint32_t minScore,
                                         uint32_t windowSeconds,
                                         uint32_t minCategories,
                                         uint32_t dedupWindowSeconds,
                                         size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_minCategories(std::max<uint32_t>(2, minCategories)),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

/* static */
bool HostProfileDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool HostProfileDetector::Classify(const std::string& lower,
                                   std::string* category) const {
    /* --- Process discovery (T1007) -------------------------------- */
    if (ContainsAny(lower, {"get-process", "get-ciminstance win32_process",
                            "wmic process", "wmic.exe process",
                            "tasklist", "pslist", "getprocesses"})) {
        *category = "processes";
        return true;
    }
    /* --- Service discovery (T1007) -------------------------------- */
    if (ContainsAny(lower, {"get-service", "wmic service", "wmic.exe service",
                            "net start", "sc query", "sc.exe query",
                            "sc qc", "sc.exe qc", "sc qdescription",
                            "sc.exe qdescription", "driverquery",
                            "fltmc", "getservice"})) {
        *category = "services";
        return true;
    }
    /* --- Registry discovery (T1012) ------------------------------- */
    if (ContainsAny(lower, {"reg query", "reg.exe query", "get-itemproperty",
                            "get-childitem hklm", "get-childitem -path hklm",
                            "regedit /e", "regedit.exe /e", "reg export",
                            "reg.exe export"})) {
        *category = "registry";
        return true;
    }
    /* --- Network configuration discovery (T1016) ------------------- */
    /* The executable basename must appear verbatim: "ipconfig" nests inside
     * "ipconfig6" and generic substrings invite false positives, so the
     * trailing space / .exe boundary is part of every needle. */
    if (ContainsAny(lower, {"ipconfig ", "ipconfig.exe", "route print",
                            "netsh interface show", "get-netipconfiguration",
                            "get-netipaddress", "arp -a", "arp.exe -a",
                            "getmac"})) {
        *category = "netconfig";
        return true;
    }
    /* --- System information discovery (T1082) ---------------------- */
    if (ContainsAny(lower, {"systeminfo", "msinfo32", "get-computerinfo",
                            "wmic os get", "wmic.exe os get", "wmic bios",
                            "wmic.csproduct get"})) {
        *category = "systeminfo";
        return true;
    }
    /* --- Permission group discovery (T1069) ------------------------ */
    if (ContainsAny(lower, {"net localgroup", "net.exe localgroup",
                            "net group ", "net.exe group ", "whoami /groups",
                            "whoami /priv", "get-localgroup",
                            "get-adgroupmember", "dsquery group"})) {
        *category = "groups";
        return true;
    }
    /* --- Account discovery (T1087) --------------------------------- */
    if (ContainsAny(lower, {"net user", "net.exe user", "net accounts",
                            "net.exe accounts", "get-localuser",
                            "wmic useraccount", "wmic.exe useraccount",
                            "dsquery user"})) {
        *category = "accounts";
        return true;
    }
    return false;
}

void HostProfileDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_actors.begin(); it != m_actors.end();) {
        ActorState& state = it->second;
        for (auto cat = state.categories.begin();
             cat != state.categories.end();) {
            if (now100ns >= cat->second && m_window100ns != 0 &&
                now100ns - cat->second > m_window100ns)
                cat = state.categories.erase(cat);
            else
                ++cat;
        }
        if (state.categories.empty()) {
            it = m_actors.erase(it);
        } else {
            /* lastSeen100ns drives capacity eviction below; keep it in step
             * with the surviving window so a stale actor is dropped first. */
            uint64_t newest = 0;
            for (const auto& entry : state.categories) {
                if (entry.second > newest) newest = entry.second;
            }
            state.lastSeen100ns = newest;
            ++it;
        }
    }
}

bool HostProfileDetector::Analyze(Event& event, Finding* out) {
    const std::string image = FieldValue(event, field::kImage);
    const std::string command = FieldValue(event, field::kCommandLine);
    const std::string lower = LowerAscii(command);

    std::string category;
    if (!Classify(lower, &category)) return false;

    const std::string name = BaseName(image);
    /* The actor key is the executable basename plus the owning user. Two
     * different users on the same box are two different investigators, and
     * a tool that re-spawns per query (reg.exe, net.exe) still accumulates
     * correctly because the category window lives on the actor, not the
     * process instance. */
    std::string actor = name.empty() ? std::string("?") : name;
    const std::string user = FieldValue(event, field::kSubjectUserName);
    if (!user.empty()) {
        actor += "|";
        actor += LowerAscii(user);
    }
    if (actor.size() > kActorKeyMax) actor.resize(kActorKeyMax);

    const uint64_t now = event.ts100ns;
    if (now == 0) return false; /* cannot window an untimed event */

    /* Carry the privileged flag across a capacity reset. */
    bool privileged = false;
    auto existing = m_actors.find(actor);
    if (existing != m_actors.end()) {
        /* Clamp out-of-order timestamps before they can poison the window. */
        if (existing->second.lastSeen100ns != 0 &&
            now < existing->second.lastSeen100ns)
            return false;
        privileged = existing->second.privileged;
    }

    /* Capacity: reset the whole map rather than silently growing without
     * bound. Profiling state is cheap to rebuild (a few events). Never hold
     * a reference across the clear(). */
    if (m_stateCapacity != 0 && m_actors.size() > m_stateCapacity) {
        std::fprintf(stderr,
                     "[edr-host-profile] actor capacity %zu reached; "
                     "profiling state reset\n",
                     m_stateCapacity);
        m_actors.clear();
        existing = m_actors.end();
    }

    ActorState& state = m_actors[actor];
    state.lastSeen100ns = now;
    state.categories[category] = now;
    if (LooksPrivileged(lower)) state.privileged = true;

    PurgeExpired(now);

    const uint32_t count = static_cast<uint32_t>(state.categories.size());
    if (count < m_minCategories) return false;

    const bool grew = count > state.lastFlaggedCount;
    const bool cooled = state.lastStamp100ns == 0 ||
                        (now >= state.lastStamp100ns &&
                         now - state.lastStamp100ns >= m_dedupWindow100ns);
    if (!grew && !cooled) return false;

    std::vector<std::string> ordered;
    ordered.reserve(state.categories.size());
    for (const auto& entry : state.categories) ordered.push_back(entry.first);
    std::sort(ordered.begin(), ordered.end());

    std::string joined;
    for (const std::string& item : ordered) {
        if (!joined.empty()) joined += ",";
        joined += item;
    }

    out->categoryCount = count;
    out->categories = joined;
    out->privileged = state.privileged;
    /* Breadth is the signal: 2 categories is baseline admin work and
     * scores 55 (the SUSPICIOUS floor), 3 categories scores 60, and each
     * further category adds 12, hard-capped at 100. A privileged actor
     * that also shows breadth is escalated, matching the strict stance
     * taken toward T1068 elsewhere. */
    uint32_t score = 55u + (count >= 3u ? (count - 2u) * 12u : 0u);
    if (score > 100u) score = 100u;
    if (state.privileged) score = std::min(100u, score + 10u);
    out->score = score;
    out->signal = state.privileged
                      ? "privileged host profiling across multiple categories"
                      : "host profiling across multiple discovery categories";

    state.lastFlaggedCount = count;
    state.lastStamp100ns = now;
    return true;
}

void HostProfileDetector::Stamp(Event& event, const Finding& finding) const {
    event.fields[field::kHostProfileScore] = std::to_string(finding.score);
    event.fields[field::kHostProfileVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kHostProfileSignals] = finding.signal;
    event.fields[field::kHostProfileCategories] = finding.categories;
    event.fields[field::kHostProfileCategoryCount] =
        std::to_string(finding.categoryCount);
    event.fields[field::kHostProfileWindowSeconds] =
        std::to_string(m_windowSeconds);
    event.fields[field::kHostProfilePrivileged] =
        finding.privileged ? "true" : "false";
}

void HostProfileDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (event.type != EDR_EVT_PROCESS_START) return;

    Finding finding;
    if (!Analyze(event, &finding)) return;
    if (finding.score < m_minScore) return;
    Stamp(event, finding);
}

} // namespace edr
