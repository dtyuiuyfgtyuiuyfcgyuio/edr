/*
 * net_share_discovery_detector.cpp - Network share discovery burst detector
 * (T1135). See header for the scoring model.
 *
 * House contract: PROCESS_START takes kCommandLine; POWERSHELL_SCRIPT takes
 * kScriptBlockText (never kCommandLine). Scores >= 55 suspicious,
 * >= 75 malicious; below min_score stays silent.
 */
#include "net_share_discovery_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <initializer_list>

namespace edr {

namespace {

constexpr size_t kActorKeyMax = 256;
constexpr size_t kCommandSnippetMax = 160;
constexpr size_t kTargetMax = 128;
constexpr size_t kTargetsJoinedMax = 512;

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

/* Pull UNC targets (\\host, \\host\share) out of lowered text by scanning
 * each "\\\\" run and reading the host token up to the next separator.
 * \\host is what net view emits; \\host\share is what the PowerShell UNC
 * readers take. */
void ExtractTargets(const std::string& lower,
                    std::unordered_set<std::string>* out) {
    size_t pos = 0;
    while ((pos = lower.find("\\\\", pos)) != std::string::npos) {
        const size_t start = pos + 2;
        size_t end = start;
        while (end < lower.size() && lower[end] != '\\' &&
               lower[end] != ' ' && lower[end] != '"' && lower[end] != '\'')
            ++end;
        if (end > start) {
            const std::string target =
                lower.substr(pos, std::min(end - pos, kTargetMax));
            /* Skip admin namespaces that say nothing about which share the
             * actor was hunting. */
            if (target != "\\\\localhost" &&
                target.find('$') == std::string::npos)
                out->insert(target);
        }
        pos = start;
    }
}

} // namespace

NetShareDiscoveryDetector::NetShareDiscoveryDetector(
    bool enabled, uint32_t minScore, uint32_t windowSeconds,
    uint32_t minCommands, uint32_t dedupWindowSeconds, size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_minCommands(minCommands == 0 ? 1 : minCommands),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool NetShareDiscoveryDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

/* static */
bool NetShareDiscoveryDetector::Classify(const std::string& lower,
                                         bool* localEnum, bool* remoteUnc) {
    /* Local share enumeration: what this host exposes or has mounted. */
    if (ContainsAny(lower, {"net view", "net.exe view", "net1 view"})) {
        *localEnum = true;
        /* A UNC-bearing net view is enumeration aimed at a remote host. */
        if (Contains(lower, "\\\\")) *remoteUnc = true;
        return true;
    }
    if (ContainsAny(lower, {"net use", "net.exe use", "net1 use"})) {
        *localEnum = true;
        if (Contains(lower, "\\\\")) *remoteUnc = true;
        return true;
    }
    if (ContainsAny(lower, {"wmic share get", "wmic.exe share get",
                            "get-ciminstance win32_share",
                            "get-wmiobject win32_share", "get-smbshare",
                            "get-smbsharingconfiguration"})) {
        *localEnum = true;
        return true;
    }
    /* Direct UNC directory listing: probe a specific host or share path. */
    if (ContainsAny(lower, {"dir \\\\", "dir \\\\host", "ls \\\\host",
                            "get-childitem \\\\host", "get-childitem \\\\",
                            "gci \\\\host", "gci \\\\"})) {
        *remoteUnc = true;
        return true;
    }
    /* PowerShell .NET UNC read: WebClient pulling a \\host\share path. */
    if (ContainsAny(lower, {"downloadstring", "downloadfile"}) &&
        Contains(lower, "\\\\")) {
        *remoteUnc = true;
        return true;
    }
    if (Contains(lower, "new-object net.webclient") &&
        Contains(lower, "\\\\")) {
        *remoteUnc = true;
        return true;
    }
    return false;
}

void NetShareDiscoveryDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_actors.begin(); it != m_actors.end();) {
        ActorState& state = it->second;
        for (auto cmd = state.commands.begin(); cmd != state.commands.end();) {
            if (now100ns >= cmd->second && m_window100ns != 0 &&
                now100ns - cmd->second > m_window100ns)
                cmd = state.commands.erase(cmd);
            else
                ++cmd;
        }
        if (state.commands.empty()) {
            it = m_actors.erase(it);
            continue;
        }
        /* Targets carry no timestamps of their own: rebuild them from the
         * surviving commands so an expired command drops its target too. */
        state.targets.clear();
        for (const auto& entry : state.commands)
            ExtractTargets(entry.first, &state.targets);
        ++it;
    }
}

bool NetShareDiscoveryDetector::Analyze(Event& event, Finding* out) {
    std::string text;
    if (event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        text = FieldValue(event, field::kScriptBlockText);
    } else {
        text = FieldValue(event, field::kCommandLine);
        if (text.empty()) text = FieldValue(event, field::kImage);
    }
    if (text.empty()) return false;

    const std::string lower = LowerAscii(text);

    bool localEnum = false;
    bool remoteUnc = false;
    if (!Classify(lower, &localEnum, &remoteUnc)) return false;
    const bool privileged = LooksPrivileged(lower);

    /* The actor key is the executable basename plus the owning identity.
     * A tool that re-spawns per query still accumulates correctly because
     * the burst window lives on the actor, not the process instance. */
    std::string actor = BaseName(FieldValue(event, field::kImage));
    if (actor.empty()) actor = "?";
    actor += "|";
    actor += LowerAscii(FieldValue(event, field::kUserSid));
    actor += "|";
    actor += FieldValue(event, field::kSessionId);
    if (actor.size() > kActorKeyMax) actor.resize(kActorKeyMax);

    const uint64_t now = event.ts100ns;
    if (now == 0) return false; /* cannot window an untimed event */

    auto existing = m_actors.find(actor);
    if (existing != m_actors.end()) {
        /* Clamp out-of-order timestamps before they can poison the window. */
        if (existing->second.lastSeen100ns != 0 &&
            now < existing->second.lastSeen100ns)
            return false;
    }

    /* Capacity: reset rather than grow without bound. Burst state is cheap
     * to rebuild. Never hold a reference across the clear(). */
    if (m_stateCapacity != 0 && m_actors.size() >= m_stateCapacity) {
        std::fprintf(stderr,
                     "[edr-net-share-discovery] actor capacity %zu reached; "
                     "state reset\n",
                     m_stateCapacity);
        m_actors.clear();
        existing = m_actors.end();
    }

    ActorState& state = m_actors[actor];
    state.lastSeen100ns = now;
    if (localEnum) state.localEnum = true;
    if (remoteUnc) state.remoteUnc = true;
    if (privileged) state.privileged = true;

    /* Record the distinct command snippet: identical text never counts
     * twice toward the burst threshold. */
    const std::string snippet = lower.substr(0, kCommandSnippetMax);
    auto cmd = state.commands.find(snippet);
    if (cmd != state.commands.end()) {
        if (now > cmd->second) cmd->second = now;
    } else {
        state.commands.emplace(snippet, now);
    }

    PurgeExpired(now);

    const uint32_t count = static_cast<uint32_t>(state.commands.size());
    if (count < m_minCommands) return false; /* single probes stay silent */

    /* Dedup: re-stamp only once the burst grows or the cooldown elapses. */
    const bool grew = count > state.lastFlaggedCount;
    const bool cooled = state.lastStamp100ns == 0 ||
                        (now >= state.lastStamp100ns &&
                         now - state.lastStamp100ns >= m_dedupWindow100ns);
    if (!grew && !cooled) return false;

    /* Ladder: 3 distinct commands 60, 4 -> 70, 5 -> 75, 6+ -> 85. */
    uint32_t score = 60;
    if (count >= 6u) {
        score = 85;
    } else if (count == 5u) {
        score = 75;
    } else if (count == 4u) {
        score = 70;
    }
    /* Enumeration-then-pivot: a local share listing combined with a remote
     * UNC read is the discovery half of a lateral-movement chain. */
    if (state.localEnum && state.remoteUnc) score += 10;
    if (state.privileged) score += 10;
    if (score > 100u) score = 100u;

    out->score = score;
    out->commandCount = count;
    out->signal = state.privileged
                      ? "privileged network share discovery burst"
                      : "network share discovery burst";

    std::string joined;
    for (const std::string& target : state.targets) {
        if (!joined.empty() && joined.size() + 1 + target.size() >
                                   kTargetsJoinedMax)
            break;
        if (!joined.empty()) joined.append(",");
        joined.append(target);
    }
    out->targets = joined;

    state.lastFlaggedCount = count;
    state.lastStamp100ns = now;
    return true;
}

void NetShareDiscoveryDetector::Stamp(Event& event,
                                      const Finding& finding) const {
    event.fields[field::kNetShareDiscoveryScore] =
        std::to_string(finding.score);
    event.fields[field::kNetShareDiscoveryVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kNetShareDiscoverySignals] = finding.signal;
    event.fields[field::kNetShareDiscoveryTargets] = finding.targets;
    event.fields[field::kNetShareDiscoveryCommandCount] =
        std::to_string(finding.commandCount);
}

void NetShareDiscoveryDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    Finding finding;
    if (!Analyze(event, &finding)) return;
    if (finding.score < m_minScore) return;
    Stamp(event, finding);
}

} // namespace edr