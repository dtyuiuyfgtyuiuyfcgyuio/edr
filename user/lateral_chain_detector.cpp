/*
 * lateral_chain_detector.cpp - See lateral_chain_detector.h.
 *
 * Detection surface per vector:
 *
 * remote_service
 *   EDR_EVT_SERVICE_INSTALL / EDR_EVT_SERVICE_INSTALL_HOOK whose image path
 *   points at a remote share (\\host\...) or a transient staging directory,
 *   which is the classic "sc \\host create" / PsExec service dropper shape.
 *   This reuses the existing semantics of lateral_transfer but requires no
 *   further evidence: dropping a service binary from a share is already a
 *   remote-invocation shape on its own.
 *
 * remote_logon
 *   EDR_EVT_LOGON with logon_type 3 or 10. Type 3 excludes local interactive
 *   sessions; type 10 is an explicit RDP session. Both mean a peer host
 *   initiated the authentication, which is the "arrived from elsewhere" leg
 *   of the chain.
 *
 * admin_share
 *   FILE_CREATE / FILE_READ / FILE_DELETE whose path is a \\host\<c$|admin$|
 *   ipc$|...> administrative share reference.
 *
 * remote_exec
 *   PROCESS_START of a known remote-execution tool, or of any process whose
 *   command line carries an explicit /node:, -ComputerName, -Session or
 *   \\host\admin$ style remote target.
 *
 * session_reuse
 *   EDR_EVT_LOGON with an explicit-credential shape (type 9 with an NTLM
 *   package) or PRIVILEGE usage of a credential-replay privilege, i.e.
 *   pass-the-hash / overpass-the-hash rather than a fresh interactive logon.
 *
 * discovery
 *   Process starts of host-enumeration utilities aimed at remote targets
 *   (nltest, dclist, net view /domain, qwinsta against a host, arp scans).
 *
 * Every vector above is a shape the agent can already observe; nothing here
 * requires new telemetry, which keeps the detector usable on deployments
 * that only run the process/network/registry sources.
 */
#include "lateral_chain_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <set>
#include <string>

#include "edr_event.h"

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

/* A chain spanning four or more independent mechanisms is materially
 * stronger than the sum of its parts; three or fewer can plausibly come from
 * a management console driving several features at once. */
constexpr int kBreadthBonus = 20;
constexpr int kBreadthThreshold = 4;

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (value.find(needle) != std::string::npos) return true;
    }
    return false;
}

/* True for a UNC path that names an administrative share. `\\host\c$`,
 * `\\host\admin$`, `\\host\ipc$`, `\\host\print$` and the drive-letter share
 * form are all unambiguous remote-administration references. */
bool IsAdminSharePath(const std::string& path, std::string& hostOut) {
    const std::string lower = LowerAscii(path);
    if (lower.rfind("\\\\", 0) != 0) return false;
    const size_t hostBegin = 2;
    const size_t hostEnd = lower.find('\\', hostBegin);
    if (hostEnd == std::string::npos) return false;
    const size_t shareEnd = lower.find('\\', hostEnd + 1);
    const std::string share = lower.substr(
        hostEnd + 1, (shareEnd == std::string::npos ? lower.size() : shareEnd) -
                         hostEnd - 1);
    const bool admin = share == "c$" || share == "admin$" || share == "ipc$" ||
                       share == "print$" || share == "d$" ||
                       (share.size() == 2 && share[0] >= 'a' && share[0] <= 'z' &&
                        share[1] == '$');
    if (!admin) return false;
    hostOut = lower.substr(hostBegin, hostEnd - hostBegin);
    return true;
}

/* Any remote UNC reference, used for the looser remote_exec shape. */
bool IsUncReference(const std::string& value) {
    return value.rfind("\\\\", 0) == 0;
}

/* A bare remote host argument: `\\host` with no share component behind it.
 *
 * This is PsExec's canonical target form. `psexec.exe \\fileserver -u admin
 * cmd.exe` names a remote host directly; because no share follows the host
 * the generic UNC handling above never sees it, so the remote_exec vector
 * used to go dark on the most common lateral-movement invocation there is.
 * The host token appears anywhere in the command line, not only at the
 * start, so this scans every `\\` occurrence and validates the token that
 * follows it. Matches only a host-shaped token: letters, digits, dots,
 * hyphens and underscores, with no trailing `\` share component. */
bool IsBareRemoteHost(const std::string& lower, std::string& hostOut) {
    size_t at = lower.find("\\\\");
    while (at != std::string::npos) {
        const size_t begin = at + 2;
        size_t end = lower.find_first_of(" \t\"", begin);
        if (end == std::string::npos) end = lower.size();
        if (end > begin) {
            const std::string host = lower.substr(begin, end - begin);
            /* A share component means this is a UNC path, not a bare host. */
            if (host.find('\\') == std::string::npos && !host.empty()) {
                bool shaped = true;
                for (char c : host) {
                    if (!(std::isalnum(static_cast<unsigned char>(c)) ||
                          c == '.' || c == '-' || c == '_')) {
                        shaped = false;
                        break;
                    }
                }
                if (shaped) {
                    hostOut = host;
                    return true;
                }
            }
        }
        at = lower.find("\\\\", at + 2);
    }
    return false;
}

/* A staging directory is where a remote tool gets written before execution;
 * system directories are excluded so ordinary installed software is silent. */
bool IsTransientPath(const std::string& value) {
    const std::string lower = LowerAscii(value);
    if (lower.find("\\windows\\") != std::string::npos) return false;
    return ContainsAny(lower, {"\\temp\\", "\\appdata\\", "\\programdata\\",
                               "\\public\\", "\\downloads\\", "\\users\\public\\",
                               "\\windows\\temp\\"});
}

bool IsRemoteExecTool(const std::string& base) {
    static const std::set<std::string> tools = {
        "psexec.exe", "psexesvc.exe", "paexec.exe", "smbexec.exe",
        "atexec.exe", "wmiexec.exe", "wmic.exe", "winrs.exe", "mmc.exe",
        "schtasks.exe", "sc.exe", "net.exe"
    };
    return tools.count(base) != 0;
}

bool IsDiscoveryTool(const std::string& base) {
    static const std::set<std::string> tools = {
        "nltest.exe", "dclist.exe", "nbtstat.exe", "qwinsta.exe",
        "dsquery.exe", "adfind.exe", "bloodhound.exe", "sharphound.exe"
    };
    return tools.count(base) != 0;
}

/* Explicit remote-target flags on an execution command line. These appear in
 * the exact shapes the corresponding tools document, so a plain local use of
 * the same tool cannot match. */
bool HasRemoteTargetFlag(const std::string& lower) {
    return ContainsAny(lower, {"/node:", "-computername", "-session:",
                               "-credential", "\\\\*\\", "psexesvc"});
}

std::string RemoteHostFromCommand(const std::string& lower) {
    size_t position = lower.find("/node:");
    if (position != std::string::npos) {
        position += 6;
        size_t end = lower.find_first_of(" \t\"", position);
        return lower.substr(position, (end == std::string::npos
                                           ? lower.size()
                                           : end) - position);
    }
    position = lower.find("-computername");
    if (position != std::string::npos) {
        position += 13;
        size_t begin = lower.find_first_not_of(" \t=:\"", position);
        if (begin == std::string::npos) return {};
        size_t end = lower.find_first_of(" \t\"", begin);
        return lower.substr(begin, (end == std::string::npos ? lower.size()
                                                             : end) - begin);
    }
    return {};
}

template <typename Map>
void EvictOldest(Map& map, size_t capacity) {
    if (map.size() <= capacity) return;
    auto oldest = std::min_element(map.begin(), map.end(),
        [](const auto& left, const auto& right) {
            return left.second.lastSeen100ns < right.second.lastSeen100ns;
        });
    if (oldest != map.end()) map.erase(oldest);
}

} // namespace

LateralChainDetector::LateralChainDetector(bool enabled, uint32_t minScore,
                                           uint32_t windowSeconds,
                                           uint32_t dedupWindowSeconds,
                                           size_t stateCapacity)
    : m_enabled(enabled),
      m_minScore(minScore),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool LateralChainDetector::Inspects(uint16_t type) {
    switch (type) {
    case EDR_EVT_PROCESS_START:
    case EDR_EVT_LOGON:
    case EDR_EVT_SERVICE_INSTALL:
    case EDR_EVT_SERVICE_INSTALL_HOOK:
    case EDR_EVT_PRIVILEGE:
    case EDR_EVT_FILE_CREATE:
    case EDR_EVT_FILE_READ:
    case EDR_EVT_FILE_DELETE:
    case EDR_EVT_NET_CONNECT:
        return true;
    default:
        return false;
    }
}

uint32_t LateralChainDetector::WeightFor(uint8_t vector) {
    switch (vector) {
    case VectorRemoteService: return 20;
    case VectorRemoteLogon:   return 20;
    case VectorAdminShare:    return 15;
    case VectorRemoteExec:    return 15;
    case VectorSessionReuse:  return 10;
    case VectorDiscovery:     return 10;
    default:                  return 0;
    }
}

const char* LateralChainDetector::VectorName(uint8_t bit) {
    switch (bit) {
    case VectorRemoteService: return "remote_service";
    case VectorRemoteLogon:   return "remote_logon";
    case VectorAdminShare:    return "admin_share";
    case VectorRemoteExec:    return "remote_exec";
    case VectorSessionReuse:  return "session_reuse";
    case VectorDiscovery:     return "discovery";
    default:                  return "unknown";
    }
}

uint8_t LateralChainDetector::VectorFor(const Event& event,
                                        std::string& evidence,
                                        std::string& remoteHost) {
    switch (event.type) {
    case EDR_EVT_SERVICE_INSTALL:
    case EDR_EVT_SERVICE_INSTALL_HOOK: {
        const std::string imagePath =
            FieldValue(event, field::kServiceImagePath);
        const std::string serviceName =
            FieldValue(event, field::kServiceName);
        const std::string lower = LowerAscii(imagePath);
        if (IsUncReference(lower)) {
            /* Name the service: a remote-staged service binary is only
             * actionable if an analyst can see which service was created
             * (PSEXESVC identifies PsExec outright). */
            evidence = "service binary staged from remote share: " +
                       imagePath +
                       (serviceName.empty() ? std::string()
                                            : " (service " + serviceName + ")");
            IsAdminSharePath(imagePath, remoteHost);
            return VectorRemoteService;
        }
        if (!imagePath.empty() && IsTransientPath(imagePath)) {
            evidence = "service binary in transient path: " + imagePath;
            return VectorRemoteService;
        }
        return VectorNone;
    }
    case EDR_EVT_LOGON: {
        const std::string logonType = FieldValue(event, field::kLogonType);
        const std::string package =
            LowerAscii(FieldValue(event, field::kAuthPackage));
        const std::string workstation =
            FieldValue(event, field::kSourceWorkstation);
        if (!workstation.empty()) remoteHost = LowerAscii(workstation);
        /* Type 9 with NTLM is credential replay, not a fresh logon. */
        if (logonType == "9" &&
            ContainsAny(package, {"ntlm", "negotiate"})) {
            evidence = "explicit-credential logon (type 9, " + package + ")";
            return VectorSessionReuse;
        }
        if (logonType == "3" || logonType == "10") {
            evidence = std::string("inbound remote logon (type ") + logonType +
                       ")" +
                       (workstation.empty() ? "" : " from " + workstation);
            return VectorRemoteLogon;
        }
        return VectorNone;
    }
    case EDR_EVT_PRIVILEGE: {
        const std::string privileges =
            LowerAscii(FieldValue(event, field::kPrivilegeList));
        if (ContainsAny(privileges, {"sebackupprivilege",
                                     "sedebugprivilege"}) &&
            FieldValue(event, field::kPrivilegeOperation) == "SENSITIVE_USED") {
            evidence = "sensitive credential-replay privilege used";
            return VectorSessionReuse;
        }
        return VectorNone;
    }
    case EDR_EVT_FILE_CREATE:
    case EDR_EVT_FILE_READ:
    case EDR_EVT_FILE_DELETE: {
        const std::string path = FieldValue(event, field::kFilePath).empty()
                                     ? FieldValue(event, field::kTargetPath)
                                     : FieldValue(event, field::kFilePath);
        if (IsAdminSharePath(path, remoteHost)) {
            evidence = "administrative share access: " + path;
            return VectorAdminShare;
        }
        return VectorNone;
    }
    case EDR_EVT_NET_CONNECT: {
        /* Fan-out to many hosts is the existing lateral_movement detector's
         * job; here a network connection only corroborates when it targets a
         * lateral port directly on a peer, so the chain keeps a network leg
         * without duplicating that detector's burst logic. */
        const std::string port = FieldValue(event, field::kDstPort);
        const std::string ip = LowerAscii(FieldValue(event, field::kDstIp));
        if (ip.empty() || ip == "127.0.0.1" || ip.rfind("127.", 0) == 0)
            return VectorNone;
        if (port == "445" || port == "5985" || port == "5986") {
            remoteHost = ip;
            evidence = "lateral port reachable at " + ip + ":" + port;
            return VectorDiscovery;
        }
        return VectorNone;
    }
    case EDR_EVT_PROCESS_START: {
        const std::string image = FieldValue(event, field::kImage);
        const std::string base = BaseName(image);
        const std::string command =
            LowerAscii(FieldValue(event, field::kCommandLine));
        if (IsRemoteExecTool(base) &&
            (IsUncReference(command) || HasRemoteTargetFlag(command))) {
            evidence = "remote execution: " + base;
            const std::string host = RemoteHostFromCommand(command);
            if (!host.empty()) remoteHost = host;
            return VectorRemoteExec;
        }
        if (IsDiscoveryTool(base)) {
            evidence = "remote host enumeration: " + base;
            return VectorDiscovery;
        }
        const std::string host = RemoteHostFromCommand(command);
        std::string bareHost;
        if (!host.empty()) {
            remoteHost = host;
            evidence = "remote target on command line: " + host;
            return VectorRemoteExec;
        }
        if (IsBareRemoteHost(command, bareHost)) {
            remoteHost = bareHost;
            evidence = "remote target on command line: " + bareHost;
            return VectorRemoteExec;
        }
        return VectorNone;
    }
    default:
        return VectorNone;
    }
}

std::string LateralChainDetector::AttributionKey(const Event& event) {
    if (!event.processIdentity.empty()) return event.processIdentity;
    if (event.pid != 0) return "pid:" + std::to_string(event.pid);
    const std::string image = FieldValue(event, field::kImage);
    if (!image.empty()) return "img:" + BaseName(image);
    return {};
}

int LateralChainDetector::ScoreOf(const KeyState& state) const {
    int score = 0;
    int vectors = 0;
    for (uint8_t bit : state.order) {
        score += static_cast<int>(WeightFor(bit));
        ++vectors;
    }
    if (vectors >= kBreadthThreshold) score += kBreadthBonus;
    return std::min(100, score);
}

bool LateralChainDetector::InCooldown(const KeyState& state,
                                      uint64_t now100ns) const {
    if (!state.flagged) return false;
    if (m_dedupWindow100ns == 0) return false;
    if (now100ns < state.lastFlag100ns) return false;
    return now100ns - state.lastFlag100ns < m_dedupWindow100ns;
}

void LateralChainDetector::WriteState(Event& event, const KeyState& state,
                                      int score) {
    std::string vectors;
    for (uint8_t bit : state.order) {
        if (!vectors.empty()) vectors += ",";
        vectors += VectorName(bit);
    }
    std::string evidence;
    for (const std::string& item : state.evidence) {
        if (!evidence.empty()) evidence += " | ";
        evidence += item;
    }
    event.fields[field::kLateralChainScore] = std::to_string(score);
    event.fields[field::kLateralChainVerdict] =
        score >= 75 ? "MALICIOUS" : "SUSPICIOUS";
    event.fields[field::kLateralChainSignals] = vectors;
    event.fields[field::kLateralChainVectorCount] =
        std::to_string(state.order.size());
    event.fields[field::kLateralChainEvidence] = evidence;
    if (!state.remoteHost.empty())
        event.fields[field::kLateralChainRemoteHost] = state.remoteHost;
    event.fields[field::kLateralChainWindowSeconds] =
        std::to_string(m_window100ns / kFiletimeTicksPerSecond);
}

void LateralChainDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_states.begin(); it != m_states.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_states.erase(it);
        else
            ++it;
    }
}

void LateralChainDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string key = AttributionKey(event);
    if (key.empty()) return;

    std::string evidence;
    std::string remoteHost;
    const uint8_t vector = VectorFor(event, evidence, remoteHost);
    if (vector == VectorNone) return;

    KeyState& state = m_states[key];
    state.lastSeen100ns = now;
    if (state.remoteHost.empty() && !remoteHost.empty())
        state.remoteHost = remoteHost;

    bool widened = false;
    if (!(state.mask & vector)) {
        state.mask |= vector;
        state.order.push_back(vector);
        if (!evidence.empty()) state.evidence.push_back(evidence);
        widened = true;
    } else if (!evidence.empty() &&
               std::find(state.evidence.begin(), state.evidence.end(),
                         evidence) == state.evidence.end() &&
               state.evidence.size() < 16) {
        /* Same vector, new corroborating detail: keep the sample bounded so a
         * chatty event stream cannot grow the state without limit. */
        state.evidence.push_back(evidence);
    }

    const int score = ScoreOf(state);
    state.peakScore = std::max(state.peakScore, score);

    /* The cooldown exists to stop one chain flooding the alert stream with
     * repeats of the same finding. It must not swallow a genuine escalation:
     * if this event added a vector the chain had not seen before, the alert
     * carries new information and is always emitted, so a chain that widens
     * from SUSPICIOUS to MALICIOUS inside the dedup window still reports the
     * escalation. */
    if (score < static_cast<int>(m_minScore) ||
        (!widened && InCooldown(state, now))) {
        EvictOldest(m_states, m_stateCapacity);
        return;
    }

    state.flagged = true;
    state.lastFlag100ns = now;
    WriteState(event, state, score);
    EvictOldest(m_states, m_stateCapacity);
}

} // namespace edr
