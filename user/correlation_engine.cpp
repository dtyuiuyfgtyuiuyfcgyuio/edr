/*
 * correlation_engine.cpp - See correlation_engine.h.
 *
 * Incident identity combines a random engine/run nonce with a sequence, so
 * restarted agents can append to the same ledger without reusing old IDs.
 *
 * Score roll-up: the incident carries the maximum single-alert severity
 * weight, plus a breadth term once the chain spans multiple tactics, because
 * an incident that has moved from Execution to Credential Access to Lateral
 * Movement is more urgent than one repeating a single noisy rule. Both terms
 * are capped so the incident score stays comparable with a rule score.
 */
#include "correlation_engine.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <string>

#include "alerter.h"
#include "edr_event.h"
#include "json_lite.h"

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string NewRunId() {
    unsigned char bytes[16] = {};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("correlation random source unavailable");
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(32);
    for (unsigned char byte : bytes) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 15]);
    }
    return result;
}

constexpr int kScoreCritical = 90;
constexpr int kScoreHigh = 75;
constexpr int kScoreMedium = 50;
constexpr int kScoreLow = 25;
constexpr int kScoreInfo = 10;

/* Each additional distinct tactic adds this much, so a four-tactic chain
 * outranks any single noisy rule. */
constexpr int kTacticBreadthStep = 5;
constexpr int kMaxTacticBonus = 20;

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string LocalEndpointId() {
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD chars = static_cast<DWORD>(sizeof(computerName) /
                                     sizeof(computerName[0]));
    if (!GetComputerNameW(computerName, &chars) || chars == 0)
        throw std::runtime_error("local endpoint identity unavailable");
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                           computerName,
                                           static_cast<int>(chars), nullptr, 0,
                                           nullptr, nullptr);
    if (bytes <= 0)
        throw std::runtime_error("local endpoint identity conversion failed");
    std::string result(static_cast<size_t>(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, computerName,
                            static_cast<int>(chars), &result[0], bytes,
                            nullptr, nullptr) != bytes)
        throw std::runtime_error("local endpoint identity conversion failed");
    return result;
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

int SeverityScore(const std::string& severity) {
    const std::string lower = LowerAscii(severity);
    if (lower == "critical") return kScoreCritical;
    if (lower == "high") return kScoreHigh;
    if (lower == "medium") return kScoreMedium;
    if (lower == "low") return kScoreLow;
    return kScoreInfo;
}

bool SeverityGreater(const std::string& candidate, const std::string& current) {
    return SeverityScore(candidate) > SeverityScore(current);
}

/* Prefer the more specific entity names for the incident label; a pid says
 * little to an analyst a day later, an image or account says a lot. */
std::string BestLabel(const Event& event) {
    const std::string image = FieldValue(event, field::kImage);
    if (!image.empty()) return BaseName(image);
    const std::string actor = FieldValue(event, field::kActorImage);
    if (!actor.empty()) return BaseName(actor);
    return {};
}

std::string EndpointOf(const Event& event, const std::string& localEndpointId) {
    const std::string explicitEndpoint =
        FieldValue(event, field::kEndpointId);
    return LowerAscii(explicitEndpoint.empty() ? localEndpointId
                                               : explicitEndpoint);
}

bool IsBarePidIdentity(const std::string& identity) {
    const std::string lower = LowerAscii(identity);
    if (lower.rfind("pid:", 0) == 0) return true;
    if (lower.empty()) return false;
    for (unsigned char ch : lower) {
        if (ch < '0' || ch > '9') return false;
    }
    return true;
}

bool IsOpaqueProcessIdentity(const std::string& identity) {
    if (identity.empty() || IsBarePidIdentity(identity)) return false;
    const std::string lower = LowerAscii(identity);
    /* WMI uses this field for a client/PID event key, not a process instance. */
    return lower.rfind("wmi/", 0) != 0;
}

bool ParseDecimal(const std::string& text, size_t begin, size_t end,
                  uint64_t& value) {
    if (begin >= end) return false;
    value = 0;
    for (size_t i = begin; i < end; ++i) {
        const unsigned char ch = static_cast<unsigned char>(text[i]);
        if (ch < '0' || ch > '9') return false;
        const uint64_t digit = ch - '0';
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    return true;
}

bool ParsePidCreationIdentity(const std::string& identity, uint32_t& pid,
                              uint64_t& creationTime) {
    const size_t separator = identity.find('@');
    if (separator == std::string::npos ||
        identity.find('@', separator + 1) != std::string::npos) return false;
    uint64_t parsedPid = 0;
    if (!ParseDecimal(identity, 0, separator, parsedPid) || parsedPid == 0 ||
        parsedPid > std::numeric_limits<uint32_t>::max() ||
        !ParseDecimal(identity, separator + 1, identity.size(), creationTime) ||
        creationTime == 0) return false;
    pid = static_cast<uint32_t>(parsedPid);
    return true;
}

std::string OpaqueProcessKey(const std::string& endpoint,
                             const Event& event,
                             const std::string& identity) {
    std::string source = event.source;
    if (source.empty()) source = FieldValue(event, field::kSource);
    if (source.empty()) source = "unknown";
    return "proc:" + endpoint + "|source:" + LowerAscii(source) +
           "|opaque:" + LowerAscii(identity);
}

std::string ProcessIdentityKey(const std::string& endpoint, const Event& event,
                               const std::string& identity) {
    uint32_t pid = 0;
    uint64_t creationTime = 0;
    if (ParsePidCreationIdentity(identity, pid, creationTime)) {
        return "proc:" + endpoint + "|pid:" + std::to_string(pid) + "@" +
               std::to_string(creationTime);
    }
    if (IsOpaqueProcessIdentity(identity))
        return OpaqueProcessKey(endpoint, event, identity);
    return {};
}

std::string FirstNonEmpty(const Event& event,
                          std::initializer_list<const char*> names) {
    for (const char* name : names) {
        const std::string value = FieldValue(event, name);
        if (!value.empty()) return value;
    }
    return {};
}

} // namespace

CorrelationEngine::CorrelationEngine(bool enabled, uint32_t windowSeconds,
                                     size_t stateCapacity,
                                     uint32_t minAlertsToClose, RunIdFn runIdFn,
                                     std::string localEndpointId)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minAlertsToClose(minAlertsToClose) {
    if (!m_enabled) return;
    m_localEndpointId = localEndpointId.empty() ? LocalEndpointId()
                                                : LowerAscii(localEndpointId);
    if (m_localEndpointId.empty())
        throw std::runtime_error("local endpoint identity unavailable");
    m_runId = runIdFn ? runIdFn() : NewRunId();
    if (m_runId.size() != 32 || m_runId.find_first_not_of("0123456789abcdef") !=
                               std::string::npos) {
        throw std::runtime_error("invalid correlation run identifier");
    }
}

namespace {
/* Defined below; reopened here so EntitiesOf can emit the identity entity
 * alongside the strong pid@creation key (see the alias-entity contract in
 * TestProcessAliasesJoinPartialAndParentEvidence). */
std::string ProcessIdentityKey(const std::string& endpoint,
                               const Event& event,
                               const std::string& identity);
} // namespace

std::vector<std::string> CorrelationEngine::EntitiesOf(
    const Alert& alert, uint64_t now100ns) {
    std::vector<std::string> entities;
    const Event& event = *alert.event;
    const std::string endpoint = EndpointOf(event, m_localEndpointId);

    if (event.pid != 0 && event.processStartTime100ns != 0) {
        const std::string strong = "proc:" + endpoint + "|pid:" +
                                   std::to_string(event.pid) + "@" +
                                   std::to_string(event.processStartTime100ns);
        entities.push_back(strong);
        /* Providers that also carry an opaque/exact process identity emit a
         * second entity so partial evidence (no creation time yet) joins the
         * same incident no matter which shape arrives first. The alias is
         * learned on the first strong sighting; a second DISTINCT strong key
         * claiming the same identity is PID reuse or identity spoofing - the
         * alias is poisoned (fail closed: nothing derived from it joins
         * anything) and the shared entity key is unregistered. */
        if (!event.processIdentity.empty() && !m_opaqueAliasesDisabled) {
            const std::string aliasKey =
                ProcessIdentityKey(endpoint, event, event.processIdentity);
            if (!aliasKey.empty() && aliasKey != strong &&
                m_blockedEntities.count(aliasKey) == 0) {
                auto mapped = m_identityAlias.find(aliasKey);
                if (mapped == m_identityAlias.end()) {
                    EvictOldestAlias();
                    m_identityAlias.emplace(aliasKey, ProcessAlias{strong, now100ns});
                    entities.push_back(aliasKey);
                } else if (mapped->second.strongKey.empty()) {
                    /* poisoned by an earlier conflict: emit nothing */
                } else if (mapped->second.strongKey == strong) {
                    mapped->second.lastSeen100ns =
                        std::max(mapped->second.lastSeen100ns, now100ns);
                    entities.push_back(aliasKey);
                } else {
                    mapped->second.strongKey.clear();
                    m_blockedEntities.insert(aliasKey);
                    m_entities.erase(aliasKey);
                    if (m_blockedEntities.size() >= m_stateCapacity) {
                        m_opaqueAliasesDisabled = true;
                        std::fprintf(stderr,
                            "[edr-correlation] identity conflict capacity reached; "
                            "opaque process correlation disabled until restart\n");
                    }
                }
            }
        }
    } else {
        const std::string aliasKey =
            ProcessIdentityKey(endpoint, event, event.processIdentity);
        if (!aliasKey.empty() && m_blockedEntities.count(aliasKey) == 0 &&
            (!m_opaqueAliasesDisabled || aliasKey.find("|opaque:") == std::string::npos))
            entities.push_back(aliasKey);
    }
    const std::string parent =
        ProcessIdentityKey(endpoint, event, event.parentProcessIdentity);
    if (!parent.empty() && m_blockedEntities.count(parent) == 0 &&
        (!m_opaqueAliasesDisabled || parent.find("|opaque:") == std::string::npos))
        entities.push_back(parent);

    const std::string path = FirstNonEmpty(
        event, {field::kFilePath, field::kFimPath, field::kTargetPath,
                field::kRegKey});
    if (!path.empty() && path.size() <= 260)
        entities.push_back("path:" + endpoint + "|" + LowerAscii(path));

    return entities;
}

void CorrelationEngine::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_identityAlias.begin(); it != m_identityAlias.end();) {
        const uint64_t last = it->second.lastSeen100ns;
        if (now100ns >= last && now100ns - last > m_window100ns) {
            m_entities.erase(it->first);
            it = m_identityAlias.erase(it);
        } else {
            ++it;
        }
    }
    std::vector<std::string> expired;
    for (auto& entry : m_incidents) {
        const uint64_t last = entry.second.incident.lastSeen100ns;
        if (now100ns >= last && now100ns - last > m_window100ns)
            expired.push_back(entry.first);
    }
    for (const std::string& id : expired) {
        auto found = m_incidents.find(id);
        if (found != m_incidents.end() && m_callback &&
            found->second.incident.alertCount >= m_minAlertsToClose)
            Emit(found->second);
        Retire(id);
    }
}

void CorrelationEngine::FlushExpired(uint64_t now100ns) {
    m_latestTime100ns = std::max(m_latestTime100ns, now100ns);
    PurgeExpired(m_latestTime100ns);
}

void CorrelationEngine::EvictOldestAlias() {
    if (m_identityAlias.size() < m_stateCapacity) return;
    const auto oldest = std::min_element(m_identityAlias.begin(), m_identityAlias.end(),
        [](const auto& left, const auto& right) {
            if (left.second.lastSeen100ns != right.second.lastSeen100ns)
                return left.second.lastSeen100ns < right.second.lastSeen100ns;
            return left.first < right.first;
        });
    if (oldest != m_identityAlias.end()) {
        m_entities.erase(oldest->first);
        m_identityAlias.erase(oldest);
    }
}

void CorrelationEngine::Retire(const std::string& incidentId) {
    m_incidents.erase(incidentId);
    for (auto it = m_entities.begin(); it != m_entities.end();) {
        if (it->second.incidentId == incidentId)
            it = m_entities.erase(it);
        else
            ++it;
    }
}

void CorrelationEngine::ReindexEntities(const std::string& sourceId,
                                        const std::string& targetId) {
    for (auto& entry : m_entities) {
        if (entry.second.incidentId == sourceId)
            entry.second.incidentId = targetId;
    }
}

/* Fold `sourceId` into `targetId`, keeping tactics in first-sighting order
 * and coalescing a tactic that appears in both chains into one node. */
bool CorrelationEngine::MergeIncidents(const std::string& targetId,
                                       const std::string& sourceId) {
    if (targetId == sourceId) return true;
    auto targetIt = m_incidents.find(targetId);
    auto sourceIt = m_incidents.find(sourceId);
    if (targetIt == m_incidents.end() || sourceIt == m_incidents.end())
        return false;

    Incident& target = targetIt->second.incident;
    Incident& source = sourceIt->second.incident;

    /* Time envelope spans both chains. */
    if (source.firstSeen100ns != 0 &&
        (target.firstSeen100ns == 0 ||
         source.firstSeen100ns < target.firstSeen100ns))
        target.firstSeen100ns = source.firstSeen100ns;
    if (source.lastSeen100ns > target.lastSeen100ns)
        target.lastSeen100ns = source.lastSeen100ns;

    target.alertCount += source.alertCount;
    if (SeverityGreater(source.severity, target.severity))
        target.severity = source.severity;
    if (target.primaryImage.empty()) target.primaryImage = source.primaryImage;
    if (target.primaryUser.empty()) target.primaryUser = source.primaryUser;
    if (target.host.empty()) target.host = source.host;

    for (const std::string& rule : source.rules) {
        if (std::find(target.rules.begin(), target.rules.end(), rule) ==
            target.rules.end())
            target.rules.push_back(rule);
    }

    /* Append the source's stages, coalescing tactics it shares with the
     * target so each tactic stays a single graph node. */
    for (const IncidentStage& stage : source.stages) {
        auto found = targetIt->second.stageIndex.find(stage.tactic);
        if (found == targetIt->second.stageIndex.end()) {
            IncidentStage copy = stage;
            targetIt->second.stageIndex.emplace(copy.tactic,
                                                target.stages.size());
            target.tactics.push_back(copy.tactic);
            target.stages.push_back(std::move(copy));
        } else {
            IncidentStage& existing = target.stages[found->second];
            existing.alertCount += stage.alertCount;
            if (stage.firstSeen100ns != 0 &&
                (existing.firstSeen100ns == 0 ||
                 stage.firstSeen100ns < existing.firstSeen100ns))
                existing.firstSeen100ns = stage.firstSeen100ns;
            if (stage.lastSeen100ns > existing.lastSeen100ns)
                existing.lastSeen100ns = stage.lastSeen100ns;
            if (SeverityGreater(stage.severity, existing.severity))
                existing.severity = stage.severity;
        }
    }

    /* Recompute the roll-up: severity weight + tactic breadth bonus. */
    int score = SeverityScore(target.severity);
    const int breadth = std::min(
        kMaxTacticBonus,
        static_cast<int>(target.tactics.size() - 1) * kTacticBreadthStep);
    if (breadth > 0) score += breadth;
    target.score = std::min(100, score);

    ReindexEntities(sourceId, targetId);
    m_incidents.erase(sourceId);
    return true;
}

void CorrelationEngine::Emit(const IncidentState& state) {
    if (m_callback) m_callback(state.incident);
}

void CorrelationEngine::EvictOldest() {
    if (m_incidents.size() <= m_stateCapacity) return;
    auto oldest = std::min_element(m_incidents.begin(), m_incidents.end(),
        [](const auto& left, const auto& right) {
            return left.second.incident.lastSeen100ns <
                   right.second.incident.lastSeen100ns;
        });
    if (oldest != m_incidents.end()) Retire(oldest->first);
}

std::vector<Incident> CorrelationEngine::Snapshot(size_t limit) const {
    std::vector<Incident> result;
    result.reserve(std::min(limit, m_incidents.size()));
    for (const auto& entry : m_incidents)
        result.push_back(entry.second.incident);
    std::sort(result.begin(), result.end(),
        [](const Incident& left, const Incident& right) {
            if (left.lastSeen100ns != right.lastSeen100ns)
                return left.lastSeen100ns > right.lastSeen100ns;
            return left.id < right.id;
        });
    if (result.size() > limit) result.resize(limit);
    return result;
}

CorrelationAnnotation CorrelationEngine::Observe(const Alert& alert) {
    CorrelationAnnotation annotation;
    if (!m_enabled || alert.event == nullptr) return annotation;

    const Event& event = *alert.event;
    const uint64_t now = EventTime(event);
    m_latestTime100ns = std::max(m_latestTime100ns, now);
    PurgeExpired(m_latestTime100ns);
    /* Keep the original alert, but do not let evidence older than the
     * live window revive a retired alias or backdate a current incident. */
    if (m_latestTime100ns - now > m_window100ns) return annotation;

    const std::vector<std::string> entities = EntitiesOf(alert, now);

    /* Collect every live incident this alert touches, not just the first.
     * An alert that bridges two chains - a process from chain X opening a
     * file named by chain Y - must join them into one incident, otherwise
     * the kill chain fragments into pieces that each look less severe than
     * the intrusion actually is. */
    std::vector<std::string> matches;
    for (const std::string& entity : entities) {
        auto found = m_entities.find(entity);
        if (found == m_entities.end()) continue;
        const std::string& candidate = found->second.incidentId;
        if (m_incidents.count(candidate) == 0) continue;
        if (std::find(matches.begin(), matches.end(), candidate) ==
            matches.end())
            matches.push_back(candidate);
    }

    std::string incidentId;
    if (!matches.empty()) {
        /* Oldest chain absorbs the others: it usually holds the entry
         * stage, and keeping its id stable avoids churning the id an
         * analyst may already be tracking. */
        incidentId = matches.front();
        for (size_t i = 1; i < matches.size(); ++i) {
            const std::string& victim = matches[i];
            if (MergeIncidents(incidentId, victim) && m_callback)
                m_callback(m_incidents[incidentId].incident);
        }
    }

    bool created = false;
    if (incidentId.empty()) {
        incidentId = "inc-" + m_runId + "-" + std::to_string(++m_sequence);
        IncidentState state;
        state.incident.id = incidentId;
        state.incident.host = EndpointOf(event, m_localEndpointId);
        state.incident.primaryImage = BestLabel(event);
        state.incident.primaryUser = FirstNonEmpty(
            event, {field::kSubjectUserName, field::kTargetUser,
                    field::kAccountName, field::kRdpUser});
        state.incident.firstSeen100ns = now;
        m_incidents.emplace(incidentId, std::move(state));
        created = true;
    }

    IncidentState& state = m_incidents[incidentId];
    Incident& incident = state.incident;
    incident.firstSeen100ns = std::min(incident.firstSeen100ns, now);
    incident.lastSeen100ns = std::max(incident.lastSeen100ns, now);
    incident.alertCount += 1;
    if (!event.processIdentity.empty()) {
        incident.primaryImage = incident.primaryImage.empty()
                                    ? BestLabel(event)
                                    : incident.primaryImage;
    }
    if (SeverityGreater(alert.severity, incident.severity))
        incident.severity = alert.severity;
    if (std::find(incident.rules.begin(), incident.rules.end(),
                  alert.ruleId) == incident.rules.end())
        incident.rules.push_back(alert.ruleId);

    /* Fold the alert's tactics into the kill-chain stage list. A rule may
     * map to several tactics; each distinct one is its own graph node. */
    std::string firstTactic;
    for (const std::string& tactic : alert.mitreTactic) {
        if (tactic.empty()) continue;
        if (firstTactic.empty()) firstTactic = tactic;
        auto found = state.stageIndex.find(tactic);
        if (found == state.stageIndex.end()) {
            IncidentStage stage;
            stage.tactic = tactic;
            stage.ruleId = alert.ruleId;
            stage.severity = alert.severity;
            stage.firstSeen100ns = now;
            stage.lastSeen100ns = now;
            stage.alertCount = 1;
            state.stageIndex.emplace(tactic, incident.stages.size());
            incident.stages.push_back(std::move(stage));
            incident.tactics.push_back(tactic);
        } else {
            IncidentStage& stage = incident.stages[found->second];
            stage.firstSeen100ns = std::min(stage.firstSeen100ns, now);
            stage.lastSeen100ns = std::max(stage.lastSeen100ns, now);
            stage.alertCount += 1;
            if (SeverityGreater(alert.severity, stage.severity))
                stage.severity = alert.severity;
        }
    }

    int score = SeverityScore(incident.severity);
    const int breadth = std::min(
        kMaxTacticBonus,
        static_cast<int>(incident.tactics.size() - 1) * kTacticBreadthStep);
    if (breadth > 0) score += breadth;
    incident.score = std::min(100, score);

    /* Re-register every entity against the incident so future alerts with a
     * new pivot still join. */
    for (const std::string& entity : entities) {
        EntityIndex& index = m_entities[entity];
        index.incidentId = incidentId;
        index.lastSeen100ns = std::max(index.lastSeen100ns, now);
    }

    annotation.incidentId = incidentId;
    annotation.stage = firstTactic;
    annotation.score = incident.score;
    annotation.alertCount = incident.alertCount;
    annotation.stageCount = static_cast<uint32_t>(incident.stages.size());
    {
        std::string joined;
        for (const std::string& tactic : incident.tactics) {
            if (!joined.empty()) joined += ",";
            joined += tactic;
        }
        annotation.tactics = joined;
    }

    /* Announce a brand-new chain only after its first alert is fully folded,
     * so a sink sees a populated incident rather than an empty shell. */
    if (created && m_openedCallback) {
        m_openedCallback(incident);
    }

    EvictOldest();
    return annotation;
}

std::string IncidentToJson(const Incident& incident) {
    std::string line = "{\"id\":\"";
    line += jsonlite::escape(incident.id);
    line += "\",\"host\":\"";
    line += jsonlite::escape(incident.host);
    line += "\",\"image\":\"";
    line += jsonlite::escape(incident.primaryImage);
    line += "\",\"user\":\"";
    line += jsonlite::escape(incident.primaryUser);
    line += "\",\"severity\":\"";
    line += jsonlite::escape(incident.severity);
    line += "\",\"score\":";
    line += std::to_string(incident.score);
    line += ",\"alertCount\":";
    line += std::to_string(incident.alertCount);
    line += ",\"firstSeen100ns\":";
    line += std::to_string(incident.firstSeen100ns);
    line += ",\"lastSeen100ns\":";
    line += std::to_string(incident.lastSeen100ns);

    auto appendStringArray = [&](const char* key,
                                 const std::vector<std::string>& values) {
        line += ",\"";
        line += key;
        line += "\":[";
        bool first = true;
        for (const std::string& value : values) {
            if (!first) line += ",";
            first = false;
            line += "\"";
            line += jsonlite::escape(value);
            line += "\"";
        }
        line += "]";
    };
    appendStringArray("rules", incident.rules);
    appendStringArray("tactics", incident.tactics);

    line += ",\"stages\":[";
    for (size_t i = 0; i < incident.stages.size(); ++i) {
        const IncidentStage& stage = incident.stages[i];
        if (i != 0) line += ",";
        line += "{\"tactic\":\"";
        line += jsonlite::escape(stage.tactic);
        line += "\",\"rule\":\"";
        line += jsonlite::escape(stage.ruleId);
        line += "\",\"severity\":\"";
        line += jsonlite::escape(stage.severity);
        line += "\",\"alertCount\":";
        line += std::to_string(stage.alertCount);
        line += ",\"firstSeen100ns\":";
        line += std::to_string(stage.firstSeen100ns);
        line += ",\"lastSeen100ns\":";
        line += std::to_string(stage.lastSeen100ns);
        line += "}";
    }
    line += "]}";
    return line;
}

} // namespace edr
