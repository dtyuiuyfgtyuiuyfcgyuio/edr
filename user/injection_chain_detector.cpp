/*
 * injection_chain_detector.cpp - See injection_chain_detector.h.
 *
 * Scoring (cross-process pairs only; score only grows, cap 100):
 *   - PROCESS_ACCESS with a virtual-memory or thread-creation right
 *     (access_vm_operation/access_vm_write/access_create_thread) step ACCESS
 *     +20 (reason access)
 *   - MEMORY_WRITE or cross-process SECTION_MAP = WRITE +20 (write)
 *   - remote THREAD_CREATE, APC_INJECT, or cross-process CONTEXT_CHANGE
 *     = EXECUTE +35 (execute)
 *   - PROCESS_READ of lsass/winlogon/csrss = READ +20 (lsass_read)
 * A non-scoring cross-process event on an existing pair only refreshes its
 * age. NETWORK is intentionally not scored: NET_CONNECT events carry no
 * source/target pair and wiring a chain->outbound-connect match would need an
 * O(n) scan of every chain per network event.
 */
#include "injection_chain_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <limits>
#include <string>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

bool ParseUint32(const std::string& text, uint32_t& out) {
    if (text.empty() || text.size() > 10) return false;
    uint64_t value = 0;
    for (unsigned char c : text) {
        if (c < '0' || c > '9') return false;
        if (value > (std::numeric_limits<uint32_t>::max() -
                     static_cast<uint64_t>(c - '0')) / 10)
            return false;
        value = value * 10 + static_cast<uint64_t>(c - '0');
    }
    out = static_cast<uint32_t>(value);
    return true;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

std::string Join(const std::vector<std::string>& values,
                 const char* separator) {
    std::string result;
    for (const std::string& value : values) {
        if (!result.empty()) result += separator;
        result += value;
    }
    return result;
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

InjectionChainDetector::InjectionChainDetector(size_t stateCapacity,
                                               uint32_t windowSeconds,
                                               uint32_t minTransitionScore)
    : m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_minTransitionScore(minTransitionScore) {}

bool InjectionChainDetector::Inspects(uint16_t type) {
    switch (type) {
    case EDR_EVT_PROCESS_ACCESS:
    case EDR_EVT_MEMORY_WRITE:
    case EDR_EVT_SECTION_MAP:
    case EDR_EVT_THREAD_CREATE:
    case EDR_EVT_APC_INJECT:
    case EDR_EVT_CONTEXT_CHANGE:
    case EDR_EVT_PROCESS_READ:
    case EDR_EVT_HANDLE_DUPLICATE:
        return true;
    default:
        return false;
    }
}

const char* InjectionChainDetector::StageName(Stage stage) {
    switch (stage) {
    case Stage::ACCESS: return "ACCESS";
    case Stage::WRITE: return "WRITE";
    case Stage::EXECUTE: return "EXECUTE";
    case Stage::READ: return "READ";
    case Stage::NETWORK: return "NETWORK";
    default: return "NONE";
    }
}

void InjectionChainDetector::PurgeExpired(uint64_t now100ns) {
    /* Lazy sweep: at most once per window, same as the BehaviorEnricher. */
    if (m_lastPurge100ns != 0 &&
        now100ns >= m_lastPurge100ns &&
        now100ns - m_lastPurge100ns <= m_window100ns)
        return;
    m_lastPurge100ns = now100ns;
    for (auto it = m_chains.begin(); it != m_chains.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_chains.erase(it);
        else
            ++it;
    }
}

void InjectionChainDetector::RaiseStage(Chain& chain, Stage stage,
                                        int points, const char* reason) {
    if (chain.stage >= stage) return;
    chain.stage = stage;
    chain.score = std::min(100, chain.score + points);
    chain.reasons.push_back(reason);
}

void InjectionChainDetector::WriteState(Event& event, const Chain& chain) {
    if (chain.score < static_cast<int>(m_minTransitionScore)) return;
    event.fields[field::kInjectChainScore] = std::to_string(chain.score);
    event.fields[field::kInjectChainStage] = StageName(chain.stage);
    event.fields[field::kInjectChainReasons] = Join(chain.reasons, ",");
    if (!chain.targetImage.empty())
        event.fields[field::kInjectTargetImage] = chain.targetImage;
}

void InjectionChainDetector::Enrich(Event& event) {
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    uint32_t sourcePid = 0;
    uint32_t targetPid = 0;
    if (!ParseUint32(FieldValue(event, field::kSourcePid), sourcePid) ||
        !ParseUint32(FieldValue(event, field::kTargetPid), targetPid) ||
        sourcePid == 0 || targetPid == 0 || sourcePid == targetPid ||
        FieldValue(event, field::kCrossProcess) != "true") {
        return;
    }

    struct Step {
        Stage stage = Stage::NONE;
        int points = 0;
        const char* reason = nullptr;
    } step;

    switch (event.type) {
    case EDR_EVT_PROCESS_ACCESS:
        if (FieldValue(event, field::kAccessVmOperation) == "true" ||
            FieldValue(event, field::kAccessVmWrite) == "true" ||
            FieldValue(event, field::kAccessCreateThread) == "true") {
            step = {Stage::ACCESS, 20, "access"};
        }
        break;
    case EDR_EVT_MEMORY_WRITE:
    case EDR_EVT_SECTION_MAP:
        step = {Stage::WRITE, 20, "write"};
        break;
    case EDR_EVT_THREAD_CREATE:
        if (FieldValue(event, field::kRemoteThread) == "true")
            step = {Stage::EXECUTE, 35, "execute"};
        break;
    case EDR_EVT_APC_INJECT:
    case EDR_EVT_CONTEXT_CHANGE:
        step = {Stage::EXECUTE, 35, "execute"};
        break;
    case EDR_EVT_PROCESS_READ: {
        const std::string target =
            BaseName(FieldValue(event, field::kTargetImage));
        if (target == "lsass.exe" || target == "winlogon.exe" ||
            target == "csrss.exe")
            step = {Stage::READ, 20, "lsass_read"};
        break;
    }
    default:
        break;
    }

    const auto key = std::make_pair(sourcePid, targetPid);
    auto existing = m_chains.find(key);
    if (existing == m_chains.end()) {
        if (step.stage == Stage::NONE) return;
        Chain chain;
        chain.lastSeen100ns = now;
        chain.targetImage = FieldValue(event, field::kTargetImage);
        RaiseStage(chain, step.stage, step.points, step.reason);
        WriteState(event, chain);
        m_chains.emplace(key, std::move(chain));
        EvictOldest(m_chains, m_stateCapacity);
        return;
    }

    Chain& chain = existing->second;
    chain.lastSeen100ns = now;
    if (chain.targetImage.empty())
        chain.targetImage = FieldValue(event, field::kTargetImage);
    if (step.stage != Stage::NONE)
        RaiseStage(chain, step.stage, step.points, step.reason);
    WriteState(event, chain);
    EvictOldest(m_chains, m_stateCapacity);
}

} // namespace edr
