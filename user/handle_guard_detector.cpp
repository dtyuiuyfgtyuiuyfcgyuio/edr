/*
 * handle_guard_detector.cpp - High-risk process/thread handle access detector.
 */
#include "handle_guard_detector.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <limits>

namespace edr {

namespace {

bool ParseUint32(const std::string& text, uint32_t* out) {
    if (text.empty() || out == nullptr) return false;
    uint64_t value = 0;
    for (unsigned char c : text) {
        if (c < '0' || c > '9') return false;
        value = value * 10 + static_cast<uint64_t>(c - '0');
        if (value > std::numeric_limits<uint32_t>::max()) return false;
    }
    *out = static_cast<uint32_t>(value);
    return true;
}

void AddSignal(std::string* signals, const char* signal) {
    if (!signals->empty()) signals->append(",");
    signals->append(signal);
}

} // namespace

HandleGuardDetector::HandleGuardDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool HandleGuardDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_HANDLE_OPEN;
}

bool HandleGuardDetector::Analyze(const std::string& objectType,
                                  uint32_t accessMask,
                                  Finding* out) const {
    if (out == nullptr) return false;
    uint32_t score = 0;
    std::string signals;

    if (objectType == "process") {
        const bool vmRead = (accessMask & 0x10u) != 0;
        const bool vmWrite = (accessMask & 0x20u) != 0;
        const bool vmOperation = (accessMask & 0x8u) != 0;
        const bool createThread = (accessMask & 0x2u) != 0;
        const bool duplicate = (accessMask & 0x40u) != 0;
        const bool terminate = (accessMask & 0x1u) != 0;

        if (vmRead && vmOperation) {
            score += 55;
            AddSignal(&signals, "process_vm_read_operation");
        }
        if (vmWrite && vmOperation) {
            score += 25;
            AddSignal(&signals, "process_vm_write_operation");
        } else if (vmWrite) {
            score += 15;
            AddSignal(&signals, "process_vm_write");
        }
        if (createThread) {
            score += 20;
            AddSignal(&signals, "process_create_thread");
        }
        if (duplicate) {
            score += 15;
            AddSignal(&signals, "process_duplicate_handle");
        }
        if (terminate) {
            score += 5;
            AddSignal(&signals, "process_terminate");
        }
        if (vmRead && vmWrite && vmOperation) {
            score += 10;
            AddSignal(&signals, "process_memory_write_chain");
        }
    } else if (objectType == "thread") {
        const bool suspendResume = (accessMask & 0x2u) != 0;
        const bool getContext = (accessMask & 0x8u) != 0;
        const bool setContext = (accessMask & 0x10u) != 0;
        const bool setInformation = (accessMask & 0x20u) != 0;
        const bool queryInformation = (accessMask & 0x40u) != 0;
        const bool terminate = (accessMask & 0x1u) != 0;

        if (getContext && setContext) {
            score += 60;
            AddSignal(&signals, "thread_context_read_write");
        } else if (getContext || setContext) {
            score += 30;
            AddSignal(&signals, getContext ? "thread_get_context"
                                           : "thread_set_context");
        }
        if (suspendResume) {
            score += 20;
            AddSignal(&signals, "thread_suspend_resume");
        }
        if (setInformation) {
            score += 15;
            AddSignal(&signals, "thread_set_information");
        }
        if (queryInformation) {
            score += 5;
            AddSignal(&signals, "thread_query_information");
        }
        if (terminate) {
            score += 10;
            AddSignal(&signals, "thread_terminate");
        }
        if ((getContext || setContext) && suspendResume) {
            score += 10;
            AddSignal(&signals, "thread_hijack_chain");
        }
    } else {
        return false;
    }

    if (score == 0) return false;
    out->score = std::min<uint32_t>(score, 100);
    out->signals = signals;
    return true;
}

void HandleGuardDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kHandleGuardScore] = std::to_string(finding.score);
    event.fields[field::kHandleGuardVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kHandleGuardSignals] = finding.signals;
}

void HandleGuardDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_HANDLE_OPEN) return;

    const auto objectIt = event.fields.find(field::kObjectType);
    const auto accessIt = event.fields.find(field::kAccessMask);
    if (objectIt == event.fields.end() || accessIt == event.fields.end()) return;

    uint32_t accessMask = 0;
    if (!ParseUint32(accessIt->second, &accessMask)) return;

    Finding finding;
    if (!Analyze(objectIt->second, accessMask, &finding) ||
        finding.score < m_minScore)
        return;

    const auto callerIt = event.fields.find(field::kPid);
    const auto targetIt = event.fields.find(field::kTargetPid);
    const std::string caller = callerIt == event.fields.end() ?
        std::to_string(event.pid) : callerIt->second;
    const std::string target = targetIt == event.fields.end() ? "" : targetIt->second;
    const std::string key = caller + "|" + target + "|" + objectIt->second +
                            "|" + accessIt->second;
    const uint64_t now = event.ts100ns;
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
                "[edr-handle-guard] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
