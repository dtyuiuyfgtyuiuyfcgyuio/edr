/*
 * boot_provider_persist_detector.cpp - See
 * boot_provider_persist_detector.h (T1547.003 / T1547.012).
 */
#include "boot_provider_persist_detector.h"

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

/* Read-only inspection of the provider registrations. */
bool IsReadOnlyQuery(const std::string& lower) {
    const bool reads = Contains(lower, "reg query") ||
                       Contains(lower, "get-itemproperty") ||
                       Contains(lower, "get-childitem") ||
                       Contains(lower, "get-printerdriver") ||
                       Contains(lower, "get-printprocessor") ||
                       Contains(lower, "w32tm /query");
    if (!reads) return false;
    return !Contains(lower, "reg add") && !Contains(lower, "set-itemproperty") &&
           !Contains(lower, "new-item") && !Contains(lower, "add-printer");
}

/* The W32Time provider subkey. */
bool MentionsTimeProvider(const std::string& lower) {
    return Contains(lower, "w32time\\timeproviders") ||
           Contains(lower, "w32time/timeproviders") ||
           Contains(lower, "timeproviders\\");
}

/* The spooler print-processor subkey. */
bool MentionsPrintProcessor(const std::string& lower) {
    return Contains(lower, "print processors") ||
           Contains(lower, "printprocessors") ||
           Contains(lower, "print\\environments");
}

/* The value name that actually points at the payload DLL. */
bool MentionsProviderDllValue(const std::string& lower) {
    return Contains(lower, "dllname") || Contains(lower, "driver") ||
           Contains(lower, ".dll");
}

} // namespace

BootProviderPersistDetector::BootProviderPersistDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool BootProviderPersistDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool BootProviderPersistDetector::Analyze(const std::string& lower,
                                          Finding* out) const {
    if (IsReadOnlyQuery(lower)) return false;

    if (MentionsTimeProvider(lower) && MentionsProviderDllValue(lower)) {
        *out = Finding{90, "W32Time provider DLL registered"};
        return true;
    }

    if (MentionsPrintProcessor(lower) && MentionsProviderDllValue(lower)) {
        *out = Finding{90, "print processor DLL registered"};
        return true;
    }

    /* Object-model registration of a print processor / driver carrying a
     * DLL payload. */
    if ((Contains(lower, "addprintprocessor") ||
         Contains(lower, "add-printerdriver") ||
         Contains(lower, "addprinterdriverex")) &&
        Contains(lower, ".dll")) {
        *out = Finding{80, "print processor registered via API"};
        return true;
    }

    /* w32tm /register installs the service provider entry. */
    if (Contains(lower, "w32tm") && Contains(lower, "/register")) {
        *out = Finding{75, "w32tm provider registration"};
        return true;
    }

    /* A bare provider-subkey write with no DLL value still creates the
     * registration skeleton an attacker fills in next. */
    if (MentionsTimeProvider(lower) || MentionsPrintProcessor(lower)) {
        *out = Finding{70, "boot provider subkey created"};
        return true;
    }

    return false;
}

void BootProviderPersistDetector::Stamp(Event& event, const Finding& finding,
                                        const std::string& key) {
    event.fields[field::kBootProviderScore] = std::to_string(finding.score);
    event.fields[field::kBootProviderVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kBootProviderSignals] = finding.signal;
    event.fields[field::kBootProviderText] = key;
}

void BootProviderPersistDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        if (keyIt == event.fields.end()) return;
        text = keyIt->second;
        auto valIt = event.fields.find(field::kRegValue);
        if (valIt != event.fields.end()) {
            if (!text.empty()) text += " ";
            text += valIt->second;
        }
    } else {
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            auto scriptIt = event.fields.find(field::kScriptBlockText);
            if (scriptIt != event.fields.end()) text = scriptIt->second;
        }
    }
    if (text.empty()) return;

    const std::string lower = ToLowerAscii(text);
    Finding finding;
    if (!Analyze(lower, &finding)) return;
    if (finding.score < m_minScore) return;

    const std::string key = lower.substr(0, 160);
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
                "[edr-boot-provider] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
