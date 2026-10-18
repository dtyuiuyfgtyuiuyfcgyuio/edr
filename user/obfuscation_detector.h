/*
 * obfuscation_detector.h - Obfuscated files or information (T1027).
 *
 * Scores PROCESS_START command lines and POWERSHELL_SCRIPT bodies for
 * generic obfuscation signals:
 *   - base64 long token (>=80 chars of [A-Za-z0-9+/=])         -> 80
 *   - -enc / -encodedcommand / FromBase64String                -> 90
 *   - caret / quote concatenation (e.g. p^o^w^e^r, ' + ', "+")  -> 85
 *   - env var substring %x:~n,m% and $env slice/substring      -> 80
 *   - high entropy token shannon > 4.5                          -> 75
 *   - special character ratio > 30%                             -> 60
 *
 * Also detects repeated [char] casts, repeated PowerShell backtick escapes,
 * and combinations of join/replace/ScriptBlock/reflection/reverse constructs.
 * Highest triggered signal determines the score. Statistical signals alone
 * are suspicious even at 75+; malicious requires structural evidence at 75+.
 * obfuscation_hard_signal distinguishes these heuristic evidence classes.
 * Below 55 no verdict is written. Hard does not mean confirmed compromise.
 * PS_SCRIPT bodies are taken from kScriptBlockText, never kCommandLine.
 *
 * Alerts are deduplicated per normalized text prefix inside the
 * dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_OBFUSCATION_DETECTOR_H
#define EDR_OBFUSCATION_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ObfuscationDetector {
public:
    ObfuscationDetector(bool enabled, uint32_t minScore,
                        uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        std::string signals;
        bool hardSignal = false;
    };

    bool Analyze(const std::string& text, const std::string& lower, Finding* out) const;

    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_OBFUSCATION_DETECTOR_H */
