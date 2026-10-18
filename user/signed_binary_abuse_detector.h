/*
 * signed_binary_abuse_detector.h - Signed binary proxy execution
 * detector (T1218.012 / T1218.013 / T1218.014 and peers).
 *
 * Scores command-plane abuse of Windows-signed binaries as proxies for
 * arbitrary code execution / DLL side-loading. Complements the chain
 * detectors (lolbin_chain / lolbin_parent_child), which correlate
 * parent-child shapes rather than scoring the single invocation:
 *   - mavinject.exe /INJECTRUNNING <pid> <dll>                  -> 90
 *   - register-cimprovider -path <dll>                          -> 85
 *   - infdefaultinstall.exe <inf> (DefaultInstall section)      -> 80
 *   - xwizard.exe RunWizard / {custom CLSID dll host}           -> 80
 *   - verclsid.exe /c /CLSID:{...}                              -> 70
 *   - syncappvpublishingserver.exe (scripted variant)           -> 65
 *
 * Benign administration (bare binary name with no payload argument)
 * stays silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_SIGNED_BINARY_ABUSE_DETECTOR_H
#define EDR_SIGNED_BINARY_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
// pi-lens-ignore: clang:pp_file_not_found
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class SignedBinaryAbuseDetector {
public:
    SignedBinaryAbuseDetector(bool enabled, uint32_t minScore,
                              uint32_t dedupWindowSeconds,
                              size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, const std::string& imageLower,
                 Finding* out) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_SIGNED_BINARY_ABUSE_DETECTOR_H */
