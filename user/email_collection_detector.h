/*
 * email_collection_detector.h - Email collection detector (MITRE T1114).
 *
 * Flags bulk mailbox exfiltration on the command/script faces:
 *   - ExMerge mailbox extraction                                -> 90
 *   - Exchange Search-Mailbox / New-ComplianceSearch with a
 *     -TargetMailbox export sink                                -> 85
 *   - .pst / .ost mail stores read/copied/archived by non-Outlook
 *     processes (copy/xcopy/robocopy/7z/zip/rar/certutil)         -> 80
 *   - Outlook COM automation bulk export (GetDefaultFolder +
 *     copy/move to disk)                                         -> 75
 *   - Outlook attachment stripping via script tooling            -> 70
 *
 * Plain Outlook.exe itself and read-only directory listings never
 * score. 55+ alerted; 75+ malicious.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_EMAIL_COLLECTION_DETECTOR_H
#define EDR_EMAIL_COLLECTION_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class EmailCollectionDetector {
public:
    EmailCollectionDetector(bool enabled, uint32_t minScore,
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

    static bool IsMailClientImage(const std::string& image);
    static bool HasMailStore(const std::string& lower);
    static bool HasExfilVerb(const std::string& lower);
    bool Analyze(const std::string& lower, const std::string& image,
                 Finding* out) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_EMAIL_COLLECTION_DETECTOR_H */
