/*
 * private_key_detector.h - Private key theft detector
 * (T1552.004 Unsecured Credentials: Private Keys).
 *
 * Two faces:
 *
 *   File face (FILE_READ / FILE_CREATE, path in field::kFilePath):
 *     - non-whitelisted process reading key material
 *       (id_rsa/id_dsa/id_ecdsa/id_ed25519, *.ppk, *.pfx, *.p12,
 *        *.pem/*.key under .ssh/.gnupg/.aws, .aws\credentials)  -> 75
 *     - key material written/copied into a transient or shared
 *       location (\temp\, \public\, UNC, ...)                   -> 85
 *     - key material written elsewhere (staging)                -> 60
 *     Legitimate key consumers (ssh/sshd/ssh-keygen/git/putty/
 *     pageant) are exempt.
 *
 *   Command face (PROCESS_START command line / POWERSHELL_SCRIPT
 *   body in field::kScriptBlockText):
 *     - mimikatz crypto:: module                                -> 90
 *     - certutil -exportPFX                                     -> 90
 *     - Export-PfxCertificate                                   -> 80
 *     - read/copy verb (type/findstr/copy/Copy-Item/...) aimed
 *       at a key-material token                                 -> 70
 *     - bare key-material token mention                         -> 55
 *
 * Complements CredentialFileHuntDetector (T1552.001): that one hunts
 * recursive "password/secret content" searches; this one specializes in
 * private-key file types and certificate/key *export* actions.
 *
 * The detector is a single-event scorer with bounded dedup keyed on
 * "process_basename\x1Ftarget_token".
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PRIVATE_KEY_DETECTOR_H
#define EDR_PRIVATE_KEY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PrivateKeyDetector {
public:
    PrivateKeyDetector(bool enabled, uint32_t minScore,
                       uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool AnalyzeFile(const Event& event, std::string* target,
                     Finding* out) const;
    bool AnalyzeCommand(const std::string& lower, std::string* target,
                        Finding* out) const;
    void Stamp(Event& event, const Finding& finding) const;

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_PRIVATE_KEY_DETECTOR_H */
