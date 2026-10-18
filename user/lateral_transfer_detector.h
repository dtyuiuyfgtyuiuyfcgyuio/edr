/*
 * lateral_transfer_detector.h - Lateral Tool Transfer (MITRE T1570).
 *
 * COVERS (in scope - Lateral Movement, TA0001/T1570):
 *   - Pulling a tool/payload from a remote SMB/UNC source:
 *       copy / xcopy / robocopy / move / esentutl /y  with a
 *       \\host\c$ | \\host\admin$  (admin share) source
 *     or from a plain share \\host\share\...
 *   - Executing a remote payload directly: the process image itself is a
 *     UNC path ending in an executable/script extension
 *     (\\host\share\tool.exe).
 *   - PowerShell remote transfer: Copy-Item / Move-Item / Get-Content with a
 *     UNC source, and the PS Remoting file-copy form `-FromSession`.
 *   - Writing an executable/script tool into a UNC admin share so another
 *     host can pull it (FILE_CREATE whose path is a UNC path).
 *
 * DOES NOT COVER (owned by other detectors - do NOT duplicate):
 *   - BITS transfers (bitsadmin / Start-BitsTransfer) -> bits_abuse (T1105)
 *   - SMB / RDP / WinRM *authenticated* lateral movement
 *     -> lateral_movement (T1021) / winrm_abuse
 *   - Tunnelling through the transfer                       -> tunnel_tool
 *   - Named-pipe IPC                                        -> named_pipe_abuse
 *   - Account / domain / share discovery                    -> discovery_recon
 *
 * SCORING (house rule): >= 75 -> "malicious"; 55..74 -> "suspicious";
 *   < 55 (or < cfg.minScore) -> write NOTHING at all (fully silent).
 *
 *   The ladder deliberately spans the 54/55 and 74/75 house boundaries so the
 *   threshold behaviour is directly testable.
 *
 *   kind                     when                                    score
 *   -----------------------  --------------------------------------  -----
 *   remote_exec              image is \\host\...\*.exe|*.ps1|...     90
 *   admin_share_transfer     transfer verb + \\host\<c$|admin$>         90
 *   esentutl_unc             esentutl against any UNC path           90
 *   ps_session_pull          PowerShell Item/Get-Content -FromSession 90
 *   share_transfer_exec      verb + plain share + exec/script file   85
 *   share_transfer           verb + plain share, generic file        75
 *   admin_share_reference    no verb + admin share + exec/script     74
 *   share_reference_exec     no verb + plain share + exec/script     55
 *   share_reference          no verb + plain share, generic file     54
 *
 *   breadth: +10 when >= 2 distinct remote hosts appear in the same episode
 *   window (capped at 100).
 *
 * EPISODE WINDOW: per-host correlation state (tracking which remote hosts were
 *   contacted) expires on a hardcoded 900 s episode window. This is
 *   deliberately SEPARATE from the dedup window: dedup only suppresses
 *   re-stamping of an already-alerted host and must never drive state expiry
 *   (see the local_collect batch lesson).
 *
 * Thread-safety: no internal locking; only the single EventBus consumer thread
 * calls Enrich (see main.cpp).
 */
#ifndef EDR_LATERAL_TRANSFER_DETECTOR_H
#define EDR_LATERAL_TRANSFER_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

/* --- free helpers, exposed for unit testing (house style: the classifier of
 *     a detector is directly testable, cf. ClassifyDiscoveryTechnique) --- */

struct UncLocation {
    bool found = false;
    std::string host;   // lower-cased host component
    std::string share;  // lower-cased share component
    std::string tail;   // path component after the share (up to whitespace)
    bool adminShare = false;  // share name ends with '$' (c$ / admin$ / ipc$)
};

/* Finds the first plausible \\host\share UNC reference in a lower-cased text.
 * Skips \\?\ and \\.\ verbatim-prefixes and bare \\host (no share) forms,
 * because the latter is an authentication path owned by lateral_movement. */
UncLocation FindUncLocation(const std::string& lowerText);

/* True when the string ends in an executable / script extension that is
 * meaningful for tool transfer (.exe .dll .sys .scr .msi .bat .cmd .ps1 .vbs
 * .js .jse .hta .jar .py .lnk). */
bool IsExecutableOrScript(const std::string& lower);

/* Classifies a (image, text) pair into one of the lateral-transfer kinds
 * listed in the header comment, or "" when nothing matches. */
std::string ClassifyLateralTransfer(const std::string& image,
                                    const std::string& text);

/* Base score for a kind returned by ClassifyLateralTransfer ("", 0). */
uint32_t LateralTransferBaseScore(const std::string& kind);

class LateralTransferDetector {
public:
    LateralTransferDetector(bool enabled, uint32_t minScore,
                            uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_hosts.size(); }

private:
    struct HostState {
        uint64_t lastSeen100ns = 0;
        std::map<std::string, uint64_t> remoteHosts;  // remote host -> lastSeen
        uint64_t lastStamp100ns = 0;
    };

    struct Finding {
        uint32_t score = 0;
        std::string kind;
        std::vector<std::string> signals;
        std::vector<std::string> techniques;
        std::string remoteHost;
    };

    void PurgeExpired(uint64_t now100ns);
    bool Analyze(const Event& event, Finding* finding) const;
    void WriteState(Event& event, const Finding& finding,
                    const HostState& state);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_map<std::string, HostState> m_hosts;  // key: "local"
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
    /* Correlation episode window - hardcoded, never the dedup window. */
    static constexpr uint64_t kEpisodeWindow100ns = 900ULL * kFiletimeTicksPerSecond;
    static constexpr uint32_t kBreadthBonus = 10u;
};

} // namespace edr

#endif /* EDR_LATERAL_TRANSFER_DETECTOR_H */
