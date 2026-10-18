/*
 * lateral_transfer_detector.cpp - See lateral_transfer_detector.h.
 */
#include "lateral_transfer_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <string>
#include <vector>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string LowerAscii(const std::string& value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool IsAlphaNum(unsigned char c) { return std::isalnum(c) != 0; }

/* Token match with word boundaries, so "robocopy" does not match the "copy"
 * token and "copyright.txt" does not either. */
bool HasToken(const std::string& lower, const char* token) {
    const std::string needle(token);
    if (needle.empty()) return false;
    size_t pos = 0;
    while ((pos = lower.find(needle, pos)) != std::string::npos) {
        const bool leftOk =
            pos == 0 || !IsAlphaNum(static_cast<unsigned char>(lower[pos - 1]));
        const size_t end = pos + needle.size();
        const bool rightOk =
            end >= lower.size() ||
            !IsAlphaNum(static_cast<unsigned char>(lower[end]));
        if (leftOk && rightOk) return true;
        pos = end;
    }
    return false;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
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

std::string Join(const std::vector<std::string>& parts) {
    std::string joined;
    for (const std::string& part : parts) {
        if (part.empty()) continue;
        if (!joined.empty()) joined += ",";
        joined += part;
    }
    return joined;
}

} // namespace

/* ------------------------------------------------------------------ */
/* free helpers                                                        */
/* ------------------------------------------------------------------ */

UncLocation FindUncLocation(const std::string& lowerText) {
    UncLocation hit;
    for (size_t i = 0; i + 3 < lowerText.size(); ++i) {
        if (lowerText[i] != '\\' || lowerText[i + 1] != '\\') continue;
        const char after = lowerText[i + 2];
        /* Skip verbatim prefixes \\?\ and \\.\ (local device paths). */
        if (after == '?' || after == '.') continue;

        const size_t hostStart = i + 2;
        const size_t hostEnd = lowerText.find('\\', hostStart);
        if (hostEnd == std::string::npos) continue; /* \\host only: auth path */

        const size_t shareStart = hostEnd + 1;
        // Find the first path separator, but stop at token delimiters first.
        // Without this ordering, a later local argument such as C:\stage\
        // would be mistaken for the UNC share's path separator.
        size_t shareEnd = std::string::npos;
        size_t shareLimit = shareStart;
        while (shareLimit < lowerText.size() &&
               lowerText[shareLimit] != ' ' &&
               lowerText[shareLimit] != '\t' &&
               lowerText[shareLimit] != '"' &&
               lowerText[shareLimit] != '\'') {
            if (lowerText[shareLimit] == '\\') {
                shareEnd = shareLimit;
                break;
            }
            ++shareLimit;
        }
        const std::string host =
            lowerText.substr(hostStart, hostEnd - hostStart);
        const std::string share = lowerText.substr(
            shareStart, shareLimit - shareStart);
        if (host.empty() || share.empty()) continue;

        /* tail = the remote path component after the share, up to the first
         * whitespace or quote - used to tell an executable payload apart from
         * a generic remote file without tripping over the local image name
         * (e.g. "cmd.exe /c dir \\host\share"). */
        std::string tail;
        if (shareEnd != std::string::npos) {
            size_t end = shareEnd;
            while (end < lowerText.size() && lowerText[end] != ' ' &&
                   lowerText[end] != '\t' && lowerText[end] != '"' &&
                   lowerText[end] != '\'') {
                ++end;
            }
            tail = lowerText.substr(shareEnd, end - shareEnd);
        }

        hit.found = true;
        hit.host = host;
        hit.share = share;
        hit.tail = tail;
        hit.adminShare = !share.empty() && share.back() == '$';
        return hit;
    }
    return hit;
}

bool IsExecutableOrScript(const std::string& lower) {
    static const char* kExts[] = {
        ".exe", ".dll", ".sys", ".scr", ".msi", ".bat", ".cmd", ".ps1",
        ".vbs", ".vbe", ".js",  ".jse", ".wsf", ".hta", ".jar", ".py",
        ".pl",  ".lnk", ".com", ".cpl", ".pif", ".gadget",
    };
    for (const char* ext : kExts) {
        const std::string needle(ext);
        if (lower.size() >= needle.size() &&
            lower.compare(lower.size() - needle.size(), needle.size(),
                          needle) == 0) {
            return true;
        }
    }
    return false;
}

std::string ClassifyLateralTransfer(const std::string& image,
                                    const std::string& text) {
    const std::string lowerImage = LowerAscii(image);
    const std::string lowerText = LowerAscii(text);

    // BITS download/upload activity is handled by bits_abuse (T1105). Keep
    // those commands out of UNC reference scoring to avoid duplicate alerts.
    if (HasToken(lowerImage, "bitsadmin") ||
        HasToken(lowerText, "bitsadmin") ||
        HasToken(lowerText, "start-bitstransfer")) {
        return std::string();
    }

    /* 1. Direct remote execution: the process image itself is a UNC path
     *    pointing at an executable/script. */
    const UncLocation imageUnc = FindUncLocation(lowerImage);
    if (imageUnc.found && IsExecutableOrScript(lowerImage)) {
        return "remote_exec";
    }

    /* 2. PowerShell remoting file copy (needs no UNC literal). */
    const bool psItem = HasToken(lowerText, "copy-item") ||
                        HasToken(lowerText, "move-item") ||
                        HasToken(lowerText, "get-content");
    if (psItem && Contains(lowerText, "-fromsession")) {
        return "ps_session_pull";
    }

    const UncLocation unc = FindUncLocation(lowerText);
    if (!unc.found) return std::string();
    // IPC$ references establish an authenticated SMB session; they do not
    // transfer a tool and are owned by the lateral-movement detector.
    if (unc.share == "ipc$") return std::string();

    /* Whether the remote path component itself names an executable/script.
     * Computed from the UNC tail only, so a local image token such as
     * "cmd.exe" in the same command line cannot fake a payload reference. */
    const bool execRef = IsExecutableOrScript(unc.tail);

    /* 3. esentutl against a UNC target (classic tool-copy trick). */
    if (HasToken(lowerText, "esentutl")) return "esentutl_unc";

    /* 4. Transfer verbs (cmd family + PowerShell Item cmdlets). */
    const bool verb = HasToken(lowerText, "copy") ||
                      HasToken(lowerText, "xcopy") ||
                      HasToken(lowerText, "robocopy") ||
                      HasToken(lowerText, "move") ||
                      HasToken(lowerText, "expand") || psItem;
    if (verb) {
        if (unc.adminShare) return "admin_share_transfer";
        // Robocopy commonly transfers an entire tool directory, so the
        // executable payload may be represented by the source tree rather
        // than a filename extension in the UNC token.
        const bool directoryTool = HasToken(lowerImage, "robocopy");
        return (execRef || directoryTool) ? "share_transfer_exec"
                                          : "share_transfer";
    }

    /* 5. Reference only (no transfer verb): graded by share sensitivity and
     *    payload extension so the 54/55 and 74/75 house boundaries are both
     *    reachable and honestly testable. */
    if (unc.adminShare && execRef) return "admin_share_reference";
    return execRef ? "share_reference_exec" : "share_reference";
}

uint32_t LateralTransferBaseScore(const std::string& kind) {
    if (kind == "remote_exec") return 90u;
    if (kind == "admin_share_transfer") return 90u;
    if (kind == "esentutl_unc") return 90u;
    if (kind == "ps_session_pull") return 90u;
    if (kind == "share_transfer_exec") return 85u;
    if (kind == "share_transfer") return 75u;
    if (kind == "admin_share_reference") return 74u;
    if (kind == "share_reference_exec") return 55u;
    if (kind == "share_reference") return 54u;
    return 0u;
}

/* ------------------------------------------------------------------ */
/* detector                                                            */
/* ------------------------------------------------------------------ */

LateralTransferDetector::LateralTransferDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled),
      m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

/* static */
bool LateralTransferDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START || type == EDR_EVT_FILE_CREATE;
}

void LateralTransferDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_hosts.begin(); it != m_hosts.end();) {
        HostState& state = it->second;
        for (auto host = state.remoteHosts.begin();
             host != state.remoteHosts.end();) {
            if (now100ns >= host->second &&
                now100ns - host->second > kEpisodeWindow100ns) {
                host = state.remoteHosts.erase(host);
            } else {
                ++host;
            }
        }
        if (now100ns >= state.lastSeen100ns &&
            now100ns - state.lastSeen100ns > kEpisodeWindow100ns) {
            it = m_hosts.erase(it);
        } else {
            ++it;
        }
    }
}

bool LateralTransferDetector::Analyze(const Event& event,
                                     Finding* finding) const {
    if (event.type == EDR_EVT_FILE_CREATE) {
        const std::string path = FieldValue(event, field::kFilePath);
        const std::string lower = LowerAscii(path);
        const UncLocation unc = FindUncLocation(lower);
        if (!unc.found || !IsExecutableOrScript(lower)) return false;
        /* A tool written out to a remote admin share is a push; a normal
         * share is the weaker but still high-confidence variant. */
        finding->kind =
            unc.adminShare ? "admin_share_transfer" : "share_transfer_exec";
        finding->score = LateralTransferBaseScore(finding->kind);
        finding->remoteHost = unc.host;
        finding->signals.push_back("remote_tool_push");
        finding->signals.push_back(unc.adminShare ? "admin_share"
                                                  : "plain_share");
        finding->signals.push_back("remote_host=" + unc.host);
        finding->techniques.push_back("T1570");
        finding->techniques.push_back("remote_tool_push");
        return true;
    }

    if (event.type != EDR_EVT_PROCESS_START) return false;

    const std::string image = FieldValue(event, field::kImage);
    const std::string command = FieldValue(event, field::kCommandLine);
    const std::string scriptText = FieldValue(event, field::kScriptBlockText);

    /* POWERSHELL_SCRIPT bodies live only in kScriptBlockText, never in
     * kCommandLine / kImage. Order: command line -> PS body -> image. */
    std::string text;
    if (!command.empty()) text = command;
    else if (!scriptText.empty()) text = scriptText;
    else text = image;

    const std::string kind = ClassifyLateralTransfer(image, text);
    if (kind.empty()) return false;

    finding->kind = kind;
    finding->score = LateralTransferBaseScore(kind);
    finding->techniques.push_back("T1570");
    finding->techniques.push_back(kind);
    finding->signals.push_back(kind);

    UncLocation unc = FindUncLocation(LowerAscii(text));
    if (!unc.found) unc = FindUncLocation(LowerAscii(image));
    if (unc.found) {
        finding->remoteHost = unc.host;
        finding->signals.push_back(unc.adminShare ? "admin_share"
                                                  : "plain_share");
        finding->signals.push_back("remote_host=" + unc.host);
    }
    return true;
}

void LateralTransferDetector::WriteState(Event& event, const Finding& finding,
                                         const HostState& state) {
    (void)state;
    event.fields[field::kLateralTransferScore] =
        std::to_string(finding.score);
    event.fields[field::kLateralTransferSignals] = Join(finding.signals);
    event.fields[field::kLateralTransferTechniques] = Join(finding.techniques);
    event.fields[field::kLateralTransferVerdict] =
        finding.score >= 75u ? "malicious" : "suspicious";
}

void LateralTransferDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    Finding finding;
    if (!Analyze(event, &finding) || finding.score == 0) return;

    HostState& state = m_hosts["local"];

    /* Time-backward protection: never borrow "future" evidence. */
    if (state.lastSeen100ns != 0 && now < state.lastSeen100ns) return;
    state.lastSeen100ns = now;

    if (!finding.remoteHost.empty()) {
        state.remoteHosts[finding.remoteHost] = now;
    }

    /* Breadth: touching several distinct remote hosts in the same episode
     * window is materially stronger than a single one-off copy. */
    if (state.remoteHosts.size() >= 2) {
        finding.score =
            std::min<uint32_t>(100u, finding.score + kBreadthBonus);
        finding.signals.push_back("multi_host_breadth");
    }

    if (finding.score < 55u || finding.score < m_minScore) {
        EvictOldest(m_hosts, m_stateCapacity);
        return;
    }

    const std::string dedupKey = finding.kind + "|" + finding.remoteHost;
    auto last = m_lastAlert.find(dedupKey);
    if (m_dedupWindow100ns != 0 && last != m_lastAlert.end() &&
        now >= last->second &&
        now - last->second < m_dedupWindow100ns) {
        EvictOldest(m_hosts, m_stateCapacity);
        return;
    }
    m_lastAlert[dedupKey] = now;

    WriteState(event, finding, state);
    EvictOldest(m_hosts, m_stateCapacity);
}

} // namespace edr
