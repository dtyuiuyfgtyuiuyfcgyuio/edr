/*
 * local_collect_detector.cpp - See local_collect_detector.h.
 */
#include "local_collect_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

/* Document extensions collected during local staging (TA0009). */
const std::vector<std::string>& DocExtensions() {
    static const std::vector<std::string> kExt = {
        ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".txt",
        ".ppt", ".pptx", ".csv", ".eml", ".msg"};
    return kExt;
}

/* User profile directories we treat as collection targets. */
const std::vector<std::string>& ProfileMarkers() {
    static const std::vector<std::string> kMarkers = {
        "\\desktop\\", "\\documents\\", "\\downloads\\",
        "\\onedrive\\", "\\appdata\\", "\\users\\"};
    return kMarkers;
}

/* Local staging directories used to hold collected material. */
const std::vector<std::string>& StagingMarkers() {
    static const std::vector<std::string> kMarkers = {
        "\\appdata\\local\\temp\\", "\\appdata\\roaming\\temp\\",
        "\\programdata\\", "\\public\\", "\\temp\\"};
    return kMarkers;
}

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

bool Contains(const std::string& value, const std::string& needle) {
    return value.find(needle) != std::string::npos;
}

/*
 * Find the earliest occurrence of any marker. Uses the safe
 * `(a != npos) ? a : b` combination pattern so a missing marker never
 * wins over a present one (the std::max(rfind(A), rfind(B)) trap).
 */
size_t FirstMarker(const std::string& lower,
                   const std::vector<std::string>& markers) {
    size_t best = std::string::npos;
    for (const std::string& marker : markers) {
        size_t p = lower.find(marker);
        if (p == std::string::npos) continue;
        best = (best == std::string::npos)
                   ? p
                   : (p < best ? p : best);
    }
    return best;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "malicious";
    if (score >= 55) return "suspicious";
    return "";
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

LocalCollectDetector::LocalCollectDetector(bool enabled, uint32_t minScore,
                                           uint32_t dedupWindowSeconds,
                                           size_t stateCapacity)
    : m_enabled(enabled),
      m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

/* static */
bool LocalCollectDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_READ ||
           type == EDR_EVT_PROCESS_START;
}

/* static */
bool LocalCollectDetector::IsDocumentExtension(const std::string& lowerBase) {
    size_t dot = lowerBase.find_last_of('.');
    if (dot == std::string::npos) return false;
    const std::string ext = lowerBase.substr(dot);
    for (const std::string& doc : DocExtensions()) {
        if (ext == doc) return true;
    }
    return false;
}

/* static */
bool LocalCollectDetector::IsProfilePath(const std::string& lower) {
    return FirstMarker(lower, ProfileMarkers()) != std::string::npos;
}

/* static */
bool LocalCollectDetector::IsStagingPath(const std::string& lower) {
    return FirstMarker(lower, StagingMarkers()) != std::string::npos;
}

/* static */
bool LocalCollectDetector::IsProfileEnumeration(const std::string& lowerImage,
                                               const std::string& lowerText) {
    if (!IsProfilePath(lowerText)) return false;
    /* cmd.exe /c dir /s ... over a profile dir */
    if (lowerImage == "cmd.exe" || lowerImage == "powershell.exe" ||
        lowerImage == "pwsh.exe") {
        if (Contains(lowerText, "dir") &&
            (Contains(lowerText, "/s") || Contains(lowerText, "-s") ||
             Contains(lowerText, "/r")))
            return true;
        if ((Contains(lowerText, "get-childitem") ||
             Contains(lowerText, "gci ") || Contains(lowerText, "ls ") ||
             Contains(lowerText, "get-item")) &&
            (Contains(lowerText, "-recurse") || Contains(lowerText, "-r") ||
             Contains(lowerText, "/s") || Contains(lowerText, " -s")))
            return true;
    }
    /* robocopy / xcopy recursive copy of a profile dir (enum + copy) */
    if (lowerImage == "robocopy.exe" || lowerImage == "xcopy.exe" ||
        lowerImage == "xcopy32.exe") {
        if (Contains(lowerText, "/e") || Contains(lowerText, "/s") ||
            Contains(lowerText, "-e") || Contains(lowerText, "-s"))
            return true;
    }
    return false;
}

/* static */
bool LocalCollectDetector::IsArchivePackaging(const std::string& lowerImage,
                                             const std::string& lowerText) {
    if (!IsProfilePath(lowerText)) return false;
    /* PowerShell Compress-Archive on a profile directory. */
    if (Contains(lowerText, "compress-archive") ||
        Contains(lowerText, "compressarchive"))
        return true;
    /* tar / 7z / zip creating an archive from a profile dir. */
    if (lowerImage == "tar.exe" || lowerImage == "7z.exe" ||
        lowerImage == "7za.exe" || lowerImage == "zip.exe" ||
        lowerImage == "winzip.exe" || lowerImage == "winrar.exe") {
        if (Contains(lowerText, " a ") || Contains(lowerText, "add") ||
            Contains(lowerText, "-cf") || Contains(lowerText, "--create") ||
            Contains(lowerText, " u ") || Contains(lowerText, " -a "))
            return true;
    }
    return false;
}

void LocalCollectDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > kEpisodeWindow100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t LocalCollectDetector::ComputeScore(const ProcState& state) const {
    uint32_t score = 0;
    if (state.sawEnumProfile) score += 30;
    if (state.sawArchiveProfile) score += 45;
    if (state.sawStageCopy) score += 30;
    if (state.sawStageLanding) score += 25;
    if (state.docReadCount >= 8) {
        /* Short-window bulk document read burst: 1 point per read,
         * capped at 100 so boundary tests can hit exact values. */
        score += std::min<uint32_t>(state.docReadCount, 100u);
    }
    return std::min<uint32_t>(score, 100u);
}

std::string LocalCollectDetector::SignalList(const ProcState& state) const {
    std::string signals;
    const std::pair<bool, const char*> kFlags[] = {
        {state.sawEnumProfile, "profile_enumeration"},
        {state.sawArchiveProfile, "archive_packaging"},
        {state.sawStageCopy, "staging_copy"},
        {state.sawStageLanding, "staging_landing"},
        {state.docReadCount >= 8, "document_burst"},
    };
    for (const auto& entry : kFlags) {
        if (!entry.first) continue;
        if (!signals.empty()) signals += ",";
        signals += entry.second;
    }
    if (state.docReadCount > 0) {
        if (!signals.empty()) signals += ",";
        signals += "doc_reads=" + std::to_string(state.docReadCount);
    }
    return signals;
}

std::string LocalCollectDetector::TechniqueList(const ProcState& state) const {
    std::string tech = "T1005";
    if (state.sawEnumProfile) tech += ",profile_enumeration";
    if (state.sawArchiveProfile) tech += ",archive_packaging";
    if (state.sawStageCopy) tech += ",staging_copy";
    if (state.sawStageLanding) tech += ",staging_landing";
    if (state.docReadCount >= 8) tech += ",document_burst";
    return tech;
}

void LocalCollectDetector::WriteState(Event& event, const ProcState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kLocalCollectScore] = std::to_string(score);
    event.fields[field::kLocalCollectSignals] = SignalList(state);
    event.fields[field::kLocalCollectTechniques] = TechniqueList(state);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kLocalCollectVerdict] = verdict;
    }
}

void LocalCollectDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const uint32_t pid = event.pid;
    if (pid == 0) return; /* need a process correlation key */

    ProcState& state = m_procs[pid];

    /* Time-backward protection: refuse to borrow "future" evidence.
     * Mirrors discovery_recon_detector's guard. */
    if (state.lastSeen100ns != 0 && now < state.lastSeen100ns) {
        return;
    }

    bool changed = false;

    if (event.type == EDR_EVT_PROCESS_START) {
        const std::string image = FieldValue(event, field::kImage);
        const std::string cmd = FieldValue(event, field::kCommandLine);
        const std::string psText = FieldValue(event, field::kScriptBlockText);
        /* PS script body lives only in kScriptBlockText, never in
         * kCommandLine / kImage. Order: cmd -> (PS host) script -> image. */
        std::string text;
        if (!cmd.empty()) text = cmd;
        else if (!psText.empty()) text = psText;
        else text = image;
        const std::string lowerText = LowerAscii(text);
        /* Process telemetry normally carries a full image path.  Classifiers
         * compare executable names, so normalize to the basename before
         * dispatching; this preserves support for basename-only fixtures. */
        const std::string lowerImage = BaseName(image);

        if (IsProfileEnumeration(lowerImage, lowerText)) {
            state.sawEnumProfile = true;
            changed = true;
        }
        if (IsArchivePackaging(lowerImage, lowerText)) {
            state.sawArchiveProfile = true;
            changed = true;
        }
    } else if (event.type == EDR_EVT_FILE_CREATE) {
        const std::string path = FieldValue(event, field::kFilePath);
        const std::string lower = LowerAscii(path);
        if (IsStagingPath(lower)) {
            const std::string base = BaseName(lower);
            const bool docExt = IsDocumentExtension(base);
            const bool matchesRead =
                state.readDocNames.find(base) != state.readDocNames.end();
            if (docExt || matchesRead) {
                state.sawStageCopy = true;
                changed = true;
                if (matchesRead) {
                    state.sawStageLanding = true;
                    changed = true;
                }
            }
        }
    } else if (event.type == EDR_EVT_FILE_READ) {
        const std::string path = FieldValue(event, field::kFilePath);
        const std::string base = BaseName(path);
        if (IsDocumentExtension(base)) {
            state.docReadCount++;
            state.readDocNames.insert(base);
            changed = true;
        }
    }

    if (!changed) return;
    state.lastSeen100ns = now;

    const uint32_t score = ComputeScore(state);
    const bool qualifies = score >= 55 && score >= m_minScore;
    if (qualifies) {
        const bool suppressed =
            m_dedupWindow100ns != 0 && state.lastStamp100ns != 0 &&
            now >= state.lastStamp100ns &&
            (now - state.lastStamp100ns) < m_dedupWindow100ns;
        if (!suppressed) {
            WriteState(event, state);
            state.lastStamp100ns = now;
        }
    }

    EvictOldest(m_procs, m_stateCapacity);
}

} // namespace edr
