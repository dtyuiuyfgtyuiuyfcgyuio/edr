/*
 * archive_staging_detector.cpp - See archive_staging_detector.h.
 */
#include "archive_staging_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

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

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
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

ArchiveStagingDetector::ArchiveStagingDetector(bool enabled,
                                               uint32_t windowSeconds,
                                               size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool ArchiveStagingDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_READ ||
           type == EDR_EVT_FILE_RENAME;
}

bool ArchiveStagingDetector::IsArchiveTool(const std::string& image) {
    static const std::vector<std::string> kTools = {
        "7z.exe", "7za.exe", "7zr.exe", "winrar.exe", "rar.exe",
        "unrar.exe", "tar.exe", "gzip.exe", "gunzip.exe", "zip.exe",
        "unzip.exe", "expand.exe", "expand-archive.exe", "powershell.exe"
    };
    const std::string base = BaseName(image);
    for (const std::string& tool : kTools) {
        if (base == tool) return true;
    }
    return false;
}

bool ArchiveStagingDetector::IsArchiveExtension(const std::string& path) {
    const std::string base = BaseName(path);
    const size_t dot = base.find_last_of('.');
    if (dot == std::string::npos) return false;
    const std::string ext = base.substr(dot + 1);
    return ext == "zip" || ext == "rar" || ext == "7z" || ext == "tar" ||
           ext == "gz" || ext == "gzip" || ext == "tgz" || ext == "cab" ||
           ext == "iso" || ext == "jar" || ext == "xz" || ext == "bz2";
}

bool ArchiveStagingDetector::IsArchiveFile(const std::string& path) {
    const std::string lower = LowerAscii(path);
    if (IsArchiveExtension(lower)) return true;
    return lower.find("\\downloads\\") != std::string::npos &&
           (lower.find(".zip") != std::string::npos ||
            lower.find(".rar") != std::string::npos ||
            lower.find(".7z") != std::string::npos ||
            lower.find(".iso") != std::string::npos ||
            lower.find(".cab") != std::string::npos);
}

bool ArchiveStagingDetector::IsExtractionTool(const std::string& image) {
    const std::string base = BaseName(image);
    return base == "7z.exe" || base == "7za.exe" || base == "7zr.exe" ||
           base == "winrar.exe" || base == "rar.exe" || base == "unrar.exe" ||
           base == "tar.exe" || base == "gzip.exe" || base == "gunzip.exe" ||
           base == "zip.exe" || base == "unzip.exe" || base == "expand.exe" ||
           base == "powershell.exe" || base == "pwsh.exe";
}

bool ArchiveStagingDetector::IsTempOrDownloadPath(const std::string& path) {
    const std::string lower = LowerAscii(path);
    return lower.find("\\temp\\") != std::string::npos ||
           lower.find("\\appdata\\local\\temp\\") != std::string::npos ||
           lower.find("\\appdata\\roaming\\temp\\") != std::string::npos ||
           lower.find("\\downloads\\") != std::string::npos ||
           lower.find("\\desktop\\") != std::string::npos ||
           lower.find("\\public\\") != std::string::npos ||
           lower.find("\\programdata\\") != std::string::npos;
}

bool ArchiveStagingDetector::IsSuspiciousExtractLocation(const std::string& path) {
    const std::string lower = LowerAscii(path);
    if (IsTempOrDownloadPath(lower)) return true;
    if (lower.find("\\users\\") != std::string::npos &&
        (lower.find("\\appdata\\") != std::string::npos ||
         lower.find("\\desktop\\") != std::string::npos ||
         lower.find("\\downloads\\") != std::string::npos)) {
        return true;
    }
    return false;
}

void ArchiveStagingDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t ArchiveStagingDetector::ComputeScore(const ProcState& state) const {
    uint32_t score = 0;
    if (state.sawArchiveTool) score += 25;
    if (state.sawArchiveCreate) score += 20;
    if (state.sawArchiveRead) score += 15;
    if (state.sawExtraction) score += 25;
    if (state.sawTempExtract) score += 20;
    if (state.extractedFileCount >= 3) score += 10;
    if (state.rapidCreateCount >= 3) score += 10;
    return std::min(100u, score);
}

std::string ArchiveStagingDetector::SignalList(const ProcState& state) const {
    std::string signals;
    const std::pair<bool, const char*> kFlags[] = {
        {state.sawArchiveTool, "archive_tool"},
        {state.sawArchiveCreate, "archive_create"},
        {state.sawArchiveRead, "archive_read"},
        {state.sawExtraction, "extraction"},
        {state.sawTempExtract, "temp_extract"},
    };
    for (const auto& entry : kFlags) {
        if (!entry.first) continue;
        if (!signals.empty()) signals += ",";
        signals += entry.second;
    }
    if (state.extractedFileCount > 0) {
        if (!signals.empty()) signals += ",";
        signals += "extracted_files";
    }
    if (state.rapidCreateCount > 0) {
        if (!signals.empty()) signals += ",";
        signals += "rapid_creates";
    }
    return signals;
}

std::string ArchiveStagingDetector::ToolList(const ProcState& state) const {
    std::string list;
    for (const auto& tool : state.archiveTools) {
        if (!list.empty()) list += ",";
        list += tool;
    }
    return list;
}

std::string ArchiveStagingDetector::ArchiveList(const ProcState& state) const {
    std::string list;
    for (const auto& archive : state.archivePaths) {
        if (!list.empty()) list += ",";
        list += archive;
    }
    return list;
}

void ArchiveStagingDetector::WriteState(Event& event, const ProcState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kArchiveStagingScore] = std::to_string(score);
    event.fields[field::kArchiveStagingSignals] = SignalList(state);
    event.fields[field::kArchiveStagingTools] = ToolList(state);
    event.fields[field::kArchiveStagingArchives] = ArchiveList(state);
    event.fields[field::kArchiveStagingWindowSeconds] =
        std::to_string(m_windowSeconds);
    if (state.extractedFileCount > 0) {
        event.fields[field::kArchiveStagingExtractedCount] =
            std::to_string(state.extractedFileCount);
    }
    if (state.rapidCreateCount > 0) {
        event.fields[field::kArchiveStagingRapidCount] =
            std::to_string(state.rapidCreateCount);
    }
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kArchiveStagingVerdict] = verdict;
    }
}

void ArchiveStagingDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const uint32_t pid = event.pid;
    if (pid == 0) return;

    ProcState& state = m_procs[pid];
    bool changed = false;

    if (event.type == EDR_EVT_PROCESS_START) {
        const std::string image = FieldValue(event, field::kImage);
        const std::string command = FieldValue(event, field::kCommandLine);
        const std::string base = BaseName(image);
        if (IsArchiveTool(image) || IsExtractionTool(image)) {
            state.sawArchiveTool = true;
            state.archiveTools.insert(base);
            changed = true;
        }
        if (IsArchiveTool(image) &&
            (command.find(" x ") != std::string::npos ||
             command.find(" e ") != std::string::npos ||
             command.find(" extract") != std::string::npos ||
             command.find("unzip") != std::string::npos ||
             command.find("expand-archive") != std::string::npos)) {
            state.sawExtraction = true;
            changed = true;
        }
        if (command.find("-o") != std::string::npos ||
            command.find(" /o") != std::string::npos ||
            command.find(" -x") != std::string::npos) {
            state.sawExtraction = true;
            changed = true;
        }
    } else if (event.type == EDR_EVT_FILE_CREATE ||
               event.type == EDR_EVT_FILE_READ ||
               event.type == EDR_EVT_FILE_RENAME) {
        const std::string path =
            event.type == EDR_EVT_FILE_RENAME
                ? FieldValue(event, field::kOldFilePath)
                : FieldValue(event, field::kFilePath);
        const std::string image = FieldValue(event, field::kImage);
        const std::string action = FieldValue(event, field::kFileAction);

        if (IsArchiveFile(path)) {
            state.sawArchiveRead = event.type == EDR_EVT_FILE_READ;
            state.sawArchiveCreate = event.type == EDR_EVT_FILE_CREATE ||
                                     event.type == EDR_EVT_FILE_RENAME;
            state.archivePaths.insert(path);
            changed = true;
        }

        if (!path.empty() && IsSuspiciousExtractLocation(path) &&
            (action == "added" || action == "created" ||
             action == "modified" || action.empty())) {
            state.sawTempExtract = true;
            state.extractedPaths.insert(path);
            ++state.extractedFileCount;
            if (state.extractedFileCount >= 2) {
                state.rapidCreateCount = state.extractedFileCount;
            }
            changed = true;
        }

        if (IsExtractionTool(image) && IsSuspiciousExtractLocation(path)) {
            state.sawExtraction = true;
            changed = true;
        }
    }

    if (!changed) return;
    state.lastSeen100ns = now;
    WriteState(event, state);
    EvictOldest(m_procs, m_stateCapacity);
}

} // namespace edr
