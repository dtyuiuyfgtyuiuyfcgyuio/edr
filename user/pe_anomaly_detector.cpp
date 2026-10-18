/*
 * pe_anomaly_detector.cpp - See pe_anomaly_detector.h.
 */
#include "pe_anomaly_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include "pe_anomaly_scan.h"

namespace edr {
namespace {

std::string ToLower(const std::string& t) {
    std::string o = t;
    std::transform(o.begin(), o.end(), o.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return o;
}

/* Normalize separators and lower-case so prefix comparisons are stable
 * across collector spellings (file_fallback emits backslash paths). */
std::string NormalizePathLower(const std::string& path) {
    std::string lower = ToLower(path);
    std::replace(lower.begin(), lower.end(), '/', '\\');
    while (lower.size() > 1 && lower.back() == '\\') lower.pop_back();
    return lower;
}

std::string BasenameLower(const std::string& lowerPath) {
    size_t slash = lowerPath.find_last_of("\\");
    return slash == std::string::npos ? lowerPath
                                      : lowerPath.substr(slash + 1);
}

bool HasPeExtension(const std::string& lowerBase) {
    static const char* kExtensions[] = {
        ".exe", ".dll", ".scr", ".ocx", ".cpl", ".sys",
    };
    for (const char* ext : kExtensions) {
        size_t len = std::strlen(ext);
        if (lowerBase.size() >= len &&
            lowerBase.compare(lowerBase.size() - len, len, ext) == 0)
            return true;
    }
    return false;
}

bool IsDiskFilePath(const std::string& lowerPath) {
    if (lowerPath.size() < 3 || lowerPath[1] != ':' || lowerPath[2] != '\\')
        return false;
    return true;
}

std::wstring Utf8ToWidePath(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     utf8.data(), static_cast<int>(utf8.size()),
                                     nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring wide(static_cast<size_t>(needed), L'\0');
    int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                      utf8.data(), static_cast<int>(utf8.size()),
                                      &wide[0], needed);
    if (written <= 0) return std::wstring();
    wide.resize(static_cast<size_t>(written));
    return wide;
}

uint64_t NowUnixSeconds() {
    FILETIME now;
    GetSystemTimePreciseAsFileTime(&now);
    uint64_t ticks = (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
                     now.dwLowDateTime;
    /* FILETIME epoch (1601-01-01) -> Unix epoch (1970-01-01). */
    return ticks >= 116444736000000000ULL
               ? (ticks - 116444736000000000ULL) / 10000000ULL
               : 0;
}

} // namespace

PeAnomalyDetector::PeAnomalyDetector(bool e, uint32_t min, uint32_t dedup,
                                     size_t cap, uint64_t maxFileBytes,
                                     std::vector<std::string> scanDirs)
    : m_enabled(e),
      m_minScore(min),
      m_dedupWindow100ns((uint64_t)dedup * kFiletimeTicksPerSecond),
      m_stateCapacity(cap),
      m_maxFileBytes(maxFileBytes == 0 ? 4ULL * 1024 * 1024 : maxFileBytes) {
    for (const std::string& dir : scanDirs)
        m_scanDirs.push_back(NormalizePathLower(dir));
}

bool PeAnomalyDetector::Inspects(uint16_t t) {
    return t == EDR_EVT_FILE_CREATE || t == EDR_EVT_FILE_RENAME ||
           t == EDR_EVT_FILE_INTEGRITY;
}

bool PeAnomalyDetector::ShouldScanPath(const std::string& lowerPath) const {
    if (!IsDiskFilePath(lowerPath)) return false;
    if (!HasPeExtension(BasenameLower(lowerPath))) return false;
    if (m_scanDirs.empty()) return true;
    for (const std::string& dir : m_scanDirs) {
        if (lowerPath.compare(0, dir.size(), dir) == 0 &&
            (lowerPath.size() == dir.size() ||
             lowerPath[dir.size()] == '\\'))
            return true;
    }
    return false;
}

bool PeAnomalyDetector::ReadFileBytes(const std::string& utf8Path,
                                      std::vector<uint8_t>* buffer) const {
    std::wstring wide = Utf8ToWidePath(utf8Path);
    if (wide.empty()) return false;
    HANDLE handle = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    bool ok = false;
    LARGE_INTEGER size;
    if (GetFileSizeEx(handle, &size) && size.QuadPart > 0 &&
        static_cast<uint64_t>(size.QuadPart) <= m_maxFileBytes) {
        buffer->resize(static_cast<size_t>(size.QuadPart));
        DWORD total = 0;
        ok = ReadFile(handle, buffer->data(),
                      static_cast<DWORD>(buffer->size()), &total,
                      nullptr) &&
             total == buffer->size();
    }
    CloseHandle(handle);
    return ok;
}

void PeAnomalyDetector::Stamp(Event& ev, const Finding& f,
                              const std::string& key) {
    ev.fields[field::kPeAnomalyScore] = std::to_string(f.score);
    ev.fields[field::kPeAnomalyVerdict] =
        f.score >= 75 ? "malicious" : "suspicious";
    ev.fields[field::kPeAnomalySignals] = f.signals;
    ev.fields[field::kPeAnomalySections] = f.sections;
    (void)key;
}

void PeAnomalyDetector::Enrich(Event& ev) {
    if (!m_enabled) return;
    auto it = ev.fields.find(field::kFilePath);
    if (it == ev.fields.end() || it->second.empty()) return;
    std::string lower = NormalizePathLower(it->second);
    if (!ShouldScanPath(lower)) return;
    std::vector<uint8_t> buffer;
    if (!ReadFileBytes(it->second, &buffer)) return;
    PeAnomalyFinding finding = ScanPeBuffer(buffer.data(), buffer.size(),
                                            NowUnixSeconds());
    if (!finding.valid || finding.score == 0) return;
    if (finding.score < m_minScore) return;
    std::string key = lower.substr(0, 160);
    uint64_t now = ev.ts100ns;
    auto dit = m_lastAlert.find(key);
    if (dit != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= dit->second &&
            now - dit->second < m_dedupWindow100ns)
            return;
        dit->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
            std::fprintf(stderr,
                         "[edr-pe-anomaly] state capacity %zu reached; "
                         "dedup reset\n",
                         m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }
    Finding stamped;
    stamped.score = finding.score;
    for (const std::string& signal : finding.signals) {
        if (!stamped.signals.empty()) stamped.signals += "; ";
        stamped.signals += signal;
    }
    stamped.sections = finding.anomalousSections;
    Stamp(ev, stamped, key);
}

} // namespace edr
