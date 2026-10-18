/*
 * accessibility_hijack_detector.cpp - See accessibility_hijack_detector.h.
 */
#include "accessibility_hijack_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {
namespace {

constexpr const char* kProtectedImages[] = {
    "sethc.exe", "utilman.exe", "osk.exe", "narrator.exe",
    "magnify.exe", "displayswitch.exe", "atbroker.exe"
};

std::string FieldValue(const Event& event, const char* name) {
    const auto it = event.fields.find(name);
    return it == event.fields.end() ? std::string() : it->second;
}

std::string ToLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string Basename(const std::string& path) {
    std::string value = ToLowerAscii(path);
    while (!value.empty() && (value.back() == '"' || value.back() == ' '))
        value.pop_back();
    const size_t slash = value.find_last_of("\\/");
    if (slash != std::string::npos) value = value.substr(slash + 1);
    return value;
}

bool IsProtectedImage(const std::string& path) {
    const std::string base = Basename(path);
    for (const char* image : kProtectedImages)
        if (base == image) return true;
    return false;
}

bool IsProtectedSystemLocation(const std::string& path) {
    const std::string lower = ToLowerAscii(path);
    return lower.find("\\system32\\") != std::string::npos ||
           lower.find("\\syswow64\\") != std::string::npos;
}

bool IsUserWritableLocation(const std::string& path) {
    static const char* kMarkers[] = {
        "\\temp\\", "\\appdata\\", "\\downloads\\", "\\desktop\\",
        "\\public\\", "\\programdata\\", "\\perflogs\\"
    };
    const std::string lower = ToLowerAscii(path);
    for (const char* marker : kMarkers)
        if (lower.find(marker) != std::string::npos) return true;
    return false;
}

std::string RegistryTarget(const std::string& rawKey) {
    /* REG_WRITE has two shapes in this codebase: driver events keep the bare
     * key and put the value name in reg_value; Sysmon/watch snapshots append
     * the value component to reg_key. Accept both explicitly. */
    const std::string key = ToLowerAscii(rawKey);
    const size_t ifeo = key.rfind("\\image file execution options\\");
    const size_t silent = key.rfind("\\silentprocessexit\\");
    /* Prefer IFEO; fall back to SilentProcessExit. Never std::max() the
     * two - npos (SIZE_MAX) from an absent marker would poison the
     * comparison and make every lookup miss. */
    const size_t root =
        ifeo != std::string::npos ? ifeo : silent;
    if (root == std::string::npos) return {};

    size_t begin = root + 1;
    while (begin < key.size() && key[begin] != '\\') ++begin;
    ++begin;
    if (begin >= key.size()) return {};
    const size_t end = key.find('\\', begin);
    const std::string first = end == std::string::npos
        ? key.substr(begin) : key.substr(begin, end - begin);
    if (first == "debugger" || first == "monitorprocess") return {};
    return IsProtectedImage(first) ? first : std::string();
}

} // namespace

AccessibilityHijackDetector::AccessibilityHijackDetector(bool enabled,
                                                         uint32_t minScore)
    : m_enabled(enabled), m_minScore(minScore) {}

/* static */
bool AccessibilityHijackDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START || type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_RENAME || type == EDR_EVT_REG_WRITE;
}

void AccessibilityHijackDetector::Stamp(Event& event, uint32_t score,
                                        const std::string& signal,
                                        const std::string& target,
                                        const std::string& evidence) {
    event.fields[field::kAccessibilityHijackScore] = std::to_string(score);
    event.fields[field::kAccessibilityHijackVerdict] =
        score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kAccessibilityHijackSignals] = signal;
    event.fields[field::kAccessibilityHijackTarget] = target;
    event.fields[field::kAccessibilityHijackEvidence] = evidence;
}

void AccessibilityHijackDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    uint32_t score = 0;
    std::string signal;
    std::string target;
    std::string evidence;

    if (event.type == EDR_EVT_REG_WRITE) {
        const std::string key = FieldValue(event, field::kRegKey);
        const std::string keyTail = Basename(key);
        const std::string explicitValue =
            ToLowerAscii(FieldValue(event, field::kRegValue));
        target = RegistryTarget(key);
        const bool redirected = !target.empty() &&
            (explicitValue == "debugger" || explicitValue == "monitorprocess" ||
             keyTail == "debugger" || keyTail == "monitorprocess");
        if (redirected) {
            /* Marker probe must run against the lowercased key - the
             * raw registry path keeps mixed case and never matches a
             * lowercase needle. */
            score = 85;
            signal =
                ToLowerAscii(key).rfind("\\silentprocessexit\\") !=
                        std::string::npos
                    ? "accessibility SilentProcessExit redirect"
                    : "accessibility IFEO debugger";
            evidence = key;
        }
    } else if (event.type == EDR_EVT_FILE_CREATE ||
               event.type == EDR_EVT_FILE_RENAME) {
        std::string path = FieldValue(event, field::kFilePath);
        if (path.empty()) path = FieldValue(event, field::kTargetPath);
        if (IsProtectedImage(path)) {
            target = Basename(path);
            evidence = path;
            if (IsProtectedSystemLocation(path)) {
                score = 90;
                signal = "protected accessibility binary replaced";
            } else if (IsUserWritableLocation(path)) {
                score = 60;
                signal = "accessibility binary staged in user-writable path";
            }
        }
    } else if (event.type == EDR_EVT_PROCESS_START) {
        std::string path = FieldValue(event, field::kImagePath);
        if (path.empty()) path = FieldValue(event, field::kImage);
        if (!path.empty() && IsProtectedImage(path) &&
            path.find_first_of("\\/") != std::string::npos &&
            !IsProtectedSystemLocation(path)) {
            score = IsUserWritableLocation(path) ? 80 : 70;
            signal = "accessibility binary executed outside system location";
            target = Basename(path);
            evidence = path;
        }
    }

    if (score == 0 || score < m_minScore) return;
    Stamp(event, score, signal, target, evidence);
}

} // namespace edr