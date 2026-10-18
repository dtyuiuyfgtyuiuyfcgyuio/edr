/*
 * hidden_artifacts_detector.cpp - See hidden_artifacts_detector.h.
 */
#include "hidden_artifacts_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>

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

bool Contains(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

std::string BaseNameOf(const std::string& value) {
    const size_t slash = value.find_last_of("\\/");
    return slash == std::string::npos ? value : value.substr(slash + 1);
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

/* Return the file portion of a quoted or bare token; strips enclosing
 * quotes so "C:\temp\p.txt:ads" and C:\temp\p.txt:ads both resolve. */
std::string StripQuotes(std::string token) {
    if (token.size() >= 2 && token.front() == '"' && token.back() == '"')
        token = token.substr(1, token.size() - 2);
    return token;
}

/* True when the path contains a stream separator beyond the drive colon,
 * i.e. "C:\dir\file.txt:stream" or "...:$DATA" / ":stream:$DATA". */
bool HasAdsSeparator(const std::string& path) {
    const size_t driveColon = path.find(':');
    if (driveColon == std::string::npos) return false;
    /* Skip the drive colon (X:) and any UNC \\?\C: prefix colon. */
    size_t search = driveColon + 1;
    const size_t sep = path.find(':', search);
    return sep != std::string::npos;
}

} // namespace

HiddenArtifactsDetector::HiddenArtifactsDetector(bool enabled,
                                                 uint32_t windowSeconds,
                                                 size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool HiddenArtifactsDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_RENAME;
}

bool HiddenArtifactsDetector::IsInterpreter(const std::string& image) {
    static const char* kInterpreters[] = {
        "powershell.exe", "pwsh.exe", "certutil.exe", "bitsadmin.exe",
        "mshta.exe", "wscript.exe", "cscript.exe", "curl.exe",
        "certreq.exe", "msiexec.exe"
    };
    const std::string base = LowerAscii(BaseNameOf(image));
    for (const char* name : kInterpreters) {
        if (base == name) return true;
    }
    return false;
}

bool HiddenArtifactsDetector::IsExecutablePath(const std::string& path) {
    static const char* kExtensions[] = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
        ".hta", ".scr", ".pif", ".msi", ".jar", ".lnk"
    };
    const std::string lower = LowerAscii(path);
    for (const char* ext : kExtensions) {
        if (lower.size() >= std::strlen(ext) &&
            lower.compare(lower.size() - std::strlen(ext),
                          std::strlen(ext), ext) == 0)
            return true;
    }
    return false;
}

bool HiddenArtifactsDetector::IsUserWritablePath(const std::string& path) {
    const std::string lower = LowerAscii(path);
    return Contains(lower, "\\appdata\\") ||
           Contains(lower, "\\temp\\") ||
           Contains(lower, "\\tmp\\") ||
           Contains(lower, "\\programdata\\") ||
           Contains(lower, "\\users\\public\\") ||
           Contains(lower, "\\downloads\\") ||
           Contains(lower, "\\windows\\temp\\");
}

std::string HiddenArtifactsDetector::AdsPathInCommandLine(
    const std::string& commandLine) {
    /* Walk whitespace-separated tokens looking for an ADS target after a
     * redirection operator (>, >>) or an explicit path argument. */
    const std::string lower = LowerAscii(commandLine);
    size_t pos = 0;
    while (pos < commandLine.size()) {
        const size_t start = commandLine.find_first_not_of(" \t", pos);
        if (start == std::string::npos) break;
        size_t end = commandLine.find_first_of(" \t", start);
        if (end == std::string::npos) end = commandLine.size();
        std::string token =
            StripQuotes(commandLine.substr(start, end - start));
        pos = end;

        /* Skip operators themselves; the token after them is the target. */
        if (token == ">" || token == ">>" || token == "1>" || token == "2>") {
            continue;
        }
        if (token.empty()) continue;
        /* Strip leading operator prefix glued to the target (">file:x"). */
        if (token[0] == '>') token = token.substr(1);
        if (token.empty()) continue;
        if (HasAdsSeparator(token)) return token;
    }
    /* PowerShell -Command ... Set-Content -Path x:y -Stream shapes. */
    if (Contains(lower, "-stream") && commandLine.find(':') !=
                                          std::string::npos) {
        return "powershell_stream_argument";
    }
    return std::string();
}

std::string HiddenArtifactsDetector::AdsPathInFilePath(
    const std::string& filePath) {
    if (!filePath.empty() && HasAdsSeparator(filePath)) return filePath;
    return std::string();
}

bool HiddenArtifactsDetector::IsHiddenAttribCommand(
    const std::string& commandLine, std::string* outPath) {
    const std::string lower = LowerAscii(commandLine);
    if (!Contains(lower, "attrib")) return false;

    /* Must actually set the hidden / system flag, not clear it. */
    const size_t plusH = lower.find("+h");
    const size_t plusS = lower.find("+s");
    if (plusH == std::string::npos && plusS == std::string::npos) return false;

    /* Recover the first non-flag token as the target path. */
    size_t pos = 0;
    while (pos < commandLine.size()) {
        const size_t start = commandLine.find_first_not_of(" \t", pos);
        if (start == std::string::npos) break;
        size_t end = commandLine.find_first_of(" \t", start);
        if (end == std::string::npos) end = commandLine.size();
        std::string token =
            StripQuotes(commandLine.substr(start, end - start));
        pos = end;
        if (token.empty()) continue;
        if (token[0] == '+' || token[0] == '-' || token[0] == '/') continue;
        if (LowerAscii(token) == "attrib.exe" || LowerAscii(token) == "attrib")
            continue;
        if (outPath) *outPath = token;
        return true;
    }
    return false;
}

bool HiddenArtifactsDetector::IsPowerShellHiddenAttribute(
    const std::string& commandLine, std::string* outPath) {
    const std::string lower = LowerAscii(commandLine);
    const bool setItemProperty = Contains(lower, "set-itemproperty") &&
                                 Contains(lower, "attributes") &&
                                 Contains(lower, "hidden");
    const bool ioFile = Contains(lower, "[io.file]::setattributes") &&
                        Contains(lower, "hidden");
    const bool attrib = Contains(lower, "attrib ") && Contains(lower, "+h");
    if (!setItemProperty && !ioFile && !attrib) return false;

    /* Best-effort path recovery: first quoted argument after -path or the
     * first drive-letter token. */
    size_t pathPos = lower.find("-path");
    if (pathPos == std::string::npos) pathPos = lower.find("attrib ");
    if (pathPos != std::string::npos) {
        const size_t quote = commandLine.find('"', pathPos);
        if (quote != std::string::npos) {
            const size_t quoteEnd = commandLine.find('"', quote + 1);
            if (quoteEnd != std::string::npos) {
                if (outPath)
                    *outPath = commandLine.substr(quote + 1,
                                                  quoteEnd - quote - 1);
                return true;
            }
        }
    }
    if (outPath) *outPath = std::string();
    return true;
}

void HiddenArtifactsDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_procs.erase(it);
        else
            ++it;
    }
}

uint32_t HiddenArtifactsDetector::ComputeScore(
    const ProcState& state) const {
    uint32_t score = 0;
    if (state.sawAdsWrite) score += 55;
    if (state.sawInterpreterAds) score += 35;
    if (state.sawHiddenAttrib) score += 45;

    /* Create-then-hide: files created by this process were later hidden. */
    for (const std::string& hidden : state.hiddenPaths) {
        const std::string lower = LowerAscii(hidden);
        for (const std::string& created : state.createdFiles) {
            if (LowerAscii(created) == lower) {
                score += 35;
                break;
            }
        }
    }
    /* Hidden executables are stronger than hidden data files. */
    for (const std::string& hidden : state.hiddenPaths) {
        if (IsExecutablePath(hidden)) {
            score += 25;
            break;
        }
    }
    /* Hiding artifacts inside user-writable staging directories is the
     * classic payload-drop pattern. */
    for (const std::string& hidden : state.hiddenPaths) {
        if (IsUserWritablePath(hidden)) {
            score += 10;
            break;
        }
    }
    return std::min(100u, score);
}

std::string HiddenArtifactsDetector::SignalList(
    const ProcState& state) const {
    std::string signals;
    const std::pair<bool, const char*> kFlags[] = {
        {state.sawAdsWrite, "ads_write"},
        {state.sawInterpreterAds, "interpreter_ads"},
        {state.sawHiddenAttrib, "hidden_attrib"},
        {state.sawInterpreterAds && state.sawHiddenAttrib, "staged_payload"},
    };
    for (const auto& entry : kFlags) {
        if (!entry.first) continue;
        if (!signals.empty()) signals += ",";
        signals += entry.second;
    }
    return signals;
}

std::string HiddenArtifactsDetector::PathList(
    const std::unordered_set<std::string>& paths) const {
    std::string joined;
    for (const std::string& path : paths) {
        if (!joined.empty()) joined += ",";
        joined += path;
    }
    return joined;
}

void HiddenArtifactsDetector::WriteState(Event& event,
                                         const ProcState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kHiddenArtifactsScore] = std::to_string(score);
    event.fields[field::kHiddenArtifactsSignals] = SignalList(state);
    event.fields[field::kHiddenArtifactsPaths] = PathList(state.hiddenPaths);
    event.fields[field::kHiddenArtifactsAdsPaths] =
        PathList(state.adsPaths);
    event.fields[field::kHiddenArtifactsWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kHiddenArtifactsVerdict] = verdict;
    }
}

void HiddenArtifactsDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (event.pid == 0) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string image = FieldValue(event, field::kImage);
    const std::string commandLine =
        FieldValue(event, field::kCommandLine);
    const std::string filePath = FieldValue(event, field::kFilePath);
    const std::string oldFilePath =
        FieldValue(event, field::kOldFilePath);

    ProcState* state = nullptr;
    auto ensureState = [&]() -> ProcState& {
        if (!state) state = &m_procs[event.pid];
        return *state;
    };

    if (event.type == EDR_EVT_PROCESS_START) {
        /* Hidden attribute commands. */
        std::string attribPath;
        if (IsHiddenAttribCommand(commandLine, &attribPath) ||
            IsPowerShellHiddenAttribute(commandLine, &attribPath)) {
            ProcState& proc = ensureState();
            proc.sawHiddenAttrib = true;
            if (!attribPath.empty()) proc.hiddenPaths.insert(attribPath);
            proc.lastSeen100ns = now;
        }
        /* ADS creation via command-line redirection. */
        const std::string adsPath = AdsPathInCommandLine(commandLine);
        if (!adsPath.empty()) {
            ProcState& proc = ensureState();
            proc.sawAdsWrite = true;
            proc.adsPaths.insert(adsPath);
            if (IsInterpreter(image)) proc.sawInterpreterAds = true;
            proc.lastSeen100ns = now;
        }
    } else if (event.type == EDR_EVT_FILE_CREATE) {
        /* File write events carrying an ADS path. */
        const std::string adsPath = AdsPathInFilePath(filePath);
        if (!adsPath.empty()) {
            ProcState& proc = ensureState();
            proc.sawAdsWrite = true;
            proc.adsPaths.insert(adsPath);
            if (IsInterpreter(image)) proc.sawInterpreterAds = true;
            proc.lastSeen100ns = now;
        } else if (!filePath.empty()) {
            ProcState& proc = ensureState();
            proc.createdFiles.insert(filePath);
            proc.lastSeen100ns = now;
        }
    } else if (event.type == EDR_EVT_FILE_RENAME) {
        /* Rename to a hidden-stream style target also counts. */
        const std::string adsPath = AdsPathInFilePath(oldFilePath.empty()
                                                          ? filePath
                                                          : filePath);
        if (!adsPath.empty()) {
            ProcState& proc = ensureState();
            proc.sawAdsWrite = true;
            proc.adsPaths.insert(adsPath);
            proc.lastSeen100ns = now;
        }
    }

    if (state) {
        /* Only stamp when there is an actual signal - a bare file
         * creation must not carry a zero score field. */
        if (ComputeScore(*state) > 0) {
            WriteState(event, *state);
        }
        EvictOldest(m_procs, m_stateCapacity);
    }
}

} // namespace edr
