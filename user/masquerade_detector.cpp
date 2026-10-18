/*
 * masquerade_detector.cpp - Filename-level masquerading (T1036).
 */
#include "masquerade_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

std::string LowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

/* Returns the final path component (handles both \ and / separators). */
std::string Basename(const std::string& path) {
    const size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

bool EndsWith(const std::string& text, const char* suffix) {
    const size_t len = strlen(suffix);
    return text.size() >= len &&
           text.compare(text.size() - len, len, suffix) == 0;
}

} // namespace

MasqueradeDetector::MasqueradeDetector(bool enabled, uint32_t minScore,
                                       uint32_t dedupWindowSeconds,
                                       size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {
    /* Common ASCII typosquats of protected system binaries. Exact-basename
     * matches only - deterministic, zero false positives by construction
     * (no legit binary ships with these names). */
    for (const char* name : {
             "svch0st.exe", "scvhost.exe", "svchosts.exe", "sychost.exe",
             "1sass.exe", "lsass .exe", "1smss.exe", "csrsss.exe",
             "cssrs.exe", "smsss.exe", "exp1orer.exe", "expl0rer.exe",
             "explorer .exe", "win1ogon.exe", "services .exe",
             "taskmgr .exe", "chrome .exe"})
        m_lookalikeNames.insert(name);
}

/* static */
bool MasqueradeDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool MasqueradeDetector::Analyze(const std::string& rawPath,
                                 Finding* out) const {
    if (rawPath.empty()) return false;
    const std::string path = LowerAscii(rawPath);
    /* Trailing dots/spaces are an Explorer disguise themselves, so accept
     * both the bare extension and its trailing-dot/space variants here;
     * the padded-name checks below then score them. */
    if (!EndsWith(path, ".exe") && !EndsWith(path, ".scr") &&
        !EndsWith(path, ".com") && !EndsWith(path, ".pif") &&
        !EndsWith(path, ".exe.") && !EndsWith(path, ".exe ") &&
        !EndsWith(path, ".scr.") && !EndsWith(path, ".scr ") &&
        !EndsWith(path, ".com.") && !EndsWith(path, ".com ") &&
        !EndsWith(path, ".pif.") && !EndsWith(path, ".pif "))
        return false; /* disguise checks target executable images */

    /* RTLO U+202E = 0xE2 0x80 0xAE in UTF-8. */
    if (path.find("\xE2\x80\xAE") != std::string::npos) {
        *out = Finding{85, "rtlo disguised image name"};
        return true;
    }

    const std::string base = Basename(path);
    if (m_lookalikeNames.count(base) != 0) {
        *out = Finding{80, "system binary lookalike basename"};
        return true;
    }

    static const char* const kOuterExts[] = {
        ".pdf.", ".jpg.", ".jpeg.", ".png.", ".gif.", ".txt.", ".doc.",
        ".docx.", ".xls.", ".xlsx.", ".pptx.", ".mp3.", ".mp4.", ".zip.",
        ".rar.", ".htm.", ".html."
    };
    static const char* const kInnerExts[] = {
        "exe", "scr", "com", "pif", "bat", "cmd", "js", "vbs"
    };
    for (const char* outer : kOuterExts) {
        if (base.find(outer) == std::string::npos) continue;
        for (const char* inner : kInnerExts) {
            if (base.find(std::string(outer) + inner) != std::string::npos) {
                *out = Finding{70, "double extension executable"};
                return true;
            }
        }
    }

    /* Whitespace padding before the extension or trailing dots/spaces:
     * "setup .exe" visually reads as a document; trailing dots hide the
     * real extension in Explorer's default view. */
    if (base.size() > 4) {
        const size_t dot = base.rfind(".exe");
        if (dot != std::string::npos && dot >= 1) {
            const char before = base[dot - 1];
            if (before == ' ' || before == '\t') {
                *out = Finding{60, "whitespace-padded executable name"};
                return true;
            }
        }
        if (EndsWith(base, ".exe.") || EndsWith(base, ".exe ")) {
            *out = Finding{60, "trailing-dot padded executable name"};
            return true;
        }
    }
    return false;
}

void MasqueradeDetector::Stamp(Event& event, const Finding& finding,
                               const std::string& imagePath) {
    event.fields[field::kMasqueradeScore] = std::to_string(finding.score);
    event.fields[field::kMasqueradeVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kMasqueradeSignals] = finding.signal;
    event.fields[field::kMasqueradeImage] = imagePath;
}

void MasqueradeDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    auto imageIt = event.fields.find(field::kImage);
    if (imageIt == event.fields.end()) return;

    Finding finding;
    if (!Analyze(imageIt->second, &finding)) return;
    if (finding.score < m_minScore) return;

    const std::string key = LowerAscii(imageIt->second);
    const uint64_t now = event.ts100ns;
    auto it = m_lastAlert.find(key);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
            std::fprintf(stderr,
                "[edr-masquerade] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
