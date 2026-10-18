/*
 * screensaver_persist_detector.cpp - See
 * screensaver_persist_detector.h (T1546.002).
 */
#include "screensaver_persist_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool EndsWith(const std::string& value, const char* suffix) {
    const size_t n = std::char_traits<char>::length(suffix);
    return value.size() >= n &&
           value.compare(value.size() - n, n, suffix) == 0;
}

bool MentionsScreensaverSlot(const std::string& lower) {
    return Contains(lower, "scrnsave.exe");
}

/* Interpreters: a screensaver value that launches one of these is a
 * script payload, not a screensaver. */
bool MentionsInterpreter(const std::string& lower) {
    return Contains(lower, "powershell") || Contains(lower, "pwsh") ||
           Contains(lower, "cmd.exe") || Contains(lower, "cmd /") ||
           Contains(lower, "wscript") || Contains(lower, "cscript") ||
           Contains(lower, "rundll32") || Contains(lower, "mshta") ||
           Contains(lower, "regsvr32");
}

/* User-writable locations: a screensaver binary living there is
 * attacker-owned rather than vendor-shipped. */
bool MentionsWritablePath(const std::string& lower) {
    return Contains(lower, "\\temp\\") || Contains(lower, "%temp%") ||
           Contains(lower, "\\appdata\\") || Contains(lower, "%appdata%") ||
           Contains(lower, "\\users\\public") ||
           Contains(lower, "\\programdata\\") ||
           Contains(lower, "\\downloads\\") ||
           Contains(lower, "\\desktop\\");
}

/* Payload extensions worth flagging outside the writable-dir band. */
bool MentionsPayloadExtension(const std::string& lower) {
    return Contains(lower, ".exe") || Contains(lower, ".scr") ||
           Contains(lower, ".bat") || Contains(lower, ".cmd") ||
           Contains(lower, ".vbs") || Contains(lower, ".js") ||
           Contains(lower, ".ps1") || Contains(lower, ".hta") ||
           Contains(lower, ".com") || Contains(lower, ".pif");
}

/* Stock screensavers shipped with Windows live in system32; those and
 * read-only enumeration of the slot stay silent. */
bool IsStockScreensaver(const std::string& lower) {
    return (Contains(lower, "\\windows\\system32\\") ||
            Contains(lower, "%systemroot%\\system32") ||
            Contains(lower, "%windir%\\system32")) &&
           !MentionsWritablePath(lower);
}

bool IsReadOnlyQuery(const std::string& lower) {
    const bool reads = Contains(lower, "reg query") ||
                       Contains(lower, "get-itemproperty") ||
                       Contains(lower, "get-childitem") ||
                       Contains(lower, "dir ") ||
                       Contains(lower, "gpresult");
    if (!reads) return false;
    return !Contains(lower, "reg add") && !Contains(lower, "reg delete") &&
           !Contains(lower, "set-itemproperty") &&
           !Contains(lower, "new-itemproperty");
}

} // namespace

ScreensaverPersistDetector::ScreensaverPersistDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool ScreensaverPersistDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

/* static */
bool ScreensaverPersistDetector::ClassifyPayload(const std::string& data,
                                                 Finding* out) {
    const std::string lower = ToLowerAscii(data);
    if (lower.empty()) return false;

    if (MentionsInterpreter(lower)) {
        *out = Finding{90, "screensaver slot pointing at interpreter"};
        return true;
    }
    if (MentionsWritablePath(lower)) {
        *out = Finding{90, "screensaver binary in user-writable path"};
        return true;
    }
    if (IsStockScreensaver(lower)) return false;
    if (MentionsPayloadExtension(lower)) {
        *out = Finding{85, "screensaver slot pointed at payload file"};
        return true;
    }
    return false;
}

/* static */
bool ScreensaverPersistDetector::ExtractAssignedData(
    const std::string& raw, const std::string& lower, std::string* out) {
    /* reg add ... /v SCRNSAVE.EXE /t REG_SZ /d "<payload>" and
     * Set-ItemProperty ... SCRNSAVE.EXE -Value "<payload>". The last
     * assignment marker after the SCRNSAVE.EXE mention wins. The marker
     * scan runs on the lowercased copy (-Value vs -value) while the
     * slice comes from raw; ToLowerAscii is byte-wise, so the indices
     * are identical. */
    size_t marker = std::string::npos;
    size_t markerLen = 0;
    for (const char* candidate : {"/d ", "-value ", "-value="}) {
        const size_t at = lower.rfind(candidate);
        /* npos is SIZE_MAX, so a plain std::max would let a missing
         * marker win over a present one (npos poisoning). */
        if (at == std::string::npos) continue;
        if (marker == std::string::npos || at > marker) {
            marker = at;
            markerLen = std::strlen(candidate);
        }
    }
    if (marker == std::string::npos) return false;

    const size_t start = marker + markerLen;
    if (start >= raw.size()) return false;

    /* Accept a double- or single-quoted token or a bare token up to
     * the next switch. */
    const char open = raw[start];
    if (open == '"' || open == '\'') {
        const size_t endQuote = raw.find(open, start + 1);
        if (endQuote == std::string::npos) return false;
        *out = raw.substr(start + 1, endQuote - start - 1);
        return true;
    }
    const size_t end = raw.find(" /", start);
    const size_t spaceEnd = raw.find(' ', start);
    size_t tokenEnd = end;
    if (tokenEnd == std::string::npos ||
        (spaceEnd != std::string::npos && spaceEnd < tokenEnd)) {
        tokenEnd = spaceEnd;
    }
    if (tokenEnd == std::string::npos) tokenEnd = raw.size();
    *out = raw.substr(start, tokenEnd - start);
    return true;
}

void ScreensaverPersistDetector::Stamp(Event& event,
                                       const Finding& finding,
                                       const std::string& key) {
    event.fields[field::kScreensaverPersistScore] =
        std::to_string(finding.score);
    event.fields[field::kScreensaverPersistVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kScreensaverPersistSignals] = finding.signal;
    event.fields[field::kScreensaverPersistText] = key;
}

void ScreensaverPersistDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;

    if (event.type == EDR_EVT_REG_WRITE) {
        /* Dual shape: kRegKey holds the bare key or the full path
         * including the value name; kRegValue holds the value NAME
         * (driver) or the DATA (sysmon/reg_watch snapshot). Either way,
         * the slot is in scope when the concatenation mentions
         * SCRNSAVE.EXE. */
        auto keyIt = event.fields.find(field::kRegKey);
        auto valIt = event.fields.find(field::kRegValue);
        std::string keyText;
        if (keyIt != event.fields.end()) keyText = keyIt->second;
        std::string valText;
        if (valIt != event.fields.end()) valText = valIt->second;

        const std::string lowerJoined = ToLowerAscii(keyText + " " + valText);
        if (!MentionsScreensaverSlot(lowerJoined)) return;

        /* Which half carries the payload? The data half mentions a
         * payload extension or interpreter; the name half is exactly
         * the slot name. Prefer whichever half is not just the slot
         * name itself. */
        const std::string lowerKey = ToLowerAscii(keyText);
        const std::string lowerVal = ToLowerAscii(valText);

        /* sysmon/reg_watch shape: kRegKey ends with \SCRNSAVE.EXE and
         * kRegValue carries the data. */
        bool keyNamesSlot = EndsWith(lowerKey, "\\scrnsave.exe") ||
                            lowerKey == "scrnsave.exe";
        /* driver shape: kRegValue IS the name "SCRNSAVE.EXE". */
        bool valNamesSlot = lowerVal == "scrnsave.exe";

        Finding finding;
        if (keyNamesSlot && !valText.empty()) {
            if (!ClassifyPayload(valText, &finding)) return;
        } else if (valNamesSlot) {
            if (keyText.empty() || lowerKey.find('\\') == std::string::npos)
                return;
            /* Name-only observation: the slot was registered with no
             * data captured. */
            finding = Finding{75, "screensaver slot registered with no payload token"};
        } else {
            /* Command-shaped reg write arriving on the REG_WRITE plane:
             * treat the value half as the payload data. */
            if (valText.empty() || !ClassifyPayload(valText, &finding))
                return;
        }

        if (finding.score < m_minScore) return;
        Stamp(event, finding, lowerJoined.substr(0, 160));
        return;
    }

    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) return;

    const std::string lower = ToLowerAscii(text);
    if (!MentionsScreensaverSlot(lower)) return;
    if (IsReadOnlyQuery(lower)) return;

    Finding finding;
    std::string data;
    if (ExtractAssignedData(text, lower, &data) &&
        ClassifyPayload(data, &finding)) {
        /* scored below */
    } else {
        /* reg add without an extractable /d payload still creates the
         * slot. */
        if (Contains(lower, "reg add") || Contains(lower, "set-itemproperty") ||
            Contains(lower, "new-itemproperty")) {
            finding = Finding{75, "screensaver slot written with no payload token"};
        } else {
            return;
        }
    }
    if (finding.score < m_minScore) return;

    const std::string key = lower.substr(0, 160);
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
                "[edr-screensaver] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
