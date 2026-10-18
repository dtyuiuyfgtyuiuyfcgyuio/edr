/*
 * com_hijack_detector.cpp - COM CLSID hijack detector (T1546.015).
 */
#include "com_hijack_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

bool Contains(const std::string& v, const char* n) { return v.find(n) != std::string::npos; }

std::string ToLowerAscii(const std::string& t) {
    std::string o = t;
    std::transform(o.begin(), o.end(), o.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return o;
}

bool EndsWith(const std::string& v, const char* s) {
    size_t sl = std::strlen(s);
    if (v.size() < sl) return false;
    return v.compare(v.size()-sl, sl, s)==0;
}

bool MentionsWritableDir(const std::string& l) {
    return Contains(l, "\\temp\\") || Contains(l, "\\tmp\\") || Contains(l, "appdata") ||
           Contains(l, "programdata") || Contains(l, "\\users\\public") || Contains(l, "\\public\\") ||
           Contains(l, "\\downloads\\") || Contains(l, "%temp%") || Contains(l, "%appdata%") ||
           Contains(l, "\\users\\") || Contains(l, "c:\\temp") || Contains(l, "c:\\users\\public");
}

bool MentionsInterpreter(const std::string& l) {
    return Contains(l, "cmd.exe") || Contains(l, "powershell") || Contains(l, "pwsh") ||
           Contains(l, "wscript") || Contains(l, "cscript") || Contains(l, "rundll32") ||
           Contains(l, "mshta") || Contains(l, "regsvr32");
}

bool IsSystem32Path(const std::string& l) {
    return Contains(l, "\\windows\\system32\\") || Contains(l, "\\windows\\syswow64\\") ||
           Contains(l, "\\system32\\") || Contains(l, "system32\\");
}

bool IsReadOnlyQuery(const std::string& l) {
    return Contains(l, "reg query") || Contains(l, "reg /query") || Contains(l, "get-itemproperty") ||
           Contains(l, "get_itemproperty") || Contains(l, "reg get");
}

bool IsTrustedWriter(const std::string& l) {
    return Contains(l, "msiexec") || Contains(l, "trustedinstaller") || Contains(l, "tiworker");
}

bool IsComKey(const std::string& l) {
    if (l.find("clsid") == std::string::npos) return false;
    if (l.find("software\\classes") == std::string::npos && l.find("software/classes") == std::string::npos) return false;
    return Contains(l, "inprocserver32") || Contains(l, "localserver32") || Contains(l, "inproc") || Contains(l, "treatas");
}

} // namespace

ComHijackDetector::ComHijackDetector(bool enabled, uint32_t minScore,
                                     uint32_t dedupWindowSeconds, size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds)*kFiletimeTicksPerSecond),
      m_capacity(stateCapacity) {}

bool ComHijackDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_REG_WRITE || type == EDR_EVT_PROCESS_START || type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool ComHijackDetector::ClassifyPayload(const std::string& data, Finding* out) {
    if (data.empty()) return false;
    std::string l = ToLowerAscii(data);
    if (IsSystem32Path(l) && !MentionsWritableDir(l) && !MentionsInterpreter(l)) return false;
    if (MentionsInterpreter(l) || MentionsWritableDir(l)) {
        *out = Finding{90, "COM hijack to writable/interpreter path"};
        return true;
    }
    if (!IsSystem32Path(l)) {
        *out = Finding{85, "COM hijack outside system32"};
        return true;
    }
    return false;
}

void ComHijackDetector::Stamp(Event& event, const Finding& f, const std::string& key) {
    event.fields[field::kComHijackScore] = std::to_string(f.score);
    event.fields[field::kComHijackVerdict] = (f.score >= 75 ? "malicious" : "suspicious");
    event.fields[field::kComHijackSignals] = f.signal;
    event.fields[field::kComHijackText] = key;
}

void ComHijackDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    if (event.type == EDR_EVT_REG_WRITE) {
        auto kit = event.fields.find(field::kRegKey);
        auto vit = event.fields.find(field::kRegValue);
        std::string keyText = kit != event.fields.end() ? kit->second : "";
        std::string valText = vit != event.fields.end() ? vit->second : "";
        std::string lowerJoined = ToLowerAscii(keyText + " " + valText);
        if (!IsComKey(lowerJoined)) return;
        std::string lowerKey = ToLowerAscii(keyText);
        std::string lowerVal = ToLowerAscii(valText);
        bool keyNamesSlot = Contains(lowerKey, "inprocserver32") || Contains(lowerKey, "localserver32") || EndsWith(lowerKey, "\\(default)") || lowerKey.find("clsid")!=std::string::npos;
        // Dual shape: if key contains clsid and val is data
        Finding f;
        if (!valText.empty() && IsComKey(lowerJoined)) {
            if (!ClassifyPayload(valText, &f)) {
                // name-only case still counts if valText empty?
                return;
            }
        } else if (valText.empty()) {
            // name-only observation (driver shape)
            f = Finding{75, "COM hijack registered with no payload token"};
        } else {
            if (!ClassifyPayload(valText, &f)) return;
        }
        if (f.score < m_minScore) return;
        std::string dedupKey = lowerJoined.substr(0,160);
        uint64_t now = event.ts100ns;
        auto it = m_state.find(dedupKey);
        if (it != m_state.end()) {
            if (m_dedupWindow100ns!=0 && now>=it->second && now-it->second < m_dedupWindow100ns) return;
            it->second = now;
        } else {
            if (m_capacity>0 && m_state.size()>=m_capacity) {
                m_state.clear();
                std::fprintf(stderr,"[edr-com-hijack] state capacity %zu reached; dedup reset\n", m_capacity);
            }
            m_state.emplace(dedupKey, now);
        }
        Stamp(event, f, lowerJoined.substr(0,160));
        return;
    }
    // command plane
    std::string text;
    auto cit = event.fields.find(field::kCommandLine);
    if (cit != event.fields.end()) text = cit->second;
    if (text.empty() && event.type==EDR_EVT_POWERSHELL_SCRIPT) {
        auto sit = event.fields.find(field::kScriptBlockText);
        if (sit!=event.fields.end()) text = sit->second;
    }
    if (text.empty()) return;
    std::string lower = ToLowerAscii(text);
    if (!IsComKey(lower)) return;
    if (IsReadOnlyQuery(lower)) return;
    if (IsTrustedWriter(lower)) return;
    // extract payload after /d
    std::string data;
    size_t dpos = lower.find("/d");
    if (dpos!=std::string::npos) {
        size_t start = dpos+2;
        while (start<text.size() && (text[start]==' '||text[start]=='\"' || text[start]==':')) ++start;
        size_t end = text.find(" /", start);
        if (end==std::string::npos) end = text.size();
        data = text.substr(start, end-start);
    } else {
        // fallback: whole text
        data = text;
    }
    // if no dll/exe token, treat as name-only
    Finding f;
    if (data.find(".dll")==std::string::npos && data.find(".exe")==std::string::npos && !MentionsInterpreter(ToLowerAscii(data))) {
        f = Finding{75, "COM hijack registered with no payload token"};
    } else {
        if (!ClassifyPayload(data, &f)) return;
    }
    if (f.score < m_minScore) return;
    std::string key = lower.substr(0,160);
    uint64_t now = event.ts100ns;
    auto it = m_state.find(key);
    if (it != m_state.end()) {
        if (m_dedupWindow100ns!=0 && now>=it->second && now-it->second < m_dedupWindow100ns) return;
        it->second = now;
    } else {
        if (m_capacity>0 && m_state.size()>=m_capacity) {
            m_state.clear();
            std::fprintf(stderr,"[edr-com-hijack] state capacity %zu reached; dedup reset\n", m_capacity);
        }
        m_state.emplace(key, now);
    }
    Stamp(event, f, key);
}

} // namespace edr
