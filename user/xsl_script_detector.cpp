/*
 * xsl_script_detector.cpp - XSL script processing detector (T1220).
 */
#include "xsl_script_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

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

std::string Basename(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

bool IsBuiltinWmicFormat(const std::string& lower) {
    /* Built-in /format: names never load attacker XSL. */
    static const char* kBuiltin[] = {
        "/format:list", "/format:table", "/format:csv",
        "/format:xml", "/format:value", "/format:mof",
        "/format:hform", "/format:htable", "/format:\"list\"",
        "/format:\"table\"", "/format:\"csv\"", "/format:\"xml\""
    };
    for (const char* name : kBuiltin) {
        if (Contains(lower, name)) return true;
    }
    return false;
}

} // namespace

XslScriptDetector::XslScriptDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool XslScriptDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool XslScriptDetector::Analyze(const std::string& lower,
                                const std::string& imageLower,
                                Finding* out) const {
    const std::string base = Basename(imageLower);

    if ((base == "msxsl.exe" || Contains(lower, "msxsl")) &&
        (Contains(lower, ".xsl") || Contains(lower, ".xslt"))) {
        *out = Finding{90, "msxsl stylesheet execution"};
        return true;
    }

    const bool wmic =
        base == "wmic.exe" || Contains(lower, "wmic ");
    if (wmic && Contains(lower, "/format:")) {
        if (IsBuiltinWmicFormat(lower)) return false;
        if (Contains(lower, "http://") || Contains(lower, "https://")) {
            *out = Finding{90, "wmic remote XSL stylesheet"};
            return true;
        }
        if (Contains(lower, "\\users\\") ||
            Contains(lower, "\\temp\\") ||
            Contains(lower, "%temp%") ||
            Contains(lower, "%tmp%") ||
            Contains(lower, "$env:temp") ||
            Contains(lower, "$env:tmp") ||
            Contains(lower, "\\appdata\\") ||
            Contains(lower, "\\public\\") ||
            Contains(lower, "\\programdata\\") ||
            Contains(lower, "\\downloads\\")) {
            *out = Finding{85, "wmic user-writable XSL stylesheet"};
            return true;
        }
        if (Contains(lower, ".xsl")) {
            *out = Finding{75, "wmic local XSL stylesheet"};
            return true;
        }
    }

    if (Contains(lower, "xslcompiledtransform") ||
        Contains(lower, "transformnode")) {
        *out = Finding{80, "MSXML/XslCompiledTransform script"};
        return true;
    }

    return false;
}

void XslScriptDetector::Stamp(Event& event, const Finding& finding,
                              const std::string& key) {
    event.fields[field::kXslScriptScore] = std::to_string(finding.score);
    event.fields[field::kXslScriptVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kXslScriptSignals] = finding.signal;
    event.fields[field::kXslScriptText] = key;
}

void XslScriptDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    std::string image;
    auto imgIt = event.fields.find(field::kImage);
    if (imgIt != event.fields.end()) image = imgIt->second;
    if (text.empty() && image.empty()) return;

    const std::string combined = ToLowerAscii(image + " " + text);
    const std::string imageLower = ToLowerAscii(image);

    Finding finding;
    if (!Analyze(combined, imageLower, &finding)) return;
    if (finding.score < m_minScore) return;

    const std::string key = combined.substr(0, 160);
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
                "[edr-xsl-script] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
