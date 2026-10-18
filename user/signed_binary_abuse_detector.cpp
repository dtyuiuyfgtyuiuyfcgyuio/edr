/*
 * signed_binary_abuse_detector.cpp - Signed binary proxy execution
 * detector (T1218.012 / T1218.013 / T1218.014 and peers).
 */
#include "signed_binary_abuse_detector.h"

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

/* The basename of the invoked image (after the last separator). */
std::string Basename(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

} // namespace

SignedBinaryAbuseDetector::SignedBinaryAbuseDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool SignedBinaryAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool SignedBinaryAbuseDetector::Analyze(const std::string& lower,
                                        const std::string& imageLower,
                                        Finding* out) const {
    const std::string base = Basename(imageLower);

    /* mavinject: signed App-V DLL injector abused for process
     * injection (MITRE T1218.012 proxy execution). */
    if ((base == "mavinject.exe" || Contains(lower, "mavinject")) &&
        (Contains(lower, "/injectrunning") ||
         Contains(lower, "mavinject32") || Contains(lower, "hnccl.dll"))) {
        *out = Finding{90, "mavinject process injection"};
        return true;
    }
    if (base == "mavinject.exe" || base == "mavinject32.exe") {
        *out = Finding{75, "signed DLL injector invoked"};
        return true;
    }

    /* register-cimprovider: loads an arbitrary DLL into a signed
     * service host (T1218 proxy execution). */
    if (Contains(lower, "register-cimprovider") &&
        (Contains(lower, "-path") || Contains(lower, "-namespace"))) {
        *out = Finding{85, "register-cimprovider arbitrary DLL load"};
        return true;
    }

    /* infdefaultinstall: executes the DefaultInstall section of a
     * caller-supplied .inf (T1218.014). */
    if ((base == "infdefaultinstall.exe" ||
         Contains(lower, "infdefaultinstall")) &&
        Contains(lower, ".inf")) {
        *out = Finding{80, "infdefaultinstall .inf execution"};
        return true;
    }

    /* xwizard: custom wizard CLSID / dll-host shapes (T1218.013
     * peer). Bare `xwizard` with no argument stays silent. */
    if (Contains(lower, "xwizard") &&
        (Contains(lower, "runwizard") || Contains(lower, "{") ||
         Contains(lower, ".dll"))) {
        *out = Finding{80, "xwizard proxy execution"};
        return true;
    }

    /* verclsid: instantiates an arbitrary COM CLSID (proxy). */
    if ((base == "verclsid.exe" || Contains(lower, "verclsid")) &&
        Contains(lower, "/clsid:")) {
        *out = Finding{70, "verclsid arbitrary CLSID instantiation"};
        return true;
    }

    /* syncappvpublishingserver: script execution surface when given
     * arguments; bare invocation is benign telemetry. */
    if (base == "syncappvpublishingserver.exe" &&
        lower.size() > 40) {
        *out = Finding{65, "syncappvpublishingserver scripted abuse"};
        return true;
    }

    return false;
}

void SignedBinaryAbuseDetector::Stamp(Event& event,
                                      const Finding& finding,
                                      const std::string& key) {
    event.fields[field::kSignedBinaryAbuseScore] =
        std::to_string(finding.score);
    event.fields[field::kSignedBinaryAbuseVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kSignedBinaryAbuseSignals] = finding.signal;
    event.fields[field::kSignedBinaryAbuseText] = key;
}

void SignedBinaryAbuseDetector::Enrich(Event& event) {
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

    /* Command text alone must carry the signal when the image is not
     * known (script plane); otherwise combine both. */
    if (text.empty() && image.empty()) return;

    const std::string combined =
        ToLowerAscii(image + " " + text);
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
                "[edr-signed-binary-abuse] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
