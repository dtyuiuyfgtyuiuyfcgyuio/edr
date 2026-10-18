/*
 * email_collection_detector.cpp - Email collection detector (T1114).
 */
#include "email_collection_detector.h"

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

std::string BaseNameOf(const std::string& value) {
    const size_t slash = value.find_last_of("\\/");
    return slash == std::string::npos ? value : value.substr(slash + 1);
}

} // namespace

EmailCollectionDetector::EmailCollectionDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool EmailCollectionDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

/* static */
bool EmailCollectionDetector::IsMailClientImage(const std::string& image) {
    const std::string base = ToLowerAscii(BaseNameOf(image));
    return base == "outlook.exe" || base == "olk.exe" ||
           base == "hxoutlook.exe" || base == "thunderbird.exe" ||
           base == "searchprotocolhost.exe" ||
           base == "searchindexer.exe" || base == "msteams.exe" ||
           base == "edr.exe";
}

/* static */
bool EmailCollectionDetector::HasMailStore(const std::string& lower) {
    return Contains(lower, ".pst") || Contains(lower, ".ost") ||
           Contains(lower, "archive.pst") ||
           Contains(lower, "\\microsoft\\outlook\\") ||
           Contains(lower, "\\windows live mail\\") ||
           Contains(lower, "\\thunderbird\\profiles\\");
}

/* static */
bool EmailCollectionDetector::HasExfilVerb(const std::string& lower) {
    static const char* const kVerbs[] = {
        "copy ", "copy-item", "xcopy", "robocopy", "move ", "move-item",
        "7z ", "zip ", "rar ", "tar ", "certutil", "curl", "wget",
        "upload", "type ", "cat ", "bitsadmin", "scp ",
    };
    for (const char* verb : kVerbs) {
        if (Contains(lower, verb)) return true;
    }
    return false;
}

bool EmailCollectionDetector::Analyze(const std::string& lower,
                                      const std::string& image,
                                      Finding* out) const {
    /* ExMerge: the classic Exchange mailbox extraction binary. */
    if (Contains(lower, "exmerge")) {
        *out = Finding{90, "exmerge mailbox extraction"};
        return true;
    }

    /* Exchange/Compliance search with an export sink. */
    const bool searchCmd = Contains(lower, "search-mailbox") ||
                           Contains(lower, "new-compliancesearch") ||
                           Contains(lower, "start-compliancesearch") ||
                           Contains(lower, "new-mailboxexportrequest") ||
                           Contains(lower, "new-exportrequest");
    const bool exportSink = Contains(lower, "-targetmailbox") ||
                            Contains(lower, "-targetmailboxfolder") ||
                            Contains(lower, "-mailbox") ||
                            Contains(lower, "export");
    if (searchCmd && exportSink) {
        *out = Finding{85, "exchange mailbox export"};
        return true;
    }

    /* Outlook COM automation bulk export: reach into MAPI folders and
     * write items out to disk. */
    if (Contains(lower, "outlook.application") &&
        (Contains(lower, "getdefaultfolder") ||
         Contains(lower, "getnamespace") ||
         Contains(lower, "items") || Contains(lower, "attachment")) &&
        (Contains(lower, "saveas") || Contains(lower, "copy") ||
         Contains(lower, "move ") || Contains(lower, "move(") ||
         Contains(lower, "export"))) {
        *out = Finding{75, "outlook com bulk export"};
        return true;
    }

    /* Mail store (.pst/.ost) touched by anything that is not the mail
     * client itself; an exfil verb raises the score. */
    if (HasMailStore(lower) && !IsMailClientImage(image)) {
        if (HasExfilVerb(lower)) {
            *out = Finding{80, "mail store copied by external process"};
            return true;
        }
        *out = Finding{70, "mail store referenced by external process"};
        return true;
    }

    return false;
}

void EmailCollectionDetector::Stamp(Event& event, const Finding& finding,
                                    const std::string& key) {
    event.fields[field::kEmailCollectionScore] =
        std::to_string(finding.score);
    event.fields[field::kEmailCollectionVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kEmailCollectionSignals] = finding.signal;
    event.fields[field::kEmailCollectionCommand] = key;
}

void EmailCollectionDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    const std::string image = [&event]() {
        auto imgIt = event.fields.find(field::kImage);
        return imgIt == event.fields.end() ? std::string() : imgIt->second;
    }();
    if (text.empty()) {
        if (image.empty()) return;
        text = image;
    }
    const std::string lower = ToLowerAscii(text);

    Finding finding;
    if (!Analyze(lower, image, &finding)) return;
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
                "[edr-email] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
