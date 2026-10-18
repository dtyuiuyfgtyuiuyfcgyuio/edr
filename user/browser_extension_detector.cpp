/*
 * browser_extension_detector.cpp - Browser extension persistence detector
 * (MITRE T1176).
 */
#include "browser_extension_detector.h"

#include "json_lite.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <utility>
#include <vector>

namespace edr {
namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (Contains(value, needle)) return true;
    }
    return false;
}

bool IsRegistryTokenBoundary(char c) {
    return c == '\\' || c == '/' || c == '"' || c == '\'' || c == ':' ||
           c == '=' || c == ',' || c == '{' || c == '}' || c == '[' ||
           c == ']' || std::isspace(static_cast<unsigned char>(c));
}

bool ContainsRegistryToken(const std::string& text, const char* token) {
    const size_t length = std::strlen(token);
    size_t pos = 0;
    while ((pos = text.find(token, pos)) != std::string::npos) {
        const bool before = pos == 0 || IsRegistryTokenBoundary(text[pos - 1]);
        const size_t afterPos = pos + length;
        const bool after = afterPos == text.size() ||
                           IsRegistryTokenBoundary(text[afterPos]);
        if (before && after) return true;
        pos += length;
    }
    return false;
}

bool ContainsRegistryPathRoot(const std::string& text, const char* root) {
    const size_t length = std::strlen(root);
    size_t pos = 0;
    while ((pos = text.find(root, pos)) != std::string::npos) {
        const size_t after = pos + length;
        if (after == text.size() || IsRegistryTokenBoundary(text[after]))
            return true;
        pos += length;
    }
    return false;
}

std::string ToLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string FieldValue(const Event& event, const char* name) {
    const auto it = event.fields.find(name);
    return it == event.fields.end() ? std::string() : it->second;
}

std::string BaseName(std::string path) {
    while (!path.empty() &&
           (path.back() == '"' || path.back() == '\'' ||
            std::isspace(static_cast<unsigned char>(path.back())))) {
        path.pop_back();
    }
    const size_t slash = path.find_last_of("\\/");
    if (slash != std::string::npos) path = path.substr(slash + 1);
    while (!path.empty() && (path.front() == '"' || path.front() == '\''))
        path.erase(path.begin());
    return ToLowerAscii(path);
}

bool IsChromiumBrowser(const std::string& lowerImage) {
    const std::string image = BaseName(lowerImage);
    return image == "chrome.exe" || image == "msedge.exe" ||
           image == "chromium.exe" || image == "chromium-browser.exe" ||
           image == "brave.exe" || image == "brave-browser.exe" ||
           image == "vivaldi.exe";
}

std::string SwitchValue(const std::string& lowerText, const char* name) {
    size_t found = 0;
    const size_t nameLength = std::strlen(name);
    for (;;) {
        found = lowerText.find(name, found);
        if (found == std::string::npos) return {};
        const bool startBoundary =
            found == 0 ||
            std::isspace(static_cast<unsigned char>(lowerText[found - 1])) ||
            lowerText[found - 1] == '"' || lowerText[found - 1] == '\'';
        const size_t after = found + nameLength;
        const bool endBoundary =
            after == lowerText.size() || lowerText[after] == '=' ||
            std::isspace(static_cast<unsigned char>(lowerText[after]));
        if (startBoundary && endBoundary) break;
        found += nameLength;
    }

    size_t pos = found + nameLength;
    while (pos < lowerText.size() &&
           std::isspace(static_cast<unsigned char>(lowerText[pos]))) {
        ++pos;
    }
    if (pos < lowerText.size() && lowerText[pos] == '=') {
        ++pos;
        while (pos < lowerText.size() &&
               std::isspace(static_cast<unsigned char>(lowerText[pos]))) {
            ++pos;
        }
    }
    if (pos >= lowerText.size()) return {};

    const char quote =
        (lowerText[pos] == '"' || lowerText[pos] == '\'')
            ? lowerText[pos++] : '\0';
    const size_t begin = pos;
    if (quote != '\0') {
        const size_t end = lowerText.find(quote, begin);
        return lowerText.substr(begin, end == std::string::npos
            ? std::string::npos : end - begin);
    }
    while (pos < lowerText.size() &&
           !std::isspace(static_cast<unsigned char>(lowerText[pos]))) {
        ++pos;
    }
    return lowerText.substr(begin, pos - begin);
}

std::string NormalizePathSeparators(std::string value) {
    std::replace(value.begin(), value.end(), '/', '\\');
    return value;
}

bool IsUserWritablePath(const std::string& lowerPath) {
    const std::string normalized = NormalizePathSeparators(lowerPath);
    return ContainsAny(normalized,
        {"\\users\\", "\\appdata\\", "\\downloads\\",
         "\\desktop\\", "\\public\\", "\\programdata\\",
         "\\windows\\temp\\", "c:\\temp\\", "%userprofile%",
         "%localappdata%", "%appdata%", "%temp%",
         "$env:userprofile", "$env:localappdata", "$env:appdata",
         "$env:temp"});
}

bool IsRiskyExtensionPath(const std::string& lowerPath) {
    size_t begin = 0;
    do {
        const size_t comma = lowerPath.find(',', begin);
        const std::string item = NormalizePathSeparators(lowerPath.substr(
            begin, comma == std::string::npos ? std::string::npos
                                               : comma - begin));
        if (IsUserWritablePath(item) || item.rfind("\\\\", 0) == 0)
            return true;
        /* Relative extension paths inherit the browser's working directory
         * and are easier to replace than an absolute, owned path. */
        const bool trustedEnvironmentRoot =
            item.rfind("%programfiles%", 0) == 0 ||
            item.rfind("%programfiles(x86)%", 0) == 0 ||
            item.rfind("%windir%", 0) == 0;
        if (item.find(":\\") == std::string::npos &&
            item.find(":/") == std::string::npos &&
            item.rfind("/", 0) != 0 && !trustedEnvironmentRoot) return true;
        if (comma == std::string::npos) break;
        begin = comma + 1;
    } while (begin < lowerPath.size());
    return false;
}

std::string NormalizePathList(std::string value) {
    value.erase(std::remove_if(value.begin(), value.end(),
        [](unsigned char c) { return c == '"' || c == '\'' || c == ' '; }),
        value.end());
    value = NormalizePathSeparators(std::move(value));
    while (!value.empty() && (value.back() == '\\' || value.back() == '/'))
        value.pop_back();
    return value;
}

bool IsReadOnlyRegistryQuery(const std::string& lowerText) {
    const bool read = ContainsAny(lowerText,
        {"reg query", "reg.exe query", "get-itemproperty",
         "get-item ", "get-item\t", "get-childitem", "test-path"});
    if (!read) return false;
    return !ContainsAny(lowerText,
        {"reg add", "reg.exe add", "reg import", "reg.exe import",
         "set-itemproperty", "new-itemproperty", "new-item ",
         "new-item\t", "set-gpregistryvalue", ".setvalue("});
}

bool HasRegistryWriteIntent(const std::string& lowerText) {
    return ContainsAny(lowerText,
        {"reg add", "reg.exe add", "reg import", "reg.exe import",
         "set-itemproperty", "new-itemproperty", "new-item ",
         "new-item\t", "set-gpregistryvalue", ".setvalue("});
}

bool IsBrowserPolicyRoot(const std::string& lowerText) {
    return ContainsRegistryPathRoot(
               lowerText, "\\policies\\google\\chrome") ||
           ContainsRegistryPathRoot(
               lowerText, "\\policies\\microsoft\\edge") ||
           ContainsRegistryPathRoot(lowerText, "\\policies\\chromium");
}

bool IsExternalExtensionKey(const std::string& lowerText) {
    if (Contains(lowerText, "\\policies\\")) return false;
    return ContainsAny(lowerText,
        {"\\google\\chrome\\extensions\\",
         "\\microsoft\\edge\\extensions\\",
         "\\chromium\\extensions\\"});
}

bool IsDeleteOperation(const std::string& operation) {
    return ContainsAny(operation,
        {"delete", "removed", "remove"});
}

bool IsRenameOperation(const std::string& operation) {
    return Contains(operation, "rename");
}

bool IsUserHive(const std::string& lowerKey) {
    return ContainsAny(lowerKey,
        {"hkcu\\", "hkcu:\\", "hkey_current_user\\",
         "hkey_current_user:\\", "hku\\", "hku:\\",
         "hkey_users\\", "hkey_users:\\", "\\registry\\user\\"});
}

std::string BrowserKind(const std::string& lowerKey) {
    if (Contains(lowerKey, "\\microsoft\\edge\\") ||
        Contains(lowerKey, "\\microsoft\\edge")) return "edge";
    if (Contains(lowerKey, "\\google\\chrome\\") ||
        Contains(lowerKey, "\\google\\chrome")) return "chrome";
    if (Contains(lowerKey, "\\chromium\\") ||
        Contains(lowerKey, "\\chromium")) return "chromium";
    return {};
}

std::string ExtractExtensionId(const std::string& lowerText) {
    for (size_t i = 0; i + 32 <= lowerText.size(); ++i) {
        bool valid = true;
        for (size_t j = 0; j < 32; ++j) {
            if (lowerText[i + j] < 'a' || lowerText[i + j] > 'p') {
                valid = false;
                break;
            }
        }
        if (!valid) continue;
        const bool before = i == 0 || lowerText[i - 1] < 'a' ||
                            lowerText[i - 1] > 'p';
        const bool after = i + 32 == lowerText.size() ||
                           lowerText[i + 32] < 'a' ||
                           lowerText[i + 32] > 'p';
        if (before && after) return lowerText.substr(i, 32);
    }
    return {};
}

bool IsExtensionId(const std::string& value) {
    if (value.size() != 32) return false;
    return std::all_of(value.begin(), value.end(), [](char c) {
        return c >= 'a' && c <= 'p';
    });
}

std::string FirstUrlHost(const std::string& lowerText) {
    size_t scheme = lowerText.find("https://");
    size_t schemeLength = 8;
    const size_t http = lowerText.find("http://");
    if (http != std::string::npos &&
        (scheme == std::string::npos || http < scheme)) {
        scheme = http;
        schemeLength = 7;
    }
    if (scheme == std::string::npos) return {};
    size_t begin = scheme + schemeLength;
    size_t end = begin;
    while (end < lowerText.size()) {
        const char c = lowerText[end];
        if (c == '/' || c == ':' || c == ';' || c == '"' || c == '\'' ||
            c == ',' || c == '}' ||
            std::isspace(static_cast<unsigned char>(c))) break;
        ++end;
    }
    if (end == begin) return {};
    std::string host = lowerText.substr(begin, end - begin);
    const size_t at = host.rfind('@');
    if (at != std::string::npos) host = host.substr(at + 1);
    return host;
}

std::string DefaultUpdateHost(const std::string& browser) {
    if (browser == "chrome" || browser == "chromium")
        return "clients2.google.com";
    if (browser == "edge") return "edge.microsoft.com";
    return {};
}

bool IsOfficialUpdateHost(const std::string& browser,
                          const std::string& host) {
    return !host.empty() && host == DefaultUpdateHost(browser);
}

bool HasLocalPathData(const std::string& lowerValue) {
    const std::string normalized = NormalizePathSeparators(lowerValue);
    const size_t firstPercent = normalized.find('%');
    const bool hasEnvironmentExpansion = firstPercent != std::string::npos &&
        normalized.find('%', firstPercent + 1) != std::string::npos;
    return normalized.find(":\\") != std::string::npos ||
           normalized.rfind("\\\\", 0) == 0 ||
           hasEnvironmentExpansion ||
           ContainsAny(normalized,
               {"%userprofile%", "%appdata%", "%localappdata%",
                "%programdata%", "$env:"});
}

struct ExtensionSetting {
    std::string extensionId;
    std::string updateHost;
    bool hasUpdateUrl = false;
};

bool FindJsonObjectEnd(const std::string& text, size_t begin, size_t* end,
                       size_t* scanBudget) {
    size_t depth = 0;
    bool inString = false;
    bool escaped = false;
    for (size_t i = begin; i < text.size(); ++i) {
        if (*scanBudget == 0) return false;
        --*scanBudget;
        const char c = text[i];
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                inString = false;
            }
            continue;
        }
        if (c == '"') {
            inString = true;
        } else if (c == '{') {
            ++depth;
        } else if (c == '}') {
            if (depth == 0) return false;
            if (--depth == 0) {
                *end = i;
                return true;
            }
        }
    }
    return false;
}

bool CollectExtensionSettings(const jsonlite::Value& root,
                              std::vector<ExtensionSetting>* forced) {
    if (root.type != jsonlite::Type::Object) return false;

    bool recognized = false;
    for (const auto& item : root.object) {
        const std::string extensionId = ToLowerAscii(item.first);
        if (extensionId != "*" && !IsExtensionId(extensionId)) continue;
        if (item.second.type != jsonlite::Type::Object) continue;

        const jsonlite::Value* mode = item.second.find("installation_mode");
        if (mode == nullptr || mode->type != jsonlite::Type::String) continue;
        recognized = true;
        if (ToLowerAscii(mode->str) != "force_installed") continue;

        ExtensionSetting setting;
        setting.extensionId = extensionId;
        const jsonlite::Value* updateUrl = item.second.find("update_url");
        if (updateUrl != nullptr && updateUrl->type == jsonlite::Type::String &&
            !updateUrl->str.empty()) {
            setting.hasUpdateUrl = true;
            setting.updateHost = FirstUrlHost(ToLowerAscii(updateUrl->str));
        }
        forced->push_back(std::move(setting));
    }
    return recognized;
}

bool ParseExtensionSettings(const std::string& lowerText,
                            std::vector<ExtensionSetting>* forced) {
    bool recognized = false;
    size_t search = 0;
    /* Script text may contain non-JSON braces around the actual policy
     * value. Bound candidate scans so malformed, deeply nested telemetry
     * cannot turn parsing into quadratic work on the EventBus thread. */
    size_t scanBudget = lowerText.size() * 4 + 1;
    while ((search = lowerText.find('{', search)) != std::string::npos) {
        size_t end = 0;
        if (!FindJsonObjectEnd(lowerText, search, &end, &scanBudget)) break;
        try {
            const jsonlite::Value root = jsonlite::parse(
                lowerText.substr(search, end - search + 1));
            if (CollectExtensionSettings(root, forced)) {
                recognized = true;
            } else if (root.type == jsonlite::Type::Object) {
                const jsonlite::Value* nested = root.find("extensionsettings");
                if (nested != nullptr &&
                    CollectExtensionSettings(*nested, forced)) {
                    recognized = true;
                }
            }
            search = end + 1;
        } catch (const jsonlite::ParseError&) {
            ++search;
        }
    }
    return recognized;
}

std::string JoinText(const std::string& first, const std::string& second) {
    if (first.empty()) return second;
    if (second.empty()) return first;
    return first + " " + second;
}

std::string Truncate(const std::string& value, size_t limit) {
    return value.size() <= limit ? value : value.substr(0, limit);
}

} // namespace

BrowserExtensionDetector::BrowserExtensionDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity, const std::vector<std::string>& allowlist)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {
    for (const std::string& entry : allowlist)
        m_allowlist.insert(ToLowerAscii(entry));
}

/* static */
bool BrowserExtensionDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool BrowserExtensionDetector::AnalyzeBrowserLaunch(
    const std::string& lowerImage, const std::string& lowerText,
    Finding* out) const {
    if (!IsChromiumBrowser(lowerImage)) return false;

    const std::string loadPath = SwitchValue(lowerText, "--load-extension");
    if (loadPath.empty()) return false;

    uint32_t score = 60;
    const bool riskyPath = IsRiskyExtensionPath(loadPath);
    if (riskyPath) score += 20;

    const std::string allowedPath =
        SwitchValue(lowerText, "--disable-extensions-except");
    const bool isolatedByMatchingSwitch = !allowedPath.empty() &&
        NormalizePathList(allowedPath) == NormalizePathList(loadPath);
    if (isolatedByMatchingSwitch) {
        score += 10;
    }
    score = std::min(100u, score);
    if (riskyPath && isolatedByMatchingSwitch)
        *out = Finding{score, "risky unpacked extension isolated by switch"};
    else if (riskyPath)
        *out = Finding{score, "unpacked extension loaded from risky path"};
    else
        *out = Finding{score, "unpacked browser extension loaded"};
    return true;
}

bool BrowserExtensionDetector::AnalyzeRegistryWrite(
    const std::string& lowerKey, const std::string& lowerValue,
    bool scriptedWrite, Finding* out) const {
    const std::string combined = JoinText(lowerKey, lowerValue);
    const std::string browser = BrowserKind(lowerKey);
    const std::string extensionId = ExtractExtensionId(combined);
    const std::string observedUpdateHost = FirstUrlHost(lowerValue);

    const bool userHive = IsUserHive(lowerKey);

    if (IsBrowserPolicyRoot(lowerKey) &&
        ContainsRegistryToken(lowerKey, "extensioninstallforcelist")) {
        if (extensionId.empty()) {
            *out = Finding{40, "browser force-install policy touched"};
            return true;
        }
        const size_t idAt = lowerValue.find(extensionId);
        const size_t separator = idAt == std::string::npos
            ? std::string::npos
            : lowerValue.find(';', idAt + extensionId.size());
        const bool hasExplicitUpdate = idAt != std::string::npos &&
            separator == idAt + extensionId.size() &&
            separator + 1 < lowerValue.size() &&
            !std::isspace(static_cast<unsigned char>(
                lowerValue[separator + 1]));
        const std::string policyUpdateHost = hasExplicitUpdate
            ? FirstUrlHost(lowerValue.substr(separator + 1)) : std::string();
        const std::string expectedHost = hasExplicitUpdate
            ? policyUpdateHost : DefaultUpdateHost(browser);
        if (IsAllowlisted(browser, extensionId, expectedHost)) return false;
        const bool customUpdate = hasExplicitUpdate &&
            !IsOfficialUpdateHost(browser, policyUpdateHost);
        uint32_t score = 65 + (userHive ? 10u : 0u) +
                         (customUpdate ? 15u : 0u) +
                         (scriptedWrite ? 10u : 0u);
        *out = Finding{std::min(100u, score),
                       "forced browser extension policy written"};
        return true;
    }
    if (IsBrowserPolicyRoot(lowerKey) &&
        (ContainsRegistryToken(lowerKey, "extensionsettings") ||
         ContainsRegistryToken(lowerValue, "extensionsettings"))) {
        std::vector<ExtensionSetting> forced;
        if (!ParseExtensionSettings(lowerValue, &forced)) {
            *out = Finding{40, "browser ExtensionSettings policy touched"};
            return true;
        }
        if (forced.empty()) return false;

        bool hasUnapproved = false;
        bool customUpdate = false;
        for (const ExtensionSetting& setting : forced) {
            const std::string expectedHost = setting.hasUpdateUrl
                ? setting.updateHost : DefaultUpdateHost(browser);
            if (IsExtensionId(setting.extensionId) &&
                IsAllowlisted(browser, setting.extensionId, expectedHost)) {
                continue;
            }
            hasUnapproved = true;
            if (setting.hasUpdateUrl &&
                !IsOfficialUpdateHost(browser, setting.updateHost)) {
                customUpdate = true;
            }
        }
        if (!hasUnapproved) return false;
        uint32_t score = 70 + (userHive ? 10u : 0u) +
                         (customUpdate ? 15u : 0u) +
                         (scriptedWrite ? 10u : 0u);
        *out = Finding{std::min(100u, score),
                       "force-installed ExtensionSettings policy written"};
        return true;
    }
    if (IsExternalExtensionKey(lowerKey)) {
        const bool hasPath = HasLocalPathData(lowerValue);
        const bool hasUrl = !observedUpdateHost.empty();
        if (hasUrl && IsAllowlisted(
                browser, extensionId, observedUpdateHost)) return false;
        if (extensionId.empty() || (!hasPath && !hasUrl)) {
            *out = Finding{extensionId.empty() ? 50u : 40u,
                           "external extension registry key touched"};
            return true;
        }
        const bool customUpdate = hasUrl &&
            !IsOfficialUpdateHost(browser, observedUpdateHost);
        uint32_t score = 70 + (userHive ? 10u : 0u) +
                         (scriptedWrite ? 10u : 0u);
        if ((hasPath && IsRiskyExtensionPath(lowerValue)) || customUpdate)
            score += 20;
        *out = Finding{std::min(100u, score),
                       "external browser extension registered"};
        return true;
    }
    return false;
}

bool BrowserExtensionDetector::IsAllowlisted(
    const std::string& browser, const std::string& extensionId,
    const std::string& updateHost) const {
    if (browser.empty() || extensionId.empty() || updateHost.empty())
        return false;
    return m_allowlist.find(browser + ":" + extensionId + "@" +
                            updateHost) != m_allowlist.end();
}

bool BrowserExtensionDetector::IsDuplicate(const std::string& key,
                                            uint64_t now100ns) {
    if (m_stateCapacity == 0) return false;

    auto existing = m_lastAlert.find(key);
    if (existing != m_lastAlert.end()) {
        const uint64_t previous = existing->second;
        if (m_dedupWindow100ns != 0 && now100ns >= previous &&
            now100ns - previous < m_dedupWindow100ns) {
            return true;
        }
        existing->second = now100ns;
        return false;
    }

    if (m_lastAlert.size() >= m_stateCapacity) {
        const auto oldest = std::min_element(
            m_lastAlert.begin(), m_lastAlert.end(),
            [](const auto& left, const auto& right) {
                return left.second < right.second;
            });
        if (oldest != m_lastAlert.end()) m_lastAlert.erase(oldest);
    }
    m_lastAlert.emplace(key, now100ns);
    return false;
}

void BrowserExtensionDetector::Stamp(Event& event, const Finding& finding,
                                     const std::string& evidence) {
    event.fields[field::kBrowserExtensionScore] =
        std::to_string(finding.score);
    if (finding.score >= 75)
        event.fields[field::kBrowserExtensionVerdict] = "malicious";
    else if (finding.score >= 55)
        event.fields[field::kBrowserExtensionVerdict] = "suspicious";
    event.fields[field::kBrowserExtensionSignals] = finding.signal;
    event.fields[field::kBrowserExtensionEvidence] = Truncate(evidence, 512);
}

void BrowserExtensionDetector::Enrich(Event& event) {
    if (!m_enabled || !Inspects(event.type)) return;

    std::string evidence;
    std::string safeEvidence;
    std::string image;
    bool registryEvent = false;

    if (event.type == EDR_EVT_REG_WRITE) {
        const std::string key = FieldValue(event, field::kRegKey);
        if (key.empty()) return;
        evidence = FieldValue(event, field::kRegValue);
        safeEvidence = key;
        registryEvent = true;
    } else {
        image = FieldValue(event, field::kImage);
        if (image.empty()) image = FieldValue(event, field::kImagePath);
        evidence = FieldValue(event, field::kCommandLine);
        if (event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            evidence = JoinText(evidence,
                FieldValue(event, field::kScriptBlockText));
        }
    }
    if (evidence.empty() && !registryEvent) return;

    const std::string lowerText = ToLowerAscii(evidence);
    const std::string lowerImage = ToLowerAscii(image);
    Finding finding;

    bool matched = AnalyzeBrowserLaunch(lowerImage, lowerText, &finding);
    if (matched) {
        safeEvidence = BaseName(lowerImage) + " --load-extension=" +
            Truncate(SwitchValue(lowerText, "--load-extension"), 320);
    }
    if (!matched) {
        if (registryEvent) {
            const std::string operation = ToLowerAscii(
                FieldValue(event, field::kRegOperation));
            if (IsDeleteOperation(operation)) return;
            if (IsRenameOperation(operation)) {
                const std::string newTarget =
                    FieldValue(event, field::kRegNewTarget);
                if (newTarget.empty()) return;
                const std::string lowerNewTarget = ToLowerAscii(newTarget);
                const bool policyActivation =
                    IsBrowserPolicyRoot(lowerNewTarget) &&
                    (ContainsRegistryToken(lowerNewTarget,
                         "extensioninstallforcelist") ||
                     ContainsRegistryToken(lowerNewTarget,
                         "extensionsettings"));
                const bool externalActivation =
                    IsExternalExtensionKey(lowerNewTarget) &&
                    !ExtractExtensionId(lowerNewTarget).empty();
                if (!policyActivation && !externalActivation) return;
                const uint32_t score = 70 +
                    (IsUserHive(lowerNewTarget) ? 10u : 0u);
                finding = Finding{
                    score,
                    policyActivation
                        ? "browser extension policy activated by registry rename"
                        : "external browser extension activated by registry rename"
                };
                safeEvidence = newTarget;
                matched = true;
            } else {
                matched = AnalyzeRegistryWrite(
                    ToLowerAscii(safeEvidence), lowerText, false, &finding);
            }
        } else {
            if (IsReadOnlyRegistryQuery(lowerText) ||
                !HasRegistryWriteIntent(lowerText)) {
                return;
            }
            matched = AnalyzeRegistryWrite(
                lowerText, lowerText, true, &finding);
            safeEvidence = finding.signal;
        }
    }
    if (!matched || finding.score < m_minScore) return;

    const std::string dedupKey = std::string(finding.signal) + ":" +
        Truncate(ToLowerAscii(safeEvidence), 512) + ":" +
        std::to_string(std::hash<std::string>{}(lowerText));
    if (IsDuplicate(dedupKey, event.ts100ns)) return;
    Stamp(event, finding, safeEvidence);
}

} // namespace edr
