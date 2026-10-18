/*
 * wifi_cred_theft_detector.cpp - See wifi_cred_theft_detector.h.
 */
#include "wifi_cred_theft_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>

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

} // namespace

WifiCredTheftDetector::WifiCredTheftDetector(bool enabled,
                                             uint32_t windowSeconds,
                                             size_t stateCapacity,
                                             uint32_t minRepeatCount)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minRepeatCount(std::max<uint32_t>(2, minRepeatCount)) {}

bool WifiCredTheftDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool WifiCredTheftDetector::IsEnumerationCommand(
    const std::string& image, const std::string& commandLine,
    std::string* outTool) {
    const std::string base = LowerAscii(BaseNameOf(image));
    const std::string lower = LowerAscii(commandLine);

    if (base == "netsh.exe" && Contains(lower, "wlan") &&
        Contains(lower, "show profile")) {
        if (outTool) *outTool = "netsh_wlan_show";
        return true;
    }
    if (base == "cmdkey.exe" && Contains(lower, "/list")) {
        if (outTool) *outTool = "cmdkey_list";
        return true;
    }
    /* PowerShell reading saved credentials from the vault / RDP store. */
    if ((base == "powershell.exe" || base == "pwsh.exe") &&
        (Contains(lower, "cmdkey /list") ||
         Contains(lower, "cmdkey.exe /list") ||
         (Contains(lower, "get-storedcredential")))) {
        if (outTool) *outTool = "powershell_saved_creds";
        return true;
    }
    return false;
}

bool WifiCredTheftDetector::IsExportCommand(const std::string& image,
                                            const std::string& commandLine,
                                            bool* outKeyClear) {
    const std::string base = LowerAscii(BaseNameOf(image));
    if (base != "netsh.exe") return false;
    const std::string lower = LowerAscii(commandLine);
    if (!Contains(lower, "wlan") || !Contains(lower, "export profile"))
        return false;

    if (outKeyClear) {
        *outKeyClear = Contains(lower, "key=clear") ||
                       Contains(lower, "key = clear");
    }
    return true;
}

bool WifiCredTheftDetector::IsVaultCommand(const std::string& image,
                                           const std::string& commandLine,
                                           std::string* outTool) {
    const std::string base = LowerAscii(BaseNameOf(image));
    const std::string lower = LowerAscii(commandLine);

    if (base == "vaultcmd.exe" && Contains(lower, "/listcreds")) {
        if (outTool) *outTool = "vaultcmd_listcreds";
        return true;
    }
    /* CredentialManager PowerShell module (third-party, common in
     * collection tooling). */
    if ((base == "powershell.exe" || base == "pwsh.exe") &&
        (Contains(lower, "get-vaultcredential") ||
         Contains(lower, "import-module credentialmanager") ||
         Contains(lower, "import-module credentialmanager.psm1"))) {
        if (outTool) *outTool = "credentialmanager_module";
        return true;
    }
    /* RDP saved-credential harvest: cmdkey piped through grep/findstr. */
    if (Contains(lower, "cmdkey /list") &&
        (Contains(lower, "| findstr") || Contains(lower, "| grep") ||
         Contains(lower, "| select-string"))) {
        if (outTool) *outTool = "rdp_saved_creds";
        return true;
    }
    return false;
}

void WifiCredTheftDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_keys.begin(); it != m_keys.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_keys.erase(it);
        else
            ++it;
    }
}

uint32_t WifiCredTheftDetector::ComputeScore(const KeyState& state) const {
    uint32_t score = 0;
    if (state.sawProfileExport) score += 60;
    if (state.sawKeyClear) score += 30;
    if (state.sawVaultEnum) score += 75;
    if (state.sawCredmanModule) score += 70;
    if (state.sawRdpHarvest) score += 75;
    if (state.sawCmdkeyEnum) score += 55;
    if (state.enumCount >= m_minRepeatCount &&
        (state.sawCmdkeyEnum || !state.tools.empty()))
        score += 15;
    return std::min(100u, score);
}

std::string WifiCredTheftDetector::SignalList(const KeyState& state) const {
    std::string signals;
    const std::pair<bool, const char*> kFlags[] = {
        {state.sawProfileExport, "wifi_profile_export"},
        {state.sawKeyClear, "wifi_key_clear"},
        {state.sawVaultEnum, "vault_enum"},
        {state.sawCmdkeyEnum, "cmdkey_enum"},
        {state.sawCredmanModule, "credentialmanager_module"},
        {state.sawRdpHarvest, "rdp_saved_creds"},
        {state.enumCount >= m_minRepeatCount, "enum_repeat"},
    };
    for (const auto& entry : kFlags) {
        if (!entry.first) continue;
        if (!signals.empty()) signals += ",";
        signals += entry.second;
    }
    return signals;
}

std::string WifiCredTheftDetector::ToolList(const KeyState& state) const {
    std::string joined;
    for (const std::string& tool : state.tools) {
        if (!joined.empty()) joined += ",";
        joined += tool;
    }
    return joined;
}

void WifiCredTheftDetector::WriteState(Event& event,
                                       const KeyState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kWifiTheftScore] = std::to_string(score);
    event.fields[field::kWifiTheftSignals] = SignalList(state);
    event.fields[field::kWifiTheftTools] = ToolList(state);
    event.fields[field::kWifiTheftEnumCount] =
        std::to_string(state.enumCount);
    event.fields[field::kWifiTheftWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kWifiTheftVerdict] = verdict;
    }
}

void WifiCredTheftDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string image = FieldValue(event, field::kImage);
    const std::string commandLine =
        FieldValue(event, field::kCommandLine);
    if (image.empty() && commandLine.empty()) return;

    std::string key;
    if (event.pid > 0 && !image.empty()) {
        key = "pid:" + std::to_string(event.pid) + "@" +
              LowerAscii(BaseNameOf(image));
    } else if (!image.empty()) {
        key = "img:" + LowerAscii(BaseNameOf(image));
    } else {
        return; /* No attribution possible. */
    }

    bool touched = false;
    KeyState& state = m_keys[key];

    bool keyClear = false;
    if (IsExportCommand(image, commandLine, &keyClear)) {
        state.sawProfileExport = true;
        state.tools.insert("netsh_wlan_export");
        if (keyClear) {
            state.sawKeyClear = true;
            state.tools.insert("netsh_key_clear");
        }
        touched = true;
    }

    std::string tool;
    if (IsVaultCommand(image, commandLine, &tool)) {
        if (tool == "rdp_saved_creds") {
            state.sawRdpHarvest = true;
        } else if (tool == "credentialmanager_module") {
            state.sawCredmanModule = true;
        } else {
            state.sawVaultEnum = true;
        }
        state.tools.insert(tool);
        touched = true;
    }

    if (IsEnumerationCommand(image, commandLine, &tool)) {
        ++state.enumCount;
        state.tools.insert(tool);
        if (tool == "cmdkey_list") state.sawCmdkeyEnum = true;
        touched = true;
    }

    if (!touched) {
        if (state.lastSeen100ns == 0) m_keys.erase(key);
        return;
    }

    state.lastSeen100ns = now;
    WriteState(event, state);
    EvictOldest(m_keys, m_stateCapacity);
}

} // namespace edr
