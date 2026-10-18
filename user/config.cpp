#include "config.h"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <cmath>
#include <limits>
#include <sstream>
#include <utility>

#include "json_lite.h"

namespace edr {

std::string WideToUtf8(const wchar_t* wide, size_t len) {
    if (wide == nullptr) {
        return std::string();
    }
    int srcLen = (len == (size_t)-1) ? -1 : (int)len;
    int needed = WideCharToMultiByte(CP_UTF8, 0, wide, srcLen, nullptr, 0,
                                     nullptr, nullptr);
    if (needed <= 0) {
        return std::string();
    }
    /* With srcLen == -1 the count includes the terminating null; drop it so
     * the returned string compares equal to plain C string literals. */
    if (srcLen == -1) {
        needed--;
    }
    std::string out((size_t)needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, srcLen, out.data(), needed,
                        nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) {
        return std::wstring();
    }
    int needed = MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
                                     (int)utf8.size(), nullptr, 0);
    if (needed <= 0) {
        return std::wstring();
    }
    std::wstring out((size_t)needed, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(),
                        out.data(), needed);
    return out;
}

std::string ExpandEnvStrings(const std::string& in) {
    std::wstring wide = Utf8ToWide(in);
    wchar_t buf[32768];
    DWORD n = ExpandEnvironmentStringsW(wide.c_str(), buf, (DWORD)std::size(buf));
    if (n == 0 || n > std::size(buf)) {
        return in;
    }
    return WideToUtf8(buf, n - 1);
}

static uint32_t BoundedUInt(const jsonlite::Value& value, const char* name,
                           uint32_t minimum, uint32_t maximum) {
    if (value.type != jsonlite::Type::Number || !std::isfinite(value.number) ||
        value.number < minimum || value.number > maximum ||
        std::floor(value.number) != value.number) {
        throw jsonlite::ParseError(std::string("config value '") + name +
                                   "' must be an integer in [" +
                                   std::to_string(minimum) + ", " +
                                   std::to_string(maximum) + "]");
    }
    return static_cast<uint32_t>(value.number);
}

static uint64_t BoundedUInt64(const jsonlite::Value& value, const char* name,
                              uint64_t minimum, uint64_t maximum) {
    if (value.type != jsonlite::Type::Number || !std::isfinite(value.number) ||
        value.number < static_cast<double>(minimum) ||
        value.number > static_cast<double>(maximum) ||
        std::floor(value.number) != value.number) {
        throw jsonlite::ParseError(std::string("config value '") + name +
            "' must be an integer in [" + std::to_string(minimum) + ", " +
            std::to_string(maximum) + "]");
    }
    return static_cast<uint64_t>(value.number);
}

static bool Boolean(const jsonlite::Value& value, const char* name) {
    if (value.type != jsonlite::Type::Bool)
        throw jsonlite::ParseError(std::string("config value '") + name +
                                   "' must be boolean");
    return value.boolean;
}

static std::string String(const jsonlite::Value& value, const char* name) {
    if (value.type != jsonlite::Type::String)
        throw jsonlite::ParseError(std::string("config value '") + name +
                                   "' must be a string");
    return value.str;
}

static std::string ExpandedPath(const jsonlite::Value& value, const char* name) {
    const auto raw = String(value, name);
    if (raw.find('\0') != std::string::npos)
        throw jsonlite::ParseError(std::string("config path '") + name + "' contains NUL");
    return ExpandEnvStrings(raw);
}

static std::wstring SpoolDirectoryPath(const std::string& input) {
    if (input.empty() || input.size() > 32760 || input.find('\0') != std::string::npos ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                           static_cast<int>(input.size()), nullptr, 0) <= 0)
        throw jsonlite::ParseError("reporter spool directories must be valid absolute UTF-8 paths");
    const auto path = Utf8ToWide(input);
    if (path.size() < 4 || path[1] != L':' ||
        (path[2] != L'\\' && path[2] != L'/') ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')))
        throw jsonlite::ParseError("reporter spool directories require an absolute drive path below the root");
    const DWORD length = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (!length || length > 32768) throw jsonlite::ParseError("invalid reporter spool directory");
    std::wstring full(length, L'\0');
    const DWORD written = GetFullPathNameW(path.c_str(), length, &full[0], nullptr);
    if (!written || written >= length) throw jsonlite::ParseError("invalid reporter spool directory");
    full.resize(written);
    while (full.size() > 3 && (full.back() == L'\\' || full.back() == L'/')) full.pop_back();
    if (full.size() <= 3) throw jsonlite::ParseError("reporter spool directory cannot be a drive root");
    return full;
}

static std::string BrowserExtensionAllowlistEntry(
    const jsonlite::Value& value, const char* name) {
    const std::string entry = String(value, name);
    const size_t colon = entry.find(':');
    const size_t at = entry.find('@', colon == std::string::npos ? 0
                                                                 : colon + 1);
    if (colon == std::string::npos || at == std::string::npos ||
        entry.find(':', colon + 1) != std::string::npos ||
        entry.find('@', at + 1) != std::string::npos) {
        throw jsonlite::ParseError(std::string("config value '") + name +
            "' must use browser:extension_id@update_host");
    }
    const std::string browser = entry.substr(0, colon);
    const std::string extensionId = entry.substr(colon + 1, at - colon - 1);
    const std::string host = entry.substr(at + 1);
    if (browser != "chrome" && browser != "edge" &&
        browser != "chromium") {
        throw jsonlite::ParseError(std::string("config value '") + name +
            "' browser must be chrome, edge, or chromium");
    }
    if (extensionId.size() != 32 ||
        !std::all_of(extensionId.begin(), extensionId.end(),
            [](char c) { return c >= 'a' && c <= 'p'; })) {
        throw jsonlite::ParseError(std::string("config value '") + name +
            "' extension_id must be 32 lowercase characters in [a-p]");
    }
    if (host.empty() || !std::all_of(host.begin(), host.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                   c == '.' || c == '-';
        })) {
        throw jsonlite::ParseError(std::string("config value '") + name +
            "' update_host must be a lowercase hostname without a URL path");
    }
    return entry;
}

static void ApplyValue(const jsonlite::Value& root, Config& cfg) {
    using jsonlite::Value;
    if (const Value* replay = root.find("event_log_replay")) {
        if (replay->type != jsonlite::Type::Object)
            throw jsonlite::ParseError("event_log_replay must be an object");
        for (const auto& item : replay->object)
            if (item.first != "enable" && item.first != "checkpoint_directory" &&
                item.first != "max_pending_records")
                throw jsonlite::ParseError("unknown event_log_replay value '" + item.first + "'");
        if (const Value* item = replay->find("enable"))
            cfg.eventLogReplayEnable = Boolean(*item, "event_log_replay.enable");
        if (const Value* item = replay->find("checkpoint_directory"))
            cfg.eventLogReplayCheckpointDirectory = ExpandedPath(*item, "event_log_replay.checkpoint_directory");
        if (const Value* item = replay->find("max_pending_records"))
            cfg.eventLogReplayMaxPendingRecords = BoundedUInt(*item, "event_log_replay.max_pending_records", 0, 8200);
        if (cfg.eventLogReplayEnable) {
            const auto path = SpoolDirectoryPath(cfg.eventLogReplayCheckpointDirectory);
            cfg.eventLogReplayCheckpointDirectory = WideToUtf8(path.c_str());
        }
    }
    if (const Value* v = root.find("enable_driver_collector")) {
        cfg.enableDriverCollector = Boolean(*v, "enable_driver_collector");
    }
    if (const Value* v = root.find("enable_file_fallback")) {
        cfg.enableFileFallback = Boolean(*v, "enable_file_fallback");
    }
    if (const Value* v = root.find("enable_net_fallback")) {
        cfg.enableNetFallback = Boolean(*v, "enable_net_fallback");
    }
    if (const Value* v = root.find("enable_net_etw")) {
        cfg.enableNetEtw = Boolean(*v, "enable_net_etw");
    }
    if (const Value* v = root.find("net_etw_udp")) {
        cfg.netEtwUdp = Boolean(*v, "net_etw_udp");
    }
    if (const Value* v = root.find("enable_reg_baseline")) {
        cfg.enableRegBaseline = Boolean(*v, "enable_reg_baseline");
    }
    if (const Value* v = root.find("enable_reg_watch")) {
        cfg.enableRegWatch = Boolean(*v, "enable_reg_watch");
    }
    if (const Value* v = root.find("enable_proc_etw")) {
        cfg.enableProcEtw = Boolean(*v, "enable_proc_etw");
    }
    if (const Value* v = root.find("enable_rat_analyzer")) {
        cfg.ratAnalyzerEnable = Boolean(*v, "enable_rat_analyzer");
    }
    if (const Value* v = root.find("rat_analyzer_scan_interval_seconds")) {
        cfg.ratAnalyzerScanIntervalSeconds = BoundedUInt(
            *v, "rat_analyzer_scan_interval_seconds", 5, 3600);
    }
    if (const Value* v = root.find("rat_analyzer_min_score")) {
        cfg.ratAnalyzerMinScore = BoundedUInt(
            *v, "rat_analyzer_min_score", 1, 100);
    }
    if (const Value* v = root.find("rat_analyzer_dedup_window_seconds")) {
        cfg.ratAnalyzerDedupWindowSeconds = BoundedUInt(
            *v, "rat_analyzer_dedup_window_seconds", 30, 86400);
    }
    if (const Value* v = root.find("rat_analyzer_state_capacity")) {
        cfg.ratAnalyzerStateCapacity = BoundedUInt(
            *v, "rat_analyzer_state_capacity", 128, 65536);
    }
    if (const Value* v = root.find("enable_imonitor")) {
        cfg.enableIMonitor = Boolean(*v, "enable_imonitor");
    }
    if (const Value* v = root.find("enable_sysmon")) {
        cfg.enableSysmon = Boolean(*v, "enable_sysmon");
    }
    if (const Value* v = root.find("enable_sysmon_image_load")) {
        cfg.enableSysmonImageLoad = Boolean(*v, "enable_sysmon_image_load");
    }
    if (const Value* v = root.find("enable_sysmon_process_access")) {
        cfg.enableSysmonProcessAccess = Boolean(*v,
            "enable_sysmon_process_access");
    }
    if (const Value* v = root.find("enable_sysmon_remote_thread")) {
        cfg.enableSysmonRemoteThread = Boolean(*v,
            "enable_sysmon_remote_thread");
    }
    if (const Value* v = root.find("enable_imonitor_process_open")) {
        cfg.enableIMonitorProcessOpen = Boolean(*v,
            "enable_imonitor_process_open");
    }
    if (const Value* v = root.find("enable_imonitor_remote_thread")) {
        cfg.enableIMonitorRemoteThread = Boolean(*v,
            "enable_imonitor_remote_thread");
    }
    if (const Value* v = root.find("enable_imonitor_credential_monitor")) {
        cfg.enableIMonitorCredentialMonitor = Boolean(*v,
            "enable_imonitor_credential_monitor");
    }
    if (const Value* v = root.find("enable_imonitor_injection_deep")) {
        cfg.enableIMonitorInjectionDeep = Boolean(*v,
            "enable_imonitor_injection_deep");
    }
    if (const Value* v = root.find("enable_security_log")) {
        cfg.enableSecurityLog = Boolean(*v, "enable_security_log");
    }
    if (const Value* v = root.find("security_log_queue_capacity")) {
        cfg.securityLogQueueCapacity = BoundedUInt(*v,
            "security_log_queue_capacity", 64, 8192);
    }
    if (const Value* v = root.find("security_log_workers")) {
        cfg.securityLogWorkers = BoundedUInt(*v,
            "security_log_workers", 1, 8);
    }
    if (const Value* v = root.find("security_log_max_xml_bytes")) {
        cfg.securityLogMaxXmlBytes = BoundedUInt(*v,
            "security_log_max_xml_bytes", 4096, 1024 * 1024);
    }
    if (const Value* v = root.find("enable_wmi_collector")) {
        cfg.enableWmiCollector = Boolean(*v, "enable_wmi_collector");
    }
    if (const Value* v = root.find("wmi_queue_capacity")) {
        cfg.wmiQueueCapacity = BoundedUInt(*v,
            "wmi_queue_capacity", 64, 8192);
    }
    if (const Value* v = root.find("wmi_workers")) {
        cfg.wmiWorkers = BoundedUInt(*v, "wmi_workers", 1, 8);
    }
    if (const Value* v = root.find("wmi_max_xml_bytes")) {
        cfg.wmiMaxXmlBytes = BoundedUInt(*v,
            "wmi_max_xml_bytes", 4096, 512 * 1024);
    }
    if (const Value* v = root.find("enable_taskscheduler_log")) {
        cfg.enableTaskSchedulerLog = Boolean(*v, "enable_taskscheduler_log");
    }
    if (const Value* v = root.find("taskscheduler_queue_capacity")) {
        cfg.taskSchedulerQueueCapacity = BoundedUInt(*v,
            "taskscheduler_queue_capacity", 64, 8192);
    }
    if (const Value* v = root.find("taskscheduler_workers")) {
        cfg.taskSchedulerWorkers = BoundedUInt(*v,
            "taskscheduler_workers", 1, 8);
    }
    if (const Value* v = root.find("taskscheduler_max_xml_bytes")) {
        cfg.taskSchedulerMaxXmlBytes = BoundedUInt(*v,
            "taskscheduler_max_xml_bytes", 4096, 256 * 1024);
    }
    if (const Value* v = root.find("enable_defender_log")) {
        cfg.enableDefenderLog = Boolean(*v, "enable_defender_log");
    }
    if (const Value* v = root.find("enable_rdp_log")) {
        cfg.enableRdpLog = Boolean(*v, "enable_rdp_log");
    }
    if (const Value* v = root.find("rdp_queue_capacity")) {
        cfg.rdpLogQueueCapacity = BoundedUInt(*v,
            "rdp_queue_capacity", 64, 8192);
    }
    if (const Value* v = root.find("rdp_workers")) {
        cfg.rdpLogWorkers = BoundedUInt(*v, "rdp_workers", 1, 8);
    }
    if (const Value* v = root.find("rdp_max_xml_bytes")) {
        cfg.rdpLogMaxXmlBytes = BoundedUInt(*v,
            "rdp_max_xml_bytes", 4096, 256 * 1024);
    }
    if (const Value* v = root.find("defender_queue_capacity")) {
        cfg.defenderQueueCapacity = BoundedUInt(*v,
            "defender_queue_capacity", 64, 8192);
    }
    if (const Value* v = root.find("defender_workers")) {
        cfg.defenderWorkers = BoundedUInt(*v,
            "defender_workers", 1, 8);
    }
    if (const Value* v = root.find("defender_max_xml_bytes")) {
        cfg.defenderMaxXmlBytes = BoundedUInt(*v,
            "defender_max_xml_bytes", 4096, 512 * 1024);
    }
    if (const Value* v = root.find("enable_powershell_log")) {
        cfg.enablePowerShellLog = Boolean(*v, "enable_powershell_log");
    }
    if (const Value* v = root.find("powershell_queue_capacity")) {
        cfg.powerShellQueueCapacity = BoundedUInt(*v,
            "powershell_queue_capacity", 64, 8192);
    }
    if (const Value* v = root.find("powershell_workers")) {
        cfg.powerShellWorkers = BoundedUInt(*v, "powershell_workers", 1, 8);
    }
    if (const Value* v = root.find("powershell_max_xml_bytes")) {
        cfg.powerShellMaxXmlBytes = BoundedUInt(*v,
            "powershell_max_xml_bytes", 4096, 2 * 1024 * 1024);
    }
    if (const Value* v = root.find("powershell_max_script_chars")) {
        cfg.powerShellMaxScriptChars = BoundedUInt(*v,
            "powershell_max_script_chars", 1024, 1024 * 1024);
    }
    if (const Value* v = root.find("powershell_reassembly")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError("config value 'powershell_reassembly' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "max_fragments" &&
                item.first != "max_assembled_bytes" && item.first != "state_capacity" &&
                item.first != "max_buffered_bytes" && item.first != "timeout_seconds")
                throw jsonlite::ParseError("unknown powershell_reassembly value '" + item.first + "'");
        }
        if (const Value* value = v->find("enable")) cfg.powerShellReassemblyEnable = Boolean(*value, "powershell_reassembly.enable");
        if (const Value* value = v->find("max_fragments")) cfg.powerShellReassemblyMaxFragments = BoundedUInt(*value, "powershell_reassembly.max_fragments", 2, 1024);
        if (const Value* value = v->find("max_assembled_bytes")) cfg.powerShellReassemblyMaxAssembledBytes = BoundedUInt(*value, "powershell_reassembly.max_assembled_bytes", 4096, 8 * 1024 * 1024);
        if (const Value* value = v->find("state_capacity")) cfg.powerShellReassemblyStateCapacity = BoundedUInt(*value, "powershell_reassembly.state_capacity", 1, 4096);
        if (const Value* value = v->find("max_buffered_bytes")) cfg.powerShellReassemblyMaxBufferedBytes = BoundedUInt(*value, "powershell_reassembly.max_buffered_bytes", 1024 * 1024, 256 * 1024 * 1024);
        if (const Value* value = v->find("timeout_seconds")) cfg.powerShellReassemblyTimeoutSeconds = BoundedUInt(*value, "powershell_reassembly.timeout_seconds", 1, 300);
        if (cfg.powerShellReassemblyMaxBufferedBytes < cfg.powerShellReassemblyMaxAssembledBytes)
            throw jsonlite::ParseError("powershell_reassembly.max_buffered_bytes must be >= max_assembled_bytes");
    }
    if (const Value* v = root.find("enable_startup_watch")) {
        cfg.enableStartupWatch = Boolean(*v, "enable_startup_watch");
    }
    if (const Value* v = root.find("enable_image_load")) {
        cfg.enableImageLoad = Boolean(*v, "enable_image_load");
    }
    if (const Value* v = root.find("image_load_queue_capacity")) {
        cfg.imageLoadQueueCapacity = BoundedUInt(*v,
            "image_load_queue_capacity", 64, 8192);
    }
    if (const Value* v = root.find("enable_privilege_esc")) {
        cfg.enablePrivilegeEsc = Boolean(*v, "enable_privilege_esc");
    }
    if (const Value* v = root.find("enable_dns_etw")) {
        cfg.enableDnsEtw = Boolean(*v, "enable_dns_etw");
    }
    if (const Value* v = root.find("enable_usb_monitor")) {
        cfg.enableUsbMonitor = Boolean(*v, "enable_usb_monitor");
    }
    if (const Value* v = root.find("usb_poll_ms")) {
        cfg.usbPollMs = BoundedUInt(*v, "usb_poll_ms", 500, 3600000);
    }
    if (const Value* v = root.find("usb_dedup_window_ms")) {
        cfg.usbDedupWindowMs = BoundedUInt64(*v, "usb_dedup_window_ms",
            1000, 3600000);
    }
    if (const Value* v = root.find("enable_listener_monitor")) {
        cfg.enableListenerMonitor = Boolean(*v, "enable_listener_monitor");
    }
    if (const Value* v = root.find("listener_poll_ms")) {
        cfg.listenerPollMs = BoundedUInt(*v, "listener_poll_ms",
            1000, 3600000);
    }
    if (const Value* v = root.find("enable_service_monitor")) {
        cfg.enableServiceMonitor = Boolean(*v, "enable_service_monitor");
    }
    if (const Value* v = root.find("service_poll_ms")) {
        cfg.servicePollMs = BoundedUInt(*v, "service_poll_ms",
            1000, 3600000);
    }
    if (const Value* v = root.find("enable_critical_process_monitor")) {
        cfg.enableCriticalProcessMonitor =
            Boolean(*v, "enable_critical_process_monitor");
    }
    if (const Value* v = root.find("critical_process_poll_ms")) {
        cfg.criticalProcessPollMs = BoundedUInt(*v,
            "critical_process_poll_ms", 500, 3600000);
    }
    if (const Value* v = root.find("critical_process_missing_threshold")) {
        cfg.criticalProcessMissingThreshold = BoundedUInt(*v,
            "critical_process_missing_threshold", 1, 64);
    }
    if (const Value* v = root.find("critical_process_images")) {
        if (v->type != jsonlite::Type::Array) {
            throw jsonlite::ParseError(
                "config value 'critical_process_images' must be an array");
        }
        cfg.criticalProcessImages.clear();
        for (const Value& item : v->array) {
            if (item.type != jsonlite::Type::String) {
                throw jsonlite::ParseError(
                    "config value 'critical_process_images' entries must be strings");
            }
            cfg.criticalProcessImages.push_back(item.str);
        }
    }
    if (const Value* v = root.find("enable_fim_monitor")) {
        cfg.enableFimMonitor = Boolean(*v, "enable_fim_monitor");
    }
    if (const Value* v = root.find("fim_poll_ms")) {
        cfg.fimPollMs = BoundedUInt(*v, "fim_poll_ms", 1000, 86400000);
    }
    if (const Value* v = root.find("fim_max_file_bytes")) {
        cfg.fimMaxFileBytes = BoundedUInt64(*v, "fim_max_file_bytes",
            1024, 1024ULL * 1024ULL * 1024ULL);
    }
    if (const Value* v = root.find("fim_watch_files")) {
        if (v->type != jsonlite::Type::Array) {
            throw jsonlite::ParseError(
                "config value 'fim_watch_files' must be an array");
        }
        cfg.fimWatchFiles.clear();
        for (const Value& item : v->array) {
            if (item.type != jsonlite::Type::String) {
                throw jsonlite::ParseError(
                    "config value 'fim_watch_files' entries must be strings");
            }
            cfg.fimWatchFiles.push_back(ExpandEnvStrings(item.str));
        }
    }
    if (const Value* v = root.find("enable_share_monitor")) {
        cfg.enableShareMonitor = Boolean(*v, "enable_share_monitor");
    }
    if (const Value* v = root.find("share_poll_ms")) {
        cfg.sharePollMs = BoundedUInt(*v, "share_poll_ms",
            1000, 3600000);
    }
    if (const Value* v = root.find("enable_named_pipe_monitor")) {
        cfg.enableNamedPipeMonitor = Boolean(*v, "enable_named_pipe_monitor");
    }
    if (const Value* v = root.find("enable_local_account_monitor")) {
        cfg.enableLocalAccountMonitor =
            Boolean(*v, "enable_local_account_monitor");
    }
    if (const Value* v = root.find("local_account_poll_ms")) {
        cfg.localAccountPollMs = BoundedUInt(*v, "local_account_poll_ms",
            1000, 86400000);
    }
    if (const Value* v = root.find("local_account_watch_groups")) {
        if (v->type != jsonlite::Type::Array) {
            throw jsonlite::ParseError(
                "config value 'local_account_watch_groups' must be an array");
        }
        cfg.localAccountWatchGroups.clear();
        for (const Value& item : v->array) {
            if (item.type != jsonlite::Type::String) {
                throw jsonlite::ParseError(
                    "config value 'local_account_watch_groups' entries must be strings");
            }
            cfg.localAccountWatchGroups.push_back(item.str);
        }
    }
    if (const Value* v = root.find("enable_firewall_monitor")) {
        cfg.enableFirewallMonitor = Boolean(*v, "enable_firewall_monitor");
    }
    if (const Value* v = root.find("firewall_poll_ms")) {
        cfg.firewallPollMs = BoundedUInt(*v, "firewall_poll_ms",
            1000, 3600000);
    }
    if (const Value* v = root.find("enable_etw_tamper_monitor")) {
        cfg.enableEtwTamperMonitor =
            Boolean(*v, "enable_etw_tamper_monitor");
    }
    if (const Value* v = root.find("etw_tamper_poll_ms")) {
        cfg.etwTamperPollMs = BoundedUInt(*v, "etw_tamper_poll_ms",
            1000, 3600000);
    }
    if (const Value* v = root.find("etw_tamper_protected_guids")) {
        if (v->type != jsonlite::Type::Array) {
            throw jsonlite::ParseError(
                "config value 'etw_tamper_protected_guids' must be an array");
        }
        cfg.etwTamperProtectedGuids.clear();
        for (const Value& item : v->array) {
            if (item.type != jsonlite::Type::String) {
                throw jsonlite::ParseError(
                    "config value 'etw_tamper_protected_guids' entries must be strings");
            }
            cfg.etwTamperProtectedGuids.push_back(item.str);
        }
    }
    if (const Value* v = root.find("etw_tamper_watch_sessions")) {
        cfg.etwTamperWatchSessions =
            Boolean(*v, "etw_tamper_watch_sessions");
    }
    if (const Value* v = root.find("etw_tamper_scan_processes")) {
        cfg.etwTamperScanProcesses =
            Boolean(*v, "etw_tamper_scan_processes");
    }
    if (const Value* v = root.find("etw_tamper_skip_images")) {
        if (v->type != jsonlite::Type::Array) {
            throw jsonlite::ParseError(
                "config value 'etw_tamper_skip_images' must be an array");
        }
        cfg.etwTamperSkipImages.clear();
        for (const Value& item : v->array) {
            if (item.type != jsonlite::Type::String) {
                throw jsonlite::ParseError(
                    "config value 'etw_tamper_skip_images' entries must be strings");
            }
            cfg.etwTamperSkipImages.push_back(item.str);
        }
    }
    if (const Value* v = root.find("enable_lsass_sam_collector")) {
        cfg.enableLsassSamCollector = Boolean(*v, "enable_lsass_sam_collector");
    }
    if (const Value* v = root.find("lsass_sam_poll_ms")) {
        cfg.lsassSamPollMs = BoundedUInt(*v, "lsass_sam_poll_ms",
            1000, 3600000);
    }
    if (const Value* v = root.find("lsass_sam_dedup_ms")) {
        cfg.lsassSamDedupMs = BoundedUInt(*v, "lsass_sam_dedup_ms",
            1000, 3600000);
    }

    // Host isolation
    if (const Value* v = root.find("enable_host_isolation")) {
        cfg.enableHostIsolation = Boolean(*v, "enable_host_isolation");
    }
    if (const Value* v = root.find("host_isolation_allowed_ports")) {
        cfg.hostIsolationAllowedPorts = String(*v, "host_isolation_allowed_ports");
    }
    if (const Value* v = root.find("host_isolation_management_ip")) {
        cfg.hostIsolationManagementIp = String(*v, "host_isolation_management_ip");
    }

    // Driver BLOCK policy (Phase B+C)
    if (const Value* v = root.find("driver_enable_file")) {
        cfg.driverEnableFile = Boolean(*v, "driver_enable_file");
    }
    if (const Value* v = root.find("driver_enable_net")) {
        cfg.driverEnableNet = Boolean(*v, "driver_enable_net");
    }
    if (const Value* v = root.find("driver_enable_block")) {
        cfg.driverEnableBlock = Boolean(*v, "driver_enable_block");
    }
    if (const Value* v = root.find("driver_enable_object_handle")) {
        cfg.driverEnableObjectHandle = Boolean(*v, "driver_enable_object_handle");
    }
    if (const Value* v = root.find("driver_block_file_paths")) {
        if (v->type != jsonlite::Type::Array) {
            throw jsonlite::ParseError(
                "config value 'driver_block_file_paths' must be an array");
        }
        cfg.driverBlockFilePaths.clear();
        for (const Value& item : v->array) {
            if (item.type != jsonlite::Type::String) {
                throw jsonlite::ParseError(
                    "config value 'driver_block_file_paths' entries must be strings");
            }
            cfg.driverBlockFilePaths.push_back(item.str);
        }
    }
    if (const Value* v = root.find("driver_net_rules")) {
        if (v->type != jsonlite::Type::Array) {
            throw jsonlite::ParseError(
                "config value 'driver_net_rules' must be an array");
        }
        cfg.driverNetRules.clear();
        for (const Value& item : v->array) {
            if (item.type != jsonlite::Type::Object) {
                throw jsonlite::ParseError(
                    "config value 'driver_net_rules' entries must be objects");
            }
            Config::DriverNetRule rule;
            const Value* ip = item.find("ip");
            if (ip == nullptr || ip->type != jsonlite::Type::String) {
                throw jsonlite::ParseError(
                    "config value 'driver_net_rules[].ip' must be a string");
            }
            rule.ip = ip->str;
            if (const Value* port = item.find("port")) {
                if (port->type != jsonlite::Type::Number) {
                    throw jsonlite::ParseError(
                        "config value 'driver_net_rules[].port' must be a number");
                }
                rule.port = (uint16_t)BoundedUInt(*port,
                    "driver_net_rules[].port", 0, 65535);
            }
            cfg.driverNetRules.push_back(std::move(rule));
        }
    }

    // Process tree enrichment
    if (const Value* v = root.find("enable_process_tree_enrich")) {
        cfg.enableProcessTreeEnrich = Boolean(*v, "enable_process_tree_enrich");
    }
    if (const Value* v = root.find("process_tree_max_depth")) {
        cfg.processTreeMaxDepth = BoundedUInt(*v, "process_tree_max_depth", 1, 20);
    }
    if (const Value* v = root.find("process_tree_prune_age_ms")) {
        cfg.processTreePruneAgeMs = BoundedUInt64(*v, "process_tree_prune_age_ms", 60000, 86400000);
    }

    if (const Value* v = root.find("privilege_esc_queue_capacity")) {
        cfg.privilegeEscQueueCapacity = BoundedUInt(*v,
            "privilege_esc_queue_capacity", 64, 8192);
    }
    if (const Value* v = root.find("privilege_esc_workers")) {
        cfg.privilegeEscWorkers = BoundedUInt(*v,
            "privilege_esc_workers", 1, 8);
    }
    if (const Value* v = root.find("privilege_esc_max_xml_bytes")) {
        cfg.privilegeEscMaxXmlBytes = BoundedUInt(*v,
            "privilege_esc_max_xml_bytes", 4096, 512 * 1024);
    }
    if (const Value* v = root.find("startup_watch_dirs")) {
        if (v->type != jsonlite::Type::Array)
            throw jsonlite::ParseError(
                "config value 'startup_watch_dirs' must be an array");
        cfg.startupWatchDirs.clear();
        for (const Value& item : v->array) {
            if (item.type != jsonlite::Type::String)
                throw jsonlite::ParseError(
                    "config value 'startup_watch_dirs' entries must be strings");
            cfg.startupWatchDirs.push_back(ExpandEnvStrings(item.str));
        }
    }
    if (const Value* v = root.find("sysmon_queue_capacity")) {
        cfg.sysmonQueueCapacity = BoundedUInt(*v, "sysmon_queue_capacity", 16, 512);
    }
    if (const Value* v = root.find("sysmon_workers")) {
        cfg.sysmonWorkers = BoundedUInt(*v, "sysmon_workers", 1, 4);
    }
    if (const Value* v = root.find("sysmon_max_xml_bytes")) {
        cfg.sysmonMaxXmlBytes = BoundedUInt(*v, "sysmon_max_xml_bytes", 4096, 256 * 1024);
    }
    if (const Value* v = root.find("file_reputation")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError("config value 'file_reputation' must be an object");
        if (const Value* enabled = v->find("enable"))
            cfg.fileReputationEnable = Boolean(*enabled, "file_reputation.enable");
        if (const Value* maxBytes = v->find("max_file_bytes"))
            cfg.fileReputationMaxBytes = BoundedUInt64(*maxBytes,
                "file_reputation.max_file_bytes", 1024 * 1024,
                1024ULL * 1024ULL * 1024ULL);
        if (const Value* cacheOnly = v->find("cache_only_trust")) {
            cfg.fileReputationCacheOnlyTrust = Boolean(*cacheOnly,
                "file_reputation.cache_only_trust");
            if (!cfg.fileReputationCacheOnlyTrust)
                throw jsonlite::ParseError(
                    "file_reputation.cache_only_trust must be true; online trust is unsupported");
        }
    }
    if (const Value* v = root.find("amsi")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError("config value 'amsi' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "max_content_chars")
                throw jsonlite::ParseError("unknown amsi value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.amsiEnable = Boolean(*enabled, "amsi.enable");
        if (const Value* maxChars = v->find("max_content_chars"))
            cfg.amsiMaxContentChars = BoundedUInt(*maxChars,
                "amsi.max_content_chars", 256, 32768);
    }
    if (const Value* v = root.find("silverfox")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'silverfox' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "ioc_path" &&
                item.first != "correlation_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown silverfox value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.enableSilverFox =
                Boolean(*enabled, "silverfox.enable");
        if (const Value* path = v->find("ioc_path")) {
            cfg.silverFoxIocPath =
                ExpandEnvStrings(String(*path, "silverfox.ioc_path"));
            if (cfg.silverFoxIocPath.empty())
                throw jsonlite::ParseError(
                    "config value 'silverfox.ioc_path' must not be empty");
        }
        if (const Value* window =
                v->find("correlation_window_seconds"))
            cfg.silverFoxCorrelationWindowSeconds = BoundedUInt(
                *window, "silverfox.correlation_window_seconds",
                30, 3600);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.silverFoxStateCapacity = BoundedUInt(
                *capacity, "silverfox.state_capacity", 128, 65536);
    }
    if (const Value* v = root.find("behavior_enrich")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'behavior_enrich' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "state_capacity" &&
                item.first != "window_seconds" &&
                item.first != "lsass_burst_window_seconds" &&
                item.first != "lsass_burst_threshold_bytes")
                throw jsonlite::ParseError(
                    "unknown behavior_enrich value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.behaviorEnrichEnable =
                Boolean(*enabled, "behavior_enrich.enable");
        if (const Value* capacity = v->find("state_capacity"))
            cfg.behaviorEnrichStateCapacity = BoundedUInt(
                *capacity, "behavior_enrich.state_capacity", 128, 65536);
        if (const Value* window = v->find("window_seconds"))
            cfg.behaviorEnrichWindowSeconds = BoundedUInt(
                *window, "behavior_enrich.window_seconds", 30, 3600);
        if (const Value* burstWindow =
                v->find("lsass_burst_window_seconds"))
            cfg.behaviorEnrichLsassBurstWindowSeconds = BoundedUInt(
                *burstWindow, "behavior_enrich.lsass_burst_window_seconds",
                5, 3600);
        if (const Value* threshold =
                v->find("lsass_burst_threshold_bytes"))
            cfg.behaviorEnrichLsassBurstThresholdBytes = BoundedUInt64(
                *threshold, "behavior_enrich.lsass_burst_threshold_bytes",
                1024 * 1024, 1024ULL * 1024ULL * 1024ULL);
    }
    if (const Value* v = root.find("inject_chain")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'inject_chain' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_transition_score")
                throw jsonlite::ParseError(
                    "unknown inject_chain value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.injectChainEnable =
                Boolean(*enabled, "inject_chain.enable");
        if (const Value* capacity = v->find("state_capacity"))
            cfg.injectChainStateCapacity = BoundedUInt(
                *capacity, "inject_chain.state_capacity", 64, 65536);
        if (const Value* window = v->find("window_seconds"))
            cfg.injectChainWindowSeconds = BoundedUInt(
                *window, "inject_chain.window_seconds", 10, 3600);
        if (const Value* threshold = v->find("min_transition_score"))
            cfg.injectChainMinTransitionScore = BoundedUInt(
                *threshold, "inject_chain.min_transition_score", 20, 100);
    }
    if (const Value* v = root.find("attack_chain")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'attack_chain' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown attack_chain value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.attackChainEnable =
                Boolean(*enabled, "attack_chain.enable");
        if (const Value* capacity = v->find("state_capacity"))
            cfg.attackChainStateCapacity = BoundedUInt(
                *capacity, "attack_chain.state_capacity", 128, 65536);
        if (const Value* window = v->find("window_seconds"))
            cfg.attackChainWindowSeconds = BoundedUInt(
                *window, "attack_chain.window_seconds", 30, 3600);
    }
    if (const Value* v = root.find("persist_chain")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'persist_chain' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_mechanisms")
                throw jsonlite::ParseError(
                    "unknown persist_chain value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.persistChainEnable =
                Boolean(*enabled, "persist_chain.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.persistChainWindowSeconds = BoundedUInt(
                *window, "persist_chain.window_seconds", 60, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.persistChainStateCapacity = BoundedUInt(
                *capacity, "persist_chain.state_capacity", 128, 65536);
        if (const Value* minMechs = v->find("min_mechanisms"))
            cfg.persistChainMinMechanisms = BoundedUInt(
                *minMechs, "persist_chain.min_mechanisms", 2, 8);
    }
    if (const Value* v = root.find("lolbin_parent_child")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'lolbin_parent_child' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score")
                throw jsonlite::ParseError(
                    "unknown lolbin_parent_child value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.lolbinParentChildEnable =
                Boolean(*enabled, "lolbin_parent_child.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.lolbinParentChildMinScore = BoundedUInt(
                *minScore, "lolbin_parent_child.min_score", 1, 100);
    }
    if (const Value* v = root.find("lolbin_chain")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'lolbin_chain' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_distinct_children")
                throw jsonlite::ParseError(
                    "unknown lolbin_chain value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.lolbinChainEnable = Boolean(*enabled, "lolbin_chain.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.lolbinChainWindowSeconds = BoundedUInt(
                *window, "lolbin_chain.window_seconds", 30, 3600);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.lolbinChainStateCapacity = BoundedUInt(
                *capacity, "lolbin_chain.state_capacity", 128, 65536);
        if (const Value* minChildren = v->find("min_distinct_children"))
            cfg.lolbinChainMinDistinctChildren = BoundedUInt(
                *minChildren, "lolbin_chain.min_distinct_children", 2, 8);
    }
    if (const Value* v = root.find("powershell_download_execute")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'powershell_download_execute' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_distinct_scripts")
                throw jsonlite::ParseError(
                    "unknown powershell_download_execute value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.powershellDownloadExecuteEnable =
                Boolean(*enabled, "powershell_download_execute.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.powershellDownloadExecuteWindowSeconds = BoundedUInt(
                *window, "powershell_download_execute.window_seconds", 30, 3600);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.powershellDownloadExecuteStateCapacity = BoundedUInt(
                *capacity, "powershell_download_execute.state_capacity", 128, 65536);
        if (const Value* minScripts = v->find("min_distinct_scripts"))
            cfg.powershellDownloadExecuteMinDistinctScripts = BoundedUInt(
                *minScripts, "powershell_download_execute.min_distinct_scripts", 2, 8);
    }
    if (const Value* v = root.find("rdp_chain")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'rdp_chain' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_distinct_sources")
                throw jsonlite::ParseError(
                    "unknown rdp_chain value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.rdpChainEnable = Boolean(*enabled, "rdp_chain.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.rdpChainWindowSeconds = BoundedUInt(
                *window, "rdp_chain.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.rdpChainStateCapacity = BoundedUInt(
                *capacity, "rdp_chain.state_capacity", 16, 65536);
        if (const Value* minSources = v->find("min_distinct_sources"))
            cfg.rdpChainMinDistinctSources = BoundedUInt(
                *minSources, "rdp_chain.min_distinct_sources", 1, 32);
    }
    if (const Value* v = root.find("uac_bypass_chain")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'uac_bypass_chain' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_distinct_keys")
                throw jsonlite::ParseError(
                    "unknown uac_bypass_chain value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.uacBypassEnable = Boolean(*enabled, "uac_bypass_chain.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.uacBypassWindowSeconds = BoundedUInt(
                *window, "uac_bypass_chain.window_seconds", 30, 3600);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.uacBypassStateCapacity = BoundedUInt(
                *capacity, "uac_bypass_chain.state_capacity", 16, 65536);
        if (const Value* minKeys = v->find("min_distinct_keys"))
            cfg.uacBypassMinDistinctKeys = BoundedUInt(
                *minKeys, "uac_bypass_chain.min_distinct_keys", 1, 8);
    }
    if (const Value* v = root.find("wmi_persistence")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'wmi_persistence' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_matches")
                throw jsonlite::ParseError(
                    "unknown wmi_persistence value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.wmiPersistenceEnable = Boolean(*enabled, "wmi_persistence.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.wmiPersistenceWindowSeconds = BoundedUInt(
                *window, "wmi_persistence.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.wmiPersistenceStateCapacity = BoundedUInt(
                *capacity, "wmi_persistence.state_capacity", 16, 65536);
        if (const Value* minMatches = v->find("min_matches"))
            cfg.wmiPersistenceMinMatches = BoundedUInt(
                *minMatches, "wmi_persistence.min_matches", 1, 8);
    }
    if (const Value* v = root.find("ransom_precursor")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'ransom_precursor' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_techniques" &&
                item.first != "dedup_seconds")
                throw jsonlite::ParseError(
                    "unknown ransom_precursor value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.ransomPrecursorEnable =
                Boolean(*enabled, "ransom_precursor.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.ransomPrecursorWindowSeconds = BoundedUInt(
                *window, "ransom_precursor.window_seconds", 30, 3600);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.ransomPrecursorStateCapacity = BoundedUInt(
                *capacity, "ransom_precursor.state_capacity", 16, 4096);
        if (const Value* minTech = v->find("min_techniques"))
            cfg.ransomPrecursorMinTechniques = BoundedUInt(
                *minTech, "ransom_precursor.min_techniques", 2, 8);
        if (const Value* dedup = v->find("dedup_seconds"))
            cfg.ransomPrecursorDedupSeconds = BoundedUInt(
                *dedup, "ransom_precursor.dedup_seconds", 0, 86400);
    }
    if (const Value* v = root.find("memory_scanner")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'memory_scanner' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown memory_scanner value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.memoryScannerEnable =
                Boolean(*enabled, "memory_scanner.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.memoryScannerMinScore = BoundedUInt(
                *minScore, "memory_scanner.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.memoryScannerDedupWindowSeconds = BoundedUInt(
                *dedup, "memory_scanner.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.memoryScannerStateCapacity = BoundedUInt(
                *capacity, "memory_scanner.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("driver_load")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'driver_load' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown driver_load value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.driverLoadEnable = Boolean(*enabled, "driver_load.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.driverLoadMinScore = BoundedUInt(
                *minScore, "driver_load.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.driverLoadDedupWindowSeconds = BoundedUInt(
                *dedup, "driver_load.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.driverLoadStateCapacity = BoundedUInt(
                *capacity, "driver_load.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("canary")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'canary' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "poll_ms" &&
                item.first != "max_file_bytes" &&
                item.first != "files" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown canary value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.canaryEnable = Boolean(*enabled, "canary.enable");
        if (const Value* poll = v->find("poll_ms"))
            cfg.canaryPollMs = BoundedUInt(*poll, "canary.poll_ms",
                                           1000, 86400000);
        if (const Value* maxBytes = v->find("max_file_bytes"))
            cfg.canaryMaxFileBytes = BoundedUInt64(
                *maxBytes, "canary.max_file_bytes", 1024, 1073741824ULL);
        if (const Value* files = v->find("files")) {
            if (files->type != jsonlite::Type::Array)
                throw jsonlite::ParseError(
                    "config value 'canary.files' must be an array");
            cfg.canaryFiles.clear();
            for (const Value& item : files->array) {
                if (item.type != jsonlite::Type::String)
                    throw jsonlite::ParseError(
                        "config value 'canary.files' entries must be strings");
                cfg.canaryFiles.push_back(ExpandEnvStrings(item.str));
            }
        }
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.canaryDedupWindowSeconds = BoundedUInt(
                *dedup, "canary.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.canaryStateCapacity = BoundedUInt(
                *capacity, "canary.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("hook_scan")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'hook_scan' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "poll_seconds" &&
                item.first != "max_entries")
                throw jsonlite::ParseError(
                    "unknown hook_scan value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.hookScanEnable = Boolean(*enabled, "hook_scan.enable");
        if (const Value* poll = v->find("poll_seconds"))
            cfg.hookScanPollSeconds = BoundedUInt(
                *poll, "hook_scan.poll_seconds", 30, 86400);
        if (const Value* maxEntries = v->find("max_entries"))
            cfg.hookScanMaxEntries = static_cast<size_t>(BoundedUInt(
                *maxEntries, "hook_scan.max_entries", 16, 65536));
    }
    if (const Value* v = root.find("hook_persistence")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'hook_persistence' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown hook_persistence value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.hookPersistenceEnable =
                Boolean(*enabled, "hook_persistence.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.hookPersistenceMinScore = BoundedUInt(
                *minScore, "hook_persistence.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.hookPersistenceDedupWindowSeconds = BoundedUInt(
                *dedup, "hook_persistence.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.hookPersistenceStateCapacity = BoundedUInt(
                *capacity, "hook_persistence.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("task_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'task_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "delete_burst_threshold" &&
                item.first != "delete_burst_window_seconds")
                throw jsonlite::ParseError(
                    "unknown task_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.taskAbuseEnable = Boolean(*enabled, "task_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.taskAbuseMinScore = BoundedUInt(
                *minScore, "task_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.taskAbuseDedupWindowSeconds = BoundedUInt(
                *dedup, "task_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.taskAbuseStateCapacity = BoundedUInt(
                *capacity, "task_abuse.state_capacity", 16, 65536);
        if (const Value* threshold = v->find("delete_burst_threshold"))
            cfg.taskAbuseDeleteBurstThreshold = BoundedUInt(
                *threshold, "task_abuse.delete_burst_threshold", 2, 1000);
        if (const Value* window = v->find("delete_burst_window_seconds"))
            cfg.taskAbuseDeleteBurstWindowSeconds = BoundedUInt(
                *window, "task_abuse.delete_burst_window_seconds",
                10, 3600);
    }
    if (const Value* v = root.find("masquerade")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'masquerade' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown masquerade value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.masqueradeEnable = Boolean(*enabled, "masquerade.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.masqueradeMinScore = BoundedUInt(
                *minScore, "masquerade.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.masqueradeDedupWindowSeconds = BoundedUInt(
                *dedup, "masquerade.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.masqueradeStateCapacity = BoundedUInt(
                *capacity, "masquerade.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("ppid_spoof")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'ppid_spoof' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown ppid_spoof value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.ppidSpoofEnable = Boolean(*enabled, "ppid_spoof.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.ppidSpoofMinScore = BoundedUInt(
                *minScore, "ppid_spoof.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.ppidSpoofDedupWindowSeconds = BoundedUInt(
                *dedup, "ppid_spoof.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.ppidSpoofStateCapacity = BoundedUInt(
                *capacity, "ppid_spoof.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("net_discovery")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'net_discovery' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "window_seconds" &&
                item.first != "burst_threshold" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown net_discovery value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.netDiscoveryEnable = Boolean(*enabled, "net_discovery.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.netDiscoveryMinScore = BoundedUInt(
                *minScore, "net_discovery.min_score", 10, 100);
        if (const Value* window = v->find("window_seconds"))
            cfg.netDiscoveryWindowSeconds = BoundedUInt(
                *window, "net_discovery.window_seconds", 10, 86400);
        if (const Value* burst = v->find("burst_threshold"))
            cfg.netDiscoveryBurstThreshold = BoundedUInt(
                *burst, "net_discovery.burst_threshold", 2, 1000);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.netDiscoveryDedupWindowSeconds = BoundedUInt(
                *dedup, "net_discovery.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.netDiscoveryStateCapacity = BoundedUInt(
                *capacity, "net_discovery.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("host_profile")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'host_profile' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "window_seconds" &&
                item.first != "min_categories" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown host_profile value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.hostProfileEnable = Boolean(*enabled, "host_profile.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.hostProfileMinScore = BoundedUInt(
                *minScore, "host_profile.min_score", 10, 100);
        if (const Value* window = v->find("window_seconds"))
            cfg.hostProfileWindowSeconds = BoundedUInt(
                *window, "host_profile.window_seconds", 10, 86400);
        if (const Value* categories = v->find("min_categories"))
            cfg.hostProfileMinCategories = BoundedUInt(
                *categories, "host_profile.min_categories", 2, 7);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.hostProfileDedupWindowSeconds = BoundedUInt(
                *dedup, "host_profile.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.hostProfileStateCapacity = BoundedUInt(
                *capacity, "host_profile.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("private_key")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'private_key' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown private_key value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.privateKeyEnable = Boolean(*enabled, "private_key.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.privateKeyMinScore = BoundedUInt(
                *minScore, "private_key.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.privateKeyDedupWindowSeconds = BoundedUInt(
                *dedup, "private_key.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.privateKeyStateCapacity = BoundedUInt(
                *capacity, "private_key.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("av_tamper")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'av_tamper' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown av_tamper value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.avTamperEnable = Boolean(*enabled, "av_tamper.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.avTamperMinScore = BoundedUInt(
                *minScore, "av_tamper.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.avTamperDedupWindowSeconds = BoundedUInt(
                *dedup, "av_tamper.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.avTamperStateCapacity = BoundedUInt(
                *capacity, "av_tamper.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("timestomp")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'timestomp' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown timestomp value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.timestompEnable = Boolean(*enabled, "timestomp.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.timestompMinScore = BoundedUInt(
                *minScore, "timestomp.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.timestompDedupWindowSeconds = BoundedUInt(
                *dedup, "timestomp.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.timestompStateCapacity = BoundedUInt(
                *capacity, "timestomp.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("obfuscation")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'obfuscation' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown obfuscation value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.obfuscationEnable = Boolean(*enabled, "obfuscation.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.obfuscationMinScore = BoundedUInt(
                *minScore, "obfuscation.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.obfuscationDedupWindowSeconds = BoundedUInt(
                *dedup, "obfuscation.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.obfuscationStateCapacity = BoundedUInt(
                *capacity, "obfuscation.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("lsass_dump")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'lsass_dump' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown lsass_dump value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.lsassDumpEnable = Boolean(*enabled, "lsass_dump.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.lsassDumpMinScore = BoundedUInt(
                *minScore, "lsass_dump.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.lsassDumpDedupWindowSeconds = BoundedUInt(
                *dedup, "lsass_dump.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.lsassDumpStateCapacity = BoundedUInt(
                *capacity, "lsass_dump.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("accessibility_hijack")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'accessibility_hijack' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown accessibility_hijack value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.accessibilityHijackEnable =
                Boolean(*enabled, "accessibility_hijack.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.accessibilityHijackMinScore = BoundedUInt(
                *minScore, "accessibility_hijack.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds")) {
            cfg.accessibilityHijackDedupWindowSeconds = BoundedUInt(
                *dedup, "accessibility_hijack.dedup_window_seconds", 0, 86400);
            std::fprintf(stderr,
                         "[edr-config] note: accessibility_hijack.dedup_window_seconds is accepted "
                         "but not consumed (detector has built-in dedup, no window parameter)\n");
        }
        if (const Value* capacity = v->find("state_capacity")) {
            cfg.accessibilityHijackStateCapacity = static_cast<size_t>(BoundedUInt(
                *capacity, "accessibility_hijack.state_capacity", 16, 65536));
            std::fprintf(stderr,
                         "[edr-config] note: accessibility_hijack.state_capacity is accepted "
                         "but not consumed (detector uses a fixed state capacity)\n");
        }
    }
    if (const Value* v = root.find("acl_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'acl_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown acl_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.aclAbuseEnable = Boolean(*enabled, "acl_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.aclAbuseMinScore = BoundedUInt(
                *minScore, "acl_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.aclAbuseDedupWindowSeconds = BoundedUInt(
                *dedup, "acl_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.aclAbuseStateCapacity = BoundedUInt(
                *capacity, "acl_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("amsi_bypass")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'amsi_bypass' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown amsi_bypass value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.amsiBypassEnable = Boolean(*enabled, "amsi_bypass.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.amsiBypassMinScore = BoundedUInt(
                *minScore, "amsi_bypass.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.amsiBypassDedupWindowSeconds = BoundedUInt(
                *dedup, "amsi_bypass.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.amsiBypassStateCapacity = BoundedUInt(
                *capacity, "amsi_bypass.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("appinit_dll")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'appinit_dll' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown appinit_dll value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.appInitDllEnable = Boolean(*enabled, "appinit_dll.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.appInitDllMinScore = BoundedUInt(
                *minScore, "appinit_dll.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.appInitDllDedupWindowSeconds = BoundedUInt(
                *dedup, "appinit_dll.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.appInitDllStateCapacity = BoundedUInt(
                *capacity, "appinit_dll.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("as_rep_roast")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'as_rep_roast' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "dedup_seconds")
                throw jsonlite::ParseError(
                    "unknown as_rep_roast value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.asRepRoastEnable = Boolean(*enabled, "as_rep_roast.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.asRepRoastWindowSeconds = BoundedUInt(
                *window, "as_rep_roast.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.asRepRoastStateCapacity = BoundedUInt(
                *capacity, "as_rep_roast.state_capacity", 16, 65536);
        if (const Value* dedup = v->find("dedup_seconds"))
            cfg.asRepRoastDedupSeconds = BoundedUInt(
                *dedup, "as_rep_roast.dedup_seconds", 0, 86400);
    }
    if (const Value* v = root.find("boot_provider_persist")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'boot_provider_persist' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown boot_provider_persist value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.bootProviderEnable = Boolean(*enabled, "boot_provider_persist.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.bootProviderMinScore = BoundedUInt(
                *minScore, "boot_provider_persist.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.bootProviderDedupWindowSeconds = BoundedUInt(
                *dedup, "boot_provider_persist.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.bootProviderStateCapacity = BoundedUInt(
                *capacity, "boot_provider_persist.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("cert_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'cert_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown cert_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.certAbuseEnable = Boolean(*enabled, "cert_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.certAbuseMinScore = BoundedUInt(
                *minScore, "cert_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.certAbuseDedupWindowSeconds = BoundedUInt(
                *dedup, "cert_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.certAbuseStateCapacity = BoundedUInt(
                *capacity, "cert_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("cor_profiler_hijack")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'cor_profiler_hijack' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown cor_profiler_hijack value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.corProfilerEnable = Boolean(*enabled, "cor_profiler_hijack.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.corProfilerMinScore = BoundedUInt(
                *minScore, "cor_profiler_hijack.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.corProfilerDedupWindowSeconds = BoundedUInt(
                *dedup, "cor_profiler_hijack.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.corProfilerStateCapacity = BoundedUInt(
                *capacity, "cor_profiler_hijack.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("cred_file_hunt")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'cred_file_hunt' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown cred_file_hunt value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.credFileHuntEnable = Boolean(*enabled, "cred_file_hunt.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.credFileHuntMinScore = BoundedUInt(
                *minScore, "cred_file_hunt.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.credFileHuntDedupWindowSeconds = BoundedUInt(
                *dedup, "cred_file_hunt.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.credFileHuntStateCapacity = BoundedUInt(
                *capacity, "cred_file_hunt.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("dcsync")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'dcsync' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown dcsync value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.dcsyncEnable = Boolean(*enabled, "dcsync.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.dcsyncMinScore = BoundedUInt(
                *minScore, "dcsync.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.dcsyncDedupWindowSeconds = BoundedUInt(
                *dedup, "dcsync.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.dcsyncStateCapacity = BoundedUInt(
                *capacity, "dcsync.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("dev_util_proxy")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'dev_util_proxy' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown dev_util_proxy value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.devUtilProxyEnable = Boolean(*enabled, "dev_util_proxy.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.devUtilProxyMinScore = BoundedUInt(
                *minScore, "dev_util_proxy.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.devUtilProxyDedupWindowSeconds = BoundedUInt(
                *dedup, "dev_util_proxy.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.devUtilProxyStateCapacity = BoundedUInt(
                *capacity, "dev_util_proxy.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("disk_wipe")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'disk_wipe' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown disk_wipe value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.diskWipeEnable = Boolean(*enabled, "disk_wipe.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.diskWipeMinScore = BoundedUInt(
                *minScore, "disk_wipe.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.diskWipeDedupWindowSeconds = BoundedUInt(
                *dedup, "disk_wipe.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.diskWipeStateCapacity = BoundedUInt(
                *capacity, "disk_wipe.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("cmstp_bypass")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'cmstp_bypass' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown cmstp_bypass value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.cmstpBypassEnable = Boolean(*enabled, "cmstp_bypass.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.cmstpBypassMinScore = BoundedUInt(
                *minScore, "cmstp_bypass.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.cmstpBypassDedupWindowSeconds = BoundedUInt(
                *dedup, "cmstp_bypass.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.cmstpBypassStateCapacity = BoundedUInt(
                *capacity, "cmstp_bypass.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("file_assoc")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'file_assoc' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown file_assoc value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.fileAssocEnable = Boolean(*enabled, "file_assoc.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.fileAssocMinScore = BoundedUInt(
                *minScore, "file_assoc.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.fileAssocDedupWindowSeconds = BoundedUInt(
                *dedup, "file_assoc.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.fileAssocStateCapacity = BoundedUInt(
                *capacity, "file_assoc.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("hidden_window")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'hidden_window' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown hidden_window value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.hiddenWindowEnable = Boolean(*enabled, "hidden_window.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.hiddenWindowMinScore = BoundedUInt(
                *minScore, "hidden_window.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.hiddenWindowDedupWindowSeconds = BoundedUInt(
                *dedup, "hidden_window.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.hiddenWindowStateCapacity = BoundedUInt(
                *capacity, "hidden_window.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("office_persist")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'office_persist' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown office_persist value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.officePersistEnable = Boolean(*enabled, "office_persist.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.officePersistMinScore = BoundedUInt(
                *minScore, "office_persist.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.officePersistDedupWindowSeconds = BoundedUInt(
                *dedup, "office_persist.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.officePersistStateCapacity = BoundedUInt(
                *capacity, "office_persist.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("shortcut_persist")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'shortcut_persist' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown shortcut_persist value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.shortcutPersistEnable = Boolean(*enabled, "shortcut_persist.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.shortcutPersistMinScore = BoundedUInt(
                *minScore, "shortcut_persist.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.shortcutPersistDedupWindowSeconds = BoundedUInt(
                *dedup, "shortcut_persist.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.shortcutPersistStateCapacity = BoundedUInt(
                *capacity, "shortcut_persist.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("indirect_exec")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'indirect_exec' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown indirect_exec value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.indirectExecEnable = Boolean(*enabled, "indirect_exec.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.indirectExecMinScore = BoundedUInt(
                *minScore, "indirect_exec.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.indirectExecDedupWindowSeconds = BoundedUInt(
                *dedup, "indirect_exec.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.indirectExecStateCapacity = BoundedUInt(
                *capacity, "indirect_exec.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("screensaver_persist")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'screensaver_persist' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown screensaver_persist value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.screensaverPersistEnable = Boolean(*enabled, "screensaver_persist.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.screensaverPersistMinScore = BoundedUInt(
                *minScore, "screensaver_persist.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.screensaverPersistDedupWindowSeconds = BoundedUInt(
                *dedup, "screensaver_persist.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.screensaverPersistStateCapacity = BoundedUInt(
                *capacity, "screensaver_persist.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("svc_path_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'svc_path_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown svc_path_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.svcPathAbuseEnable = Boolean(*enabled, "svc_path_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.svcPathAbuseMinScore = BoundedUInt(
                *minScore, "svc_path_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.svcPathAbuseDedupWindowSeconds = BoundedUInt(
                *dedup, "svc_path_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.svcPathAbuseStateCapacity = BoundedUInt(
                *capacity, "svc_path_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("service_dll_hijack")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'service_dll_hijack' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown service_dll_hijack value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.serviceDllHijackEnable = Boolean(*enabled, "service_dll_hijack.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.serviceDllHijackMinScore = BoundedUInt(
                *minScore, "service_dll_hijack.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.serviceDllHijackDedupWindowSeconds = BoundedUInt(
                *dedup, "service_dll_hijack.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.serviceDllHijackStateCapacity = BoundedUInt(
                *capacity, "service_dll_hijack.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("dll_search_order")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'dll_search_order' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown dll_search_order value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.dllSearchOrderEnable = Boolean(*enabled, "dll_search_order.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.dllSearchOrderMinScore = BoundedUInt(
                *minScore, "dll_search_order.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.dllSearchOrderDedupWindowSeconds = BoundedUInt(
                *dedup, "dll_search_order.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.dllSearchOrderStateCapacity = BoundedUInt(
                *capacity, "dll_search_order.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("svc_recovery")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'svc_recovery' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown svc_recovery value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.svcRecoveryEnable = Boolean(*enabled, "svc_recovery.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.svcRecoveryMinScore = BoundedUInt(
                *minScore, "svc_recovery.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.svcRecoveryDedupWindowSeconds = BoundedUInt(
                *dedup, "svc_recovery.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.svcRecoveryStateCapacity = BoundedUInt(
                *capacity, "svc_recovery.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("com_hijack")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'com_hijack' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown com_hijack value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.comHijackEnable = Boolean(*enabled, "com_hijack.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.comHijackMinScore = BoundedUInt(
                *minScore, "com_hijack.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.comHijackDedupWindowSeconds = BoundedUInt(
                *dedup, "com_hijack.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.comHijackStateCapacity = BoundedUInt(
                *capacity, "com_hijack.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("winlogon_hijack")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'winlogon_hijack' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown winlogon_hijack value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.winlogonHijackEnable = Boolean(*enabled, "winlogon_hijack.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.winlogonHijackMinScore = BoundedUInt(
                *minScore, "winlogon_hijack.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.winlogonHijackDedupWindowSeconds = BoundedUInt(
                *dedup, "winlogon_hijack.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.winlogonHijackStateCapacity = BoundedUInt(
                *capacity, "winlogon_hijack.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("mshta_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'mshta_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown mshta_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.mshtaAbuseEnable = Boolean(*enabled, "mshta_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.mshtaAbuseMinScore = BoundedUInt(
                *minScore, "mshta_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.mshtaAbuseDedupWindowSeconds = BoundedUInt(
                *dedup, "mshta_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.mshtaAbuseStateCapacity = BoundedUInt(
                *capacity, "mshta_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("dotnet_proxy_exec")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'dotnet_proxy_exec' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown dotnet_proxy_exec value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.dotnetProxyExecEnable = Boolean(
                *enabled, "dotnet_proxy_exec.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.dotnetProxyExecMinScore = BoundedUInt(
                *minScore, "dotnet_proxy_exec.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.dotnetProxyExecDedupWindowSeconds = BoundedUInt(
                *dedup, "dotnet_proxy_exec.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.dotnetProxyExecStateCapacity = BoundedUInt(
                *capacity, "dotnet_proxy_exec.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("wsl_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'wsl_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown wsl_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.wslAbuseEnable = Boolean(*enabled, "wsl_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.wslAbuseMinScore = BoundedUInt(
                *minScore, "wsl_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.wslAbuseDedupWindowSeconds = BoundedUInt(
                *dedup, "wsl_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.wslAbuseStateCapacity = BoundedUInt(
                *capacity, "wsl_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("software_discovery")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'software_discovery' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "window_seconds" &&
                item.first != "min_categories" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown software_discovery value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.softwareDiscoveryEnable =
                Boolean(*enabled, "software_discovery.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.softwareDiscoveryMinScore = BoundedUInt(
                *minScore, "software_discovery.min_score", 10, 100);
        if (const Value* window = v->find("window_seconds"))
            cfg.softwareDiscoveryWindowSeconds = BoundedUInt(
                *window, "software_discovery.window_seconds", 10, 86400);
        if (const Value* minCategories = v->find("min_categories"))
            cfg.softwareDiscoveryMinCategories = BoundedUInt(
                *minCategories, "software_discovery.min_categories", 1, 16);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.softwareDiscoveryDedupWindowSeconds = BoundedUInt(
                *dedup, "software_discovery.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.softwareDiscoveryStateCapacity = BoundedUInt(
                *capacity, "software_discovery.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("net_share_discovery")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'net_share_discovery' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "window_seconds" &&
                item.first != "min_commands" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown net_share_discovery value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.netShareDiscoveryEnable =
                Boolean(*enabled, "net_share_discovery.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.netShareDiscoveryMinScore = BoundedUInt(
                *minScore, "net_share_discovery.min_score", 10, 100);
        if (const Value* window = v->find("window_seconds"))
            cfg.netShareDiscoveryWindowSeconds = BoundedUInt(
                *window, "net_share_discovery.window_seconds", 10, 86400);
        if (const Value* minCommands = v->find("min_commands"))
            cfg.netShareDiscoveryMinCommands = BoundedUInt(
                *minCommands, "net_share_discovery.min_commands", 1, 64);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.netShareDiscoveryDedupWindowSeconds = BoundedUInt(
                *dedup, "net_share_discovery.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.netShareDiscoveryStateCapacity = BoundedUInt(
                *capacity, "net_share_discovery.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("nonstandard_port_egress")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'nonstandard_port_egress' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "window_seconds" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown nonstandard_port_egress value '" + item.first +
                    "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.nonstandardPortEgressEnable =
                Boolean(*enabled, "nonstandard_port_egress.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.nonstandardPortEgressMinScore = BoundedUInt(
                *minScore, "nonstandard_port_egress.min_score", 10, 100);
        if (const Value* window = v->find("window_seconds"))
            cfg.nonstandardPortEgressWindowSeconds = BoundedUInt(
                *window, "nonstandard_port_egress.window_seconds", 10, 86400);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.nonstandardPortEgressDedupWindowSeconds = BoundedUInt(
                *dedup, "nonstandard_port_egress.dedup_window_seconds", 0,
                86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.nonstandardPortEgressStateCapacity = BoundedUInt(
                *capacity, "nonstandard_port_egress.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("msdt_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'msdt_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown msdt_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.msdtAbuseEnable = Boolean(*enabled, "msdt_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.msdtAbuseMinScore = BoundedUInt(
                *minScore, "msdt_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.msdtAbuseDedupWindowSeconds = BoundedUInt(
                *dedup, "msdt_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.msdtAbuseStateCapacity = BoundedUInt(
                *capacity, "msdt_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("iso_mount")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'iso_mount' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown iso_mount value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.isoMountEnable = Boolean(*enabled, "iso_mount.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.isoMountMinScore = BoundedUInt(
                *minScore, "iso_mount.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.isoMountDedupWindowSeconds = BoundedUInt(
                *dedup, "iso_mount.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.isoMountStateCapacity = BoundedUInt(
                *capacity, "iso_mount.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("mailbox_rule")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'mailbox_rule' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown mailbox_rule value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.mailboxRuleEnable = Boolean(*enabled, "mailbox_rule.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.mailboxRuleMinScore = BoundedUInt(
                *minScore, "mailbox_rule.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.mailboxRuleDedupWindowSeconds = BoundedUInt(
                *dedup, "mailbox_rule.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.mailboxRuleStateCapacity = BoundedUInt(
                *capacity, "mailbox_rule.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("mailbox_delegate")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'mailbox_delegate' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown mailbox_delegate value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.mailboxDelegateEnable =
                Boolean(*enabled, "mailbox_delegate.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.mailboxDelegateMinScore = BoundedUInt(
                *minScore, "mailbox_delegate.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.mailboxDelegateDedupWindowSeconds = BoundedUInt(
                *dedup, "mailbox_delegate.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.mailboxDelegateStateCapacity = BoundedUInt(
                *capacity, "mailbox_delegate.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("llmnr_poison")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'llmnr_poison' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown llmnr_poison value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.llmnrPoisonEnable = Boolean(*enabled, "llmnr_poison.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.llmnrPoisonMinScore = BoundedUInt(
                *minScore, "llmnr_poison.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.llmnrPoisonDedupWindowSeconds = BoundedUInt(
                *dedup, "llmnr_poison.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.llmnrPoisonStateCapacity = BoundedUInt(
                *capacity, "llmnr_poison.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("netprovider_persist")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'netprovider_persist' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown netprovider_persist value '" + item.first +
                    "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.netProviderPersistEnable =
                Boolean(*enabled, "netprovider_persist.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.netProviderPersistMinScore = BoundedUInt(
                *minScore, "netprovider_persist.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.netProviderPersistDedupWindowSeconds = BoundedUInt(
                *dedup, "netprovider_persist.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.netProviderPersistStateCapacity = BoundedUInt(
                *capacity, "netprovider_persist.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("password_vault")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'password_vault' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown password_vault value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.passwordVaultEnable =
                Boolean(*enabled, "password_vault.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.passwordVaultMinScore = BoundedUInt(
                *minScore, "password_vault.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.passwordVaultDedupWindowSeconds = BoundedUInt(
                *dedup, "password_vault.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.passwordVaultStateCapacity = BoundedUInt(
                *capacity, "password_vault.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("arp_poison")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'arp_poison' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown arp_poison value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.arpPoisonEnable =
                Boolean(*enabled, "arp_poison.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.arpPoisonMinScore = BoundedUInt(
                *minScore, "arp_poison.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.arpPoisonDedupWindowSeconds = BoundedUInt(
                *dedup, "arp_poison.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.arpPoisonStateCapacity = BoundedUInt(
                *capacity, "arp_poison.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("cloud_metadata")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'cloud_metadata' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown cloud_metadata value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.cloudMetadataEnable =
                Boolean(*enabled, "cloud_metadata.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.cloudMetadataMinScore = BoundedUInt(
                *minScore, "cloud_metadata.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.cloudMetadataDedupWindowSeconds = BoundedUInt(
                *dedup, "cloud_metadata.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.cloudMetadataStateCapacity = BoundedUInt(
                *capacity, "cloud_metadata.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("gpp_password")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'gpp_password' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown gpp_password value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.gppPasswordEnable =
                Boolean(*enabled, "gpp_password.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.gppPasswordMinScore = BoundedUInt(
                *minScore, "gpp_password.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.gppPasswordDedupWindowSeconds = BoundedUInt(
                *dedup, "gpp_password.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.gppPasswordStateCapacity = BoundedUInt(
                *capacity, "gpp_password.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("control_panel_proxy")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'control_panel_proxy' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown control_panel_proxy value '" + item.first +
                    "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.controlPanelProxyEnable =
                Boolean(*enabled, "control_panel_proxy.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.controlPanelProxyMinScore = BoundedUInt(
                *minScore, "control_panel_proxy.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.controlPanelProxyDedupWindowSeconds = BoundedUInt(
                *dedup, "control_panel_proxy.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.controlPanelProxyStateCapacity = BoundedUInt(
                *capacity, "control_panel_proxy.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("hidden_user_account")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'hidden_user_account' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown hidden_user_account value '" + item.first +
                    "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.hiddenUserAccountEnable =
                Boolean(*enabled, "hidden_user_account.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.hiddenUserAccountMinScore = BoundedUInt(
                *minScore, "hidden_user_account.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.hiddenUserAccountDedupWindowSeconds = BoundedUInt(
                *dedup, "hidden_user_account.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.hiddenUserAccountStateCapacity = BoundedUInt(
                *capacity, "hidden_user_account.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("password_policy_discovery")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'password_policy_discovery' must be an "
                "object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown password_policy_discovery value '" +
                    item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.passwordPolicyDiscoveryEnable =
                Boolean(*enabled, "password_policy_discovery.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.passwordPolicyDiscoveryMinScore = BoundedUInt(
                *minScore, "password_policy_discovery.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.passwordPolicyDiscoveryDedupWindowSeconds = BoundedUInt(
                *dedup, "password_policy_discovery.dedup_window_seconds",
                0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.passwordPolicyDiscoveryStateCapacity = BoundedUInt(
                *capacity, "password_policy_discovery.state_capacity",
                16, 65536);
    }
    if (const Value* v = root.find("msi_package_install")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'msi_package_install' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown msi_package_install value '" + item.first +
                    "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.msiPackageInstallEnable =
                Boolean(*enabled, "msi_package_install.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.msiPackageInstallMinScore = BoundedUInt(
                *minScore, "msi_package_install.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.msiPackageInstallDedupWindowSeconds = BoundedUInt(
                *dedup, "msi_package_install.dedup_window_seconds",
                0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.msiPackageInstallStateCapacity = BoundedUInt(
                *capacity, "msi_package_install.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("log_enumeration")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'log_enumeration' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown log_enumeration value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.logEnumerationEnable =
                Boolean(*enabled, "log_enumeration.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.logEnumerationMinScore = BoundedUInt(
                *minScore, "log_enumeration.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.logEnumerationDedupWindowSeconds = BoundedUInt(
                *dedup, "log_enumeration.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.logEnumerationStateCapacity = BoundedUInt(
                *capacity, "log_enumeration.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("ps_profile")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'ps_profile' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown ps_profile value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.psProfileEnable = Boolean(*enabled, "ps_profile.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.psProfileMinScore = BoundedUInt(
                *minScore, "ps_profile.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.psProfileDedupWindowSeconds = BoundedUInt(
                *dedup, "ps_profile.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.psProfileStateCapacity = BoundedUInt(
                *capacity, "ps_profile.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("downgrade_attack")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'downgrade_attack' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown downgrade_attack value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.downgradeAttackEnable = Boolean(*enabled, "downgrade_attack.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.downgradeAttackMinScore = BoundedUInt(*minScore, "downgrade_attack.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.downgradeAttackDedupWindowSeconds = BoundedUInt(*dedup, "downgrade_attack.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.downgradeAttackStateCapacity = BoundedUInt(*capacity, "downgrade_attack.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("dpapi_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'dpapi_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown dpapi_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.dpapiAbuseEnable = Boolean(*enabled, "dpapi_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.dpapiAbuseMinScore = BoundedUInt(*minScore, "dpapi_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.dpapiAbuseDedupWindowSeconds = BoundedUInt(*dedup, "dpapi_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.dpapiAbuseStateCapacity = BoundedUInt(*capacity, "dpapi_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("email_collection")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'email_collection' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown email_collection value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.emailCollectionEnable = Boolean(*enabled, "email_collection.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.emailCollectionMinScore = BoundedUInt(*minScore, "email_collection.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.emailCollectionDedupWindowSeconds = BoundedUInt(*dedup, "email_collection.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.emailCollectionStateCapacity = BoundedUInt(*capacity, "email_collection.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("etw_script_tamper")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'etw_script_tamper' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown etw_script_tamper value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.etwScriptTamperEnable = Boolean(*enabled, "etw_script_tamper.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.etwScriptTamperMinScore = BoundedUInt(*minScore, "etw_script_tamper.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.etwScriptTamperDedupWindowSeconds = BoundedUInt(*dedup, "etw_script_tamper.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.etwScriptTamperStateCapacity = BoundedUInt(*capacity, "etw_script_tamper.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("forced_auth")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'forced_auth' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown forced_auth value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.forcedAuthEnable = Boolean(*enabled, "forced_auth.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.forcedAuthMinScore = BoundedUInt(*minScore, "forced_auth.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.forcedAuthDedupWindowSeconds = BoundedUInt(*dedup, "forced_auth.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.forcedAuthStateCapacity = BoundedUInt(*capacity, "forced_auth.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("golden_ticket")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'golden_ticket' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "window_seconds" &&
                item.first != "min_repeat_count")
                throw jsonlite::ParseError(
                    "unknown golden_ticket value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.goldenTicketEnable = Boolean(*enabled, "golden_ticket.enable");
        if (const Value* minScore = v->find("min_score")) {
            cfg.goldenTicketMinScore = BoundedUInt(*minScore, "golden_ticket.min_score", 10, 100);
            std::fprintf(stderr,
                         "[edr-config] note: golden_ticket.min_score is accepted but not consumed "
                         "(detector ctor has no min_score gating; the 55+ house band applies)\n");
        }
        if (const Value* dedup = v->find("dedup_window_seconds")) {
            cfg.goldenTicketDedupWindowSeconds = BoundedUInt(*dedup, "golden_ticket.dedup_window_seconds", 0, 86400);
            std::fprintf(stderr,
                         "[edr-config] note: golden_ticket.dedup_window_seconds is accepted but not "
                         "consumed; use window_seconds which feeds the detector\n");
        }
        if (const Value* capacity = v->find("state_capacity"))
            cfg.goldenTicketStateCapacity = BoundedUInt(*capacity, "golden_ticket.state_capacity", 16, 65536);
        if (const Value* w = v->find("window_seconds"))
            cfg.goldenTicketWindowSeconds = BoundedUInt(*w, "golden_ticket.window_seconds", 30, 86400);
        if (const Value* k = v->find("min_repeat_count"))
            cfg.goldenTicketMinRepeatCount = BoundedUInt(*k, "golden_ticket.min_repeat_count", 2, 10000);
    }
    if (const Value* v = root.find("gpo_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'gpo_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown gpo_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.gpoAbuseEnable = Boolean(*enabled, "gpo_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.gpoAbuseMinScore = BoundedUInt(*minScore, "gpo_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.gpoAbuseDedupWindowSeconds = BoundedUInt(*dedup, "gpo_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.gpoAbuseStateCapacity = BoundedUInt(*capacity, "gpo_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("hidden_artifacts")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'hidden_artifacts' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "window_seconds")
                throw jsonlite::ParseError(
                    "unknown hidden_artifacts value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.hiddenArtifactsEnable = Boolean(*enabled, "hidden_artifacts.enable");
        if (const Value* minScore = v->find("min_score")) {
            cfg.hiddenArtifactsMinScore = BoundedUInt(*minScore, "hidden_artifacts.min_score", 10, 100);
            std::fprintf(stderr,
                         "[edr-config] note: hidden_artifacts.min_score is accepted but not consumed "
                         "(detector ctor has no min_score gating; the 55+ house band applies)\n");
        }
        if (const Value* dedup = v->find("dedup_window_seconds")) {
            cfg.hiddenArtifactsDedupWindowSeconds = BoundedUInt(*dedup, "hidden_artifacts.dedup_window_seconds", 0, 86400);
            std::fprintf(stderr,
                         "[edr-config] note: hidden_artifacts.dedup_window_seconds is accepted but not "
                         "consumed; use window_seconds which feeds the detector\n");
        }
        if (const Value* capacity = v->find("state_capacity"))
            cfg.hiddenArtifactsStateCapacity = BoundedUInt(*capacity, "hidden_artifacts.state_capacity", 16, 65536);
        if (const Value* w = v->find("window_seconds"))
            cfg.hiddenArtifactsWindowSeconds = BoundedUInt(*w, "hidden_artifacts.window_seconds", 30, 86400);
    }
    if (const Value* v = root.find("history_tamper")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'history_tamper' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown history_tamper value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.historyTamperEnable = Boolean(*enabled, "history_tamper.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.historyTamperMinScore = BoundedUInt(*minScore, "history_tamper.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.historyTamperDedupWindowSeconds = BoundedUInt(*dedup, "history_tamper.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.historyTamperStateCapacity = BoundedUInt(*capacity, "history_tamper.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("hive_copy")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'hive_copy' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown hive_copy value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.hiveCopyEnable = Boolean(*enabled, "hive_copy.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.hiveCopyMinScore = BoundedUInt(*minScore, "hive_copy.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.hiveCopyDedupWindowSeconds = BoundedUInt(*dedup, "hive_copy.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.hiveCopyStateCapacity = BoundedUInt(*capacity, "hive_copy.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("hosts_redirect")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'hosts_redirect' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown hosts_redirect value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.hostsRedirectEnable = Boolean(*enabled, "hosts_redirect.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.hostsRedirectMinScore = BoundedUInt(*minScore, "hosts_redirect.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.hostsRedirectDedupWindowSeconds = BoundedUInt(*dedup, "hosts_redirect.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.hostsRedirectStateCapacity = BoundedUInt(*capacity, "hosts_redirect.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("iis_module")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'iis_module' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown iis_module value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.iisModuleEnable = Boolean(*enabled, "iis_module.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.iisModuleMinScore = BoundedUInt(*minScore, "iis_module.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.iisModuleDedupWindowSeconds = BoundedUInt(*dedup, "iis_module.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.iisModuleStateCapacity = BoundedUInt(*capacity, "iis_module.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("input_simulation")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'input_simulation' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "window_seconds" &&
                item.first != "burst_threshold")
                throw jsonlite::ParseError(
                    "unknown input_simulation value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.inputSimulationEnable = Boolean(*enabled, "input_simulation.enable");
        if (const Value* minScore = v->find("min_score")) {
            cfg.inputSimulationMinScore = BoundedUInt(*minScore, "input_simulation.min_score", 10, 100);
            std::fprintf(stderr,
                         "[edr-config] note: input_simulation.min_score is accepted but not consumed "
                         "(detector ctor has no min_score gating; the 55+ house band applies)\n");
        }
        if (const Value* dedup = v->find("dedup_window_seconds")) {
            cfg.inputSimulationDedupWindowSeconds = BoundedUInt(*dedup, "input_simulation.dedup_window_seconds", 0, 86400);
            std::fprintf(stderr,
                         "[edr-config] note: input_simulation.dedup_window_seconds is accepted but not "
                         "consumed; use window_seconds which feeds the detector\n");
        }
        if (const Value* capacity = v->find("state_capacity"))
            cfg.inputSimulationStateCapacity = BoundedUInt(*capacity, "input_simulation.state_capacity", 16, 65536);
        if (const Value* w = v->find("window_seconds"))
            cfg.inputSimulationWindowSeconds = BoundedUInt(*w, "input_simulation.window_seconds", 30, 86400);
        if (const Value* k = v->find("burst_threshold"))
            cfg.inputSimulationBurstThreshold = BoundedUInt(*k, "input_simulation.burst_threshold", 5, 10000);
    }
    if (const Value* v = root.find("logon_script_persist")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'logon_script_persist' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown logon_script_persist value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.logonScriptPersistEnable = Boolean(*enabled, "logon_script_persist.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.logonScriptPersistMinScore = BoundedUInt(*minScore, "logon_script_persist.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.logonScriptPersistDedupWindowSeconds = BoundedUInt(*dedup, "logon_script_persist.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.logonScriptPersistStateCapacity = BoundedUInt(*capacity, "logon_script_persist.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("lsa_package")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'lsa_package' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown lsa_package value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.lsaPackageEnable = Boolean(*enabled, "lsa_package.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.lsaPackageMinScore = BoundedUInt(*minScore, "lsa_package.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.lsaPackageDedupWindowSeconds = BoundedUInt(*dedup, "lsa_package.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.lsaPackageStateCapacity = BoundedUInt(*capacity, "lsa_package.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("motw_bypass")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'motw_bypass' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown motw_bypass value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.motwBypassEnable = Boolean(*enabled, "motw_bypass.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.motwBypassMinScore = BoundedUInt(*minScore, "motw_bypass.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.motwBypassDedupWindowSeconds = BoundedUInt(*dedup, "motw_bypass.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.motwBypassStateCapacity = BoundedUInt(*capacity, "motw_bypass.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("netsh_helper")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'netsh_helper' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown netsh_helper value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.netshHelperEnable = Boolean(*enabled, "netsh_helper.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.netshHelperMinScore = BoundedUInt(*minScore, "netsh_helper.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.netshHelperDedupWindowSeconds = BoundedUInt(*dedup, "netsh_helper.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.netshHelperStateCapacity = BoundedUInt(*capacity, "netsh_helper.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("network_sniffing")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'network_sniffing' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown network_sniffing value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.networkSniffingEnable = Boolean(*enabled, "network_sniffing.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.networkSniffingMinScore = BoundedUInt(*minScore, "network_sniffing.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.networkSniffingDedupWindowSeconds = BoundedUInt(*dedup, "network_sniffing.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.networkSniffingStateCapacity = BoundedUInt(*capacity, "network_sniffing.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("ntds_dit")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'ntds_dit' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown ntds_dit value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.ntdsDitEnable = Boolean(*enabled, "ntds_dit.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.ntdsDitMinScore = BoundedUInt(*minScore, "ntds_dit.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.ntdsDitDedupWindowSeconds = BoundedUInt(*dedup, "ntds_dit.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.ntdsDitStateCapacity = BoundedUInt(*capacity, "ntds_dit.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("pass_the_hash")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'pass_the_hash' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown pass_the_hash value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.passTheHashEnable = Boolean(*enabled, "pass_the_hash.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.passTheHashMinScore = BoundedUInt(*minScore, "pass_the_hash.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.passTheHashDedupWindowSeconds = BoundedUInt(*dedup, "pass_the_hash.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.passTheHashStateCapacity = BoundedUInt(*capacity, "pass_the_hash.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("password_cracking")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'password_cracking' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown password_cracking value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.passwordCrackingEnable = Boolean(*enabled, "password_cracking.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.passwordCrackingMinScore = BoundedUInt(*minScore, "password_cracking.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.passwordCrackingDedupWindowSeconds = BoundedUInt(*dedup, "password_cracking.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.passwordCrackingStateCapacity = BoundedUInt(*capacity, "password_cracking.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("path_interception")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'path_interception' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown path_interception value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.pathInterceptionEnable = Boolean(*enabled, "path_interception.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.pathInterceptionMinScore = BoundedUInt(*minScore, "path_interception.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.pathInterceptionDedupWindowSeconds = BoundedUInt(*dedup, "path_interception.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.pathInterceptionStateCapacity = BoundedUInt(*capacity, "path_interception.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("pe_anomaly")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'pe_anomaly' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "max_file_bytes")
                throw jsonlite::ParseError(
                    "unknown pe_anomaly value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.peAnomalyEnable = Boolean(*enabled, "pe_anomaly.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.peAnomalyMinScore = BoundedUInt(*minScore, "pe_anomaly.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.peAnomalyDedupWindowSeconds = BoundedUInt(*dedup, "pe_anomaly.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.peAnomalyStateCapacity = BoundedUInt(*capacity, "pe_anomaly.state_capacity", 16, 65536);
        if (const Value* m = v->find("max_file_bytes"))
            cfg.peAnomalyMaxFileBytes =
                static_cast<uint64_t>(BoundedUInt(
                    *m, "pe_anomaly.max_file_bytes", 4096, 268435456));
    }
    if (const Value* v = root.find("ransom_ops")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'ransom_ops' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown ransom_ops value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.ransomOpsEnable = Boolean(*enabled, "ransom_ops.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.ransomOpsMinScore = BoundedUInt(*minScore, "ransom_ops.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.ransomOpsDedupWindowSeconds = BoundedUInt(*dedup, "ransom_ops.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.ransomOpsStateCapacity = BoundedUInt(*capacity, "ransom_ops.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("rdp_session_hijack")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'rdp_session_hijack' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown rdp_session_hijack value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.rdpSessionHijackEnable = Boolean(*enabled, "rdp_session_hijack.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.rdpSessionHijackMinScore = BoundedUInt(*minScore, "rdp_session_hijack.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.rdpSessionHijackDedupWindowSeconds = BoundedUInt(*dedup, "rdp_session_hijack.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.rdpSessionHijackStateCapacity = BoundedUInt(*capacity, "rdp_session_hijack.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("reg_cred_hunt")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'reg_cred_hunt' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown reg_cred_hunt value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.regCredHuntEnable = Boolean(*enabled, "reg_cred_hunt.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.regCredHuntMinScore = BoundedUInt(*minScore, "reg_cred_hunt.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.regCredHuntDedupWindowSeconds = BoundedUInt(*dedup, "reg_cred_hunt.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.regCredHuntStateCapacity = BoundedUInt(*capacity, "reg_cred_hunt.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("remote_exec")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'remote_exec' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown remote_exec value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.remoteExecEnable = Boolean(*enabled, "remote_exec.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.remoteExecMinScore = BoundedUInt(*minScore, "remote_exec.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.remoteExecDedupWindowSeconds = BoundedUInt(*dedup, "remote_exec.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.remoteExecStateCapacity = BoundedUInt(*capacity, "remote_exec.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("secboot_tamper")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'secboot_tamper' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown secboot_tamper value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.secbootTamperEnable = Boolean(*enabled, "secboot_tamper.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.secbootTamperMinScore = BoundedUInt(*minScore, "secboot_tamper.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.secbootTamperDedupWindowSeconds = BoundedUInt(*dedup, "secboot_tamper.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.secbootTamperStateCapacity = BoundedUInt(*capacity, "secboot_tamper.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("shim_db")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'shim_db' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown shim_db value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.shimDbEnable = Boolean(*enabled, "shim_db.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.shimDbMinScore = BoundedUInt(*minScore, "shim_db.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.shimDbDedupWindowSeconds = BoundedUInt(*dedup, "shim_db.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.shimDbStateCapacity = BoundedUInt(*capacity, "shim_db.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("signed_binary_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'signed_binary_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown signed_binary_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.signedBinaryAbuseEnable = Boolean(*enabled, "signed_binary_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.signedBinaryAbuseMinScore = BoundedUInt(*minScore, "signed_binary_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.signedBinaryAbuseDedupWindowSeconds = BoundedUInt(*dedup, "signed_binary_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.signedBinaryAbuseStateCapacity = BoundedUInt(*capacity, "signed_binary_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("sip_hijack")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'sip_hijack' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown sip_hijack value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.sipHijackEnable = Boolean(*enabled, "sip_hijack.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.sipHijackMinScore = BoundedUInt(*minScore, "sip_hijack.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.sipHijackDedupWindowSeconds = BoundedUInt(*dedup, "sip_hijack.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.sipHijackStateCapacity = BoundedUInt(*capacity, "sip_hijack.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("ssh_key_persistence")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'ssh_key_persistence' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown ssh_key_persistence value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.sshKeyPersistenceEnable = Boolean(*enabled, "ssh_key_persistence.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.sshKeyPersistenceMinScore = BoundedUInt(*minScore, "ssh_key_persistence.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.sshKeyPersistenceDedupWindowSeconds = BoundedUInt(*dedup, "ssh_key_persistence.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.sshKeyPersistenceStateCapacity = BoundedUInt(*capacity, "ssh_key_persistence.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("ticket_cache_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'ticket_cache_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown ticket_cache_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.ticketCacheAbuseEnable = Boolean(*enabled, "ticket_cache_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.ticketCacheAbuseMinScore = BoundedUInt(*minScore, "ticket_cache_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.ticketCacheAbuseDedupWindowSeconds = BoundedUInt(*dedup, "ticket_cache_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.ticketCacheAbuseStateCapacity = BoundedUInt(*capacity, "ticket_cache_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("token_impersonation")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'token_impersonation' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown token_impersonation value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.tokenImpersonationEnable = Boolean(*enabled, "token_impersonation.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.tokenImpersonationMinScore = BoundedUInt(*minScore, "token_impersonation.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.tokenImpersonationDedupWindowSeconds = BoundedUInt(*dedup, "token_impersonation.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.tokenImpersonationStateCapacity = BoundedUInt(*capacity, "token_impersonation.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("handle_guard")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'handle_guard' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown handle_guard value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.handleGuardEnable = Boolean(*enabled, "handle_guard.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.handleGuardMinScore = BoundedUInt(*minScore, "handle_guard.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.handleGuardDedupWindowSeconds = BoundedUInt(*dedup, "handle_guard.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.handleGuardStateCapacity = BoundedUInt(*capacity, "handle_guard.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("named_pipe_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'named_pipe_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_distinct_pids" &&
                item.first != "dedup_window_seconds")
                throw jsonlite::ParseError(
                    "unknown named_pipe_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.namedPipeAbuseEnable = Boolean(*enabled, "named_pipe_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.namedPipeAbuseMinScore = BoundedUInt(*minScore, "named_pipe_abuse.min_score", 10, 100);
        if (const Value* window = v->find("window_seconds"))
            cfg.namedPipeAbuseWindowSeconds = BoundedUInt(*window, "named_pipe_abuse.window_seconds", 1, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.namedPipeAbuseStateCapacity = BoundedUInt(*capacity, "named_pipe_abuse.state_capacity", 16, 65536);
        if (const Value* pids = v->find("min_distinct_pids"))
            cfg.namedPipeAbuseMinDistinctPids = BoundedUInt(*pids, "named_pipe_abuse.min_distinct_pids", 2, 256);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.namedPipeAbuseDedupWindowSeconds = BoundedUInt(*dedup, "named_pipe_abuse.dedup_window_seconds", 0, 86400);
    }
    if (const Value* v = root.find("web_exfil")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'web_exfil' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown web_exfil value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.webExfilEnable = Boolean(*enabled, "web_exfil.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.webExfilMinScore = BoundedUInt(*minScore, "web_exfil.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.webExfilDedupWindowSeconds = BoundedUInt(*dedup, "web_exfil.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.webExfilStateCapacity = BoundedUInt(*capacity, "web_exfil.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("wifi_cred_theft")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'wifi_cred_theft' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "window_seconds" &&
                item.first != "min_repeat_count")
                throw jsonlite::ParseError(
                    "unknown wifi_cred_theft value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.wifiCredTheftEnable = Boolean(*enabled, "wifi_cred_theft.enable");
        if (const Value* minScore = v->find("min_score")) {
            cfg.wifiCredTheftMinScore = BoundedUInt(*minScore, "wifi_cred_theft.min_score", 10, 100);
            std::fprintf(stderr,
                         "[edr-config] note: wifi_cred_theft.min_score is accepted but not consumed "
                         "(detector ctor has no min_score gating; the 55+ house band applies)\n");
        }
        if (const Value* dedup = v->find("dedup_window_seconds")) {
            cfg.wifiCredTheftDedupWindowSeconds = BoundedUInt(*dedup, "wifi_cred_theft.dedup_window_seconds", 0, 86400);
            std::fprintf(stderr,
                         "[edr-config] note: wifi_cred_theft.dedup_window_seconds is accepted but not "
                         "consumed; use window_seconds which feeds the detector\n");
        }
        if (const Value* capacity = v->find("state_capacity"))
            cfg.wifiCredTheftStateCapacity = BoundedUInt(*capacity, "wifi_cred_theft.state_capacity", 16, 65536);
        if (const Value* w = v->find("window_seconds"))
            cfg.wifiCredTheftWindowSeconds = BoundedUInt(*w, "wifi_cred_theft.window_seconds", 30, 86400);
        if (const Value* k = v->find("min_repeat_count"))
            cfg.wifiCredTheftMinRepeatCount = BoundedUInt(*k, "wifi_cred_theft.min_repeat_count", 2, 10000);
    }
    if (const Value* v = root.find("winrm_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'winrm_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown winrm_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.winrmAbuseEnable = Boolean(*enabled, "winrm_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.winrmAbuseMinScore = BoundedUInt(*minScore, "winrm_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.winrmAbuseDedupWindowSeconds = BoundedUInt(*dedup, "winrm_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.winrmAbuseStateCapacity = BoundedUInt(*capacity, "winrm_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("winrm_config_tamper")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'winrm_config_tamper' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown winrm_config_tamper value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.winrmConfigTamperEnable = Boolean(*enabled, "winrm_config_tamper.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.winrmConfigTamperMinScore = BoundedUInt(*minScore, "winrm_config_tamper.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.winrmConfigTamperDedupWindowSeconds = BoundedUInt(*dedup, "winrm_config_tamper.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.winrmConfigTamperStateCapacity = BoundedUInt(*capacity, "winrm_config_tamper.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("xsl_script")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'xsl_script' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown xsl_script value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.xslScriptEnable = Boolean(*enabled, "xsl_script.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.xslScriptMinScore = BoundedUInt(*minScore, "xsl_script.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.xslScriptDedupWindowSeconds = BoundedUInt(*dedup, "xsl_script.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.xslScriptStateCapacity = BoundedUInt(*capacity, "xsl_script.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("health")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'health' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "poll_seconds" &&
                item.first != "dispatch_timing")
                throw jsonlite::ParseError(
                    "unknown health value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.healthEnable = Boolean(*enabled, "health.enable");
        if (const Value* poll = v->find("poll_seconds"))
            cfg.healthPollSeconds = BoundedUInt(
                *poll, "health.poll_seconds", 30, 86400);
        if (const Value* timing = v->find("dispatch_timing")) {
            if (timing->type != jsonlite::Type::Object)
                throw jsonlite::ParseError(
                    "config value 'health.dispatch_timing' must be an object");
            for (const auto& item : timing->object) {
                if (item.first != "enable" && item.first != "slow_warn_us" &&
                    item.first != "warn_cooldown_seconds")
                    throw jsonlite::ParseError(
                        "unknown health.dispatch_timing value '" + item.first + "'");
            }
            if (const Value* enabled = timing->find("enable"))
                cfg.healthDispatchTimingEnable = Boolean(
                    *enabled, "health.dispatch_timing.enable");
            if (const Value* threshold = timing->find("slow_warn_us"))
                cfg.healthDispatchSlowWarnUs = BoundedUInt(
                    *threshold, "health.dispatch_timing.slow_warn_us", 0, 60000000);
            if (const Value* cooldown = timing->find("warn_cooldown_seconds"))
                cfg.healthDispatchWarnCooldownSeconds = BoundedUInt(
                    *cooldown, "health.dispatch_timing.warn_cooldown_seconds", 0, 86400);
        }
    }
    if (const Value* v = root.find("fileless_attack")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'fileless_attack' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown fileless_attack value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.filelessEnable = Boolean(*enabled, "fileless_attack.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.filelessMinScore = BoundedUInt(
                *minScore, "fileless_attack.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.filelessDedupWindowSeconds = BoundedUInt(
                *dedup, "fileless_attack.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.filelessStateCapacity = BoundedUInt(
                *capacity, "fileless_attack.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("api_hook")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'api_hook' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown api_hook value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.apiHookEnable = Boolean(*enabled, "api_hook.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.apiHookMinScore = BoundedUInt(
                *minScore, "api_hook.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.apiHookDedupWindowSeconds = BoundedUInt(
                *dedup, "api_hook.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.apiHookStateCapacity = BoundedUInt(
                *capacity, "api_hook.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("remote_access")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'remote_access' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown remote_access value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.remoteAccessEnable = Boolean(*enabled, "remote_access.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.remoteAccessWindowSeconds = BoundedUInt(
                *window, "remote_access.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
           cfg.remoteAccessStateCapacity = BoundedUInt(
               *capacity, "remote_access.state_capacity", 16, 65536);
   }
    if (const Value* v = root.find("credential_dumping")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'credential_dumping' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown credential_dumping value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.credentialDumpEnable = Boolean(*enabled, "credential_dumping.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.credentialDumpWindowSeconds = BoundedUInt(
                *window, "credential_dumping.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.credentialDumpStateCapacity = BoundedUInt(
                *capacity, "credential_dumping.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("data_exfiltration")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'data_exfiltration' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "dns_tunnel_threshold")
                throw jsonlite::ParseError(
                    "unknown data_exfiltration value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.dataExfilEnable = Boolean(*enabled, "data_exfiltration.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.dataExfilWindowSeconds = BoundedUInt(
                *window, "data_exfiltration.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.dataExfilStateCapacity = BoundedUInt(
                *capacity, "data_exfiltration.state_capacity", 16, 65536);
        if (const Value* threshold = v->find("dns_tunnel_threshold"))
            cfg.dataExfilDnsTunnelThreshold = BoundedUInt(
                *threshold, "data_exfiltration.dns_tunnel_threshold", 5, 10000);
    }
    if (const Value* v = root.find("privilege_escalation")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'privilege_escalation' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown privilege_escalation value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.privEscEnable = Boolean(*enabled, "privilege_escalation.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.privEscWindowSeconds = BoundedUInt(
                *window, "privilege_escalation.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.privEscStateCapacity = BoundedUInt(
                *capacity, "privilege_escalation.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("ntlm_relay")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'ntlm_relay' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" && item.first != "min_events")
                throw jsonlite::ParseError(
                    "unknown ntlm_relay value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.ntlmRelayEnable = Boolean(*enabled, "ntlm_relay.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.ntlmRelayWindowSeconds = BoundedUInt(
                *window, "ntlm_relay.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.ntlmRelayStateCapacity = BoundedUInt(
                *capacity, "ntlm_relay.state_capacity", 16, 65536);
        if (const Value* minEv = v->find("min_events"))
            cfg.ntlmRelayMinEvents = BoundedUInt(
                *minEv, "ntlm_relay.min_events", 2, 1000);
    }
    if (const Value* v = root.find("browser_theft")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'browser_theft' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown browser_theft value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.browserTheftEnable = Boolean(*enabled, "browser_theft.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.browserTheftWindowSeconds = BoundedUInt(
                *window, "browser_theft.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.browserTheftStateCapacity = BoundedUInt(
                *capacity, "browser_theft.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("browser_extension")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'browser_extension' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "allowlist")
                throw jsonlite::ParseError(
                    "unknown browser_extension value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.browserExtensionEnable = Boolean(
                *enabled, "browser_extension.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.browserExtensionMinScore = BoundedUInt(
                *minScore, "browser_extension.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.browserExtensionDedupWindowSeconds = BoundedUInt(
                *dedup, "browser_extension.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.browserExtensionStateCapacity = BoundedUInt(
                *capacity, "browser_extension.state_capacity", 16, 65536);
        if (const Value* allowlist = v->find("allowlist")) {
            if (allowlist->type != jsonlite::Type::Array)
                throw jsonlite::ParseError(
                    "config value 'browser_extension.allowlist' must be an array");
            std::vector<std::string> parsed;
            parsed.reserve(allowlist->array.size());
            for (const Value& entry : allowlist->array) {
                parsed.push_back(BrowserExtensionAllowlistEntry(
                    entry, "browser_extension.allowlist[]"));
            }
            cfg.browserExtensionAllowlist = std::move(parsed);
        }
    }
    if (const Value* v = root.find("archive_staging")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'archive_staging' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown archive_staging value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.archiveStagingEnable = Boolean(*enabled, "archive_staging.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.archiveStagingWindowSeconds = BoundedUInt(
                *window, "archive_staging.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.archiveStagingStateCapacity = BoundedUInt(
                *capacity, "archive_staging.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("bits_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'bits_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown bits_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.bitsAbuseEnable = Boolean(*enabled, "bits_abuse.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.bitsAbuseWindowSeconds = BoundedUInt(
                *window, "bits_abuse.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.bitsAbuseStateCapacity = BoundedUInt(
                *capacity, "bits_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("doh_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'doh_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_repeat_count")
                throw jsonlite::ParseError(
                    "unknown doh_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.dohAbuseEnable = Boolean(*enabled, "doh_abuse.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.dohAbuseWindowSeconds = BoundedUInt(
                *window, "doh_abuse.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.dohAbuseStateCapacity = BoundedUInt(
                *capacity, "doh_abuse.state_capacity", 16, 65536);
        if (const Value* minRepeat = v->find("min_repeat_count"))
            cfg.dohAbuseMinRepeatCount = BoundedUInt(
                *minRepeat, "doh_abuse.min_repeat_count", 1, 1024);
    }
    if (const Value* v = root.find("svc_install")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'svc_install' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable")
                throw jsonlite::ParseError(
                    "unknown svc_install value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.svcInstallEnable = Boolean(*enabled, "svc_install.enable");
    }
    if (const Value* v = root.find("shadow_copy")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'shadow_copy' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown shadow_copy value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.shadowCopyEnable = Boolean(*enabled, "shadow_copy.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.shadowCopyMinScore = BoundedUInt(
                *minScore, "shadow_copy.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.shadowCopyDedupWindowSeconds = BoundedUInt(
                *dedup, "shadow_copy.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.shadowCopyStateCapacity = BoundedUInt(
                *capacity, "shadow_copy.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("persist_burst")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'persist_burst' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_score" &&
                item.first != "dedup_seconds")
                throw jsonlite::ParseError(
                    "unknown persist_burst value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.persistBurstEnable = Boolean(*enabled, "persist_burst.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.persistBurstWindowSeconds = BoundedUInt(
                *window, "persist_burst.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.persistBurstStateCapacity = BoundedUInt(
                *capacity, "persist_burst.state_capacity", 16, 65536);
        if (const Value* minScore = v->find("min_score"))
            cfg.persistBurstMinScore = BoundedUInt(
                *minScore, "persist_burst.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_seconds"))
            cfg.persistBurstDedupSeconds = BoundedUInt(
                *dedup, "persist_burst.dedup_seconds", 0, 86400);
    }
    if (const Value* v = root.find("cryptominer")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'cryptominer' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown cryptominer value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.cryptoMinerEnable = Boolean(*enabled, "cryptominer.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.cryptoMinerWindowSeconds = BoundedUInt(
                *window, "cryptominer.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.cryptoMinerStateCapacity = BoundedUInt(
                *capacity, "cryptominer.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("anti_analysis")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'anti_analysis' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown anti_analysis value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.antiAnalysisEnable = Boolean(*enabled, "anti_analysis.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.antiAnalysisWindowSeconds = BoundedUInt(
                *window, "anti_analysis.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.antiAnalysisStateCapacity = BoundedUInt(
                *capacity, "anti_analysis.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("script_host_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'script_host_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable")
                throw jsonlite::ParseError(
                    "unknown script_host_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.scriptHostAbuseEnable =
                Boolean(*enabled, "script_host_abuse.enable");
    }
    if (const Value* v = root.find("account_op")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'account_op' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable")
                throw jsonlite::ParseError(
                    "unknown account_op value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.accountOpEnable = Boolean(*enabled, "account_op.enable");
    }
    if (const Value* v = root.find("tunnel_tool")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'tunnel_tool' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable")
                throw jsonlite::ParseError(
                    "unknown tunnel_tool value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.tunnelToolEnable = Boolean(*enabled, "tunnel_tool.enable");
    }
    if (const Value* v = root.find("surveillance")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'surveillance' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_signals")
                throw jsonlite::ParseError(
                    "unknown surveillance value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.surveillanceEnable =
                Boolean(*enabled, "surveillance.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.surveillanceWindowSeconds = BoundedUInt(
                *window, "surveillance.window_seconds", 30, 3600);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.surveillanceStateCapacity = BoundedUInt(
                *capacity, "surveillance.state_capacity", 16, 65536);
        if (const Value* minSignals = v->find("min_signals"))
            cfg.surveillanceMinSignals = BoundedUInt(
                *minSignals, "surveillance.min_signals", 1, 4);
    }
    if (const Value* v = root.find("clipboard_theft")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'clipboard_theft' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_reads" &&
                item.first != "dedup_window_seconds")
                throw jsonlite::ParseError(
                    "unknown clipboard_theft value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.clipboardTheftEnable =
                Boolean(*enabled, "clipboard_theft.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.clipboardTheftMinScore = BoundedUInt(
                *minScore, "clipboard_theft.min_score", 10, 100);
        if (const Value* window = v->find("window_seconds"))
            cfg.clipboardTheftWindowSeconds = BoundedUInt(
                *window, "clipboard_theft.window_seconds", 1, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.clipboardTheftStateCapacity = BoundedUInt(
                *capacity, "clipboard_theft.state_capacity", 16, 65536);
        if (const Value* reads = v->find("min_reads"))
            cfg.clipboardTheftMinReads = BoundedUInt(
                *reads, "clipboard_theft.min_reads", 1, 1000);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.clipboardTheftDedupWindowSeconds = BoundedUInt(
                *dedup, "clipboard_theft.dedup_window_seconds", 0, 86400);
    }
    if (const Value* v = root.find("webshell")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'webshell' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "state_capacity" &&
                item.first != "dedup_seconds")
                throw jsonlite::ParseError(
                    "unknown webshell value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.webshellEnable = Boolean(*enabled, "webshell.enable");
        if (const Value* capacity = v->find("state_capacity"))
            cfg.webshellStateCapacity = BoundedUInt(
                *capacity, "webshell.state_capacity", 16, 65536);
        if (const Value* dedup = v->find("dedup_seconds"))
            cfg.webshellDedupSeconds = BoundedUInt(
                *dedup, "webshell.dedup_seconds", 0, 86400);
    }
    if (const Value* v = root.find("usb_exfil")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'usb_exfil' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_file_count" &&
                item.first != "dedup_seconds")
                throw jsonlite::ParseError(
                    "unknown usb_exfil value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.usbExfilEnable = Boolean(*enabled, "usb_exfil.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.usbExfilWindowSeconds = BoundedUInt(
                *window, "usb_exfil.window_seconds", 30, 3600);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.usbExfilStateCapacity = BoundedUInt(
                *capacity, "usb_exfil.state_capacity", 16, 65536);
        if (const Value* minFiles = v->find("min_file_count"))
            cfg.usbExfilMinFileCount = BoundedUInt(
                *minFiles, "usb_exfil.min_file_count", 2, 1000);
        if (const Value* dedup = v->find("dedup_seconds"))
            cfg.usbExfilDedupSeconds = BoundedUInt(
                *dedup, "usb_exfil.dedup_seconds", 0, 86400);
    }
    if (const Value* v = root.find("c2_beacon")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'c2_beacon' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_repeat_endpoints" &&
                item.first != "min_connections_per_endpoint")
                throw jsonlite::ParseError(
                    "unknown c2_beacon value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.c2BeaconEnable = Boolean(*enabled, "c2_beacon.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.c2BeaconWindowSeconds = BoundedUInt(
                *window, "c2_beacon.window_seconds", 60, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.c2BeaconStateCapacity = BoundedUInt(
                *capacity, "c2_beacon.state_capacity", 256, 65536);
        if (const Value* minEndpoints = v->find("min_repeat_endpoints"))
            cfg.c2BeaconMinRepeatEndpoints = BoundedUInt(
                *minEndpoints, "c2_beacon.min_repeat_endpoints", 1, 64);
        if (const Value* minConnections =
                v->find("min_connections_per_endpoint"))
            cfg.c2BeaconMinConnectionsPerEndpoint = BoundedUInt(
                *minConnections, "c2_beacon.min_connections_per_endpoint",
                1, 64);
    }
    if (const Value* v = root.find("ransom_burst")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'ransom_burst' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_file_count" &&
                item.first != "min_distinct_extensions")
                throw jsonlite::ParseError(
                    "unknown ransom_burst value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.ransomBurstEnable = Boolean(*enabled, "ransom_burst.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.ransomBurstWindowSeconds = BoundedUInt(
                *window, "ransom_burst.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.ransomBurstStateCapacity = BoundedUInt(
                *capacity, "ransom_burst.state_capacity", 256, 65536);
        if (const Value* count = v->find("min_file_count"))
            cfg.ransomBurstMinFileCount = BoundedUInt(
                *count, "ransom_burst.min_file_count", 1, 100000);
        if (const Value* extensions = v->find("min_distinct_extensions"))
            cfg.ransomBurstMinDistinctExtensions = BoundedUInt(
                *extensions, "ransom_burst.min_distinct_extensions", 1, 1000);
    }
    if (const Value* v = root.find("process_hollowing")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'process_hollowing' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown process_hollowing value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.processHollowingEnable =
                Boolean(*enabled, "process_hollowing.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.processHollowingMinScore = BoundedUInt(
                *minScore, "process_hollowing.min_score", 20, 100);
        if (const Value* window = v->find("dedup_window_seconds"))
            cfg.processHollowingDedupWindowSeconds = BoundedUInt(
                *window, "process_hollowing.dedup_window_seconds", 5, 3600);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.processHollowingStateCapacity = BoundedUInt(
                *capacity, "process_hollowing.state_capacity", 256, 65536);
    }
    if (const Value* v = root.find("dll_hijack")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'dll_hijack' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable")
                throw jsonlite::ParseError(
                    "unknown dll_hijack value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.dllHijackEnable = Boolean(*enabled, "dll_hijack.enable");
    }
    if (const Value* v = root.find("registry_persistence")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'registry_persistence' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown registry_persistence value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.registryPersistenceEnable =
                Boolean(*enabled, "registry_persistence.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.registryPersistenceWindowSeconds = BoundedUInt(
                *window, "registry_persistence.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.registryPersistenceStateCapacity = BoundedUInt(
                *capacity, "registry_persistence.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("anti_forensics")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'anti_forensics' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown anti_forensics value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.antiForensicsEnable =
                Boolean(*enabled, "anti_forensics.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.antiForensicsWindowSeconds = BoundedUInt(
                *window, "anti_forensics.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.antiForensicsStateCapacity = BoundedUInt(
                *capacity, "anti_forensics.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("time_change")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'time_change' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "tolerance_seconds" &&
                item.first != "big_jump_seconds")
                throw jsonlite::ParseError(
                    "unknown time_change value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.timeChangeEnable = Boolean(*enabled, "time_change.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.timeChangeWindowSeconds = BoundedUInt(
                *window, "time_change.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.timeChangeStateCapacity = BoundedUInt(
                *capacity, "time_change.state_capacity", 16, 65536);
        if (const Value* tolerance = v->find("tolerance_seconds"))
            cfg.timeChangeToleranceSeconds = BoundedUInt(
                *tolerance, "time_change.tolerance_seconds", 0, 3600);
        if (const Value* bigJump = v->find("big_jump_seconds"))
            cfg.timeChangeBigJumpSeconds = BoundedUInt(
                *bigJump, "time_change.big_jump_seconds", 60, 31536000);
    }
    if (const Value* v = root.find("privileged_group")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'privileged_group' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown privileged_group value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.privilegedGroupEnable =
                Boolean(*enabled, "privileged_group.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.privilegedGroupWindowSeconds = BoundedUInt(
                *window, "privileged_group.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.privilegedGroupStateCapacity = BoundedUInt(
                *capacity, "privileged_group.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("firewall_rule")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'firewall_rule' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable")
                throw jsonlite::ParseError(
                    "unknown firewall_rule value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.firewallRuleEnable = Boolean(*enabled, "firewall_rule.enable");
    }
    if (const Value* v = root.find("share_change")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'share_change' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable")
                throw jsonlite::ParseError(
                    "unknown share_change value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.shareChangeEnable = Boolean(*enabled, "share_change.enable");
    }
    if (const Value* v = root.find("local_account")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'local_account' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable")
                throw jsonlite::ParseError(
                    "unknown local_account value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.localAccountEnable = Boolean(*enabled, "local_account.enable");
    }
    if (const Value* v = root.find("reg_modify")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'reg_modify' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown reg_modify value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.regModifyEnable = Boolean(*enabled, "reg_modify.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.regModifyMinScore = BoundedUInt(
                *minScore, "reg_modify.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.regModifyDedupWindowSeconds = BoundedUInt(
                *dedup, "reg_modify.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.regModifyStateCapacity = BoundedUInt(
                *capacity, "reg_modify.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("wmi_exec")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'wmi_exec' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown wmi_exec value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.wmiExecEnable = Boolean(*enabled, "wmi_exec.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.wmiExecMinScore = BoundedUInt(
                *minScore, "wmi_exec.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.wmiExecDedupWindowSeconds = BoundedUInt(
                *dedup, "wmi_exec.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.wmiExecStateCapacity = BoundedUInt(
                *capacity, "wmi_exec.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("local_collect")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'local_collect' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown local_collect value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.localCollectEnable = Boolean(*enabled, "local_collect.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.localCollectMinScore = BoundedUInt(
                *minScore, "local_collect.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.localCollectDedupWindowSeconds = BoundedUInt(
                *dedup, "local_collect.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.localCollectStateCapacity = BoundedUInt(
                *capacity, "local_collect.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("lateral_transfer")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'lateral_transfer' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown lateral_transfer value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.lateralTransferEnable =
                Boolean(*enabled, "lateral_transfer.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.lateralTransferMinScore = BoundedUInt(
                *minScore, "lateral_transfer.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.lateralTransferDedupWindowSeconds = BoundedUInt(
                *dedup, "lateral_transfer.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.lateralTransferStateCapacity = BoundedUInt(
                *capacity, "lateral_transfer.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("defense_evasion")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'defense_evasion' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_techniques" &&
                item.first != "dedup_seconds")
                throw jsonlite::ParseError(
                    "unknown defense_evasion value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.defenseEvasionEnable =
                Boolean(*enabled, "defense_evasion.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.defenseEvasionWindowSeconds = BoundedUInt(
                *window, "defense_evasion.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.defenseEvasionStateCapacity = BoundedUInt(
                *capacity, "defense_evasion.state_capacity", 16, 65536);
        if (const Value* minTech = v->find("min_techniques"))
            cfg.defenseEvasionMinTechniques = BoundedUInt(
                *minTech, "defense_evasion.min_techniques", 2, 16);
        if (const Value* dedup = v->find("dedup_seconds"))
            cfg.defenseEvasionDedupSeconds = BoundedUInt(
                *dedup, "defense_evasion.dedup_seconds", 0, 86400);
    }
    if (const Value* v = root.find("discovery_recon")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'discovery_recon' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_techniques" &&
                item.first != "dedup_seconds")
                throw jsonlite::ParseError(
                    "unknown discovery_recon value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.discoveryReconEnable =
                Boolean(*enabled, "discovery_recon.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.discoveryReconWindowSeconds = BoundedUInt(
                *window, "discovery_recon.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.discoveryReconStateCapacity = BoundedUInt(
                *capacity, "discovery_recon.state_capacity", 16, 65536);
        if (const Value* minTech = v->find("min_techniques"))
            cfg.discoveryReconMinTechniques = BoundedUInt(
                *minTech, "discovery_recon.min_techniques", 2, 16);
        if (const Value* dedup = v->find("dedup_seconds"))
            cfg.discoveryReconDedupSeconds = BoundedUInt(
                *dedup, "discovery_recon.dedup_seconds", 0, 86400);
    }
    if (const Value* v = root.find("logon_success")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError("config value 'logon_success' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" && item.first != "min_failures")
                throw jsonlite::ParseError("unknown logon_success value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.logonSuccessEnable = Boolean(*enabled, "logon_success.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.logonSuccessWindowSeconds = BoundedUInt(
                *window, "logon_success.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.logonSuccessStateCapacity = BoundedUInt(
                *capacity, "logon_success.state_capacity", 256, 8192);
        if (const Value* failures = v->find("min_failures"))
            cfg.logonSuccessMinFailures = BoundedUInt(
                *failures, "logon_success.min_failures", 2, 256);
    }
    if (const Value* v = root.find("logon_brute_force")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'logon_brute_force' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_failures" &&
                item.first != "dedup_seconds")
                throw jsonlite::ParseError(
                    "unknown logon_brute_force value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.logonBruteForceEnable =
                Boolean(*enabled, "logon_brute_force.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.logonBruteForceWindowSeconds = BoundedUInt(
                *window, "logon_brute_force.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.logonBruteForceStateCapacity = BoundedUInt(
                *capacity, "logon_brute_force.state_capacity", 256, 65536);
        if (const Value* failures = v->find("min_failures"))
            cfg.logonBruteForceMinFailures = BoundedUInt(
                *failures, "logon_brute_force.min_failures", 2, 100000);
        if (const Value* dedup = v->find("dedup_seconds"))
            cfg.logonBruteForceDedupSeconds = BoundedUInt(
                *dedup, "logon_brute_force.dedup_seconds", 0, 86400);
    }
    if (const Value* v = root.find("password_spray")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'password_spray' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_failures" &&
                item.first != "min_distinct_users" &&
                item.first != "success_followup_seconds" &&
                item.first != "dedup_seconds" &&
                item.first != "max_failures_per_source")
                throw jsonlite::ParseError(
                    "unknown password_spray value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.passwordSprayEnable =
                Boolean(*enabled, "password_spray.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.passwordSprayWindowSeconds = BoundedUInt(
                *window, "password_spray.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.passwordSprayStateCapacity = BoundedUInt(
                *capacity, "password_spray.state_capacity", 64, 65536);
        if (const Value* failures = v->find("min_failures"))
            cfg.passwordSprayMinFailures = BoundedUInt(
                *failures, "password_spray.min_failures", 2, 100000);
        if (const Value* users = v->find("min_distinct_users"))
            cfg.passwordSprayMinDistinctUsers = BoundedUInt(
                *users, "password_spray.min_distinct_users", 2, 100000);
        if (const Value* followup = v->find("success_followup_seconds"))
            cfg.passwordSpraySuccessFollowupSeconds = BoundedUInt(
                *followup, "password_spray.success_followup_seconds", 1, 86400);
        if (const Value* dedup = v->find("dedup_seconds"))
            cfg.passwordSprayDedupSeconds = BoundedUInt(
                *dedup, "password_spray.dedup_seconds", 0, 86400);
        if (const Value* maximum = v->find("max_failures_per_source"))
            cfg.passwordSprayMaxFailuresPerSource = BoundedUInt(
                *maximum, "password_spray.max_failures_per_source", 2, 4096);
        if (cfg.passwordSprayMaxFailuresPerSource <
                cfg.passwordSprayMinFailures ||
            cfg.passwordSprayMaxFailuresPerSource <
                cfg.passwordSprayMinDistinctUsers)
            throw jsonlite::ParseError(
                "password_spray.max_failures_per_source must be >= "
                "min_failures and min_distinct_users");
    }
    if (const Value* v = root.find("kerberoast_burst")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'kerberoast_burst' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_service_count" &&
                item.first != "dedup_seconds" &&
                item.first != "max_services_per_requester")
                throw jsonlite::ParseError(
                    "unknown kerberoast_burst value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.kerberoastBurstEnable =
                Boolean(*enabled, "kerberoast_burst.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.kerberoastBurstWindowSeconds = BoundedUInt(
                *window, "kerberoast_burst.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.kerberoastBurstStateCapacity = BoundedUInt(
                *capacity, "kerberoast_burst.state_capacity", 64, 65536);
        if (const Value* count = v->find("min_service_count"))
            cfg.kerberoastBurstMinServiceCount = BoundedUInt(
                *count, "kerberoast_burst.min_service_count", 2, 4096);
        if (const Value* dedup = v->find("dedup_seconds"))
            cfg.kerberoastBurstDedupSeconds = BoundedUInt(
                *dedup, "kerberoast_burst.dedup_seconds", 0, 86400);
        if (const Value* maximum = v->find("max_services_per_requester"))
            cfg.kerberoastBurstMaxServicesPerRequester = BoundedUInt(
                *maximum, "kerberoast_burst.max_services_per_requester", 2,
                4096);
        if (cfg.kerberoastBurstMaxServicesPerRequester <
            cfg.kerberoastBurstMinServiceCount)
            throw jsonlite::ParseError(
                "kerberoast_burst.max_services_per_requester must be >= "
                "min_service_count");
    }
    if (const Value* v = root.find("dns_failure")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError("config value 'dns_failure' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" && item.first != "min_queries" &&
                item.first != "min_distinct_names" && item.first != "min_failure_percent" &&
                item.first != "min_high_entropy_failures")
                throw jsonlite::ParseError("unknown dns_failure value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.dnsFailureEnable = Boolean(*enabled, "dns_failure.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.dnsFailureWindowSeconds = BoundedUInt(*window, "dns_failure.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.dnsFailureStateCapacity = BoundedUInt(*capacity, "dns_failure.state_capacity", 256, 8192);
        if (const Value* count = v->find("min_queries"))
            cfg.dnsFailureMinQueries = BoundedUInt(*count, "dns_failure.min_queries", 2, 256);
        if (const Value* names = v->find("min_distinct_names"))
            cfg.dnsFailureMinDistinctNames = BoundedUInt(*names, "dns_failure.min_distinct_names", 2, 256);
        if (const Value* percent = v->find("min_failure_percent"))
            cfg.dnsFailureMinFailurePercent = BoundedUInt(*percent, "dns_failure.min_failure_percent", 1, 100);
        if (const Value* count = v->find("min_high_entropy_failures"))
            cfg.dnsFailureMinHighEntropyFailures = BoundedUInt(*count, "dns_failure.min_high_entropy_failures", 1, 256);
    }
    if (const Value* v = root.find("dns_beacon")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'dns_beacon' must be an object");
        for (const auto& item : v->object)
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_query_count" &&
                item.first != "min_high_entropy_count")
                throw jsonlite::ParseError(
                    "unknown dns_beacon value '" + item.first + "'");
        if (const Value* enabled = v->find("enable"))
            cfg.dnsBeaconEnable = Boolean(*enabled, "dns_beacon.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.dnsBeaconWindowSeconds = BoundedUInt(
                *window, "dns_beacon.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.dnsBeaconStateCapacity = BoundedUInt(
                *capacity, "dns_beacon.state_capacity", 256, 65536);
        if (const Value* count = v->find("min_query_count"))
            cfg.dnsBeaconMinQueryCount = BoundedUInt(
                *count, "dns_beacon.min_query_count", 1, 100000);
        if (const Value* entropy = v->find("min_high_entropy_count"))
            cfg.dnsBeaconMinHighEntropyCount = BoundedUInt(
                *entropy, "dns_beacon.min_high_entropy_count", 0, 100000);
    }
    if (const Value* v = root.find("behavior_baseline")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'behavior_baseline' must be an object");
        for (const auto& item : v->object)
            if (item.first != "enable" && item.first != "training_seconds" &&
                item.first != "window_seconds" &&
                item.first != "dedup_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_score" && item.first != "pollution_score" &&
                item.first != "baseline_path" &&
                item.first != "max_age_days" &&
                item.first != "max_observations")
                throw jsonlite::ParseError(
                    "unknown behavior_baseline value '" + item.first + "'");
        if (const Value* enabled = v->find("enable"))
            cfg.behaviorBaselineEnable = Boolean(*enabled,
                "behavior_baseline.enable");
        if (const Value* training = v->find("training_seconds"))
            cfg.behaviorBaselineTrainingSeconds = BoundedUInt(
                *training, "behavior_baseline.training_seconds", 0, 31536000);
        if (const Value* window = v->find("window_seconds"))
            cfg.behaviorBaselineWindowSeconds = BoundedUInt(
                *window, "behavior_baseline.window_seconds", 1, 86400);
        if (const Value* dedup = v->find("dedup_seconds"))
            cfg.behaviorBaselineDedupSeconds = BoundedUInt(
                *dedup, "behavior_baseline.dedup_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.behaviorBaselineStateCapacity = BoundedUInt(
                *capacity, "behavior_baseline.state_capacity", 1, 65536);
        if (const Value* score = v->find("min_score"))
            cfg.behaviorBaselineMinScore = BoundedUInt(
                *score, "behavior_baseline.min_score", 10, 100);
        if (const Value* pollution = v->find("pollution_score"))
            cfg.behaviorBaselinePollutionScore = BoundedUInt(
                *pollution, "behavior_baseline.pollution_score", 1, 100);
        if (const Value* path = v->find("baseline_path"))
            cfg.behaviorBaselinePath = ExpandedPath(
                *path, "behavior_baseline.baseline_path");
        if (const Value* age = v->find("max_age_days"))
            cfg.behaviorBaselineMaxAgeDays = BoundedUInt(
                *age, "behavior_baseline.max_age_days", 1, 3650);
        if (const Value* observations = v->find("max_observations"))
            cfg.behaviorBaselineMaxObservations = BoundedUInt(
                *observations, "behavior_baseline.max_observations", 1, 4096);
    }
    if (const Value* v = root.find("lateral_move")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'lateral_move' must be an object");
        for (const auto& item : v->object)
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_dest_count" &&
                item.first != "score_per_dest")
                throw jsonlite::ParseError(
                    "unknown lateral_move value '" + item.first + "'");
        if (const Value* enabled = v->find("enable"))
            cfg.lateralMoveEnable = Boolean(*enabled, "lateral_move.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.lateralMoveWindowSeconds = BoundedUInt(
                *window, "lateral_move.window_seconds", 30, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.lateralMoveStateCapacity = BoundedUInt(
                *capacity, "lateral_move.state_capacity", 256, 65536);
        if (const Value* count = v->find("min_dest_count"))
            cfg.lateralMoveMinDestCount = BoundedUInt(
                *count, "lateral_move.min_dest_count", 2, 65536);
        if (const Value* score = v->find("score_per_dest"))
            cfg.lateralMoveScorePerDest = BoundedUInt(
                *score, "lateral_move.score_per_dest", 1, 100);
    }
    if (const Value* v = root.find("port_scan")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'port_scan' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_distinct_ports")
                throw jsonlite::ParseError(
                    "unknown port_scan value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.portScanEnable = Boolean(*enabled, "port_scan.enable");
        if (const Value* window = v->find("window_seconds"))
            cfg.portScanWindowSeconds = BoundedUInt(
                *window, "port_scan.window_seconds", 5, 3600);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.portScanStateCapacity = BoundedUInt(
                *capacity, "port_scan.state_capacity", 256, 65536);
        if (const Value* ports = v->find("min_distinct_ports"))
            cfg.portScanMinDistinctPorts = BoundedUInt(
                *ports, "port_scan.min_distinct_ports", 5, 1024);
    }
    if (const Value* v = root.find("enable_hooks_injection")) {
        cfg.enableHooksInjection = Boolean(*v, "enable_hooks_injection");
    }
    if (const Value* v = root.find("enable_hooks_rpc_create_process")) {
        cfg.enableHooksRpcCreateProcess =
            Boolean(*v, "enable_hooks_rpc_create_process");
    }
    if (const Value* v = root.find("enable_hooks_windows_hook")) {
        cfg.enableHooksWindowsHook =
            Boolean(*v, "enable_hooks_windows_hook");
    }
    if (const Value* v = root.find("enable_hooks_service")) {
        cfg.enableHooksService = Boolean(*v, "enable_hooks_service");
    }
    if (const Value* v = root.find("enable_hooks_com")) {
        cfg.enableHooksCom = Boolean(*v, "enable_hooks_com");
    }
    if (const Value* v = root.find("enable_hooks_handle")) {
        cfg.enableHooksHandle = Boolean(*v, "enable_hooks_handle");
    }
    if (const Value* v = root.find("enable_hooks_input")) {
        cfg.enableHooksInput = Boolean(*v, "enable_hooks_input");
    }
    if (const Value* v = root.find("enable_hooks_system")) {
        cfg.enableHooksSystem = Boolean(*v, "enable_hooks_system");
    }
    if (const Value* v = root.find("enable_hooks_surveillance")) {
        cfg.enableHooksSurveillance =
            Boolean(*v, "enable_hooks_surveillance");
    }
    if (const Value* v = root.find("enable_hooks_powershell")) {
        cfg.enableHooksPowerShell = Boolean(*v, "enable_hooks_powershell");
    }
    if (const Value* v = root.find("enable_proc_poll")) {
        cfg.enableProcPoll = Boolean(*v, "enable_proc_poll");
    }
    if (const Value* v = root.find("watch_dirs")) {
        if (v->type != jsonlite::Type::Array)
            throw jsonlite::ParseError("config value 'watch_dirs' must be an array");
        cfg.watchDirs.clear();
        for (const Value& item : v->array) {
            if (item.type != jsonlite::Type::String)
                throw jsonlite::ParseError(
                    "config value 'watch_dirs' entries must be strings");
            cfg.watchDirs.push_back(ExpandEnvStrings(item.str));
        }
    }
    if (const Value* v = root.find("net_poll_ms")) {
        cfg.netPollMs = BoundedUInt(*v, "net_poll_ms", 100, 3600000);
    }
    if (const Value* v = root.find("reg_baseline_ms")) {
        cfg.regBaselineMs = BoundedUInt(*v, "reg_baseline_ms", 1000, 86400000);
    }
    if (const Value* v = root.find("alerts_path")) {
        cfg.alertsPath = String(*v, "alerts_path");
    }
    if (const Value* v = root.find("redact")) {
        cfg.redact = Boolean(*v, "redact");
    }
    if (const Value* v = root.find("eventlog")) {
        cfg.eventLog = Boolean(*v, "eventlog");
    }
    if (const Value* v = root.find("rules_path")) {
        cfg.rulesPath = String(*v, "rules_path");
    }
    if (const Value* v = root.find("rule_reload")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'rule_reload' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "poll_seconds")
                throw jsonlite::ParseError(
                    "unknown rule_reload value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.ruleReloadEnable = Boolean(*enabled, "rule_reload.enable");
        if (const Value* poll = v->find("poll_seconds"))
            cfg.ruleReloadPollSeconds = BoundedUInt(
                *poll, "rule_reload.poll_seconds", 1, 86400);
    }
    if (const Value* v = root.find("threat_intel")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'threat_intel' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "feed_path" &&
                item.first != "min_score" && item.first != "dedup_window_seconds" &&
                item.first != "state_capacity" && item.first != "reload_poll_seconds")
                throw jsonlite::ParseError(
                    "unknown threat_intel value '" + item.first + "'");
        }
        if (const Value* value = v->find("enable"))
            cfg.threatIntelEnable = Boolean(*value, "threat_intel.enable");
        if (const Value* value = v->find("feed_path"))
            cfg.threatIntelFeedPath = String(*value, "threat_intel.feed_path");
        if (const Value* value = v->find("min_score"))
            cfg.threatIntelMinScore = BoundedUInt(*value,
                "threat_intel.min_score", 1, 100);
        if (const Value* value = v->find("dedup_window_seconds"))
            cfg.threatIntelDedupWindowSeconds = BoundedUInt(*value,
                "threat_intel.dedup_window_seconds", 0, 86400);
        if (const Value* value = v->find("state_capacity"))
            cfg.threatIntelStateCapacity = BoundedUInt(*value,
                "threat_intel.state_capacity", 16, 65536);
        if (const Value* value = v->find("reload_poll_seconds"))
            cfg.threatIntelReloadPollSeconds = BoundedUInt(*value,
                "threat_intel.reload_poll_seconds", 0, 86400);
    }
    if (const Value* v = root.find("lateral_chain")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'lateral_chain' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_score" &&
                item.first != "window_seconds" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown lateral_chain value '" + item.first + "'");
        }
        if (const Value* value = v->find("enable"))
            cfg.lateralChainEnable = Boolean(*value, "lateral_chain.enable");
        if (const Value* value = v->find("min_score"))
            cfg.lateralChainMinScore = BoundedUInt(*value,
                "lateral_chain.min_score", 1, 100);
        if (const Value* value = v->find("window_seconds"))
            cfg.lateralChainWindowSeconds = BoundedUInt(*value,
                "lateral_chain.window_seconds", 1, 86400);
        if (const Value* value = v->find("dedup_window_seconds"))
            cfg.lateralChainDedupWindowSeconds = BoundedUInt(*value,
                "lateral_chain.dedup_window_seconds", 0, 86400);
        if (const Value* value = v->find("state_capacity"))
            cfg.lateralChainStateCapacity = BoundedUInt(*value,
                "lateral_chain.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("correlation")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'correlation' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "window_seconds" &&
                item.first != "state_capacity" &&
                item.first != "min_alerts_to_close" &&
                item.first != "incident_path" &&
                item.first != "max_records" &&
                item.first != "rollup_enable" &&
                item.first != "rollup_min_stage_count" &&
                item.first != "rollup_min_score" &&
                item.first != "rollup_state_capacity")
                throw jsonlite::ParseError(
                    "unknown correlation value '" + item.first + "'");
        }
        if (const Value* value = v->find("enable"))
            cfg.correlationEnable = Boolean(*value, "correlation.enable");
        if (const Value* value = v->find("window_seconds"))
            cfg.correlationWindowSeconds = BoundedUInt(*value,
                "correlation.window_seconds", 1, 86400);
        if (const Value* value = v->find("state_capacity"))
            cfg.correlationStateCapacity = BoundedUInt(*value,
                "correlation.state_capacity", 16, 65536);
        if (const Value* value = v->find("min_alerts_to_close"))
            cfg.correlationMinAlertsToClose = BoundedUInt(*value,
                "correlation.min_alerts_to_close", 1, 1000);
        if (const Value* value = v->find("incident_path"))
            cfg.correlationIncidentPath =
                String(*value, "correlation.incident_path");
        if (const Value* value = v->find("max_records"))
            cfg.correlationMaxRecords = BoundedUInt(*value,
                "correlation.max_records", 1, 100000000);
        if (const Value* value = v->find("rollup_enable"))
            cfg.correlationRollupEnable =
                Boolean(*value, "correlation.rollup_enable");
        if (const Value* value = v->find("rollup_min_stage_count"))
            cfg.correlationRollupMinStageCount = BoundedUInt(*value,
                "correlation.rollup_min_stage_count", 2, 64);
        if (const Value* value = v->find("rollup_min_score"))
            cfg.correlationRollupMinScore = BoundedUInt(*value,
                "correlation.rollup_min_score", 0, 100);
        if (const Value* value = v->find("rollup_state_capacity"))
            cfg.correlationRollupStateCapacity = BoundedUInt(*value,
                "correlation.rollup_state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("eventlog_tamper")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'eventlog_tamper' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown eventlog_tamper value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.eventlogTamperEnable = Boolean(*enabled, "eventlog_tamper.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.eventlogTamperMinScore = BoundedUInt(
                *minScore, "eventlog_tamper.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.eventlogTamperDedupWindowSeconds = BoundedUInt(
                *dedup, "eventlog_tamper.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.eventlogTamperStateCapacity = BoundedUInt(
                *capacity, "eventlog_tamper.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("ssh_abuse")) {
        if (v->type != jsonlite::Type::Object)
            throw jsonlite::ParseError(
                "config value 'ssh_abuse' must be an object");
        for (const auto& item : v->object) {
            if (item.first != "enable" &&
                item.first != "min_score" &&
                item.first != "dedup_window_seconds" &&
                item.first != "state_capacity")
                throw jsonlite::ParseError(
                    "unknown ssh_abuse value '" + item.first + "'");
        }
        if (const Value* enabled = v->find("enable"))
            cfg.sshAbuseEnable = Boolean(*enabled, "ssh_abuse.enable");
        if (const Value* minScore = v->find("min_score"))
            cfg.sshAbuseMinScore = BoundedUInt(
                *minScore, "ssh_abuse.min_score", 10, 100);
        if (const Value* dedup = v->find("dedup_window_seconds"))
            cfg.sshAbuseDedupWindowSeconds = BoundedUInt(
                *dedup, "ssh_abuse.dedup_window_seconds", 0, 86400);
        if (const Value* capacity = v->find("state_capacity"))
            cfg.sshAbuseStateCapacity = BoundedUInt(
                *capacity, "ssh_abuse.state_capacity", 16, 65536);
    }
    if (const Value* v = root.find("reporter")) {
        if (v->type == jsonlite::Type::Object) {
            if (const Value* e = v->find("enable")) {
                cfg.reporterEnable = Boolean(*e, "reporter.enable");
            }
            if (const Value* u = v->find("url")) {
                cfg.reporterUrl = String(*u, "reporter.url");
            }
            if (cfg.reporterUrl.find('\0') != std::string::npos ||
                cfg.reporterUrl.find('#') != std::string::npos ||
                (cfg.reporterEnable && cfg.reporterUrl.empty())) {
                throw jsonlite::ParseError(
                    "enabled reporter requires a nonempty URL without NUL or fragment");
            }
            if (const Value* k = v->find("api_key")) {
                cfg.reporterApiKey = String(*k, "reporter.api_key");
            }
            if (const Value* spool = v->find("spool")) {
                if (spool->type != jsonlite::Type::Object)
                    throw jsonlite::ParseError("reporter.spool must be an object");
                for (const auto& item : spool->object) {
                    if (item.first != "enable" && item.first != "directory" &&
                        item.first != "event_directory" && item.first != "max_records" &&
                        item.first != "max_bytes" && item.first != "max_item_bytes")
                        throw jsonlite::ParseError("unknown reporter.spool value '" + item.first + "'");
                }
                if (const Value* item = spool->find("enable"))
                    cfg.reporterSpoolEnable = Boolean(*item, "reporter.spool.enable");
                if (const Value* item = spool->find("directory"))
                    cfg.reporterSpoolDirectory = ExpandedPath(*item, "reporter.spool.directory");
                if (const Value* item = spool->find("event_directory"))
                    cfg.reporterEventSpoolDirectory = ExpandedPath(*item, "reporter.spool.event_directory");
                if (const Value* item = spool->find("max_records"))
                    cfg.reporterSpoolMaxRecords = BoundedUInt(*item, "reporter.spool.max_records", 1, 1000);
                if (const Value* item = spool->find("max_bytes"))
                    cfg.reporterSpoolMaxBytes = BoundedUInt64(*item, "reporter.spool.max_bytes", 1, 64u * 1024u * 1024u);
                if (const Value* item = spool->find("max_item_bytes"))
                    cfg.reporterSpoolMaxItemBytes = BoundedUInt64(*item, "reporter.spool.max_item_bytes", 1, 4u * 1024u * 1024u);
                if (cfg.reporterSpoolMaxItemBytes > cfg.reporterSpoolMaxBytes)
                    throw jsonlite::ParseError("reporter spool item limit exceeds total bytes");
                if (cfg.reporterSpoolEnable) {
                    if (!cfg.reporterEnable || cfg.reporterUrl.empty())
                        throw jsonlite::ParseError("durable reporter requires reporter.enable and url");
                    const auto alertPath = SpoolDirectoryPath(cfg.reporterSpoolDirectory);
                    const auto eventPath = SpoolDirectoryPath(cfg.reporterEventSpoolDirectory);
                    if (CompareStringOrdinal(alertPath.c_str(), -1, eventPath.c_str(), -1, TRUE) == CSTR_EQUAL)
                        throw jsonlite::ParseError("alert and event spool directories must differ");
                    cfg.reporterSpoolDirectory = WideToUtf8(alertPath.c_str());
                    cfg.reporterEventSpoolDirectory = WideToUtf8(eventPath.c_str());
                }
            }
        } else {
            throw jsonlite::ParseError("config value 'reporter' must be an object");
        }
    }
    if (const Value* v = root.find("syslog")) {
        if (v->type != jsonlite::Type::Object) {
            throw jsonlite::ParseError("config value 'syslog' must be an object");
        }
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "host" &&
                item.first != "port" && item.first != "facility" &&
                item.first != "hostname")
                throw jsonlite::ParseError("unknown syslog value '" + item.first + "'");
        }
        if (const Value* e = v->find("enable")) {
            cfg.syslogEnable = Boolean(*e, "syslog.enable");
        }
        if (const Value* h = v->find("host")) {
            cfg.syslogHost = String(*h, "syslog.host");
        }
        if (const Value* p = v->find("port")) {
            cfg.syslogPort = static_cast<uint16_t>(
                BoundedUInt(*p, "syslog.port", 1, 65535));
        }
        if (const Value* f = v->find("facility")) {
            cfg.syslogFacility = static_cast<uint8_t>(
                BoundedUInt(*f, "syslog.facility", 0, 23));
        }
        if (const Value* h = v->find("hostname")) {
            cfg.syslogHostname = String(*h, "syslog.hostname");
        }
        if (cfg.syslogEnable && cfg.syslogHost.empty()) {
            throw jsonlite::ParseError("syslog.enable requires syslog.host");
        }
    }
    if (const Value* v = root.find("webhook")) {
        if (v->type != jsonlite::Type::Object) {
            throw jsonlite::ParseError("config value 'webhook' must be an object");
        }
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "url" &&
                item.first != "timeout_seconds" &&
                item.first != "queue_capacity")
                throw jsonlite::ParseError(
                    "unknown webhook value '" + item.first + "'");
        }
        if (const Value* e = v->find("enable")) {
            cfg.webhookEnable = Boolean(*e, "webhook.enable");
        }
        if (const Value* u = v->find("url")) {
            cfg.webhookUrl = String(*u, "webhook.url");
        }
        if (const Value* t = v->find("timeout_seconds")) {
            cfg.webhookTimeoutSeconds = BoundedUInt(*t, "webhook.timeout_seconds", 1, 60);
        }
        if (const Value* q = v->find("queue_capacity")) {
            cfg.webhookQueueCapacity = static_cast<size_t>(
                BoundedUInt(*q, "webhook.queue_capacity", 16, 65536));
        }
    }
    if (const Value* v = root.find("response_channel")) {
        if (v->type != jsonlite::Type::Object) {
            throw jsonlite::ParseError(
                "config value 'response_channel' must be an object");
        }
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "pipe_name" &&
                item.first != "enable_process_termination" &&
                item.first != "enable_quarantine" &&
                item.first != "enable_delete_file" &&
                item.first != "enable_process_suspend" &&
                item.first != "enable_process_resume" &&
                item.first != "quarantine_dir" &&
                item.first != "quarantine_max_file_bytes" &&
                item.first != "command_key_file" &&
                item.first != "audit_path" &&
                item.first != "max_tree_size") {
                throw jsonlite::ParseError(
                    "unknown response_channel value '" + item.first + "'");
            }
        }
        if (const Value* e = v->find("enable"))
            cfg.responseChannelEnable = Boolean(*e, "response_channel.enable");
        if (const Value* e = v->find("enable_process_termination"))
            cfg.responseEnableProcessTermination = Boolean(
                *e, "response_channel.enable_process_termination");
        if (const Value* e = v->find("enable_quarantine"))
            cfg.responseEnableQuarantine = Boolean(
                *e, "response_channel.enable_quarantine");
        if (const Value* e = v->find("enable_delete_file"))
            cfg.responseEnableDeleteFile = Boolean(
                *e, "response_channel.enable_delete_file");
        if (const Value* e = v->find("enable_process_suspend"))
            cfg.responseEnableProcessSuspend = Boolean(
                *e, "response_channel.enable_process_suspend");
        if (const Value* e = v->find("enable_process_resume"))
            cfg.responseEnableProcessResume = Boolean(
                *e, "response_channel.enable_process_resume");
        if (const Value* q = v->find("quarantine_dir"))
            cfg.responseQuarantineDir = ExpandEnvStrings(
                String(*q, "response_channel.quarantine_dir"));
        if (const Value* m = v->find("quarantine_max_file_bytes"))
            cfg.responseQuarantineMaxFileBytes = BoundedUInt64(*m,
                "response_channel.quarantine_max_file_bytes", 1024ULL * 1024ULL,
                4ULL * 1024ULL * 1024ULL * 1024ULL);
        if (const Value* p = v->find("pipe_name"))
            cfg.responsePipeName = String(*p, "response_channel.pipe_name");
        if (const Value* k = v->find("command_key_file"))
            cfg.responseCommandKeyFile = String(*k, "response_channel.command_key_file");
        if (const Value* a = v->find("audit_path"))
            cfg.responseAuditPath = String(*a, "response_channel.audit_path");
        if (const Value* t = v->find("max_tree_size"))
            cfg.responseMaxTreeSize = BoundedUInt(*t,
                "response_channel.max_tree_size", 4, 64);
    }
    if (const Value* v = root.find("auto_response")) {
        if (v->type != jsonlite::Type::Object) {
            throw jsonlite::ParseError(
                "config value 'auto_response' must be an object");
        }
        for (const auto& item : v->object) {
            if (item.first != "enable" && item.first != "min_severity" &&
                item.first != "max_per_minute" &&
                item.first != "tree_termination" &&
                item.first != "suspend_before_terminate" &&
                item.first != "max_tree_depth" &&
                item.first != "isolate_before_terminate" &&
                item.first != "capture_snapshot" &&
                item.first != "snapshot_dir" &&
                item.first != "parent_image_whitelist" &&
                item.first != "enable_kill" &&
                item.first != "enable_delete_file") {
                throw jsonlite::ParseError(
                    "unknown auto_response value '" + item.first + "'");
            }
        }
        if (const Value* e = v->find("enable"))
            cfg.autoResponseEnable = Boolean(*e, "auto_response.enable");
        if (const Value* t = v->find("tree_termination"))
            cfg.autoResponseTreeTermination =
                Boolean(*t, "auto_response.tree_termination");
        if (const Value* s = v->find("suspend_before_terminate"))
            cfg.autoResponseSuspendBeforeTerminate =
                Boolean(*s, "auto_response.suspend_before_terminate");
        if (const Value* d = v->find("max_tree_depth"))
            cfg.autoResponseMaxTreeDepth = BoundedUInt(*d,
                "auto_response.max_tree_depth", 0, 64);
        if (const Value* i = v->find("isolate_before_terminate"))
            cfg.autoResponseIsolateBeforeTerminate = Boolean(
                *i, "auto_response.isolate_before_terminate");
        if (const Value* c = v->find("capture_snapshot"))
            cfg.autoResponseCaptureSnapshot = Boolean(
                *c, "auto_response.capture_snapshot");
        if (const Value* sd = v->find("snapshot_dir"))
            cfg.autoResponseSnapshotDir = ExpandEnvStrings(
                String(*sd, "auto_response.snapshot_dir"));
        if (const Value* whitelist = v->find("parent_image_whitelist")) {
            if (whitelist->type != jsonlite::Type::Array)
                throw jsonlite::ParseError(
                    "auto_response.parent_image_whitelist must be an array");
            cfg.autoResponseParentWhitelist.clear();
            for (const auto& item : whitelist->array) {
                if (item.type != jsonlite::Type::String)
                    throw jsonlite::ParseError(
                        "auto_response.parent_image_whitelist items must be strings");
                cfg.autoResponseParentWhitelist.push_back(item.str);
            }
        }
        if (const Value* k = v->find("enable_kill")) {
            cfg.autoResponseEnableKill = Boolean(*k, "auto_response.enable_kill");
            std::fprintf(stderr,
                         "[edr-config] note: auto_response.enable_kill is accepted but not consumed; "
                         "auto-response kill is gated by response_channel.enable_process_termination\n");
        }
        if (const Value* d = v->find("enable_delete_file"))
            cfg.autoResponseEnableDeleteFile = Boolean(
                *d, "auto_response.enable_delete_file");
        if (const Value* s = v->find("min_severity")) {
            std::string severity = String(*s, "auto_response.min_severity");
            if (severity != "medium" && severity != "high" &&
                severity != "critical") {
                throw jsonlite::ParseError(
                    "auto_response.min_severity must be medium|high|critical");
            }
            cfg.autoResponseMinSeverity = severity;
        }
        if (const Value* m = v->find("max_per_minute"))
            cfg.autoResponseMaxPerMinute = BoundedUInt(*m,
                "auto_response.max_per_minute", 1, 64);
    }
}

bool LoadConfigFile(const std::string& path, Config& cfg, std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "config file not found: " + path;
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    try {
        jsonlite::Value root = jsonlite::parse(ss.str());
        if (root.type != jsonlite::Type::Object) {
            err = "config root must be an object";
            return false;
        }
        Config candidate = cfg;
        ApplyValue(root, candidate);
        cfg = std::move(candidate);
    } catch (const jsonlite::ParseError& e) {
        err = e.what();
        return false;
    }
    return true;
}

} // namespace edr
