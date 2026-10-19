/*
 * main.cpp - EDR user-mode agent entry point.
 *
 * Modes:
 *   (default)            console mode; runs collectors until Ctrl+C
 *   --console            same, explicit
 *   --service            run under the Windows Service Control Manager
 *   --selftest           inject synthetic events, verify rule hits, exit
 *   --rules <path>       rules file override
 *   --config <path>      config file override
 *   --redact=on|off      sensitive telemetry redaction (default on)
 */
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "alerter.h"
#include "webhook_notifier.h"
#include "amsi_enricher.h"
#include "amsi_platform.h"
#include "attack_chain_detector.h"
#include "auto_responder.h"
#include "c2_beacon_detector.h"
#include "dns_beacon_detector.h"
#include "dns_failure_detector.h"
#include "behavior_baseline_detector.h"
#include "lateral_movement_detector.h"
#include "port_scan_detector.h"
#include "persistence_chain_detector.h"
#include "lolbin_chain_detector.h"
#include "powershell_download_execute_detector.h"
#include "dll_hijack_detector.h"
#include "registry_persistence_detector.h"
#include "anti_forensics_detector.h"
#include "time_change_detector.h"
#include "privileged_group_detector.h"
#include "defense_evasion_detector.h"
#include "discovery_recon_detector.h"
#include "lolbin_parent_child_detector.h"
#include "ransom_precursor_detector.h"
#include "rdp_chain_detector.h"
#include "uac_bypass_detector.h"
#include "wmi_persistence_detector.h"
#include "ransom_burst_detector.h"
#include "collector_rdp.h"
#include "logon_brute_force_detector.h"
#include "logon_success_detector.h"
#include "password_spray_detector.h"
#include "kerberoast_detector.h"
#include "process_hollowing_detector.h"
#include "memory_scanner_detector.h"
#include "canary_manager.h"
#include "canary_detector.h"
#include "collector_hook_scan.h"
#include "hook_persistence_detector.h"
#include "task_abuse_detector.h"
#include "masquerade_detector.h"
#include "ppid_spoof_detector.h"
#include "net_discovery_detector.h"
#include "host_profile_detector.h"
#include "private_key_detector.h"
#include "av_tamper_detector.h"
#include "timestomp_detector.h"
#include "obfuscation_detector.h"
#include "lsass_dump_detector.h"
#include "accessibility_hijack_detector.h"
#include "acl_abuse_detector.h"
#include "reg_modify_detector.h"
#include "wmi_exec_detector.h"
#include "local_collect_detector.h"
#include "lateral_transfer_detector.h"
#include "amsi_bypass_detector.h"
#include "appinit_dll_detector.h"
#include "as_rep_roast_detector.h"
#include "boot_provider_persist_detector.h"
#include "cert_abuse_detector.h"
#include "cor_profiler_hijack_detector.h"
#include "cred_file_hunt_detector.h"
#include "dcsync_detector.h"
#include "dev_util_proxy_detector.h"
#include "disk_wipe_detector.h"
#include "shadow_copy_detector.h"
#include "persistence_burst_detector.h"
#include "threat_intel_detector.h"
#include "lateral_chain_detector.h"
#include "correlation_engine.h"
#include "correlation_rollup.h"
#include "incident_store.h"
#include "cmstp_bypass_detector.h"
#include "file_assoc_detector.h"
#include "hidden_window_detector.h"
#include "office_persist_detector.h"
#include "shortcut_persist_detector.h"
#include "indirect_exec_detector.h"
#include "screensaver_persist_detector.h"
#include "svc_path_abuse_detector.h"
#include "service_dll_hijack_detector.h"
#include "dll_search_order_detector.h"
#include "svc_recovery_detector.h"
#include "com_hijack_detector.h"
#include "winlogon_hijack_detector.h"
#include "mshta_abuse_detector.h"
#include "dotnet_proxy_exec_detector.h"
#include "wsl_abuse_detector.h"
#include "msdt_abuse_detector.h"
#include "software_discovery_detector.h"
#include "net_share_discovery_detector.h"
#include "nonstandard_port_egress_detector.h"
#include "iso_mount_detector.h"
#include "ps_profile_detector.h"
#include "downgrade_attack_detector.h"
#include "dpapi_abuse_detector.h"
#include "email_collection_detector.h"
#include "etw_script_tamper_detector.h"
#include "forced_auth_detector.h"
#include "golden_ticket_detector.h"
#include "gpo_abuse_detector.h"
#include "hidden_artifacts_detector.h"
#include "history_tamper_detector.h"
#include "registry_hive_detector.h"
#include "hosts_redirect_detector.h"
#include "iis_module_detector.h"
#include "input_simulation_detector.h"
#include "llmnr_poison_detector.h"
#include "logon_script_persist_detector.h"
#include "lsa_package_detector.h"
#include "mailbox_delegate_detector.h"
#include "mailbox_rule_detector.h"
#include "motw_bypass_detector.h"
#include "netsh_helper_detector.h"
#include "network_sniffing_detector.h"
#include "netprovider_persist_detector.h"
#include "ntds_dit_detector.h"
#include "pass_the_hash_detector.h"
#include "password_cracking_detector.h"
#include "password_vault_detector.h"
#include "arp_poison_detector.h"
#include "cloud_metadata_detector.h"
#include "gpp_password_detector.h"
#include "control_panel_proxy_detector.h"
#include "hidden_user_account_detector.h"
#include "password_policy_discovery_detector.h"
#include "msi_package_install_detector.h"
#include "log_enumeration_detector.h"
#include "path_interception_detector.h"
#include "pe_anomaly_detector.h"
#include "ransom_ops_detector.h"
#include "rdp_session_hijack_detector.h"
#include "reg_cred_hunt_detector.h"
#include "remote_exec_detector.h"
#include "secboot_tamper_detector.h"
#include "shim_db_detector.h"
#include "signed_binary_abuse_detector.h"
#include "sip_hijack_detector.h"
#include "ssh_key_persistence_detector.h"
#include "ticket_cache_abuse_detector.h"
#include "token_impersonation_detector.h"
#include "handle_guard_detector.h"
#include "clipboard_theft_detector.h"
#include "named_pipe_abuse_detector.h"
#include "web_exfil_detector.h"
#include "wifi_cred_theft_detector.h"
#include "winrm_abuse_detector.h"
#include "winrm_config_tamper_detector.h"
#include "xsl_script_detector.h"
#include "eventlog_tamper_detector.h"
#include "ssh_abuse_detector.h"
#include "health_heartbeat.h"
#include "dispatch_timing.h"
#include "dispatch_timing_scope.h"
#include "driver_load_detector.h"
#include "fileless_attack_detector.h"
#include "api_hook_detector.h"
#include "remote_access_detector.h"
#include "credential_dumping_detector.h"
#include "data_exfiltration_detector.h"
#include "privilege_escalation_detector.h"
#include "ntlm_relay_detector.h"
#include "browser_theft_detector.h"
#include "browser_extension_detector.h"
#include "archive_staging_detector.h"
#include "bits_abuse_detector.h"
#include "doh_abuse_detector.h"
#include "service_install_detector.h"
#include "firewall_rule_detector.h"
#include "share_change_detector.h"
#include "local_account_detector.h"
#include "cryptominer_detector.h"
#include "anti_analysis_detector.h"
#include "script_host_abuse_detector.h"
#include "account_op_detector.h"
#include "tunnel_tool_detector.h"
#include "surveillance_detector.h"
#include "webshell_detector.h"
#include "usb_exfil_detector.h"
#include "behavior_enricher.h"
#include "collector.h"
#include "event_log_bookmark.h"
#include "collector_critical_process.h"
#include "collector_etw_tamper.h"
#include "collector_rat_analyzer.h"
#include "collector_fim.h"
#include "collector_firewall.h"
#include "collector_listener.h"
#include "collector_local_account.h"
#include "collector_lsass_sam.h"
#include "collector_net_etw.h"
#include "collector_service.h"
#include "collector_share.h"
#include "collector_named_pipe.h"
#include "collector_usb.h"
#include "config.h"
#include "driver_policy_publisher.h"
#include "host_isolation.h"
#include "injection_chain_detector.h"
#include "json_lite.h"
#include "process_tree_builder.h"
#include "security_baseline.h"
#include "system_snapshot.h"
#include "triage_pack.h"
#include "edr_event.h"
#include "event_bus.h"
#include "reporter.h"
#include "telemetry_delivery.h"
#include "response_server.h"
#include "rule_engine.h"
#include "powershell_reassembler.h"
#include "silverfox_detector.h"
#include "syslog_forwarder.h"

namespace edr {

class EventDispatchSink : public ISink {
public:
    DispatchTiming* timing = nullptr;
    RuleEngine* rules = nullptr;
    Reporter* reporter = nullptr;
    bool redact = true;
    AmsiEnricher* amsi = nullptr;
    SilverFoxDetector* silverfox = nullptr;
    BehaviorEnricher* behavior = nullptr;
    InjectionChainDetector* injector = nullptr;
    AttackChainDetector* attacker = nullptr;
    C2BeaconDetector* c2beacon = nullptr;
    RansomBurstDetector* ransom = nullptr;
    LogonBruteForceDetector* logonBrute = nullptr;
    LogonSuccessDetector* logonSuccess = nullptr;
    PasswordSprayDetector* passwordSpray = nullptr;
    KerberoastDetector* kerberoast = nullptr;
    ProcessHollowingDetector* hollowing = nullptr;
    DnsBeaconDetector* dnsBeacon = nullptr;
    DnsFailureDetector* dnsFailure = nullptr;
    BehaviorBaselineDetector* behaviorBaseline = nullptr;
    LateralMovementDetector* lateralMove = nullptr;
    PortScanDetector* portScan = nullptr;
    PersistenceChainDetector* persistChain = nullptr;
    LolbinParentChildDetector* lolbin = nullptr;
    LolbinChainDetector* lolbinChain = nullptr;
    PowerShellDownloadExecuteDetector* powershellDownloadExecute = nullptr;
    DllHijackDetector* dllHijack = nullptr;
    RegistryPersistenceDetector* registryPersistence = nullptr;
    AntiForensicsDetector* antiForensics = nullptr;
    TimeChangeDetector* timeChange = nullptr;
    PrivilegedGroupDetector* privilegedGroup = nullptr;
    DefenseEvasionDetector* defenseEvasion = nullptr;
    DiscoveryReconDetector* discoveryRecon = nullptr;
    RdpChainDetector* rdpChain = nullptr;
    UacBypassDetector* uacBypass = nullptr;
    WmiPersistenceDetector* wmiPersistence = nullptr;
    RansomPrecursorDetector* ransomPrecursor = nullptr;
    MemoryScannerDetector* memoryScanner = nullptr;
    DriverLoadDetector* driverLoad = nullptr;
    FilelessAttackDetector* fileless = nullptr;
    ApiHookDetector* apiHook = nullptr;
    RemoteAccessDetector* remoteAccess = nullptr;
    CredentialDumpingDetector* credDump = nullptr;
    DataExfiltrationDetector* dataExfil = nullptr;
    PrivilegeEscalationDetector* privEsc = nullptr;
    NtlmRelayDetector* ntlmRelay = nullptr;
    BrowserTheftDetector* browserTheft = nullptr;
    BrowserExtensionDetector* browserExtension = nullptr;
    ArchiveStagingDetector* archiveStaging = nullptr;
    BitsAbuseDetector* bitsAbuse = nullptr;
    DohAbuseDetector* dohAbuse = nullptr;
    ServiceInstallDetector* svcInstall = nullptr;
    FirewallRuleDetector* firewallRule = nullptr;
    ShareChangeDetector* shareChange = nullptr;
    LocalAccountDetector* localAccount = nullptr;
    CryptominerDetector* cryptoMiner = nullptr;
    AntiAnalysisDetector* antiAnalysis = nullptr;
    ScriptHostAbuseDetector* scriptHostAbuse = nullptr;
    AccountOpDetector* accountOp = nullptr;
    TunnelToolDetector* tunnelTool = nullptr;
    SurveillanceDetector* surveillance = nullptr;
    ClipboardTheftDetector* clipboardTheft = nullptr;
    WebshellDetector* webshell = nullptr;
    UsbExfilDetector* usbExfil = nullptr;
    ProcessTreeBuilder* processTree = nullptr;
    CanaryDetector* canary = nullptr;
    HookPersistenceDetector* hookPersist = nullptr;
    TaskAbuseDetector* taskAbuse = nullptr;
    MasqueradeDetector* masquerade = nullptr;
    PpidSpoofDetector* ppidSpoof = nullptr;
    NetDiscoveryDetector* netDiscovery = nullptr;
    HostProfileDetector* hostProfile = nullptr;
    PrivateKeyDetector* privateKey = nullptr;
    AccessibilityHijackDetector* accessibilityHijack = nullptr;
    AclAbuseDetector* aclAbuse = nullptr;
    AmsiBypassDetector* amsiBypass = nullptr;
    AppinitDllDetector* appInitDll = nullptr;
    AsRepRoastDetector* asRepRoast = nullptr;
    BootProviderPersistDetector* bootProvider = nullptr;
    CertAbuseDetector* certAbuse = nullptr;
    CorProfilerHijackDetector* corProfiler = nullptr;
    CredentialFileHuntDetector* credFileHunt = nullptr;
    DcsyncDetector* dcsync = nullptr;
    DevUtilProxyDetector* devUtilProxy = nullptr;
    DiskWipeDetector* diskWipe = nullptr;
    AvTamperDetector* avTamper = nullptr;
    TimestompDetector* timestomp = nullptr;
    ObfuscationDetector* obfuscation = nullptr;
    RegModifyDetector* regModify = nullptr;
    WmiExecDetector* wmiExec = nullptr;
    LocalCollectDetector* localCollect = nullptr;
    LateralTransferDetector* lateralTransfer = nullptr;
    ThreatIntelDetector* threatIntel = nullptr;
    LateralChainDetector* lateralChain = nullptr;
    CorrelationEngine* correlation = nullptr;
    LsassDumpDetector* lsassDump = nullptr;
    ShadowCopyDetector* shadowCopy = nullptr;
    PersistenceBurstDetector* persistBurst = nullptr;
    CmstpBypassDetector* cmstpBypass = nullptr;
    FileAssocDetector* fileAssoc = nullptr;
    HiddenWindowDetector* hiddenWindow = nullptr;
    OfficePersistDetector* officePersist = nullptr;
    ShortcutPersistDetector* shortcutPersist = nullptr;
    IndirectExecDetector* indirectExec = nullptr;
    ScreensaverPersistDetector* screensaverPersist = nullptr;
    SvcPathAbuseDetector* svcPathAbuse = nullptr;
    ServiceDllHijackDetector* serviceDllHijack = nullptr;
    DllSearchOrderDetector* dllSearchOrder = nullptr;
    SvcRecoveryDetector* svcRecovery = nullptr;
    ComHijackDetector* comHijack = nullptr;
    WinlogonHijackDetector* winlogonHijack = nullptr;
    MshtaAbuseDetector* mshtaAbuse = nullptr;
    DotnetProxyExecDetector* dotnetProxyExec = nullptr;
    WslAbuseDetector* wslAbuse = nullptr;
    MsdtAbuseDetector* msdtAbuse = nullptr;
    SoftwareDiscoveryDetector* softwareDiscovery = nullptr;
    NetShareDiscoveryDetector* netShareDiscovery = nullptr;
    NonstandardPortEgressDetector* nonstandardPortEgress = nullptr;
    IsoMountDetector* isoMount = nullptr;
    PsProfileDetector* psProfile = nullptr;
    DowngradeAttackDetector* downgradeAttack = nullptr;
    DpapiAbuseDetector* dpapiAbuse = nullptr;
    EmailCollectionDetector* emailCollection = nullptr;
    EtwScriptTamperDetector* etwScriptTamper = nullptr;
    ForcedAuthDetector* forcedAuth = nullptr;
    GoldenTicketDetector* goldenTicket = nullptr;
    GpoAbuseDetector* gpoAbuse = nullptr;
    HiddenArtifactsDetector* hiddenArtifacts = nullptr;
    HistoryTamperDetector* historyTamper = nullptr;
    HiveCopyDetector* hiveCopy = nullptr;
    HostsRedirectDetector* hostsRedirect = nullptr;
    IisModuleDetector* iisModule = nullptr;
    InputSimulationDetector* inputSimulation = nullptr;
    LogonScriptPersistDetector* logonScriptPersist = nullptr;
    LsaPackageDetector* lsaPackage = nullptr;
    MotwBypassDetector* motwBypass = nullptr;
    NetshHelperDetector* netshHelper = nullptr;
    NetworkSniffingDetector* networkSniffing = nullptr;
    NtdsDitDetector* ntdsDit = nullptr;
    PassTheHashDetector* passTheHash = nullptr;
    PasswordCrackingDetector* passwordCracking = nullptr;
    MailboxRuleDetector* mailboxRule = nullptr;
    MailboxDelegateDetector* mailboxDelegate = nullptr;
    LlmnrPoisonDetector* llmnrPoison = nullptr;
    NetProviderPersistDetector* netProviderPersist = nullptr;
    PasswordVaultDetector* passwordVault = nullptr;
    ArpPoisonDetector* arpPoison = nullptr;
    CloudMetadataDetector* cloudMetadata = nullptr;
    GppPasswordDetector* gppPassword = nullptr;
    ControlPanelProxyDetector* controlPanelProxy = nullptr;
    HiddenUserAccountDetector* hiddenUserAccount = nullptr;
    PasswordPolicyDiscoveryDetector* passwordPolicyDiscovery = nullptr;
    MsiPackageInstallDetector* msiPackageInstall = nullptr;
    LogEnumerationDetector* logEnumeration = nullptr;
    PathInterceptionDetector* pathInterception = nullptr;
    PeAnomalyDetector* peAnomaly = nullptr;
    RansomOpsDetector* ransomOps = nullptr;
    RdpSessionHijackDetector* rdpSessionHijack = nullptr;
    RegCredHuntDetector* regCredHunt = nullptr;
    RemoteExecDetector* remoteExec = nullptr;
    SecbootTamperDetector* secbootTamper = nullptr;
    ShimDbDetector* shimDb = nullptr;
    SignedBinaryAbuseDetector* signedBinaryAbuse = nullptr;
    SipHijackDetector* sipHijack = nullptr;
    SshKeyPersistenceDetector* sshKeyPersistence = nullptr;
    TicketCacheAbuseDetector* ticketCacheAbuse = nullptr;
    TokenImpersonationDetector* tokenImpersonation = nullptr;
    HandleGuardDetector* handleGuard = nullptr;
    NamedPipeAbuseDetector* namedPipeAbuse = nullptr;
    WebExfilDetector* webExfil = nullptr;
    WifiCredTheftDetector* wifiCredTheft = nullptr;
    WinrmAbuseDetector* winrmAbuse = nullptr;
    WinrmConfigTamperDetector* winrmConfigTamper = nullptr;
    XslScriptDetector* xslScript = nullptr;
    EventlogTamperDetector* eventlogTamper = nullptr;
    SshAbuseDetector* sshAbuse = nullptr;

    void OnEvent(const Event& event) override {
        DispatchTimingScope duration(timing, event.type);
        if (DeliverReportOnlyEvent(event, reporter, redact, rules)) return;
        // Add process tree enrichment
        if (processTree) processTree->Observe(event);

        const bool scanWithAmsi = amsi && amsi->IsEligible(event);
        const bool enrichWithBehavior =
            behavior && behavior->Inspects(event.type);
        const bool enrichWithInjector =
            injector && injector->Inspects(event.type);
        const bool enrichWithAttacker =
            attacker && attacker->Inspects(event.type);
        const bool enrichWithC2Beacon =
            c2beacon && c2beacon->Inspects(event.type);
        const bool enrichWithRansom =
            ransom && ransom->Inspects(event.type);
        const bool enrichWithLogonBrute =
            logonBrute && logonBrute->Inspects(event.type);
        const bool enrichWithLogonSuccess =
            logonSuccess && logonSuccess->Inspects(event.type);
        const bool enrichWithPasswordSpray =
            passwordSpray && passwordSpray->Inspects(event.type);
        const bool enrichWithKerberoast =
            kerberoast && kerberoast->Inspects(event.type);
        const bool enrichWithHollowing =
            hollowing && hollowing->Inspects(event.type);
        const bool enrichWithDnsBeacon =
            dnsBeacon && dnsBeacon->Inspects(event.type);
        const bool enrichWithDnsFailure =
            dnsFailure && dnsFailure->Inspects(event.type);
        const bool enrichWithBehaviorBaseline =
            behaviorBaseline && behaviorBaseline->Inspects(event.type);
        const bool enrichWithLateralMove =
            lateralMove && lateralMove->Inspects(event.type);
        const bool enrichWithPortScan =
            portScan && portScan->Inspects(event.type);
        const bool enrichWithPersistChain =
            persistChain && persistChain->Inspects(event.type);
        const bool enrichWithLolbin =
            lolbin && lolbin->Inspects(event.type);
        const bool enrichWithLolbinChain =
            lolbinChain && lolbinChain->Inspects(event.type);
        const bool enrichWithPowerShellDownloadExecute =
            powershellDownloadExecute &&
            powershellDownloadExecute->Inspects(event.type);
        const bool enrichWithDllHijack =
            dllHijack && dllHijack->Inspects(event.type);
        const bool enrichWithRegistryPersistence =
            registryPersistence && registryPersistence->Inspects(event.type);
        const bool enrichWithAntiForensics =
            antiForensics && antiForensics->Inspects(event.type);
        const bool enrichWithTimeChange =
            timeChange && timeChange->Inspects(event.type);
        const bool enrichWithPrivilegedGroup =
            privilegedGroup && privilegedGroup->Inspects(event.type);
        const bool enrichWithDefenseEvasion =
            defenseEvasion && defenseEvasion->Inspects(event.type);
        const bool enrichWithDiscoveryRecon =
            discoveryRecon && discoveryRecon->Inspects(event.type);
        const bool enrichWithRdpChain =
            rdpChain && rdpChain->Inspects(event.type);
        const bool enrichWithUacBypass =
            uacBypass && uacBypass->Inspects(event.type);
        const bool enrichWithWmiPersistence =
            wmiPersistence && wmiPersistence->Inspects(event.type);
        const bool enrichWithRansomPrecursor =
            ransomPrecursor && ransomPrecursor->Inspects(event.type);
        const bool enrichWithMemoryScanner =
            memoryScanner && memoryScanner->Inspects(event.type);
        const bool enrichWithCanary =
            canary && canary->Inspects(event.type);
        const bool enrichWithHookPersist =
            hookPersist && hookPersist->Inspects(event.type);
        const bool enrichWithTaskAbuse =
            taskAbuse && taskAbuse->Inspects(event.type);
        const bool enrichWithMasquerade =
            masquerade && masquerade->Inspects(event.type);
        const bool enrichWithPpidSpoof =
            ppidSpoof && ppidSpoof->Inspects(event.type);
        const bool enrichWithNetDiscovery =
            netDiscovery && netDiscovery->Inspects(event.type);
        const bool enrichWithHostProfile =
            hostProfile && hostProfile->Inspects(event.type);
        const bool enrichWithPrivateKey =
            privateKey && privateKey->Inspects(event.type);
        const bool enrichWithAccessibilityHijack =
            accessibilityHijack && accessibilityHijack->Inspects(event.type);
        const bool enrichWithAclAbuse =
            aclAbuse && aclAbuse->Inspects(event.type);
        const bool enrichWithAmsiBypass =
            amsiBypass && amsiBypass->Inspects(event.type);
        const bool enrichWithAppInitDll =
            appInitDll && appInitDll->Inspects(event.type);
        const bool enrichWithAsRepRoast =
            asRepRoast && asRepRoast->Inspects(event.type);
        const bool enrichWithBootProvider =
            bootProvider && bootProvider->Inspects(event.type);
        const bool enrichWithCertAbuse =
            certAbuse && certAbuse->Inspects(event.type);
        const bool enrichWithCorProfiler =
            corProfiler && corProfiler->Inspects(event.type);
        const bool enrichWithCredFileHunt =
            credFileHunt && credFileHunt->Inspects(event.type);
        const bool enrichWithDcsync =
            dcsync && dcsync->Inspects(event.type);
        const bool enrichWithDevUtilProxy =
            devUtilProxy && devUtilProxy->Inspects(event.type);
        const bool enrichWithDiskWipe =
            diskWipe && diskWipe->Inspects(event.type);
        const bool enrichWithAvTamper =
            avTamper && avTamper->Inspects(event.type);
        const bool enrichWithTimestomp =
            timestomp && timestomp->Inspects(event.type);
        const bool enrichWithObfuscation =
            obfuscation && obfuscation->Inspects(event.type);
        const bool enrichWithRegModify =
            regModify && regModify->Inspects(event.type);
        const bool enrichWithWmiExec =
            wmiExec && wmiExec->Inspects(event.type);
        const bool enrichWithLocalCollect =
            localCollect && localCollect->Inspects(event.type);
        const bool enrichWithLateralTransfer =
            lateralTransfer && lateralTransfer->Inspects(event.type);
        const bool enrichWithThreatIntel =
            threatIntel && threatIntel->Inspects(event.type);
        const bool enrichWithLateralChain =
            lateralChain && lateralChain->Inspects(event.type);
        const bool enrichWithLsassDump =
            lsassDump && lsassDump->Inspects(event.type);
        const bool enrichWithShadowCopy =
            shadowCopy && shadowCopy->Inspects(event.type);
        const bool enrichWithPersistBurst =
            persistBurst && persistBurst->Inspects(event.type);
        const bool enrichWithMailboxRule =
            mailboxRule && mailboxRule->Inspects(event.type);
        const bool enrichWithMailboxDelegate =
            mailboxDelegate && mailboxDelegate->Inspects(event.type);
        const bool enrichWithLlmnrPoison =
            llmnrPoison && llmnrPoison->Inspects(event.type);
        const bool enrichWithNetProviderPersist =
            netProviderPersist && netProviderPersist->Inspects(event.type);
        const bool enrichWithPasswordVault =
            passwordVault && passwordVault->Inspects(event.type);
        const bool enrichWithArpPoison =
            arpPoison && arpPoison->Inspects(event.type);
        const bool enrichWithCloudMetadata =
            cloudMetadata && cloudMetadata->Inspects(event.type);
        const bool enrichWithGppPassword =
            gppPassword && gppPassword->Inspects(event.type);
        const bool enrichWithControlPanelProxy =
            controlPanelProxy && controlPanelProxy->Inspects(event.type);
        const bool enrichWithHiddenUserAccount =
            hiddenUserAccount && hiddenUserAccount->Inspects(event.type);
        const bool enrichWithPasswordPolicyDiscovery =
            passwordPolicyDiscovery &&
            passwordPolicyDiscovery->Inspects(event.type);
        const bool enrichWithMsiPackageInstall =
            msiPackageInstall && msiPackageInstall->Inspects(event.type);
        const bool enrichWithLogEnumeration =
            logEnumeration && logEnumeration->Inspects(event.type);
        const bool enrichWithCmstpBypass =
            cmstpBypass && cmstpBypass->Inspects(event.type);
        const bool enrichWithFileAssoc =
            fileAssoc && fileAssoc->Inspects(event.type);
        const bool enrichWithHiddenWindow =
            hiddenWindow && hiddenWindow->Inspects(event.type);
        const bool enrichWithOfficePersist =
            officePersist && officePersist->Inspects(event.type);
        const bool enrichWithShortcutPersist =
            shortcutPersist && shortcutPersist->Inspects(event.type);
        const bool enrichWithIndirectExec =
            indirectExec && indirectExec->Inspects(event.type);
        const bool enrichWithScreensaverPersist =
            screensaverPersist && screensaverPersist->Inspects(event.type);
        const bool enrichWithSvcPathAbuse =
            svcPathAbuse && svcPathAbuse->Inspects(event.type);
        const bool enrichWithServiceDllHijack =
            serviceDllHijack && serviceDllHijack->Inspects(event.type);
        const bool enrichWithDllSearchOrder =
            dllSearchOrder && dllSearchOrder->Inspects(event.type);
        const bool enrichWithSvcRecovery =
            svcRecovery && svcRecovery->Inspects(event.type);
        const bool enrichWithComHijack =
            comHijack && comHijack->Inspects(event.type);
        const bool enrichWithWinlogonHijack =
            winlogonHijack && winlogonHijack->Inspects(event.type);
        const bool enrichWithMshtaAbuse =
            mshtaAbuse && mshtaAbuse->Inspects(event.type);
        const bool enrichWithDotnetProxyExec =
            dotnetProxyExec && dotnetProxyExec->Inspects(event.type);
        const bool enrichWithWslAbuse =
            wslAbuse && wslAbuse->Inspects(event.type);
        const bool enrichWithMsdtAbuse =
            msdtAbuse && msdtAbuse->Inspects(event.type);
        const bool enrichWithSoftwareDiscovery =
            softwareDiscovery && softwareDiscovery->Inspects(event.type);
        const bool enrichWithNetShareDiscovery =
            netShareDiscovery && netShareDiscovery->Inspects(event.type);
        const bool enrichWithNonstandardPortEgress =
            nonstandardPortEgress && nonstandardPortEgress->Inspects(event.type);
        const bool enrichWithIsoMount =
            isoMount && isoMount->Inspects(event.type);
        const bool enrichWithPsProfile =
            psProfile && psProfile->Inspects(event.type);
        const bool enrichWithDowngradeAttack =
            downgradeAttack && downgradeAttack->Inspects(event.type);
        const bool enrichWithDpapiAbuse =
            dpapiAbuse && dpapiAbuse->Inspects(event.type);
        const bool enrichWithEmailCollection =
            emailCollection && emailCollection->Inspects(event.type);
        const bool enrichWithEtwScriptTamper =
            etwScriptTamper && etwScriptTamper->Inspects(event.type);
        const bool enrichWithForcedAuth =
            forcedAuth && forcedAuth->Inspects(event.type);
        const bool enrichWithGoldenTicket =
            goldenTicket && goldenTicket->Inspects(event.type);
        const bool enrichWithGpoAbuse =
            gpoAbuse && gpoAbuse->Inspects(event.type);
        const bool enrichWithHiddenArtifacts =
            hiddenArtifacts && hiddenArtifacts->Inspects(event.type);
        const bool enrichWithHistoryTamper =
            historyTamper && historyTamper->Inspects(event.type);
        const bool enrichWithHiveCopy =
            hiveCopy && hiveCopy->Inspects(event.type);
        const bool enrichWithHostsRedirect =
            hostsRedirect && hostsRedirect->Inspects(event.type);
        const bool enrichWithIisModule =
            iisModule && iisModule->Inspects(event.type);
        const bool enrichWithInputSimulation =
            inputSimulation && inputSimulation->Inspects(event.type);
        const bool enrichWithLogonScriptPersist =
            logonScriptPersist && logonScriptPersist->Inspects(event.type);
        const bool enrichWithLsaPackage =
            lsaPackage && lsaPackage->Inspects(event.type);
        const bool enrichWithMotwBypass =
            motwBypass && motwBypass->Inspects(event.type);
        const bool enrichWithNetshHelper =
            netshHelper && netshHelper->Inspects(event.type);
        const bool enrichWithNetworkSniffing =
            networkSniffing && networkSniffing->Inspects(event.type);
        const bool enrichWithNtdsDit =
            ntdsDit && ntdsDit->Inspects(event.type);
        const bool enrichWithPassTheHash =
            passTheHash && passTheHash->Inspects(event.type);
        const bool enrichWithPasswordCracking =
            passwordCracking && passwordCracking->Inspects(event.type);
        const bool enrichWithPathInterception =
            pathInterception && pathInterception->Inspects(event.type);
        const bool enrichWithPeAnomaly =
            peAnomaly && peAnomaly->Inspects(event.type);
        const bool enrichWithRansomOps =
            ransomOps && ransomOps->Inspects(event.type);
        const bool enrichWithRdpSessionHijack =
            rdpSessionHijack && rdpSessionHijack->Inspects(event.type);
        const bool enrichWithRegCredHunt =
            regCredHunt && regCredHunt->Inspects(event.type);
        const bool enrichWithRemoteExec =
            remoteExec && remoteExec->Inspects(event.type);
        const bool enrichWithSecbootTamper =
            secbootTamper && secbootTamper->Inspects(event.type);
        const bool enrichWithShimDb =
            shimDb && shimDb->Inspects(event.type);
        const bool enrichWithSignedBinaryAbuse =
            signedBinaryAbuse && signedBinaryAbuse->Inspects(event.type);
        const bool enrichWithSipHijack =
            sipHijack && sipHijack->Inspects(event.type);
        const bool enrichWithSshKeyPersistence =
            sshKeyPersistence && sshKeyPersistence->Inspects(event.type);
        const bool enrichWithTicketCacheAbuse =
            ticketCacheAbuse && ticketCacheAbuse->Inspects(event.type);
        const bool enrichWithTokenImpersonation =
            tokenImpersonation && tokenImpersonation->Inspects(event.type);
        const bool enrichWithHandleGuard =
            handleGuard && handleGuard->Inspects(event.type);
        const bool enrichWithNamedPipeAbuse =
            namedPipeAbuse && namedPipeAbuse->Inspects(event.type);
        const bool enrichWithWebExfil =
            webExfil && webExfil->Inspects(event.type);
        const bool enrichWithWifiCredTheft =
            wifiCredTheft && wifiCredTheft->Inspects(event.type);
        const bool enrichWithWinrmAbuse =
            winrmAbuse && winrmAbuse->Inspects(event.type);
        const bool enrichWithWinrmConfigTamper =
            winrmConfigTamper && winrmConfigTamper->Inspects(event.type);
        const bool enrichWithXslScript =
            xslScript && xslScript->Inspects(event.type);
        const bool enrichWithEventlogTamper =
            eventlogTamper && eventlogTamper->Inspects(event.type);
        const bool enrichWithSshAbuse =
            sshAbuse && sshAbuse->Inspects(event.type);
        const bool enrichWithDriverLoad =
            driverLoad && driverLoad->Inspects(event.type);
        const bool enrichWithFileless =
            fileless && fileless->Inspects(event.type);
        const bool enrichWithApiHook =
            apiHook && apiHook->Inspects(event.type);
        const bool enrichWithRemoteAccess =
           remoteAccess && remoteAccess->Inspects(event.type);
        const bool enrichWithCredDump =
            credDump && credDump->Inspects(event.type);
        const bool enrichWithDataExfil =
            dataExfil && dataExfil->Inspects(event.type);
        const bool enrichWithPrivEsc =
            privEsc && privEsc->Inspects(event.type);
        const bool enrichWithNtlmRelay =
            ntlmRelay && ntlmRelay->Inspects(event.type);
        const bool enrichWithBrowserTheft =
            browserTheft && browserTheft->Inspects(event.type);
        const bool enrichWithBrowserExtension =
            browserExtension && browserExtension->Inspects(event.type);
        const bool enrichWithArchiveStaging =
            archiveStaging && archiveStaging->Inspects(event.type);
        const bool enrichWithBitsAbuse =
            bitsAbuse && bitsAbuse->Inspects(event.type);
        const bool enrichWithDohAbuse =
            dohAbuse && dohAbuse->Inspects(event.type);
        const bool enrichWithSvcInstall =
            svcInstall && svcInstall->Inspects(event.type);
        const bool enrichWithFirewallRule =
            firewallRule && firewallRule->Inspects(event.type);
        const bool enrichWithShareChange =
            shareChange && shareChange->Inspects(event.type);
        const bool enrichWithLocalAccount =
            localAccount && localAccount->Inspects(event.type);
        const bool enrichWithCryptoMiner =
            cryptoMiner && cryptoMiner->Inspects(event.type);
        const bool enrichWithAntiAnalysis =
            antiAnalysis && antiAnalysis->Inspects(event.type);
        const bool enrichWithScriptHostAbuse =
            scriptHostAbuse && scriptHostAbuse->Inspects(event.type);
        const bool enrichWithAccountOp =
            accountOp && accountOp->Inspects(event.type);
        const bool enrichWithTunnelTool =
            tunnelTool && tunnelTool->Inspects(event.type);
        const bool enrichWithSurveillance =
            surveillance && surveillance->Inspects(event.type);
        const bool enrichWithClipboardTheft =
            clipboardTheft && clipboardTheft->Inspects(event.type);
        const bool enrichWithWebshell =
            webshell && webshell->Inspects(event.type);
        const bool enrichWithUsbExfil =
            usbExfil && usbExfil->Inspects(event.type);
       if (scanWithAmsi || silverfox || enrichWithBehavior ||
            enrichWithInjector || enrichWithAttacker || enrichWithC2Beacon ||
            enrichWithRansom || enrichWithLogonBrute || enrichWithLogonSuccess ||
            enrichWithPasswordSpray || enrichWithKerberoast ||
            enrichWithHollowing || enrichWithDnsBeacon || enrichWithDnsFailure || enrichWithBehaviorBaseline || enrichWithLateralMove ||
            enrichWithPortScan ||
            enrichWithPersistChain || enrichWithLolbin || enrichWithLolbinChain ||
            enrichWithPowerShellDownloadExecute || enrichWithDllHijack ||
            enrichWithRegistryPersistence || enrichWithAntiForensics ||
            enrichWithTimeChange || enrichWithPrivilegedGroup ||
            enrichWithDefenseEvasion || enrichWithDiscoveryRecon ||
            enrichWithRdpChain ||
            enrichWithUacBypass || enrichWithWmiPersistence ||
            enrichWithRansomPrecursor || enrichWithMemoryScanner ||
           enrichWithDriverLoad || enrichWithFileless || enrichWithApiHook ||
           enrichWithRemoteAccess || enrichWithCredDump ||
           enrichWithDataExfil || enrichWithPrivEsc ||
           enrichWithNtlmRelay || enrichWithBrowserTheft ||
           enrichWithBrowserExtension ||
           enrichWithArchiveStaging || enrichWithCryptoMiner ||
           enrichWithBitsAbuse || enrichWithDohAbuse ||
           enrichWithSvcInstall ||
           enrichWithAntiAnalysis || enrichWithScriptHostAbuse ||
           enrichWithAccountOp || enrichWithTunnelTool ||
           enrichWithSurveillance || enrichWithWebshell ||
           enrichWithClipboardTheft ||
            enrichWithUsbExfil || enrichWithFirewallRule ||
            enrichWithShareChange || enrichWithLocalAccount ||
              enrichWithCanary || enrichWithHookPersist ||
              enrichWithTaskAbuse || enrichWithMasquerade ||
               enrichWithPpidSpoof || enrichWithNetDiscovery ||
               enrichWithPrivateKey || enrichWithAccessibilityHijack ||
                     enrichWithAclAbuse || enrichWithAmsiBypass || enrichWithAppInitDll || enrichWithAsRepRoast || enrichWithBootProvider || enrichWithCertAbuse || enrichWithCorProfiler || enrichWithCredFileHunt || enrichWithDcsync || enrichWithDevUtilProxy || enrichWithDiskWipe || enrichWithAvTamper || enrichWithTimestomp || enrichWithObfuscation ||
            enrichWithLsassDump || enrichWithShadowCopy ||
            enrichWithPersistBurst ||
            enrichWithMailboxDelegate || enrichWithMailboxRule ||
            enrichWithLlmnrPoison ||
            enrichWithNetProviderPersist || enrichWithPasswordVault ||
            enrichWithArpPoison ||
            enrichWithCloudMetadata ||
            enrichWithGppPassword ||
            enrichWithControlPanelProxy ||
            enrichWithHiddenUserAccount ||
            enrichWithPasswordPolicyDiscovery ||
            enrichWithMsiPackageInstall ||
            enrichWithLogEnumeration ||
            enrichWithCmstpBypass || enrichWithFileAssoc ||
            enrichWithHiddenWindow ||
            enrichWithOfficePersist || enrichWithShortcutPersist ||
            enrichWithIndirectExec || enrichWithScreensaverPersist ||
            enrichWithDllSearchOrder || enrichWithSvcRecovery ||
            enrichWithComHijack || enrichWithWinlogonHijack ||
            enrichWithMshtaAbuse || enrichWithPsProfile ||
            enrichWithDotnetProxyExec ||
            enrichWithWslAbuse || enrichWithMsdtAbuse ||
            enrichWithSoftwareDiscovery || enrichWithNetShareDiscovery ||
            enrichWithNonstandardPortEgress ||
            enrichWithIsoMount ||
            enrichWithDowngradeAttack || enrichWithDpapiAbuse ||
            enrichWithEmailCollection || enrichWithEtwScriptTamper ||
            enrichWithForcedAuth || enrichWithGoldenTicket ||
            enrichWithGpoAbuse || enrichWithHiddenArtifacts ||
            enrichWithHistoryTamper || enrichWithHiveCopy ||
            enrichWithHostsRedirect || enrichWithIisModule ||
            enrichWithInputSimulation || enrichWithLogonScriptPersist ||
            enrichWithLsaPackage || enrichWithMotwBypass ||
            enrichWithNetshHelper || enrichWithNetworkSniffing ||
            enrichWithNtdsDit || enrichWithPassTheHash ||
            enrichWithPasswordCracking || enrichWithPathInterception ||
            enrichWithPeAnomaly || enrichWithRansomOps ||
            enrichWithRdpSessionHijack || enrichWithRegCredHunt ||
            enrichWithRemoteExec || enrichWithSecbootTamper ||
            enrichWithShimDb || enrichWithSignedBinaryAbuse ||
            enrichWithSipHijack || enrichWithSshKeyPersistence ||
            enrichWithTicketCacheAbuse || enrichWithTokenImpersonation ||
            enrichWithHandleGuard ||
            enrichWithNamedPipeAbuse ||
            enrichWithWebExfil || enrichWithWifiCredTheft ||
            enrichWithWinrmAbuse || enrichWithWinrmConfigTamper ||
            enrichWithXslScript ||
            enrichWithRegModify || enrichWithWmiExec ||
            enrichWithLocalCollect || enrichWithLateralTransfer ||
            enrichWithThreatIntel || enrichWithLateralChain ||
            enrichWithEventlogTamper || enrichWithSshAbuse) {
            Event enriched(event);
            if (scanWithAmsi)
                amsi->EnrichEligible(enriched);
            if (silverfox)
                silverfox->Enrich(enriched);
            if (enrichWithBehavior)
                behavior->Enrich(enriched);
            if (enrichWithInjector)
                injector->Enrich(enriched);
            if (enrichWithAttacker)
                attacker->Enrich(enriched);
            if (enrichWithC2Beacon)
                c2beacon->Enrich(enriched);
            if (enrichWithRansom)
                ransom->Enrich(enriched);
            if (enrichWithLogonBrute)
                logonBrute->Enrich(enriched);
            if (enrichWithLogonSuccess)
                logonSuccess->Enrich(enriched);
            if (enrichWithPasswordSpray)
                passwordSpray->Enrich(enriched);
            if (enrichWithKerberoast)
                kerberoast->Enrich(enriched);
            if (enrichWithHollowing)
                hollowing->Enrich(enriched);
            if (enrichWithDnsBeacon)
                dnsBeacon->Enrich(enriched);
            if (enrichWithDnsFailure)
                dnsFailure->Enrich(enriched);
            if (enrichWithBehaviorBaseline)
                behaviorBaseline->Enrich(enriched);
            if (enrichWithLateralMove)
                lateralMove->Enrich(enriched);
            if (enrichWithPortScan)
                portScan->Enrich(enriched);
            if (enrichWithPersistChain)
                persistChain->Enrich(enriched);
            if (enrichWithLolbin)
                lolbin->Enrich(enriched);
            if (enrichWithLolbinChain)
                lolbinChain->Enrich(enriched);
            if (enrichWithPowerShellDownloadExecute)
                powershellDownloadExecute->Enrich(enriched);
            if (enrichWithDllHijack)
                dllHijack->Enrich(enriched);
            if (enrichWithRegistryPersistence)
                registryPersistence->Enrich(enriched);
            if (enrichWithAntiForensics)
                antiForensics->Enrich(enriched);
            if (enrichWithTimeChange)
                timeChange->Enrich(enriched);
            if (enrichWithPrivilegedGroup)
                privilegedGroup->Enrich(enriched);
            if (enrichWithDefenseEvasion)
                defenseEvasion->Enrich(enriched);
            if (enrichWithDiscoveryRecon)
                discoveryRecon->Enrich(enriched);
            if (enrichWithRdpChain)
                rdpChain->Enrich(enriched);
            if (enrichWithUacBypass)
                uacBypass->Enrich(enriched);
            if (enrichWithWmiPersistence)
                wmiPersistence->Enrich(enriched);
            if (enrichWithRansomPrecursor)
                ransomPrecursor->Enrich(enriched);
            if (enrichWithMemoryScanner)
                memoryScanner->Enrich(enriched);
            if (enrichWithDriverLoad)
                driverLoad->Enrich(enriched);
            if (enrichWithFileless)
                fileless->Enrich(enriched);
            if (enrichWithApiHook)
                apiHook->Enrich(enriched);
           if (enrichWithRemoteAccess)
               remoteAccess->Enrich(enriched);
            if (enrichWithCredDump)
                credDump->Enrich(enriched);
            if (enrichWithDataExfil)
                dataExfil->Enrich(enriched);
            if (enrichWithPrivEsc)
                privEsc->Enrich(enriched);
            if (enrichWithNtlmRelay)
                ntlmRelay->Enrich(enriched);
            if (enrichWithBrowserTheft)
                browserTheft->Enrich(enriched);
            if (enrichWithBrowserExtension)
                browserExtension->Enrich(enriched);
            if (enrichWithArchiveStaging)
                archiveStaging->Enrich(enriched);
            if (enrichWithBitsAbuse)
                bitsAbuse->Enrich(enriched);
            if (enrichWithDohAbuse)
                dohAbuse->Enrich(enriched);
            if (enrichWithSvcInstall)
                svcInstall->Enrich(enriched);
            if (enrichWithFirewallRule)
                firewallRule->Enrich(enriched);
            if (enrichWithShareChange)
                shareChange->Enrich(enriched);
            if (enrichWithLocalAccount)
                localAccount->Enrich(enriched);
            if (enrichWithCanary)
                canary->Enrich(enriched);
            if (enrichWithHookPersist)
                hookPersist->Enrich(enriched);
            if (enrichWithTaskAbuse)
                taskAbuse->Enrich(enriched);
            if (enrichWithMasquerade)
                masquerade->Enrich(enriched);
            if (enrichWithPpidSpoof)
                ppidSpoof->Enrich(enriched);
            if (enrichWithNetDiscovery)
                netDiscovery->Enrich(enriched);
            if (enrichWithHostProfile)
                hostProfile->Enrich(enriched);
            if (enrichWithPrivateKey)
                privateKey->Enrich(enriched);
            if (enrichWithAccessibilityHijack)
                accessibilityHijack->Enrich(enriched);
            if (enrichWithAclAbuse)
                aclAbuse->Enrich(enriched);
            if (enrichWithAmsiBypass)
                amsiBypass->Enrich(enriched);
            if (enrichWithAppInitDll)
                appInitDll->Enrich(enriched);
            if (enrichWithAsRepRoast)
                asRepRoast->Enrich(enriched);
            if (enrichWithBootProvider)
                bootProvider->Enrich(enriched);
            if (enrichWithCertAbuse)
                certAbuse->Enrich(enriched);
            if (enrichWithCorProfiler)
                corProfiler->Enrich(enriched);
            if (enrichWithCredFileHunt)
                credFileHunt->Enrich(enriched);
            if (enrichWithDcsync)
                dcsync->Enrich(enriched);
            if (enrichWithDevUtilProxy)
                devUtilProxy->Enrich(enriched);
            if (enrichWithDiskWipe)
                diskWipe->Enrich(enriched);
            if (enrichWithAvTamper)
                avTamper->Enrich(enriched);
            if (enrichWithTimestomp)
                timestomp->Enrich(enriched);
            if (enrichWithObfuscation)
                obfuscation->Enrich(enriched);
            if (enrichWithRegModify)
                regModify->Enrich(enriched);
            if (enrichWithWmiExec)
                wmiExec->Enrich(enriched);
            if (enrichWithLocalCollect)
                localCollect->Enrich(enriched);
            if (enrichWithLateralTransfer)
                lateralTransfer->Enrich(enriched);
            if (enrichWithThreatIntel)
                threatIntel->Enrich(enriched);
            if (enrichWithLateralChain)
                lateralChain->Enrich(enriched);
            if (enrichWithLsassDump)
                lsassDump->Enrich(enriched);
            if (enrichWithShadowCopy)
                shadowCopy->Enrich(enriched);
            if (enrichWithPersistBurst)
                persistBurst->Enrich(enriched);
            if (enrichWithMailboxRule)
                mailboxRule->Enrich(enriched);
            if (enrichWithMailboxDelegate)
                mailboxDelegate->Enrich(enriched);
            if (enrichWithLlmnrPoison)
                llmnrPoison->Enrich(enriched);
            if (enrichWithNetProviderPersist)
                netProviderPersist->Enrich(enriched);
            if (enrichWithPasswordVault)
                passwordVault->Enrich(enriched);
            if (enrichWithArpPoison)
                arpPoison->Enrich(enriched);
            if (enrichWithCloudMetadata)
                cloudMetadata->Enrich(enriched);
            if (enrichWithGppPassword)
                gppPassword->Enrich(enriched);
            if (enrichWithControlPanelProxy)
                controlPanelProxy->Enrich(enriched);
            if (enrichWithHiddenUserAccount)
                hiddenUserAccount->Enrich(enriched);
            if (enrichWithPasswordPolicyDiscovery)
                passwordPolicyDiscovery->Enrich(enriched);
            if (enrichWithMsiPackageInstall)
                msiPackageInstall->Enrich(enriched);
            if (enrichWithLogEnumeration)
                logEnumeration->Enrich(enriched);
            if (enrichWithCmstpBypass)
                cmstpBypass->Enrich(enriched);
            if (enrichWithFileAssoc)
                fileAssoc->Enrich(enriched);
            if (enrichWithHiddenWindow)
                hiddenWindow->Enrich(enriched);
            if (enrichWithOfficePersist)
                officePersist->Enrich(enriched);
            if (enrichWithShortcutPersist)
                shortcutPersist->Enrich(enriched);
            if (enrichWithIndirectExec)
                indirectExec->Enrich(enriched);
            if (enrichWithScreensaverPersist)
                screensaverPersist->Enrich(enriched);
            if (enrichWithSvcPathAbuse)
                svcPathAbuse->Enrich(enriched);
            if (enrichWithServiceDllHijack)
                serviceDllHijack->Enrich(enriched);
            if (enrichWithDllSearchOrder)
                dllSearchOrder->Enrich(enriched);
            if (enrichWithSvcRecovery)
                svcRecovery->Enrich(enriched);
            if (enrichWithComHijack)
                comHijack->Enrich(enriched);
            if (enrichWithWinlogonHijack)
                winlogonHijack->Enrich(enriched);
            if (enrichWithMshtaAbuse)
                mshtaAbuse->Enrich(enriched);
            if (enrichWithDotnetProxyExec)
                dotnetProxyExec->Enrich(enriched);
            if (enrichWithWslAbuse)
                wslAbuse->Enrich(enriched);
            if (enrichWithMsdtAbuse)
                msdtAbuse->Enrich(enriched);
            if (enrichWithSoftwareDiscovery)
                softwareDiscovery->Enrich(enriched);
            if (enrichWithNetShareDiscovery)
                netShareDiscovery->Enrich(enriched);
            if (enrichWithNonstandardPortEgress)
                nonstandardPortEgress->Enrich(enriched);
            if (enrichWithIsoMount)
                isoMount->Enrich(enriched);
            if (enrichWithPsProfile)
                psProfile->Enrich(enriched);
            if (enrichWithDowngradeAttack)
                downgradeAttack->Enrich(enriched);
            if (enrichWithDpapiAbuse)
                dpapiAbuse->Enrich(enriched);
            if (enrichWithEmailCollection)
                emailCollection->Enrich(enriched);
            if (enrichWithEtwScriptTamper)
                etwScriptTamper->Enrich(enriched);
            if (enrichWithForcedAuth)
                forcedAuth->Enrich(enriched);
            if (enrichWithGoldenTicket)
                goldenTicket->Enrich(enriched);
            if (enrichWithGpoAbuse)
                gpoAbuse->Enrich(enriched);
            if (enrichWithHiddenArtifacts)
                hiddenArtifacts->Enrich(enriched);
            if (enrichWithHistoryTamper)
                historyTamper->Enrich(enriched);
            if (enrichWithHiveCopy)
                hiveCopy->Enrich(enriched);
            if (enrichWithHostsRedirect)
                hostsRedirect->Enrich(enriched);
            if (enrichWithIisModule)
                iisModule->Enrich(enriched);
            if (enrichWithInputSimulation)
                inputSimulation->Enrich(enriched);
            if (enrichWithLogonScriptPersist)
                logonScriptPersist->Enrich(enriched);
            if (enrichWithLsaPackage)
                lsaPackage->Enrich(enriched);
            if (enrichWithMotwBypass)
                motwBypass->Enrich(enriched);
            if (enrichWithNetshHelper)
                netshHelper->Enrich(enriched);
            if (enrichWithNetworkSniffing)
                networkSniffing->Enrich(enriched);
            if (enrichWithNtdsDit)
                ntdsDit->Enrich(enriched);
            if (enrichWithPassTheHash)
                passTheHash->Enrich(enriched);
            if (enrichWithPasswordCracking)
                passwordCracking->Enrich(enriched);
            if (enrichWithPathInterception)
                pathInterception->Enrich(enriched);
            if (enrichWithPeAnomaly)
                peAnomaly->Enrich(enriched);
            if (enrichWithRansomOps)
                ransomOps->Enrich(enriched);
            if (enrichWithRdpSessionHijack)
                rdpSessionHijack->Enrich(enriched);
            if (enrichWithRegCredHunt)
                regCredHunt->Enrich(enriched);
            if (enrichWithRemoteExec)
                remoteExec->Enrich(enriched);
            if (enrichWithSecbootTamper)
                secbootTamper->Enrich(enriched);
            if (enrichWithShimDb)
                shimDb->Enrich(enriched);
            if (enrichWithSignedBinaryAbuse)
                signedBinaryAbuse->Enrich(enriched);
            if (enrichWithSipHijack)
                sipHijack->Enrich(enriched);
            if (enrichWithSshKeyPersistence)
                sshKeyPersistence->Enrich(enriched);
            if (enrichWithTicketCacheAbuse)
                ticketCacheAbuse->Enrich(enriched);
            if (enrichWithTokenImpersonation)
                tokenImpersonation->Enrich(enriched);
            if (enrichWithHandleGuard)
                handleGuard->Enrich(enriched);
            if (enrichWithNamedPipeAbuse)
                namedPipeAbuse->Enrich(enriched);
            if (enrichWithWebExfil)
                webExfil->Enrich(enriched);
            if (enrichWithWifiCredTheft)
                wifiCredTheft->Enrich(enriched);
            if (enrichWithWinrmAbuse)
                winrmAbuse->Enrich(enriched);
            if (enrichWithWinrmConfigTamper)
                winrmConfigTamper->Enrich(enriched);
            if (enrichWithXslScript)
                xslScript->Enrich(enriched);
            if (enrichWithEventlogTamper)
                eventlogTamper->Enrich(enriched);
            if (enrichWithSshAbuse)
                sshAbuse->Enrich(enriched);
            if (enrichWithCryptoMiner)
                cryptoMiner->Enrich(enriched);
            if (enrichWithAntiAnalysis)
                antiAnalysis->Enrich(enriched);
            if (enrichWithScriptHostAbuse)
                scriptHostAbuse->Enrich(enriched);
            if (enrichWithAccountOp)
                accountOp->Enrich(enriched);
            if (enrichWithTunnelTool)
                tunnelTool->Enrich(enriched);
            if (enrichWithSurveillance)
                surveillance->Enrich(enriched);
            if (enrichWithClipboardTheft)
                clipboardTheft->Enrich(enriched);
            if (enrichWithWebshell)
                webshell->Enrich(enriched);
            if (enrichWithUsbExfil)
                usbExfil->Enrich(enriched);
           Dispatch(enriched);
            return;
        }
        Dispatch(event);
    }

private:
    void Dispatch(const Event& event) {
        DeliverTelemetryEvent(event, reporter, redact, rules);
    }
};

ICollector* CreateDriverCollector();
ICollector* CreateFileFallbackCollector(std::vector<std::string> dirs);
ICollector* CreateNetFallbackCollector(uint32_t pollMs);
ICollector* CreateNetEtwCollector(bool udpEnabled);
ICollector* CreateRegBaselineCollector(uint32_t periodMs);
ICollector* CreateRegWatchCollector();
ICollector* CreateProcEtwCollector(bool fullImage, bool userSid);
ICollector* CreateProcPollCollector(bool fullImage);
ICollector* CreateIMonitorCollector(bool enableProcessOpen,
                                    bool enableRemoteThread,
                                    bool enableCredentialMonitor,
                                    bool enableInjectionDeep);
ICollector* CreateHooksCollector(const Config& cfg);
ICollector* CreateSysmonCollector(bool enableImageLoad, bool enableProcessAccess,
                                   bool enableRemoteThread, bool enableNamedPipe,
                                   uint32_t queueCapacity,
                                  uint32_t workers, uint32_t maxXmlBytes,
                                  bool reputationEnable, uint64_t reputationMaxBytes,
                                  bool reputationCacheOnlyTrust, EventLogReplayOptions replay);
ICollector* CreateSecurityLogCollector(uint32_t queueCapacity,
                                       uint32_t workers,
                                       uint32_t maxXmlBytes, EventLogReplayOptions replay);
ICollector* CreateWmiCollector(uint32_t queueCapacity, uint32_t workers,
                               uint32_t maxXmlBytes, EventLogReplayOptions replay);
ICollector* CreateTaskSchedulerCollector(uint32_t queueCapacity,
                                         uint32_t workers,
                                         uint32_t maxXmlBytes, EventLogReplayOptions replay);
ICollector* CreateDefenderCollector(uint32_t queueCapacity,
                                    uint32_t workers,
                                    uint32_t maxXmlBytes, EventLogReplayOptions replay);
ICollector* CreatePowerShellCollector(uint32_t queueCapacity,
                                       uint32_t workers,
                                       uint32_t maxXmlBytes,
                                       uint32_t maxScriptChars,
                                       PowerShellReassemblyConfig reassembly, EventLogReplayOptions replay);
ICollector* CreateStartupWatchCollector(std::vector<std::string> dirs);
ICollector* CreateImageLoadCollector(uint32_t queueCapacity);
ICollector* CreatePrivilegeCollector(uint32_t queueCapacity, uint32_t workers,
                                       uint32_t maxXmlBytes, EventLogReplayOptions replay);
ICollector* CreateDnsEtwCollector();
ICollector* CreateUsbCollector(uint32_t pollMs, uint64_t dedupWindowMs);
ICollector* CreateListenerCollector(uint32_t pollMs);
ICollector* CreateServiceCollector(uint32_t pollMs);
ICollector* CreateCriticalProcessCollector(
    uint32_t pollMs, uint32_t missingThreshold,
    const std::vector<std::string>& protectedImages);
    ICollector* CreateFimCollector(uint32_t pollMs, uint64_t maxFileBytes,
                               std::vector<std::string> watchFiles);
ICollector* CreateCanaryCollector(uint32_t pollMs, uint64_t maxFileBytes,
                                  std::vector<std::string> files);
ICollector* CreateHookScanCollector(uint32_t pollSeconds, size_t maxEntries);
ICollector* CreateShareCollector(uint32_t pollMs);
ICollector* CreateNamedPipeCollector();
ICollector* CreateLsassSamCollector(uint32_t pollMs, uint32_t dedupMs);
ICollector* CreateLocalAccountCollector(
    uint32_t pollMs, const std::vector<std::string>& watchGroups);
ICollector* CreateFirewallCollector(uint32_t pollMs);
ICollector* CreateRatAnalyzerCollector(const RatAnalyzerConfig& cfg);

static std::atomic<bool> g_quit{false};

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrl) {
    if (ctrl == CTRL_C_EVENT || ctrl == CTRL_CLOSE_EVENT ||
        ctrl == CTRL_BREAK_EVENT) {
        g_quit.store(true);
        return TRUE;
    }
    return FALSE;
}

struct Options {
    std::string configPath = "config\\edr.config.json";
    bool configGiven = false;
    bool redactGiven = false;
    bool redactValue = true;
    bool rulesGiven = false;
    std::string rulesPath;
    char action = 0; /* 0 = run, 'I' = install-service, 'U' = uninstall-service,
                        'B' = security baseline, 'T' = triage pack */
    std::string triageOut;
};

static bool ParseArgs(int argc, wchar_t** argv, Config& cfg, Options& opt) {
    for (int i = 1; i < argc; i++) {
        std::string arg = WideToUtf8(argv[i]);
        if (arg == "--console") {
            cfg.console = true;
        } else if (arg == "--service") {
            cfg.runAsService = true;
        } else if (arg == "--selftest") {
            cfg.selftest = true;
        } else if (arg == "--redact=on") {
            cfg.redact = true;
            opt.redactGiven = true;
            opt.redactValue = true;
        } else if (arg == "--redact=off") {
            cfg.redact = false;
            opt.redactGiven = true;
            opt.redactValue = false;
        } else if (arg == "--rules" && i + 1 < argc) {
            cfg.rulesPath = WideToUtf8(argv[++i]);
            opt.rulesGiven = true;
            opt.rulesPath = cfg.rulesPath;
        } else if (arg == "--config" && i + 1 < argc) {
            opt.configPath = WideToUtf8(argv[++i]);
            opt.configGiven = true;
        } else if (arg == "--baseline") {
            if (opt.action != 0) {
                std::fprintf(stderr, "only one action may be specified\n");
                return false;
            }
            opt.action = 'B';
        } else if (arg == "--sysinfo") {
            if (opt.action != 0) {
                std::fprintf(stderr, "only one action may be specified\n");
                return false;
            }
            opt.action = 'S';
        } else if (arg == "--install-service") {
            if (opt.action != 0) {
                std::fprintf(stderr, "only one action may be specified\n");
                return false;
            }
            opt.action = 'I';
        } else if (arg == "--uninstall-service") {
            if (opt.action != 0) {
                std::fprintf(stderr, "only one action may be specified\n");
                return false;
            }
            opt.action = 'U';
        } else if (arg == "--triage") {
            if (opt.action != 0) {
                std::fprintf(stderr, "only one action may be specified\n");
                return false;
            }
            opt.action = 'T';
        } else if (arg == "--out") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "--out requires a directory argument\n");
                return false;
            }
            i = i + 1;
            opt.triageOut = WideToUtf8(argv[i]);
        } else if (arg == "--help" || arg == "-h") {
            std::printf(
                "edr.exe [--console] [--service] [--selftest]\n"
                "        [--config <path>] [--rules <path>] [--redact=on|off]\n"
                "        [--baseline] [--sysinfo] [--install-service] "
                "[--uninstall-service] [--triage [--out <dir>]]\n");
            return false;
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", arg.c_str());
            return false;
        }
    }
    return true;
}

/* Current wall clock as a FILETIME tick count (100ns), matching the unit used
 * by every Event::ts100ns and therefore by the correlation window. */
static uint64_t Now100ns() {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

/* --selftest: synthetic events that must hit EDR-001 and EDR-004. */
static void InjectSelftestEvents(EventBus& bus) {
    {
        Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.pid = 4242;
        ev.ppid = 1111;
        ev.fields[field::kType] = "PROCESS_START";
        ev.fields[field::kImage] =
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        ev.fields[field::kCommandLine] = "powershell -enc AAAA";
        ev.fields[field::kParentImage] =
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_REG_WRITE;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.fields[field::kType] = "REG_WRITE";
        ev.fields[field::kRegKey] =
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\"
            "CurrentVersion\\Run\\SelftestValue";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_FILE_INTEGRITY;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.source = "fim_monitor";
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "FILE_INTEGRITY";
        ev.fields[field::kFimAction] = "modified";
        ev.fields[field::kFimPath] =
            "C:\\Windows\\System32\\drivers\\etc\\hosts";
        ev.fields[field::kFimSize] = "1024";
        ev.fields[field::kFimSha256] =
            "abc123def4567890abcdef1234567890abcdef1234567890abcdef1234567890";
        ev.fields[field::kFimBaseline] = "true";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_SHARE_CHANGE;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.source = "share_monitor";
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "SHARE_CHANGE";
        ev.fields[field::kShareAction] = "added";
        ev.fields[field::kShareName] = "SecretShare";
        ev.fields[field::kSharePath] = "C:\\Data\\Secret";
        ev.fields[field::kShareType] = "disk";
        ev.fields[field::kShareRemark] = "Internal share";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_DNS_QUERY;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.source = "dns_etw";
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "DNS_QUERY";
        ev.fields[field::kDnsQueryName] =
            "abcd.efgh.ijkl.mnop.qrst.wxyz.example.com";
        ev.fields[field::kDnsQueryType] = "A";
        ev.fields[field::kDnsEntropy] = "3.86";
        ev.fields[field::kDnsSubdomainCount] = "6";
        ev.fields[field::kDnsMaxLabelLength] = "4";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_BLOCK;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.source = "host_isolation";
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "BLOCK";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_ETW_TAMPER;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.source = "etw_tamper_monitor";
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "ETW_TAMPER";
        ev.fields[field::kEtwTamperType] = "etw_event_write_patched";
        ev.fields[field::kEtwTamperPid] = "4242";
        ev.fields[field::kEtwTamperImage] =
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        ev.fields[field::kEtwTamperModule] = "ntdll.dll";
        ev.fields[field::kEtwExpectedBytes] =
            "48894c24084889542410574883ec38";
        ev.fields[field::kEtwActualBytes] =
            "c34889542410574883ec38";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.pid = 4300;
        ev.ppid = 1111;
        ev.fields[field::kType] = "PROCESS_START";
        ev.fields[field::kImage] = "C:\\Windows\\System32\\ntdsutil.exe";
        ev.fields[field::kCommandLine] = "ntdsutil \"ac i ntds\" ifm \"create full c:\\temp\"";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.pid = 4301;
        ev.ppid = 1111;
        ev.fields[field::kType] = "PROCESS_START";
        ev.fields[field::kImage] = "C:\\Windows\\System32\\tscon.exe";
        ev.fields[field::kCommandLine] = "tscon 2 /dest:console";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_REG_WRITE;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.source = "registry_watch";
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "REG_WRITE";
        ev.fields[field::kRegKey] =
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\"
            "WDigest\\UseLogonCredential";
        ev.fields[field::kRegValue] = "1";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_RDP_SESSION;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.source = "rdp_log";
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "RDP_SESSION";
        ev.fields[field::kRdpAction] = "logon";
        ev.fields[field::kRdpUser] = "selftest";
        ev.fields[field::kRdpDomain] = "LAB";
        ev.fields[field::kRdpSessionId] = "2";
        ev.fields[field::kRdpSourceIp] = "192.0.2.10";
        ev.fields[field::kRdpEventId] = "21";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.pid = 4302;
        ev.fields[field::kType] = "PROCESS_START";
        ev.fields[field::kImage] = "C:\\Windows\\System32\\vssadmin.exe";
        ev.fields[field::kCommandLine] = "vssadmin delete shadows /all /quiet";
        bus.Push(ev);
    }
    {
        Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        ev.pid = 4303;
        ev.fields[field::kType] = "PROCESS_START";
        ev.fields[field::kImage] = "C:\\Windows\\System32\\bcdedit.exe";
        ev.fields[field::kCommandLine] =
            "bcdedit /set {default} recoveryenabled no";
        bus.Push(ev);
    }
}

static void InjectCorrelationSelftestEvents(EventBus& bus, const Config& cfg) {
    const uint64_t now = Now100ns();
    if (cfg.logonSuccessEnable) {
        for (uint32_t index = 0; index <= cfg.logonSuccessMinFailures; ++index) {
            Event event;
            event.type = EDR_EVT_LOGON;
            event.ts100ns = now + index;
            event.source = "security_log";
            event.fields[field::kSource] = event.source;
            event.fields[field::kType] = "LOGON";
            event.fields[field::kOperationType] =
                index == cfg.logonSuccessMinFailures ? "LOGON" : "LOGON_FAILURE";
            event.fields[field::kLogonType] = "3";
            event.fields[field::kSrcIp] = "192.0.2.90";
            event.fields[field::kTargetDomain] = "EDR-SELFTEST";
            event.fields[field::kTargetUser] = "test-account";
            bus.Push(event);
        }
    }
    if (cfg.dnsFailureEnable) {
        const uint32_t count = std::max({cfg.dnsFailureMinQueries,
            cfg.dnsFailureMinDistinctNames, cfg.dnsFailureMinHighEntropyFailures});
        for (uint32_t index = 0; index < count; ++index) {
            Event event;
            event.type = EDR_EVT_DNS_QUERY;
            event.ts100ns = now + index;
            event.pid = 4401;
            event.processStartTime100ns = now - 10000000ULL;
            event.source = "dns_etw";
            event.fields[field::kSource] = event.source;
            event.fields[field::kType] = "DNS_QUERY";
            event.fields[field::kImage] = "C:\\EDR-Selftest\\dns-client.exe";
            event.fields["dns_phase"] = "completed";
            event.fields[field::kDnsQueryStatus] = "9003";
            event.fields[field::kDnsQueryName] =
                "q" + std::to_string(index) + ".edr-selftest.example.com";
            event.fields[field::kDnsEntropy] = "4.2";
            bus.Push(event);
        }
    }
}

class Agent {
public:
    int Run(Config& cfg, const std::function<void()>& onReady = {}) {
        std::string err;
        if (!LoadConfigFile(m_configPath, cfg, err)) {
            std::wstring configPath = Utf8ToWide(m_configPath);
            DWORD attributes = GetFileAttributesW(configPath.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES) {
                std::fprintf(stderr, "[edr] config load failed: %s\n", err.c_str());
                return 2;
            }
            std::fprintf(stderr, "[edr] config: %s (using defaults)\n", err.c_str());
        }
        if (m_redactCliGiven) {
            cfg.redact = m_redact; /* CLI overrides config file */
        }
        if (!m_rulesCliPath.empty()) {
            cfg.rulesPath = m_rulesCliPath;
        }

        if (cfg.responseChannelEnable) {
            m_responseServer = std::make_unique<ResponseServer>();
            if (!m_responseServer->Start(cfg.responsePipeName,
                    cfg.responseCommandKeyFile, cfg.responseAuditPath,
                    cfg.responseEnableProcessTermination, err,
                    cfg.responseEnableQuarantine, cfg.responseQuarantineDir,
                    cfg.responseQuarantineMaxFileBytes,
                    cfg.responseMaxTreeSize,
                    cfg.responseEnableDeleteFile,
                    cfg.responseEnableProcessSuspend,
                    cfg.responseEnableProcessResume)) {
                std::fprintf(stderr,
                    "[edr] response channel enabled but startup failed: %s\n",
                    err.c_str());
                m_responseServer.reset();
                return 2;
            }
            std::fprintf(stderr,
                "[edr] authenticated response channel ready (termination=%s, quarantine=%s, delete_file=%s)\n",
                cfg.responseEnableProcessTermination ? "real" : "dry-run",
                cfg.responseEnableQuarantine ? "real" : "dry-run",
                cfg.responseEnableDeleteFile ? "real" : "dry-run");
        }

        /* Host isolation controller initialization. */
        if (cfg.enableHostIsolation) {
            m_hostIsolation = std::make_unique<HostIsolationController>();
            if (m_responseServer) {
                HostIsolationController* isolation = m_hostIsolation.get();
                const std::string configuredManagementIp = cfg.hostIsolationManagementIp;
                const std::string configuredAllowedPorts = cfg.hostIsolationAllowedPorts;
                m_responseServer->SetIsolationHandler(
                    [isolation, configuredManagementIp, configuredAllowedPorts](bool enable,
                                const std::string& managementIp,
                                const std::string& allowedPorts)
                        -> ResponseIsolationResult {
                    ResponseIsolationResult result;
                    if (managementIp != configuredManagementIp ||
                        allowedPorts != configuredAllowedPorts) {
                        result.success = false;
                        result.status = "policy_mismatch";
                        result.error = "requested isolation policy does not match agent configuration";
                        return result;
                    }
                    std::string error;
                    if (enable) {
                        if (isolation->EnableIsolation(managementIp,
                                allowedPorts, error)) {
                            result.success = true;
                            result.status = "isolated";
                        } else {
                            result.success = false;
                            result.status = "enable_failed";
                            result.error = error;
                        }
                    } else {
                        if (isolation->DisableIsolation(error)) {
                            result.success = true;
                            result.status = "restored";
                        } else {
                            result.success = false;
                            result.status = "disable_failed";
                            result.error = error;
                        }
                    }
                    return result;
                });
                m_responseServer->SetIsolationStatusHandler(
                    [isolation]() { return isolation->GetStatus(); });
                std::fprintf(stderr,
                    "[edr] host isolation controller ready (managementIp=%s)\n",
                    cfg.hostIsolationManagementIp.c_str());
            } else {
                std::fprintf(stderr,
                    "[edr] host isolation enabled but no response server; "
                    "isolation commands will not be available\n");
            }
        }

        try {
            m_rules.LoadFromFile(cfg.rulesPath);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[edr] rules load failed: %s\n", e.what());
            return 2;
        }
        std::fprintf(stderr, "[edr] loaded %zu rules from %s\n",
                     m_rules.RuleCount(), cfg.rulesPath.c_str());
        if (cfg.ruleReloadEnable)
            std::fprintf(stderr,
                         "[edr] rules hot reload armed (every %us; parse "
                         "failures keep the previous rule set)\n",
                         cfg.ruleReloadPollSeconds);

        m_alerter = std::make_unique<Alerter>(cfg.alertsPath, cfg.redact,
                                              cfg.eventLog);
        if (!m_alerter->Open()) {
            std::fprintf(stderr, "[edr] cannot open %s; alert persistence unavailable\n",
                         cfg.alertsPath.c_str());
        }
        if (cfg.reporterEnable) {
            ReporterSpoolOptions alertSpool;
            if (cfg.reporterSpoolEnable) {
                alertSpool.directory = cfg.reporterSpoolDirectory;
                alertSpool.maxRecords = cfg.reporterSpoolMaxRecords;
                alertSpool.maxBytes = static_cast<size_t>(cfg.reporterSpoolMaxBytes);
                alertSpool.maxItemBytes = static_cast<size_t>(cfg.reporterSpoolMaxItemBytes);
            }
            m_reporter = std::make_unique<Reporter>(cfg.reporterUrl,
                cfg.reporterApiKey, 1000, Reporter::PostFn{}, alertSpool);
            if (!m_reporter->Start()) {
                std::fprintf(stderr, "[edr] alert reporter unavailable (spool=%s)\n",
                             m_reporter->GetSpoolStatus().c_str());
            }
            ReporterSpoolOptions eventSpool = alertSpool;
            if (cfg.reporterSpoolEnable)
                eventSpool.directory = cfg.reporterEventSpoolDirectory;
            m_eventReporter = std::make_unique<Reporter>(
                EventReporterUrl(cfg.reporterUrl), cfg.reporterApiKey,
                1000, Reporter::PostFn{}, eventSpool);
            if (!m_eventReporter->Start()) {
                std::fprintf(stderr, "[edr] event reporter unavailable (spool=%s)\n",
                             m_eventReporter->GetSpoolStatus().c_str());
            }
        }

        if (cfg.syslogEnable) {
            std::string hostname = cfg.syslogHostname;
            if (hostname.empty()) {
                char nameBuf[256] = {};
                DWORD nameLen = (DWORD)sizeof(nameBuf);
                if (GetComputerNameA(nameBuf, &nameLen)) {
                    hostname.assign(nameBuf, nameLen);
                }
            }
            m_syslogForwarder = std::make_unique<SyslogForwarder>(
                cfg.syslogHost, cfg.syslogPort, cfg.syslogFacility, hostname);
            if (!m_syslogForwarder->Start()) {
                std::fprintf(stderr, "[edr] syslog forwarder enabled but start failed; disabled\n");
                m_syslogForwarder.reset();
            } else {
                std::fprintf(stderr,
                    "[edr] syslog forwarder armed (%s:%lu facility=%lu)\n",
                    cfg.syslogHost.c_str(),
                    static_cast<unsigned long>(cfg.syslogPort),
                    static_cast<unsigned long>(cfg.syslogFacility));
            }
        }

        if (cfg.webhookEnable) {
            m_webhookNotifier = std::make_unique<WebhookNotifier>(
                cfg.webhookEnable, cfg.webhookUrl, cfg.webhookTimeoutSeconds,
                cfg.webhookQueueCapacity);
            std::fprintf(stderr, "[edr] webhook notifier armed (%s, timeout=%us, queue capacity=%zu)\n",
                         cfg.webhookUrl.c_str(),
                         static_cast<unsigned>(cfg.webhookTimeoutSeconds),
                         cfg.webhookQueueCapacity);
        }

        /* Webhook delivery rides the Alerter sink so EVERY persisted alert
         * (rule alerts and auto-responder follow-ups alike) is mirrored to
         * the notifier exactly once, with the same JSON line that landed in
         * alerts.jsonl. m_alerter is already constructed above; registered
         * here so m_webhookNotifier is live before any alert can fire. */
        if (m_alerter) {
            m_alerter->SetSink([this](const std::string& alertJson) {
                if (m_webhookNotifier) m_webhookNotifier->Notify(alertJson);
            });
        }

        if (cfg.autoResponseEnable) {
            if (cfg.responseChannelEnable && m_responseServer &&
                (cfg.responseEnableProcessTermination ||
                 cfg.responseEnableDeleteFile)) {
                ResponseServer* server = m_responseServer.get();
                m_autoResponder = std::make_unique<AutoResponder>(
                    [server, &cfg](const ResponseActionRequest& request) {
                        ResponseActionResult result;
                        if (!cfg.responseEnableProcessTermination ||
                            !server->ExecuteTerminate(request, result)) {
                            result.status = "unavailable";
                        }
                        return result;
                    },
                    [server, &cfg](const DeleteFileRequest& request) {
                        DeleteFileResult result;
                        if (!cfg.responseEnableDeleteFile ||
                            !cfg.autoResponseEnableDeleteFile ||
                            !server->ExecuteDeleteFile(request, result)) {
                            result.status = "unavailable";
                        }
                        return result;
                    },
                    m_alerter.get(), SeverityRank(cfg.autoResponseMinSeverity),
                    cfg.autoResponseMaxPerMinute,
                    cfg.autoResponseTreeTermination ? cfg.responseMaxTreeSize : 0,
                    cfg.autoResponseSuspendBeforeTerminate,
                    cfg.autoResponseMaxTreeDepth,
                    cfg.autoResponseIsolateBeforeTerminate,
                    AutoResponder::IsolationFn{},
                    cfg.autoResponseCaptureSnapshot ?
                        [snapshotDir = cfg.autoResponseSnapshotDir,
                         maxDepth = cfg.processTreeMaxDepth, this](
                            const Alert& alert, const std::string& requestId,
                            std::string& evidencePath) -> bool {
                            std::wstring baseDir = snapshotDir.empty()
                                ? Utf8ToWide("C:\\ProgramData\\EDR\\evidence")
                                : Utf8ToWide(snapshotDir);
                            if (baseDir.empty()) return false;
                            std::wstring requestWide = Utf8ToWide(requestId);
                            if (requestWide.empty()) return false;
                            std::wstring dir = baseDir + L"\\" + requestWide;
                            if (!CreateDirectoryW(baseDir.c_str(), nullptr) &&
                                GetLastError() != ERROR_ALREADY_EXISTS) {
                                return false;
                            }
                            if (!CreateDirectoryW(dir.c_str(), nullptr) &&
                                GetLastError() != ERROR_ALREADY_EXISTS) {
                                return false;
                            }
                            std::string snapshotTextPath = WideToUtf8((dir + L"\\snapshot.txt").c_str());
                            std::string error;
                            edr::SnapshotOptions options;
                            options.processTreeDepth = maxDepth;
                            if (!edr::WriteSystemSnapshotFile(snapshotTextPath, error, options)) {
                                return false;
                            }
                            std::string treePath = WideToUtf8((dir + L"\\process_tree.json").c_str());
                            std::ofstream treeOut(treePath, std::ios::binary);
                            if (!treeOut) return false;
                            if (m_processTree && alert.event && alert.event->pid > 0) {
                                treeOut << m_processTree->GetProcessTreeJson(alert.event->pid, maxDepth);
                            } else {
                                treeOut << "{}";
                            }
                            std::string alertPath = WideToUtf8((dir + L"\\alert.json").c_str());
                            std::ofstream alertOut(alertPath, std::ios::binary);
                            if (!alertOut) return false;
                            alertOut << AlertToJsonLine(alert, false);
                            std::string responsePath = WideToUtf8((dir + L"\\response.json").c_str());
                            std::ofstream responseOut(responsePath, std::ios::binary);
                            if (!responseOut) return false;
                            responseOut << "{\"requestId\":\"" << jsonlite::escape(requestId) << "\",";
                            responseOut << "\"ruleId\":\"" << jsonlite::escape(alert.ruleId) << "\",";
                            responseOut << "\"action\":\"" << jsonlite::escape(alert.action) << "\",";
                            responseOut << "\"severity\":\"" << jsonlite::escape(alert.severity) << "\"}";
                            std::string manifestPath = WideToUtf8((dir + L"\\manifest.json").c_str());
                            std::ofstream manifest(manifestPath, std::ios::binary);
                            if (!manifest) return false;
                            manifest << edr::BuildSystemSnapshotManifest(
                                requestId, alert.ruleId, alert.severity, alert.action,
                                snapshotTextPath, treePath, alertPath, snapshotTextPath);
                            evidencePath = snapshotTextPath;
                            return true;
                        } : AutoResponder::SnapshotWriterFn{},
                    cfg.autoResponseParentWhitelist);
                std::fprintf(stderr,
                    "[edr] auto-response armed (min_severity=%s, max %lu/min, tree=%s%s, kill=%s, delete_file=%s)\n",
                    cfg.autoResponseMinSeverity.c_str(),
                    static_cast<unsigned long>(cfg.autoResponseMaxPerMinute),
                    cfg.autoResponseTreeTermination ? "on" : "off",
                    cfg.autoResponseSuspendBeforeTerminate ?
                        ", suspend-first" : "",
                    cfg.responseEnableProcessTermination ? "on" : "off",
                    cfg.responseEnableDeleteFile ? "on" : "off");
            } else {
                std::fprintf(stderr,
                    "[edr] auto_response.enable=true but no real response action is "
                    "active (needs response_channel.enable and at least one of "
                    "enable_process_termination or enable_delete_file); "
                    "auto-response disabled\n");
            }
        }

        m_rules.SetAlertCallback([this](const Alert& alert) {
            /* Correlate before dispatching so the roll-up sees this alert and
             * the incident id is available to any consumer that wants it. The
             * correlator is a pure observer: it never triggers a response.
             * Roll-up events are excluded: folding one back in would make the
             * incident graph feed on its own output. */
            if (m_correlation && alert.event != nullptr &&
                !CorrelationRollup::IsRollup(*alert.event)) {
                const CorrelationAnnotation annotation =
                    m_correlation->Observe(alert);
                if (!annotation.incidentId.empty()) {
                    std::fprintf(stderr,
                        "[edr] %s %s -> %s (stage=%s, alerts=%u)\n",
                        alert.severity.c_str(), alert.ruleId.c_str(),
                        annotation.incidentId.c_str(),
                        annotation.stage.empty() ? "-" : annotation.stage.c_str(),
                        static_cast<unsigned>(annotation.alertCount));
                    if (m_rollup != nullptr)
                        m_rollup->Publish(annotation, *alert.event);
                }
            }
            m_alerter->OnAlert(alert);
            if (m_reporter) {
                m_reporter->Enqueue(AlertToJsonLine(alert, m_redact));
            }
            if (m_syslogForwarder) {
                m_syslogForwarder->Enqueue(alert.severity, alert.ruleId,
                                           AlertToJsonLine(alert, m_redact));
            }
            /* Webhook is fed from Alerter::SetSink (OnAlert tail) so rule
             * alerts and responder follow-ups are mirrored exactly once. */
            if ((alert.action == "terminate" || alert.action == "kill" ||
                 alert.action == "delete_file") && m_autoResponder) {
                m_autoResponder->Enqueue(alert);
            }
            std::fprintf(stderr, "[edr] %s %s (%s)\n",
                         alert.severity.c_str(), alert.ruleId.c_str(),
                         EventTypeName(alert.event->type));
        });

        m_dispatch.rules = &m_rules;
        m_dispatch.reporter = m_eventReporter.get();
        m_dispatch.redact = cfg.redact;
        m_amsiPlatform = CreateNativeAmsiPlatform();
        m_amsi = std::make_unique<AmsiEnricher>(
            cfg.amsiEnable, cfg.amsiMaxContentChars, *m_amsiPlatform);
        m_dispatch.amsi = m_amsi.get();
        if (m_amsi->InitializationFailed()) {
            std::fprintf(stderr,
                "[edr] AMSI initialization failed (0x%08lx); eligible events will report errors\n",
                static_cast<unsigned long>(m_amsi->InitializationHresult()));
        }
        if (cfg.enableSilverFox) {
            m_silverfox = std::make_unique<SilverFoxDetector>(
                true, cfg.silverFoxCorrelationWindowSeconds,
                cfg.silverFoxStateCapacity);
            std::string iocError;
            if (!m_silverfox->LoadIndicators(
                    cfg.silverFoxIocPath, iocError)) {
                std::fprintf(stderr,
                    "[edr] SilverFox IOC load warning: %s; "
                    "behavior correlation remains active\n",
                    iocError.c_str());
            } else {
                std::fprintf(stderr,
                    "[edr] SilverFox detector ready (%zu sourced IOCs)\n",
                    m_silverfox->IndicatorCount());
            }
            m_dispatch.silverfox = m_silverfox.get();
        }
        if (cfg.behaviorEnrichEnable) {
            m_behavior = std::make_unique<BehaviorEnricher>(
                cfg.behaviorEnrichStateCapacity,
                cfg.behaviorEnrichWindowSeconds,
                cfg.behaviorEnrichLsassBurstWindowSeconds,
                cfg.behaviorEnrichLsassBurstThresholdBytes);
            m_dispatch.behavior = m_behavior.get();
            std::fprintf(stderr, "[edr] behavior enricher ready\n");
        }
        if (cfg.injectChainEnable) {
            m_injector = std::make_unique<InjectionChainDetector>(
                cfg.injectChainStateCapacity,
                cfg.injectChainWindowSeconds,
                cfg.injectChainMinTransitionScore);
            m_dispatch.injector = m_injector.get();
            std::fprintf(stderr, "[edr] injection chain detector ready\n");
        }
        if (cfg.attackChainEnable) {
            m_attacker = std::make_unique<AttackChainDetector>(
                cfg.attackChainStateCapacity,
                cfg.attackChainWindowSeconds);
            m_dispatch.attacker = m_attacker.get();
            std::fprintf(stderr, "[edr] attack chain detector ready\n");
        }
        if (cfg.c2BeaconEnable) {
            m_c2 = std::make_unique<C2BeaconDetector>(
                cfg.c2BeaconEnable, cfg.c2BeaconWindowSeconds,
                cfg.c2BeaconStateCapacity, cfg.c2BeaconMinRepeatEndpoints,
                cfg.c2BeaconMinConnectionsPerEndpoint);
            m_dispatch.c2beacon = m_c2.get();
            std::fprintf(stderr, "[edr] c2 beacon detector ready\n");
        }
        if (cfg.ransomBurstEnable) {
            m_ransom = std::make_unique<RansomBurstDetector>(
                cfg.ransomBurstEnable, cfg.ransomBurstWindowSeconds,
                cfg.ransomBurstStateCapacity, cfg.ransomBurstMinFileCount,
                cfg.ransomBurstMinDistinctExtensions);
            m_dispatch.ransom = m_ransom.get();
            std::fprintf(stderr, "[edr] ransomware burst detector ready\n");
        }
        if (cfg.logonBruteForceEnable) {
            m_logonBrute = std::make_unique<LogonBruteForceDetector>(
                cfg.logonBruteForceEnable, cfg.logonBruteForceWindowSeconds,
                cfg.logonBruteForceStateCapacity, cfg.logonBruteForceMinFailures,
                cfg.logonBruteForceDedupSeconds);
            m_dispatch.logonBrute = m_logonBrute.get();
            std::fprintf(stderr, "[edr] logon brute-force detector ready\n");
        }
        if (cfg.logonSuccessEnable) {
            m_logonSuccess = std::make_unique<LogonSuccessDetector>(
                cfg.logonSuccessEnable, cfg.logonSuccessWindowSeconds,
                cfg.logonSuccessStateCapacity, cfg.logonSuccessMinFailures);
            m_dispatch.logonSuccess = m_logonSuccess.get();
            std::fprintf(stderr, "[edr] logon success-after-failures detector ready\n");
        }
        if ((cfg.passwordSprayEnable || cfg.kerberoastBurstEnable || cfg.logonSuccessEnable) &&
            !cfg.enableSecurityLog) {
            std::fprintf(stderr,
                "[edr] warning: credential correlation is enabled but "
                "enable_security_log=false; Security 4624/4625/4769 "
                "telemetry will be unavailable\n");
        }
        if (cfg.passwordSprayEnable) {
            m_passwordSpray = std::make_unique<PasswordSprayDetector>(
                cfg.passwordSprayEnable, cfg.passwordSprayWindowSeconds,
                cfg.passwordSprayStateCapacity, cfg.passwordSprayMinFailures,
                cfg.passwordSprayMinDistinctUsers,
                cfg.passwordSpraySuccessFollowupSeconds,
                cfg.passwordSprayDedupSeconds,
                cfg.passwordSprayMaxFailuresPerSource);
            m_dispatch.passwordSpray = m_passwordSpray.get();
            std::fprintf(stderr, "[edr] password spray detector ready\n");
        }
        if (cfg.kerberoastBurstEnable) {
            m_kerberoast = std::make_unique<KerberoastDetector>(
                cfg.kerberoastBurstEnable,
                cfg.kerberoastBurstWindowSeconds,
                cfg.kerberoastBurstStateCapacity,
                cfg.kerberoastBurstMinServiceCount,
                cfg.kerberoastBurstDedupSeconds,
                cfg.kerberoastBurstMaxServicesPerRequester);
            m_dispatch.kerberoast = m_kerberoast.get();
            std::fprintf(stderr, "[edr] Kerberoast burst detector ready\n");
        }
        if (cfg.processHollowingEnable) {
            m_hollowing = std::make_unique<ProcessHollowingDetector>(
                cfg.processHollowingEnable, cfg.processHollowingMinScore,
                cfg.processHollowingDedupWindowSeconds,
                cfg.processHollowingStateCapacity);
            m_dispatch.hollowing = m_hollowing.get();
            std::fprintf(stderr, "[edr] process hollowing detector ready\n");
        }
        if (cfg.dnsFailureEnable) {
            if (!cfg.enableDnsEtw)
                std::fprintf(stderr, "[edr] warning: dns_failure needs completed DNS "
                    "status and reliable process attribution; enable_dns_etw=false\n");
            m_dnsFailure = std::make_unique<DnsFailureDetector>(
                cfg.dnsFailureEnable, cfg.dnsFailureWindowSeconds,
                cfg.dnsFailureStateCapacity, cfg.dnsFailureMinQueries,
                cfg.dnsFailureMinDistinctNames, cfg.dnsFailureMinFailurePercent,
                cfg.dnsFailureMinHighEntropyFailures);
            m_dispatch.dnsFailure = m_dnsFailure.get();
            std::fprintf(stderr, "[edr] DNS name-error burst detector ready\n");
        }
        if (cfg.dnsBeaconEnable) {
            m_dns = std::make_unique<DnsBeaconDetector>(
                cfg.dnsBeaconEnable, cfg.dnsBeaconWindowSeconds,
                cfg.dnsBeaconStateCapacity, cfg.dnsBeaconMinQueryCount,
                cfg.dnsBeaconMinHighEntropyCount);
            m_dispatch.dnsBeacon = m_dns.get();
            std::fprintf(stderr, "[edr] dns beacon detector ready\n");
        }
        if (cfg.behaviorBaselineEnable) {
            if (!cfg.behaviorEnrichEnable)
                std::fprintf(stderr,
                    "[edr] behavior baseline pollution guard needs "
                    "behavior_enrich.enable for chain_score input\n");
            BehaviorBaselineDetector::Options options;
            options.enabled = cfg.behaviorBaselineEnable;
            options.trainingSeconds = cfg.behaviorBaselineTrainingSeconds;
            options.windowSeconds = cfg.behaviorBaselineWindowSeconds;
            options.dedupSeconds = cfg.behaviorBaselineDedupSeconds;
            options.stateCapacity = cfg.behaviorBaselineStateCapacity;
            options.minScore = cfg.behaviorBaselineMinScore;
            options.pollutionScore = cfg.behaviorBaselinePollutionScore;
            options.maxObservations = cfg.behaviorBaselineMaxObservations;
            options.maxAgeDays = cfg.behaviorBaselineMaxAgeDays;
            options.baselinePath = cfg.behaviorBaselinePath;
            m_behaviorBaseline =
                std::make_unique<BehaviorBaselineDetector>(options);
            m_dispatch.behaviorBaseline = m_behaviorBaseline.get();
            std::fprintf(stderr,
                "[edr] behavior baseline detector ready (%zu entries"
                " loaded from disk)\n",
                m_behaviorBaseline->LoadedEntries());
        }
        if (cfg.lateralMoveEnable) {
            m_lateral = std::make_unique<LateralMovementDetector>(
                cfg.lateralMoveEnable, cfg.lateralMoveWindowSeconds,
                cfg.lateralMoveStateCapacity, cfg.lateralMoveMinDestCount,
                cfg.lateralMoveScorePerDest);
            m_dispatch.lateralMove = m_lateral.get();
            std::fprintf(stderr, "[edr] lateral movement detector ready\n");
        }
        if (cfg.portScanEnable) {
            m_portScan = std::make_unique<PortScanDetector>(
                cfg.portScanEnable, cfg.portScanWindowSeconds,
                cfg.portScanStateCapacity, cfg.portScanMinDistinctPorts);
            m_dispatch.portScan = m_portScan.get();
            std::fprintf(stderr, "[edr] port scan detector ready\n");
        }
        if (cfg.persistChainEnable) {
            m_persistChain = std::make_unique<PersistenceChainDetector>(
                cfg.persistChainEnable, cfg.persistChainWindowSeconds,
                cfg.persistChainStateCapacity, cfg.persistChainMinMechanisms);
            m_dispatch.persistChain = m_persistChain.get();
            std::fprintf(stderr, "[edr] persistence chain detector ready\n");
        }
        if (cfg.lolbinParentChildEnable) {
            m_lolbin = std::make_unique<LolbinParentChildDetector>(
                cfg.lolbinParentChildEnable, cfg.lolbinParentChildMinScore);
            m_dispatch.lolbin = m_lolbin.get();
            std::fprintf(stderr, "[edr] lolbin parent-child detector ready\n");
        }
        if (cfg.lolbinChainEnable) {
            m_lolbinChain = std::make_unique<LolbinChainDetector>(
                cfg.lolbinChainEnable, cfg.lolbinChainWindowSeconds,
                cfg.lolbinChainStateCapacity,
                cfg.lolbinChainMinDistinctChildren);
            m_dispatch.lolbinChain = m_lolbinChain.get();
            std::fprintf(stderr, "[edr] lolbin chain detector ready\n");
        }
        if (cfg.powershellDownloadExecuteEnable) {
            m_powershellDownloadExecute =
                std::make_unique<PowerShellDownloadExecuteDetector>(
                    cfg.powershellDownloadExecuteEnable,
                    cfg.powershellDownloadExecuteWindowSeconds,
                    cfg.powershellDownloadExecuteStateCapacity,
                    cfg.powershellDownloadExecuteMinDistinctScripts);
            m_dispatch.powershellDownloadExecute =
                m_powershellDownloadExecute.get();
            std::fprintf(stderr, "[edr] powershell download-execute detector ready\n");
        }
        if (cfg.dllHijackEnable) {
            m_dllHijack = std::make_unique<DllHijackDetector>(
                cfg.dllHijackEnable);
            m_dispatch.dllHijack = m_dllHijack.get();
            if (!cfg.enableImageLoad) {
                std::fprintf(stderr,
                    "[edr] warning: DLL hijack detector enabled but "
                    "enable_image_load=false; IMAGE_LOAD telemetry will be "
                    "unavailable\n");
            }
            std::fprintf(stderr, "[edr] DLL hijack detector ready\n");
        }
        if (cfg.registryPersistenceEnable) {
            m_registryPersistence = std::make_unique<RegistryPersistenceDetector>(
                cfg.registryPersistenceEnable,
                cfg.registryPersistenceWindowSeconds,
                cfg.registryPersistenceStateCapacity);
            m_dispatch.registryPersistence = m_registryPersistence.get();
            if (!cfg.enableRegWatch) {
                std::fprintf(stderr,
                    "[edr] warning: registry persistence detector enabled but "
                    "enable_reg_watch=false; REG_WRITE telemetry will be "
                    "unavailable\n");
            }
            std::fprintf(stderr, "[edr] registry persistence detector ready\n");
        }
        if (cfg.antiForensicsEnable) {
            m_antiForensics = std::make_unique<AntiForensicsDetector>(
                cfg.antiForensicsEnable,
                cfg.antiForensicsWindowSeconds,
                cfg.antiForensicsStateCapacity);
            m_dispatch.antiForensics = m_antiForensics.get();
            if (!cfg.enableSecurityLog) {
                std::fprintf(stderr,
                    "[edr] warning: anti-forensics detector enabled but "
                    "enable_security_log=false; AUDIT_LOG telemetry will be "
                    "unavailable\n");
            }
            std::fprintf(stderr, "[edr] anti-forensics detector ready\n");
        }
        if (cfg.timeChangeEnable) {
            m_timeChange = std::make_unique<TimeChangeDetector>(
                cfg.timeChangeEnable,
                cfg.timeChangeWindowSeconds,
                cfg.timeChangeStateCapacity,
                cfg.timeChangeToleranceSeconds,
                cfg.timeChangeBigJumpSeconds);
            m_dispatch.timeChange = m_timeChange.get();
            if (!cfg.enableSecurityLog) {
                std::fprintf(stderr,
                    "[edr] warning: time-change detector enabled but "
                    "enable_security_log=false; 4616 telemetry will be "
                    "unavailable\n");
            }
            std::fprintf(stderr, "[edr] time-change detector ready\n");
        }
        if (cfg.privilegedGroupEnable) {
            m_privilegedGroup = std::make_unique<PrivilegedGroupDetector>(
                cfg.privilegedGroupEnable,
                cfg.privilegedGroupWindowSeconds,
                cfg.privilegedGroupStateCapacity);
            m_dispatch.privilegedGroup = m_privilegedGroup.get();
            if (!cfg.enableSecurityLog) {
                std::fprintf(stderr,
                    "[edr] warning: privileged-group detector enabled but "
                    "enable_security_log=false; 4728/4732/4756 telemetry "
                    "will be unavailable\n");
            }
            std::fprintf(stderr,
                "[edr] privileged-group detector ready\n");
        }
        if (cfg.defenseEvasionEnable) {
            m_defenseEvasion = std::make_unique<DefenseEvasionDetector>(
                cfg.defenseEvasionEnable, cfg.defenseEvasionWindowSeconds,
                cfg.defenseEvasionStateCapacity,
                cfg.defenseEvasionMinTechniques,
                cfg.defenseEvasionDedupSeconds);
            m_dispatch.defenseEvasion = m_defenseEvasion.get();
            std::fprintf(stderr, "[edr] defense evasion detector ready\n");
        }
        if (cfg.discoveryReconEnable) {
            m_discoveryRecon = std::make_unique<DiscoveryReconDetector>(
                cfg.discoveryReconEnable, cfg.discoveryReconWindowSeconds,
                cfg.discoveryReconStateCapacity,
                cfg.discoveryReconMinTechniques,
                cfg.discoveryReconDedupSeconds);
            m_dispatch.discoveryRecon = m_discoveryRecon.get();
            std::fprintf(stderr, "[edr] discovery recon detector ready\n");
        }
        if (cfg.rdpChainEnable) {
            m_rdpChain = std::make_unique<RdpChainDetector>(
                cfg.rdpChainEnable, cfg.rdpChainWindowSeconds,
                cfg.rdpChainStateCapacity, cfg.rdpChainMinDistinctSources);
            m_dispatch.rdpChain = m_rdpChain.get();
            std::fprintf(stderr, "[edr] rdp chain detector ready\n");
        }
        if (cfg.uacBypassEnable) {
            m_uacBypass = std::make_unique<UacBypassDetector>(
                cfg.uacBypassEnable, cfg.uacBypassWindowSeconds,
                cfg.uacBypassStateCapacity, cfg.uacBypassMinDistinctKeys);
            m_dispatch.uacBypass = m_uacBypass.get();
            std::fprintf(stderr, "[edr] uac bypass chain detector ready\n");
        }
        if (cfg.wmiPersistenceEnable) {
            m_wmiPersistence = std::make_unique<WmiPersistenceDetector>(
                cfg.wmiPersistenceEnable, cfg.wmiPersistenceWindowSeconds,
                cfg.wmiPersistenceStateCapacity, cfg.wmiPersistenceMinMatches);
            m_dispatch.wmiPersistence = m_wmiPersistence.get();
            std::fprintf(stderr, "[edr] wmi persistence detector ready\n");
        }
        if (cfg.ransomPrecursorEnable) {
            m_ransomPrecursor = std::make_unique<RansomPrecursorDetector>(
                cfg.ransomPrecursorEnable, cfg.ransomPrecursorWindowSeconds,
                cfg.ransomPrecursorStateCapacity,
                cfg.ransomPrecursorMinTechniques,
                cfg.ransomPrecursorDedupSeconds);
            m_dispatch.ransomPrecursor = m_ransomPrecursor.get();
            std::fprintf(stderr, "[edr] ransom precursor detector ready\n");
        }
        if (cfg.memoryScannerEnable) {
            m_memoryScanner = std::make_unique<MemoryScannerDetector>(
                cfg.memoryScannerEnable, cfg.memoryScannerMinScore,
                cfg.memoryScannerDedupWindowSeconds,
                cfg.memoryScannerStateCapacity);
            m_dispatch.memoryScanner = m_memoryScanner.get();
            std::fprintf(stderr, "[edr] memory scanner detector ready\n");
        }
        if (cfg.driverLoadEnable) {
            m_driverLoad = std::make_unique<DriverLoadDetector>(
                cfg.driverLoadEnable, cfg.driverLoadMinScore,
                cfg.driverLoadDedupWindowSeconds,
                cfg.driverLoadStateCapacity);
            m_dispatch.driverLoad = m_driverLoad.get();
            std::fprintf(stderr, "[edr] driver load detector ready\n");
        }
        if (cfg.canaryEnable) {
            m_canary = std::make_unique<CanaryDetector>(
                cfg.canaryEnable, cfg.canaryDedupWindowSeconds,
                cfg.canaryStateCapacity);
            m_dispatch.canary = m_canary.get();
            std::fprintf(stderr, "[edr] canary detector ready\n");
        }
        if (cfg.hookPersistenceEnable) {
            m_hookPersist = std::make_unique<HookPersistenceDetector>(
                cfg.hookPersistenceEnable, cfg.hookPersistenceMinScore,
                cfg.hookPersistenceDedupWindowSeconds,
                cfg.hookPersistenceStateCapacity);
            m_dispatch.hookPersist = m_hookPersist.get();
            std::fprintf(stderr, "[edr] hook persistence detector ready\n");
        }
        if (cfg.taskAbuseEnable) {
            TaskAbuseDetector::Settings settings;
            settings.enabled = true;
            settings.minScore = cfg.taskAbuseMinScore;
            settings.dedupWindowSeconds =
                cfg.taskAbuseDedupWindowSeconds;
            settings.stateCapacity = cfg.taskAbuseStateCapacity;
            settings.deleteBurstThreshold =
                cfg.taskAbuseDeleteBurstThreshold;
            settings.deleteBurstWindowSeconds =
                cfg.taskAbuseDeleteBurstWindowSeconds;
            m_taskAbuse = std::make_unique<TaskAbuseDetector>(settings);
            m_dispatch.taskAbuse = m_taskAbuse.get();
            std::fprintf(stderr, "[edr] task abuse detector ready\n");
        }
        if (cfg.masqueradeEnable) {
            m_masquerade = std::make_unique<MasqueradeDetector>(
                cfg.masqueradeEnable, cfg.masqueradeMinScore,
                cfg.masqueradeDedupWindowSeconds,
                cfg.masqueradeStateCapacity);
            m_dispatch.masquerade = m_masquerade.get();
            std::fprintf(stderr, "[edr] masquerade detector ready\n");
        }
        if (cfg.ppidSpoofEnable) {
            m_ppidSpoof = std::make_unique<PpidSpoofDetector>(
                cfg.ppidSpoofEnable, cfg.ppidSpoofMinScore,
                cfg.ppidSpoofDedupWindowSeconds,
                cfg.ppidSpoofStateCapacity);
            m_dispatch.ppidSpoof = m_ppidSpoof.get();
            std::fprintf(stderr, "[edr] ppid spoof detector ready\n");
        }
        if (cfg.netDiscoveryEnable) {
            m_netDiscovery = std::make_unique<NetDiscoveryDetector>(
                cfg.netDiscoveryEnable, cfg.netDiscoveryMinScore,
                cfg.netDiscoveryWindowSeconds,
                cfg.netDiscoveryBurstThreshold,
                cfg.netDiscoveryDedupWindowSeconds,
                cfg.netDiscoveryStateCapacity);
            m_dispatch.netDiscovery = m_netDiscovery.get();
            std::fprintf(stderr, "[edr] net discovery detector ready\n");
        }
        if (cfg.hostProfileEnable) {
            m_hostProfile = std::make_unique<HostProfileDetector>(
                cfg.hostProfileEnable, cfg.hostProfileMinScore,
                cfg.hostProfileWindowSeconds, cfg.hostProfileMinCategories,
                cfg.hostProfileDedupWindowSeconds,
                cfg.hostProfileStateCapacity);
            m_dispatch.hostProfile = m_hostProfile.get();
            std::fprintf(stderr,
                         "[edr] host profile detector ready "
                         "(min_categories=%u)\n",
                         cfg.hostProfileMinCategories);
        }
        if (cfg.privateKeyEnable) {
            m_privateKey = std::make_unique<PrivateKeyDetector>(
                cfg.privateKeyEnable, cfg.privateKeyMinScore,
                cfg.privateKeyDedupWindowSeconds,
                cfg.privateKeyStateCapacity);
            m_dispatch.privateKey = m_privateKey.get();
            std::fprintf(stderr, "[edr] private key detector ready\n");
        }
        if (cfg.accessibilityHijackEnable) {
            m_accessibilityHijack = std::make_unique<AccessibilityHijackDetector>(
                cfg.accessibilityHijackEnable,
                cfg.accessibilityHijackMinScore);
            m_dispatch.accessibilityHijack = m_accessibilityHijack.get();
            std::fprintf(stderr, "[edr] accessibility hijack detector ready\n");
        }
        if (cfg.aclAbuseEnable) {
            m_aclAbuse = std::make_unique<AclAbuseDetector>(
                cfg.aclAbuseEnable, cfg.aclAbuseMinScore,
                cfg.aclAbuseDedupWindowSeconds,
                cfg.aclAbuseStateCapacity);
            m_dispatch.aclAbuse = m_aclAbuse.get();
            std::fprintf(stderr, "[edr] acl abuse detector ready\n");
        }
        if (cfg.amsiBypassEnable) {
            m_amsiBypass = std::make_unique<AmsiBypassDetector>(
                cfg.amsiBypassEnable, cfg.amsiBypassMinScore,
                cfg.amsiBypassDedupWindowSeconds,
                cfg.amsiBypassStateCapacity);
            m_dispatch.amsiBypass = m_amsiBypass.get();
            std::fprintf(stderr, "[edr] amsi bypass detector ready\n");
        }
        if (cfg.appInitDllEnable) {
            m_appInitDll = std::make_unique<AppinitDllDetector>(
                cfg.appInitDllEnable, cfg.appInitDllMinScore,
                cfg.appInitDllDedupWindowSeconds,
                cfg.appInitDllStateCapacity);
            m_dispatch.appInitDll = m_appInitDll.get();
            std::fprintf(stderr, "[edr] appinit dll detector ready\n");
        }
        if (cfg.asRepRoastEnable) {
            m_asRepRoast = std::make_unique<AsRepRoastDetector>(
                cfg.asRepRoastEnable, cfg.asRepRoastWindowSeconds,
                cfg.asRepRoastStateCapacity, cfg.asRepRoastDedupSeconds);
            m_dispatch.asRepRoast = m_asRepRoast.get();
            std::fprintf(stderr, "[edr] as-rep roast detector ready\n");
        }
        if (cfg.bootProviderEnable) {
            m_bootProvider = std::make_unique<BootProviderPersistDetector>(
                cfg.bootProviderEnable, cfg.bootProviderMinScore,
                cfg.bootProviderDedupWindowSeconds,
                cfg.bootProviderStateCapacity);
            m_dispatch.bootProvider = m_bootProvider.get();
            std::fprintf(stderr, "[edr] boot provider detector ready\n");
        }
        if (cfg.certAbuseEnable) {
            m_certAbuse = std::make_unique<CertAbuseDetector>(
                cfg.certAbuseEnable, cfg.certAbuseMinScore,
                cfg.certAbuseDedupWindowSeconds,
                cfg.certAbuseStateCapacity);
            m_dispatch.certAbuse = m_certAbuse.get();
            std::fprintf(stderr, "[edr] cert abuse detector ready\n");
        }
        if (cfg.corProfilerEnable) {
            m_corProfiler = std::make_unique<CorProfilerHijackDetector>(
                cfg.corProfilerEnable, cfg.corProfilerMinScore,
                cfg.corProfilerDedupWindowSeconds,
                cfg.corProfilerStateCapacity);
            m_dispatch.corProfiler = m_corProfiler.get();
            std::fprintf(stderr, "[edr] cor profiler hijack detector ready\n");
        }
        if (cfg.credFileHuntEnable) {
            m_credFileHunt = std::make_unique<CredentialFileHuntDetector>(
                cfg.credFileHuntEnable, cfg.credFileHuntMinScore,
                cfg.credFileHuntDedupWindowSeconds,
                cfg.credFileHuntStateCapacity);
            m_dispatch.credFileHunt = m_credFileHunt.get();
            std::fprintf(stderr, "[edr] cred file hunt detector ready\n");
        }
        if (cfg.dcsyncEnable) {
            m_dcsync = std::make_unique<DcsyncDetector>(
                cfg.dcsyncEnable, cfg.dcsyncMinScore,
                cfg.dcsyncDedupWindowSeconds,
                cfg.dcsyncStateCapacity);
            m_dispatch.dcsync = m_dcsync.get();
            std::fprintf(stderr, "[edr] dcsync detector ready\n");
        }
        if (cfg.devUtilProxyEnable) {
            m_devUtilProxy = std::make_unique<DevUtilProxyDetector>(
                cfg.devUtilProxyEnable, cfg.devUtilProxyMinScore,
                cfg.devUtilProxyDedupWindowSeconds,
                cfg.devUtilProxyStateCapacity);
            m_dispatch.devUtilProxy = m_devUtilProxy.get();
            std::fprintf(stderr, "[edr] dev util proxy detector ready\n");
        }
        if (cfg.diskWipeEnable) {
            m_diskWipe = std::make_unique<DiskWipeDetector>(
                cfg.diskWipeEnable, cfg.diskWipeMinScore,
                cfg.diskWipeDedupWindowSeconds,
                cfg.diskWipeStateCapacity);
            m_dispatch.diskWipe = m_diskWipe.get();
            std::fprintf(stderr, "[edr] disk wipe detector ready\n");
        }
        if (cfg.avTamperEnable) {
            m_avTamper = std::make_unique<AvTamperDetector>(
                cfg.avTamperEnable, cfg.avTamperMinScore,
                cfg.avTamperDedupWindowSeconds,
                cfg.avTamperStateCapacity);
            m_dispatch.avTamper = m_avTamper.get();
            std::fprintf(stderr, "[edr] av tamper detector ready\n");
        }
        if (cfg.timestompEnable) {
            m_timestomp = std::make_unique<TimestompDetector>(
                cfg.timestompEnable, cfg.timestompMinScore,
                cfg.timestompDedupWindowSeconds,
                cfg.timestompStateCapacity);
            m_dispatch.timestomp = m_timestomp.get();
            std::fprintf(stderr, "[edr] timestomp detector ready\n");
        }
        if (cfg.obfuscationEnable) {
            m_obfuscation = std::make_unique<ObfuscationDetector>(
                cfg.obfuscationEnable, cfg.obfuscationMinScore,
                cfg.obfuscationDedupWindowSeconds,
                cfg.obfuscationStateCapacity);
            m_dispatch.obfuscation = m_obfuscation.get();
            std::fprintf(stderr, "[edr] obfuscation detector ready\n");
        }
        if (cfg.regModifyEnable) {
            m_regModify = std::make_unique<RegModifyDetector>(
                cfg.regModifyEnable, cfg.regModifyMinScore,
                cfg.regModifyDedupWindowSeconds, cfg.regModifyStateCapacity);
            m_dispatch.regModify = m_regModify.get();
            std::fprintf(stderr, "[edr] reg modify detector ready\n");
        }
        if (cfg.wmiExecEnable) {
            m_wmiExec = std::make_unique<WmiExecDetector>(
                cfg.wmiExecEnable, cfg.wmiExecMinScore,
                cfg.wmiExecDedupWindowSeconds, cfg.wmiExecStateCapacity);
            m_dispatch.wmiExec = m_wmiExec.get();
            std::fprintf(stderr, "[edr] wmi exec detector ready\n");
        }
        if (cfg.localCollectEnable) {
            m_localCollect = std::make_unique<LocalCollectDetector>(
                cfg.localCollectEnable, cfg.localCollectMinScore,
                cfg.localCollectDedupWindowSeconds,
                cfg.localCollectStateCapacity);
            m_dispatch.localCollect = m_localCollect.get();
            std::fprintf(stderr, "[edr] local collect detector ready\n");
        }
        if (cfg.lateralTransferEnable) {
            m_lateralTransfer = std::make_unique<LateralTransferDetector>(
                cfg.lateralTransferEnable, cfg.lateralTransferMinScore,
                cfg.lateralTransferDedupWindowSeconds,
                cfg.lateralTransferStateCapacity);
            m_dispatch.lateralTransfer = m_lateralTransfer.get();
            std::fprintf(stderr, "[edr] lateral transfer detector ready\n");
        }
        if (cfg.threatIntelEnable) {
            m_threatIntel = std::make_unique<ThreatIntelDetector>(
                cfg.threatIntelEnable, cfg.threatIntelMinScore,
                cfg.threatIntelDedupWindowSeconds,
                cfg.threatIntelStateCapacity,
                cfg.threatIntelReloadPollSeconds);
            std::string intelError;
            if (m_threatIntel->LoadIndicators(cfg.threatIntelFeedPath,
                                              intelError)) {
                std::fprintf(stderr,
                    "[edr] threat intel detector ready (%lu indicators from %s)\n",
                    static_cast<unsigned long>(m_threatIntel->IndicatorCount()),
                    cfg.threatIntelFeedPath.c_str());
                m_dispatch.threatIntel = m_threatIntel.get();
            } else {
                /* Operators enable this for the coverage, so a broken feed
                 * must be loud rather than a silent no-op. */
                std::fprintf(stderr,
                    "[edr] threat intel feed unavailable (%s): %s; %s\n",
                    cfg.threatIntelFeedPath.c_str(), intelError.c_str(),
                    cfg.threatIntelReloadPollSeconds != 0
                        ? "polling will retry" : "detector disabled");
                if (cfg.threatIntelReloadPollSeconds != 0)
                    m_dispatch.threatIntel = m_threatIntel.get();
                else
                    m_threatIntel.reset();
            }
        }
        if (cfg.lateralChainEnable) {
            m_lateralChain = std::make_unique<LateralChainDetector>(
                cfg.lateralChainEnable, cfg.lateralChainMinScore,
                cfg.lateralChainWindowSeconds,
                cfg.lateralChainDedupWindowSeconds,
                cfg.lateralChainStateCapacity);
            m_dispatch.lateralChain = m_lateralChain.get();
            std::fprintf(stderr, "[edr] lateral chain detector ready\n");
        }
        if (cfg.correlationEnable) {
            try {
                m_correlation = std::make_unique<CorrelationEngine>(
                    cfg.correlationEnable, cfg.correlationWindowSeconds,
                    cfg.correlationStateCapacity,
                    cfg.correlationMinAlertsToClose);
            } catch (const std::exception& error) {
                std::fprintf(stderr, "[edr] correlation unavailable: %s; "
                                     "detection continues\n", error.what());
                m_correlation.reset();
            }
        }
        if (cfg.correlationEnable && m_correlation) {
            /* Republish crossed campaign bands onto the bus so a rule can
             * alert on the kill chain as one campaign (EDR-443). Without this
             * the correlator's score/stage totals only ever reached stderr. */
            m_rollup = std::make_unique<CorrelationRollup>(
                cfg.correlationRollupEnable, cfg.correlationRollupMinStageCount,
                cfg.correlationRollupMinScore, cfg.correlationRollupStateCapacity);
            m_rollup->SetBus(&m_bus);

            /* Durable incident sink. Incidents are the kill-chain roll-up an
             * analyst actually wants, so losing them at process exit would
             * waste the correlator's whole output. A write failure is loud but
             * never disables detection. */
            m_incidentStore = std::make_unique<IncidentStore>(
                cfg.correlationIncidentPath, cfg.redact,
                cfg.correlationMaxRecords);
            const bool storeOpen = m_incidentStore->Open();
            if (m_incidentStore->Enabled() && !storeOpen) {
                std::fprintf(stderr,
                    "[edr] WARNING: could not open incident store '%s'; "
                    "incidents will not be persisted\n",
                    cfg.correlationIncidentPath.c_str());
            }

            /* The callback runs on the EventBus consumer thread, so it must
             * stay cheap: serialize and append, no blocking work. */
            IncidentStore* store = m_incidentStore.get();
            m_correlation->SetIncidentCallback([store](const Incident& incident) {
                std::fprintf(stderr,
                    "[edr] incident %s closed: severity=%s score=%d alerts=%u stages=%zu\n",
                    incident.id.c_str(), incident.severity.c_str(),
                    incident.score,
                    static_cast<unsigned>(incident.alertCount),
                    incident.stages.size());
                if (store != nullptr) {
                    store->OnIncidentClosed(incident);
                }
            });
            m_correlation->SetIncidentOpenedCallback([store](const Incident& incident) {
                if (store != nullptr) {
                    store->OnIncidentOpened(incident);
                }
            });
            m_dispatch.correlation = m_correlation.get();
            std::fprintf(stderr, "[edr] correlation engine ready "
                                 "(window=%us, min_alerts=%u, rollup=%s, "
                                 "rollup_band=%u tactics/%u score)\n",
                         cfg.correlationWindowSeconds,
                         cfg.correlationMinAlertsToClose,
                         m_rollup && cfg.correlationRollupEnable ? "on" : "off",
                         cfg.correlationRollupMinStageCount,
                         cfg.correlationRollupMinScore);
            if (m_incidentStore && storeOpen) {
                std::fprintf(stderr,
                    "[edr] incident store armed (path=%s, max_records=%u)\n",
                    cfg.correlationIncidentPath.c_str(),
                    static_cast<unsigned>(cfg.correlationMaxRecords));
            }
        }
        if (cfg.lsassDumpEnable) {
            m_lsassDump = std::make_unique<LsassDumpDetector>(
                cfg.lsassDumpEnable, cfg.lsassDumpMinScore,
                cfg.lsassDumpDedupWindowSeconds,
                cfg.lsassDumpStateCapacity);
            m_dispatch.lsassDump = m_lsassDump.get();
            std::fprintf(stderr, "[edr] lsass dump detector ready\n");
        }
        if (cfg.filelessEnable) {
            m_fileless = std::make_unique<FilelessAttackDetector>(
                cfg.filelessEnable, cfg.filelessMinScore,
                cfg.filelessDedupWindowSeconds,
                cfg.filelessStateCapacity);
            m_dispatch.fileless = m_fileless.get();
            std::fprintf(stderr, "[edr] fileless attack detector ready\n");
        }
        if (cfg.apiHookEnable) {
            m_apiHook = std::make_unique<ApiHookDetector>(
                cfg.apiHookEnable, cfg.apiHookMinScore,
                cfg.apiHookDedupWindowSeconds,
                cfg.apiHookStateCapacity);
            m_dispatch.apiHook = m_apiHook.get();
            std::fprintf(stderr, "[edr] api hook detector ready\n");
        }
        if (cfg.remoteAccessEnable) {
            m_remoteAccess = std::make_unique<RemoteAccessDetector>(
                cfg.remoteAccessEnable, cfg.remoteAccessWindowSeconds,
                cfg.remoteAccessStateCapacity);
            m_dispatch.remoteAccess = m_remoteAccess.get();
           std::fprintf(stderr, "[edr] remote access detector ready\n");
       }
        if (cfg.credentialDumpEnable) {
            m_credDump = std::make_unique<CredentialDumpingDetector>(
                cfg.credentialDumpEnable, cfg.credentialDumpWindowSeconds,
                cfg.credentialDumpStateCapacity);
            m_dispatch.credDump = m_credDump.get();
            std::fprintf(stderr, "[edr] credential dumping detector ready\n");
        }
        if (cfg.dataExfilEnable) {
            m_dataExfil = std::make_unique<DataExfiltrationDetector>(
                cfg.dataExfilEnable, cfg.dataExfilWindowSeconds,
                cfg.dataExfilStateCapacity, cfg.dataExfilDnsTunnelThreshold);
            m_dispatch.dataExfil = m_dataExfil.get();
            std::fprintf(stderr, "[edr] data exfiltration detector ready\n");
        }
        if (cfg.privEscEnable) {
            m_privEsc = std::make_unique<PrivilegeEscalationDetector>(
                cfg.privEscEnable, cfg.privEscWindowSeconds,
                cfg.privEscStateCapacity);
            m_dispatch.privEsc = m_privEsc.get();
            std::fprintf(stderr, "[edr] privilege escalation detector ready\n");
        }
        if (cfg.ntlmRelayEnable) {
            m_ntlmRelay = std::make_unique<NtlmRelayDetector>(
                cfg.ntlmRelayEnable, cfg.ntlmRelayWindowSeconds,
                cfg.ntlmRelayStateCapacity, cfg.ntlmRelayMinEvents);
            m_dispatch.ntlmRelay = m_ntlmRelay.get();
            std::fprintf(stderr, "[edr] ntlm relay detector ready\n");
        }
        if (cfg.browserTheftEnable) {
            m_browserTheft = std::make_unique<BrowserTheftDetector>(
                cfg.browserTheftEnable, cfg.browserTheftWindowSeconds,
                cfg.browserTheftStateCapacity);
            m_dispatch.browserTheft = m_browserTheft.get();
            std::fprintf(stderr, "[edr] browser theft detector ready\n");
        }
        if (cfg.browserExtensionEnable) {
            m_browserExtension = std::make_unique<BrowserExtensionDetector>(
                cfg.browserExtensionEnable, cfg.browserExtensionMinScore,
                cfg.browserExtensionDedupWindowSeconds,
                cfg.browserExtensionStateCapacity,
                cfg.browserExtensionAllowlist);
            m_dispatch.browserExtension = m_browserExtension.get();
            std::fprintf(stderr,
                "[edr] browser extension detector ready\n");
        }
        if (cfg.archiveStagingEnable) {
            m_archiveStaging = std::make_unique<ArchiveStagingDetector>(
                cfg.archiveStagingEnable, cfg.archiveStagingWindowSeconds,
                cfg.archiveStagingStateCapacity);
            m_dispatch.archiveStaging = m_archiveStaging.get();
            std::fprintf(stderr, "[edr] archive staging detector ready\n");
        }
        if (cfg.bitsAbuseEnable) {
            m_bitsAbuse = std::make_unique<BitsAbuseDetector>(
                cfg.bitsAbuseEnable, cfg.bitsAbuseWindowSeconds,
                cfg.bitsAbuseStateCapacity);
            m_dispatch.bitsAbuse = m_bitsAbuse.get();
            std::fprintf(stderr, "[edr] bits abuse detector ready\n");
        }
        if (cfg.dohAbuseEnable) {
            m_dohAbuse = std::make_unique<DohAbuseDetector>(
                cfg.dohAbuseEnable, cfg.dohAbuseWindowSeconds,
                cfg.dohAbuseStateCapacity, cfg.dohAbuseMinRepeatCount);
            m_dispatch.dohAbuse = m_dohAbuse.get();
            std::fprintf(stderr, "[edr] doh abuse detector ready\n");
        }
        if (cfg.svcInstallEnable) {
            m_svcInstall = std::make_unique<ServiceInstallDetector>(
                cfg.svcInstallEnable);
            m_dispatch.svcInstall = m_svcInstall.get();
            std::fprintf(stderr, "[edr] service install detector ready\n");
        }
        if (cfg.shadowCopyEnable) {
            m_shadowCopy = std::make_unique<ShadowCopyDetector>(
                cfg.shadowCopyEnable, cfg.shadowCopyMinScore,
                cfg.shadowCopyDedupWindowSeconds,
                cfg.shadowCopyStateCapacity);
            m_dispatch.shadowCopy = m_shadowCopy.get();
            std::fprintf(stderr, "[edr] shadow copy detector ready\n");
        }
        if (cfg.persistBurstEnable) {
            m_persistBurst = std::make_unique<PersistenceBurstDetector>(
                cfg.persistBurstEnable, cfg.persistBurstWindowSeconds,
                cfg.persistBurstStateCapacity, cfg.persistBurstMinScore,
                cfg.persistBurstDedupSeconds);
            m_dispatch.persistBurst = m_persistBurst.get();
            std::fprintf(stderr, "[edr] persistence burst detector ready\n");
        }
        if (cfg.mailboxRuleEnable) {
            m_mailboxRule = std::make_unique<MailboxRuleDetector>(
                cfg.mailboxRuleEnable, cfg.mailboxRuleMinScore,
                cfg.mailboxRuleDedupWindowSeconds,
                cfg.mailboxRuleStateCapacity);
            m_dispatch.mailboxRule = m_mailboxRule.get();
            std::fprintf(stderr, "[edr] mailbox rule detector ready\n");
        }
        if (cfg.mailboxDelegateEnable) {
            m_mailboxDelegate = std::make_unique<MailboxDelegateDetector>(
                cfg.mailboxDelegateEnable, cfg.mailboxDelegateMinScore,
                cfg.mailboxDelegateDedupWindowSeconds,
                cfg.mailboxDelegateStateCapacity);
            m_dispatch.mailboxDelegate = m_mailboxDelegate.get();
            std::fprintf(stderr, "[edr] mailbox delegate detector ready\n");
        }
        if (cfg.llmnrPoisonEnable) {
            m_llmnrPoison = std::make_unique<LlmnrPoisonDetector>(
                cfg.llmnrPoisonEnable, cfg.llmnrPoisonMinScore,
                cfg.llmnrPoisonDedupWindowSeconds,
                cfg.llmnrPoisonStateCapacity);
            m_dispatch.llmnrPoison = m_llmnrPoison.get();
            std::fprintf(stderr, "[edr] llmnr poison detector ready\n");
        }
        if (cfg.netProviderPersistEnable) {
            m_netProviderPersist = std::make_unique<NetProviderPersistDetector>(
                cfg.netProviderPersistEnable, cfg.netProviderPersistMinScore,
                cfg.netProviderPersistDedupWindowSeconds,
                cfg.netProviderPersistStateCapacity);
            m_dispatch.netProviderPersist = m_netProviderPersist.get();
            std::fprintf(stderr, "[edr] netprovider persist detector ready\n");
        }
        if (cfg.passwordVaultEnable) {
            m_passwordVault = std::make_unique<PasswordVaultDetector>(
                cfg.passwordVaultEnable, cfg.passwordVaultMinScore,
                cfg.passwordVaultDedupWindowSeconds,
                cfg.passwordVaultStateCapacity);
            m_dispatch.passwordVault = m_passwordVault.get();
            std::fprintf(stderr, "[edr] password vault detector ready\n");
        }
        if (cfg.arpPoisonEnable) {
            m_arpPoison = std::make_unique<ArpPoisonDetector>(
                cfg.arpPoisonEnable, cfg.arpPoisonMinScore,
                cfg.arpPoisonDedupWindowSeconds,
                cfg.arpPoisonStateCapacity);
            m_dispatch.arpPoison = m_arpPoison.get();
            std::fprintf(stderr, "[edr] arp poison detector ready\n");
        }
        if (cfg.cloudMetadataEnable) {
            m_cloudMetadata = std::make_unique<CloudMetadataDetector>(
                cfg.cloudMetadataEnable, cfg.cloudMetadataMinScore,
                cfg.cloudMetadataDedupWindowSeconds,
                cfg.cloudMetadataStateCapacity);
            m_dispatch.cloudMetadata = m_cloudMetadata.get();
            std::fprintf(stderr, "[edr] cloud metadata detector ready\n");
        }
        if (cfg.gppPasswordEnable) {
            m_gppPassword = std::make_unique<GppPasswordDetector>(
                cfg.gppPasswordEnable, cfg.gppPasswordMinScore,
                cfg.gppPasswordDedupWindowSeconds,
                cfg.gppPasswordStateCapacity);
            m_dispatch.gppPassword = m_gppPassword.get();
            std::fprintf(stderr, "[edr] gpp password detector ready\n");
        }
        if (cfg.controlPanelProxyEnable) {
            m_controlPanelProxy =
                std::make_unique<ControlPanelProxyDetector>(
                    cfg.controlPanelProxyEnable,
                    cfg.controlPanelProxyMinScore,
                    cfg.controlPanelProxyDedupWindowSeconds,
                    cfg.controlPanelProxyStateCapacity);
            m_dispatch.controlPanelProxy = m_controlPanelProxy.get();
            std::fprintf(stderr,
                         "[edr] control panel proxy detector ready\n");
        }
        if (cfg.hiddenUserAccountEnable) {
            m_hiddenUserAccount =
                std::make_unique<HiddenUserAccountDetector>(
                    cfg.hiddenUserAccountEnable,
                    cfg.hiddenUserAccountMinScore,
                    cfg.hiddenUserAccountDedupWindowSeconds,
                    cfg.hiddenUserAccountStateCapacity);
            m_dispatch.hiddenUserAccount = m_hiddenUserAccount.get();
            std::fprintf(stderr,
                         "[edr] hidden user account detector ready\n");
        }
        if (cfg.passwordPolicyDiscoveryEnable) {
            m_passwordPolicyDiscovery =
                std::make_unique<PasswordPolicyDiscoveryDetector>(
                    cfg.passwordPolicyDiscoveryEnable,
                    cfg.passwordPolicyDiscoveryMinScore,
                    cfg.passwordPolicyDiscoveryDedupWindowSeconds,
                    cfg.passwordPolicyDiscoveryStateCapacity);
            m_dispatch.passwordPolicyDiscovery =
                m_passwordPolicyDiscovery.get();
            std::fprintf(stderr,
                         "[edr] password policy discovery detector ready\n");
        }
        if (cfg.msiPackageInstallEnable) {
            m_msiPackageInstall = std::make_unique<MsiPackageInstallDetector>(
                cfg.msiPackageInstallEnable, cfg.msiPackageInstallMinScore,
                cfg.msiPackageInstallDedupWindowSeconds,
                cfg.msiPackageInstallStateCapacity);
            m_dispatch.msiPackageInstall = m_msiPackageInstall.get();
            std::fprintf(stderr, "[edr] msi package install detector ready\n");
        }
        if (cfg.logEnumerationEnable) {
            m_logEnumeration = std::make_unique<LogEnumerationDetector>(
                cfg.logEnumerationEnable, cfg.logEnumerationMinScore,
                cfg.logEnumerationDedupWindowSeconds,
                cfg.logEnumerationStateCapacity);
            m_dispatch.logEnumeration = m_logEnumeration.get();
            std::fprintf(stderr, "[edr] log enumeration detector ready\n");
        }
        if (cfg.cmstpBypassEnable) {
            m_cmstpBypass = std::make_unique<CmstpBypassDetector>(
                cfg.cmstpBypassEnable, cfg.cmstpBypassMinScore,
                cfg.cmstpBypassDedupWindowSeconds,
                cfg.cmstpBypassStateCapacity);
            m_dispatch.cmstpBypass = m_cmstpBypass.get();
            std::fprintf(stderr, "[edr] cmstp bypass detector ready\n");
        }
        if (cfg.fileAssocEnable) {
            m_fileAssoc = std::make_unique<FileAssocDetector>(
                cfg.fileAssocEnable, cfg.fileAssocMinScore,
                cfg.fileAssocDedupWindowSeconds,
                cfg.fileAssocStateCapacity);
            m_dispatch.fileAssoc = m_fileAssoc.get();
            std::fprintf(stderr, "[edr] file association detector ready\n");
        }
        if (cfg.hiddenWindowEnable) {
            m_hiddenWindow = std::make_unique<HiddenWindowDetector>(
                cfg.hiddenWindowEnable, cfg.hiddenWindowMinScore,
                cfg.hiddenWindowDedupWindowSeconds,
                cfg.hiddenWindowStateCapacity);
            m_dispatch.hiddenWindow = m_hiddenWindow.get();
            std::fprintf(stderr, "[edr] hidden window detector ready\n");
        }
        if (cfg.firewallRuleEnable) {
            m_firewallRule = std::make_unique<FirewallRuleDetector>();
            m_dispatch.firewallRule = m_firewallRule.get();
            std::fprintf(stderr, "[edr] firewall rule detector ready\n");
        }
        if (cfg.officePersistEnable) {
            m_officePersist = std::make_unique<OfficePersistDetector>(
                cfg.officePersistEnable, cfg.officePersistMinScore,
                cfg.officePersistDedupWindowSeconds,
                cfg.officePersistStateCapacity);
            m_dispatch.officePersist = m_officePersist.get();
            std::fprintf(stderr, "[edr] office persist detector ready\n");
        }
        if (cfg.shortcutPersistEnable) {
            m_shortcutPersist = std::make_unique<ShortcutPersistDetector>(
                cfg.shortcutPersistEnable, cfg.shortcutPersistMinScore,
                cfg.shortcutPersistDedupWindowSeconds,
                cfg.shortcutPersistStateCapacity);
            m_dispatch.shortcutPersist = m_shortcutPersist.get();
            std::fprintf(stderr, "[edr] shortcut persist detector ready\n");
        }
        if (cfg.indirectExecEnable) {
            m_indirectExec = std::make_unique<IndirectExecDetector>(
                cfg.indirectExecEnable, cfg.indirectExecMinScore,
                cfg.indirectExecDedupWindowSeconds,
                cfg.indirectExecStateCapacity);
            m_dispatch.indirectExec = m_indirectExec.get();
            std::fprintf(stderr, "[edr] indirect exec detector ready\n");
        }
        if (cfg.screensaverPersistEnable) {
            m_screensaverPersist = std::make_unique<ScreensaverPersistDetector>(
                cfg.screensaverPersistEnable, cfg.screensaverPersistMinScore,
                cfg.screensaverPersistDedupWindowSeconds,
                cfg.screensaverPersistStateCapacity);
            m_dispatch.screensaverPersist = m_screensaverPersist.get();
            std::fprintf(stderr, "[edr] screensaver persist detector ready\n");
        }
        if (cfg.svcPathAbuseEnable) {
            m_svcPathAbuse = std::make_unique<SvcPathAbuseDetector>(
                cfg.svcPathAbuseEnable, cfg.svcPathAbuseMinScore,
                cfg.svcPathAbuseDedupWindowSeconds,
                cfg.svcPathAbuseStateCapacity);
            m_dispatch.svcPathAbuse = m_svcPathAbuse.get();
            std::fprintf(stderr, "[edr] service path abuse detector ready\n");
        }
        if (cfg.serviceDllHijackEnable) {
            m_serviceDllHijack = std::make_unique<ServiceDllHijackDetector>(
                cfg.serviceDllHijackEnable, cfg.serviceDllHijackMinScore,
                cfg.serviceDllHijackDedupWindowSeconds,
                cfg.serviceDllHijackStateCapacity);
            m_dispatch.serviceDllHijack = m_serviceDllHijack.get();
            std::fprintf(stderr, "[edr] service dll hijack detector ready\n");
        }
        if (cfg.dllSearchOrderEnable) {
            m_dllSearchOrder = std::make_unique<DllSearchOrderDetector>(
                cfg.dllSearchOrderEnable, cfg.dllSearchOrderMinScore,
                cfg.dllSearchOrderDedupWindowSeconds,
                cfg.dllSearchOrderStateCapacity);
            m_dispatch.dllSearchOrder = m_dllSearchOrder.get();
            std::fprintf(stderr, "[edr] dll search order detector ready\n");
        }
        if (cfg.svcRecoveryEnable) {
            m_svcRecovery = std::make_unique<SvcRecoveryDetector>(
                cfg.svcRecoveryEnable, cfg.svcRecoveryMinScore,
                cfg.svcRecoveryDedupWindowSeconds,
                cfg.svcRecoveryStateCapacity);
            m_dispatch.svcRecovery = m_svcRecovery.get();
            std::fprintf(stderr, "[edr] service recovery detector ready\n");
        }
        if (cfg.comHijackEnable) {
            m_comHijack = std::make_unique<ComHijackDetector>(
                cfg.comHijackEnable, cfg.comHijackMinScore,
                cfg.comHijackDedupWindowSeconds,
                cfg.comHijackStateCapacity);
            m_dispatch.comHijack = m_comHijack.get();
            std::fprintf(stderr, "[edr] com hijack detector ready\n");
        }
        if (cfg.winlogonHijackEnable) {
            m_winlogonHijack = std::make_unique<WinlogonHijackDetector>(
                cfg.winlogonHijackEnable, cfg.winlogonHijackMinScore,
                cfg.winlogonHijackDedupWindowSeconds,
                cfg.winlogonHijackStateCapacity);
            m_dispatch.winlogonHijack = m_winlogonHijack.get();
            std::fprintf(stderr, "[edr] winlogon hijack detector ready\n");
        }
        if (cfg.mshtaAbuseEnable) {
            m_mshtaAbuse = std::make_unique<MshtaAbuseDetector>(
                cfg.mshtaAbuseEnable, cfg.mshtaAbuseMinScore,
                cfg.mshtaAbuseDedupWindowSeconds,
                cfg.mshtaAbuseStateCapacity);
            m_dispatch.mshtaAbuse = m_mshtaAbuse.get();
            std::fprintf(stderr, "[edr] mshta abuse detector ready\n");
        }
        if (cfg.dotnetProxyExecEnable) {
            m_dotnetProxyExec = std::make_unique<DotnetProxyExecDetector>(
                cfg.dotnetProxyExecEnable, cfg.dotnetProxyExecMinScore,
                cfg.dotnetProxyExecDedupWindowSeconds,
                cfg.dotnetProxyExecStateCapacity);
            m_dispatch.dotnetProxyExec = m_dotnetProxyExec.get();
            std::fprintf(stderr, "[edr] dotnet proxy exec detector ready\n");
        }
        if (cfg.wslAbuseEnable) {
            m_wslAbuse = std::make_unique<WslAbuseDetector>(
                cfg.wslAbuseEnable, cfg.wslAbuseMinScore,
                cfg.wslAbuseDedupWindowSeconds,
                cfg.wslAbuseStateCapacity);
            m_dispatch.wslAbuse = m_wslAbuse.get();
            std::fprintf(stderr, "[edr] wsl abuse detector ready\n");
        }
        if (cfg.msdtAbuseEnable) {
            m_msdtAbuse = std::make_unique<MsdtAbuseDetector>(
                cfg.msdtAbuseEnable, cfg.msdtAbuseMinScore,
                cfg.msdtAbuseDedupWindowSeconds,
                cfg.msdtAbuseStateCapacity);
            m_dispatch.msdtAbuse = m_msdtAbuse.get();
            std::fprintf(stderr, "[edr] msdt abuse detector ready\n");
        }
        if (cfg.softwareDiscoveryEnable) {
            m_softwareDiscovery = std::make_unique<SoftwareDiscoveryDetector>(
                cfg.softwareDiscoveryEnable, cfg.softwareDiscoveryMinScore,
                cfg.softwareDiscoveryWindowSeconds,
                cfg.softwareDiscoveryMinCategories,
                cfg.softwareDiscoveryDedupWindowSeconds,
                cfg.softwareDiscoveryStateCapacity);
            m_dispatch.softwareDiscovery = m_softwareDiscovery.get();
            std::fprintf(stderr, "[edr] software discovery detector ready\n");
        }
        if (cfg.netShareDiscoveryEnable) {
            m_netShareDiscovery = std::make_unique<NetShareDiscoveryDetector>(
                cfg.netShareDiscoveryEnable, cfg.netShareDiscoveryMinScore,
                cfg.netShareDiscoveryWindowSeconds,
                cfg.netShareDiscoveryMinCommands,
                cfg.netShareDiscoveryDedupWindowSeconds,
                cfg.netShareDiscoveryStateCapacity);
            m_dispatch.netShareDiscovery = m_netShareDiscovery.get();
            std::fprintf(stderr, "[edr] net share discovery detector ready\n");
        }
        if (cfg.nonstandardPortEgressEnable) {
            m_nonstandardPortEgress =
                std::make_unique<NonstandardPortEgressDetector>(
                    cfg.nonstandardPortEgressEnable,
                    cfg.nonstandardPortEgressMinScore,
                    cfg.nonstandardPortEgressWindowSeconds,
                    cfg.nonstandardPortEgressDedupWindowSeconds,
                    cfg.nonstandardPortEgressStateCapacity);
            m_dispatch.nonstandardPortEgress =
                m_nonstandardPortEgress.get();
            std::fprintf(stderr,
                         "[edr] nonstandard port egress detector ready\n");
        }
        if (cfg.isoMountEnable) {
            m_isoMount = std::make_unique<IsoMountDetector>(
                cfg.isoMountEnable, cfg.isoMountMinScore,
                cfg.isoMountDedupWindowSeconds,
                cfg.isoMountStateCapacity);
            m_dispatch.isoMount = m_isoMount.get();
            std::fprintf(stderr, "[edr] iso mount detector ready\n");
        }
        if (cfg.psProfileEnable) {
            m_psProfile = std::make_unique<PsProfileDetector>(
                cfg.psProfileEnable, cfg.psProfileMinScore,
                cfg.psProfileDedupWindowSeconds,
                cfg.psProfileStateCapacity);
            m_dispatch.psProfile = m_psProfile.get();
            std::fprintf(stderr, "[edr] ps profile detector ready\n");
        }
        if (cfg.downgradeAttackEnable) {
            m_downgradeAttack = std::make_unique<DowngradeAttackDetector>(
                cfg.downgradeAttackEnable, cfg.downgradeAttackMinScore,
                cfg.downgradeAttackDedupWindowSeconds,
                cfg.downgradeAttackStateCapacity);
            m_dispatch.downgradeAttack = m_downgradeAttack.get();
            std::fprintf(stderr, "[edr] downgrade attack detector ready\n");
        }
        if (cfg.dpapiAbuseEnable) {
            m_dpapiAbuse = std::make_unique<DpapiAbuseDetector>(
                cfg.dpapiAbuseEnable, cfg.dpapiAbuseMinScore,
                cfg.dpapiAbuseDedupWindowSeconds,
                cfg.dpapiAbuseStateCapacity);
            m_dispatch.dpapiAbuse = m_dpapiAbuse.get();
            std::fprintf(stderr, "[edr] dpapi abuse detector ready\n");
        }
        if (cfg.emailCollectionEnable) {
            m_emailCollection = std::make_unique<EmailCollectionDetector>(
                cfg.emailCollectionEnable, cfg.emailCollectionMinScore,
                cfg.emailCollectionDedupWindowSeconds,
                cfg.emailCollectionStateCapacity);
            m_dispatch.emailCollection = m_emailCollection.get();
            std::fprintf(stderr, "[edr] email collection detector ready\n");
        }
        if (cfg.etwScriptTamperEnable) {
            m_etwScriptTamper = std::make_unique<EtwScriptTamperDetector>(
                cfg.etwScriptTamperEnable, cfg.etwScriptTamperMinScore,
                cfg.etwScriptTamperDedupWindowSeconds,
                cfg.etwScriptTamperStateCapacity);
            m_dispatch.etwScriptTamper = m_etwScriptTamper.get();
            std::fprintf(stderr, "[edr] etw script tamper detector ready\n");
        }
        if (cfg.forcedAuthEnable) {
            m_forcedAuth = std::make_unique<ForcedAuthDetector>(
                cfg.forcedAuthEnable, cfg.forcedAuthMinScore,
                cfg.forcedAuthDedupWindowSeconds,
                cfg.forcedAuthStateCapacity);
            m_dispatch.forcedAuth = m_forcedAuth.get();
            std::fprintf(stderr, "[edr] forced auth detector ready\n");
        }
        if (cfg.goldenTicketEnable) {
            m_goldenTicket = std::make_unique<GoldenTicketDetector>(
                cfg.goldenTicketEnable, cfg.goldenTicketWindowSeconds,
                cfg.goldenTicketStateCapacity, cfg.goldenTicketMinRepeatCount);
            m_dispatch.goldenTicket = m_goldenTicket.get();
            std::fprintf(stderr, "[edr] golden ticket detector ready\n");
        }
        if (cfg.gpoAbuseEnable) {
            m_gpoAbuse = std::make_unique<GpoAbuseDetector>(
                cfg.gpoAbuseEnable, cfg.gpoAbuseMinScore,
                cfg.gpoAbuseDedupWindowSeconds,
                cfg.gpoAbuseStateCapacity);
            m_dispatch.gpoAbuse = m_gpoAbuse.get();
            std::fprintf(stderr, "[edr] gpo abuse detector ready\n");
        }
        if (cfg.hiddenArtifactsEnable) {
            m_hiddenArtifacts = std::make_unique<HiddenArtifactsDetector>(
                cfg.hiddenArtifactsEnable, cfg.hiddenArtifactsWindowSeconds,
                cfg.hiddenArtifactsStateCapacity);
            m_dispatch.hiddenArtifacts = m_hiddenArtifacts.get();
            std::fprintf(stderr, "[edr] hidden artifacts detector ready\n");
        }
        if (cfg.historyTamperEnable) {
            m_historyTamper = std::make_unique<HistoryTamperDetector>(
                cfg.historyTamperEnable, cfg.historyTamperMinScore,
                cfg.historyTamperDedupWindowSeconds,
                cfg.historyTamperStateCapacity);
            m_dispatch.historyTamper = m_historyTamper.get();
            std::fprintf(stderr, "[edr] history tamper detector ready\n");
        }
        if (cfg.hiveCopyEnable) {
            m_hiveCopy = std::make_unique<HiveCopyDetector>(
                cfg.hiveCopyEnable, cfg.hiveCopyMinScore,
                cfg.hiveCopyDedupWindowSeconds,
                cfg.hiveCopyStateCapacity);
            m_dispatch.hiveCopy = m_hiveCopy.get();
            std::fprintf(stderr, "[edr] hive copy detector ready\n");
        }
        if (cfg.hostsRedirectEnable) {
            m_hostsRedirect = std::make_unique<HostsRedirectDetector>(
                cfg.hostsRedirectEnable, cfg.hostsRedirectMinScore,
                cfg.hostsRedirectDedupWindowSeconds,
                cfg.hostsRedirectStateCapacity);
            m_dispatch.hostsRedirect = m_hostsRedirect.get();
            std::fprintf(stderr, "[edr] hosts redirect detector ready\n");
        }
        if (cfg.iisModuleEnable) {
            m_iisModule = std::make_unique<IisModuleDetector>(
                cfg.iisModuleEnable, cfg.iisModuleMinScore,
                cfg.iisModuleDedupWindowSeconds,
                cfg.iisModuleStateCapacity);
            m_dispatch.iisModule = m_iisModule.get();
            std::fprintf(stderr, "[edr] iis module detector ready\n");
        }
        if (cfg.inputSimulationEnable) {
            m_inputSimulation = std::make_unique<InputSimulationDetector>(
                cfg.inputSimulationEnable, cfg.inputSimulationWindowSeconds,
                cfg.inputSimulationStateCapacity, cfg.inputSimulationBurstThreshold);
            m_dispatch.inputSimulation = m_inputSimulation.get();
            std::fprintf(stderr, "[edr] input simulation detector ready\n");
        }
        if (cfg.logonScriptPersistEnable) {
            m_logonScriptPersist = std::make_unique<LogonScriptPersistDetector>(
                cfg.logonScriptPersistEnable, cfg.logonScriptPersistMinScore,
                cfg.logonScriptPersistDedupWindowSeconds,
                cfg.logonScriptPersistStateCapacity);
            m_dispatch.logonScriptPersist = m_logonScriptPersist.get();
            std::fprintf(stderr, "[edr] logon script persist detector ready\n");
        }
        if (cfg.lsaPackageEnable) {
            m_lsaPackage = std::make_unique<LsaPackageDetector>(
                cfg.lsaPackageEnable, cfg.lsaPackageMinScore,
                cfg.lsaPackageDedupWindowSeconds,
                cfg.lsaPackageStateCapacity);
            m_dispatch.lsaPackage = m_lsaPackage.get();
            std::fprintf(stderr, "[edr] lsa package detector ready\n");
        }
        if (cfg.motwBypassEnable) {
            m_motwBypass = std::make_unique<MotwBypassDetector>(
                cfg.motwBypassEnable, cfg.motwBypassMinScore,
                cfg.motwBypassDedupWindowSeconds,
                cfg.motwBypassStateCapacity);
            m_dispatch.motwBypass = m_motwBypass.get();
            std::fprintf(stderr, "[edr] motw bypass detector ready\n");
        }
        if (cfg.netshHelperEnable) {
            m_netshHelper = std::make_unique<NetshHelperDetector>(
                cfg.netshHelperEnable, cfg.netshHelperMinScore,
                cfg.netshHelperDedupWindowSeconds,
                cfg.netshHelperStateCapacity);
            m_dispatch.netshHelper = m_netshHelper.get();
            std::fprintf(stderr, "[edr] netsh helper detector ready\n");
        }
        if (cfg.networkSniffingEnable) {
            m_networkSniffing = std::make_unique<NetworkSniffingDetector>(
                cfg.networkSniffingEnable, cfg.networkSniffingMinScore,
                cfg.networkSniffingDedupWindowSeconds,
                cfg.networkSniffingStateCapacity);
            m_dispatch.networkSniffing = m_networkSniffing.get();
            std::fprintf(stderr, "[edr] network sniffing detector ready\n");
        }
        if (cfg.ntdsDitEnable) {
            m_ntdsDit = std::make_unique<NtdsDitDetector>(
                cfg.ntdsDitEnable, cfg.ntdsDitMinScore,
                cfg.ntdsDitDedupWindowSeconds,
                cfg.ntdsDitStateCapacity);
            m_dispatch.ntdsDit = m_ntdsDit.get();
            std::fprintf(stderr, "[edr] ntds dit detector ready\n");
        }
        if (cfg.passTheHashEnable) {
            m_passTheHash = std::make_unique<PassTheHashDetector>(
                cfg.passTheHashEnable, cfg.passTheHashMinScore,
                cfg.passTheHashDedupWindowSeconds,
                cfg.passTheHashStateCapacity);
            m_dispatch.passTheHash = m_passTheHash.get();
            std::fprintf(stderr, "[edr] pass the hash detector ready\n");
        }
        if (cfg.passwordCrackingEnable) {
            m_passwordCracking = std::make_unique<PasswordCrackingDetector>(
                cfg.passwordCrackingEnable, cfg.passwordCrackingMinScore,
                cfg.passwordCrackingDedupWindowSeconds,
                cfg.passwordCrackingStateCapacity);
            m_dispatch.passwordCracking = m_passwordCracking.get();
            std::fprintf(stderr, "[edr] password cracking detector ready\n");
        }
        if (cfg.pathInterceptionEnable) {
            m_pathInterception = std::make_unique<PathInterceptionDetector>(
                cfg.pathInterceptionEnable, cfg.pathInterceptionMinScore,
                cfg.pathInterceptionDedupWindowSeconds,
                cfg.pathInterceptionStateCapacity);
            m_dispatch.pathInterception = m_pathInterception.get();
            std::fprintf(stderr, "[edr] path interception detector ready\n");
        }
        if (cfg.peAnomalyEnable) {
            m_peAnomaly = std::make_unique<PeAnomalyDetector>(
                cfg.peAnomalyEnable, cfg.peAnomalyMinScore,
                cfg.peAnomalyDedupWindowSeconds,
                cfg.peAnomalyStateCapacity, cfg.peAnomalyMaxFileBytes,
                std::vector<std::string>());
            m_dispatch.peAnomaly = m_peAnomaly.get();
            std::fprintf(stderr, "[edr] pe anomaly detector ready\n");
        }
        if (cfg.ransomOpsEnable) {
            m_ransomOps = std::make_unique<RansomOpsDetector>(
                cfg.ransomOpsEnable, cfg.ransomOpsMinScore,
                cfg.ransomOpsDedupWindowSeconds,
                cfg.ransomOpsStateCapacity);
            m_dispatch.ransomOps = m_ransomOps.get();
            std::fprintf(stderr, "[edr] ransom ops detector ready\n");
        }
        if (cfg.rdpSessionHijackEnable) {
            m_rdpSessionHijack = std::make_unique<RdpSessionHijackDetector>(
                cfg.rdpSessionHijackEnable, cfg.rdpSessionHijackMinScore,
                cfg.rdpSessionHijackDedupWindowSeconds,
                cfg.rdpSessionHijackStateCapacity);
            m_dispatch.rdpSessionHijack = m_rdpSessionHijack.get();
            std::fprintf(stderr, "[edr] rdp session hijack detector ready\n");
        }
        if (cfg.regCredHuntEnable) {
            m_regCredHunt = std::make_unique<RegCredHuntDetector>(
                cfg.regCredHuntEnable, cfg.regCredHuntMinScore,
                cfg.regCredHuntDedupWindowSeconds,
                cfg.regCredHuntStateCapacity);
            m_dispatch.regCredHunt = m_regCredHunt.get();
            std::fprintf(stderr, "[edr] reg cred hunt detector ready\n");
        }
        if (cfg.remoteExecEnable) {
            m_remoteExec = std::make_unique<RemoteExecDetector>(
                cfg.remoteExecEnable, cfg.remoteExecMinScore,
                cfg.remoteExecDedupWindowSeconds,
                cfg.remoteExecStateCapacity);
            m_dispatch.remoteExec = m_remoteExec.get();
            std::fprintf(stderr, "[edr] remote exec detector ready\n");
        }
        if (cfg.secbootTamperEnable) {
            m_secbootTamper = std::make_unique<SecbootTamperDetector>(
                cfg.secbootTamperEnable, cfg.secbootTamperMinScore,
                cfg.secbootTamperDedupWindowSeconds,
                cfg.secbootTamperStateCapacity);
            m_dispatch.secbootTamper = m_secbootTamper.get();
            std::fprintf(stderr, "[edr] secboot tamper detector ready\n");
        }
        if (cfg.shimDbEnable) {
            m_shimDb = std::make_unique<ShimDbDetector>(
                cfg.shimDbEnable, cfg.shimDbMinScore,
                cfg.shimDbDedupWindowSeconds,
                cfg.shimDbStateCapacity);
            m_dispatch.shimDb = m_shimDb.get();
            std::fprintf(stderr, "[edr] shim db detector ready\n");
        }
        if (cfg.signedBinaryAbuseEnable) {
            m_signedBinaryAbuse = std::make_unique<SignedBinaryAbuseDetector>(
                cfg.signedBinaryAbuseEnable, cfg.signedBinaryAbuseMinScore,
                cfg.signedBinaryAbuseDedupWindowSeconds,
                cfg.signedBinaryAbuseStateCapacity);
            m_dispatch.signedBinaryAbuse = m_signedBinaryAbuse.get();
            std::fprintf(stderr, "[edr] signed binary abuse detector ready\n");
        }
        if (cfg.sipHijackEnable) {
            m_sipHijack = std::make_unique<SipHijackDetector>(
                cfg.sipHijackEnable, cfg.sipHijackMinScore,
                cfg.sipHijackDedupWindowSeconds,
                cfg.sipHijackStateCapacity);
            m_dispatch.sipHijack = m_sipHijack.get();
            std::fprintf(stderr, "[edr] sip hijack detector ready\n");
        }
        if (cfg.sshKeyPersistenceEnable) {
            m_sshKeyPersistence = std::make_unique<SshKeyPersistenceDetector>(
                cfg.sshKeyPersistenceEnable, cfg.sshKeyPersistenceMinScore,
                cfg.sshKeyPersistenceDedupWindowSeconds,
                cfg.sshKeyPersistenceStateCapacity);
            m_dispatch.sshKeyPersistence = m_sshKeyPersistence.get();
            std::fprintf(stderr, "[edr] ssh key persistence detector ready\n");
        }
        if (cfg.ticketCacheAbuseEnable) {
            m_ticketCacheAbuse = std::make_unique<TicketCacheAbuseDetector>(
                cfg.ticketCacheAbuseEnable, cfg.ticketCacheAbuseMinScore,
                cfg.ticketCacheAbuseDedupWindowSeconds,
                cfg.ticketCacheAbuseStateCapacity);
            m_dispatch.ticketCacheAbuse = m_ticketCacheAbuse.get();
            std::fprintf(stderr, "[edr] ticket cache abuse detector ready\n");
        }
        if (cfg.tokenImpersonationEnable) {
            m_tokenImpersonation = std::make_unique<TokenImpersonationDetector>(
                cfg.tokenImpersonationEnable, cfg.tokenImpersonationMinScore,
                cfg.tokenImpersonationDedupWindowSeconds,
                cfg.tokenImpersonationStateCapacity);
            m_dispatch.tokenImpersonation = m_tokenImpersonation.get();
            std::fprintf(stderr, "[edr] token impersonation detector ready\n");
        }
        if (cfg.handleGuardEnable) {
            m_handleGuard = std::make_unique<HandleGuardDetector>(
                cfg.handleGuardEnable, cfg.handleGuardMinScore,
                cfg.handleGuardDedupWindowSeconds,
                cfg.handleGuardStateCapacity);
            m_dispatch.handleGuard = m_handleGuard.get();
            std::fprintf(stderr, "[edr] handle guard detector ready\n");
        }
        if (cfg.namedPipeAbuseEnable) {
            m_namedPipeAbuse = std::make_unique<NamedPipeAbuseDetector>(
                cfg.namedPipeAbuseEnable, cfg.namedPipeAbuseMinScore,
                cfg.namedPipeAbuseWindowSeconds,
                cfg.namedPipeAbuseStateCapacity,
                cfg.namedPipeAbuseMinDistinctPids,
                cfg.namedPipeAbuseDedupWindowSeconds);
            m_dispatch.namedPipeAbuse = m_namedPipeAbuse.get();
            std::fprintf(stderr, "[edr] named pipe abuse detector ready\n");
        }
        if (cfg.webExfilEnable) {
            m_webExfil = std::make_unique<WebExfilDetector>(
                cfg.webExfilEnable, cfg.webExfilMinScore,
                cfg.webExfilDedupWindowSeconds,
                cfg.webExfilStateCapacity);
            m_dispatch.webExfil = m_webExfil.get();
            std::fprintf(stderr, "[edr] web exfil detector ready\n");
        }
        if (cfg.wifiCredTheftEnable) {
            m_wifiCredTheft = std::make_unique<WifiCredTheftDetector>(
                cfg.wifiCredTheftEnable, cfg.wifiCredTheftWindowSeconds,
                cfg.wifiCredTheftStateCapacity, cfg.wifiCredTheftMinRepeatCount);
            m_dispatch.wifiCredTheft = m_wifiCredTheft.get();
            std::fprintf(stderr, "[edr] wifi cred theft detector ready\n");
        }
        if (cfg.winrmAbuseEnable) {
            m_winrmAbuse = std::make_unique<WinrmAbuseDetector>(
                cfg.winrmAbuseEnable, cfg.winrmAbuseMinScore,
                cfg.winrmAbuseDedupWindowSeconds,
                cfg.winrmAbuseStateCapacity);
            m_dispatch.winrmAbuse = m_winrmAbuse.get();
            std::fprintf(stderr, "[edr] winrm abuse detector ready\n");
        }
        if (cfg.winrmConfigTamperEnable) {
            m_winrmConfigTamper = std::make_unique<WinrmConfigTamperDetector>(
                cfg.winrmConfigTamperEnable, cfg.winrmConfigTamperMinScore,
                cfg.winrmConfigTamperDedupWindowSeconds,
                cfg.winrmConfigTamperStateCapacity);
            m_dispatch.winrmConfigTamper = m_winrmConfigTamper.get();
            std::fprintf(stderr, "[edr] winrm config tamper detector ready\n");
        }
        if (cfg.xslScriptEnable) {
            m_xslScript = std::make_unique<XslScriptDetector>(
                cfg.xslScriptEnable, cfg.xslScriptMinScore,
                cfg.xslScriptDedupWindowSeconds,
                cfg.xslScriptStateCapacity);
            m_dispatch.xslScript = m_xslScript.get();
            std::fprintf(stderr, "[edr] xsl script detector ready\n");
        }
        if (cfg.eventlogTamperEnable) {
            m_eventlogTamper = std::make_unique<EventlogTamperDetector>(
                cfg.eventlogTamperEnable, cfg.eventlogTamperMinScore,
                cfg.eventlogTamperDedupWindowSeconds,
                cfg.eventlogTamperStateCapacity);
            m_dispatch.eventlogTamper = m_eventlogTamper.get();
            std::fprintf(stderr, "[edr] eventlog tamper detector ready\n");
        }
        if (cfg.sshAbuseEnable) {
            m_sshAbuse = std::make_unique<SshAbuseDetector>(
                cfg.sshAbuseEnable, cfg.sshAbuseMinScore,
                cfg.sshAbuseDedupWindowSeconds,
                cfg.sshAbuseStateCapacity);
            m_dispatch.sshAbuse = m_sshAbuse.get();
            std::fprintf(stderr, "[edr] ssh abuse detector ready\n");
        }
        if (cfg.shareChangeEnable) {
            m_shareChange = std::make_unique<ShareChangeDetector>();
            m_dispatch.shareChange = m_shareChange.get();
            std::fprintf(stderr, "[edr] share change detector ready\n");
        }
        if (cfg.localAccountEnable) {
            m_localAccount = std::make_unique<LocalAccountDetector>();
            m_dispatch.localAccount = m_localAccount.get();
            std::fprintf(stderr, "[edr] local account detector ready\n");
        }
        if (cfg.cryptoMinerEnable) {
            m_cryptoMiner = std::make_unique<CryptominerDetector>(
                cfg.cryptoMinerEnable, cfg.cryptoMinerWindowSeconds,
                cfg.cryptoMinerStateCapacity);
            m_dispatch.cryptoMiner = m_cryptoMiner.get();
            std::fprintf(stderr, "[edr] cryptominer detector ready\n");
        }
        if (cfg.antiAnalysisEnable) {
            m_antiAnalysis = std::make_unique<AntiAnalysisDetector>(
                cfg.antiAnalysisEnable, cfg.antiAnalysisWindowSeconds,
                cfg.antiAnalysisStateCapacity);
            m_dispatch.antiAnalysis = m_antiAnalysis.get();
            std::fprintf(stderr, "[edr] anti-analysis detector ready\n");
        }
        if (cfg.scriptHostAbuseEnable) {
            m_scriptHostAbuse = std::make_unique<ScriptHostAbuseDetector>(
                cfg.scriptHostAbuseEnable);
            m_dispatch.scriptHostAbuse = m_scriptHostAbuse.get();
            std::fprintf(stderr, "[edr] script host abuse detector ready\n");
        }
        if (cfg.accountOpEnable) {
            m_accountOp = std::make_unique<AccountOpDetector>(
                cfg.accountOpEnable);
            m_dispatch.accountOp = m_accountOp.get();
            std::fprintf(stderr, "[edr] account op detector ready\n");
        }
        if (cfg.tunnelToolEnable) {
            m_tunnelTool = std::make_unique<TunnelToolDetector>(
                cfg.tunnelToolEnable);
            m_dispatch.tunnelTool = m_tunnelTool.get();
            std::fprintf(stderr, "[edr] tunnel tool detector ready\n");
        }
        if (cfg.surveillanceEnable) {
            m_surveillance = std::make_unique<SurveillanceDetector>(
                cfg.surveillanceEnable, cfg.surveillanceWindowSeconds,
                cfg.surveillanceStateCapacity, cfg.surveillanceMinSignals);
            m_dispatch.surveillance = m_surveillance.get();
            std::fprintf(stderr, "[edr] surveillance detector ready\n");
        }
        if (cfg.clipboardTheftEnable) {
            m_clipboardTheft = std::make_unique<ClipboardTheftDetector>(
                cfg.clipboardTheftEnable, cfg.clipboardTheftMinScore,
                cfg.clipboardTheftWindowSeconds,
                cfg.clipboardTheftStateCapacity, cfg.clipboardTheftMinReads,
                cfg.clipboardTheftDedupWindowSeconds);
            m_dispatch.clipboardTheft = m_clipboardTheft.get();
            std::fprintf(stderr, "[edr] clipboard theft detector ready\n");
        }
        if (cfg.webshellEnable) {
            m_webshell = std::make_unique<WebshellDetector>(
                cfg.webshellEnable, cfg.webshellStateCapacity,
                cfg.webshellDedupSeconds);
            m_dispatch.webshell = m_webshell.get();
            std::fprintf(stderr, "[edr] webshell detector ready\n");
        }
        if (cfg.usbExfilEnable) {
            m_usbExfil = std::make_unique<UsbExfilDetector>(
                cfg.usbExfilEnable, cfg.usbExfilWindowSeconds,
                cfg.usbExfilStateCapacity, cfg.usbExfilMinFileCount,
                cfg.usbExfilDedupSeconds);
            m_dispatch.usbExfil = m_usbExfil.get();
            std::fprintf(stderr, "[edr] usb exfil detector ready\n");
        }
        if (cfg.healthEnable) {
            if (cfg.healthDispatchTimingEnable) {
                m_dispatchTiming = std::make_unique<DispatchTiming>(
                    true, cfg.healthDispatchSlowWarnUs,
                    cfg.healthDispatchWarnCooldownSeconds);
                m_dispatch.timing = m_dispatchTiming.get();
            }
            std::fprintf(stderr,
                "[edr-dispatch] timing=%s slow_warn_us=%u warn_cooldown_seconds=%u\n",
                cfg.healthDispatchTimingEnable ? "enabled" : "disabled",
                static_cast<unsigned>(cfg.healthDispatchSlowWarnUs),
                static_cast<unsigned>(cfg.healthDispatchWarnCooldownSeconds));
        }
        m_bus.Start(&m_dispatch);

        if (cfg.selftest) {
            InjectSelftestEvents(m_bus);
            InjectCorrelationSelftestEvents(m_bus, cfg);
            /* Let the single consumer drain, then shut down. */
            for (int i = 0; i < 100 && m_bus.Pending() > 0; i++) {
                Sleep(10);
            }
            Sleep(200); /* allow sink callbacks to flush */
            m_bus.Stop();
            if (m_behaviorBaseline && !cfg.behaviorBaselinePath.empty() &&
                !m_behaviorBaseline->Save())
                std::fprintf(stderr, "[edr] behavior baseline save failed: %s\n",
                    m_behaviorBaseline->LastError().c_str());
            if (m_dispatchTiming) {
                std::fprintf(stderr, "[edr-dispatch] selftest dispatched_events=%llu\n",
                    static_cast<unsigned long long>(m_dispatchTiming->TotalEvents()));
            }
            if (m_autoResponder) m_autoResponder->Stop(); /* drain + join */
            m_amsi->Shutdown();
            m_alerter->Close();
            if (m_responseServer) m_responseServer->Stop();
            m_hostIsolation.reset();
            std::fprintf(stderr, "[edr] selftest done; check %s\n",
                         cfg.alertsPath.c_str());
            return 0;
        }

        bool iMonitorStarted = cfg.enableIMonitor &&
            StartCollector("iMonitor", CreateIMonitorCollector(
                cfg.enableIMonitorProcessOpen, cfg.enableIMonitorRemoteThread,
                cfg.enableIMonitorCredentialMonitor,
                cfg.enableIMonitorInjectionDeep));
        bool anyHooksEnabled = cfg.enableHooksRpcCreateProcess ||
            cfg.enableHooksWindowsHook || cfg.enableHooksService ||
            cfg.enableHooksCom || cfg.enableHooksInjection ||
            cfg.enableHooksHandle || cfg.enableHooksInput ||
            cfg.enableHooksSystem || cfg.enableHooksSurveillance ||
            cfg.enableHooksPowerShell;
        if (anyHooksEnabled)
            StartCollector("Hooks", CreateHooksCollector(cfg));
        const EventLogReplayOptions replayOptions{
            cfg.eventLogReplayEnable,
            Utf8ToWide(cfg.eventLogReplayCheckpointDirectory),
            cfg.eventLogReplayMaxPendingRecords};
        if (cfg.enableSysmon)
            StartCollector("Sysmon", CreateSysmonCollector(
                cfg.enableSysmonImageLoad, cfg.enableSysmonProcessAccess,
                cfg.enableSysmonRemoteThread, cfg.enableSysmonNamedPipe,
                cfg.sysmonQueueCapacity, cfg.sysmonWorkers,
                cfg.sysmonMaxXmlBytes, cfg.fileReputationEnable,
                cfg.fileReputationMaxBytes,
                cfg.fileReputationCacheOnlyTrust, replayOptions));
        if (!iMonitorStarted) {
            bool etwStarted = cfg.enableProcEtw &&
                StartCollector("process ETW", CreateProcEtwCollector(cfg.procEtwFullImage, cfg.procEtwUserSid));
            if (!etwStarted && cfg.enableProcPoll)
                StartCollector("process polling", CreateProcPollCollector(cfg.procEtwFullImage));
            if (cfg.enableDriverCollector)
                StartCollector("driver", CreateDriverCollector());
            if (cfg.enableFileFallback)
                StartCollector("file fallback", CreateFileFallbackCollector(cfg.watchDirs));
            if (cfg.enableNetFallback)
                StartCollector("network fallback", CreateNetFallbackCollector(cfg.netPollMs));
            if (cfg.enableNetEtw)
                StartCollector("network ETW", CreateNetEtwCollector(cfg.netEtwUdp));
        }
        /* These explicit registry sources provide value data that iMonitor
         * does not. Keep their switches independent of the iMonitor fallback
         * decision so policy detectors retain full registry semantics. */
        if (cfg.enableRegWatch)
            StartCollector("registry watch", CreateRegWatchCollector());
        if (cfg.enableRegBaseline)
            StartCollector("registry baseline", CreateRegBaselineCollector(cfg.regBaselineMs));
        /* Driver policy push is independent of iMonitor: publish whenever
         * the driver could enforce anything. Failure is degraded (reported,
         * never claims BLOCK readiness). */
        if (cfg.enableDriverCollector || cfg.driverEnableFile ||
            cfg.driverEnableNet || cfg.driverEnableBlock) {
            std::string perr;
            if (!PublishDriverPolicy(cfg, perr)) {
                std::fprintf(stderr, "[edr] driver policy: %s\n",
                             perr.c_str());
            }
        }
        if (cfg.enableSecurityLog)
            StartCollector("Security Log", CreateSecurityLogCollector(
                cfg.securityLogQueueCapacity, cfg.securityLogWorkers,
                cfg.securityLogMaxXmlBytes, replayOptions));        if (cfg.enableWmiCollector)
            StartCollector("WMI", CreateWmiCollector(
                cfg.wmiQueueCapacity, cfg.wmiWorkers,
                cfg.wmiMaxXmlBytes, replayOptions));
        if (cfg.enableTaskSchedulerLog)
            StartCollector("TaskScheduler", CreateTaskSchedulerCollector(
                cfg.taskSchedulerQueueCapacity, cfg.taskSchedulerWorkers,
                cfg.taskSchedulerMaxXmlBytes, replayOptions));
        if (cfg.enableDefenderLog)
            StartCollector("Microsoft Defender", CreateDefenderCollector(
                cfg.defenderQueueCapacity, cfg.defenderWorkers,
                cfg.defenderMaxXmlBytes, replayOptions));
        if (cfg.enableRdpLog)
            StartCollector("RDP session", CreateRdpCollector(
                cfg.rdpLogQueueCapacity, cfg.rdpLogWorkers,
                cfg.rdpLogMaxXmlBytes, replayOptions));
        if (cfg.enablePowerShellLog)
            StartCollector("PowerShell", CreatePowerShellCollector(
                cfg.powerShellQueueCapacity, cfg.powerShellWorkers,
                cfg.powerShellMaxXmlBytes,
                cfg.powerShellMaxScriptChars,
                {cfg.powerShellReassemblyEnable,
                 cfg.powerShellReassemblyMaxFragments,
                 cfg.powerShellReassemblyMaxAssembledBytes,
                 cfg.powerShellReassemblyStateCapacity,
                 cfg.powerShellReassemblyMaxBufferedBytes,
                 cfg.powerShellReassemblyTimeoutSeconds}, replayOptions));
        if (cfg.enableStartupWatch)
            StartCollector("startup watch",
                           CreateStartupWatchCollector(cfg.startupWatchDirs));
        if (cfg.enableImageLoad)
            StartCollector("image load",
                           CreateImageLoadCollector(cfg.imageLoadQueueCapacity));
if (cfg.enablePrivilegeEsc)
            StartCollector("privilege escalation", CreatePrivilegeCollector(
                cfg.privilegeEscQueueCapacity, cfg.privilegeEscWorkers,
                cfg.privilegeEscMaxXmlBytes, replayOptions));
        if (cfg.enableDnsEtw)
            StartCollector("DNS ETW", CreateDnsEtwCollector());
        if (cfg.enableUsbMonitor)
            StartCollector("USB monitor",
                CreateUsbCollector(cfg.usbPollMs, cfg.usbDedupWindowMs));
        if (cfg.enableListenerMonitor)
            StartCollector("listener monitor",
                CreateListenerCollector(cfg.listenerPollMs));
        if (cfg.enableServiceMonitor)
            StartCollector("service monitor",
                CreateServiceCollector(cfg.servicePollMs));
        if (cfg.enableCriticalProcessMonitor)
            StartCollector("critical process monitor",
                CreateCriticalProcessCollector(cfg.criticalProcessPollMs,
                    cfg.criticalProcessMissingThreshold,
                    cfg.criticalProcessImages));
        if (cfg.enableFimMonitor)
            StartCollector("file integrity monitor",
                CreateFimCollector(cfg.fimPollMs, cfg.fimMaxFileBytes,
                                   cfg.fimWatchFiles));
        if (cfg.canaryEnable)
            StartCollector("canary manager",
                CreateCanaryCollector(cfg.canaryPollMs, cfg.canaryMaxFileBytes,
                                      cfg.canaryFiles));
        if (cfg.hookScanEnable)
            StartCollector("hook persistence scan",
                CreateHookScanCollector(cfg.hookScanPollSeconds,
                                        cfg.hookScanMaxEntries));
        if (cfg.enableShareMonitor)
            StartCollector("share monitor",
                CreateShareCollector(cfg.sharePollMs));
        if (cfg.enableNamedPipeMonitor)
            StartCollector("named pipe ETW",
                CreateNamedPipeCollector());
        if (cfg.enableLsassSamCollector)
            StartCollector("LSASS/SAM",
                CreateLsassSamCollector(cfg.lsassSamPollMs,
                                        cfg.lsassSamDedupMs));
        if (cfg.enableLocalAccountMonitor)
            StartCollector("local account monitor",
                CreateLocalAccountCollector(cfg.localAccountPollMs,
                    cfg.localAccountWatchGroups));
        if (cfg.enableFirewallMonitor)
            StartCollector("firewall monitor",
                CreateFirewallCollector(cfg.firewallPollMs));
        if (cfg.ratAnalyzerEnable)
            StartCollector("RAT analyzer", CreateRatAnalyzerCollector(
                RatAnalyzerConfig{
                    cfg.ratAnalyzerEnable,
                    cfg.ratAnalyzerScanIntervalSeconds,
                    cfg.ratAnalyzerMinScore,
                    cfg.ratAnalyzerDedupWindowSeconds,
                    cfg.ratAnalyzerStateCapacity}));
        if (cfg.enableEtwTamperMonitor)
            StartCollector("ETW tamper",
                CreateEtwTamperCollector(EtwTamperConfig{
                    cfg.etwTamperPollMs,
                    cfg.etwTamperProtectedGuids,
                    cfg.etwTamperWatchSessions,
                    cfg.etwTamperScanProcesses,
                    cfg.etwTamperSkipImages}));

        // Agent health heartbeat: pure observability, after collectors.
        if (cfg.healthEnable) {
            m_health = std::make_unique<HealthHeartbeat>(
                cfg.healthPollSeconds, &m_bus, m_syslogForwarder.get(),
                "started=" + std::to_string(m_collectors.size()),
                m_reporter.get(), m_eventReporter.get(), [this] {
                    std::vector<HealthComponent> components;
                    components.push_back(SampleDispatchTimingHealth(m_dispatchTiming.get()));
                    for (size_t i = 0; i < m_collectors.size(); ++i)
                        components.push_back(SampleCollectorHealth(
                            m_collectorNames[i], m_collectors[i].get()));
                    for (const auto& name : m_failedCollectors) {
                        HealthComponent component;
                        component.name = name;
                        component.state = "unavailable";
                        components.push_back(std::move(component));
                    }
                    HealthComponent alerts;
                    alerts.name = "alerts";
                    alerts.state = "unavailable";
                    if (m_alerter) {
                        const auto status = m_alerter->GetWriteStatus();
                        alerts.state = status.writable ? "writable" : "unavailable";
                        alerts.countersAvailable = true;
                        alerts.counters = {{"write_failures", status.writeFailures},
                                           {"chain_sequence", status.chainSequence}};
                    }
                    components.push_back(std::move(alerts));
                    HealthComponent incidents;
                    incidents.name = "incidents";
                    incidents.state = "disabled";
                    if (m_incidentStore) {
                        const auto status = m_incidentStore->GetWriteStatus();
                        incidents.state = !status.enabled ? "disabled" :
                            status.truncated ? "truncated" :
                            status.writable ? "writable" :
                            status.open && status.lastError == "per-instance incident record limit reached"
                                ? "capacity_reached" : "unavailable";
                        incidents.countersAvailable = true;
                        incidents.counters = {{"write_failures", status.writeFailures},
                                              {"dropped", status.dropped},
                                              {"chain_sequence", status.chainSequence}};
                    }
                    components.push_back(std::move(incidents));
                    return components;
                });
            if (m_health->Start()) {
                std::fprintf(stderr,
                    "[edr] health heartbeat armed (every %lus)\n",
                    static_cast<unsigned long>(cfg.healthPollSeconds));
            } else {
                std::fprintf(stderr, "[edr-health] {\"sampling\":\"unavailable\",\"last_sample_ts\":null}\n");
                m_health.reset();
            }
        } else {
            std::fprintf(stderr, "[edr-health] {\"sampling\":\"disabled\",\"last_sample_ts\":null}\n");
        }

        // Initialize process tree builder
        if (cfg.enableProcessTreeEnrich) {
            m_processTree = std::make_unique<ProcessTreeBuilder>();
            m_dispatch.processTree = m_processTree.get();
            std::fprintf(stderr, "[edr] process tree builder ready (max_depth=%lu, prune_age=%llu ms)\n",
                (unsigned long)cfg.processTreeMaxDepth,
                (unsigned long long)cfg.processTreePruneAgeMs);
        }

        if (onReady) onReady();
        if (!cfg.runAsService)
            std::fprintf(stderr, "[edr] running (Ctrl+C to stop)\n");
        uint64_t lastPruneMs = GetTickCount64();
        uint64_t lastRulesReloadCheckMs = lastPruneMs;
        while (!g_quit.load()) {
            Sleep(200);
            const uint64_t nowMs = GetTickCount64();
            if (m_processTree && nowMs - lastPruneMs >= 600000ULL) {
                lastPruneMs = nowMs;
                m_processTree->PruneOldEntries(nowMs,
                                               cfg.processTreePruneAgeMs);
            }
            /* Thread-safe against the consumer's OnEvent via the engine's
             * shared_mutex; parse failures keep the previous rule set and
             * are retried only after the file changes again. */
            if (cfg.ruleReloadEnable &&
                nowMs - lastRulesReloadCheckMs >=
                    (uint64_t)cfg.ruleReloadPollSeconds * 1000ULL) {
                lastRulesReloadCheckMs = nowMs;
                (void)m_rules.MaybeReload();
            }
        }

        if (m_health) m_health->Stop();
        for (auto& c : m_collectors) {
            c->Stop();
        }
        m_bus.Stop();
        /* The consumer thread has joined, so the learned baseline is stable:
         * persist it atomically after the last event has been enriched. */
        if (m_behaviorBaseline && !cfg.behaviorBaselinePath.empty() &&
            !m_behaviorBaseline->Save())
            std::fprintf(stderr, "[edr] behavior baseline save failed: %s\n",
                m_behaviorBaseline->LastError().c_str());
        /* The consumer thread has joined, so no incident can arrive now; a
         * final manual flush closes every chain that is still open and gives
         * the store its last records before the file handle goes away. */
        if (m_correlation) {
            m_correlation->FlushExpired(Now100ns());
        }
        if (m_incidentStore) m_incidentStore->Close();
        if (m_autoResponder) m_autoResponder->Stop(); /* drain + join */
        m_amsi->Shutdown();
        m_alerter->Close();
        if (m_reporter) {
            m_reporter->Stop();
        }
        if (m_eventReporter) m_eventReporter->Stop();
        if (m_syslogForwarder) m_syslogForwarder->Stop();
        if (m_responseServer) m_responseServer->Stop();
        m_hostIsolation.reset();
        m_processTree.reset();
        return 0;
    }

    std::string m_configPath;
    bool m_redact = true;
    bool m_redactCliGiven = false;
    std::string m_rulesCliPath;

private:
    bool StartCollector(const char* name, ICollector* raw) {
        std::unique_ptr<ICollector> collector(raw);
        if (!collector || !collector->Start(&m_bus)) {
            std::fprintf(stderr, "[edr] %s collector failed to start\n", name);
            m_failedCollectors.emplace_back(name);
            return false;
        }
        std::fprintf(stderr, "[edr] %s collector started\n", name);
        m_collectorNames.emplace_back(name);
        m_collectors.push_back(std::move(collector));
        return true;
    }

    /* Outlives the bus so shutdown joins the consumer before timing is freed. */
    std::unique_ptr<DispatchTiming> m_dispatchTiming;
    EventBus m_bus;
    RuleEngine m_rules;
    std::unique_ptr<Alerter> m_alerter;
    std::unique_ptr<Reporter> m_reporter;
    std::unique_ptr<Reporter> m_eventReporter;
    std::unique_ptr<SyslogForwarder> m_syslogForwarder;
    std::unique_ptr<WebhookNotifier> m_webhookNotifier;
    std::unique_ptr<ResponseServer> m_responseServer;
    std::unique_ptr<AutoResponder> m_autoResponder;
    std::unique_ptr<IAmsiPlatform> m_amsiPlatform;
    std::unique_ptr<AmsiEnricher> m_amsi;
    EventDispatchSink m_dispatch;
    std::unique_ptr<SilverFoxDetector> m_silverfox;
    std::unique_ptr<BehaviorEnricher> m_behavior;
    std::unique_ptr<InjectionChainDetector> m_injector;
    std::unique_ptr<AttackChainDetector> m_attacker;
    std::unique_ptr<C2BeaconDetector> m_c2;
    std::unique_ptr<RansomBurstDetector> m_ransom;
    std::unique_ptr<LogonBruteForceDetector> m_logonBrute;
    std::unique_ptr<LogonSuccessDetector> m_logonSuccess;
    std::unique_ptr<PasswordSprayDetector> m_passwordSpray;
    std::unique_ptr<KerberoastDetector> m_kerberoast;
    std::unique_ptr<ProcessHollowingDetector> m_hollowing;
    std::unique_ptr<DnsBeaconDetector> m_dns;
    std::unique_ptr<DnsFailureDetector> m_dnsFailure;
    std::unique_ptr<BehaviorBaselineDetector> m_behaviorBaseline;
    std::unique_ptr<LateralMovementDetector> m_lateral;
    std::unique_ptr<PortScanDetector> m_portScan;
    std::unique_ptr<PersistenceChainDetector> m_persistChain;
    std::unique_ptr<LolbinParentChildDetector> m_lolbin;
    std::unique_ptr<LolbinChainDetector> m_lolbinChain;
    std::unique_ptr<PowerShellDownloadExecuteDetector> m_powershellDownloadExecute;
    std::unique_ptr<DllHijackDetector> m_dllHijack;
    std::unique_ptr<RegistryPersistenceDetector> m_registryPersistence;
    std::unique_ptr<AntiForensicsDetector> m_antiForensics;
    std::unique_ptr<TimeChangeDetector> m_timeChange;
    std::unique_ptr<PrivilegedGroupDetector> m_privilegedGroup;
    std::unique_ptr<DefenseEvasionDetector> m_defenseEvasion;
    std::unique_ptr<DiscoveryReconDetector> m_discoveryRecon;
    std::unique_ptr<RdpChainDetector> m_rdpChain;
    std::unique_ptr<UacBypassDetector> m_uacBypass;
    std::unique_ptr<WmiPersistenceDetector> m_wmiPersistence;
    std::unique_ptr<RansomPrecursorDetector> m_ransomPrecursor;
std::unique_ptr<MemoryScannerDetector> m_memoryScanner;
std::unique_ptr<DriverLoadDetector> m_driverLoad;
std::unique_ptr<CanaryDetector> m_canary;
std::unique_ptr<HookPersistenceDetector> m_hookPersist;
std::unique_ptr<TaskAbuseDetector> m_taskAbuse;
std::unique_ptr<MasqueradeDetector> m_masquerade;
std::unique_ptr<PpidSpoofDetector> m_ppidSpoof;
std::unique_ptr<NetDiscoveryDetector> m_netDiscovery;
std::unique_ptr<HostProfileDetector> m_hostProfile;
std::unique_ptr<PrivateKeyDetector> m_privateKey;
    std::unique_ptr<AccessibilityHijackDetector> m_accessibilityHijack;
    std::unique_ptr<AclAbuseDetector> m_aclAbuse;
    std::unique_ptr<AmsiBypassDetector> m_amsiBypass;
    std::unique_ptr<ComHijackDetector> m_comHijack;
    std::unique_ptr<WinlogonHijackDetector> m_winlogonHijack;
    std::unique_ptr<MshtaAbuseDetector> m_mshtaAbuse;
    std::unique_ptr<DotnetProxyExecDetector> m_dotnetProxyExec;
    std::unique_ptr<WslAbuseDetector> m_wslAbuse;
    std::unique_ptr<MsdtAbuseDetector> m_msdtAbuse;
    std::unique_ptr<SoftwareDiscoveryDetector> m_softwareDiscovery;
    std::unique_ptr<NetShareDiscoveryDetector> m_netShareDiscovery;
    std::unique_ptr<NonstandardPortEgressDetector> m_nonstandardPortEgress;
    std::unique_ptr<IsoMountDetector> m_isoMount;
    std::unique_ptr<AppinitDllDetector> m_appInitDll;
    std::unique_ptr<AsRepRoastDetector> m_asRepRoast;
    std::unique_ptr<BootProviderPersistDetector> m_bootProvider;
    std::unique_ptr<CertAbuseDetector> m_certAbuse;
    std::unique_ptr<CorProfilerHijackDetector> m_corProfiler;
    std::unique_ptr<CredentialFileHuntDetector> m_credFileHunt;
    std::unique_ptr<DcsyncDetector> m_dcsync;
    std::unique_ptr<DevUtilProxyDetector> m_devUtilProxy;
    std::unique_ptr<DiskWipeDetector> m_diskWipe;
    std::unique_ptr<AvTamperDetector> m_avTamper;
std::unique_ptr<TimestompDetector> m_timestomp;
std::unique_ptr<ObfuscationDetector> m_obfuscation;
    std::unique_ptr<RegModifyDetector> m_regModify;
    std::unique_ptr<WmiExecDetector> m_wmiExec;
    std::unique_ptr<LocalCollectDetector> m_localCollect;
    std::unique_ptr<LateralTransferDetector> m_lateralTransfer;
    std::unique_ptr<ThreatIntelDetector> m_threatIntel;
    std::unique_ptr<LateralChainDetector> m_lateralChain;
    std::unique_ptr<CorrelationEngine> m_correlation;
    std::unique_ptr<CorrelationRollup> m_rollup;
    std::unique_ptr<IncidentStore> m_incidentStore;
std::unique_ptr<LsassDumpDetector> m_lsassDump;
std::unique_ptr<ShadowCopyDetector> m_shadowCopy;
std::unique_ptr<PersistenceBurstDetector> m_persistBurst;
std::unique_ptr<CmstpBypassDetector> m_cmstpBypass;
std::unique_ptr<FileAssocDetector> m_fileAssoc;
std::unique_ptr<HiddenWindowDetector> m_hiddenWindow;
std::unique_ptr<OfficePersistDetector> m_officePersist;
std::unique_ptr<ShortcutPersistDetector> m_shortcutPersist;
std::unique_ptr<IndirectExecDetector> m_indirectExec;
std::unique_ptr<ScreensaverPersistDetector> m_screensaverPersist;
std::unique_ptr<SvcPathAbuseDetector> m_svcPathAbuse;
std::unique_ptr<ServiceDllHijackDetector> m_serviceDllHijack;
std::unique_ptr<DllSearchOrderDetector> m_dllSearchOrder;
std::unique_ptr<SvcRecoveryDetector> m_svcRecovery;
std::unique_ptr<PsProfileDetector> m_psProfile;
std::unique_ptr<DowngradeAttackDetector> m_downgradeAttack;
std::unique_ptr<DpapiAbuseDetector> m_dpapiAbuse;
std::unique_ptr<EmailCollectionDetector> m_emailCollection;
std::unique_ptr<EtwScriptTamperDetector> m_etwScriptTamper;
std::unique_ptr<ForcedAuthDetector> m_forcedAuth;
std::unique_ptr<GoldenTicketDetector> m_goldenTicket;
std::unique_ptr<GpoAbuseDetector> m_gpoAbuse;
std::unique_ptr<HiddenArtifactsDetector> m_hiddenArtifacts;
std::unique_ptr<HistoryTamperDetector> m_historyTamper;
std::unique_ptr<HiveCopyDetector> m_hiveCopy;
std::unique_ptr<HostsRedirectDetector> m_hostsRedirect;
std::unique_ptr<IisModuleDetector> m_iisModule;
std::unique_ptr<InputSimulationDetector> m_inputSimulation;
std::unique_ptr<LogonScriptPersistDetector> m_logonScriptPersist;
std::unique_ptr<LsaPackageDetector> m_lsaPackage;
std::unique_ptr<MotwBypassDetector> m_motwBypass;
std::unique_ptr<NetshHelperDetector> m_netshHelper;
std::unique_ptr<NetworkSniffingDetector> m_networkSniffing;
std::unique_ptr<NtdsDitDetector> m_ntdsDit;
std::unique_ptr<PassTheHashDetector> m_passTheHash;
std::unique_ptr<PasswordCrackingDetector> m_passwordCracking;
std::unique_ptr<PathInterceptionDetector> m_pathInterception;
std::unique_ptr<PeAnomalyDetector> m_peAnomaly;
std::unique_ptr<RansomOpsDetector> m_ransomOps;
std::unique_ptr<RdpSessionHijackDetector> m_rdpSessionHijack;
std::unique_ptr<RegCredHuntDetector> m_regCredHunt;
std::unique_ptr<RemoteExecDetector> m_remoteExec;
std::unique_ptr<SecbootTamperDetector> m_secbootTamper;
std::unique_ptr<ShimDbDetector> m_shimDb;
std::unique_ptr<SignedBinaryAbuseDetector> m_signedBinaryAbuse;
std::unique_ptr<SipHijackDetector> m_sipHijack;
std::unique_ptr<SshKeyPersistenceDetector> m_sshKeyPersistence;
std::unique_ptr<TicketCacheAbuseDetector> m_ticketCacheAbuse;
std::unique_ptr<TokenImpersonationDetector> m_tokenImpersonation;
std::unique_ptr<HandleGuardDetector> m_handleGuard;
std::unique_ptr<NamedPipeAbuseDetector> m_namedPipeAbuse;
std::unique_ptr<WebExfilDetector> m_webExfil;
std::unique_ptr<WifiCredTheftDetector> m_wifiCredTheft;
    std::unique_ptr<WinrmAbuseDetector> m_winrmAbuse;
    std::unique_ptr<WinrmConfigTamperDetector> m_winrmConfigTamper;
    std::unique_ptr<XslScriptDetector> m_xslScript;
    std::unique_ptr<EventlogTamperDetector> m_eventlogTamper;
    std::unique_ptr<SshAbuseDetector> m_sshAbuse;
    std::unique_ptr<MailboxRuleDetector> m_mailboxRule;
    std::unique_ptr<MailboxDelegateDetector> m_mailboxDelegate;
    std::unique_ptr<LlmnrPoisonDetector> m_llmnrPoison;
    std::unique_ptr<NetProviderPersistDetector> m_netProviderPersist;
    std::unique_ptr<PasswordVaultDetector> m_passwordVault;
    std::unique_ptr<ArpPoisonDetector> m_arpPoison;
    std::unique_ptr<CloudMetadataDetector> m_cloudMetadata;
    std::unique_ptr<GppPasswordDetector> m_gppPassword;
    std::unique_ptr<ControlPanelProxyDetector> m_controlPanelProxy;
    std::unique_ptr<HiddenUserAccountDetector> m_hiddenUserAccount;
    std::unique_ptr<PasswordPolicyDiscoveryDetector> m_passwordPolicyDiscovery;
    std::unique_ptr<MsiPackageInstallDetector> m_msiPackageInstall;
    std::unique_ptr<LogEnumerationDetector> m_logEnumeration;
    std::unique_ptr<HealthHeartbeat> m_health;
    std::unique_ptr<FilelessAttackDetector> m_fileless;
    std::unique_ptr<ApiHookDetector> m_apiHook;
   std::unique_ptr<RemoteAccessDetector> m_remoteAccess;
    std::unique_ptr<CredentialDumpingDetector> m_credDump;
    std::unique_ptr<DataExfiltrationDetector> m_dataExfil;
    std::unique_ptr<PrivilegeEscalationDetector> m_privEsc;
    std::unique_ptr<NtlmRelayDetector> m_ntlmRelay;
    std::unique_ptr<BrowserTheftDetector> m_browserTheft;
    std::unique_ptr<BrowserExtensionDetector> m_browserExtension;
    std::unique_ptr<ArchiveStagingDetector> m_archiveStaging;
    std::unique_ptr<BitsAbuseDetector> m_bitsAbuse;
    std::unique_ptr<DohAbuseDetector> m_dohAbuse;
    std::unique_ptr<ServiceInstallDetector> m_svcInstall;
    std::unique_ptr<FirewallRuleDetector> m_firewallRule;
    std::unique_ptr<ShareChangeDetector> m_shareChange;
    std::unique_ptr<LocalAccountDetector> m_localAccount;
    std::unique_ptr<CryptominerDetector> m_cryptoMiner;
    std::unique_ptr<AntiAnalysisDetector> m_antiAnalysis;
    std::unique_ptr<ScriptHostAbuseDetector> m_scriptHostAbuse;
    std::unique_ptr<AccountOpDetector> m_accountOp;
    std::unique_ptr<TunnelToolDetector> m_tunnelTool;
    std::unique_ptr<SurveillanceDetector> m_surveillance;
    std::unique_ptr<ClipboardTheftDetector> m_clipboardTheft;
    std::unique_ptr<WebshellDetector> m_webshell;
    std::unique_ptr<UsbExfilDetector> m_usbExfil;
   std::unique_ptr<ProcessTreeBuilder> m_processTree;
    std::unique_ptr<HostIsolationController> m_hostIsolation;
    std::vector<std::unique_ptr<ICollector>> m_collectors;
    std::vector<std::string> m_collectorNames;
    std::vector<std::string> m_failedCollectors;
};

static constexpr wchar_t kServiceName[] = L"edr";

static std::wstring GetExecutablePath() {
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        SetLastError(ERROR_SUCCESS);
        DWORD length = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) return {};
        if (length < buffer.size()) {
            return std::wstring(buffer.data(), length);
        }
        if (buffer.size() >= 32768) return {};
        buffer.resize(buffer.size() * 2);
    }
}

/* Returns directory containing this executable. */
static std::wstring GetConfigDirForService() {
    std::wstring module = GetExecutablePath();
    if (module.empty()) return L".";
    size_t slash = module.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L".";
    module.resize(slash);
    return module;
}

/* ------------------------- Windows service ------------------------------- */

static Agent* g_serviceAgent = nullptr;
static Config* g_serviceConfig = nullptr;
static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static SERVICE_STATUS g_status = {};
static SRWLOCK g_statusLock = SRWLOCK_INIT;
static DWORD g_statusCheckpoint = 0;

static void ReportServiceStatus(DWORD state, DWORD win32ExitCode = NO_ERROR,
                                DWORD serviceExitCode = 0,
                                DWORD waitHint = 0) {
    AcquireSRWLockExclusive(&g_statusLock);
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32ExitCode;
    g_status.dwServiceSpecificExitCode = serviceExitCode;
    g_status.dwWaitHint = waitHint;
    g_status.dwControlsAccepted =
        state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
                                 : 0;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        g_status.dwCheckPoint = ++g_statusCheckpoint;
    } else {
        g_status.dwCheckPoint = 0;
        g_statusCheckpoint = 0;
    }
    if (g_statusHandle) SetServiceStatus(g_statusHandle, &g_status);
    ReleaseSRWLockExclusive(&g_statusLock);
}

static void ReportCurrentServiceStatus() {
    AcquireSRWLockShared(&g_statusLock);
    if (g_statusHandle) SetServiceStatus(g_statusHandle, &g_status);
    ReleaseSRWLockShared(&g_statusLock);
}

static VOID WINAPI ServiceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        g_quit.store(true);
        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, 30000);
    } else if (ctrl == SERVICE_CONTROL_INTERROGATE) {
        ReportCurrentServiceStatus();
    }
}

static void LogServiceEvent(WORD type, DWORD eventId, LPCWSTR message) {
    HANDLE eventLog = RegisterEventSourceW(nullptr, L"EDR-Agent-Service");
    if (!eventLog) return;
    ReportEventW(eventLog, type, 0, eventId, nullptr, 1, 0, &message, nullptr);
    DeregisterEventSource(eventLog);
}

static VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    AcquireSRWLockExclusive(&g_statusLock);
    ZeroMemory(&g_status, sizeof(g_status));
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ReleaseSRWLockExclusive(&g_statusLock);
    g_quit.store(false);

    g_statusHandle =
        RegisterServiceCtrlHandlerW(kServiceName, ServiceCtrlHandler);
    if (g_statusHandle == nullptr) {
        return;
    }
    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 0, 30000);
    LogServiceEvent(EVENTLOG_INFORMATION_TYPE, 1001,
                    L"EDR Agent service starting");

    int rc = g_serviceAgent->Run(*g_serviceConfig, [] {
        if (g_quit.load()) {
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, 30000);
        } else {
            ReportServiceStatus(SERVICE_RUNNING);
        }
    });

    if (rc == 0) {
        LogServiceEvent(EVENTLOG_INFORMATION_TYPE, 1002,
                        L"EDR Agent service stopped");
        ReportServiceStatus(SERVICE_STOPPED);
    } else {
        LogServiceEvent(EVENTLOG_ERROR_TYPE, 1003,
                        L"EDR Agent service failed during startup or execution");
        ReportServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR,
                            static_cast<DWORD>(rc));
    }
}

} // namespace edr

static std::wstring QuoteCommandLineArgument(const std::wstring& argument) {
    std::wstring quoted(1, L'"');
    size_t backslashes = 0;
    for (wchar_t ch : argument) {
        if (ch == L'\\') {
            ++backslashes;
            continue;
        }
        if (ch == L'"') {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted.push_back(ch);
            backslashes = 0;
            continue;
        }
        quoted.append(backslashes, L'\\');
        backslashes = 0;
        quoted.push_back(ch);
    }
    quoted.append(backslashes * 2, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

static bool ResolveAbsolutePath(const std::wstring& path,
                                std::wstring& absolute) {
    DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (needed == 0) return false;
    std::vector<wchar_t> buffer(static_cast<size_t>(needed) + 1);
    DWORD written = GetFullPathNameW(
        path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    if (written == 0 || written >= buffer.size()) return false;
    absolute.assign(buffer.data(), written);
    return true;
}

static bool InstallService(const edr::Options& options) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!manager) {
        std::fprintf(stderr, "[edr] OpenSCManager failed: %lu\n", GetLastError());
        return false;
    }

    std::wstring module = edr::GetExecutablePath();
    std::wstring configPath;
    if (module.empty()) {
        std::fprintf(stderr, "[edr] cannot resolve executable path: %lu\n",
                     GetLastError());
        CloseServiceHandle(manager);
        return false;
    }

    if (options.configGiven) {
        std::wstring requested = edr::Utf8ToWide(options.configPath);
        if (requested.empty() || !ResolveAbsolutePath(requested, configPath)) {
            std::fprintf(stderr, "[edr] cannot resolve service config path\n");
            CloseServiceHandle(manager);
            return false;
        }
    } else {
        configPath =
            edr::GetConfigDirForService() + L"\\config\\edr.config.json";
    }

    std::wstring command = QuoteCommandLineArgument(module) +
        L" --service --config " + QuoteCommandLineArgument(configPath);
    if (options.rulesGiven) {
        std::wstring rulesPath;
        if (!ResolveAbsolutePath(edr::Utf8ToWide(options.rulesPath), rulesPath)) {
            std::fprintf(stderr, "[edr] cannot resolve service rules path\n");
            CloseServiceHandle(manager);
            return false;
        }
        command += L" --rules " + QuoteCommandLineArgument(rulesPath);
    }
    if (options.redactGiven) {
        command += options.redactValue ? L" --redact=on" : L" --redact=off";
    }

    SC_HANDLE svc = CreateServiceW(manager, edr::kServiceName, L"EDR Agent",
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            std::fprintf(stderr, "[edr] service 'edr' already exists\n");
        else
            std::fprintf(stderr, "[edr] CreateService failed: %lu\n", err);
        CloseServiceHandle(manager);
        return false;
    }

    SERVICE_DESCRIPTIONW description = {
        const_cast<LPWSTR>(L"Endpoint detection and response agent")
    };
    if (!ChangeServiceConfig2W(
            svc, SERVICE_CONFIG_DESCRIPTION, &description)) {
        std::fprintf(stderr,
            "[edr] warning: cannot set service description: %lu\n",
            GetLastError());
    }

    SC_ACTION recoveryActions[] = {
        { SC_ACTION_RESTART, 5000 },
        { SC_ACTION_RESTART, 15000 },
        { SC_ACTION_NONE, 0 }
    };
    SERVICE_FAILURE_ACTIONSW failureActions = {};
    failureActions.dwResetPeriod = 86400;
    failureActions.cActions =
        static_cast<DWORD>(std::size(recoveryActions));
    failureActions.lpsaActions = recoveryActions;
    if (!ChangeServiceConfig2W(
            svc, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions)) {
        std::fprintf(stderr,
            "[edr] warning: cannot set service recovery actions: %lu\n",
            GetLastError());
    }

    SERVICE_FAILURE_ACTIONS_FLAG failureFlag = {};
    failureFlag.fFailureActionsOnNonCrashFailures = TRUE;
    if (!ChangeServiceConfig2W(
            svc, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failureFlag)) {
        std::fprintf(stderr,
            "[edr] warning: cannot enable service recovery policy: %lu\n",
            GetLastError());
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(manager);
    std::fprintf(stderr, "[edr] service 'edr' installed successfully\n");
    return true;
}

static bool WaitForServiceStopped(SC_HANDLE service, DWORD timeoutMs) {
    SERVICE_STATUS_PROCESS status = {};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
        std::fprintf(stderr, "[edr] QueryServiceStatusEx failed: %lu\n",
                     GetLastError());
        return false;
    }
    if (status.dwCurrentState == SERVICE_STOPPED) return true;

    if (status.dwCurrentState != SERVICE_STOP_PENDING) {
        SERVICE_STATUS controlStatus = {};
        if (!ControlService(service, SERVICE_CONTROL_STOP, &controlStatus) &&
            GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
            std::fprintf(stderr, "[edr] service stop failed: %lu\n",
                         GetLastError());
            return false;
        }
    }

    ULONGLONG deadline = GetTickCount64() + timeoutMs;
    while (GetTickCount64() < deadline) {
        DWORD sleepMs = status.dwWaitHint / 10;
        if (sleepMs < 100) sleepMs = 100;
        if (sleepMs > 1000) sleepMs = 1000;
        Sleep(sleepMs);
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status), sizeof(status),
                &bytesNeeded)) {
            std::fprintf(stderr, "[edr] QueryServiceStatusEx failed: %lu\n",
                         GetLastError());
            return false;
        }
        if (status.dwCurrentState == SERVICE_STOPPED) return true;
    }

    std::fprintf(stderr, "[edr] timed out waiting for service to stop\n");
    return false;
}

static bool UninstallService() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        std::fprintf(stderr, "[edr] OpenSCManager failed: %lu\n", GetLastError());
        return false;
    }
    SC_HANDLE svc = OpenServiceW(manager, edr::kServiceName,
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!svc) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            std::fprintf(stderr, "[edr] service 'edr' is not installed\n");
        } else {
            std::fprintf(stderr, "[edr] OpenService failed: %lu\n", error);
        }
        CloseServiceHandle(manager);
        return error == ERROR_SERVICE_DOES_NOT_EXIST;
    }

    bool success = WaitForServiceStopped(svc, 30000);
    if (success && !DeleteService(svc)) {
        DWORD error = GetLastError();
        success = error == ERROR_SERVICE_MARKED_FOR_DELETE;
        if (!success)
            std::fprintf(stderr, "[edr] DeleteService failed: %lu\n", error);
    }
    if (success)
        std::fprintf(stderr, "[edr] service 'edr' uninstalled\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(manager);
    return success;
}

int wmain(int argc, wchar_t** argv) {
    using namespace edr;

    Config cfg;
    Options opt;
    if (!ParseArgs(argc, argv, cfg, opt)) {
        return 1;
    }

    if (opt.action == 'B') {
        return RunSecurityBaseline() == 0 ? 0 : 1;
    }
    if (opt.action == 'S') {
        return RunSystemSnapshot() == 0 ? 0 : 1;
    }
    if (opt.action == 'T') {
        if (opt.triageOut.empty()) {
            std::fprintf(stderr, "--triage requires --out <dir>\n");
            return 1;
        }
        std::string configError;
        if (!LoadConfigFile(opt.configPath, cfg, configError)) {
            std::fprintf(stderr, "[triage] config load failed: %s\n", configError.c_str());
            return 1;
        }
        if (opt.rulesGiven) cfg.rulesPath = opt.rulesPath;
        TriageOptions triage;
        triage.configPath = opt.configPath;
        triage.rulesPath = cfg.rulesPath;
        triage.alertsPath = cfg.alertsPath;
        triage.incidentsPath = cfg.correlationIncidentPath;
        triage.responseAuditPath = cfg.responseAuditPath;
        triage.outDir = opt.triageOut;
        std::string triageError;
        const int triageRc = WriteTriagePack(triage, /*dryRun=*/false, triageError);
        if (triageRc != 0)
            std::fprintf(stderr, "[triage] failed: %s\n", triageError.c_str());
        return triageRc == 0 ? 0 : 1;
    }
    if (opt.action == 'I') return InstallService(opt) ? 0 : 1;
    if (opt.action == 'U') return UninstallService() ? 0 : 1;

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    Agent agent;
    agent.m_configPath = opt.configPath;
    agent.m_redact = cfg.redact;
    agent.m_redactCliGiven = opt.redactGiven;
    if (opt.rulesGiven) {
        agent.m_rulesCliPath = opt.rulesPath;
    }

    if (cfg.runAsService) {
        /* Set working directory to the executable's directory */
        std::wstring dir = GetConfigDirForService();
        SetCurrentDirectoryW(dir.c_str());

        /* SCM entry: blocks until the service stops. */
        g_serviceAgent = &agent;
        g_serviceConfig = &cfg;
        SERVICE_TABLE_ENTRYW table[] = {
            { const_cast<LPWSTR>(kServiceName), ServiceMain },
            { nullptr, nullptr }
        };
        if (!StartServiceCtrlDispatcherW(table)) {
            std::fprintf(stderr, "[edr] StartServiceCtrlDispatcher failed: %lu\n",
                         GetLastError());
            return 1;
        }
        return 0;
    }

    int rc = agent.Run(cfg);
    return rc;
}
