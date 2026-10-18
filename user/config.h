/*
 * config.h - Agent configuration (JSON file + command-line overrides).
 */
#ifndef EDR_CONFIG_H
#define EDR_CONFIG_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace edr {

struct Config {
    /* Opt-in Event Log replay; default retains future-only subscriptions. */
    bool eventLogReplayEnable = false;
    std::string eventLogReplayCheckpointDirectory;
    uint32_t eventLogReplayMaxPendingRecords = 0;
    /* Sources */
    bool enableDriverCollector = true;
    bool enableFileFallback = true;
    bool enableNetFallback = true;
    bool enableNetEtw = true;       /* ETW-based network monitor */
    bool netEtwUdp = false;         /* additionally collect UDP flows */
    bool enableRegBaseline = false; /* opt-in */
    bool enableRegWatch = true;     /* RegNotifyChangeKeyValue */
    bool enableProcEtw = true;      /* ETW-based process monitor */
    bool enableProcPoll = true;     /* polling fallback */
    bool enableSilverFox = true;    /* SilverFox detector (silverfox.enable) */
    std::string silverFoxIocPath = "rules\\silverfox_ioc.v2.json";
    uint32_t silverFoxCorrelationWindowSeconds = 600;
    uint32_t silverFoxStateCapacity = 4096;
    /* RAT analyzer poll collector (opt-in; enable_rat_analyzer). */
    bool ratAnalyzerEnable = false;
    uint32_t ratAnalyzerScanIntervalSeconds = 15;
    uint32_t ratAnalyzerMinScore = 15;
    uint32_t ratAnalyzerDedupWindowSeconds = 300;
    size_t ratAnalyzerStateCapacity = 4096;
    /* Persistence chain detector (multi-mechanism persistence; opt-in). */
    bool persistChainEnable = false;
    uint32_t persistChainWindowSeconds = 600;
    uint32_t persistChainStateCapacity = 4096;
    uint32_t persistChainMinMechanisms = 3;
    /* LOLBin parent-child detector (Office/browser -> LOLBin; opt-in). */
    bool lolbinParentChildEnable = false;
    uint32_t lolbinParentChildMinScore = 50;
    /* LOLBin chain detector (repeat suspicious child launches; opt-in). */
    bool lolbinChainEnable = false;
    uint32_t lolbinChainWindowSeconds = 600;
    uint32_t lolbinChainStateCapacity = 4096;
    uint32_t lolbinChainMinDistinctChildren = 3;
    /* PowerShell download-execute chain detector (opt-in). */
    bool powershellDownloadExecuteEnable = false;
    uint32_t powershellDownloadExecuteWindowSeconds = 600;
    uint32_t powershellDownloadExecuteStateCapacity = 4096;
    uint32_t powershellDownloadExecuteMinDistinctScripts = 3;
    /* RDP session chain detector (opt-in). */
    bool rdpChainEnable = false;
    uint32_t rdpChainWindowSeconds = 600;
    uint32_t rdpChainStateCapacity = 4096;
    uint32_t rdpChainMinDistinctSources = 2;
    /* UAC bypass chain detector (opt-in). */
    bool uacBypassEnable = false;
    uint32_t uacBypassWindowSeconds = 300;
    uint32_t uacBypassStateCapacity = 1024;
    uint32_t uacBypassMinDistinctKeys = 1;
    /* WMI persistence chain detector (opt-in). */
    bool wmiPersistenceEnable = false;
    uint32_t wmiPersistenceWindowSeconds = 600;
    uint32_t wmiPersistenceStateCapacity = 4096;
    uint32_t wmiPersistenceMinMatches = 1;
    /* Ransomware precursor correlator (shadow/backup/log wipe; opt-in). */
    bool ransomPrecursorEnable = false;
    uint32_t ransomPrecursorWindowSeconds = 180;
    uint32_t ransomPrecursorStateCapacity = 256;
    uint32_t ransomPrecursorMinTechniques = 2;
    uint32_t ransomPrecursorDedupSeconds = 300;
    /* Memory scanner detector (in-memory injection / shellcode; opt-in). */
    bool memoryScannerEnable = false;
    uint32_t memoryScannerMinScore = 55;
    uint32_t memoryScannerDedupWindowSeconds = 60;
    size_t memoryScannerStateCapacity = 2048;
    /* Driver load detector (BYOVD / unsigned drivers; opt-in). */
    bool driverLoadEnable = false;
    uint32_t driverLoadMinScore = 55;
    uint32_t driverLoadDedupWindowSeconds = 300;
    size_t driverLoadStateCapacity = 1024;
    /* Canary (honeypot) files: decoy documents, any touch alerts. */
    bool canaryEnable = false;
    uint32_t canaryPollMs = 30000;
    uint64_t canaryMaxFileBytes = 64ULL * 1024ULL * 1024ULL;
    std::vector<std::string> canaryFiles;
    uint32_t canaryDedupWindowSeconds = 300;
    size_t canaryStateCapacity = 1024;
    /* Hook persistence surface scanner + T1546 detector (opt-in). */
    bool hookScanEnable = false;
    uint32_t hookScanPollSeconds = 600;
    size_t hookScanMaxEntries = 1024;
    bool hookPersistenceEnable = false;
    uint32_t hookPersistenceMinScore = 55;
    uint32_t hookPersistenceDedupWindowSeconds = 300;
    size_t hookPersistenceStateCapacity = 1024;
    /* Scheduled task abuse detector (T1053.005; opt-in). */
    bool taskAbuseEnable = false;
    uint32_t taskAbuseMinScore = 55;
    uint32_t taskAbuseDedupWindowSeconds = 300;
    size_t taskAbuseStateCapacity = 1024;
    uint32_t taskAbuseDeleteBurstThreshold = 5;
    uint32_t taskAbuseDeleteBurstWindowSeconds = 60;
    /* Filename masquerading detector (T1036; opt-in). */
    bool masqueradeEnable = false;
    uint32_t masqueradeMinScore = 55;
    uint32_t masqueradeDedupWindowSeconds = 300;
    size_t masqueradeStateCapacity = 2048;
    /* Parent-PID spoofing detector (T1134.004; opt-in). */
    bool ppidSpoofEnable = false;
    uint32_t ppidSpoofMinScore = 55;
    uint32_t ppidSpoofDedupWindowSeconds = 300;
    size_t ppidSpoofStateCapacity = 2048;
    /* Network discovery burst detector (T1018/T1049; opt-in). */
    bool netDiscoveryEnable = false;
    uint32_t netDiscoveryMinScore = 55;
    uint32_t netDiscoveryWindowSeconds = 300;
    uint32_t netDiscoveryBurstThreshold = 4;
    uint32_t netDiscoveryDedupWindowSeconds = 300;
    size_t netDiscoveryStateCapacity = 1024;
    /* Per-actor host profiling breadth detector (T1007/T1012/T1016/T1018/
     * T1069/T1082/T1087; opt-in). */
    bool hostProfileEnable = false;
    uint32_t hostProfileMinScore = 55;
    uint32_t hostProfileWindowSeconds = 300;
    uint32_t hostProfileMinCategories = 3;
    uint32_t hostProfileDedupWindowSeconds = 300;
    size_t hostProfileStateCapacity = 1024;
    /* Private key theft detector (T1552.004; opt-in). */
    bool privateKeyEnable = false;
    uint32_t privateKeyMinScore = 55;
    uint32_t privateKeyDedupWindowSeconds = 300;
    size_t privateKeyStateCapacity = 1024;
    /* AV / EDR tampering detector (T1562.001; opt-in). */
    bool avTamperEnable = false;
    uint32_t avTamperMinScore = 55;
    uint32_t avTamperDedupWindowSeconds = 300;
    size_t avTamperStateCapacity = 1024;
    /* Timestomping detector (T1070.006; opt-in). */
    bool timestompEnable = false;
    uint32_t timestompMinScore = 55;
    uint32_t timestompDedupWindowSeconds = 300;
    size_t timestompStateCapacity = 1024;
    /* Obfuscation detector (T1027; opt-in). */
    bool obfuscationEnable = false;
    uint32_t obfuscationMinScore = 55;
    uint32_t obfuscationDedupWindowSeconds = 300;
    size_t obfuscationStateCapacity = 1024;
    /* One-liner LSASS dump detector (T1003.001; opt-in). */
    bool lsassDumpEnable = false;
    uint32_t lsassDumpMinScore = 55;
    uint32_t lsassDumpDedupWindowSeconds = 300;
    size_t lsassDumpStateCapacity = 2048;
    /* Accessibility feature hijack detector (T1546.008; opt-in). */
    bool accessibilityHijackEnable = false;
    uint32_t accessibilityHijackMinScore = 55;
    uint32_t accessibilityHijackDedupWindowSeconds = 300;
    size_t accessibilityHijackStateCapacity = 1024;
    /* ACL abuse detector (T1222.001/T1222.002; opt-in). */
    bool aclAbuseEnable = false;
    uint32_t aclAbuseMinScore = 55;
    uint32_t aclAbuseDedupWindowSeconds = 300;
    size_t aclAbuseStateCapacity = 1024;
    /* AMSI bypass detector (T1562.001; opt-in). */
    bool amsiBypassEnable = false;
    uint32_t amsiBypassMinScore = 55;
    uint32_t amsiBypassDedupWindowSeconds = 300;
    size_t amsiBypassStateCapacity = 1024;
    /* AppInit DLL persistence detector (T1546.010; opt-in). */
    bool appInitDllEnable = false;
    uint32_t appInitDllMinScore = 55;
    uint32_t appInitDllDedupWindowSeconds = 300;
    size_t appInitDllStateCapacity = 1024;
    /* AS-REP roasting detector (T1558.004; opt-in). */
    bool asRepRoastEnable = false;
    uint32_t asRepRoastWindowSeconds = 300;
    size_t asRepRoastStateCapacity = 2048;
    uint32_t asRepRoastDedupSeconds = 300;
    /* Boot provider persistence detector (T1547.003/T1547.012; opt-in). */
    bool bootProviderEnable = false;
    uint32_t bootProviderMinScore = 55;
    uint32_t bootProviderDedupWindowSeconds = 300;
    size_t bootProviderStateCapacity = 1024;
    /* Certificate trust abuse detector (T1553.004/T1552.004; opt-in). */
    bool certAbuseEnable = false;
    uint32_t certAbuseMinScore = 55;
    uint32_t certAbuseDedupWindowSeconds = 300;
    size_t certAbuseStateCapacity = 1024;
    /* COR profiler hijack detector (T1574.012; opt-in). */
    bool corProfilerEnable = false;
    uint32_t corProfilerMinScore = 55;
    uint32_t corProfilerDedupWindowSeconds = 300;
    size_t corProfilerStateCapacity = 1024;
    /* Credential file hunt detector (T1552.001; opt-in). */
    bool credFileHuntEnable = false;
    uint32_t credFileHuntMinScore = 55;
    uint32_t credFileHuntDedupWindowSeconds = 300;
    size_t credFileHuntStateCapacity = 1024;
    /* DCSync detector (T1003.006; opt-in). */
    bool dcsyncEnable = false;
    uint32_t dcsyncMinScore = 55;
    uint32_t dcsyncDedupWindowSeconds = 300;
    size_t dcsyncStateCapacity = 1024;
    /* Dev util proxy detector (T1127 / T1218.004; opt-in). */
    bool devUtilProxyEnable = false;
    uint32_t devUtilProxyMinScore = 55;
    uint32_t devUtilProxyDedupWindowSeconds = 300;
    size_t devUtilProxyStateCapacity = 1024;
    /* Disk wipe detector (T1485/T1561; opt-in). */
    bool diskWipeEnable = false;
    uint32_t diskWipeMinScore = 55;
    uint32_t diskWipeDedupWindowSeconds = 300;
    size_t diskWipeStateCapacity = 1024;
    /* Agent health heartbeat (observability only; opt-in). */
    bool healthEnable = false;
    uint32_t healthPollSeconds = 300;
    /* Effective only with healthEnable; defaults preserve existing timing. */
    bool healthDispatchTimingEnable = true;
    uint32_t healthDispatchSlowWarnUs = 50000;
    uint32_t healthDispatchWarnCooldownSeconds = 30;
    /* Fileless attack detector (PS/WMI in-memory techniques; opt-in). */
    bool filelessEnable = false;
    uint32_t filelessMinScore = 55;
    uint32_t filelessDedupWindowSeconds = 300;
    size_t filelessStateCapacity = 4096;
    /* API hook detector (ETW/AMSI/API hooking; opt-in). */
    bool apiHookEnable = false;
    uint32_t apiHookMinScore = 55;
    uint32_t apiHookDedupWindowSeconds = 300;
    size_t apiHookStateCapacity = 1024;
    /* Remote access / remote support tool detector (opt-in). */
    bool remoteAccessEnable = false;
    uint32_t remoteAccessWindowSeconds = 300;
    size_t remoteAccessStateCapacity = 2048;
    /* Credential dumping detector (T1003; opt-in). */
    bool credentialDumpEnable = false;
    uint32_t credentialDumpWindowSeconds = 300;
    size_t credentialDumpStateCapacity = 4096;
    /* Data exfiltration detector (T1048; opt-in). */
    bool dataExfilEnable = false;
    uint32_t dataExfilWindowSeconds = 300;
    size_t dataExfilStateCapacity = 4096;
    uint32_t dataExfilDnsTunnelThreshold = 50;
    /* Privilege escalation detector (T1134/T1068; opt-in). */
    bool privEscEnable = false;
    uint32_t privEscWindowSeconds = 300;
    size_t privEscStateCapacity = 4096;
    /* NTLM relay detector (T1550; opt-in). */
    bool ntlmRelayEnable = false;
    uint32_t ntlmRelayWindowSeconds = 600;
    size_t ntlmRelayStateCapacity = 4096;
    uint32_t ntlmRelayMinEvents = 3;
    /* Browser data theft detector (T1555; opt-in). */
    bool browserTheftEnable = false;
    uint32_t browserTheftWindowSeconds = 300;
    size_t browserTheftStateCapacity = 2048;
    /* Browser extension side-loading / forced-install detector (T1176). */
    bool browserExtensionEnable = false;
    uint32_t browserExtensionMinScore = 55;
    uint32_t browserExtensionDedupWindowSeconds = 300;
    size_t browserExtensionStateCapacity = 1024;
    std::vector<std::string> browserExtensionAllowlist;
    /* Archive staging detector (T1560.001; opt-in). */
    bool archiveStagingEnable = false;
    uint32_t archiveStagingWindowSeconds = 300;
    size_t archiveStagingStateCapacity = 2048;
    /* BITS abuse detector (T1197; opt-in). */
    bool bitsAbuseEnable = false;
    uint32_t bitsAbuseWindowSeconds = 300;
    size_t bitsAbuseStateCapacity = 2048;
    /* DoH abuse detector (T1071.004; opt-in). */
    bool dohAbuseEnable = false;
    uint32_t dohAbuseWindowSeconds = 300;
    size_t dohAbuseStateCapacity = 2048;
    uint32_t dohAbuseMinRepeatCount = 3;
    /* Service install abuse detector (T1543.003; opt-in). */
    bool svcInstallEnable = false;
    /* Shadow-copy suppression detector (T1490; opt-in). */
    bool shadowCopyEnable = false;
    uint32_t shadowCopyMinScore = 55;
    uint32_t shadowCopyDedupWindowSeconds = 300;
    size_t shadowCopyStateCapacity = 1024;
    /* Mass-persistence ransomware precursor (opt-in). */
    bool persistBurstEnable = false;
    uint32_t persistBurstWindowSeconds = 300;
    size_t persistBurstStateCapacity = 1024;
    uint32_t persistBurstMinScore = 55;
    uint32_t persistBurstDedupSeconds = 300;
    /* CMSTP / INF proxy execution detector (T1218.003 / T1127; opt-in). */
    bool cmstpBypassEnable = false;
    uint32_t cmstpBypassMinScore = 55;
    uint32_t cmstpBypassDedupWindowSeconds = 300;
    size_t cmstpBypassStateCapacity = 1024;
    /* File association hijack detector (T1546.001; opt-in). */
    bool fileAssocEnable = false;
    uint32_t fileAssocMinScore = 55;
    uint32_t fileAssocDedupWindowSeconds = 300;
    size_t fileAssocStateCapacity = 1024;
    /* Hidden window / concealed execution detector (T1564.003; opt-in). */
    bool hiddenWindowEnable = false;
    uint32_t hiddenWindowMinScore = 55;
    uint32_t hiddenWindowDedupWindowSeconds = 300;
    size_t hiddenWindowStateCapacity = 1024;
    /* Office application-startup persistence detector (T1137; opt-in). */
    bool officePersistEnable = false;
    uint32_t officePersistMinScore = 55;
    uint32_t officePersistDedupWindowSeconds = 300;
    size_t officePersistStateCapacity = 1024;
    /* Startup-folder shortcut persistence detector (T1547.009; opt-in). */
    bool shortcutPersistEnable = false;
    uint32_t shortcutPersistMinScore = 55;
    uint32_t shortcutPersistDedupWindowSeconds = 300;
    size_t shortcutPersistStateCapacity = 1024;
    /* Indirect command execution detector (T1202; opt-in). */
    bool indirectExecEnable = false;
    uint32_t indirectExecMinScore = 55;
    uint32_t indirectExecDedupWindowSeconds = 300;
    size_t indirectExecStateCapacity = 1024;
    /* Screensaver persistence detector (T1546.002; opt-in). */
    bool screensaverPersistEnable = false;
    uint32_t screensaverPersistMinScore = 55;
    uint32_t screensaverPersistDedupWindowSeconds = 300;
    size_t screensaverPersistStateCapacity = 1024;
    /* Service path abuse detector (T1574.009 / T1574.010; opt-in). */
    bool svcPathAbuseEnable = false;
    uint32_t svcPathAbuseMinScore = 55;
    uint32_t svcPathAbuseDedupWindowSeconds = 300;
    size_t svcPathAbuseStateCapacity = 1024;
    /* ServiceDll hijack detector (T1574.011; opt-in). */
    bool serviceDllHijackEnable = false;
    uint32_t serviceDllHijackMinScore = 55;
    uint32_t serviceDllHijackDedupWindowSeconds = 300;
    size_t serviceDllHijackStateCapacity = 1024;
    /* DLL search order hijack detector (T1574.002; opt-in). */
    bool dllSearchOrderEnable = false;
    uint32_t dllSearchOrderMinScore = 55;
    uint32_t dllSearchOrderDedupWindowSeconds = 300;
    size_t dllSearchOrderStateCapacity = 1024;
    /* Service recovery hijack detector (T1037.004; opt-in). */
    bool svcRecoveryEnable = false;
    uint32_t svcRecoveryMinScore = 55;
    uint32_t svcRecoveryDedupWindowSeconds = 300;
    size_t svcRecoveryStateCapacity = 1024;
    /* ComHijackDetector (T1546.015; opt-in). */
    bool comHijackEnable = false;
    uint32_t comHijackMinScore = 55;
    uint32_t comHijackDedupWindowSeconds = 300;
    size_t comHijackStateCapacity = 1024;
    /* WinlogonHijackDetector (T1547.004; opt-in). */
    bool winlogonHijackEnable = false;
    uint32_t winlogonHijackMinScore = 55;
    uint32_t winlogonHijackDedupWindowSeconds = 300;
    size_t winlogonHijackStateCapacity = 1024;
    /* MshtaAbuseDetector (T1218.005; opt-in). */
    bool mshtaAbuseEnable = false;
    uint32_t mshtaAbuseMinScore = 55;
    uint32_t mshtaAbuseDedupWindowSeconds = 300;
    size_t mshtaAbuseStateCapacity = 1024;
    /* .NET registration proxy execution detector (T1218.009; opt-in). */
    bool dotnetProxyExecEnable = false;
    uint32_t dotnetProxyExecMinScore = 55;
    uint32_t dotnetProxyExecDedupWindowSeconds = 300;
    size_t dotnetProxyExecStateCapacity = 1024;
    /* WslAbuseDetector (T1202; opt-in). */
    bool wslAbuseEnable = false;
    uint32_t wslAbuseMinScore = 55;
    uint32_t wslAbuseDedupWindowSeconds = 300;
    size_t wslAbuseStateCapacity = 1024;
    /* SoftwareDiscoveryDetector (T1518/T1518.001; opt-in). */
    bool softwareDiscoveryEnable = false;
    uint32_t softwareDiscoveryMinScore = 55;
    uint32_t softwareDiscoveryWindowSeconds = 300;
    uint32_t softwareDiscoveryMinCategories = 2;
    uint32_t softwareDiscoveryDedupWindowSeconds = 300;
    size_t softwareDiscoveryStateCapacity = 1024;
    /* NetShareDiscoveryDetector (T1135; opt-in). */
    bool netShareDiscoveryEnable = false;
    uint32_t netShareDiscoveryMinScore = 55;
    uint32_t netShareDiscoveryWindowSeconds = 300;
    uint32_t netShareDiscoveryMinCommands = 3;
    uint32_t netShareDiscoveryDedupWindowSeconds = 300;
    size_t netShareDiscoveryStateCapacity = 1024;
    /* NonstandardPortEgressDetector (T1095/T1571; opt-in). */
    bool nonstandardPortEgressEnable = false;
    uint32_t nonstandardPortEgressMinScore = 55;
    uint32_t nonstandardPortEgressWindowSeconds = 300;
    uint32_t nonstandardPortEgressDedupWindowSeconds = 300;
    size_t nonstandardPortEgressStateCapacity = 1024;
    /* MsdtAbuseDetector (T1203; opt-in). */
    bool msdtAbuseEnable = false;
    uint32_t msdtAbuseMinScore = 55;
    uint32_t msdtAbuseDedupWindowSeconds = 300;
    size_t msdtAbuseStateCapacity = 1024;
    /* IsoMountDetector (T1553.005; opt-in). */
    bool isoMountEnable = false;
    uint32_t isoMountMinScore = 55;
    uint32_t isoMountDedupWindowSeconds = 300;
    size_t isoMountStateCapacity = 1024;
    bool psProfileEnable = false;
    uint32_t psProfileMinScore = 55;
    uint32_t psProfileDedupWindowSeconds = 300;
    size_t psProfileStateCapacity = 1024;
    /* DowngradeAttackDetector (opt-in). */
    bool downgradeAttackEnable = false;
    uint32_t downgradeAttackMinScore = 55;
    uint32_t downgradeAttackDedupWindowSeconds = 300;
    size_t downgradeAttackStateCapacity = 1024;
    /* DpapiAbuseDetector (opt-in). */
    bool dpapiAbuseEnable = false;
    uint32_t dpapiAbuseMinScore = 55;
    uint32_t dpapiAbuseDedupWindowSeconds = 300;
    size_t dpapiAbuseStateCapacity = 1024;
    /* EmailCollectionDetector (opt-in). */
    bool emailCollectionEnable = false;
    uint32_t emailCollectionMinScore = 55;
    uint32_t emailCollectionDedupWindowSeconds = 300;
    size_t emailCollectionStateCapacity = 1024;
    /* EtwScriptTamperDetector (opt-in). */
    bool etwScriptTamperEnable = false;
    uint32_t etwScriptTamperMinScore = 55;
    uint32_t etwScriptTamperDedupWindowSeconds = 300;
    size_t etwScriptTamperStateCapacity = 1024;
    /* ForcedAuthDetector (opt-in). */
    bool forcedAuthEnable = false;
    uint32_t forcedAuthMinScore = 55;
    uint32_t forcedAuthDedupWindowSeconds = 300;
    size_t forcedAuthStateCapacity = 1024;
    /* GoldenTicketDetector (opt-in). */
    bool goldenTicketEnable = false;
    uint32_t goldenTicketMinScore = 55;
    uint32_t goldenTicketDedupWindowSeconds = 300;
    size_t goldenTicketStateCapacity = 1024;
    uint32_t goldenTicketWindowSeconds = 600;
    uint32_t goldenTicketMinRepeatCount = 3;
    /* GpoAbuseDetector (opt-in). */
    bool gpoAbuseEnable = false;
    uint32_t gpoAbuseMinScore = 55;
    uint32_t gpoAbuseDedupWindowSeconds = 300;
    size_t gpoAbuseStateCapacity = 1024;
    /* HiddenArtifactsDetector (opt-in). */
    bool hiddenArtifactsEnable = false;
    uint32_t hiddenArtifactsMinScore = 55;
    uint32_t hiddenArtifactsDedupWindowSeconds = 300;
    size_t hiddenArtifactsStateCapacity = 1024;
    uint32_t hiddenArtifactsWindowSeconds = 600;

    /* HistoryTamperDetector (opt-in). */
    bool historyTamperEnable = false;
    uint32_t historyTamperMinScore = 55;
    uint32_t historyTamperDedupWindowSeconds = 300;
    size_t historyTamperStateCapacity = 1024;
    /* HiveCopyDetector (opt-in). */
    bool hiveCopyEnable = false;
    uint32_t hiveCopyMinScore = 55;
    uint32_t hiveCopyDedupWindowSeconds = 300;
    size_t hiveCopyStateCapacity = 1024;
    /* HostsRedirectDetector (opt-in). */
    bool hostsRedirectEnable = false;
    uint32_t hostsRedirectMinScore = 55;
    uint32_t hostsRedirectDedupWindowSeconds = 300;
    size_t hostsRedirectStateCapacity = 1024;
    /* IisModuleDetector (opt-in). */
    bool iisModuleEnable = false;
    uint32_t iisModuleMinScore = 55;
    uint32_t iisModuleDedupWindowSeconds = 300;
    size_t iisModuleStateCapacity = 1024;
    /* InputSimulationDetector (opt-in). */
    bool inputSimulationEnable = false;
    uint32_t inputSimulationMinScore = 55;
    uint32_t inputSimulationDedupWindowSeconds = 300;
    size_t inputSimulationStateCapacity = 1024;
    uint32_t inputSimulationWindowSeconds = 600;
    uint32_t inputSimulationBurstThreshold = 40;
    /* LogonScriptPersistDetector (opt-in). */
    bool logonScriptPersistEnable = false;
    uint32_t logonScriptPersistMinScore = 55;
    uint32_t logonScriptPersistDedupWindowSeconds = 300;
    size_t logonScriptPersistStateCapacity = 1024;
    /* LsaPackageDetector (opt-in). */
    bool lsaPackageEnable = false;
    uint32_t lsaPackageMinScore = 55;
    uint32_t lsaPackageDedupWindowSeconds = 300;
    size_t lsaPackageStateCapacity = 1024;
    /* MotwBypassDetector (opt-in). */
    bool motwBypassEnable = false;
    uint32_t motwBypassMinScore = 55;
    uint32_t motwBypassDedupWindowSeconds = 300;
    size_t motwBypassStateCapacity = 1024;
    /* NetshHelperDetector (opt-in). */
    bool netshHelperEnable = false;
    uint32_t netshHelperMinScore = 55;
    uint32_t netshHelperDedupWindowSeconds = 300;
    size_t netshHelperStateCapacity = 1024;
    /* NetworkSniffingDetector (opt-in). */
    bool networkSniffingEnable = false;
    uint32_t networkSniffingMinScore = 55;
    uint32_t networkSniffingDedupWindowSeconds = 300;
    size_t networkSniffingStateCapacity = 1024;
    /* NtdsDitDetector (opt-in). */
    bool ntdsDitEnable = false;
    uint32_t ntdsDitMinScore = 55;
    uint32_t ntdsDitDedupWindowSeconds = 300;
    size_t ntdsDitStateCapacity = 1024;
    /* PassTheHashDetector (opt-in). */
    bool passTheHashEnable = false;
    uint32_t passTheHashMinScore = 55;
    uint32_t passTheHashDedupWindowSeconds = 300;
    size_t passTheHashStateCapacity = 1024;
    /* PasswordCrackingDetector (opt-in). */
    bool passwordCrackingEnable = false;
    uint32_t passwordCrackingMinScore = 55;
    uint32_t passwordCrackingDedupWindowSeconds = 300;
    size_t passwordCrackingStateCapacity = 1024;
    /* PathInterceptionDetector (opt-in). */
    bool pathInterceptionEnable = false;
    uint32_t pathInterceptionMinScore = 55;
    uint32_t pathInterceptionDedupWindowSeconds = 300;
    size_t pathInterceptionStateCapacity = 1024;
    /* PeAnomalyDetector (opt-in). */
    bool peAnomalyEnable = false;
    uint32_t peAnomalyMinScore = 55;
    uint32_t peAnomalyDedupWindowSeconds = 300;
    size_t peAnomalyStateCapacity = 1024;
    uint64_t peAnomalyMaxFileBytes = 8388608;
    /* RansomOpsDetector (opt-in). */
    bool ransomOpsEnable = false;
    uint32_t ransomOpsMinScore = 55;
    uint32_t ransomOpsDedupWindowSeconds = 300;
    size_t ransomOpsStateCapacity = 1024;
    /* RdpSessionHijackDetector (opt-in). */
    bool rdpSessionHijackEnable = false;
    uint32_t rdpSessionHijackMinScore = 55;
    uint32_t rdpSessionHijackDedupWindowSeconds = 300;
    size_t rdpSessionHijackStateCapacity = 1024;
    /* RegCredHuntDetector (opt-in). */
    bool regCredHuntEnable = false;
    uint32_t regCredHuntMinScore = 55;
    uint32_t regCredHuntDedupWindowSeconds = 300;
    size_t regCredHuntStateCapacity = 1024;
    /* RemoteExecDetector (opt-in). */
    bool remoteExecEnable = false;
    uint32_t remoteExecMinScore = 55;
    uint32_t remoteExecDedupWindowSeconds = 300;
    size_t remoteExecStateCapacity = 1024;
    /* SecbootTamperDetector (opt-in). */
    bool secbootTamperEnable = false;
    uint32_t secbootTamperMinScore = 55;
    uint32_t secbootTamperDedupWindowSeconds = 300;
    size_t secbootTamperStateCapacity = 1024;
    /* ShimDbDetector (opt-in). */
    bool shimDbEnable = false;
    uint32_t shimDbMinScore = 55;
    uint32_t shimDbDedupWindowSeconds = 300;
    size_t shimDbStateCapacity = 1024;
    /* SignedBinaryAbuseDetector (opt-in). */
    bool signedBinaryAbuseEnable = false;
    uint32_t signedBinaryAbuseMinScore = 55;
    uint32_t signedBinaryAbuseDedupWindowSeconds = 300;
    size_t signedBinaryAbuseStateCapacity = 1024;
    /* SipHijackDetector (opt-in). */
    bool sipHijackEnable = false;
    uint32_t sipHijackMinScore = 55;
    uint32_t sipHijackDedupWindowSeconds = 300;
    size_t sipHijackStateCapacity = 1024;
    /* SshKeyPersistenceDetector (opt-in). */
    bool sshKeyPersistenceEnable = false;
    uint32_t sshKeyPersistenceMinScore = 55;
    uint32_t sshKeyPersistenceDedupWindowSeconds = 300;
    size_t sshKeyPersistenceStateCapacity = 1024;
    /* TicketCacheAbuseDetector (opt-in). */
    bool ticketCacheAbuseEnable = false;
    uint32_t ticketCacheAbuseMinScore = 55;
    uint32_t ticketCacheAbuseDedupWindowSeconds = 300;
    size_t ticketCacheAbuseStateCapacity = 1024;
    /* TokenImpersonationDetector (opt-in). */
    bool tokenImpersonationEnable = false;
    uint32_t tokenImpersonationMinScore = 55;
    uint32_t tokenImpersonationDedupWindowSeconds = 300;
    size_t tokenImpersonationStateCapacity = 1024;
    /* HandleGuardDetector (opt-in; consumes driver HANDLE_OPEN events). */
    bool handleGuardEnable = false;
    uint32_t handleGuardMinScore = 55;
    uint32_t handleGuardDedupWindowSeconds = 300;
    size_t handleGuardStateCapacity = 1024;
    /* NamedPipeAbuseDetector (opt-in; consumes NAMED_PIPE ETW events). */
    bool namedPipeAbuseEnable = false;
    uint32_t namedPipeAbuseMinScore = 55;
    uint32_t namedPipeAbuseWindowSeconds = 120;
    size_t namedPipeAbuseStateCapacity = 4096;
    uint32_t namedPipeAbuseMinDistinctPids = 2;
    uint32_t namedPipeAbuseDedupWindowSeconds = 300;
    /* WebExfilDetector (opt-in). */
    bool webExfilEnable = false;
    uint32_t webExfilMinScore = 55;
    uint32_t webExfilDedupWindowSeconds = 300;
    size_t webExfilStateCapacity = 1024;
    /* WifiCredTheftDetector (opt-in). */
    bool wifiCredTheftEnable = false;
    uint32_t wifiCredTheftMinScore = 55;
    uint32_t wifiCredTheftDedupWindowSeconds = 300;
    size_t wifiCredTheftStateCapacity = 1024;
    uint32_t wifiCredTheftWindowSeconds = 600;
    uint32_t wifiCredTheftMinRepeatCount = 3;
    /* WinrmAbuseDetector (opt-in). */
    bool winrmAbuseEnable = false;
    uint32_t winrmAbuseMinScore = 55;
    uint32_t winrmAbuseDedupWindowSeconds = 300;
    size_t winrmAbuseStateCapacity = 1024;
    /* WinrmConfigTamperDetector (opt-in). */
    bool winrmConfigTamperEnable = false;
    uint32_t winrmConfigTamperMinScore = 55;
    uint32_t winrmConfigTamperDedupWindowSeconds = 300;
    size_t winrmConfigTamperStateCapacity = 1024;
    /* XslScriptDetector (opt-in). */
    bool xslScriptEnable = false;
    uint32_t xslScriptMinScore = 55;
    uint32_t xslScriptDedupWindowSeconds = 300;
    size_t xslScriptStateCapacity = 1024;
    /* Cryptominer detector (T1496; opt-in). */
    bool cryptoMinerEnable = false;
    uint32_t cryptoMinerWindowSeconds = 600;
    size_t cryptoMinerStateCapacity = 2048;
    /* Anti-analysis / evasion detector (T1497; opt-in). */
    bool antiAnalysisEnable = false;
    uint32_t antiAnalysisWindowSeconds = 300;
    size_t antiAnalysisStateCapacity = 4096;
    /* Script host abuse detector (T1059.005/007, T1105, T1218.005; opt-in). */
    bool scriptHostAbuseEnable = false;
    /* Account operation detector (T1136.001, T1098.001, T1087.001; opt-in). */
    bool accountOpEnable = false;
    /* Tunneling / port-forwarding tool detector (T1572, T1090; opt-in). */
    bool tunnelToolEnable = false;
    /* User-activity surveillance detector (T1115/T1113/T1056.001/T1125; opt-in). */
    bool surveillanceEnable = false;
    uint32_t surveillanceWindowSeconds = 300;
    size_t surveillanceStateCapacity = 4096;
    uint32_t surveillanceMinSignals = 2;
    /* Clipboard collection detector (T1115; opt-in). */
    bool clipboardTheftEnable = false;
    uint32_t clipboardTheftMinScore = 55;
    uint32_t clipboardTheftWindowSeconds = 120;
    size_t clipboardTheftStateCapacity = 4096;
    uint32_t clipboardTheftMinReads = 3;
    uint32_t clipboardTheftDedupWindowSeconds = 300;
    /* Web shell staging detector (T1505.003; opt-in). */
    bool webshellEnable = false;
    size_t webshellStateCapacity = 1024;
    uint32_t webshellDedupSeconds = 300;
    /* Removable-media exfiltration detector (T1025; opt-in). */
    bool usbExfilEnable = false;
    uint32_t usbExfilWindowSeconds = 300;
    size_t usbExfilStateCapacity = 1024;
    uint32_t usbExfilMinFileCount = 10;
    uint32_t usbExfilDedupSeconds = 600;
    /* Firewall rule tamper detector (T1562.004; opt-in). */
    bool firewallRuleEnable = false;
    /* Share change detector (T1021.002 / T1070.005; opt-in). */
    bool shareChangeEnable = false;
    /* Local account detector (T1136.001 / T1098.001; opt-in). */
    bool localAccountEnable = false;
    /* Security-control registry tamper detector (T1112; opt-in).
     * UAC / LSA / SMB signing / machine PowerShell policy / SmartScreen
     * downgrades, with same-host multi-key breadth escalation. */
    bool regModifyEnable = false;
    uint32_t regModifyMinScore = 55;
    uint32_t regModifyDedupWindowSeconds = 300;
    size_t regModifyStateCapacity = 1024;
    /* WMI/CIM execution detector (T1047; opt-in).
     * wmic process call create, /node: remote execution, PowerShell
     * Invoke-CimMethod/Invoke-WmiMethod Create and Win32_Process.Create. */
    bool wmiExecEnable = false;
    uint32_t wmiExecMinScore = 55;
    uint32_t wmiExecDedupWindowSeconds = 300;
    size_t wmiExecStateCapacity = 1024;
    /* Local bulk collection / staging detector (T1005; opt-in).
     * Profile-directory enumeration + copy to a staging path, profile
     * packaging, and short-window document READ bursts. */
    bool localCollectEnable = false;
    uint32_t localCollectMinScore = 55;
    uint32_t localCollectDedupWindowSeconds = 300;
    size_t localCollectStateCapacity = 1024;
    /* Lateral tool transfer detector (T1570; opt-in).
     * Remote-share tool pull/push, remote payload execution, esentutl UNC
     * copies and PowerShell -FromSession transfers. */
    bool lateralTransferEnable = false;
    uint32_t lateralTransferMinScore = 55;
    uint32_t lateralTransferDedupWindowSeconds = 300;
    size_t lateralTransferStateCapacity = 1024;
    /* Behavior enrichment (chain scoring + LSASS read bursts; opt-in). */
    bool behaviorEnrichEnable = false;
    uint32_t behaviorEnrichStateCapacity = 8192;
    uint32_t behaviorEnrichWindowSeconds = 300;
    uint32_t behaviorEnrichLsassBurstWindowSeconds = 60;
    uint64_t behaviorEnrichLsassBurstThresholdBytes = 4194304ULL;
    /* Process injection chain detector (cross-process injection correlation; opt-in). */
    bool injectChainEnable = false;
    uint32_t injectChainStateCapacity = 4096;
    uint32_t injectChainWindowSeconds = 60;
    uint32_t injectChainMinTransitionScore = 0;
    /* Attack chain detector (per-process tactic chain; opt-in). */
    bool attackChainEnable = false;
    uint32_t attackChainStateCapacity = 4096;
    uint32_t attackChainWindowSeconds = 600;
    /* C2 beacon detector (periodic outbound connections; opt-in). */
    bool c2BeaconEnable = false;
    uint32_t c2BeaconWindowSeconds = 3600;
    uint32_t c2BeaconStateCapacity = 4096;
    uint32_t c2BeaconMinRepeatEndpoints = 3;
    uint32_t c2BeaconMinConnectionsPerEndpoint = 2;
    /* Ransomware burst detector (bulk file creation; opt-in). */
    bool ransomBurstEnable = false;
    uint32_t ransomBurstWindowSeconds = 120;
    uint32_t ransomBurstStateCapacity = 8192;
    uint32_t ransomBurstMinFileCount = 30;
    uint32_t ransomBurstMinDistinctExtensions = 15;
    /* Process hollowing detector (masquerading/staging proxy; opt-in). */
    bool processHollowingEnable = false;
    uint32_t processHollowingMinScore = 55;
    uint32_t processHollowingDedupWindowSeconds = 30;
    size_t processHollowingStateCapacity = 1024;
    /* DLL search-order hijack / sideload detector (opt-in). */
    bool dllHijackEnable = false;
    /* Registry persistence detector (T1547; opt-in). */
    bool registryPersistenceEnable = false;
    uint32_t registryPersistenceWindowSeconds = 300;
    size_t registryPersistenceStateCapacity = 2048;
    /* Anti-forensics detector (log clearing T1070.002; opt-in). */
    bool antiForensicsEnable = false;
    uint32_t antiForensicsWindowSeconds = 300;
    size_t antiForensicsStateCapacity = 1024;
    /* System time-change evasion detector (4616; opt-in). */
    bool timeChangeEnable = false;
    uint32_t timeChangeWindowSeconds = 300;
    size_t timeChangeStateCapacity = 1024;
    uint32_t timeChangeToleranceSeconds = 5;
    uint32_t timeChangeBigJumpSeconds = 86400;
    /* Privileged-group membership modification detector (T1098/T1078.002;
     * opt-in). */
    bool privilegedGroupEnable = false;
    uint32_t privilegedGroupWindowSeconds = 600;
    size_t privilegedGroupStateCapacity = 1024;
    /* Host-wide defense-evasion correlation (opt-in). */
    bool defenseEvasionEnable = false;
    uint32_t defenseEvasionWindowSeconds = 300;
    uint32_t defenseEvasionStateCapacity = 1024;
    uint32_t defenseEvasionMinTechniques = 2;
    uint32_t defenseEvasionDedupSeconds = 600;
    /* Host-wide system/domain/network discovery correlation (opt-in). */
    bool discoveryReconEnable = false;
    uint32_t discoveryReconWindowSeconds = 300;
    uint32_t discoveryReconStateCapacity = 2048;
    uint32_t discoveryReconMinTechniques = 3;
    uint32_t discoveryReconDedupSeconds = 600;
    /* Logon brute-force detector (Security 4625 failure correlation; opt-in). */
    bool logonSuccessEnable = false;
    uint32_t logonSuccessWindowSeconds = 300;
    uint32_t logonSuccessStateCapacity = 8192;
    uint32_t logonSuccessMinFailures = 10;

    bool logonBruteForceEnable = false;
    uint32_t logonBruteForceWindowSeconds = 300;
    uint32_t logonBruteForceStateCapacity = 8192;
    uint32_t logonBruteForceMinFailures = 10;
    uint32_t logonBruteForceDedupSeconds = 600;
    /* Password spray + success-after-spray correlation (opt-in). */
    bool passwordSprayEnable = false;
    uint32_t passwordSprayWindowSeconds = 900;
    uint32_t passwordSprayStateCapacity = 4096;
    uint32_t passwordSprayMinFailures = 10;
    uint32_t passwordSprayMinDistinctUsers = 5;
    uint32_t passwordSpraySuccessFollowupSeconds = 300;
    uint32_t passwordSprayDedupSeconds = 600;
    size_t passwordSprayMaxFailuresPerSource = 256;
    /* Kerberoasting RC4 service-ticket burst correlation (opt-in). */
    bool kerberoastBurstEnable = false;
    uint32_t kerberoastBurstWindowSeconds = 600;
    uint32_t kerberoastBurstStateCapacity = 4096;
    uint32_t kerberoastBurstMinServiceCount = 5;
    uint32_t kerberoastBurstDedupSeconds = 600;
    size_t kerberoastBurstMaxServicesPerRequester = 128;
    /* DNS beacon detector (DGA / high-entropy domain flooding; opt-in). */
    bool dnsFailureEnable = false;
    uint32_t dnsFailureWindowSeconds = 300;
    uint32_t dnsFailureStateCapacity = 2048;
    uint32_t dnsFailureMinQueries = 20;
    uint32_t dnsFailureMinDistinctNames = 10;
    uint32_t dnsFailureMinFailurePercent = 80;
    uint32_t dnsFailureMinHighEntropyFailures = 5;

    bool dnsBeaconEnable = false;
    uint32_t dnsBeaconWindowSeconds = 300;
    uint32_t dnsBeaconStateCapacity = 4096;
    uint32_t dnsBeaconMinQueryCount = 50;
    uint32_t dnsBeaconMinHighEntropyCount = 20;
    /* Behavior learning baseline (per-image child/dir/endpoint deviation;
     * opt-in. Empty baselinePath keeps the baseline memory-only. */
    bool behaviorBaselineEnable = false;
    uint32_t behaviorBaselineTrainingSeconds = 86400;
    uint32_t behaviorBaselineWindowSeconds = 3600;
    uint32_t behaviorBaselineDedupSeconds = 600;
    size_t behaviorBaselineStateCapacity = 4096;
    uint32_t behaviorBaselineMinScore = 55;
    uint32_t behaviorBaselinePollutionScore = 75;
    size_t behaviorBaselineMaxObservations = 64;
    uint32_t behaviorBaselineMaxAgeDays = 30;
    std::string behaviorBaselinePath;
    /* Lateral movement detector (multi-host scanning on lateral ports; opt-in). */
    bool lateralMoveEnable = false;
    uint32_t lateralMoveWindowSeconds = 120;
    uint32_t lateralMoveStateCapacity = 4096;
    uint32_t lateralMoveMinDestCount = 5;
    uint32_t lateralMoveScorePerDest = 15;
    /* Port-scan detector (distinct dest ports on one IP; opt-in). */
    bool portScanEnable = false;
    uint32_t portScanWindowSeconds = 30;
    uint32_t portScanStateCapacity = 4096;
    uint32_t portScanMinDistinctPorts = 20;
    bool enableIMonitor = true;     /* iMonitor kernel monitoring */
    bool enableSysmon = false;      /* Sysmon Operational event log */
    bool enableSysmonImageLoad = false; /* noisy Sysmon ID 7, separately opt-in */
    bool enableSysmonProcessAccess = false; /* noisy Sysmon ID 10, opt-in */
    bool enableSysmonRemoteThread = false; /* Sysmon ID 8 (CreateRemoteThread), opt-in */
    bool enableIMonitorProcessOpen = false; /* iMonitor PROCESS_OPEN, opt-in */
    bool enableIMonitorRemoteThread = false; /* iMonitor THREAD_CREATE, opt-in */
    bool enableIMonitorCredentialMonitor = false; /* iMonitor PROCESS_READ/FILE_READ (hive reads), opt-in */
    bool enableIMonitorInjectionDeep = false; /* iMonitor APC/CONTEXT/MEMORY_WRITE, opt-in */
    bool enableHooksRpcCreateProcess = false; /* RPC remote process creation hook */
    bool enableHooksWindowsHook = false; /* SetWindowsHookEx hook */
    bool enableHooksService = false; /* Service create/start/config hooks */
    bool enableHooksCom = false; /* CoCreateInstance hook */
    bool enableHooksInjection = false; /* MapViewOfSection + injection hooks */
    bool enableHooksHandle = false; /* DuplicateHandle hook */
    bool enableHooksInput = false; /* SendInput hook */
    bool enableHooksSystem = false; /* Shutdown/SetSystemTime hooks */
    bool enableHooksSurveillance = false; /* Clipboard/Wallpaper/Camera/KeyLogger hooks */
    bool enableHooksPowerShell = false; /* PowerShell script/command hook */
    uint32_t sysmonQueueCapacity = 512;
    uint32_t sysmonWorkers = 2;
    uint32_t sysmonMaxXmlBytes = 256 * 1024;
    bool enableSecurityLog = false;
    uint32_t securityLogQueueCapacity = 4096;
    uint32_t securityLogWorkers = 4;
    uint32_t securityLogMaxXmlBytes = 512 * 1024;
    bool enableWmiCollector = false;
    uint32_t wmiQueueCapacity = 512;
    uint32_t wmiWorkers = 2;
    uint32_t wmiMaxXmlBytes = 256 * 1024;
    bool enableTaskSchedulerLog = false;
    uint32_t taskSchedulerQueueCapacity = 512;
    uint32_t taskSchedulerWorkers = 2;
    uint32_t taskSchedulerMaxXmlBytes = 128 * 1024;
    bool enableDefenderLog = false;
    uint32_t defenderQueueCapacity = 512;
    uint32_t defenderWorkers = 2;
    uint32_t defenderMaxXmlBytes = 256 * 1024;
    bool enableRdpLog = false; /* Terminal Services / RDP session log */
    uint32_t rdpLogQueueCapacity = 512;
    uint32_t rdpLogWorkers = 2;
    uint32_t rdpLogMaxXmlBytes = 128 * 1024;
    bool enablePowerShellLog = false;
    uint32_t powerShellQueueCapacity = 512;
    uint32_t powerShellWorkers = 2;
    uint32_t powerShellMaxXmlBytes = 512 * 1024;
    uint32_t powerShellMaxScriptChars = 128 * 1024;
    bool powerShellReassemblyEnable = false;
    uint32_t powerShellReassemblyMaxFragments = 64;
    uint32_t powerShellReassemblyMaxAssembledBytes = 1024 * 1024;
    uint32_t powerShellReassemblyStateCapacity = 256;
    uint32_t powerShellReassemblyMaxBufferedBytes = 32 * 1024 * 1024;
    uint32_t powerShellReassemblyTimeoutSeconds = 30;
    bool enableStartupWatch = false;
    std::vector<std::string> startupWatchDirs; /* UTF-8; expanded from env vars */
    bool enableImageLoad = false;   /* ETW image load (DLL/driver) monitor */
    uint32_t imageLoadQueueCapacity = 1024;
    bool enablePrivilegeEsc = false; /* Security log privilege escalation monitor */
    uint32_t privilegeEscQueueCapacity = 512;
    uint32_t privilegeEscWorkers = 2;
    uint32_t privilegeEscMaxXmlBytes = 256 * 1024;
    bool enableDnsEtw = false;       /* ETW-based DNS query/response monitor */
    bool enableUsbMonitor = false;   /* removable USB storage monitor */
    uint32_t usbPollMs = 5000;       /* USB snapshot interval (ms) */
    uint64_t usbDedupWindowMs = 60000; /* per-drive event rate limit (ms) */
    bool enableListenerMonitor = false; /* listening TCP/UDP port monitor */
    uint32_t listenerPollMs = 10000; /* listener snapshot interval (ms) */
    bool enableServiceMonitor = false; /* service database change monitor */
    uint32_t servicePollMs = 15000;   /* service snapshot interval (ms) */
    bool enableCriticalProcessMonitor = false; /* critical process protection */
    uint32_t criticalProcessPollMs = 5000;     /* critical process poll (ms) */
    uint32_t criticalProcessMissingThreshold = 2; /* consecutive misses before alert */
    std::vector<std::string> criticalProcessImages; /* base names, e.g. MsMpEng.exe */
    bool enableFimMonitor = false;   /* file integrity monitoring */
    uint32_t fimPollMs = 60000;      /* FIM snapshot interval (ms) */
    uint64_t fimMaxFileBytes = 64ULL * 1024ULL * 1024ULL; /* hash cap */
    std::vector<std::string> fimWatchFiles; /* sensitive files to hash */
    bool enableShareMonitor = false; /* SMB share change monitor */
    uint32_t sharePollMs = 30000;    /* share snapshot interval (ms) */

    /* Named pipe monitoring (ETW-based). */
    bool enableNamedPipeMonitor = false;
    bool enableLocalAccountMonitor = false; /* local account / group monitor */
    uint32_t localAccountPollMs = 60000;   /* account snapshot interval (ms) */
    std::vector<std::string> localAccountWatchGroups; /* group names to watch */
    bool enableFirewallMonitor = false;    /* Windows Firewall rule monitor */
    uint32_t firewallPollMs = 30000;       /* firewall snapshot interval (ms) */

    /* ETW tampering / telemetry-impairment monitor (opt-in). */
    bool enableEtwTamperMonitor = false;   /* master switch: enable_etw_tamper_monitor */
    uint32_t etwTamperPollMs = 30000;      /* tamper poll interval (ms) */
    std::vector<std::string> etwTamperProtectedGuids; /* provider GUIDs to watch for disable */
    bool etwTamperWatchSessions = true;    /* watch the agent's own EDR-* ETW sessions */
    bool etwTamperScanProcesses = false;   /* ntdll EtwEventWrite patch scan (opt-in) */
    std::vector<std::string> etwTamperSkipImages; /* base names to skip in the patch scan */

    /* LSASS/SAM credential access detector (opt-in). */
    bool enableLsassSamCollector = false;
    uint32_t lsassSamPollMs = 5000;   /* handle poll interval (ms) */
    uint32_t lsassSamDedupMs = 60000; /* per-handle event dedup window (ms) */

    /* Driver BLOCK policy (Phase B+C, pushed via IOCTL_EDR_SET_POLICY). */
    bool driverEnableFile = false;   /* FILE events from the minifilter */
    bool driverEnableNet = false;    /* NET events (WFP audits) */
    bool driverEnableBlock = false;  /* enforce BLOCK rules in the driver */
    bool driverEnableObjectHandle = false; /* ObRegisterCallbacks handle open events */
    struct DriverNetRule {
        std::string ip;              /* dotted quad, strict inet_pton */
        uint16_t port = 0;           /* 0 = any port */
    };
    std::vector<std::string> driverBlockFilePaths; /* NT prefixes, UTF-8 */
    std::vector<DriverNetRule> driverNetRules;

    /* Host isolation response */
    bool enableHostIsolation = false;
    std::string hostIsolationAllowedPorts;  // comma-separated ports to keep open
    std::string hostIsolationManagementIp;  // management server IP to keep reachable

    /* Process tree builder enrichment */
    bool enableProcessTreeEnrich = false;
    uint32_t processTreeMaxDepth = 5;
    uint64_t processTreePruneAgeMs = 3600000;  // 1 hour
    bool fileReputationEnable = false;
    uint64_t fileReputationMaxBytes = 64ULL * 1024ULL * 1024ULL;
    bool fileReputationCacheOnlyTrust = true;
    bool amsiEnable = false;
    uint32_t amsiMaxContentChars = 4096;
    std::vector<std::string> watchDirs; /* UTF-8; expanded from env vars */

    /* Polling periods (ms) */
    uint32_t netPollMs = 5000;
    uint32_t regBaselineMs = 60000;

    /* Output */
    std::string alertsPath = "alerts.jsonl";
    bool redact = true;
    bool eventLog = true;

    /* Reporter (off by default) */
    bool reporterEnable = false;
    std::string reporterUrl; /* e.g. http://127.0.0.1:8080/ingest */
    std::string reporterApiKey; /* optional API key for auth */
    bool reporterSpoolEnable = false;
    std::string reporterSpoolDirectory;
    std::string reporterEventSpoolDirectory;
    uint32_t reporterSpoolMaxRecords = 1000;
    uint64_t reporterSpoolMaxBytes = 16u * 1024u * 1024u;
    uint64_t reporterSpoolMaxItemBytes = 1024u * 1024u;

    /* Syslog forwarder (off by default). RFC 5424 over UDP. */
    bool syslogEnable = false;
    std::string syslogHost; /* collector host or IPv4 address */
    uint16_t syslogPort = 514;
    uint8_t syslogFacility = 16; /* local0 (0..23) */
    std::string syslogHostname;  /* empty: use computer name */

    /* Alert webhook (off by default). POSTs each alert envelope to a SOAR/SIEM. */
    bool webhookEnable = false;
    std::string webhookUrl;            /* e.g. http://127.0.0.1:9000/alerts */
    uint32_t webhookTimeoutSeconds = 5;
    size_t webhookQueueCapacity = 256;

    /* Authenticated local response channel (both switches default off). */
    bool responseChannelEnable = false;
    bool responseEnableProcessTermination = false;
    bool responseEnableQuarantine = false;
    bool responseEnableDeleteFile = false;
    bool responseEnableProcessSuspend = false;
    bool responseEnableProcessResume = false;
    std::string responseQuarantineDir;
    uint64_t responseQuarantineMaxFileBytes = 268435456ULL;
    std::string responsePipeName = R"(\\.\pipe\edr-response-v1)";
    std::string responseCommandKeyFile;
    std::string responseAuditPath;
    uint32_t responseMaxTreeSize = 32; /* cap on tree termination, 4..64 */

    /* Auto-response (terminate/delete on detection; defaults off). Effective only
     * together with the response channel and real action enablement (main.cpp). */
    bool autoResponseEnable = false;
    std::string autoResponseMinSeverity = "high"; /* medium|high|critical */
    uint32_t autoResponseMaxPerMinute = 4;
    bool autoResponseTreeTermination = false; /* terminate the process tree */
    bool autoResponseSuspendBeforeTerminate = false;
    uint32_t autoResponseMaxTreeDepth = 0;     /* 0 = no depth cap */
    bool autoResponseIsolateBeforeTerminate = false; /* isolate before kill */
    bool autoResponseCaptureSnapshot = false;   /* save evidence snapshot first */
    std::string autoResponseSnapshotDir;        /* empty => default evidence dir */
    std::vector<std::string> autoResponseParentWhitelist; /* protected parent image substrings */
    bool autoResponseEnableKill = false;      /* auto-terminate for kill-action rules */
    bool autoResponseEnableDeleteFile = false; /* auto-delete for delete_file rules */

    /* Restored after 2026-08-29 rollback (fields still referenced by main.cpp collectors that survived on disk). */
    bool procEtwFullImage = true;
    bool procEtwUserSid = false;
    bool enableSysmonNamedPipe = false;

    /* Threat intelligence feed matching (opt-in; operator-supplied IoCs). */
    bool threatIntelEnable = false;
    std::string threatIntelFeedPath = "rules\\threat_intel.json";
    uint32_t threatIntelMinScore = 55;
    uint32_t threatIntelDedupWindowSeconds = 300;
    size_t threatIntelStateCapacity = 4096;
    uint32_t threatIntelReloadPollSeconds = 0; // 0 disables event-driven feed polling

    /* Lateral movement chain correlator (multi-vector; opt-in). */
    bool lateralChainEnable = false;
    uint32_t lateralChainMinScore = 55;
    uint32_t lateralChainWindowSeconds = 600;
    uint32_t lateralChainDedupWindowSeconds = 300;
    size_t lateralChainStateCapacity = 4096;

    /* Alert correlation into incidents + kill-chain graph (opt-in). Purely
     * additive: it groups alerts and never triggers response actions. */
    bool correlationEnable = false;
    uint32_t correlationWindowSeconds = 1800;
    uint32_t correlationStateCapacity = 2048;
    uint32_t correlationMinAlertsToClose = 2;
    /* Kill-chain roll-up: republish an incident onto the bus once it crosses
     * the campaign band so a rule (EDR-443) can alert on the campaign, not
     * just its parts. Keep rollup_min_* aligned with that rule's thresholds -
     * lowering the rule below these values has no effect, because no
     * roll-up event is published for a smaller incident. */
    bool correlationRollupEnable = true;
    uint32_t correlationRollupMinStageCount = 4;
    uint32_t correlationRollupMinScore = 85;
    size_t correlationRollupStateCapacity = 1024;
    /* Durable incident records. Empty disables persistence; only meaningful
     * when correlationEnable is on, since incidents come from the correlator. */
    std::string correlationIncidentPath = "incidents.jsonl";
    uint32_t correlationMaxRecords = 100000;

    /* Eventlog tamper detector (T1070.001/T1562.002; opt-in). */
    bool eventlogTamperEnable = false;
    uint32_t eventlogTamperMinScore = 55;
    uint32_t eventlogTamperDedupWindowSeconds = 300;
    size_t eventlogTamperStateCapacity = 1024;
    /* SSH abuse detector (T1021.004; opt-in). */
    bool sshAbuseEnable = false;
    uint32_t sshAbuseMinScore = 55;
    uint32_t sshAbuseDedupWindowSeconds = 300;
    size_t sshAbuseStateCapacity = 1024;
    /* Mailbox rule forwarding detector (T1114.003; opt-in). */
    bool mailboxRuleEnable = false;
    uint32_t mailboxRuleMinScore = 55;
    uint32_t mailboxRuleDedupWindowSeconds = 300;
    size_t mailboxRuleStateCapacity = 1024;
    /* LLMNR/NBT-NS/mDNS poisoning detector (T1557.001; opt-in). */
    bool llmnrPoisonEnable = false;
    uint32_t llmnrPoisonMinScore = 55;
    uint32_t llmnrPoisonDedupWindowSeconds = 300;
    size_t llmnrPoisonStateCapacity = 1024;
    /* Network Provider DLL persistence detector (T1556.008; opt-in). */
    bool netProviderPersistEnable = false;
    uint32_t netProviderPersistMinScore = 55;
    uint32_t netProviderPersistDedupWindowSeconds = 300;
    size_t netProviderPersistStateCapacity = 1024;
    /* Password vault access detector (T1555.005; opt-in). */
    bool passwordVaultEnable = false;
    uint32_t passwordVaultMinScore = 55;
    uint32_t passwordVaultDedupWindowSeconds = 300;
    size_t passwordVaultStateCapacity = 1024;
    /* ARP cache poisoning detector (T1557.002; opt-in). */
    bool arpPoisonEnable = false;
    uint32_t arpPoisonMinScore = 55;
    uint32_t arpPoisonDedupWindowSeconds = 300;
    size_t arpPoisonStateCapacity = 1024;
    /* Cloud instance metadata API detector (T1552.005; opt-in). */
    bool cloudMetadataEnable = false;
    uint32_t cloudMetadataMinScore = 55;
    uint32_t cloudMetadataDedupWindowSeconds = 300;
    size_t cloudMetadataStateCapacity = 1024;
    /* Group Policy Preferences credential theft detector (T1552.006;
     * opt-in). */
    bool gppPasswordEnable = false;
    uint32_t gppPasswordMinScore = 55;
    uint32_t gppPasswordDedupWindowSeconds = 300;
    size_t gppPasswordStateCapacity = 1024;
    /* Control Panel proxy execution detector (T1218.002; opt-in). */
    bool controlPanelProxyEnable = false;
    uint32_t controlPanelProxyMinScore = 55;
    uint32_t controlPanelProxyDedupWindowSeconds = 300;
    size_t controlPanelProxyStateCapacity = 1024;
    /* Hidden local account detector (T1564.002; opt-in). */
    bool hiddenUserAccountEnable = false;
    uint32_t hiddenUserAccountMinScore = 55;
    uint32_t hiddenUserAccountDedupWindowSeconds = 300;
    size_t hiddenUserAccountStateCapacity = 1024;
    /* Password policy discovery detector (T1201; opt-in). */
    bool passwordPolicyDiscoveryEnable = false;
    uint32_t passwordPolicyDiscoveryMinScore = 55;
    uint32_t passwordPolicyDiscoveryDedupWindowSeconds = 300;
    size_t passwordPolicyDiscoveryStateCapacity = 1024;
    /* MSI package install abuse detector (T1546.016; opt-in). */
    bool msiPackageInstallEnable = false;
    uint32_t msiPackageInstallMinScore = 55;
    uint32_t msiPackageInstallDedupWindowSeconds = 300;
    size_t msiPackageInstallStateCapacity = 1024;
    /* Event log enumeration detector (T1654; opt-in). */
    bool logEnumerationEnable = false;
    uint32_t logEnumerationMinScore = 55;
    uint32_t logEnumerationDedupWindowSeconds = 300;
    size_t logEnumerationStateCapacity = 1024;
    /* Mailbox delegate permission grants detector (T1098.002; opt-in). */
    bool mailboxDelegateEnable = false;
    uint32_t mailboxDelegateMinScore = 55;
    uint32_t mailboxDelegateDedupWindowSeconds = 300;
    size_t mailboxDelegateStateCapacity = 1024;

    /* Rules */
    std::string rulesPath = "rules\\rules.json";
    /* Rules hot reload (RuleEngine::MaybeReload; off by default). On config
     * or rules parse failure the previous rule set keeps serving. */
    bool ruleReloadEnable = false;
    uint32_t ruleReloadPollSeconds = 30;
    /* Runtime */
    bool runAsService = false;
    bool console = true;
    bool selftest = false;
};

/* Load JSON config from path (missing file is not fatal: defaults kept),
 * then apply command-line overrides. Throws jsonlite::ParseError on
 * malformed JSON. */
bool LoadConfigFile(const std::string& path, Config& cfg, std::string& err);

/* UTF-16 -> UTF-8 and UTF-8 -> UTF-16 helpers. */
std::string WideToUtf8(const wchar_t* wide, size_t len = (size_t)-1);
std::wstring Utf8ToWide(const std::string& utf8);

/* Expand %ENV% variables in a path string. */
std::string ExpandEnvStrings(const std::string& in);

} // namespace edr

#endif /* EDR_CONFIG_H */
