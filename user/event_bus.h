/*
 * event_bus.h - Shared event model and bounded consumer queue.
 */
#ifndef EDR_EVENT_BUS_H
#define EDR_EVENT_BUS_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>

namespace edr {

enum class EventDisposition {
    ReportAndEvaluate,
    ReportOnly,
};

namespace field {
constexpr const char* kType = "type";
constexpr const char* kSource = "source";
constexpr const char* kEndpointId = "endpoint_id";
constexpr const char* kTimestampProvenance = "timestamp_provenance";
constexpr const char* kPid = "pid";
constexpr const char* kPpid = "ppid";
constexpr const char* kImage = "image";
constexpr const char* kParentImage = "parent_image";
constexpr const char* kCommandLine = "command_line";
constexpr const char* kTargetImage = "target_image";
constexpr const char* kTargetPath = "target_path";
constexpr const char* kFilePath = "file_path";
constexpr const char* kFileAction = "file_action";
/* Sysmon timestomp (EID 2) + ETW process enrichment fields (restored
 * 2026-08-29 after a concurrent-session rollback dropped them; the
 * orphan-batch detector sources on disk still reference them). */
constexpr const char* kFileCreationTime = "file_creation_time";
constexpr const char* kFilePreviousCreationTime =
    "file_previous_creation_time";
constexpr const char* kUserSid = "user_sid";
constexpr const char* kSessionId = "session_id";
constexpr const char* kExitStatus = "exit_status";
constexpr const char* kPreAuthType = "pre_auth_type";
constexpr const char* kOldFilePath = "old_file_path";
constexpr const char* kDstIp = "dst_ip";
constexpr const char* kDstPort = "dst_port";
constexpr const char* kSrcIp = "src_ip";
constexpr const char* kSrcPort = "src_port";
constexpr const char* kProtocol = "protocol";
constexpr const char* kRegKey = "reg_key";
constexpr const char* kRegValue = "reg_value";
constexpr const char* kRegOperation = "reg_operation";
constexpr const char* kRegOldTarget = "reg_old_target";
constexpr const char* kRegNewTarget = "reg_new_target";
constexpr const char* kImageLoaded = "image_loaded";
constexpr const char* kImageBase = "image_base";
constexpr const char* kImageSize = "image_size";
constexpr const char* kImageChecksum = "image_checksum";
constexpr const char* kImageCompileTime = "image_compile_time";
constexpr const char* kImageLoadType = "image_load_type";
constexpr const char* kHashes = "hashes";
constexpr const char* kTargetHost = "target_host";
constexpr const char* kDnsQueryName = "dns_query_name";
constexpr const char* kDnsQueryType = "dns_query_type";
constexpr const char* kDnsQueryStatus = "dns_query_status";
constexpr const char* kDnsServerIp = "dns_server_ip";
constexpr const char* kDnsAnswers = "dns_answers";
constexpr const char* kDnsAnswerType = "dns_answer_type";
constexpr const char* kDnsAnswerData = "dns_answer_data";
constexpr const char* kDnsAnswerTtl = "dns_answer_ttl";
constexpr const char* kDnsEntropy = "dns_entropy";
constexpr const char* kDnsSubdomainCount = "dns_subdomain_count";
constexpr const char* kDnsMaxLabelLength = "dns_max_label_length";
constexpr const char* kLogonType = "logon_type";
constexpr const char* kLogonId = "logon_id";
constexpr const char* kLogonProcess = "logon_process";
constexpr const char* kAuthPackage = "authentication_package";
constexpr const char* kSourceWorkstation = "source_workstation";
constexpr const char* kTargetUser = "target_user";
constexpr const char* kTargetDomain = "target_domain";
constexpr const char* kTargetUserSid = "target_user_sid";
constexpr const char* kSubjectUserName = "subject_user_name";
constexpr const char* kSubjectDomainName = "subject_domain_name";
constexpr const char* kSubjectUserSid = "subject_user_sid";
constexpr const char* kElevatedToken = "elevated_token";
constexpr const char* kPrivileges = "privileges";
constexpr const char* kFailureReason = "failure_reason";
constexpr const char* kStatus = "status";
constexpr const char* kSubStatus = "sub_status";
constexpr const char* kOperationType = "operation_type";
constexpr const char* kServiceName = "service_name";
constexpr const char* kServiceImagePath = "service_image_path";
constexpr const char* kServiceStartType = "service_start_type";
constexpr const char* kServiceAccount = "service_account";
constexpr const char* kServiceAction = "service_action";
constexpr const char* kServiceDisplayName = "service_display_name";
constexpr const char* kServiceState = "service_state";
constexpr const char* kTaskName = "task_name";
constexpr const char* kTaskUserContext = "task_user_context";
constexpr const char* kTaskSchedulerEventId = "taskscheduler_event_id";
constexpr const char* kPrivilegeOperation = "privilege_operation";
constexpr const char* kPrivilegeList = "privilege_list";
constexpr const char* kProcessName = "process_name";
constexpr const char* kMemorySize = "memory_size";
constexpr const char* kBaseAddress = "base_address";
constexpr const char* kFileOffset = "file_offset";
constexpr const char* kFileLength = "file_length";
constexpr const char* kAccessMask = "access_mask";
constexpr const char* kAccessVmOperation = "access_vm_operation";
constexpr const char* kAccessVmRead = "access_vm_read";
constexpr const char* kAccessVmWrite = "access_vm_write";
constexpr const char* kAccessQueryInformation = "access_query_information";
constexpr const char* kAccessQueryLimitedInformation = "access_query_limited_information";
constexpr const char* kAccessCreateThread = "access_create_thread";
constexpr const char* kAccessDuplicateHandle = "access_duplicate_handle";
constexpr const char* kCrossProcess = "cross_process";
constexpr const char* kRemoteThread = "remote_thread";
constexpr const char* kThreadId = "thread_id";
constexpr const char* kStartAddress = "start_address";
constexpr const char* kStartModule = "start_module";
constexpr const char* kStartFunction = "start_function";
constexpr const char* kTargetPid = "target_pid";
constexpr const char* kSourcePid = "source_pid";
constexpr const char* kSourceProcessGuid = "source_process_guid";
constexpr const char* kTargetProcessGuid = "target_process_guid";
constexpr const char* kSourceTimestamp = "source_timestamp";
constexpr const char* kGrantedAccess = "granted_access";
constexpr const char* kCallTrace = "call_trace";
constexpr const char* kObjectServer = "object_server";
constexpr const char* kObjectType = "object_type";
constexpr const char* kObjectName = "object_name";
constexpr const char* kHandleId = "handle_id";
constexpr const char* kHandleDuplicated = "handle_duplicated";
constexpr const char* kDuplicateHandleValue = "duplicate_handle_value";
constexpr const char* kRuleIndex = "rule_index";
constexpr const char* kDroppedEvents = "dropped_events";
constexpr const char* kUsbAction = "usb_action";
constexpr const char* kUsbDeviceName = "usb_device_name";
constexpr const char* kUsbSerial = "usb_serial";
constexpr const char* kUsbDriveLetter = "usb_drive_letter";
constexpr const char* kUsbFileSystem = "usb_file_system";
constexpr const char* kUsbDeviceType = "usb_device_type";
constexpr const char* kListenerAction = "listener_action";
constexpr const char* kListenerIp = "listener_ip";
constexpr const char* kListenerPort = "listener_port";
constexpr const char* kListenerProtocol = "listener_protocol";
constexpr const char* kListenerAddressFamily = "listener.address_family";
constexpr const char* kListenerPid = "listener_pid";
constexpr const char* kListenerProcess = "listener_process";
constexpr const char* kShareAction = "share_action";
constexpr const char* kShareName = "share_name";
constexpr const char* kSharePath = "share_path";
constexpr const char* kShareType = "share_type";
constexpr const char* kShareRemark = "share_remark";
constexpr const char* kCriticalProcessAction = "critical_process_action";
constexpr const char* kCriticalProcessImage = "critical_process_image";
constexpr const char* kCriticalProcessPid = "critical_process_pid";
constexpr const char* kCriticalProcessReason = "critical_process_reason";
constexpr const char* kFimAction = "fim_action";
constexpr const char* kFimPath = "fim_path";
constexpr const char* kFimSize = "fim_size";
constexpr const char* kFimSha256 = "fim_sha256";
constexpr const char* kFimBaseline = "fim_baseline";
constexpr const char* kDefenderEventId = "defender_event_id";
constexpr const char* kThreatName = "threat_name";
constexpr const char* kThreatId = "threat_id";
constexpr const char* kThreatSeverity = "threat_severity";
constexpr const char* kThreatCategory = "threat_category";
constexpr const char* kDetectionPath = "detection_path";
constexpr const char* kDetectionUser = "detection_user";
constexpr const char* kDefenderAction = "defender_action";
constexpr const char* kDefenderStatus = "defender_status";
constexpr const char* kDefenderOldValue = "defender_old_value";
constexpr const char* kDefenderNewValue = "defender_new_value";
constexpr const char* kHookType = "hook_type";
constexpr const char* kHookThreadId = "hook_thread_id";
constexpr const char* kHookProcAddress = "hook_proc_address";
constexpr const char* kHookInstance = "hook_instance";
constexpr const char* kHookModulePath = "hook_module_path";
constexpr const char* kRpcCommandline = "rpc_commandline";
constexpr const char* kRpcParentPath = "rpc_parent_path";
constexpr const char* kRpcParentCommandline = "rpc_parent_commandline";
constexpr const char* kServiceCreateType = "service_create_type";
constexpr const char* kServiceConfigType = "service_config_type";
constexpr const char* kComClassId = "com_class_id";
constexpr const char* kComInterfaceId = "com_interface_id";
constexpr const char* kComContext = "com_context";
constexpr const char* kSectionPath = "section_path";
constexpr const char* kSectionPid = "section_pid";
constexpr const char* kInputType = "input_type";
constexpr const char* kShutdownRestart = "shutdown_restart";
constexpr const char* kSystemTimeValue = "system_time_value";
constexpr const char* kClipboardFormat = "clipboard_format";
/* ClipboardTheftDetector (repeated/unusual clipboard collection). */
constexpr const char* kClipboardTheftScore = "clipboard_theft_score";
constexpr const char* kClipboardTheftVerdict = "clipboard_theft_verdict";
constexpr const char* kClipboardTheftSignals = "clipboard_theft_signals";
constexpr const char* kClipboardTheftAccessCount =
    "clipboard_theft_access_count";
constexpr const char* kClipboardTheftTextReadCount =
    "clipboard_theft_text_read_count";
constexpr const char* kClipboardTheftWindowSeconds =
    "clipboard_theft_window_seconds";
constexpr const char* kWallpaperPath = "wallpaper_path";
constexpr const char* kCameraAction = "camera_action";
constexpr const char* kKeyLoggerType = "keylogger_type";
constexpr const char* kPowerShellScriptPath = "powershell_script_path";
constexpr const char* kPowerShellCommand = "powershell_command";
constexpr const char* kHookApcRoutine = "hook_apc_routine";
constexpr const char* kHookTime = "hook_time";
constexpr const char* kSha256 = "sha256";
constexpr const char* kAuditLogEventId = "audit_log_event_id";
constexpr const char* kPipeName = "pipe_name";
constexpr const char* kPipeOperation = "pipe_operation";
constexpr const char* kTokenOperation = "token_operation";
constexpr const char* kTokenPrivileges = "token_privileges";
constexpr const char* kTokenUser = "token_user";
constexpr const char* kTokenSessionId = "token_session_id";
constexpr const char* kCatalogSignatureSupported = "catalog_signature_supported";
constexpr const char* kFileReputationStatus = "file_reputation_status";
constexpr const char* kFileReputationCode = "file_reputation_code";
constexpr const char* kSignatureStatus = "signature_status";
constexpr const char* kSignatureStatusCode = "signature_status_code";
constexpr const char* kSignerCertificateSha256 = "signer_certificate_sha256";
constexpr const char* kSignerIssuer = "signer_issuer";
constexpr const char* kSignerSubject = "signer_subject";
constexpr const char* kSysmonEventId = "sysmon_event_id";
constexpr const char* kSysmonVersion = "sysmon_version";
constexpr const char* kSysmonRuleName = "sysmon_rule_name";
constexpr const char* kQueryResults = "query_results";
constexpr const char* kQueryStatus = "query_status";
constexpr const char* kUserId = "user_id";
constexpr const char* kAccountName = "account_name";
constexpr const char* kAccountAction = "account_action";
constexpr const char* kAccountType = "account_type";
constexpr const char* kAccountEnabled = "account_enabled";
constexpr const char* kAccountFullName = "account_full_name";
constexpr const char* kGroupName = "group_name";
constexpr const char* kGroupAction = "group_action";
constexpr const char* kGroupMember = "group_member";
constexpr const char* kGroupMemberDomain = "group_member_domain";
constexpr const char* kWmiNamespace = "wmi_namespace";
constexpr const char* kWmiQuery = "wmi_query";
constexpr const char* kWmiProviderName = "wmi_provider_name";
constexpr const char* kWmiProviderPath = "wmi_provider_path";
constexpr const char* kWmiHostProcess = "wmi_host_process";
constexpr const char* kWmiPossibleCause = "wmi_possible_cause";
constexpr const char* kWmiResultCode = "wmi_result_code";
constexpr const char* kWmiOperation = "wmi_operation";
constexpr const char* kWmiClientMachine = "wmi_client_machine";
constexpr const char* kWmiEventId = "wmi_event_id";
constexpr const char* kPowerShellEventId = "powershell_event_id";
constexpr const char* kScriptBlockText = "script_block_text";
constexpr const char* kScriptBlockId = "script_block_id";
constexpr const char* kScriptPath = "script_path";
constexpr const char* kScriptMessageNumber = "script_message_number";
constexpr const char* kScriptMessageTotal = "script_message_total";
constexpr const char* kScriptBlockComplete = "script_block_complete";
constexpr const char* kScriptBlockTruncated = "script_block_truncated";
constexpr const char* kScriptReassemblyStatus = "script_reassembly_status";
constexpr const char* kScriptReassemblyReason = "script_reassembly_reason";
constexpr const char* kScriptReassemblyCount = "script_reassembly_count";
constexpr const char* kAmsiVerdict = "amsi_verdict";
constexpr const char* kAmsiSource = "amsi_source";
constexpr const char* kAmsiTruncated = "amsi_truncated";
constexpr const char* kAmsiResult = "amsi_result";
constexpr const char* kAmsiErrorHresult = "amsi_error_hresult";
constexpr const char* kDnsBeaconScore = "dns_beacon_score";
constexpr const char* kDnsBeaconQueryCount = "dns_beacon_query_count";
constexpr const char* kDnsBeaconHighEntropyCount = "dns_beacon_high_entropy_count";
constexpr const char* kDnsBeaconWindowSeconds = "dns_beacon_window_seconds";
constexpr const char* kDnsDgaScore = "dns_dga_score";
constexpr const char* kDnsDgaSignals = "dns_dga_signals";
constexpr const char* kDnsDgaLabel = "dns_dga_label";
constexpr const char* kC2BeaconScore = "c2_beacon_score";
constexpr const char* kC2BeaconRepeatConnections = "c2_beacon_repeat_connections";
constexpr const char* kC2BeaconDestinations = "c2_beacon_destinations";
constexpr const char* kC2BeaconWindowSeconds = "c2_beacon_window_seconds";
constexpr const char* kRansomBurstScore = "bulk_file_score";
constexpr const char* kRansomBurstCount = "bulk_file_count";
constexpr const char* kRansomBurstExtensions = "bulk_file_extensions";
constexpr const char* kRansomBurstWindowSeconds = "bulk_file_window_seconds";
constexpr const char* kHollowScore = "hollow_score";
constexpr const char* kHollowReasons = "hollow_reasons";
constexpr const char* kHollowBase = "hollow_base";
constexpr const char* kHollowPath = "hollow_path";
constexpr const char* kHollowParent = "hollow_parent";
constexpr const char* kDllHijackScore = "dll_hijack_score";
constexpr const char* kDllHijackPath = "dll_hijack_path";
constexpr const char* kDllHijackName = "dll_hijack_name";
constexpr const char* kDllHijackLocation = "dll_hijack_location";
constexpr const char* kDllHijackVerdict = "dll_hijack_verdict";
constexpr const char* kDefenseEvasionScore = "defense_evasion_score";
constexpr const char* kDefenseEvasionTechniques = "defense_evasion_techniques";
constexpr const char* kDefenseEvasionCount = "defense_evasion_count";
constexpr const char* kDefenseEvasionWindowSeconds =
    "defense_evasion_window_seconds";
constexpr const char* kDefenseEvasionVerdict = "defense_evasion_verdict";
constexpr const char* kDiscoveryScore = "discovery_score";
constexpr const char* kDiscoveryTechniques = "discovery_techniques";
constexpr const char* kDiscoveryCount = "discovery_count";
constexpr const char* kDiscoveryWindowSeconds = "discovery_window_seconds";
constexpr const char* kDiscoveryVerdict = "discovery_verdict";
constexpr const char* kRemoteAccessScore = "remote_access_score";
constexpr const char* kRemoteAccessTool = "remote_access_tool";
constexpr const char* kRemoteAccessSignals = "remote_access_signals";
constexpr const char* kRemoteAccessWindowSeconds = "remote_access_window_seconds";
constexpr const char* kRemoteAccessVerdict = "remote_access_verdict";
constexpr const char* kDnsFailureScore = "dns_failure_score";
constexpr const char* kDnsFailureQueryCount = "dns_failure_query_count";
constexpr const char* kDnsFailureNxdomainCount = "dns_failure_nxdomain_count";
constexpr const char* kDnsFailureDistinctNames = "dns_failure_distinct_names";
constexpr const char* kDnsFailurePercent = "dns_failure_percent";
constexpr const char* kDnsFailureHighEntropyCount = "dns_failure_high_entropy_count";
constexpr const char* kDnsFailureWindowSeconds = "dns_failure_window_seconds";
constexpr const char* kLogonSuccessScore = "logon_success_score";
constexpr const char* kLogonSuccessFailures = "logon_success_failures";
constexpr const char* kLogonSuccessWindowSeconds = "logon_success_window_seconds";
constexpr const char* kLogonBruteScore = "logon_brute_score";
constexpr const char* kLogonBruteFailures = "logon_brute_failures";
constexpr const char* kLogonBruteTargetUser = "logon_brute_target_user";
constexpr const char* kLogonBruteSrcIp = "logon_brute_src_ip";
constexpr const char* kLogonBruteWindowSeconds = "logon_brute_window_seconds";
constexpr const char* kPasswordSprayScore = "password_spray_score";
constexpr const char* kPasswordSprayFailures = "password_spray_failures";
constexpr const char* kPasswordSprayUserCount = "password_spray_user_count";
constexpr const char* kPasswordSprayUsers = "password_spray_users";
constexpr const char* kPasswordSpraySrcIp = "password_spray_src_ip";
constexpr const char* kPasswordSprayWindowSeconds = "password_spray_window_seconds";
constexpr const char* kPasswordSpraySuccess = "password_spray_success";
constexpr const char* kPasswordSpraySuccessUser = "password_spray_success_user";
constexpr const char* kPasswordSpraySuccessDelaySeconds = "password_spray_success_delay_seconds";
constexpr const char* kKerberoastScore = "kerberoast_score";
constexpr const char* kKerberoastServiceCount = "kerberoast_service_count";
constexpr const char* kKerberoastServices = "kerberoast_services";
constexpr const char* kKerberoastRequester = "kerberoast_requester";
constexpr const char* kKerberoastSrcIp = "kerberoast_src_ip";
constexpr const char* kKerberoastWindowSeconds = "kerberoast_window_seconds";
constexpr const char* kLateralMoveScore = "lateral_move_score";
constexpr const char* kLateralMoveDestCount = "lateral_move_dest_count";
constexpr const char* kLateralMovePorts = "lateral_move_ports";
constexpr const char* kLateralMoveWindowSeconds = "lateral_move_window_seconds";
constexpr const char* kPortScanScore = "port_scan_score";
constexpr const char* kPortScanPortCount = "port_scan_port_count";
constexpr const char* kPortScanTarget = "port_scan_target";
constexpr const char* kPortScanSamplePorts = "port_scan_sample_ports";
constexpr const char* kPortScanWindowSeconds = "port_scan_window_seconds";
constexpr const char* kPersistChainScore = "persist_chain_score";
constexpr const char* kPersistChainMechanisms = "persist_chain_mechanisms";
constexpr const char* kPersistChainCount = "persist_chain_count";
constexpr const char* kPersistChainWindowSeconds = "persist_chain_window_seconds";
constexpr const char* kLolbinScore = "lolbin_score";
constexpr const char* kLolbinParentClass = "lolbin_parent_class";
constexpr const char* kLolbinChildClass = "lolbin_child_class";
constexpr const char* kLolbinFlags = "lolbin_flags";
constexpr const char* kLolbinVerdict = "lolbin_verdict";
constexpr const char* kLolbinChainScore = "lolbin_chain_score";
constexpr const char* kLolbinChainCount = "lolbin_chain_count";
constexpr const char* kLolbinChainChildren = "lolbin_chain_children";
constexpr const char* kLolbinChainWindowSeconds = "lolbin_chain_window_seconds";
constexpr const char* kLolbinChainVerdict = "lolbin_chain_verdict";
constexpr const char* kPowerShellDownloadExecuteScore = "powershell_download_execute_score";
constexpr const char* kPowerShellDownloadExecuteCount = "powershell_download_execute_count";
constexpr const char* kPowerShellDownloadExecuteSignals = "powershell_download_execute_signals";
constexpr const char* kPowerShellDownloadExecuteWindowSeconds = "powershell_download_execute_window_seconds";
constexpr const char* kPowerShellDownloadExecuteVerdict = "powershell_download_execute_verdict";
constexpr const char* kRdpAction = "rdp_action";
constexpr const char* kRdpUser = "rdp_user";
constexpr const char* kRdpDomain = "rdp_domain";
constexpr const char* kRdpSessionId = "rdp_session_id";
constexpr const char* kRdpSourceIp = "rdp_source_ip";
constexpr const char* kRdpSessionName = "rdp_session_name";
constexpr const char* kRdpEventId = "rdp_event_id";
constexpr const char* kRansomPrecursorScore = "ransom_precursor_score";
constexpr const char* kRansomPrecursorTechniques = "ransom_precursor_techniques";
constexpr const char* kRansomPrecursorCount = "ransom_precursor_count";
constexpr const char* kRansomPrecursorWindowSeconds = "ransom_precursor_window_seconds";
constexpr const char* kRansomPrecursorVerdict = "ransom_precursor_verdict";
constexpr const char* kRdpChainScore = "rdp_chain_score";
constexpr const char* kRdpChainCount = "rdp_chain_count";
constexpr const char* kRdpChainSources = "rdp_chain_sources";
constexpr const char* kRdpChainWindowSeconds = "rdp_chain_window_seconds";
constexpr const char* kRdpChainVerdict = "rdp_chain_verdict";
constexpr const char* kUacBypassScore = "uac_bypass_score";
constexpr const char* kUacBypassCount = "uac_bypass_count";
constexpr const char* kUacBypassKeys = "uac_bypass_keys";
constexpr const char* kUacBypassWindowSeconds = "uac_bypass_window_seconds";
constexpr const char* kUacBypassVerdict = "uac_bypass_verdict";
constexpr const char* kWmiPersistenceScore = "wmi_persistence_score";
constexpr const char* kWmiPersistenceMatches = "wmi_persistence_matches";
constexpr const char* kWmiPersistenceMatchText = "wmi_persistence_match_text";
constexpr const char* kWmiPersistenceWindowSeconds = "wmi_persistence_window_seconds";
constexpr const char* kWmiPersistenceVerdict = "wmi_persistence_verdict";
constexpr const char* kRegistryPersistenceScore = "registry_persistence_score";
constexpr const char* kRegistryPersistenceCount = "registry_persistence_count";
constexpr const char* kRegistryPersistenceMechanisms = "registry_persistence_mechanisms";
constexpr const char* kRegistryPersistenceKeys = "registry_persistence_keys";
constexpr const char* kRegistryPersistenceWindowSeconds = "registry_persistence_window_seconds";
constexpr const char* kRegistryPersistenceVerdict = "registry_persistence_verdict";
constexpr const char* kAntiForensicsScore = "anti_forensics_score";
constexpr const char* kAntiForensicsCount = "anti_forensics_count";
constexpr const char* kAntiForensicsMechanisms = "anti_forensics_mechanisms";
constexpr const char* kAntiForensicsWindowSeconds = "anti_forensics_window_seconds";
constexpr const char* kAntiForensicsVerdict = "anti_forensics_verdict";
constexpr const char* kTimeChangePrev100ns = "time_change_prev_100ns";
constexpr const char* kTimeChangeNew100ns = "time_change_new_100ns";
constexpr const char* kTimeChangeDeltaSeconds = "time_change_delta_seconds";
constexpr const char* kTimeChangeScore = "time_change_score";
constexpr const char* kTimeChangeCount = "time_change_count";
constexpr const char* kTimeChangeMechanisms = "time_change_mechanisms";
constexpr const char* kTimeChangeWindowSeconds = "time_change_window_seconds";
constexpr const char* kTimeChangeVerdict = "time_change_verdict";
constexpr const char* kPrivilegedGroupScore = "privileged_group_score";
constexpr const char* kPrivilegedGroupCount = "privileged_group_count";
constexpr const char* kPrivilegedGroupSensitiveAdds = "privileged_group_sensitive_adds";
constexpr const char* kPrivilegedGroupGroups = "privileged_group_groups";
constexpr const char* kPrivilegedGroupWindowSeconds = "privileged_group_window_seconds";
constexpr const char* kPrivilegedGroupVerdict = "privileged_group_verdict";
constexpr const char* kTargetGroupName = "target_group_name";
constexpr const char* kInjectChainScore = "inject_chain_score";
constexpr const char* kInjectChainStage = "inject_chain_stage";
constexpr const char* kInjectChainReasons = "inject_chain_reasons";
constexpr const char* kInjectTargetImage = "inject_target_image";
constexpr const char* kAttackChainStages = "attack_chain_stages";
constexpr const char* kAttackChainStageCount = "attack_chain_stage_count";
constexpr const char* kAttackChainTactics = "attack_chain_tactics";
constexpr const char* kAttackChainScore = "attack_chain_score";
constexpr const char* kChainScore = "chain_score";
constexpr const char* kChainReasons = "chain_reasons";
constexpr const char* kLsassReadBurstBytes = "lsass_read_burst_bytes";
constexpr const char* kLsassReadBurstCount = "lsass_read_burst_count";
constexpr const char* kRatScore = "rat_score";
constexpr const char* kRatFlags = "rat_flags";
constexpr const char* kRatVerdict = "rat_verdict";
constexpr const char* kRatImagePath = "rat_image_path";
constexpr const char* kRatParentImage = "rat_parent_image";
constexpr const char* kSilverFoxFamily = "silverfox_family";
constexpr const char* kSilverFoxScore = "silverfox_score";
constexpr const char* kSilverFoxConfidence = "silverfox_confidence";
constexpr const char* kSilverFoxSignals = "silverfox_signals";
constexpr const char* kSilverFoxEvidenceCount = "silverfox_evidence_count";
constexpr const char* kSilverFoxIocIds = "silverfox_ioc_ids";
constexpr const char* kSilverFoxIocTypes = "silverfox_ioc_types";
constexpr const char* kSilverFoxIocSources = "silverfox_ioc_sources";
constexpr const char* kSilverFoxIocConfidence = "silverfox_ioc_confidence";
constexpr const char* kAutoResponseStatus = "auto_response_status";
constexpr const char* kAutoResponseActionStatus = "auto_response_action_status";
constexpr const char* kAutoResponseAuditWritten = "auto_response_audit_written";
constexpr const char* kAutoResponseRequestId = "auto_response_request_id";
constexpr const char* kAutoResponseMode = "auto_response_mode";
constexpr const char* kAutoResponseEvidencePath = "auto_response_evidence_path";
constexpr const char* kAutoResponseTreeStatus = "auto_response_tree_status";
constexpr const char* kAutoResponseTreePlanned = "auto_response_tree_planned";
constexpr const char* kAutoResponseTreeDescendants = "auto_response_tree_descendants";
constexpr const char* kAutoResponseTreeDepth = "auto_response_tree_depth";
constexpr const char* kAutoResponseTreeSuspended = "auto_response_tree_suspended";
constexpr const char* kAutoResponseTreeSkipped = "auto_response_tree_skipped";
constexpr const char* kAutoResponseTreeFailed = "auto_response_tree_failed";
constexpr const char* kAutoResponseTreeTruncated = "auto_response_tree_truncated";
constexpr const char* kAutoResponseTreeRequested = "auto_response_tree_requested";
constexpr const char* kAutoResponseIsolationRequested = "auto_response_isolation_requested";
constexpr const char* kAutoResponseIsolationSucceeded = "auto_response_isolation_succeeded";
constexpr const char* kFirewallAction = "firewall_action";
constexpr const char* kFirewallRuleName = "firewall_rule_name";
constexpr const char* kFirewallDir = "firewall_dir";
constexpr const char* kFirewallRuleAction = "firewall_rule_action";
constexpr const char* kFirewallProtocol = "firewall_protocol";
constexpr const char* kFirewallLocalPort = "firewall_local_port";
constexpr const char* kFirewallRemotePort = "firewall_remote_port";
constexpr const char* kFirewallApp = "firewall_app";
constexpr const char* kFirewallService = "firewall_service";
constexpr const char* kFirewallEnabled = "firewall_enabled";
constexpr const char* kEtwTamperType = "etw_tamper_type";
constexpr const char* kEtwProviderGuid = "etw_provider_guid";
constexpr const char* kEtwTamperDetail = "etw_tamper_detail";
constexpr const char* kEtwTamperPid = "etw_tamper_pid";
constexpr const char* kEtwTamperImage = "etw_tamper_image";
constexpr const char* kEtwTamperModule = "etw_tamper_module";
constexpr const char* kEtwExpectedBytes = "etw_expected_bytes";
constexpr const char* kEtwActualBytes = "etw_actual_bytes";
constexpr const char* kEtwTamperSession = "etw_tamper_session";
constexpr const char* kActorImage = "actor_image";
constexpr const char* kSecurityEventId = "security_event_id";
constexpr const char* kTgsServiceName = "tgs_service_name";
constexpr const char* kTgsServiceSid = "tgs_service_sid";
constexpr const char* kTgsTicketEncryptionType = "tgs_ticket_encryption_type";
constexpr const char* kTgsFailureCode = "tgs_failure_code";
constexpr const char* kStartupScope = "startup_scope";
constexpr const char* kImagePath = "image_path";
constexpr const char* kMemoryProtection = "memory_protection";
constexpr const char* kMemoryScanScore = "memory_scan_score";
constexpr const char* kMemoryScanReasons = "memory_scan_reasons";
constexpr const char* kMemoryScanRegions = "memory_scan_regions";
constexpr const char* kApcInject = "apc_inject";
constexpr const char* kDriverScanScore = "driver_scan_score";
constexpr const char* kDriverScanReasons = "driver_scan_reasons";
constexpr const char* kDriverImagePath = "driver_image_path";
constexpr const char* kDriverSigner = "driver_signer";
constexpr const char* kDriverSigned = "driver_signed";
constexpr const char* kDriverVerdict = "driver_scan_verdict";
constexpr const char* kDriverLoadType = "driver_load_type";
constexpr const char* kDriverPid = "driver_pid";
constexpr const char* kFilelessScore = "fileless_score";
constexpr const char* kFilelessSignals = "fileless_signals";
constexpr const char* kFilelessTechniques = "fileless_techniques";
constexpr const char* kFilelessCount = "fileless_count";
constexpr const char* kFilelessVerdict = "fileless_verdict";
constexpr const char* kApiHookScore = "api_hook_score";
constexpr const char* kApiHookFunctions = "api_hook_functions";
constexpr const char* kApiHookModules = "api_hook_modules";
constexpr const char* kApiHookVerdict = "api_hook_verdict";
/* Credential dumping detector (T1003) */
constexpr const char* kCredentialDumpScore = "credential_dump_score";
constexpr const char* kCredentialDumpSignals = "credential_dump_signals";
constexpr const char* kCredentialDumpTechniques = "credential_dump_techniques";
constexpr const char* kCredentialDumpDetail = "credential_dump_detail";
constexpr const char* kCredentialDumpWindowSeconds = "credential_dump_window_seconds";
constexpr const char* kCredentialDumpVerdict = "credential_dump_verdict";
/* Data exfiltration detector (T1048) */
constexpr const char* kDataExfilScore = "data_exfil_score";
constexpr const char* kDataExfilSignals = "data_exfil_signals";
constexpr const char* kDataExfilBytesOut = "data_exfil_bytes_out";
constexpr const char* kDataExfilDestinations = "data_exfil_destinations";
constexpr const char* kDataExfilDnsTunnelQueries = "data_exfil_dns_tunnel_queries";
constexpr const char* kDataExfilWindowSeconds = "data_exfil_window_seconds";
constexpr const char* kDataExfilVerdict = "data_exfil_verdict";
/* Privilege escalation detector (T1134/T1068) */
constexpr const char* kPrivEscScore = "priv_esc_score";
constexpr const char* kPrivEscSignals = "priv_esc_signals";
constexpr const char* kPrivEscTechniques = "priv_esc_techniques";
constexpr const char* kPrivEscWindowSeconds = "priv_esc_window_seconds";
constexpr const char* kPrivEscVerdict = "priv_esc_verdict";
/* NTLM relay detector (T1550) */
constexpr const char* kNtlmRelayScore = "ntlm_relay_score";
constexpr const char* kNtlmRelaySignals = "ntlm_relay_signals";
constexpr const char* kNtlmRelaySources = "ntlm_relay_sources";
constexpr const char* kNtlmRelayTargetAccounts = "ntlm_relay_target_accounts";
constexpr const char* kNtlmRelayWindowSeconds = "ntlm_relay_window_seconds";
constexpr const char* kNtlmRelayVerdict = "ntlm_relay_verdict";
/* Browser data theft detector (T1555) */
constexpr const char* kBrowserTheftScore = "browser_theft_score";
constexpr const char* kBrowserTheftBrowsers = "browser_theft_browsers";
constexpr const char* kBrowserTheftDataTypes = "browser_theft_data_types";
constexpr const char* kBrowserTheftWindowSeconds = "browser_theft_window_seconds";
constexpr const char* kBrowserTheftVerdict = "browser_theft_verdict";
/* Archive staging detector (T1560.001) */
constexpr const char* kArchiveStagingScore = "archive_staging_score";
constexpr const char* kArchiveStagingSignals = "archive_staging_signals";
constexpr const char* kArchiveStagingTools = "archive_staging_tools";
constexpr const char* kArchiveStagingArchives = "archive_staging_archives";
constexpr const char* kArchiveStagingExtractedCount = "archive_staging_extracted_count";
constexpr const char* kArchiveStagingRapidCount = "archive_staging_rapid_count";
constexpr const char* kArchiveStagingWindowSeconds = "archive_staging_window_seconds";
constexpr const char* kArchiveStagingVerdict = "archive_staging_verdict";
/* DoH abuse detector (T1071.004) */
constexpr const char* kDohAbuseScore = "doh_abuse_score";
constexpr const char* kDohAbuseSignals = "doh_abuse_signals";
constexpr const char* kDohAbuseEndpoints = "doh_abuse_endpoints";
constexpr const char* kDohAbuseQueryCount = "doh_abuse_query_count";
constexpr const char* kDohAbuseWindowSeconds = "doh_abuse_window_seconds";
constexpr const char* kDohAbuseVerdict = "doh_abuse_verdict";
/* Service install abuse detector (T1543.003) */
constexpr const char* kSvcInstallScore = "svc_install_score";
constexpr const char* kSvcInstallSignals = "svc_install_signals";
constexpr const char* kSvcInstallService = "svc_install_service";
constexpr const char* kSvcInstallImagePath = "svc_install_image_path";
constexpr const char* kSvcInstallVerdict = "svc_install_verdict";
/* Shadow-copy suppression detector (T1490) */
constexpr const char* kShadowCopyScore = "shadow_copy_score";
constexpr const char* kShadowCopyVerdict = "shadow_copy_verdict";
constexpr const char* kShadowCopySignals = "shadow_copy_signals";
/* Mass-persistence ransomware precursor detector */
constexpr const char* kPersistBurstScore = "persist_burst_score";
constexpr const char* kPersistBurstVerdict = "persist_burst_verdict";
constexpr const char* kPersistBurstMechanisms = "persist_burst_mechanisms";
constexpr const char* kPersistBurstCount = "persist_burst_count";
constexpr const char* kPersistBurstWindowSeconds =
    "persist_burst_window_seconds";
/* BITS abuse detector (T1197) */
constexpr const char* kBitsAbuseScore = "bits_abuse_score";
constexpr const char* kBitsAbuseSignals = "bits_abuse_signals";
constexpr const char* kBitsAbuseTools = "bits_abuse_tools";
constexpr const char* kBitsAbuseUrls = "bits_abuse_urls";
constexpr const char* kBitsAbuseTargets = "bits_abuse_targets";
constexpr const char* kBitsAbuseWindowSeconds = "bits_abuse_window_seconds";
constexpr const char* kBitsAbuseVerdict = "bits_abuse_verdict";
/* Cryptominer detector (T1496) */
constexpr const char* kCryptoMinerScore = "crypto_miner_score";
constexpr const char* kCryptoMinerPoolDomains = "crypto_miner_pool_domains";
constexpr const char* kCryptoMinerPoolIps = "crypto_miner_pool_ips";
constexpr const char* kCryptoMinerSignals = "crypto_miner_signals";
constexpr const char* kCryptoMinerWindowSeconds = "crypto_miner_window_seconds";
constexpr const char* kCryptoMinerVerdict = "crypto_miner_verdict";
/* Anti-analysis / evasion detector (T1497) */
constexpr const char* kAntiAnalysisScore = "anti_analysis_score";
constexpr const char* kAntiAnalysisSignals = "anti_analysis_signals";
constexpr const char* kAntiAnalysisTechniques = "anti_analysis_techniques";
constexpr const char* kAntiAnalysisWindowSeconds = "anti_analysis_window_seconds";
constexpr const char* kAntiAnalysisVerdict = "anti_analysis_verdict";
/* Script host abuse detector (T1059.005 / T1059.007 / T1105) */
constexpr const char* kScriptHostScore = "script_host_score";
constexpr const char* kScriptHostSignals = "script_host_signals";
constexpr const char* kScriptHostEngine = "script_host_engine";
constexpr const char* kScriptHostVerdict = "script_host_verdict";
/* Account operation detector (T1136.001 / T1098.001 / T1087.001) */
constexpr const char* kAccountOpScore = "account_op_score";
constexpr const char* kAccountOpSignals = "account_op_signals";
constexpr const char* kAccountOpCommands = "account_op_commands";
constexpr const char* kAccountOpVerdict = "account_op_verdict";
/* Tunneling tool detector (T1572 / T1090) */
constexpr const char* kTunnelScore = "tunnel_score";
constexpr const char* kTunnelSignals = "tunnel_signals";
constexpr const char* kTunnelTools = "tunnel_tools";
constexpr const char* kTunnelVerdict = "tunnel_verdict";
/* Surveillance detector (T1115 / T1113 / T1056.001 / T1125) */
constexpr const char* kSurveillanceScore = "surveillance_score";
constexpr const char* kSurveillanceSignals = "surveillance_signals";
constexpr const char* kSurveillanceCount = "surveillance_count";
constexpr const char* kSurveillanceWindowSeconds = "surveillance_window_seconds";
constexpr const char* kSurveillanceVerdict = "surveillance_verdict";
/* Web shell detector (T1505.003) */
constexpr const char* kWebshellScore = "webshell_score";
constexpr const char* kWebshellReasons = "webshell_reasons";
constexpr const char* kWebshellPath = "webshell_path";
constexpr const char* kWebshellExtension = "webshell_extension";
constexpr const char* kWebshellVerdict = "webshell_verdict";
/* USB exfiltration detector (T1025) */
constexpr const char* kUsbExfilScore = "usb_exfil_score";
constexpr const char* kUsbExfilCount = "usb_exfil_count";
constexpr const char* kUsbExfilDrive = "usb_exfil_drive";
constexpr const char* kUsbExfilWindowSeconds = "usb_exfil_window_seconds";
constexpr const char* kUsbExfilSensitive = "usb_exfil_sensitive";
constexpr const char* kUsbExfilVerdict = "usb_exfil_verdict";
constexpr const char* kUsbExfilSamples = "usb_exfil_samples";
/* Firewall rule detector (T1562.004) */
constexpr const char* kFirewallRuleScore = "firewall_rule_score";
constexpr const char* kFirewallRuleSignals = "firewall_rule_signals";
constexpr const char* kFirewallRuleVerdict = "firewall_rule_verdict";
/* Share change detector (T1021.002 / T1070.005) */
constexpr const char* kShareChangeScore = "share_change_score";
constexpr const char* kShareChangeSignals = "share_change_signals";
constexpr const char* kShareChangeVerdict = "share_change_verdict";
/* Local account detector (T1136.001 / T1098.001) */
constexpr const char* kLocalAccountScore = "local_account_score";
constexpr const char* kLocalAccountSignals = "local_account_signals";
constexpr const char* kLocalAccountVerdict = "local_account_verdict";
/* Canary (honeypot) file detector */
constexpr const char* kCanaryFlag = "canary";
constexpr const char* kCanaryScore = "canary_score";
constexpr const char* kCanaryVerdict = "canary_verdict";
constexpr const char* kCanaryPath = "canary_path";
constexpr const char* kCanaryReasons = "canary_reasons";
/* Hook persistence detector (T1546.008 / T1546.012 / T1546.015) */
constexpr const char* kHookPersistScore = "hook_persist_score";
constexpr const char* kHookPersistVerdict = "hook_persist_verdict";
constexpr const char* kHookPersistTechnique = "hook_persist_technique";
constexpr const char* kHookPersistReasons = "hook_persist_reasons";
constexpr const char* kHookPersistKey = "hook_persist_key";
/* Scheduled task abuse detector (T1053.005) */
constexpr const char* kTaskAbuseScore = "task_abuse_score";
constexpr const char* kTaskAbuseVerdict = "task_abuse_verdict";
constexpr const char* kTaskAbuseSignals = "task_abuse_signals";
constexpr const char* kTaskAbuseTask = "task_abuse_task";
/* Filename masquerading detector (T1036) */
constexpr const char* kMasqueradeScore = "masquerade_score";
constexpr const char* kMasqueradeVerdict = "masquerade_verdict";
constexpr const char* kMasqueradeSignals = "masquerade_signals";
constexpr const char* kMasqueradeImage = "masquerade_image";
/* Parent-PID spoofing detector (T1134.004) */
constexpr const char* kPpidSpoofScore = "ppid_spoof_score";
constexpr const char* kPpidSpoofVerdict = "ppid_spoof_verdict";
constexpr const char* kPpidSpoofSignals = "ppid_spoof_signals";
/* Network discovery burst detector (T1018 / T1049) */
constexpr const char* kNetDiscoveryScore = "net_discovery_score";
constexpr const char* kNetDiscoveryVerdict = "net_discovery_verdict";
constexpr const char* kNetDiscoverySignals = "net_discovery_signals";
/* Private key theft detector (T1552.004) */
constexpr const char* kPrivateKeyScore = "private_key_score";
constexpr const char* kPrivateKeyVerdict = "private_key_verdict";
constexpr const char* kPrivateKeySignals = "private_key_signals";
/* AV tampering detector (T1562.001) */
constexpr const char* kAvTamperScore = "av_tamper_score";
constexpr const char* kAvTamperVerdict = "av_tamper_verdict";
constexpr const char* kAvTamperSignals = "av_tamper_signals";
/* Timestomping detector (T1070.006) */
constexpr const char* kTimestompScore = "timestomp_score";
constexpr const char* kTimestompVerdict = "timestomp_verdict";
constexpr const char* kTimestompSignals = "timestomp_signals";
constexpr const char* kTimestompCommand = "timestomp_command";
/* One-liner LSASS dump detector (T1003.001) */
constexpr const char* kLsassDumpScore = "lsass_dump_score";
constexpr const char* kLsassDumpVerdict = "lsass_dump_verdict";
constexpr const char* kLsassDumpSignals = "lsass_dump_signals";
constexpr const char* kLsassDumpCommand = "lsass_dump_command";
/* Accessibility feature hijack detector (T1546.008) */
    constexpr const char* kAccessibilityHijackScore = "accessibility_hijack_score";
    constexpr const char* kAccessibilityHijackVerdict = "accessibility_hijack_verdict";
    constexpr const char* kAccessibilityHijackSignals = "accessibility_hijack_signals";
    constexpr const char* kAccessibilityHijackTarget = "accessibility_hijack_target";
    constexpr const char* kAccessibilityHijackEvidence = "accessibility_hijack_evidence";
    /* ACL abuse detector (T1222.001/T1222.002) */
    constexpr const char* kAclAbuseScore = "acl_abuse_score";
    constexpr const char* kAclAbuseVerdict = "acl_abuse_verdict";
    constexpr const char* kAclAbuseSignals = "acl_abuse_signals";
    constexpr const char* kAclAbuseCommand = "acl_abuse_command";
    /* AMSI bypass detector (T1562.001) */
    constexpr const char* kAmsiBypassScore = "amsi_bypass_score";
    constexpr const char* kAmsiBypassVerdict = "amsi_bypass_verdict";
    constexpr const char* kAmsiBypassSignals = "amsi_bypass_signals";
    constexpr const char* kAmsiBypassText = "amsi_bypass_text";
    /* AppInit DLL persistence detector (T1546.010) */
    constexpr const char* kAppinitDllScore = "appinit_dll_score";
    constexpr const char* kAppinitDllVerdict = "appinit_dll_verdict";
    constexpr const char* kAppinitDllSignals = "appinit_dll_signals";
    constexpr const char* kAppinitDllText = "appinit_dll_text";
    /* AS-REP roasting detector (T1558.004) */
    constexpr const char* kAsRepRoastScore = "as_rep_roast_score";
    constexpr const char* kAsRepRoastVerdict = "as_rep_roast_verdict";
    constexpr const char* kAsRepRoastCount = "as_rep_roast_count";
    constexpr const char* kAsRepRoastTarget = "as_rep_roast_target";
    constexpr const char* kAsRepRoastSrcIp = "as_rep_roast_src_ip";
    constexpr const char* kAsRepRoastWindowSeconds = "as_rep_roast_window_seconds";
    /* Boot provider persistence detector (T1547.003 / T1547.012) */
    constexpr const char* kBootProviderScore = "boot_provider_score";
    constexpr const char* kBootProviderVerdict = "boot_provider_verdict";
    constexpr const char* kBootProviderSignals = "boot_provider_signals";
    constexpr const char* kBootProviderText = "boot_provider_text";
    /* Certificate trust abuse detector (T1553.004 / T1552.004) */
    constexpr const char* kCertAbuseScore = "cert_abuse_score";
    constexpr const char* kCertAbuseVerdict = "cert_abuse_verdict";
    constexpr const char* kCertAbuseSignals = "cert_abuse_signals";
    constexpr const char* kCertAbuseText = "cert_abuse_text";
    /* COR profiler hijack detector (T1574.012) */
    constexpr const char* kCorProfilerHijackScore = "cor_profiler_hijack_score";
    constexpr const char* kCorProfilerHijackVerdict = "cor_profiler_hijack_verdict";
    constexpr const char* kCorProfilerHijackSignals = "cor_profiler_hijack_signals";
    constexpr const char* kCorProfilerHijackCommand = "cor_profiler_hijack_command";
    /* Credential file hunt detector (T1552.001) */
    constexpr const char* kCredFileHuntScore = "cred_file_hunt_score";
    constexpr const char* kCredFileHuntVerdict = "cred_file_hunt_verdict";
    constexpr const char* kCredFileHuntSignals = "cred_file_hunt_signals";
    constexpr const char* kCredFileHuntCommand = "cred_file_hunt_command";
    /* DCSync detector (T1003.006) */
    constexpr const char* kDcsyncScore = "dcsync_score";
    constexpr const char* kDcsyncVerdict = "dcsync_verdict";
    constexpr const char* kDcsyncSignals = "dcsync_signals";
    constexpr const char* kDcsyncTools = "dcsync_tools";
    /* Dev util proxy detector (T1127 / T1218.004) */
    constexpr const char* kDevUtilProxyScore = "dev_util_proxy_score";
    constexpr const char* kDevUtilProxyVerdict = "dev_util_proxy_verdict";
    constexpr const char* kDevUtilProxySignals = "dev_util_proxy_signals";
    constexpr const char* kDevUtilProxyText = "dev_util_proxy_text";
    /* Disk wipe detector (T1485/T1561) */
    constexpr const char* kDiskWipeScore = "disk_wipe_score";
    constexpr const char* kDiskWipeVerdict = "disk_wipe_verdict";
    constexpr const char* kDiskWipeSignals = "disk_wipe_signals";
    constexpr const char* kDiskWipeTargets = "disk_wipe_targets";
    /* CMSTP / INF proxy execution detector (T1218.003 / T1127) */
constexpr const char* kCmstpBypassScore = "cmstp_bypass_score";
constexpr const char* kCmstpBypassVerdict = "cmstp_bypass_verdict";
constexpr const char* kCmstpBypassSignals = "cmstp_bypass_signals";
constexpr const char* kCmstpBypassText = "cmstp_bypass_text";
/* File association hijack detector (T1546.001) */
constexpr const char* kFileAssocScore = "file_assoc_score";
constexpr const char* kFileAssocVerdict = "file_assoc_verdict";
constexpr const char* kFileAssocSignals = "file_assoc_signals";
constexpr const char* kFileAssocText = "file_assoc_text";
/* Hidden window / concealed execution detector (T1564.003) */
constexpr const char* kHiddenWindowScore = "hidden_window_score";
constexpr const char* kHiddenWindowVerdict = "hidden_window_verdict";
constexpr const char* kHiddenWindowSignals = "hidden_window_signals";
constexpr const char* kHiddenWindowText = "hidden_window_text";
/* Browser extension side-loading / forced-install detector (T1176) */
constexpr const char* kBrowserExtensionScore = "browser_extension_score";
constexpr const char* kBrowserExtensionVerdict = "browser_extension_verdict";
constexpr const char* kBrowserExtensionSignals = "browser_extension_signals";
constexpr const char* kBrowserExtensionEvidence = "browser_extension_evidence";
/* Office application-startup persistence detector (T1137) */
constexpr const char* kOfficePersistScore = "office_persist_score";
constexpr const char* kOfficePersistVerdict = "office_persist_verdict";
constexpr const char* kOfficePersistSignals = "office_persist_signals";
constexpr const char* kOfficePersistText = "office_persist_text";
/* Startup-folder shortcut persistence detector (T1547.009) */
constexpr const char* kShortcutPersistScore = "shortcut_persist_score";
constexpr const char* kShortcutPersistVerdict = "shortcut_persist_verdict";
constexpr const char* kShortcutPersistSignals = "shortcut_persist_signals";
constexpr const char* kShortcutPersistText = "shortcut_persist_text";
/* Indirect command execution detector (T1202) */
constexpr const char* kIndirectExecScore = "indirect_exec_score";
constexpr const char* kIndirectExecVerdict = "indirect_exec_verdict";
constexpr const char* kIndirectExecSignals = "indirect_exec_signals";
constexpr const char* kIndirectExecText = "indirect_exec_text";
/* Screensaver persistence detector (T1546.002) */
constexpr const char* kScreensaverPersistScore = "screensaver_persist_score";
constexpr const char* kScreensaverPersistVerdict = "screensaver_persist_verdict";
constexpr const char* kScreensaverPersistSignals = "screensaver_persist_signals";
constexpr const char* kScreensaverPersistText = "screensaver_persist_text";
/* Service path abuse detector (T1574.009 / T1574.010) */
constexpr const char* kSvcPathAbuseScore = "svc_path_abuse_score";
constexpr const char* kSvcPathAbuseVerdict = "svc_path_abuse_verdict";
constexpr const char* kSvcPathAbuseSignals = "svc_path_abuse_signals";
constexpr const char* kSvcPathAbuseText = "svc_path_abuse_text";
/* ServiceDll hijack detector (T1574.011) */
constexpr const char* kServiceDllHijackScore = "service_dll_hijack_score";
constexpr const char* kServiceDllHijackVerdict = "service_dll_hijack_verdict";
constexpr const char* kServiceDllHijackSignals = "service_dll_hijack_signals";
constexpr const char* kServiceDllHijackText = "service_dll_hijack_text";
/* DLL search order hijack detector (T1574.002) */
constexpr const char* kDllSearchOrderScore = "dll_search_order_score";
constexpr const char* kDllSearchOrderVerdict = "dll_search_order_verdict";
constexpr const char* kDllSearchOrderSignals = "dll_search_order_signals";
constexpr const char* kDllSearchOrderText = "dll_search_order_text";
/* Service recovery hijack detector (T1037.004) */
constexpr const char* kSvcRecoveryScore = "svc_recovery_score";
constexpr const char* kSvcRecoveryVerdict = "svc_recovery_verdict";
constexpr const char* kSvcRecoverySignals = "svc_recovery_signals";
constexpr const char* kSvcRecoveryText = "svc_recovery_text";
/* COM hijack detector (T1546.015) */
constexpr const char* kComHijackScore = "com_hijack_score";
constexpr const char* kComHijackVerdict = "com_hijack_verdict";
constexpr const char* kComHijackSignals = "com_hijack_signals";
constexpr const char* kComHijackText = "com_hijack_text";
/* Winlogon hijack detector (T1547.004) */
constexpr const char* kWinlogonHijackScore = "winlogon_hijack_score";
constexpr const char* kWinlogonHijackVerdict = "winlogon_hijack_verdict";
constexpr const char* kWinlogonHijackSignals = "winlogon_hijack_signals";
constexpr const char* kWinlogonHijackText = "winlogon_hijack_text";
/* Mshta abuse detector (T1218.005) */
constexpr const char* kMshtaAbuseScore = "mshta_abuse_score";
constexpr const char* kMshtaAbuseVerdict = "mshta_abuse_verdict";
constexpr const char* kMshtaAbuseSignals = "mshta_abuse_signals";
constexpr const char* kMshtaAbuseText = "mshta_abuse_text";
/* WSL abuse detector (T1202) */
constexpr const char* kWslAbuseScore = "wsl_abuse_score";
constexpr const char* kWslAbuseVerdict = "wsl_abuse_verdict";
constexpr const char* kWslAbuseSignals = "wsl_abuse_signals";
constexpr const char* kWslAbuseText = "wsl_abuse_text";
/* MSDT / ms-msdt abuse detector (T1203) */
constexpr const char* kMsdtAbuseScore = "msdt_abuse_score";
constexpr const char* kMsdtAbuseVerdict = "msdt_abuse_verdict";
constexpr const char* kMsdtAbuseSignals = "msdt_abuse_signals";
constexpr const char* kMsdtAbuseText = "msdt_abuse_text";
/* Disk-image mount abuse detector (T1553.005) */
constexpr const char* kIsoMountScore = "iso_mount_score";
constexpr const char* kIsoMountVerdict = "iso_mount_verdict";
constexpr const char* kIsoMountSignals = "iso_mount_signals";
constexpr const char* kIsoMountText = "iso_mount_text";
constexpr const char* kPsProfileScore = "ps_profile_score";
constexpr const char* kPsProfileVerdict = "ps_profile_verdict";
constexpr const char* kPsProfileSignals = "ps_profile_signals";
constexpr const char* kPsProfileText = "ps_profile_text";
/* DowngradeAttackDetector */
constexpr const char* kDowngradeAttackScore = "downgrade_attack_score";
constexpr const char* kDowngradeAttackSignals = "downgrade_attack_signals";
constexpr const char* kDowngradeAttackText = "downgrade_attack_text";
constexpr const char* kDowngradeAttackVerdict = "downgrade_attack_verdict";
/* DpapiAbuseDetector */
constexpr const char* kDpapiAbuseScore = "dpapi_abuse_score";
constexpr const char* kDpapiAbuseSignals = "dpapi_abuse_signals";
constexpr const char* kDpapiAbuseText = "dpapi_abuse_text";
constexpr const char* kDpapiAbuseVerdict = "dpapi_abuse_verdict";
/* EmailCollectionDetector */
constexpr const char* kEmailCollectionCommand = "email_collection_command";
constexpr const char* kEmailCollectionScore = "email_collection_score";
constexpr const char* kEmailCollectionSignals = "email_collection_signals";
constexpr const char* kEmailCollectionVerdict = "email_collection_verdict";
/* EtwScriptTamperDetector */
constexpr const char* kEtwScriptScore = "etw_script_score";
constexpr const char* kEtwScriptSignals = "etw_script_signals";
constexpr const char* kEtwScriptText = "etw_script_text";
constexpr const char* kEtwScriptVerdict = "etw_script_verdict";
/* ForcedAuthDetector */
constexpr const char* kForcedAuthScore = "forced_auth_score";
constexpr const char* kForcedAuthSignals = "forced_auth_signals";
constexpr const char* kForcedAuthTargets = "forced_auth_targets";
constexpr const char* kForcedAuthVerdict = "forced_auth_verdict";
/* GoldenTicketDetector */
constexpr const char* kGoldenTicketRc4Count = "golden_ticket_rc4_count";
constexpr const char* kGoldenTicketScore = "golden_ticket_score";
constexpr const char* kGoldenTicketSignals = "golden_ticket_signals";
constexpr const char* kGoldenTicketTargets = "golden_ticket_targets";
constexpr const char* kGoldenTicketVerdict = "golden_ticket_verdict";
constexpr const char* kGoldenTicketWindowSeconds = "golden_ticket_window_seconds";
/* GpoAbuseDetector */
constexpr const char* kGpoAbuseScore = "gpo_abuse_score";
constexpr const char* kGpoAbuseSignals = "gpo_abuse_signals";
constexpr const char* kGpoAbuseText = "gpo_abuse_text";
constexpr const char* kGpoAbuseVerdict = "gpo_abuse_verdict";
/* HiddenArtifactsDetector */
constexpr const char* kHiddenArtifactsAdsPaths = "hidden_artifacts_ads_paths";
constexpr const char* kHiddenArtifactsPaths = "hidden_artifacts_paths";
constexpr const char* kHiddenArtifactsScore = "hidden_artifacts_score";
constexpr const char* kHiddenArtifactsSignals = "hidden_artifacts_signals";
constexpr const char* kHiddenArtifactsVerdict = "hidden_artifacts_verdict";
constexpr const char* kHiddenArtifactsWindowSeconds = "hidden_artifacts_window_seconds";
/* HistoryTamperDetector */
constexpr const char* kHistoryTamperScore = "history_tamper_score";
constexpr const char* kHistoryTamperSignals = "history_tamper_signals";
constexpr const char* kHistoryTamperText = "history_tamper_text";
constexpr const char* kHistoryTamperVerdict = "history_tamper_verdict";
/* HiveCopyDetector */
constexpr const char* kHiveCopyCommand = "hive_copy_command";
constexpr const char* kHiveCopyScore = "hive_copy_score";
constexpr const char* kHiveCopySignals = "hive_copy_signals";
constexpr const char* kHiveCopyVerdict = "hive_copy_verdict";
/* HostsRedirectDetector */
constexpr const char* kHostsRedirectScore = "hosts_redirect_score";
constexpr const char* kHostsRedirectSignals = "hosts_redirect_signals";
constexpr const char* kHostsRedirectText = "hosts_redirect_text";
constexpr const char* kHostsRedirectVerdict = "hosts_redirect_verdict";
/* IisModuleDetector */
constexpr const char* kIisModuleScore = "iis_module_score";
constexpr const char* kIisModuleSignals = "iis_module_signals";
constexpr const char* kIisModuleText = "iis_module_text";
constexpr const char* kIisModuleVerdict = "iis_module_verdict";
/* InputSimulationDetector */
constexpr const char* kInputSimEventCount = "input_sim_event_count";
constexpr const char* kInputSimScore = "input_sim_score";
constexpr const char* kInputSimSignals = "input_sim_signals";
constexpr const char* kInputSimVerdict = "input_sim_verdict";
constexpr const char* kInputSimWindowSeconds = "input_sim_window_seconds";
/* LogonScriptPersistDetector */
constexpr const char* kLogonScriptScore = "logon_script_score";
constexpr const char* kLogonScriptSignals = "logon_script_signals";
constexpr const char* kLogonScriptText = "logon_script_text";
constexpr const char* kLogonScriptVerdict = "logon_script_verdict";
/* LsaPackageDetector */
constexpr const char* kLsaPackageScore = "lsa_package_score";
constexpr const char* kLsaPackageSignals = "lsa_package_signals";
constexpr const char* kLsaPackageText = "lsa_package_text";
constexpr const char* kLsaPackageVerdict = "lsa_package_verdict";
/* MotwBypassDetector */
constexpr const char* kMotwBypassScore = "motw_bypass_score";
constexpr const char* kMotwBypassSignals = "motw_bypass_signals";
constexpr const char* kMotwBypassText = "motw_bypass_text";
constexpr const char* kMotwBypassVerdict = "motw_bypass_verdict";
/* NetshHelperDetector */
constexpr const char* kNetshHelperScore = "netsh_helper_score";
constexpr const char* kNetshHelperSignals = "netsh_helper_signals";
constexpr const char* kNetshHelperText = "netsh_helper_text";
constexpr const char* kNetshHelperVerdict = "netsh_helper_verdict";
/* NetworkSniffingDetector */
constexpr const char* kNetworkSniffingCommand = "network_sniffing_command";
constexpr const char* kNetworkSniffingScore = "network_sniffing_score";
constexpr const char* kNetworkSniffingSignals = "network_sniffing_signals";
constexpr const char* kNetworkSniffingVerdict = "network_sniffing_verdict";
/* NtdsDitDetector */
constexpr const char* kNtdsDitScore = "ntds_dit_score";
constexpr const char* kNtdsDitSignals = "ntds_dit_signals";
constexpr const char* kNtdsDitVerdict = "ntds_dit_verdict";
/* PassTheHashDetector */
constexpr const char* kPassTheHashScore = "pass_the_hash_score";
constexpr const char* kPassTheHashSignals = "pass_the_hash_signals";
constexpr const char* kPassTheHashTools = "pass_the_hash_tools";
constexpr const char* kPassTheHashVerdict = "pass_the_hash_verdict";
/* PasswordCrackingDetector */
constexpr const char* kPasswordCrackScore = "password_crack_score";
constexpr const char* kPasswordCrackSignals = "password_crack_signals";
constexpr const char* kPasswordCrackTools = "password_crack_tools";
constexpr const char* kPasswordCrackVerdict = "password_crack_verdict";
/* PathInterceptionDetector */
constexpr const char* kPathInterceptScore = "path_intercept_score";
constexpr const char* kPathInterceptSignals = "path_intercept_signals";
constexpr const char* kPathInterceptText = "path_intercept_text";
constexpr const char* kPathInterceptVerdict = "path_intercept_verdict";
/* PeAnomalyDetector */
constexpr const char* kPeAnomalyScore = "pe_anomaly_score";
constexpr const char* kPeAnomalySections = "pe_anomaly_sections";
constexpr const char* kPeAnomalySignals = "pe_anomaly_signals";
constexpr const char* kPeAnomalyVerdict = "pe_anomaly_verdict";
/* RansomOpsDetector */
constexpr const char* kRansomOpsScore = "ransom_ops_score";
constexpr const char* kRansomOpsSignals = "ransom_ops_signals";
constexpr const char* kRansomOpsVerdict = "ransom_ops_verdict";
/* RdpSessionHijackDetector */
constexpr const char* kRdpSessionHijackDest = "rdp_session_hijack_dest";
constexpr const char* kRdpSessionHijackScore = "rdp_session_hijack_score";
constexpr const char* kRdpSessionHijackSession = "rdp_session_hijack_session";
constexpr const char* kRdpSessionHijackSignals = "rdp_session_hijack_signals";
constexpr const char* kRdpSessionHijackVerdict = "rdp_session_hijack_verdict";
/* RegCredHuntDetector */
constexpr const char* kRegCredHuntScore = "reg_cred_hunt_score";
constexpr const char* kRegCredHuntSignals = "reg_cred_hunt_signals";
constexpr const char* kRegCredHuntText = "reg_cred_hunt_text";
constexpr const char* kRegCredHuntVerdict = "reg_cred_hunt_verdict";
/* RemoteExecDetector */
constexpr const char* kRemoteExecScore = "remote_exec_score";
constexpr const char* kRemoteExecSignals = "remote_exec_signals";
constexpr const char* kRemoteExecTools = "remote_exec_tools";
constexpr const char* kRemoteExecVerdict = "remote_exec_verdict";
/* SecbootTamperDetector */
constexpr const char* kSecbootTamperCommand = "secboot_tamper_command";
constexpr const char* kSecbootTamperScore = "secboot_tamper_score";
constexpr const char* kSecbootTamperSignals = "secboot_tamper_signals";
constexpr const char* kSecbootTamperVerdict = "secboot_tamper_verdict";
/* ShimDbDetector */
constexpr const char* kShimDbPaths = "shim_db_paths";
constexpr const char* kShimDbScore = "shim_db_score";
constexpr const char* kShimDbSignals = "shim_db_signals";
constexpr const char* kShimDbVerdict = "shim_db_verdict";
/* SignedBinaryAbuseDetector */
constexpr const char* kSignedBinaryAbuseScore = "signed_binary_abuse_score";
constexpr const char* kSignedBinaryAbuseSignals = "signed_binary_abuse_signals";
constexpr const char* kSignedBinaryAbuseText = "signed_binary_abuse_text";
constexpr const char* kSignedBinaryAbuseVerdict = "signed_binary_abuse_verdict";
/* SipHijackDetector */
constexpr const char* kSipHijackScore = "sip_hijack_score";
constexpr const char* kSipHijackSignals = "sip_hijack_signals";
constexpr const char* kSipHijackText = "sip_hijack_text";
constexpr const char* kSipHijackVerdict = "sip_hijack_verdict";
/* SshKeyPersistenceDetector */
constexpr const char* kSshKeyPersistScore = "ssh_key_persist_score";
constexpr const char* kSshKeyPersistSignals = "ssh_key_persist_signals";
constexpr const char* kSshKeyPersistText = "ssh_key_persist_text";
constexpr const char* kSshKeyPersistVerdict = "ssh_key_persist_verdict";
/* TicketCacheAbuseDetector */
constexpr const char* kTicketCacheAbuseCommand = "ticket_cache_abuse_command";
constexpr const char* kTicketCacheAbuseScore = "ticket_cache_abuse_score";
constexpr const char* kTicketCacheAbuseSignals = "ticket_cache_abuse_signals";
constexpr const char* kTicketCacheAbuseVerdict = "ticket_cache_abuse_verdict";
/* TokenImpersonationDetector */
constexpr const char* kTokenImpersonationCommand = "token_impersonation_command";
constexpr const char* kTokenImpersonationScore = "token_impersonation_score";
constexpr const char* kTokenImpersonationSignals = "token_impersonation_signals";
constexpr const char* kTokenImpersonationVerdict = "token_impersonation_verdict";
/* Handle guard detector (high-risk process/thread handle access). */
constexpr const char* kHandleGuardScore = "handle_guard_score";
constexpr const char* kHandleGuardVerdict = "handle_guard_verdict";
constexpr const char* kHandleGuardSignals = "handle_guard_signals";
/* NamedPipeAbuseDetector (suspicious named-pipe IPC). */
constexpr const char* kNamedPipeAbuseScore = "named_pipe_abuse_score";
constexpr const char* kNamedPipeAbuseVerdict = "named_pipe_abuse_verdict";
constexpr const char* kNamedPipeAbuseSignals = "named_pipe_abuse_signals";
constexpr const char* kNamedPipeAbuseOperationCount =
    "named_pipe_abuse_operation_count";
constexpr const char* kNamedPipeAbuseDistinctPids =
    "named_pipe_abuse_distinct_pids";
constexpr const char* kNamedPipeAbuseWindowSeconds =
    "named_pipe_abuse_window_seconds";
/* WebExfilDetector */
constexpr const char* kWebExfilScore = "web_exfil_score";
constexpr const char* kWebExfilSignals = "web_exfil_signals";
constexpr const char* kWebExfilText = "web_exfil_text";
constexpr const char* kWebExfilVerdict = "web_exfil_verdict";
/* WifiCredTheftDetector */
constexpr const char* kWifiTheftEnumCount = "wifi_theft_enum_count";
constexpr const char* kWifiTheftScore = "wifi_theft_score";
constexpr const char* kWifiTheftSignals = "wifi_theft_signals";
constexpr const char* kWifiTheftTools = "wifi_theft_tools";
constexpr const char* kWifiTheftVerdict = "wifi_theft_verdict";
constexpr const char* kWifiTheftWindowSeconds = "wifi_theft_window_seconds";
/* WinrmAbuseDetector */
constexpr const char* kWinrmAbuseCommand = "winrm_abuse_command";
constexpr const char* kWinrmAbuseScore = "winrm_abuse_score";
constexpr const char* kWinrmAbuseSignals = "winrm_abuse_signals";
constexpr const char* kWinrmAbuseVerdict = "winrm_abuse_verdict";
/* WinrmConfigTamperDetector */
constexpr const char* kWinrmConfigTamperScore = "winrm_config_tamper_score";
constexpr const char* kWinrmConfigTamperSignals = "winrm_config_tamper_signals";
constexpr const char* kWinrmConfigTamperText = "winrm_config_tamper_text";
constexpr const char* kWinrmConfigTamperVerdict = "winrm_config_tamper_verdict";
/* XslScriptDetector */
constexpr const char* kXslScriptScore = "xsl_script_score";
constexpr const char* kXslScriptSignals = "xsl_script_signals";
constexpr const char* kXslScriptText = "xsl_script_text";
constexpr const char* kXslScriptVerdict = "xsl_script_verdict";
/* ObfuscationDetector (T1027) */
constexpr const char* kObfuscationScore = "obfuscation_score";
constexpr const char* kObfuscationVerdict = "obfuscation_verdict";
constexpr const char* kObfuscationSignals = "obfuscation_signals";
constexpr const char* kObfuscationText = "obfuscation_text";
constexpr const char* kObfuscationHardSignal = "obfuscation_hard_signal";
/* RegModifyDetector (T1112) */
constexpr const char* kRegModifyScore = "reg_modify_score";
constexpr const char* kRegModifyVerdict = "reg_modify_verdict";
constexpr const char* kRegModifySignals = "reg_modify_signals";
constexpr const char* kRegModifyTechniques = "reg_modify_techniques";
/* WmiExecDetector (T1047) */
constexpr const char* kWmiExecScore = "wmi_exec_score";
constexpr const char* kWmiExecVerdict = "wmi_exec_verdict";
constexpr const char* kWmiExecSignals = "wmi_exec_signals";
constexpr const char* kWmiExecTechniques = "wmi_exec_techniques";
/* LocalCollectDetector (T1005) */
constexpr const char* kLocalCollectScore = "local_collect_score";
constexpr const char* kLocalCollectVerdict = "local_collect_verdict";
constexpr const char* kLocalCollectSignals = "local_collect_signals";
constexpr const char* kLocalCollectTechniques = "local_collect_techniques";
/* LateralTransferDetector (T1570) */
constexpr const char* kLateralTransferScore = "lateral_transfer_score";
constexpr const char* kLateralTransferVerdict = "lateral_transfer_verdict";
constexpr const char* kLateralTransferSignals = "lateral_transfer_signals";
constexpr const char* kLateralTransferTechniques = "lateral_transfer_techniques";
/* ThreatIntelDetector (operator-supplied IoC feed; T1071/T1105/T1587) */
constexpr const char* kThreatIntelScore = "threat_intel_score";
constexpr const char* kThreatIntelVerdict = "threat_intel_verdict";
constexpr const char* kThreatIntelSignals = "threat_intel_signals";
constexpr const char* kThreatIntelIocIds = "threat_intel_ioc_ids";
constexpr const char* kThreatIntelIocTypes = "threat_intel_ioc_types";
constexpr const char* kThreatIntelIocSources = "threat_intel_ioc_sources";
constexpr const char* kThreatIntelIocConfidence = "threat_intel_ioc_confidence";
constexpr const char* kThreatIntelIocCount = "threat_intel_ioc_count";
constexpr const char* kThreatIntelFeed = "threat_intel_feed";
/* LateralChainDetector (multi-vector lateral movement; T1021/T1570/T1569.002) */
constexpr const char* kLateralChainScore = "lateral_chain_score";
constexpr const char* kLateralChainVerdict = "lateral_chain_verdict";
constexpr const char* kLateralChainSignals = "lateral_chain_signals";
constexpr const char* kLateralChainVectorCount = "lateral_chain_vector_count";
constexpr const char* kLateralChainEvidence = "lateral_chain_evidence";
constexpr const char* kLateralChainRemoteHost = "lateral_chain_remote_host";
constexpr const char* kLateralChainWindowSeconds =
    "lateral_chain_window_seconds";
/* CorrelationEngine (incident roll-up + kill-chain graph) */
constexpr const char* kCorrelatedIncidentId = "correlated_incident_id";
constexpr const char* kCorrelatedStage = "correlated_stage";
constexpr const char* kCorrelatedTactics = "correlated_tactics";
constexpr const char* kCorrelatedScore = "correlated_score";
constexpr const char* kCorrelatedAlertCount = "correlated_alert_count";
constexpr const char* kCorrelatedStageCount = "correlated_stage_count";
/* HostProfileDetector (per-actor discovery breadth; T1007/T1012/T1016/T1018/
 * T1069/T1087/T1082) */
constexpr const char* kHostProfileScore = "host_profile_score";
constexpr const char* kHostProfileVerdict = "host_profile_verdict";
constexpr const char* kHostProfileSignals = "host_profile_signals";
constexpr const char* kHostProfileCategories = "host_profile_categories";
constexpr const char* kHostProfileCategoryCount = "host_profile_category_count";
constexpr const char* kHostProfileWindowSeconds = "host_profile_window_seconds";
constexpr const char* kHostProfilePrivileged = "host_profile_privileged";

/* EventlogTamperDetector (clear/disable Windows event logs; T1070.001 / T1562.002) */
constexpr const char* kEventlogTamperScore = "eventlog_tamper_score";
constexpr const char* kEventlogTamperVerdict = "eventlog_tamper_verdict";
constexpr const char* kEventlogTamperSignals = "eventlog_tamper_signals";
constexpr const char* kEventlogTamperText = "eventlog_tamper_text";
/* SshAbuseDetector (SSH remote execution with suspicious options; T1021.004) */
constexpr const char* kSshAbuseScore = "ssh_abuse_score";
constexpr const char* kSshAbuseVerdict = "ssh_abuse_verdict";
constexpr const char* kSshAbuseSignals = "ssh_abuse_signals";
constexpr const char* kSshAbuseText = "ssh_abuse_text";

/* SoftwareDiscoveryDetector (per-actor software census breadth; T1518/T1518.001) */
constexpr const char* kSoftwareDiscoveryScore = "software_discovery_score";
constexpr const char* kSoftwareDiscoveryVerdict = "software_discovery_verdict";
constexpr const char* kSoftwareDiscoverySignals = "software_discovery_signals";
constexpr const char* kSoftwareDiscoveryCategories = "software_discovery_categories";
constexpr const char* kSoftwareDiscoveryCategoryCount = "software_discovery_category_count";

/* NetShareDiscoveryDetector (share-discovery burst; T1135) */
constexpr const char* kNetShareDiscoveryScore = "net_share_discovery_score";
constexpr const char* kNetShareDiscoveryVerdict = "net_share_discovery_verdict";
constexpr const char* kNetShareDiscoverySignals = "net_share_discovery_signals";
constexpr const char* kNetShareDiscoveryTargets = "net_share_discovery_targets";
constexpr const char* kNetShareDiscoveryCommandCount = "net_share_discovery_command_count";

/* NonstandardPortEgressDetector (outbound connection shape; T1095/T1571) */
constexpr const char* kNonstandardPortScore = "nonstandard_port_score";
constexpr const char* kNonstandardPortVerdict = "nonstandard_port_verdict";
constexpr const char* kNonstandardPortSignals = "nonstandard_port_signals";
constexpr const char* kNonstandardPortHostCount = "nonstandard_port_host_count";
constexpr const char* kNonstandardPortPortCount = "nonstandard_port_port_count";
constexpr const char* kNonstandardPortConnectionCount = "nonstandard_port_connection_count";

/* MailboxRuleDetector (mailbox rule forwarding; T1114.003) */
constexpr const char* kMailboxRuleScore = "mailbox_rule_score";
constexpr const char* kMailboxRuleVerdict = "mailbox_rule_verdict";
constexpr const char* kMailboxRuleSignals = "mailbox_rule_signals";
constexpr const char* kMailboxRuleCmdlets = "mailbox_rule_cmdlets";
constexpr const char* kMailboxRuleTargets = "mailbox_rule_targets";

/* LlmnrPoisonDetector (LLMNR/NBT-NS/mDNS poisoning; T1557.001) */
constexpr const char* kLlmnrPoisonScore = "llmnr_poison_score";
constexpr const char* kLlmnrPoisonVerdict = "llmnr_poison_verdict";
constexpr const char* kLlmnrPoisonSignals = "llmnr_poison_signals";
constexpr const char* kLlmnrPoisonPorts = "llmnr_poison_ports";
constexpr const char* kLlmnrPoisonTools = "llmnr_poison_tools";

/* NetProviderPersistDetector (NetworkProvider DLL persistence; T1556.008) */
constexpr const char* kNetProviderPersistScore = "netprovider_persist_score";
constexpr const char* kNetProviderPersistVerdict = "netprovider_persist_verdict";
constexpr const char* kNetProviderPersistSignals = "netprovider_persist_signals";
constexpr const char* kNetProviderPersistKeys = "netprovider_persist_keys";

/* PasswordVaultDetector (password manager vault access; T1555.005) */
constexpr const char* kPasswordVaultScore = "password_vault_score";
constexpr const char* kPasswordVaultVerdict = "password_vault_verdict";
constexpr const char* kPasswordVaultSignals = "password_vault_signals";
constexpr const char* kPasswordVaultTools = "password_vault_tools";

/* ArpPoisonDetector (ARP cache poisoning / MITM pre-positioning; T1557.002) */
constexpr const char* kArpPoisonScore = "arp_poison_score";
constexpr const char* kArpPoisonVerdict = "arp_poison_verdict";
constexpr const char* kArpPoisonSignals = "arp_poison_signals";
constexpr const char* kArpPoisonTools = "arp_poison_tools";

/* CloudMetadataDetector (cloud instance metadata API credential theft;
 * T1552.005) */
constexpr const char* kCloudMetadataScore = "cloud_metadata_score";
constexpr const char* kCloudMetadataVerdict = "cloud_metadata_verdict";
constexpr const char* kCloudMetadataSignals = "cloud_metadata_signals";
constexpr const char* kCloudMetadataIndicator = "cloud_metadata_indicator";

/* GppPasswordDetector (Group Policy Preferences credential theft;
 * T1552.006) */
constexpr const char* kGppPasswordScore = "gpp_password_score";
constexpr const char* kGppPasswordVerdict = "gpp_password_verdict";
constexpr const char* kGppPasswordSignals = "gpp_password_signals";
constexpr const char* kGppPasswordTools = "gpp_password_tools";

/* ControlPanelProxyDetector (control.exe proxy execution; T1218.002) */
constexpr const char* kControlPanelScore = "control_panel_score";
constexpr const char* kControlPanelVerdict = "control_panel_verdict";
constexpr const char* kControlPanelSignals = "control_panel_signals";
constexpr const char* kControlPanelFiles = "control_panel_files";

/* HiddenUserAccountDetector (SpecialAccounts\UserList concealment;
 * T1564.002) */
constexpr const char* kHiddenUserScore = "hidden_user_score";
constexpr const char* kHiddenUserVerdict = "hidden_user_verdict";
constexpr const char* kHiddenUserSignals = "hidden_user_signals";
constexpr const char* kHiddenUserAccounts = "hidden_user_accounts";

/* PasswordPolicyDiscoveryDetector (password policy enumeration; T1201) */
constexpr const char* kPasswordPolicyScore = "password_policy_score";
constexpr const char* kPasswordPolicyVerdict = "password_policy_verdict";
constexpr const char* kPasswordPolicySignals = "password_policy_signals";
constexpr const char* kPasswordPolicyTools = "password_policy_tools";

/* MsiPackageInstallDetector (msiexec installer package abuse;
 * T1546.016) */
constexpr const char* kMsiPackageScore = "msi_package_score";
constexpr const char* kMsiPackageVerdict = "msi_package_verdict";
constexpr const char* kMsiPackageSignals = "msi_package_signals";
constexpr const char* kMsiPackageFiles = "msi_package_files";
constexpr const char* kMsiPackageSources = "msi_package_sources";

/* LogEnumerationDetector (event log enumeration; T1654) */
constexpr const char* kLogEnumerationScore = "log_enumeration_score";
constexpr const char* kLogEnumerationVerdict = "log_enumeration_verdict";
constexpr const char* kLogEnumerationSignals = "log_enumeration_signals";
constexpr const char* kLogEnumerationTools = "log_enumeration_tools";
constexpr const char* kLogEnumerationChannels = "log_enumeration_channels";

/* MailboxDelegateDetector (mailbox delegate permission grants; T1098.002) */
constexpr const char* kMailboxDelegateScore = "mailbox_delegate_score";
constexpr const char* kMailboxDelegateVerdict = "mailbox_delegate_verdict";
constexpr const char* kMailboxDelegateSignals = "mailbox_delegate_signals";
constexpr const char* kMailboxDelegateCmdlets = "mailbox_delegate_cmdlets";
constexpr const char* kMailboxDelegateTargets = "mailbox_delegate_targets";

/* BehaviorBaselineDetector (learned child/dir/endpoint deviation;
 * behavior_baseline.enable, off by default) */
constexpr const char* kBehaviorBaselineScore = "behavior_baseline_score";
constexpr const char* kBehaviorBaselineSignals = "behavior_baseline_signals";
constexpr const char* kBehaviorBaselineImage = "behavior_baseline_image";
constexpr const char* kBehaviorBaselineState = "behavior_baseline_state";
constexpr const char* kBehaviorBaselineNewChild = "behavior_baseline_new_child";
constexpr const char* kBehaviorBaselineNewDir = "behavior_baseline_new_dir";
constexpr const char* kBehaviorBaselineNewEndpoint =
    "behavior_baseline_new_endpoint";

constexpr const char* kMitreAttack = "mitre_attack";
constexpr const char* kMitreTactic = "mitre_tactic";
} // namespace field


struct Event {
    uint16_t type = 0;
    uint64_t ts100ns = 0;
    uint32_t pid = 0;
    uint32_t ppid = 0;
    uint32_t flags = 0;
    EventDisposition disposition = EventDisposition::ReportAndEvaluate;
    std::string source;
    std::string processIdentity;
    std::string parentProcessIdentity;
    uint64_t processStartTime100ns = 0;
    std::map<std::string, std::string> fields;
    /* Local consumption receipt; never serialized. True means the sink has
     * returned (or semantic duplicate consumed), not remote delivery. */
    std::function<void(bool)> onConsumed;
};

class ISink {
public:
    virtual ~ISink() = default;
    virtual void OnEvent(const Event& ev) = 0;
};

class SemanticDeduplicator {
public:
    bool IsDuplicate(const Event& ev);
    // Failed delivery must not make a later retry look consumed.
    void Forget(const Event& ev);

private:
    std::unordered_map<std::string, uint64_t> m_seen;
};

/* A coherent local delivery sample. consumed includes semantic duplicates;
 * dropped is overflowDropped + consumerFailed + abandoned. Pending excludes
 * the one in-flight event. Backlog age uses monotonic enqueue time, not ETW
 * or replay timestamps. All counters are cumulative over this bus lifetime. */
struct EventBusStats {
    size_t capacity = 0;
    size_t pending = 0;
    size_t highWatermark = 0;
    size_t inFlight = 0;
    uint64_t dropped = 0;
    uint64_t overflowDropped = 0;
    uint64_t consumerFailed = 0;
    uint64_t abandoned = 0;
    uint64_t consumed = 0;
    uint64_t deduplicated = 0;
    uint64_t oldestPendingMs = 0;
};

class EventBus {
public:
    explicit EventBus(size_t capacity = 8192);
    ~EventBus();

    EventBus(const EventBus&) = delete;
    EventBus& operator=(const EventBus&) = delete;

    void Start(ISink* sink);
    void Stop();
    bool Push(const Event& ev);
    uint64_t DroppedCount() const { return m_dropped.load(); }
    size_t Pending() const;
    EventBusStats SnapshotStats() const;

private:
    void ConsumerLoop();

    size_t m_capacity;
    ISink* m_sink = nullptr;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    struct QueuedEvent {
        Event event;
        std::chrono::steady_clock::time_point enqueued;
    };
    std::deque<QueuedEvent> m_queue;
    EventBusStats m_stats; // Protected by m_mutex, including completion counters.
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<uint64_t> m_dropped{0};
    SemanticDeduplicator m_deduplicator;
};

const char* EventTypeName(uint16_t type);

} // namespace edr

#endif /* EDR_EVENT_BUS_H */
