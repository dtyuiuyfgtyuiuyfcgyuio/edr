cmake_minimum_required(VERSION 3.20)

if(POLICY CMP0149)
    cmake_policy(SET CMP0149 OLD)
endif()
set(CMAKE_SYSTEM_VERSION "10.0.22621.0" CACHE STRING
    "Windows SDK version used by the user-mode build")

project(edr C CXX)

include(CTest)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ---------------------------------------------------------------------------
# User-mode agent.
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(EDR_IMONITOR "AUTO" CACHE STRING "iMonitor support: AUTO, ON, or OFF")
set_property(CACHE EDR_IMONITOR PROPERTY STRINGS AUTO ON OFF)
string(TOUPPER "${EDR_IMONITOR}" EDR_IMONITOR)
if(NOT EDR_IMONITOR MATCHES "^(AUTO|ON|OFF)$")
    message(FATAL_ERROR "EDR_IMONITOR must be AUTO, ON, or OFF")
endif()

set(EDR_IMONITOR_AVAILABLE OFF)
if(NOT EDR_IMONITOR STREQUAL "OFF")
    include(CheckIncludeFileCXX)
    check_include_file_cxx(atlbase.h EDR_HAVE_ATLBASE_H)
    if(EDR_HAVE_ATLBASE_H)
        set(EDR_IMONITOR_AVAILABLE ON)
    elseif(EDR_IMONITOR STREQUAL "ON")
        message(FATAL_ERROR "EDR_IMONITOR=ON requires ATL (atlbase.h)")
    else()
        message(STATUS "ATL unavailable; building the iMonitor factory stub")
    endif()
endif()

set(EDR_USER_SOURCES
    user/main.cpp
    user/config.cpp
    user/triage_pack.cpp
    user/collector_driver.cpp
    user/driver_event_parser.cpp
    user/driver_policy_publisher.cpp
    user/collector_file_fallback.cpp
    user/collector_net_fallback.cpp
    user/collector_net_etw.cpp
    user/etw_health.cpp
    user/collector_reg_baseline.cpp
    user/collector_reg_watch.cpp
    user/collector_proc_etw.cpp
    user/collector_proc_poll.cpp
    user/collector_dns.cpp
    user/dns_etw_parser.cpp
    user/process_query.cpp
    user/silverfox_detector.cpp
    user/behavior_enricher.cpp
    user/injection_chain_detector.cpp
    user/attack_chain_detector.cpp
    user/c2_beacon_detector.cpp
    user/ransom_burst_detector.cpp
    user/dns_beacon_detector.cpp user/dns_failure_detector.cpp
    user/behavior_baseline_detector.cpp
    user/lateral_movement_detector.cpp
    user/port_scan_detector.cpp
    user/persistence_chain_detector.cpp
    user/lolbin_parent_child_detector.cpp
    user/lolbin_chain_detector.cpp
    user/powershell_download_execute_detector.cpp
    user/dll_hijack_detector.cpp
    user/registry_persistence_detector.cpp
    user/anti_forensics_detector.cpp
    user/time_change_detector.cpp
    user/privileged_group_detector.cpp
    user/defense_evasion_detector.cpp
    user/discovery_recon_detector.cpp
    user/reg_modify_detector.cpp
    user/wmi_exec_detector.cpp
    user/local_collect_detector.cpp
    user/lateral_transfer_detector.cpp
    user/threat_intel_detector.cpp
    user/lateral_chain_detector.cpp
    user/correlation_engine.cpp
    user/correlation_rollup.cpp
    user/incident_store.cpp
    user/rdp_chain_detector.cpp
    user/uac_bypass_detector.cpp
    user/wmi_persistence_detector.cpp
    user/ransom_precursor_detector.cpp
    user/collector_rat_analyzer.cpp
    user/process_hollowing_detector.cpp
    user/memory_scanner_detector.cpp
    user/driver_load_detector.cpp
    user/canary_manager.cpp
    user/canary_detector.cpp
     user/collector_hook_scan.cpp
    user/hook_persistence_detector.cpp
    user/task_abuse_detector.cpp
        user/masquerade_detector.cpp
        user/ppid_spoof_detector.cpp
        user/net_discovery_detector.cpp
        user/host_profile_detector.cpp
        user/private_key_detector.cpp
    user/accessibility_hijack_detector.cpp
    user/acl_abuse_detector.cpp
    user/amsi_bypass_detector.cpp
    user/appinit_dll_detector.cpp
    user/as_rep_roast_detector.cpp
    user/boot_provider_persist_detector.cpp
    user/cert_abuse_detector.cpp
    user/cor_profiler_hijack_detector.cpp
    user/cred_file_hunt_detector.cpp
    user/dcsync_detector.cpp
    user/dev_util_proxy_detector.cpp
    user/disk_wipe_detector.cpp
    user/av_tamper_detector.cpp
    user/timestomp_detector.cpp
    user/obfuscation_detector.cpp
    user/lsass_dump_detector.cpp
    user/shadow_copy_detector.cpp
    user/persistence_burst_detector.cpp
    user/mailbox_delegate_detector.cpp
    user/mailbox_rule_detector.cpp
    user/llmnr_poison_detector.cpp
    user/netprovider_persist_detector.cpp
    user/password_vault_detector.cpp
    user/arp_poison_detector.cpp
    user/cloud_metadata_detector.cpp
    user/gpp_password_detector.cpp
    user/control_panel_proxy_detector.cpp
    user/hidden_user_account_detector.cpp
    user/password_policy_discovery_detector.cpp
    user/msi_package_install_detector.cpp
    user/log_enumeration_detector.cpp
    user/cmstp_bypass_detector.cpp
    user/file_assoc_detector.cpp
    user/hidden_window_detector.cpp
    user/office_persist_detector.cpp
    user/shortcut_persist_detector.cpp
    user/indirect_exec_detector.cpp
    user/screensaver_persist_detector.cpp
    user/svc_path_abuse_detector.cpp
    user/service_dll_hijack_detector.cpp
    user/dll_search_order_detector.cpp
    user/svc_recovery_detector.cpp
    user/com_hijack_detector.cpp
    user/winlogon_hijack_detector.cpp
    user/mshta_abuse_detector.cpp
    user/dotnet_proxy_exec_detector.cpp
    user/wsl_abuse_detector.cpp
    user/msdt_abuse_detector.cpp
    user/software_discovery_detector.cpp
    user/net_share_discovery_detector.cpp
    user/nonstandard_port_egress_detector.cpp
    user/iso_mount_detector.cpp
    user/ps_profile_detector.cpp
    user/downgrade_attack_detector.cpp
    user/dpapi_abuse_detector.cpp
    user/email_collection_detector.cpp
    user/etw_script_tamper_detector.cpp
    user/forced_auth_detector.cpp
    user/golden_ticket_detector.cpp
    user/gpo_abuse_detector.cpp
    user/hidden_artifacts_detector.cpp
    user/history_tamper_detector.cpp
    user/hive_copy_detector.cpp
    user/hosts_redirect_detector.cpp
    user/iis_module_detector.cpp
    user/input_simulation_detector.cpp
    user/logon_script_persist_detector.cpp
    user/lsa_package_detector.cpp
    user/motw_bypass_detector.cpp
    user/netsh_helper_detector.cpp
    user/network_sniffing_detector.cpp
    user/ntds_dit_detector.cpp
    user/pass_the_hash_detector.cpp
    user/password_cracking_detector.cpp
    user/path_interception_detector.cpp
    user/pe_anomaly_detector.cpp
    user/ransom_ops_detector.cpp
    user/rdp_session_hijack_detector.cpp
    user/reg_cred_hunt_detector.cpp
    user/remote_exec_detector.cpp
    user/secboot_tamper_detector.cpp
    user/shim_db_detector.cpp
    user/signed_binary_abuse_detector.cpp
    user/sip_hijack_detector.cpp
    user/ssh_key_persistence_detector.cpp
    user/ticket_cache_abuse_detector.cpp
    user/token_impersonation_detector.cpp
    user/handle_guard_detector.cpp
    user/clipboard_theft_detector.cpp
    user/named_pipe_abuse_detector.cpp
    user/web_exfil_detector.cpp
    user/wifi_cred_theft_detector.cpp
    user/winrm_abuse_detector.cpp
    user/winrm_config_tamper_detector.cpp
    user/xsl_script_detector.cpp
    user/eventlog_tamper_detector.cpp
    user/ssh_abuse_detector.cpp
    user/pe_anomaly_scan.cpp
    user/health_heartbeat.cpp
    user/dispatch_timing.cpp
    user/dispatch_timing_scope.cpp
    user/fileless_attack_detector.cpp
    user/api_hook_detector.cpp
   user/remote_access_detector.cpp
    user/credential_dumping_detector.cpp
    user/data_exfiltration_detector.cpp
    user/privilege_escalation_detector.cpp
    user/ntlm_relay_detector.cpp
    user/browser_theft_detector.cpp
    user/browser_extension_detector.cpp
    user/archive_staging_detector.cpp
    user/bits_abuse_detector.cpp
    user/doh_abuse_detector.cpp
    user/service_install_detector.cpp
    user/firewall_rule_detector.cpp
    user/share_change_detector.cpp
    user/local_account_detector.cpp
    user/cryptominer_detector.cpp
    user/anti_analysis_detector.cpp
    user/script_host_abuse_detector.cpp
    user/account_op_detector.cpp
    user/tunnel_tool_detector.cpp
    user/surveillance_detector.cpp
    user/webshell_detector.cpp
    user/usb_exfil_detector.cpp
   user/logon_brute_force_detector.cpp user/logon_success_detector.cpp
    user/password_spray_detector.cpp
    user/kerberoast_detector.cpp
    user/event_log_bookmark.cpp
    user/collector_sysmon.cpp
    user/collector_security_log.cpp
    user/collector_wmi.cpp
    user/collector_taskscheduler.cpp
    user/collector_defender.cpp
    user/collector_rdp.cpp
    user/rdp_parser.cpp
    user/collector_powershell.cpp
    user/collector_startup_watch.cpp
    user/collector_image_load.cpp
    user/collector_privilege.cpp
    user/collector_usb.cpp
    user/collector_listener.cpp
    user/collector_service.cpp
    user/collector_critical_process.cpp
    user/collector_fim.cpp
    user/collector_share.cpp
    user/collector_named_pipe.cpp
    user/collector_lsass_sam.cpp
    user/collector_local_account.cpp
    user/collector_firewall.cpp
    user/collector_etw_tamper.cpp
    user/process_tree_builder.cpp
    user/security_baseline.cpp
    user/system_snapshot.cpp
    user/privilege_log_parser.cpp
    user/sysmon_parser.cpp
    user/security_log_parser.cpp
    user/wmi_parser.cpp
    user/taskscheduler_parser.cpp
    user/defender_parser.cpp
    user/powershell_parser.cpp
    user/powershell_reassembler.cpp
    user/file_reputation.cpp
    user/amsi_enricher.cpp
    user/amsi_platform.cpp
    user/event_bus.cpp
    user/rule_engine.cpp user/rule_lint.cpp
    user/alerter.cpp
    user/reporter.cpp
    user/reporter_spool.cpp
    user/telemetry_delivery.cpp
    user/syslog_forwarder.cpp
    user/webhook_notifier.cpp
    user/response_server.cpp
    user/response_actions.cpp
    user/quarantine_actions.cpp
    user/auto_responder.cpp
    user/host_isolation.cpp
)

if(EDR_IMONITOR_AVAILABLE)
    list(APPEND EDR_USER_SOURCES user/collector_imonitor.cpp)
    list(APPEND EDR_USER_SOURCES user/collector_hooks.cpp)
else()
    list(APPEND EDR_USER_SOURCES user/collector_imonitor_stub.cpp)
    list(APPEND EDR_USER_SOURCES user/collector_hooks_stub.cpp)
endif()

add_executable(edr ${EDR_USER_SOURCES})
add_executable(edr_rule_lint user/rule_lint_main.cpp user/rule_lint.cpp)
target_include_directories(edr_rule_lint PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/common" "${CMAKE_CURRENT_SOURCE_DIR}/user")
target_compile_definitions(edr_rule_lint PRIVATE
    UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
if(MSVC)
    target_compile_options(edr_rule_lint PRIVATE /W4 /utf-8 /EHsc)
    target_link_options(edr_rule_lint PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
endif()
target_include_directories(edr PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/sdk_fix"
    "${CMAKE_CURRENT_SOURCE_DIR}/common"
    "${CMAKE_CURRENT_SOURCE_DIR}/user"
)
if(EDR_IMONITOR_AVAILABLE)
    target_include_directories(edr PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/iMonitorSDK/inc")
endif()
target_compile_definitions(edr PRIVATE UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
if(MSVC)
    # /W4 enabled; /WX intentionally left off (see README "build warnings").
    target_compile_options(edr PRIVATE /W4 /utf-8 /EHsc)
endif()
target_link_libraries(edr PRIVATE iphlpapi winhttp advapi32 ws2_32 tdh wevtapi
    bcrypt wintrust crypt32 amsi dnsapi netapi32)
if(MSVC)
    target_link_options(edr PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
endif()

if(BUILD_TESTING)
    add_executable(edr_native_tests
        tests/native_tests.cpp
        tests/audit_chain_recovery_tests.cpp
        tests/reporter_delivery_tests.cpp
        tests/response_stream_replay_tests.cpp
        tests/endpoint_identity_tests.cpp
        tests/incident_store_health_tests.cpp
        tests/reporter_spool_tests.cpp
        tests/health_snapshot_tests.cpp
        tests/telemetry_delivery_integration_tests.cpp
        tests/telemetry_contract_tests.cpp
        tests/silverfox_tests.cpp
        tests/behavior_enricher_tests.cpp
        tests/detector_tests.cpp
        tests/c2_beacon_detector_tests.cpp
        tests/ransom_burst_detector_tests.cpp
        tests/dns_beacon_detector_tests.cpp
        tests/lateral_movement_detector_tests.cpp
        tests/port_scan_detector_tests.cpp
        tests/persistence_chain_detector_tests.cpp
        tests/lolbin_parent_child_detector_tests.cpp
        tests/lolbin_chain_detector_tests.cpp
        tests/powershell_download_execute_detector_tests.cpp
        tests/dll_hijack_detector_tests.cpp
        tests/registry_persistence_detector_tests.cpp
        tests/anti_forensics_detector_tests.cpp
        tests/time_change_detector_tests.cpp
        tests/privileged_group_detector_tests.cpp
        tests/defense_evasion_detector_tests.cpp
        tests/discovery_recon_detector_tests.cpp
        tests/reg_modify_detector_tests.cpp
        tests/wmi_exec_detector_tests.cpp
        tests/local_collect_detector_tests.cpp
        tests/lateral_transfer_detector_tests.cpp
        tests/threat_intel_detector_tests.cpp
        tests/lateral_chain_detector_tests.cpp
        tests/correlation_engine_tests.cpp
        tests/rdp_chain_detector_tests.cpp
        tests/uac_bypass_detector_tests.cpp
        tests/wmi_persistence_detector_tests.cpp
        tests/ransom_precursor_detector_tests.cpp
        tests/rdp_parser_tests.cpp
        tests/logon_brute_force_detector_tests.cpp
        tests/password_spray_detector_tests.cpp
        tests/kerberoast_detector_tests.cpp
        tests/process_hollowing_detector_tests.cpp
        tests/memory_scanner_detector_tests.cpp
        tests/driver_load_detector_tests.cpp
        tests/canary_detector_tests.cpp
        tests/hook_persistence_detector_tests.cpp
        tests/task_abuse_detector_tests.cpp
        tests/masquerade_detector_tests.cpp
        tests/accessibility_hijack_detector_tests.cpp
        tests/acl_abuse_detector_tests.cpp
        tests/amsi_bypass_detector_tests.cpp
        tests/appinit_dll_detector_tests.cpp
        tests/as_rep_roast_detector_tests.cpp
        tests/boot_provider_persist_detector_tests.cpp
        tests/cert_abuse_detector_tests.cpp
        tests/cor_profiler_hijack_detector_tests.cpp
        tests/cred_file_hunt_detector_tests.cpp
        tests/dcsync_detector_tests.cpp
        tests/dev_util_proxy_detector_tests.cpp
        tests/disk_wipe_detector_tests.cpp
        tests/av_tamper_detector_tests.cpp
        tests/timestomp_detector_tests.cpp
        tests/obfuscation_detector_tests.cpp
        tests/lsass_dump_detector_tests.cpp
        tests/fileless_attack_detector_tests.cpp
        tests/api_hook_detector_tests.cpp
       tests/remote_access_detector_tests.cpp
        tests/credential_dumping_detector_tests.cpp
        tests/data_exfiltration_detector_tests.cpp
        tests/privilege_escalation_detector_tests.cpp
        tests/ntlm_relay_detector_tests.cpp
        tests/browser_theft_detector_tests.cpp
        tests/browser_extension_detector_tests.cpp
        tests/archive_staging_detector_tests.cpp
        tests/bits_abuse_detector_tests.cpp
        tests/doh_abuse_detector_tests.cpp
        tests/service_install_detector_tests.cpp
        tests/shadow_copy_detector_tests.cpp
        tests/persistence_burst_detector_tests.cpp
        tests/mailbox_delegate_detector_tests.cpp
        tests/mailbox_rule_detector_tests.cpp
        tests/llmnr_poison_detector_tests.cpp
        tests/netprovider_persist_detector_tests.cpp
        tests/password_vault_detector_tests.cpp
        tests/arp_poison_detector_tests.cpp
        tests/cloud_metadata_detector_tests.cpp
        tests/gpp_password_detector_tests.cpp
        tests/control_panel_proxy_detector_tests.cpp
        tests/hidden_user_account_detector_tests.cpp
        tests/password_policy_discovery_detector_tests.cpp
        tests/msi_package_install_detector_tests.cpp
        tests/log_enumeration_detector_tests.cpp
        tests/webhook_notifier_tests.cpp
        tests/alerter_sink_tests.cpp
        tests/triage_pack_tests.cpp
        tests/cmstp_bypass_detector_tests.cpp
        tests/file_assoc_detector_tests.cpp
        tests/hidden_window_detector_tests.cpp
        tests/office_persist_detector_tests.cpp
        tests/shortcut_persist_detector_tests.cpp
        tests/indirect_exec_detector_tests.cpp
        tests/screensaver_persist_detector_tests.cpp
        tests/svc_path_abuse_detector_tests.cpp
        tests/service_dll_hijack_detector_tests.cpp
        tests/dll_search_order_detector_tests.cpp
        tests/svc_recovery_detector_tests.cpp
        tests/com_hijack_detector_tests.cpp
        tests/winlogon_hijack_detector_tests.cpp
        tests/mshta_abuse_detector_tests.cpp
        tests/dotnet_proxy_exec_detector_tests.cpp
        tests/wsl_abuse_detector_tests.cpp
        tests/msdt_abuse_detector_tests.cpp
        tests/software_discovery_detector_tests.cpp
        tests/net_share_discovery_detector_tests.cpp
        tests/nonstandard_port_egress_detector_tests.cpp
        tests/iso_mount_detector_tests.cpp
        tests/ps_profile_detector_tests.cpp
        tests/firewall_rule_detector_tests.cpp
        tests/local_account_detector_tests.cpp
        tests/ppid_spoof_detector_tests.cpp
        tests/net_discovery_detector_tests.cpp
        tests/host_profile_detector_tests.cpp
        tests/private_key_detector_tests.cpp
        tests/share_change_detector_tests.cpp
        tests/pe_anomaly_tests.cpp
        tests/downgrade_attack_detector_tests.cpp
        tests/dpapi_abuse_detector_tests.cpp
        tests/email_collection_detector_tests.cpp
        tests/etw_script_tamper_detector_tests.cpp
        tests/forced_auth_detector_tests.cpp
        tests/golden_ticket_detector_tests.cpp
        tests/gpo_abuse_detector_tests.cpp
        tests/hidden_artifacts_detector_tests.cpp
        tests/history_tamper_detector_tests.cpp
        tests/hive_copy_detector_tests.cpp
        tests/hosts_redirect_detector_tests.cpp
        tests/iis_module_detector_tests.cpp
        tests/input_simulation_detector_tests.cpp
        tests/logon_script_persist_detector_tests.cpp
        tests/lsa_package_detector_tests.cpp
        tests/motw_bypass_detector_tests.cpp
        tests/netsh_helper_detector_tests.cpp
        tests/network_sniffing_detector_tests.cpp
        tests/ntds_dit_detector_tests.cpp
        tests/pass_the_hash_detector_tests.cpp
        tests/password_cracking_detector_tests.cpp
        tests/path_interception_detector_tests.cpp
        tests/ransom_ops_detector_tests.cpp
        tests/rdp_session_hijack_detector_tests.cpp
        tests/reg_cred_hunt_detector_tests.cpp
        tests/remote_exec_detector_tests.cpp
        tests/secboot_tamper_detector_tests.cpp
        tests/shim_db_detector_tests.cpp
        tests/signed_binary_abuse_detector_tests.cpp
        tests/sip_hijack_detector_tests.cpp
        tests/ssh_key_persistence_detector_tests.cpp
        tests/ticket_cache_abuse_detector_tests.cpp
        tests/token_impersonation_detector_tests.cpp
        tests/handle_guard_detector_tests.cpp
        tests/clipboard_theft_detector_tests.cpp
        tests/named_pipe_abuse_detector_tests.cpp
        tests/web_exfil_detector_tests.cpp
        tests/wifi_cred_theft_detector_tests.cpp
        tests/winrm_abuse_detector_tests.cpp
        tests/winrm_config_tamper_detector_tests.cpp
        tests/xsl_script_detector_tests.cpp
        tests/eventlog_tamper_detector_tests.cpp
        tests/ssh_abuse_detector_tests.cpp
        tests/new_rule_detectors_tests.cpp
        tests/cryptominer_detector_tests.cpp
        tests/anti_analysis_detector_tests.cpp
        tests/script_host_abuse_detector_tests.cpp
        tests/account_op_detector_tests.cpp
        tests/tunnel_tool_detector_tests.cpp
        tests/surveillance_detector_tests.cpp
        tests/webshell_detector_tests.cpp
        tests/usb_exfil_detector_tests.cpp
       user/alerter.cpp
        user/config.cpp
        user/event_bus.cpp
        user/process_query.cpp
        user/file_reputation.cpp
        user/amsi_enricher.cpp
        user/silverfox_detector.cpp
        user/behavior_enricher.cpp
        user/injection_chain_detector.cpp
        user/attack_chain_detector.cpp
        user/c2_beacon_detector.cpp
        user/ransom_burst_detector.cpp
        user/dns_beacon_detector.cpp user/dns_failure_detector.cpp
        user/lateral_movement_detector.cpp
        user/port_scan_detector.cpp
        user/persistence_chain_detector.cpp
        user/lolbin_parent_child_detector.cpp
        user/lolbin_chain_detector.cpp
        user/powershell_download_execute_detector.cpp
        user/dll_hijack_detector.cpp
        user/registry_persistence_detector.cpp
        user/anti_forensics_detector.cpp
        user/time_change_detector.cpp
        user/privileged_group_detector.cpp
        user/defense_evasion_detector.cpp
        user/discovery_recon_detector.cpp
        user/reg_modify_detector.cpp
        user/wmi_exec_detector.cpp
        user/local_collect_detector.cpp
        user/lateral_transfer_detector.cpp
        user/threat_intel_detector.cpp
        user/lateral_chain_detector.cpp
        user/correlation_engine.cpp
        user/correlation_rollup.cpp
        user/incident_store.cpp
        user/rdp_chain_detector.cpp
        user/uac_bypass_detector.cpp
        user/wmi_persistence_detector.cpp
        user/ransom_precursor_detector.cpp
        user/rdp_parser.cpp
        user/logon_brute_force_detector.cpp user/logon_success_detector.cpp
        user/password_spray_detector.cpp
        user/kerberoast_detector.cpp
        user/process_hollowing_detector.cpp
        user/memory_scanner_detector.cpp
        user/driver_load_detector.cpp
        user/canary_manager.cpp
        user/canary_detector.cpp
        user/collector_hook_scan.cpp
        user/hook_persistence_detector.cpp
        user/task_abuse_detector.cpp
        user/masquerade_detector.cpp
        user/ppid_spoof_detector.cpp
        user/net_discovery_detector.cpp
        user/host_profile_detector.cpp
        user/private_key_detector.cpp
        user/accessibility_hijack_detector.cpp
        user/acl_abuse_detector.cpp
        user/amsi_bypass_detector.cpp
        user/appinit_dll_detector.cpp
        user/as_rep_roast_detector.cpp
        user/boot_provider_persist_detector.cpp
        user/cert_abuse_detector.cpp
        user/cor_profiler_hijack_detector.cpp
        user/cred_file_hunt_detector.cpp
        user/dcsync_detector.cpp
        user/dev_util_proxy_detector.cpp
        user/disk_wipe_detector.cpp
        user/av_tamper_detector.cpp
        user/timestomp_detector.cpp
        user/obfuscation_detector.cpp
        user/lsass_dump_detector.cpp
        user/shadow_copy_detector.cpp
        user/persistence_burst_detector.cpp
        user/mailbox_delegate_detector.cpp
        user/mailbox_rule_detector.cpp
        user/llmnr_poison_detector.cpp
        user/netprovider_persist_detector.cpp
        user/password_vault_detector.cpp
    user/arp_poison_detector.cpp
    user/cloud_metadata_detector.cpp
    user/gpp_password_detector.cpp
    user/control_panel_proxy_detector.cpp
    user/hidden_user_account_detector.cpp
    user/password_policy_discovery_detector.cpp
    user/msi_package_install_detector.cpp
    user/log_enumeration_detector.cpp
        user/cmstp_bypass_detector.cpp
        user/file_assoc_detector.cpp
        user/hidden_window_detector.cpp
        user/office_persist_detector.cpp
        user/shortcut_persist_detector.cpp
        user/indirect_exec_detector.cpp
        user/screensaver_persist_detector.cpp
        user/svc_path_abuse_detector.cpp
        user/service_dll_hijack_detector.cpp
        user/dll_search_order_detector.cpp
        user/svc_recovery_detector.cpp
        user/com_hijack_detector.cpp
        user/winlogon_hijack_detector.cpp
        user/mshta_abuse_detector.cpp
        user/dotnet_proxy_exec_detector.cpp
        user/wsl_abuse_detector.cpp
        user/msdt_abuse_detector.cpp
        user/software_discovery_detector.cpp
        user/net_share_discovery_detector.cpp
        user/nonstandard_port_egress_detector.cpp
        user/iso_mount_detector.cpp
        user/ps_profile_detector.cpp
    user/downgrade_attack_detector.cpp
    user/dpapi_abuse_detector.cpp
    user/email_collection_detector.cpp
    user/etw_script_tamper_detector.cpp
    user/forced_auth_detector.cpp
    user/golden_ticket_detector.cpp
    user/gpo_abuse_detector.cpp
    user/hidden_artifacts_detector.cpp
    user/history_tamper_detector.cpp
    user/hive_copy_detector.cpp
    user/hosts_redirect_detector.cpp
    user/iis_module_detector.cpp
    user/input_simulation_detector.cpp
    user/logon_script_persist_detector.cpp
    user/lsa_package_detector.cpp
    user/motw_bypass_detector.cpp
    user/netsh_helper_detector.cpp
    user/network_sniffing_detector.cpp
    user/ntds_dit_detector.cpp
    user/pass_the_hash_detector.cpp
    user/password_cracking_detector.cpp
    user/path_interception_detector.cpp
    user/pe_anomaly_detector.cpp
    user/ransom_ops_detector.cpp
    user/rdp_session_hijack_detector.cpp
    user/reg_cred_hunt_detector.cpp
    user/remote_exec_detector.cpp
    user/secboot_tamper_detector.cpp
    user/shim_db_detector.cpp
    user/signed_binary_abuse_detector.cpp
    user/sip_hijack_detector.cpp
    user/ssh_key_persistence_detector.cpp
    user/ticket_cache_abuse_detector.cpp
    user/token_impersonation_detector.cpp
    user/handle_guard_detector.cpp
    user/clipboard_theft_detector.cpp
    user/named_pipe_abuse_detector.cpp
    user/web_exfil_detector.cpp
    user/wifi_cred_theft_detector.cpp
    user/winrm_abuse_detector.cpp
    user/winrm_config_tamper_detector.cpp
    user/xsl_script_detector.cpp
    user/eventlog_tamper_detector.cpp
    user/ssh_abuse_detector.cpp
    user/pe_anomaly_scan.cpp
        user/health_heartbeat.cpp
        user/event_log_bookmark.cpp
        user/reporter.cpp
        user/reporter_spool.cpp
        user/telemetry_delivery.cpp
        user/dns_etw_parser.cpp
        user/syslog_forwarder.cpp
        user/webhook_notifier.cpp
        user/triage_pack.cpp
        user/fileless_attack_detector.cpp
        user/api_hook_detector.cpp
        user/remote_access_detector.cpp
        user/credential_dumping_detector.cpp
        user/data_exfiltration_detector.cpp
        user/privilege_escalation_detector.cpp
        user/ntlm_relay_detector.cpp
        user/browser_theft_detector.cpp
        user/browser_extension_detector.cpp
        user/archive_staging_detector.cpp
        user/bits_abuse_detector.cpp
        user/doh_abuse_detector.cpp
        user/service_install_detector.cpp
        user/firewall_rule_detector.cpp
        user/share_change_detector.cpp
        user/local_account_detector.cpp
        user/cryptominer_detector.cpp
        user/anti_analysis_detector.cpp
        user/script_host_abuse_detector.cpp
        user/account_op_detector.cpp
        user/tunnel_tool_detector.cpp
        user/surveillance_detector.cpp
        user/webshell_detector.cpp
        user/usb_exfil_detector.cpp
       user/rule_engine.cpp user/rule_lint.cpp
        user/response_server.cpp
        user/response_actions.cpp
        user/quarantine_actions.cpp
        user/auto_responder.cpp
        user/host_isolation.cpp
        user/sysmon_parser.cpp
        user/security_log_parser.cpp
        user/wmi_parser.cpp
        user/taskscheduler_parser.cpp
        user/defender_parser.cpp
        user/powershell_parser.cpp
        user/powershell_reassembler.cpp
        user/collector_startup_watch.cpp
        user/collector_reg_watch.cpp
        user/driver_event_parser.cpp
        user/driver_policy_publisher.cpp
    )
    target_include_directories(edr_native_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/user"
    )
    if(EDR_IMONITOR_AVAILABLE)
        target_sources(edr_native_tests PRIVATE tests/imonitor_mapping_tests.cpp)
        target_include_directories(edr_native_tests PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/iMonitorSDK/inc")
        target_compile_definitions(edr_native_tests PRIVATE
            EDR_IMONITOR_AVAILABLE=1)
    endif()
    target_compile_definitions(edr_native_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX EDR_NATIVE_TESTS)
    if(MSVC)
        target_compile_options(edr_native_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_native_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_native_tests PRIVATE bcrypt wintrust crypt32 advapi32 ws2_32 winhttp wevtapi)
    add_test(NAME edr_native_tests COMMAND edr_native_tests)
    add_test(NAME edr_reporter_delivery_tests COMMAND edr_native_tests --reporter-delivery)
    add_test(NAME edr_audit_recovery_tests COMMAND edr_native_tests --audit-recovery)
    add_test(NAME edr_incident_correlation_tests COMMAND edr_native_tests --incident-correlation)
    add_test(NAME edr_response_identity_tests COMMAND edr_native_tests --response-identity)
    add_test(NAME edr_response_stream_replay_tests COMMAND edr_native_tests --response-replay)
    add_test(NAME edr_endpoint_identity_tests COMMAND edr_native_tests --endpoint-identity)
    add_test(NAME edr_incident_store_health_tests COMMAND edr_native_tests --incident-health)
    add_test(NAME edr_health_snapshot_tests COMMAND edr_native_tests --health-snapshot)
    add_test(NAME edr_telemetry_delivery_integration_tests COMMAND edr_native_tests --telemetry-delivery)
    add_test(NAME edr_telemetry_contract_tests COMMAND edr_native_tests --telemetry-contract)

    add_executable(edr_behavior_contract_tests
        tests/behavior_contract_test_main.cpp tests/detector_tests.cpp
        tests/lolbin_chain_detector_tests.cpp tests/correlation_engine_tests.cpp
        user/attack_chain_detector.cpp user/lolbin_chain_detector.cpp
        user/correlation_engine.cpp user/injection_chain_detector.cpp
        user/behavior_enricher.cpp user/config.cpp user/event_bus.cpp user/rule_engine.cpp user/rule_lint.cpp)
    target_include_directories(edr_behavior_contract_tests PRIVATE user common tests)
    target_compile_definitions(edr_behavior_contract_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_behavior_contract_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_behavior_contract_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_behavior_contract_tests PRIVATE bcrypt advapi32)
    add_test(NAME edr_behavior_contract_tests COMMAND edr_behavior_contract_tests)

    add_executable(edr_telemetry_contract_unit_tests
        tests/telemetry_contract_test_main.cpp tests/telemetry_contract_tests.cpp
        user/dns_etw_parser.cpp user/security_log_parser.cpp
        user/telemetry_delivery.cpp user/attack_chain_detector.cpp
        user/reporter.cpp user/reporter_spool.cpp user/alerter.cpp
        user/rule_engine.cpp user/rule_lint.cpp user/config.cpp user/event_bus.cpp)
    target_include_directories(edr_telemetry_contract_unit_tests PRIVATE user common tests)
    target_compile_definitions(edr_telemetry_contract_unit_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_telemetry_contract_unit_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_telemetry_contract_unit_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_telemetry_contract_unit_tests PRIVATE bcrypt advapi32 winhttp)
    add_test(NAME edr_telemetry_contract_unit_tests COMMAND edr_telemetry_contract_unit_tests)
    add_test(NAME edr_threat_intel_tests COMMAND edr_native_tests --threat-intel)
    add_executable(edr_bulwark_feature_tests
        tests/bulwark_feature_tests.cpp tests/obfuscation_detector_tests.cpp
        tests/dns_beacon_detector_tests.cpp user/obfuscation_detector.cpp
        user/dns_beacon_detector.cpp user/rule_engine.cpp user/rule_lint.cpp user/config.cpp user/event_bus.cpp
        user/alerter.cpp)
    target_include_directories(edr_bulwark_feature_tests PRIVATE user common tests)
    target_compile_definitions(edr_bulwark_feature_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(edr_bulwark_feature_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_bulwark_feature_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_bulwark_feature_tests PRIVATE bcrypt advapi32)
    add_test(NAME edr_bulwark_feature_tests COMMAND edr_bulwark_feature_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")
    add_executable(edr_dns_failure_tests
        tests/dns_failure_detector_tests.cpp user/dns_failure_detector.cpp)
    target_include_directories(edr_dns_failure_tests PRIVATE user common tests)
    target_compile_definitions(edr_dns_failure_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(edr_dns_failure_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_dns_failure_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    add_test(NAME edr_dns_failure_tests COMMAND edr_dns_failure_tests)
    add_executable(edr_process_context_tests
        tests/process_context_tests.cpp user/process_query.cpp user/config.cpp)
    target_include_directories(edr_process_context_tests PRIVATE user common)
    target_compile_definitions(edr_process_context_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(edr_process_context_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_process_context_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    add_test(NAME edr_process_context_tests COMMAND edr_process_context_tests)

    add_executable(edr_registry_watch_snapshot_tests
        tests/registry_watch_snapshot_tests.cpp user/collector_reg_watch.cpp
        user/config.cpp user/event_bus.cpp)
    target_include_directories(edr_registry_watch_snapshot_tests PRIVATE user common tests)
    target_compile_definitions(edr_registry_watch_snapshot_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_registry_watch_snapshot_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_registry_watch_snapshot_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_registry_watch_snapshot_tests PRIVATE advapi32)
    add_test(NAME edr_registry_watch_snapshot_tests COMMAND edr_registry_watch_snapshot_tests)

    add_executable(edr_logon_success_tests
        tests/logon_success_detector_tests.cpp user/logon_success_detector.cpp)
    add_executable(edr_logon_success_config_tests
        tests/logon_success_config_tests.cpp user/config.cpp user/rule_engine.cpp
        user/rule_lint.cpp user/event_bus.cpp)
    foreach(_target edr_logon_success_tests edr_logon_success_config_tests)
        target_include_directories(${_target} PRIVATE user common tests)
        target_compile_definitions(${_target} PRIVATE
            UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
        if(MSVC)
            target_compile_options(${_target} PRIVATE /W4 /utf-8 /EHsc)
            target_link_options(${_target} PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
        endif()
        target_link_libraries(${_target} PRIVATE ws2_32 bcrypt advapi32)
    endforeach()
    add_test(NAME edr_logon_success_tests COMMAND edr_logon_success_tests)
    add_test(NAME edr_logon_success_config_tests COMMAND edr_logon_success_config_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")

    add_executable(edr_behavior_baseline_tests
        tests/behavior_baseline_test_main.cpp tests/behavior_baseline_detector_tests.cpp
        user/behavior_baseline_detector.cpp user/rule_engine.cpp user/rule_lint.cpp user/config.cpp user/event_bus.cpp)
    target_include_directories(edr_behavior_baseline_tests PRIVATE user common tests)
    target_compile_definitions(edr_behavior_baseline_tests PRIVATE
        UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(edr_behavior_baseline_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_behavior_baseline_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_behavior_baseline_tests PRIVATE bcrypt advapi32)
    add_test(NAME edr_behavior_baseline_tests COMMAND edr_behavior_baseline_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")
    add_executable(edr_behavior_baseline_edge_tests
        tests/behavior_baseline_edge_tests.cpp user/behavior_baseline_detector.cpp)
    target_include_directories(edr_behavior_baseline_edge_tests PRIVATE user common)
    target_compile_definitions(edr_behavior_baseline_edge_tests PRIVATE
        UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(edr_behavior_baseline_edge_tests PRIVATE /W4 /utf-8 /EHsc)
    endif()
    add_test(NAME edr_behavior_baseline_edge_tests COMMAND edr_behavior_baseline_edge_tests)
    add_executable(edr_threat_intel_reload_tests
        tests/threat_intel_reload_test_main.cpp tests/threat_intel_detector_tests.cpp
        user/threat_intel_detector.cpp user/config.cpp user/event_bus.cpp user/rule_engine.cpp user/rule_lint.cpp)
    target_include_directories(edr_threat_intel_reload_tests PRIVATE user common tests)
    target_compile_definitions(edr_threat_intel_reload_tests PRIVATE
        UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(edr_threat_intel_reload_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_threat_intel_reload_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_threat_intel_reload_tests PRIVATE bcrypt ws2_32)
    add_test(NAME edr_threat_intel_reload_tests COMMAND edr_threat_intel_reload_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")
    add_executable(edr_reporter_spool_tests
        tests/reporter_spool_test_main.cpp tests/reporter_spool_tests.cpp
        user/reporter.cpp user/reporter_spool.cpp user/config.cpp user/event_bus.cpp)
    target_include_directories(edr_reporter_spool_tests PRIVATE user common tests)
    target_compile_definitions(edr_reporter_spool_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(edr_reporter_spool_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_reporter_spool_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_reporter_spool_tests PRIVATE bcrypt advapi32 winhttp)
    add_test(NAME edr_reporter_spool_tests COMMAND edr_reporter_spool_tests)

    add_executable(edr_reporter_spool_config_tests
        tests/reporter_spool_config_tests.cpp user/config.cpp user/event_bus.cpp)
    target_include_directories(edr_reporter_spool_config_tests PRIVATE user common tests)
    target_compile_definitions(edr_reporter_spool_config_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    add_test(NAME edr_reporter_spool_config_tests COMMAND edr_reporter_spool_config_tests)

    add_executable(edr_event_log_replay_config_tests
        tests/event_log_replay_config_tests.cpp user/config.cpp user/event_bus.cpp)
    target_include_directories(edr_event_log_replay_config_tests PRIVATE user common tests)
    target_compile_definitions(edr_event_log_replay_config_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    add_test(NAME edr_event_log_replay_config_tests COMMAND edr_event_log_replay_config_tests)

    add_executable(edr_collector_runtime_health_tests
        tests/collector_runtime_health_test_main.cpp tests/collector_runtime_health_tests.cpp
        user/collector_driver.cpp user/collector_file_fallback.cpp
        user/collector_net_fallback.cpp user/collector_proc_poll.cpp
        user/driver_event_parser.cpp user/process_query.cpp user/config.cpp user/event_bus.cpp)
    target_include_directories(edr_collector_runtime_health_tests PRIVATE user common tests)
    target_compile_definitions(edr_collector_runtime_health_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(edr_collector_runtime_health_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_collector_runtime_health_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_collector_runtime_health_tests PRIVATE advapi32 iphlpapi ws2_32)
    add_test(NAME edr_collector_runtime_health_tests COMMAND edr_collector_runtime_health_tests)

    add_executable(edr_service_collector_tests
        tests/service_collector_tests.cpp user/collector_service.cpp
        user/config.cpp user/event_bus.cpp)
    target_include_directories(edr_service_collector_tests PRIVATE user common tests)
    target_compile_definitions(edr_service_collector_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(edr_service_collector_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_service_collector_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_service_collector_tests PRIVATE advapi32)
    add_test(NAME edr_service_collector_tests COMMAND edr_service_collector_tests)

    add_executable(edr_local_account_collector_tests
        tests/local_account_collector_tests.cpp user/collector_local_account.cpp
        user/config.cpp user/event_bus.cpp)
    add_executable(edr_share_collector_tests
        tests/share_collector_tests.cpp user/collector_share.cpp
        user/config.cpp user/event_bus.cpp)
    # This test includes the native reader implementation with controlled
    # NetAPI calls; do not also link collector_share.cpp into this target.
    add_executable(edr_share_native_read_tests
        tests/share_native_read_tests.cpp user/config.cpp user/event_bus.cpp)
    add_executable(edr_local_account_native_read_tests
        tests/local_account_native_read_tests.cpp user/config.cpp user/event_bus.cpp)
    add_executable(edr_firewall_collector_tests
        tests/firewall_collector_tests.cpp user/collector_firewall.cpp user/event_bus.cpp)
    add_executable(edr_fim_collector_tests
        tests/fim_collector_tests.cpp user/collector_fim.cpp user/file_reputation.cpp user/event_bus.cpp
        user/threat_intel_detector.cpp user/config.cpp user/rule_engine.cpp user/rule_lint.cpp)
    add_executable(edr_listener_collector_tests
        tests/listener_collector_tests.cpp user/collector_listener.cpp
        user/process_query.cpp user/config.cpp user/event_bus.cpp)
    add_executable(edr_usb_collector_tests
        tests/usb_collector_tests.cpp user/collector_usb.cpp user/event_bus.cpp)
    add_executable(edr_critical_process_collector_tests
        tests/critical_process_collector_tests.cpp user/collector_critical_process.cpp user/event_bus.cpp)
    add_executable(edr_hook_scan_collector_tests
        tests/hook_scan_collector_tests.cpp user/collector_hook_scan.cpp user/event_bus.cpp)
    foreach(_target edr_local_account_collector_tests edr_share_collector_tests edr_share_native_read_tests
                    edr_local_account_native_read_tests edr_firewall_collector_tests edr_fim_collector_tests
                    edr_listener_collector_tests edr_usb_collector_tests
                    edr_critical_process_collector_tests edr_hook_scan_collector_tests)
        target_include_directories(${_target} PRIVATE user common tests)
        target_compile_definitions(${_target} PRIVATE
            UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
        if(MSVC)
            target_compile_options(${_target} PRIVATE /W4 /utf-8 /EHsc)
            target_link_options(${_target} PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
        endif()
    endforeach()
    target_link_libraries(edr_local_account_collector_tests PRIVATE netapi32 advapi32)
    target_link_libraries(edr_share_collector_tests PRIVATE netapi32 advapi32)
    target_link_libraries(edr_share_native_read_tests PRIVATE netapi32 advapi32)
    target_link_libraries(edr_local_account_native_read_tests PRIVATE netapi32 advapi32)
    target_link_libraries(edr_firewall_collector_tests PRIVATE advapi32)
    target_link_libraries(edr_fim_collector_tests PRIVATE bcrypt crypt32 wintrust ws2_32)
    target_link_libraries(edr_listener_collector_tests PRIVATE advapi32 iphlpapi ws2_32)
    target_link_libraries(edr_usb_collector_tests PRIVATE advapi32)
    target_link_libraries(edr_hook_scan_collector_tests PRIVATE advapi32)
    add_test(NAME edr_local_account_collector_tests COMMAND edr_local_account_collector_tests)
    add_test(NAME edr_local_account_native_read_tests COMMAND edr_local_account_native_read_tests)
    add_test(NAME edr_share_collector_tests COMMAND edr_share_collector_tests)
    add_test(NAME edr_share_native_read_tests COMMAND edr_share_native_read_tests)
    add_test(NAME edr_listener_collector_tests COMMAND edr_listener_collector_tests)
    add_test(NAME edr_firewall_collector_tests COMMAND edr_firewall_collector_tests)
    add_test(NAME edr_fim_collector_tests COMMAND edr_fim_collector_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")
    add_test(NAME edr_usb_collector_tests COMMAND edr_usb_collector_tests)
    add_test(NAME edr_critical_process_collector_tests COMMAND edr_critical_process_collector_tests)
    add_test(NAME edr_hook_scan_collector_tests COMMAND edr_hook_scan_collector_tests)

    add_executable(edr_triage_pack_tests tests/triage_pack_tests.cpp user/triage_pack.cpp)
    target_include_directories(edr_triage_pack_tests PRIVATE user common tests)
    target_compile_definitions(edr_triage_pack_tests PRIVATE UNICODE _UNICODE NOMINMAX TRIAGE_PACK_PROBE_MAIN)
    if(MSVC)
        target_compile_options(edr_triage_pack_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_triage_pack_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_triage_pack_tests PRIVATE bcrypt advapi32)
    add_test(NAME edr_triage_pack_tests COMMAND edr_triage_pack_tests)
    find_package(Python3 QUIET COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(NAME edr_triage_cli_tests COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/triage_cli_tests.py" "$<TARGET_FILE:edr>")
    endif()

    add_executable(edr_dispatch_timing_tests
        tests/dispatch_timing_test_main.cpp tests/dispatch_timing_tests.cpp
        user/dispatch_timing.cpp user/dispatch_timing_scope.cpp
        user/config.cpp user/event_bus.cpp)
    target_include_directories(edr_dispatch_timing_tests PRIVATE user common tests)
    target_compile_definitions(edr_dispatch_timing_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(edr_dispatch_timing_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_dispatch_timing_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    add_test(NAME edr_dispatch_timing_tests COMMAND edr_dispatch_timing_tests)

    add_executable(edr_correlation_rollup_tests
        tests/correlation_rollup_test_main.cpp tests/correlation_rollup_tests.cpp
        user/correlation_rollup.cpp user/event_bus.cpp user/rule_engine.cpp user/rule_lint.cpp)
    target_include_directories(edr_correlation_rollup_tests PRIVATE user common tests)
    target_compile_definitions(edr_correlation_rollup_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_compile_options(edr_correlation_rollup_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_correlation_rollup_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_correlation_rollup_tests PRIVATE advapi32 bcrypt)
    add_test(NAME edr_correlation_rollup_tests COMMAND edr_correlation_rollup_tests)

    add_executable(edr_etw_health_tests tests/etw_health_test_main.cpp
        tests/etw_health_tests.cpp user/etw_health.cpp)
    target_include_directories(edr_etw_health_tests PRIVATE user common tests)
    target_compile_definitions(edr_etw_health_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    target_link_libraries(edr_etw_health_tests PRIVATE advapi32)
    add_test(NAME edr_etw_health_tests COMMAND edr_etw_health_tests)

    add_executable(edr_event_log_bookmark_tests
        tests/event_log_bookmark_test_main.cpp tests/event_log_bookmark_tests.cpp
        user/event_log_bookmark.cpp user/config.cpp)
    target_include_directories(edr_event_log_bookmark_tests PRIVATE user common tests)
    target_compile_definitions(edr_event_log_bookmark_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    target_link_libraries(edr_event_log_bookmark_tests PRIVATE wevtapi advapi32)
    add_test(NAME edr_event_log_bookmark_tests COMMAND edr_event_log_bookmark_tests)

    add_executable(edr_event_delivery_tests tests/event_delivery_tests.cpp user/event_bus.cpp)
    target_include_directories(edr_event_delivery_tests PRIVATE user common tests)
    target_compile_definitions(edr_event_delivery_tests PRIVATE UNICODE _UNICODE NOMINMAX)
    add_test(NAME edr_event_delivery_tests COMMAND edr_event_delivery_tests)

    add_executable(edr_health_snapshot_unit_tests
        tests/health_snapshot_test_main.cpp tests/health_snapshot_tests.cpp
        user/health_heartbeat.cpp user/event_bus.cpp user/reporter.cpp
        user/reporter_spool.cpp user/syslog_forwarder.cpp user/config.cpp)
    target_include_directories(edr_health_snapshot_unit_tests PRIVATE user common tests)
    target_compile_definitions(edr_health_snapshot_unit_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_health_snapshot_unit_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_health_snapshot_unit_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_health_snapshot_unit_tests PRIVATE
        winhttp advapi32 ws2_32 bcrypt)
    add_test(NAME edr_health_snapshot_unit_tests COMMAND edr_health_snapshot_unit_tests)

    add_executable(edr_quarantine_restore_tests
        tests/quarantine_restore_test_main.cpp
        tests/quarantine_restore_tests.cpp
        user/quarantine_actions.cpp
        user/config.cpp
        user/event_bus.cpp)
    target_include_directories(edr_quarantine_restore_tests PRIVATE user common tests)
    target_compile_definitions(edr_quarantine_restore_tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(edr_quarantine_restore_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_quarantine_restore_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_quarantine_restore_tests PRIVATE bcrypt advapi32 crypt32)
    add_test(NAME edr_quarantine_restore_tests COMMAND edr_quarantine_restore_tests)
    add_test(NAME edr_quarantine_restore_native_tests COMMAND edr_quarantine_restore_tests --native)
    set_tests_properties(edr_quarantine_restore_native_tests PROPERTIES SKIP_RETURN_CODE 77)

    add_executable(edr_alerter_durability_tests
        tests/alerter_durability_test_main.cpp
        tests/alerter_durability_tests.cpp
        user/alerter.cpp
        user/config.cpp
        user/event_bus.cpp)
    target_include_directories(edr_alerter_durability_tests PRIVATE user common tests)
    target_compile_definitions(edr_alerter_durability_tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(edr_alerter_durability_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_alerter_durability_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_alerter_durability_tests PRIVATE bcrypt advapi32)
    add_test(NAME edr_alerter_durability_tests COMMAND edr_alerter_durability_tests)
    add_test(NAME edr_driver_protocol_tests
             COMMAND edr_driver_protocol_tests)
    add_executable(edr_driver_protocol_tests tests/driver_protocol_tests.cpp
        user/config.cpp
        user/event_bus.cpp
        user/driver_event_parser.cpp
        user/driver_policy_publisher.cpp
    )
    target_include_directories(edr_driver_protocol_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/user"
        "${CMAKE_CURRENT_SOURCE_DIR}/driver"
    )
    target_compile_definitions(edr_driver_protocol_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_driver_protocol_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_driver_protocol_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_driver_protocol_tests PRIVATE ws2_32)
    add_executable(edr_defender_tests
        tests/defender_parser_tests.cpp
        user/defender_parser.cpp
        user/config.cpp
        user/event_bus.cpp
        user/rule_engine.cpp user/rule_lint.cpp
    )
    target_include_directories(edr_defender_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/user"
    )
    target_compile_definitions(edr_defender_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_defender_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_defender_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_defender_tests PRIVATE bcrypt wevtapi)
    add_test(NAME edr_defender_tests COMMAND edr_defender_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")
    add_executable(edr_defender_cfa_tests
        tests/defender_cfa_tests.cpp user/defender_parser.cpp
        user/config.cpp user/event_bus.cpp user/rule_engine.cpp user/rule_lint.cpp)
    target_include_directories(edr_defender_cfa_tests PRIVATE user common)
    target_compile_definitions(edr_defender_cfa_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_defender_cfa_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_defender_cfa_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_defender_cfa_tests PRIVATE bcrypt wevtapi)
    add_test(NAME edr_defender_cfa_tests COMMAND edr_defender_cfa_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")

    add_executable(edr_taskscheduler_runtime_tests
        tests/taskscheduler_runtime_tests.cpp user/taskscheduler_parser.cpp
        user/config.cpp user/event_bus.cpp user/task_abuse_detector.cpp
        user/persistence_burst_detector.cpp user/persistence_chain_detector.cpp)
    target_include_directories(edr_taskscheduler_runtime_tests PRIVATE user common)
    target_compile_definitions(edr_taskscheduler_runtime_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_taskscheduler_runtime_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_taskscheduler_runtime_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_taskscheduler_runtime_tests PRIVATE bcrypt advapi32 wevtapi)
    add_test(NAME edr_taskscheduler_runtime_tests COMMAND edr_taskscheduler_runtime_tests)

    add_executable(edr_doh_abuse_tests
        tests/doh_abuse_contract_tests.cpp tests/doh_abuse_detector_tests.cpp
        user/doh_abuse_detector.cpp)
    target_include_directories(edr_doh_abuse_tests PRIVATE user common tests)
    target_compile_definitions(edr_doh_abuse_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_doh_abuse_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_doh_abuse_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    add_test(NAME edr_doh_abuse_tests COMMAND edr_doh_abuse_tests)

    add_executable(edr_dns_delivery_contract_tests
        tests/dns_delivery_contract_tests.cpp user/event_bus.cpp
        user/doh_abuse_detector.cpp)
    target_include_directories(edr_dns_delivery_contract_tests PRIVATE user common)
    target_compile_definitions(edr_dns_delivery_contract_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_dns_delivery_contract_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_dns_delivery_contract_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    add_test(NAME edr_dns_delivery_contract_tests COMMAND edr_dns_delivery_contract_tests)

    add_executable(edr_security_log_contract_tests
        tests/security_log_contract_tests.cpp user/security_log_parser.cpp
        user/service_install_detector.cpp user/time_change_detector.cpp
        user/config.cpp user/event_bus.cpp user/rule_engine.cpp user/rule_lint.cpp)
    add_executable(edr_privilege_escalation_contract_tests
        tests/privilege_escalation_contract_tests.cpp tests/privilege_escalation_detector_tests.cpp
        user/privilege_escalation_detector.cpp user/sysmon_parser.cpp user/privilege_log_parser.cpp
        user/config.cpp user/event_bus.cpp user/rule_engine.cpp user/rule_lint.cpp)
    add_executable(edr_sysmon_file_delete_tests
        tests/sysmon_file_delete_tests.cpp user/sysmon_parser.cpp
        user/history_tamper_detector.cpp user/process_tree_builder.cpp
        user/config.cpp user/event_bus.cpp user/rule_engine.cpp user/rule_lint.cpp)
    add_executable(edr_sysmon_sensor_health_tests
        tests/sysmon_sensor_health_tests.cpp user/sysmon_parser.cpp
        user/process_tree_builder.cpp user/config.cpp user/event_bus.cpp
        user/rule_engine.cpp user/rule_lint.cpp)
    add_executable(edr_security_audit_visibility_tests
        tests/security_audit_visibility_tests.cpp user/security_log_parser.cpp
        user/config.cpp user/event_bus.cpp user/rule_engine.cpp user/rule_lint.cpp)
    foreach(_contract_target edr_security_log_contract_tests
            edr_privilege_escalation_contract_tests edr_sysmon_file_delete_tests
            edr_sysmon_sensor_health_tests edr_security_audit_visibility_tests)
        target_include_directories(${_contract_target} PRIVATE user common tests)
        target_compile_definitions(${_contract_target} PRIVATE
            UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
        if(MSVC)
            target_compile_options(${_contract_target} PRIVATE /W4 /utf-8 /EHsc)
            target_link_options(${_contract_target} PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
        endif()
        target_link_libraries(${_contract_target} PRIVATE bcrypt advapi32 wevtapi)
    endforeach()
    add_test(NAME edr_security_log_contract_tests COMMAND edr_security_log_contract_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")
    add_test(NAME edr_privilege_escalation_contract_tests COMMAND edr_privilege_escalation_contract_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")
    add_test(NAME edr_sysmon_file_delete_tests COMMAND edr_sysmon_file_delete_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")
    add_test(NAME edr_sysmon_sensor_health_tests COMMAND edr_sysmon_sensor_health_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")
    add_test(NAME edr_security_audit_visibility_tests COMMAND edr_security_audit_visibility_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")

    add_executable(edr_reporter_metrics_tests
        tests/reporter_metrics_tests.cpp user/reporter.cpp user/reporter_spool.cpp
        user/config.cpp user/event_bus.cpp)
    target_include_directories(edr_reporter_metrics_tests PRIVATE user common)
    target_compile_definitions(edr_reporter_metrics_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_reporter_metrics_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_reporter_metrics_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_reporter_metrics_tests PRIVATE bcrypt advapi32 winhttp)
    add_test(NAME edr_reporter_metrics_tests COMMAND edr_reporter_metrics_tests)

    add_executable(edr_task_content_redaction_tests
        tests/task_content_redaction_tests.cpp user/alerter.cpp
        user/config.cpp user/event_bus.cpp)
    target_include_directories(edr_task_content_redaction_tests PRIVATE user common)
    target_compile_definitions(edr_task_content_redaction_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_task_content_redaction_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_task_content_redaction_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_task_content_redaction_tests PRIVATE bcrypt advapi32)
    add_test(NAME edr_task_content_redaction_tests COMMAND edr_task_content_redaction_tests)

    add_executable(edr_syslog_forwarder_tests
        tests/syslog_forwarder_tests.cpp user/syslog_forwarder.cpp)
    target_include_directories(edr_syslog_forwarder_tests PRIVATE user common)
    target_compile_definitions(edr_syslog_forwarder_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_syslog_forwarder_tests PRIVATE /W4 /utf-8 /EHsc)
    endif()
    target_link_libraries(edr_syslog_forwarder_tests PRIVATE ws2_32)
    add_test(NAME edr_syslog_forwarder_tests COMMAND edr_syslog_forwarder_tests)

    add_executable(edr_sysmon_tamper_tests
        tests/sysmon_tamper_tests.cpp user/sysmon_parser.cpp user/process_tree_builder.cpp
        user/config.cpp user/event_bus.cpp user/rule_engine.cpp user/rule_lint.cpp)
    target_include_directories(edr_sysmon_tamper_tests PRIVATE user common)
    target_compile_definitions(edr_sysmon_tamper_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_sysmon_tamper_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_sysmon_tamper_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_sysmon_tamper_tests PRIVATE bcrypt wevtapi)
    add_test(NAME edr_sysmon_tamper_tests COMMAND edr_sysmon_tamper_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")
    add_executable(edr_net_etw_tests
        tests/net_etw_parser_tests.cpp
        user/collector_net_etw.cpp
    user/etw_health.cpp
        user/config.cpp
        user/event_bus.cpp
        user/rule_engine.cpp user/rule_lint.cpp
    )
    target_include_directories(edr_net_etw_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/user"
    )
    target_compile_definitions(edr_net_etw_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_net_etw_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_net_etw_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_net_etw_tests PRIVATE ws2_32 advapi32 bcrypt)
    add_test(NAME edr_net_etw_tests COMMAND edr_net_etw_tests)
    add_executable(edr_etw_tamper_tests
        tests/etw_tamper_tests.cpp
        user/collector_etw_tamper.cpp
        user/config.cpp
        user/event_bus.cpp
        user/rule_engine.cpp user/rule_lint.cpp
    )
    target_include_directories(edr_etw_tamper_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/user"
    )
    target_compile_definitions(edr_etw_tamper_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_etw_tamper_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_etw_tamper_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_etw_tamper_tests PRIVATE advapi32 psapi bcrypt)
    add_test(NAME edr_etw_tamper_tests COMMAND edr_etw_tamper_tests)
    add_executable(edr_rat_analyzer_tests
        tests/rat_analyzer_tests.cpp
        user/collector_rat_analyzer.cpp
        user/config.cpp
        user/event_bus.cpp
        user/rule_engine.cpp user/rule_lint.cpp
    )
    target_include_directories(edr_rat_analyzer_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/user"
    )
    target_compile_definitions(edr_rat_analyzer_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_rat_analyzer_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_rat_analyzer_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_rat_analyzer_tests PRIVATE advapi32 bcrypt)
    add_test(NAME edr_rat_analyzer_tests COMMAND edr_rat_analyzer_tests)
    add_executable(response_test_child tests/response_test_child.cpp)
    target_compile_definitions(response_test_child PRIVATE UNICODE _UNICODE NOMINMAX)
    if(MSVC)
        target_link_options(response_test_child PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    add_dependencies(edr_native_tests response_test_child)

    add_executable(edr_rule_engine_reload_tests
        tests/rule_engine_reload_tests.cpp
        user/rule_engine.cpp user/rule_lint.cpp
        user/event_bus.cpp
    )
    target_include_directories(edr_rule_engine_reload_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/user"
    )
    target_compile_definitions(edr_rule_engine_reload_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_rule_engine_reload_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_rule_engine_reload_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    target_link_libraries(edr_rule_engine_reload_tests PRIVATE bcrypt)
    add_test(NAME edr_rule_engine_reload_tests COMMAND edr_rule_engine_reload_tests)
    add_executable(edr_rule_lint_tests
        tests/rule_lint_test_main.cpp tests/rule_lint_tests.cpp user/rule_lint.cpp)
    target_include_directories(edr_rule_lint_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/common" "${CMAKE_CURRENT_SOURCE_DIR}/user")
    target_compile_definitions(edr_rule_lint_tests PRIVATE
        UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS NOMINMAX)
    if(MSVC)
        target_compile_options(edr_rule_lint_tests PRIVATE /W4 /utf-8 /EHsc)
        target_link_options(edr_rule_lint_tests PRIVATE /NODEFAULTLIB:OLDNAMES.lib)
    endif()
    add_test(NAME edr_rule_lint_tests COMMAND edr_rule_lint_tests)
    add_test(NAME edr_production_rule_lint COMMAND edr_rule_lint
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/rules.json")

    # Stage the exact production catalogs for tests using relative fixture paths.
    # This also supports binary trees located outside the source directory.
    file(GLOB EDR_TEST_RULE_FILES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/rules/*.json")
    foreach(rule_file IN LISTS EDR_TEST_RULE_FILES)
        get_filename_component(rule_name "${rule_file}" NAME)
        configure_file("${rule_file}"
            "${CMAKE_CURRENT_BINARY_DIR}/rules/${rule_name}" COPYONLY)
    endforeach()
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/rule-tests")
    set_tests_properties(edr_native_tests edr_net_etw_tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/rule-tests")
endif()

# ---------------------------------------------------------------------------
# Kernel driver (B1): no add_library/add_executable target. The driver is
# built by explicit custom commands invoking cl.exe / link.exe with every
# include and library path spelled out (no vcvars environment dependency).
# ---------------------------------------------------------------------------
include(FindWdkKm)

set(EDR_DRIVER_FEATURES "NONE" CACHE STRING
    "Driver feature topology: NONE, MINIFILTER, WFP, or ALL")
set_property(CACHE EDR_DRIVER_FEATURES PROPERTY STRINGS NONE MINIFILTER WFP ALL)
string(TOUPPER "${EDR_DRIVER_FEATURES}" EDR_DRIVER_FEATURES)
if(NOT EDR_DRIVER_FEATURES MATCHES "^(NONE|MINIFILTER|WFP|ALL)$")
    message(FATAL_ERROR "EDR_DRIVER_FEATURES must be NONE, MINIFILTER, WFP, or ALL")
endif()

set(EDR_DRIVER_DEFINES /D "_KERNEL_MODE" /D "POOL_NX_OPTIN=1" /D "_AMD64_"
    /D "EDR_ENABLE_THREAD=1" /D "EDR_ENABLE_IMAGE_LOAD=1")
set(EDR_DRIVER_LIBS ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowK.lib)

if(EDR_DRIVER_FEATURES STREQUAL "MINIFILTER")
    list(APPEND EDR_DRIVER_DEFINES /D "EDR_ENABLE_MINIFILTER=1")
    list(APPEND EDR_DRIVER_LIBS fltMgr.lib)
elseif(EDR_DRIVER_FEATURES STREQUAL "WFP")
    list(APPEND EDR_DRIVER_DEFINES /D "EDR_ENABLE_WFP=1")
    list(APPEND EDR_DRIVER_LIBS fwpkclnt.lib)
elseif(EDR_DRIVER_FEATURES STREQUAL "ALL")
    list(APPEND EDR_DRIVER_DEFINES
        /D "EDR_ENABLE_MINIFILTER=1" /D "EDR_ENABLE_WFP=1")
    list(APPEND EDR_DRIVER_LIBS fltMgr.lib fwpkclnt.lib)
endif()

if(EDR_KM_SDK_FOUND)
    set(EDR_DRIVER_SOURCES
        driver_entry.c
        device.c
        ioctl.c
        kill_process.c
        proc_notify.c
        reg_notify.c
        ob_notify.c
        thread_notify.c
        image_notify.c
        event_queue.c
        policy.c
        minifilter_skeleton.c
        wfp_skeleton.c
    )

    set(EDR_DRIVER_OBJS "")
    foreach(_src ${EDR_DRIVER_SOURCES})
        set(_obj "${CMAKE_CURRENT_BINARY_DIR}/driver/${_src}.obj")
        add_custom_command(
            OUTPUT "${_obj}"
            # cl /Fo does not create the output directory and the VS
            # generator does not pre-create custom-command output dirs.
            COMMAND "${CMAKE_COMMAND}" -E make_directory
                    "${CMAKE_CURRENT_BINARY_DIR}/driver"
COMMAND "${CMAKE_C_COMPILER}" /nologo /c /kernel /W4 /GS- /sdl-
                ${EDR_DRIVER_DEFINES}
                /I${EDR_WDK_INC_KM}
                /I${EDR_WDK_INC_KMCRT}
                /I${EDR_WDK_INC_UM}
                /I${EDR_WDK_INC_SHARED}
                ${EDR_WDK_INC_SHARED_FALLBACK}
                /I${CMAKE_CURRENT_SOURCE_DIR}/common
                /Fo${_obj}
                "${CMAKE_CURRENT_SOURCE_DIR}/driver/${_src}"
            DEPENDS
                    "${CMAKE_CURRENT_SOURCE_DIR}/driver/${_src}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/driver/edrdrv.h"
                    "${CMAKE_CURRENT_SOURCE_DIR}/driver/policy_validate.h"
                    "${CMAKE_CURRENT_SOURCE_DIR}/driver/response_policy.h"
                    "${CMAKE_CURRENT_SOURCE_DIR}/common/edr_event.h"
                    "${CMAKE_CURRENT_SOURCE_DIR}/common/edr_ioctl.h"
            COMMENT "cl (kernel) ${_src}"
            VERBATIM
        )
        list(APPEND EDR_DRIVER_OBJS "${_obj}")
    endforeach()

    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/driver/edrdrv.sys"
        COMMAND "${CMAKE_COMMAND}" -E make_directory
                "${CMAKE_CURRENT_BINARY_DIR}/driver"
        COMMAND "${CMAKE_LINKER}" /NOLOGO /DRIVER /SUBSYSTEM:NATIVE
                /ENTRY:DriverEntry /NODEFAULTLIB /MANIFEST:NO /MACHINE:X64
                /LIBPATH:${EDR_WDK_LIB_KM_X64}
                /OUT:${CMAKE_CURRENT_BINARY_DIR}/driver/edrdrv.sys
                ${EDR_DRIVER_OBJS}
                ${EDR_DRIVER_LIBS}
        DEPENDS ${EDR_DRIVER_OBJS}
        COMMENT "link edrdrv.sys"
        VERBATIM
    )

    # Not part of ALL: build explicitly with `cmake --build . --target edrdrv`.
    add_custom_target(edrdrv
        DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/driver/edrdrv.sys"
    )
else()
    message(WARNING
        "WDK kernel-mode SDK not fully available (see [FindWdkKm] MISSING "
        "lines above); skipping the 'edrdrv' driver target. "
        "Manual fallback: driver\\build_driver.bat")
endif()
