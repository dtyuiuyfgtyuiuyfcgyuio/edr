'use strict';

/**
 * technique -> {configKey, detector} static mapping.
 * Covers REFERENCE_TECHNIQUES where a detector exists; entries without a
 * detector are explicitly null with a comment.
 * configKey corresponds to the top-level key in config/edr.config.json
 * (enable_* or nested detector segment) that an operator can flip.
 * detector is the filename under user/ implementing the detection.
 */
const TECHNIQUE_CONFIG_MAP = Object.freeze({
  'T1003': { configKey: 'credential_dumping', detector: 'credential_dumping_detector.cpp' },
  'T1003.001': { configKey: 'lsass_dump', detector: 'lsass_dump_detector.cpp' },
  // T1005 - Data from Local System: local_collect detector (EDR-424..428)
  'T1005': { configKey: 'local_collect', detector: 'local_collect_detector.cpp' },
  // T1007 - System Service Discovery: host_profile detector (EDR-445..447)
  //         measures per-actor breadth across process/service/registry/
  //         netconfig/systeminfo/group/account questions; the static
  //         single-command rules EDR-142 (sc/tasklist) stay as-is.
  'T1007': { configKey: 'host_profile', detector: 'host_profile_detector.cpp' },
  // T1012 - Query Registry: host_profile detector (EDR-445..447)
  'T1012': { configKey: 'host_profile', detector: 'host_profile_detector.cpp' },
  // T1016 - System Network Configuration Discovery: host_profile detector
  //         (EDR-445..447); the static single-command rule EDR-141
  //         (ipconfig /all, route print) stays as-is.
  'T1016': { configKey: 'host_profile', detector: 'host_profile_detector.cpp' },
  // T1018 - Remote System Discovery: net_discovery (burst, EDR-437) and
  //         host_profile (cross-category breadth, EDR-445..447).
  'T1018': { configKey: 'net_discovery', detector: 'net_discovery_detector.cpp' },
  'T1021.001': { configKey: 'lateral_move', detector: 'lateral_movement_detector.cpp' },
  'T1021.002': { configKey: 'lateral_move', detector: 'lateral_movement_detector.cpp' },
  'T1021.003': { configKey: 'lateral_move', detector: 'lateral_movement_detector.cpp' },
  'T1021.006': { configKey: 'winrm_abuse', detector: 'winrm_abuse_detector.cpp' },
  'T1027': { configKey: 'obfuscation', detector: 'obfuscation_detector.cpp' },
  'T1036': { configKey: 'masquerade', detector: 'masquerade_detector.cpp' },
  'T1041': { configKey: 'data_exfiltration', detector: 'data_exfiltration_detector.cpp' },
  'T1046': { configKey: 'port_scan', detector: 'port_scan_detector.cpp' },
  // T1047 - Windows Management Instrumentation: wmi_exec detector (EDR-420..423)
  //         adds the PowerShell CIM surface, /node: remote execution and
  //         aggregation on top of the raw wmic.exe rules EDR-144 / EDR-268.
  'T1047': { configKey: 'wmi_exec', detector: 'wmi_exec_detector.cpp' },
  'T1053.005': { configKey: 'task_abuse', detector: 'task_abuse_detector.cpp' },
  'T1055': { configKey: 'api_hook', detector: 'api_hook_detector.cpp' },
  'T1055.001': { configKey: 'process_hollowing', detector: 'process_hollowing_detector.cpp' },
  'T1057': { configKey: 'discovery_recon', detector: 'discovery_recon_detector.cpp' },
  'T1059.001': { configKey: 'fileless_attack', detector: 'fileless_attack_detector.cpp' },
  'T1059.003': { configKey: 'fileless_attack', detector: 'fileless_attack_detector.cpp' },
  'T1059.007': { configKey: 'fileless_attack', detector: 'fileless_attack_detector.cpp' },
  // T1068 - Exploitation for Privilege Escalation: host_profile detector
  //         flags a profiling actor that also used a privilege-elevation
  //         execution path (EDR-447); driver/BYOVD exploitation stays with
  //         driver_load (EDR-305) and the static EDR-042 / EDR-234 rules.
  'T1068': { configKey: 'host_profile', detector: 'host_profile_detector.cpp' },
  // T1069.002 - Domain Groups: host_profile detector (EDR-445..447)
  'T1069.002': { configKey: 'host_profile', detector: 'host_profile_detector.cpp' },
  'T1070.004': { configKey: 'anti_forensics', detector: 'anti_forensics_detector.cpp' },
  'T1078': { configKey: 'account_op', detector: 'account_op_detector.cpp' },
  'T1082': { configKey: 'discovery_recon', detector: 'discovery_recon_detector.cpp' },
  'T1083': { configKey: 'discovery_recon', detector: 'discovery_recon_detector.cpp' },
  // T1087.002 - Domain Account: host_profile detector (EDR-445..447)
  'T1087.002': { configKey: 'host_profile', detector: 'host_profile_detector.cpp' },
  'T1090.001': { configKey: 'tunnel_tool', detector: 'tunnel_tool_detector.cpp' },
  'T1090.003': { configKey: 'tunnel_tool', detector: 'tunnel_tool_detector.cpp' },
  'T1098': { configKey: 'ssh_key_persistence', detector: 'ssh_key_persistence_detector.cpp' },
  'T1105': { configKey: 'bits_abuse', detector: 'bits_abuse_detector.cpp' },
  'T1110': { configKey: 'logon_brute_force', detector: 'logon_brute_force_detector.cpp' },
  // T1112 - Modify Registry: reg_modify detector (EDR-416..419) covers the
  //         security-control plane (UAC / LSA / SMB signing / machine
  //         PowerShell policy / SmartScreen). Persistence-flavoured registry
  //         writes stay owned by registry_persistence and friends.
  'T1112': { configKey: 'reg_modify', detector: 'reg_modify_detector.cpp' },
  'T1113': { configKey: 'surveillance', detector: 'surveillance_detector.cpp' },
  'T1115': { configKey: 'clipboard_theft', detector: 'clipboard_theft_detector.cpp' },
  'T1134': { configKey: 'token_impersonation', detector: 'token_impersonation_detector.cpp' },
  'T1136.001': { configKey: 'local_account', detector: 'local_account_detector.cpp' },
  'T1486': { configKey: 'ransom_burst', detector: 'ransom_burst_detector.cpp' },
  'T1490': { configKey: 'shadow_copy', detector: 'shadow_copy_detector.cpp' },
  'T1497': { configKey: 'anti_analysis', detector: 'anti_analysis_detector.cpp' },
  'T1543.003': { configKey: 'service_dll_hijack', detector: 'service_dll_hijack_detector.cpp' },
  // T1546.005 - WMI Event Subscription: covered by wmi_persistence detector and persist_burst (EDR-407)
  'T1546.005': { configKey: 'persist_burst', detector: 'persistence_burst_detector.cpp' },
  'T1547.001': { configKey: 'registry_persistence', detector: 'registry_persistence_detector.cpp' },
  // T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting: as_rep_roast detector (EDR-406)
  'T1558.004': { configKey: 'as_rep_roast', detector: 'as_rep_roast_detector.cpp' },
  // T1003.003 - OS Credential Dumping: NTDS: ntds_dit detector (EDR-379)
  'T1003.003': { configKey: 'ntds_dit', detector: 'ntds_dit_detector.cpp' },
  'T1562.001': { configKey: 'av_tamper', detector: 'av_tamper_detector.cpp' },
  'T1562.004': { configKey: 'firewall_rule', detector: 'firewall_rule_detector.cpp' },
  // T1570 - Lateral Tool Transfer: lateral_transfer detector (EDR-429..433)
  'T1570': { configKey: 'lateral_transfer', detector: 'lateral_transfer_detector.cpp' },
  // T1583.001 - Acquire Infrastructure: Domains: threat_intel feed matcher
  //             (EDR-439/440/444). Operator-armed IoC list, off by default.
  'T1583.001': { configKey: 'threat_intel', detector: 'threat_intel_detector.cpp' },
  // T1071 - Application Layer Protocol: threat_intel matches C2 domains /
  //         addresses / certificate fingerprints from the armed feed (EDR-440).
  'T1071.001': { configKey: 'threat_intel', detector: 'threat_intel_detector.cpp' },
  'T1071.004': { configKey: 'threat_intel', detector: 'threat_intel_detector.cpp' },
  'T1070.001': { configKey: 'eventlog_tamper', detector: 'eventlog_tamper_detector.cpp' },
  'T1562.002': { configKey: 'eventlog_tamper', detector: 'eventlog_tamper_detector.cpp' },
  'T1021.004': { configKey: 'ssh_abuse', detector: 'ssh_abuse_detector.cpp' },
  // T1021 - Remote Services: lateral_chain correlates four-plus distinct
  //         lateral vectors into one chain (EDR-441/442). Complements the
  //         per-surface lateral_move / winrm_abuse detectors.
  'T1021': { configKey: 'lateral_chain', detector: 'lateral_chain_detector.cpp' },
  // T1114.003 - Email Collection: Email Forwarding Rule: mailbox_rule detector
  //             (EDR-484/485). Off-by-default inbox-rule / SMTP forwarding.
  'T1114.003': { configKey: 'mailbox_rule', detector: 'mailbox_rule_detector.cpp' },
  // T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay:
  //             llmnr_poison detector (EDR-486/487). Off-by-default poison
  //             tooling (Inveigh / Responder / NBNS spoof shapes).
  'T1557.001': { configKey: 'llmnr_poison', detector: 'llmnr_poison_detector.cpp' },
  // T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning: arp_poison
  //             detector (EDR-493/494). Off-by-default ARP poisoner tooling
  //             (ettercap / bettercap / arpspoof) and static ARP table loads.
  'T1557.002': { configKey: 'arp_poison', detector: 'arp_poison_detector.cpp' },
  // T1552.005 - Unsecured Credentials: Cloud Instance Metadata API:
  //             cloud_metadata detector (EDR-496/497). Off-by-default IMDS
  //             credential-theft surface (169.254.169.254 / metadata hosts /
  //             token-pull request shapes).
  'T1552.005': { configKey: 'cloud_metadata', detector: 'cloud_metadata_detector.cpp' },
  // T1552.006 - Unsecured Credentials: Group Policy Preferences:
  //             gpp_password detector (EDR-500/501). Off-by-default GPP
  //             cpassword extraction surface (Get-GPPPassword / gpp-decrypt /
  //             SYSVOL Groups.xml reads).
  'T1552.006': { configKey: 'gpp_password', detector: 'gpp_password_detector.cpp' },
  // T1218.002 - System Binary Proxy Execution: Control Panel:
  //             control_panel_proxy detector (EDR-502/503). Off-by-default
  //             control.exe .inf / .cpl execution and the Control_RunDLL
  //             CPL shape.
  'T1218.002': { configKey: 'control_panel_proxy', detector: 'control_panel_proxy_detector.cpp' },
  // T1564.002 - Hide Artifacts: Hidden Users: hidden_user_account detector
  //             (EDR-504/505). Off-by-default Winlogon SpecialAccounts\
  //             UserList concealment (registry + command planes).
  'T1564.002': { configKey: 'hidden_user_account', detector: 'hidden_user_account_detector.cpp' },
  // T1201 - Password Policy Discovery: password_policy_discovery detector
  //         (EDR-506/507). Off-by-default policy read surface
  //         (Get-ADDefaultDomainPasswordPolicy / net accounts / secedit
  //         /export). Policy MODIFICATION stays with account_op.
  'T1201': { configKey: 'password_policy_discovery', detector: 'password_policy_discovery_detector.cpp' },
  // T1546.016 - Event Triggered Execution: Installer Packages: msi_package_install
  //             detector (EDR-508/509). Off-by-default msiexec install abuse
  //             (package fetched from a URL/UNC share or staged in a
  //             user-writable path).
  'T1546.016': { configKey: 'msi_package_install', detector: 'msi_package_install_detector.cpp' },
  // T1654 - Log Enumeration: log_enumeration detector (EDR-510/511).
  //         Off-by-default event-log inventory enumeration surface
  //         (wevtutil el / Get-WinEvent -ListLog); tamper stays with
  //         eventlog_tamper and defense_evasion.
  'T1654': { configKey: 'log_enumeration', detector: 'log_enumeration_detector.cpp' },
  // T1556.008 - Modify Authentication Process: Network Provider DLL:
  //             netprovider_persist detector (EDR-488). Off-by-default
  //             NetworkProvider Order / ProviderPath persistence.
  'T1556.008': { configKey: 'netprovider_persist', detector: 'netprovider_persist_detector.cpp' },
  // T1555.005 - Credentials from Password Stores: Password Managers:
  //             password_vault detector (EDR-489/490). Off-by-default vault
  //             extraction and CLI bulk reads.
  'T1555.005': { configKey: 'password_vault', detector: 'password_vault_detector.cpp' },
  // T1098.002 - Account Manipulation: Additional Email Delegate Permissions:
  //             mailbox_delegate detector (EDR-491/492). Off-by-default
  //             Exchange delegate grant surface (FullAccess / SendAs /
  //             folder permissions).
  'T1098.002': { configKey: 'mailbox_delegate', detector: 'mailbox_delegate_detector.cpp' },
  // T1531 - Account Access Removal: account_op detector (EDR-495; same
  //         configKey as T1078). Account delete / disable signals narrow the
  //         55-74 band so create/group signals are never mislabeled.
  'T1531': { configKey: 'account_op', detector: 'account_op_detector.cpp' },
  // T1561.001 - Disk Wipe: Content Wipe: disk_wipe detector (EDR-498; EDR-461
  //             covers the 75+ alert band). Off-by-default cipher /w and
  //             PowerShell volume wipe logging.
  'T1561.001': { configKey: 'disk_wipe', detector: 'disk_wipe_detector.cpp' },
  // T1561.002 - Disk Wipe: Disk Structure Wipe: disk_wipe detector (EDR-461
  //             75+ band carries it alongside T1561.002). Sibling of
  //             T1561.001 above; same disk_wipe config section.
  'T1561.002': { configKey: 'disk_wipe', detector: 'disk_wipe_detector.cpp' },
  // T1547.003 / T1547.012 - Boot/Logon Autostart: Time Providers / Print
  //             Processors: boot_provider_persist detector (EDR-455 >=75,
  //             EDR-499 55-74 subkey tier).
  'T1547.003': { configKey: 'boot_provider_persist', detector: 'boot_provider_persist_detector.cpp' },
  'T1547.012': { configKey: 'boot_provider_persist', detector: 'boot_provider_persist_detector.cpp' },
  // T1547.010 - Boot/Logon Autostart: Print Monitors: REG_WRITE dual-shape
  //             coverage (EDR-148 snapshot shape / EDR-512 driver shape).
  'T1547.010': { configKey: 'boot_provider_persist', detector: 'boot_provider_persist_detector.cpp' },
  // T1547.002 - Boot or Logon Autostart Execution: Authentication Packages:
  //             lsa_package detector (EDR-375 now carries the T1547.002
  //             label). Off-by-default LSA security-package / password-filter
  //             registration surface.
  'T1547.002': { configKey: 'lsa_package', detector: 'lsa_package_detector.cpp' },
});

module.exports = { TECHNIQUE_CONFIG_MAP };
