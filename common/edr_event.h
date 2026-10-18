/*
 * edr_event.h - Shared event wire format between kernel driver and user-mode agent.
 *
 * Timestamp convention (M5):
 *   ts_100ns is a 64-bit count of 100-nanosecond intervals since 1601-01-01 UTC
 *   (Windows FILETIME epoch).
 *   - Kernel-originated events use KeQuerySystemTime() (UTC, 100ns units, ~10-15ms
 *     tick precision).
 *   - User-mode fallback events use GetSystemTimePreciseAsFileTime() (same epoch,
 *     typically sub-microsecond precision).
 *   Both share the same epoch; only the source/precision differs. Consumers must
 *   not assume cross-source ordering accuracy finer than the kernel tick.
 *
 * Parsing rule: readers must memcpy() each field; never cast a byte pointer to a
 * struct/uint64 pointer (alignment is not guaranteed in transit buffers).
 */
#ifndef EDR_EVENT_H
#define EDR_EVENT_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)

#define EDR_EVENT_MAGIC   0x52444445u /* "EDDR" little-endian on wire */
#define EDR_EVENT_VERSION 1u

/* Event types */
#define EDR_EVT_PROCESS_START 1u
#define EDR_EVT_PROCESS_STOP  2u
#define EDR_EVT_REG_WRITE     3u
#define EDR_EVT_FILE_CREATE   4u
#define EDR_EVT_NET_CONNECT   5u
#define EDR_EVT_STATS         6u
#define EDR_EVT_IMAGE_LOAD    7u
#define EDR_EVT_DNS_QUERY     8u
#define EDR_EVT_PROCESS_ACCESS 9u
#define EDR_EVT_LOGON           10u
#define EDR_EVT_ACCOUNT_CHANGE  11u
#define EDR_EVT_SERVICE_INSTALL 12u
#define EDR_EVT_WMI_EVENT       13u
#define EDR_EVT_TASK_SCHEDULER  14u
#define EDR_EVT_PRIVILEGE        15u
#define EDR_EVT_POWERSHELL_SCRIPT 16u
#define EDR_EVT_THREAD_CREATE 17u
#define EDR_EVT_PROCESS_READ 18u
#define EDR_EVT_FILE_READ 19u
#define EDR_EVT_APC_INJECT 20u
#define EDR_EVT_CONTEXT_CHANGE 21u
#define EDR_EVT_MEMORY_WRITE 22u
#define EDR_EVT_FILE_DELETE 23u
#define EDR_EVT_USB_DEVICE 24u
#define EDR_EVT_NET_LISTENER 25u
#define EDR_EVT_SERVICE_CHANGE 26u
#define EDR_EVT_CRITICAL_PROCESS 27u
#define EDR_EVT_FILE_INTEGRITY 28u
#define EDR_EVT_SHARE_CHANGE 29u
#define EDR_EVT_BLOCK 30u /* best-effort audit for an enforced BLOCK rule */
#define EDR_EVT_DEFENDER 31u
#define EDR_EVT_RPC_CREATE_PROCESS 32u
#define EDR_EVT_WINDOWS_HOOK 33u
#define EDR_EVT_SERVICE_INSTALL_HOOK 34u
#define EDR_EVT_SERVICE_START_HOOK 35u
#define EDR_EVT_SERVICE_CONFIG_CHANGE 36u
#define EDR_EVT_CO_INSTANCE 37u
#define EDR_EVT_SECTION_MAP 38u
#define EDR_EVT_HANDLE_DUPLICATE 39u
#define EDR_EVT_INPUT_SIMULATION 40u
#define EDR_EVT_SYSTEM_SHUTDOWN 41u
#define EDR_EVT_SYSTEM_TIME_CHANGE 42u
#define EDR_EVT_CLIPBOARD_ACCESS 43u
#define EDR_EVT_WALLPAPER_CHANGE 44u
#define EDR_EVT_CAMERA_ACCESS 45u
#define EDR_EVT_KEYLOGGER 46u
#define EDR_EVT_POWERSHELL_HOOK 47u
#define EDR_EVT_AUDIT_LOG 48u
#define EDR_EVT_HANDLE_OPEN 49u    /* ObRegisterCallbacks: process/thread handle open */
#define EDR_EVT_FILE_RENAME 50u    /* Minifilter: file rename operation */
#define EDR_EVT_REG_DELETE  51u    /* Registry: value/key delete operation */
#define EDR_EVT_LOCAL_ACCOUNT 52u  /* local user account / group membership */
#define EDR_EVT_FIREWALL_RULE 53u  /* Windows Firewall rule change */
#define EDR_EVT_NAMED_PIPE 54u    /* ETW: named pipe create/connect operation */
#define EDR_EVT_ETW_TAMPER 55u   /* user-mode ETW tampering (provider disable /
                                    session stop / ntdll EtwEventWrite patch) */
#define EDR_EVT_RAT_ANALYZER 56u   /* polled remote-access-trojan behavior scan (user mode) */
#define EDR_EVT_RDP_SESSION 57u    /* Terminal Services / RDP session logon/off/reconnect */
#define EDR_EVT_INCIDENT_CORRELATED 58u /* user-mode synthetic: kill-chain roll-up
                                           published by the correlation layer, never
                                           collected from an OS telemetry source */

/* flags bits */
#define EDR_FLAG_TRUNCATED            0x1u /* some field was cut to fit limits */
#define EDR_FLAG_COMMAND_LINE_ABSENT  0x2u /* command line could not be obtained */

/* TLV tags */
#define EDR_TAG_IMAGE        1u /* utf16le, no NUL required on wire */
#define EDR_TAG_COMMAND_LINE 2u /* utf16le */
#define EDR_TAG_PARENT_IMAGE 3u /* utf16le */
#define EDR_TAG_SHA256       4u /* hex ascii */
#define EDR_TAG_FILE_PATH    5u /* utf16le */
#define EDR_TAG_DST_IP       6u /* ascii */
#define EDR_TAG_DST_PORT     7u /* u16 */
#define EDR_TAG_REG_KEY      8u /* utf16le */
#define EDR_TAG_REG_VALUE    9u /* utf16le */
#define EDR_TAG_RULE_INDEX  10u /* u32: 0-based index of the matched rule */
#define EDR_TAG_THREAD_ID   11u /* u32 */
#define EDR_TAG_IMAGE_LOADED 12u /* utf16le, full image path */
#define EDR_TAG_TARGET_PID 13u   /* u32: target process/thread id for handle open */
#define EDR_TAG_ACCESS_MASK 14u  /* u32: granted access mask for handle open */
#define EDR_TAG_OBJECT_TYPE 15u  /* u8: 0=process, 1=thread */
#define EDR_TAG_OLD_FILE_PATH 16u /* utf16le: original path before rename */
#define EDR_TAG_REG_OPERATION 17u /* u8: 0=delete_value, 1=delete_key */
#define EDR_TAG_PIPE_NAME 18u     /* utf16le: named pipe name (e.g. \Device\NamedPipe\pipename) */
#define EDR_TAG_PIPE_OPERATION 19u /* u8: 0=pipe_created, 1=pipe_connected */

typedef struct _EDR_EVENT_HEADER {
    unsigned int   magic;      /* EDR_EVENT_MAGIC */
    unsigned short version;    /* EDR_EVENT_VERSION */
    unsigned short type;       /* EDR_EVT_* */
    unsigned int   length;     /* total length incl. this 36-byte header */
    unsigned __int64 ts_100ns; /* FILETIME-epoch timestamp, see header comment */
    unsigned int   pid;
    unsigned int   ppid;
    unsigned int   flags;
    unsigned int   reserved;
} EDR_EVENT_HEADER; /* 36 bytes */

typedef struct _EDR_TLV_HEADER {
    unsigned short tag;
    unsigned short len; /* value bytes, no padding */
} EDR_TLV_HEADER;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif /* EDR_EVENT_H */
