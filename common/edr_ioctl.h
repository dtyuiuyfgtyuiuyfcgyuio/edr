/*
 * edr_ioctl.h - Device names, IOCTL codes and control structures shared by
 * the kernel driver and the user-mode agent.
 *
 * Device:      \Device\edrdrv
 * Symlink:     \DosDevices\edrdrv   (user mode opens "\\.\edrdrv")
 *
 * Protocol (B+C Stage 1):
 *   IOCTL_EDR_FETCH_EVENT: caller supplies a 64KB output buffer. The driver
 *   copies as many WHOLE events as fit (walked by header.length; stops before
 *   an event that would not fit entirely). Actual bytes returned via
 *   IoStatus.Information. If not even one minimal event fits, the request
 *   fails with STATUS_BUFFER_TOO_SMALL and Information = required size.
 *   Events always live in the driver ring queue regardless of whether an IRP
 *   is pending; FETCH only triggers a batch drain.
 *
 *   IOCTL_EDR_SET_POLICY: input is exactly one EDR_POLICY_V1 struct
 *   (EDR_POLICY_SIZE bytes). The whole table must validate; any malformed
 *   field rejects the entire update and the committed generation is left
 *   unchanged. IOCTL_EDR_SET_CONFIG was removed in favor of this single
 *   policy IOCTL.
 */
#ifndef EDR_IOCTL_H
#define EDR_IOCTL_H

#ifdef __cplusplus
extern "C" {
#endif

#define EDR_DEVICE_NAME_W   L"\\Device\\edrdrv"
#define EDR_SYMLINK_NAME_W  L"\\DosDevices\\edrdrv"
#define EDR_USERMODE_PATH   "\\\\.\\edrdrv"

#define EDR_FETCH_BUFFER_SIZE (64u * 1024u)

/* enable_mask bits for EDR_POLICY_V1 (KNOWN_MASK = 0x3f) */
#define EDR_ENABLE_PROCESS   0x1u
#define EDR_ENABLE_REGISTRY  0x2u
#define EDR_ENABLE_FILE      0x4u
#define EDR_ENABLE_NET       0x8u
#define EDR_ENABLE_BLOCK     0x10u
#define EDR_ENABLE_OBJECT_HANDLE 0x20u
#define EDR_ENABLE_KNOWN_MASK (EDR_ENABLE_PROCESS | EDR_ENABLE_REGISTRY | \
                               EDR_ENABLE_FILE | EDR_ENABLE_NET | \
                               EDR_ENABLE_BLOCK | EDR_ENABLE_OBJECT_HANDLE)

#define IOCTL_EDR_FETCH_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EDR_SET_POLICY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*
 * IOCTL_EDR_KILL_PROCESS (C+ response plane):
 * input is a 4-byte little-endian target PID. The driver requires the
 * device to be opened with write access (see FILE_WRITE_ACCESS above),
 * looks the process up by PID, refuses to terminate the calling process
 * itself or a critical-system allowlisted image, and terminates the
 * target via ZwTerminateProcess. This gives the user-mode agent a
 * kernel-assisted kill for tamper-protected malware that strips handle
 * rights - the defensive counterpart of BYOVD abuse.
 */
#define IOCTL_EDR_KILL_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* PID is fixed width on the wire; HANDLE is only an internal kernel type. */
#define EDR_KILL_PROCESS_REQUEST_SIZE 4u
typedef struct _EDR_KILL_PROCESS_REQUEST {
    UINT32 pid;
} EDR_KILL_PROCESS_REQUEST;

static __inline int EdrDecodeKillProcessRequest(const void* input,
                                               ULONG length, UINT32* pid)
{
    const unsigned char* bytes;
    UINT32 value;
    if (input == NULL || pid == NULL ||
        length != EDR_KILL_PROCESS_REQUEST_SIZE) return 0;
    bytes = (const unsigned char*)input;
    value = (UINT32)bytes[0] | ((UINT32)bytes[1] << 8) |
            ((UINT32)bytes[2] << 16) | ((UINT32)bytes[3] << 24);
    if (value == 0) return 0;
    *pid = value;
    return 1;
}

#define EDR_POLICY_VERSION     1u
#define EDR_MAX_FILE_RULES     32u
#define EDR_MAX_NET_RULES      64u
#define EDR_PATH_MAX_BYTES     512u

/* Exact wire layout facts (asserted at compile time by the protocol tests). */
#define EDR_POLICY_FILE_RULE_SIZE 516u   /* 2 len + 2 reserved + 512 path */
#define EDR_POLICY_NET_RULE_SIZE   8u   /* 4 ip + 2 port + 2 reserved */
#define EDR_POLICY_FILE_OFFSET    32u   /* EDR_POLICY_V1.file_rules      */
#define EDR_POLICY_NET_OFFSET  16544u   /* EDR_POLICY_V1.net_rules       */
#define EDR_POLICY_SIZE        17056u   /* whole packed table            */

#pragma pack(push, 1)

/*
 * One file rule: a normalized NT prefix stored as UTF-16LE.
 * length is the byte count of the prefix (even, nonzero, <= 512).
 * path[length/2] wchar units hold the prefix and must start with L'\\'.
 * Bytes in path[] beyond length and the reserved field must be zero.
 */
typedef struct _EDR_POLICY_FILE_RULE {
    unsigned short length;   /* prefix byte count, even, 2..512   */
    unsigned short reserved; /* must be zero                      */
    unsigned short path[EDR_PATH_MAX_BYTES / sizeof(unsigned short)];
} EDR_POLICY_FILE_RULE;      /* 516 bytes */

/*
 * One IPv4 rule. ip[4] is four display-order octets. port is the u16 port;
 * port 0 means "any port". reserved must be zero.
 */
typedef struct _EDR_POLICY_NET_RULE {
    unsigned char  ip[4];    /* display order, never a special address */
    unsigned short port;     /* 0 = any port                            */
    unsigned short reserved; /* must be zero                            */
} EDR_POLICY_NET_RULE;       /* 8 bytes */

/*
 * The single packed policy table. version must be EDR_POLICY_VERSION,
 * struct_size must be EDR_POLICY_SIZE, generation must be nonzero,
 * enable_mask must be within EDR_ENABLE_KNOWN_MASK, counts must be within
 * their array bounds, every reserved/unused byte must be zero, and every
 * rule must validate individually. Unused rule slots must be all zero.
 */
typedef struct _EDR_POLICY_V1 {
    unsigned int version;          /* EDR_POLICY_VERSION                  */
    unsigned int struct_size;      /* EDR_POLICY_SIZE                     */
    unsigned int generation;       /* nonzero, monotonically distinguished*/
    unsigned int enable_mask;      /* EDR_ENABLE_* bits only              */
    unsigned int file_rule_count;  /* <= EDR_MAX_FILE_RULES               */
    unsigned int net_rule_count;   /* <= EDR_MAX_NET_RULES                */
    unsigned int reserved[2];      /* must be zero                        */
    EDR_POLICY_FILE_RULE file_rules[EDR_MAX_FILE_RULES];
    EDR_POLICY_NET_RULE net_rules[EDR_MAX_NET_RULES];
} EDR_POLICY_V1;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif /* EDR_IOCTL_H */
