/*
 * reg_notify.c - Registry write monitoring via CmRegisterCallbackEx.
 *
 * Scope: RegNtPreSetValueKey only, and only keys
 * whose normalized path contains one of:
 *     \CurrentVersion\Run      \CurrentVersion\RunOnce      \Services
 *     \CurrentVersion\Image File Execution Options   \CurrentVersion\Winlogon
 *     \Policies\Explorer\Run   \CurrentVersion\RunServices
 *     \CurrentVersion\Authentication\Credential Providers
 *     \CurrentVersion\Explorer\ShellServiceObjectDelayLoad
 *     \CurrentVersion\Explorer\StartupApproved\Run
 *     \Windows NT\CurrentVersion\Windows (AppInit_DLLs)
 *     \CurrentControlSet\Control\Lsa (SecurityPackages)
 *     \Classes\CLSID (COM InprocServer32)
 *     \Policies\Google\Chrome / \Policies\Microsoft\Edge
 *     \Google\Chrome\Extensions / \Microsoft\Edge\Extensions
 * Matching is case-insensitive and tolerates the \REGISTRY\MACHINE\ prefix
 * (and \Registry\Machine generally). Matches end at a path-component
 * boundary so, for example, Run does not match Runner.
 *
 * Safety: OBJECT_NAME_INFORMATION is written into a callback-local nonpaged
 * block while the callback object is known-alive. No name is dereferenced
 * after the callback returns, and no query is made above PASSIVE_LEVEL.
 */
#include "edrdrv.h"

/* ObQueryNameString lives in <ntifs.h>, which cannot be combined with
 * <ntddk.h>; declare it locally (signature copied from ntifs.h). */
NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID Object,
    _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
    _In_ ULONG Length,
    _Out_ PULONG ReturnLength
    );

static EDR_QUEUE* g_RegQueue;
static LARGE_INTEGER g_RegCookie;
static WCHAR g_Altitude[] = L"388000"; /* numeric string, arbitrary altitude */

#define EDR_REG_NAME_BYTES 1024u

static BOOLEAN PathContainsComponentCaseInsensitive(
    _In_reads_(HaystackChars) const WCHAR* Haystack,
    _In_ SIZE_T HaystackChars,
    _In_ const WCHAR* Needle)
{
    SIZE_T nLen = 0, i;

    while (Needle[nLen] != L'\0') {
        nLen++;
    }
    if (nLen == 0 || HaystackChars < nLen) {
        return FALSE;
    }
    for (i = 0; i <= HaystackChars - nLen; i++) {
        SIZE_T j;
        BOOLEAN match = TRUE;
        for (j = 0; j < nLen; j++) {
            WCHAR a = Haystack[i + j];
            WCHAR b = Needle[j];
            if (a >= L'a' && a <= L'z') {
                a = a - L'a' + L'A';
            }
            if (b >= L'a' && b <= L'z') {
                b = b - L'a' + L'A';
            }
            if (a != b) {
                match = FALSE;
                break;
            }
        }
        if (match &&
            (i + nLen == HaystackChars || Haystack[i + nLen] == L'\\')) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN RegPathIsInteresting(_In_reads_(PathChars) const WCHAR* Path,
                                    _In_ SIZE_T PathChars)
{
    /* Autostart persistence points (component-boundary match). */
    static const WCHAR kRun[] = L"\\CurrentVersion\\Run";
    static const WCHAR kRunOnce[] = L"\\CurrentVersion\\RunOnce";
    static const WCHAR kServices[] = L"\\Services";
    static const WCHAR kIFEO[] = L"\\CurrentVersion\\Image File Execution Options";
    static const WCHAR kWinlogon[] = L"\\CurrentVersion\\Winlogon";
    static const WCHAR kPoliciesRun[] = L"\\Policies\\Explorer\\Run";
    static const WCHAR kRunServices[] = L"\\CurrentVersion\\RunServices";
    static const WCHAR kCredProviders[] =
        L"\\CurrentVersion\\Authentication\\Credential Providers";
    static const WCHAR kShellServiceObjectDelayLoad[] =
        L"\\CurrentVersion\\Explorer\\ShellServiceObjectDelayLoad";
    static const WCHAR kStartupApproved[] =
        L"\\CurrentVersion\\Explorer\\StartupApproved\\Run";
    static const WCHAR kAppInit[] = L"\\Windows NT\\CurrentVersion\\Windows";
    static const WCHAR kLsa[] = L"\\CurrentControlSet\\Control\\Lsa";
    static const WCHAR kCLSID[] = L"\\Classes\\CLSID";
    static const WCHAR kChromePolicy[] = L"\\Policies\\Google\\Chrome";
    static const WCHAR kEdgePolicy[] = L"\\Policies\\Microsoft\\Edge";
    static const WCHAR kChromeExtensions[] = L"\\Google\\Chrome\\Extensions";
    static const WCHAR kEdgeExtensions[] = L"\\Microsoft\\Edge\\Extensions";

    return PathContainsComponentCaseInsensitive(Path, PathChars, kRun) ||
           PathContainsComponentCaseInsensitive(Path, PathChars, kRunOnce) ||
           PathContainsComponentCaseInsensitive(Path, PathChars, kServices) ||
           PathContainsComponentCaseInsensitive(Path, PathChars, kIFEO) ||
           PathContainsComponentCaseInsensitive(Path, PathChars, kWinlogon) ||
           PathContainsComponentCaseInsensitive(Path, PathChars, kPoliciesRun) ||
           PathContainsComponentCaseInsensitive(Path, PathChars, kRunServices) ||
           PathContainsComponentCaseInsensitive(Path, PathChars,
                                                 kCredProviders) ||
           PathContainsComponentCaseInsensitive(Path, PathChars,
                                                 kShellServiceObjectDelayLoad) ||
           PathContainsComponentCaseInsensitive(Path, PathChars,
                                                 kStartupApproved) ||
           PathContainsComponentCaseInsensitive(Path, PathChars, kAppInit) ||
           PathContainsComponentCaseInsensitive(Path, PathChars, kLsa) ||
           PathContainsComponentCaseInsensitive(Path, PathChars, kCLSID) ||
           PathContainsComponentCaseInsensitive(Path, PathChars,
                                                 kChromePolicy) ||
           PathContainsComponentCaseInsensitive(Path, PathChars,
                                                 kEdgePolicy) ||
           PathContainsComponentCaseInsensitive(Path, PathChars,
                                                 kChromeExtensions) ||
           PathContainsComponentCaseInsensitive(Path, PathChars,
                                                 kEdgeExtensions);
}

static NTSTATUS EdrRegistryCallback(_In_ PVOID CallbackContext,
                                    _In_opt_ PVOID Argument1,
                                    _In_opt_ PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PVOID object = NULL;
    const WCHAR* valueName = NULL;
    USHORT valueNameBytes = 0;
    UCHAR* nameBlock = NULL;
    OBJECT_NAME_INFORMATION* nameInfo;
    ULONG returned = 0;
    ULONG_PTR blockStart;
    ULONG_PTR blockEnd;
    ULONG_PTR nameStart;
    ULONG_PTR nameEnd;
    USHORT nameBytes = 0;
    NTSTATUS status;
    USHORT eventType = 0;
    UCHAR regOperation = 0;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (g_RegQueue == NULL ||
        !EdrQueueIsEnabled(g_RegQueue, EDR_ENABLE_REGISTRY)) {
        return STATUS_SUCCESS;
    }

    if (notifyClass == RegNtPreSetValueKey) {
        REG_SET_VALUE_KEY_INFORMATION* info =
            (REG_SET_VALUE_KEY_INFORMATION*)Argument2;
        if (info == NULL || info->Object == NULL ||
            info->ValueName == NULL || info->ValueName->Buffer == NULL ||
            (info->ValueName->Length & (sizeof(WCHAR) - 1u)) != 0) {
            return STATUS_SUCCESS;
        }
        object = info->Object;
        valueName = info->ValueName->Buffer;
        valueNameBytes = info->ValueName->Length;
        eventType = (unsigned short)EDR_EVT_REG_WRITE;
    } else if (notifyClass == RegNtPreDeleteValueKey) {
        REG_DELETE_VALUE_KEY_INFORMATION* info =
            (REG_DELETE_VALUE_KEY_INFORMATION*)Argument2;
        if (info == NULL || info->Object == NULL) {
            return STATUS_SUCCESS;
        }
        object = info->Object;
        if (info->ValueName != NULL && info->ValueName->Buffer != NULL &&
            (info->ValueName->Length & (sizeof(WCHAR) - 1u)) == 0) {
            valueName = info->ValueName->Buffer;
            valueNameBytes = info->ValueName->Length;
        }
        eventType = (unsigned short)EDR_EVT_REG_DELETE;
        regOperation = 0; /* delete value */
    } else if (notifyClass == RegNtPreDeleteKey) {
        REG_DELETE_KEY_INFORMATION* info =
            (REG_DELETE_KEY_INFORMATION*)Argument2;
        if (info == NULL || info->Object == NULL) {
            return STATUS_SUCCESS;
        }
        object = info->Object;
        eventType = (unsigned short)EDR_EVT_REG_DELETE;
        regOperation = 1; /* delete key */
    } else {
        return STATUS_SUCCESS;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_SUCCESS;
    }

    nameBlock = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                        EDR_REG_NAME_BYTES, EDR_POOL_TAG);
    if (nameBlock == NULL) {
        return STATUS_SUCCESS;
    }
    nameInfo = (OBJECT_NAME_INFORMATION*)nameBlock;
    status = ObQueryNameString(object, nameInfo, EDR_REG_NAME_BYTES, &returned);
    if (!NT_SUCCESS(status) || nameInfo->Name.Buffer == NULL) {
        goto Cleanup;
    }

    nameBytes = nameInfo->Name.Length;
    blockStart = (ULONG_PTR)nameBlock;
    blockEnd = blockStart + EDR_REG_NAME_BYTES;
    nameStart = (ULONG_PTR)nameInfo->Name.Buffer;
    if ((nameBytes & (sizeof(WCHAR) - 1u)) != 0 ||
        nameStart < blockStart || nameStart > blockEnd ||
        (ULONG_PTR)nameBytes > blockEnd - nameStart) {
        goto Cleanup;
    }
    nameEnd = nameStart + nameBytes;
    if (nameEnd < nameStart || nameEnd > blockEnd || nameBytes == 0) {
        goto Cleanup;
    }

    if (RegPathIsInteresting(nameInfo->Name.Buffer,
                             nameBytes / sizeof(WCHAR))) {
        EDR_EVENT_HEADER hdr;
        UCHAR payload[EDR_SLOT_SIZE - sizeof(EDR_EVENT_HEADER)];
        EDR_TLV_HEADER tlv;
        ULONG payloadBytes = 0;
        ULONG available;

        memset(&hdr, 0, sizeof(hdr));
        hdr.magic = EDR_EVENT_MAGIC;
        hdr.version = (unsigned short)EDR_EVENT_VERSION;
        hdr.type = eventType;
        KeQuerySystemTime((PLARGE_INTEGER)&hdr.ts_100ns);
        hdr.pid = (unsigned int)(ULONG_PTR)PsGetCurrentProcessId();

        tlv.tag = EDR_TAG_REG_KEY;
        tlv.len = nameBytes;
        memcpy(payload, &tlv, sizeof(tlv));
        memcpy(payload + sizeof(tlv), nameInfo->Name.Buffer, nameBytes);
        payloadBytes = (ULONG)sizeof(tlv) + nameBytes;

        /* For REG_DELETE events, include the REG_OPERATION tag. */
        if (eventType == EDR_EVT_REG_DELETE) {
            available = (ULONG)sizeof(payload) - payloadBytes;
            if (available >= (ULONG)sizeof(tlv) + sizeof(UCHAR)) {
                tlv.tag = EDR_TAG_REG_OPERATION;
                tlv.len = sizeof(UCHAR);
                memcpy(payload + payloadBytes, &tlv, sizeof(tlv));
                memcpy(payload + payloadBytes + sizeof(tlv),
                       &regOperation, sizeof(regOperation));
                payloadBytes += (ULONG)sizeof(tlv) + sizeof(UCHAR);
            } else {
                hdr.flags |= EDR_FLAG_TRUNCATED;
            }
        }

        available = (ULONG)sizeof(payload) - payloadBytes;
        if (available >= (ULONG)sizeof(tlv) + valueNameBytes) {
            tlv.tag = EDR_TAG_REG_VALUE;
            tlv.len = valueNameBytes;
            memcpy(payload + payloadBytes, &tlv, sizeof(tlv));
            memcpy(payload + payloadBytes + sizeof(tlv),
                   valueName, valueNameBytes);
            payloadBytes += (ULONG)sizeof(tlv) + valueNameBytes;
        } else {
            hdr.flags |= EDR_FLAG_TRUNCATED;
        }

        EdrQueuePush(g_RegQueue, &hdr, payload, payloadBytes);
    }
Cleanup:
    ExFreePoolWithTag(nameBlock, EDR_POOL_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS EdrRegNotifyRegister(_In_ EDR_QUEUE* Q)
{
    UNICODE_STRING altitude;
    NTSTATUS status;

    g_RegQueue = Q;
    RtlInitUnicodeString(&altitude, g_Altitude);
    status = CmRegisterCallbackEx(EdrRegistryCallback, &altitude, NULL,
                                  &g_RegCookie, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        g_RegQueue = NULL;
    }
    return status;
}

NTSTATUS EdrRegNotifyUnregister(VOID)
{
    NTSTATUS status;

    if (g_RegQueue == NULL) {
        return STATUS_SUCCESS;
    }
    status = CmUnRegisterCallback(g_RegCookie);
    if (NT_SUCCESS(status)) {
        g_RegQueue = NULL; /* only clear ownership after success */
    }
    return status;
}
