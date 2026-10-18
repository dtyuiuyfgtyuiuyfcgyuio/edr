/*
 * proc_notify.c - Process create/exit notify via PsSetCreateProcessNotifyRoutineEx.
 *
 * Collects: image file name, pid, ppid, parent image (best effort).
 * The command line is deliberately NOT read in kernel (M2); the user-mode
 * agent enriches PROCESS_START events instead.
 *
 * String handling: bounded memcpy + explicit NUL termination, capped at
 * EDR_STR_MAX_BYTES bytes; on truncation the event flags bit
 * EDR_FLAG_TRUNCATED is set. No wcscpy-family calls.
 */
#include "edrdrv.h"

_Must_inspect_result_
_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

static EDR_QUEUE* g_ProcQueue;

typedef struct _EDR_TLV_BUILDER {
    UCHAR Buf[EDR_SLOT_SIZE - sizeof(EDR_EVENT_HEADER)];
    ULONG Used;
    BOOLEAN Truncated;
} EDR_TLV_BUILDER;

static VOID TlvAppendUtf16(_Inout_ EDR_TLV_BUILDER* B, _In_ USHORT Tag,
                           _In_reads_bytes_opt_(ByteLen) const VOID* Data,
                           _In_ USHORT ByteLen)
{
    EDR_TLV_HEADER tlv;
    ULONG need = (ULONG)sizeof(tlv) + ByteLen;

    if (B->Used + need > sizeof(B->Buf)) {
        B->Truncated = TRUE;
        return;
    }
    tlv.tag = Tag;
    tlv.len = ByteLen;
    memcpy(B->Buf + B->Used, &tlv, sizeof(tlv));
    B->Used += sizeof(tlv);
    if (ByteLen != 0 && Data != NULL) {
        memcpy(B->Buf + B->Used, Data, ByteLen);
        B->Used += ByteLen;
    }
}

/*
 * Copy a UNICODE_STRING into a bounded WCHAR buffer with explicit
 * termination. Returns byte count (excluding terminator); sets *Truncated
 * when the source did not fit.
 */
static USHORT CopyUnicodeBounded(_Out_writes_bytes_(CapBytes) WCHAR* Dst,
                                 _In_ USHORT CapBytes,
                                 _In_ const UNICODE_STRING* Src,
                                 _Out_ BOOLEAN* Truncated)
{
    USHORT bytes = Src->Length;

    if (bytes >= CapBytes) {
        bytes = CapBytes - sizeof(WCHAR);
        *Truncated = TRUE;
    }
    if (bytes != 0 && Src->Buffer != NULL) {
        memcpy(Dst, Src->Buffer, bytes);
    }
    Dst[bytes / sizeof(WCHAR)] = L'\0';
    return bytes;
}

/*
 * Best-effort image path for a process: use the notify-provided
 * FileName when available (create case), else fall back to
 * PsGetProcessImageFileName (short name only).
 */
static VOID GetProcessImage(_In_ HANDLE ProcessId,
                            _In_opt_ PUNICODE_STRING FileName,
                            _Out_writes_bytes_(CapBytes) WCHAR* Dst,
                            _In_ USHORT CapBytes,
                            _Out_ USHORT* OutBytes,
                            _Out_ BOOLEAN* Truncated)
{
    *OutBytes = 0;
    *Truncated = FALSE;
    Dst[0] = L'\0';

    if (FileName != NULL && FileName->Length != 0) {
        *OutBytes = CopyUnicodeBounded(Dst, CapBytes, FileName, Truncated);
        return;
    }

    if (ProcessId != NULL) {
        PEPROCESS process = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
            const UCHAR* shortName = PsGetProcessImageFileName(process);
            if (shortName != NULL) {
                SIZE_T len = 0;
                SIZE_T cap = (CapBytes / sizeof(WCHAR)) - 1;
                while (len < cap && shortName[len] != 0) {
                    Dst[len] = (WCHAR)shortName[len];
                    len++;
                }
                if (shortName[len] != 0) {
                    *Truncated = TRUE;
                }
                Dst[len] = L'\0';
                *OutBytes = (USHORT)(len * sizeof(WCHAR));
            }
            ObDereferenceObject(process);
        }
    }
}

static VOID EdrProcessNotify(_Inout_ PEPROCESS Process,
                             _In_ HANDLE ProcessId,
                             _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    EDR_EVENT_HEADER hdr;
    EDR_TLV_BUILDER tlv;
    WCHAR image[EDR_STR_MAX_BYTES / sizeof(WCHAR)];
    WCHAR parentImage[EDR_STR_MAX_BYTES / sizeof(WCHAR)];
    USHORT imageBytes = 0;
    USHORT parentBytes = 0;
    BOOLEAN truncImage = FALSE;
    BOOLEAN truncParent = FALSE;

    UNREFERENCED_PARAMETER(Process);

    if (g_ProcQueue == NULL ||
        !EdrQueueIsEnabled(g_ProcQueue, EDR_ENABLE_PROCESS)) {
        return;
    }

    memset(&hdr, 0, sizeof(hdr));
    memset(&tlv, 0, sizeof(tlv));
    hdr.magic = EDR_EVENT_MAGIC;
    hdr.version = (unsigned short)EDR_EVENT_VERSION;
    KeQuerySystemTime((PLARGE_INTEGER)&hdr.ts_100ns);
    hdr.pid = (unsigned int)(ULONG_PTR)ProcessId;

    if (CreateInfo != NULL) {
        hdr.type = (unsigned short)EDR_EVT_PROCESS_START;
        hdr.ppid = (unsigned int)(ULONG_PTR)CreateInfo->ParentProcessId;
        /* Command line intentionally not collected in kernel (M2). */
        hdr.flags |= EDR_FLAG_COMMAND_LINE_ABSENT;

        GetProcessImage(ProcessId, (PUNICODE_STRING)CreateInfo->ImageFileName,
                        image, sizeof(image), &imageBytes, &truncImage);
        GetProcessImage(CreateInfo->ParentProcessId, NULL,
                        parentImage, sizeof(parentImage), &parentBytes,
                        &truncParent);
        if (parentBytes != 0) {
            TlvAppendUtf16(&tlv, EDR_TAG_PARENT_IMAGE, parentImage, parentBytes);
        }
    } else {
        hdr.type = (unsigned short)EDR_EVT_PROCESS_STOP;
        GetProcessImage(ProcessId, NULL, image, sizeof(image),
                        &imageBytes, &truncImage);
    }

    if (imageBytes != 0) {
        TlvAppendUtf16(&tlv, EDR_TAG_IMAGE, image, imageBytes);
    }
    if (truncImage || truncParent || tlv.Truncated) {
        hdr.flags |= EDR_FLAG_TRUNCATED;
    }

    EdrQueuePush(g_ProcQueue, &hdr, tlv.Buf, tlv.Used);
}

NTSTATUS EdrProcNotifyRegister(_In_ EDR_QUEUE* Q)
{
    NTSTATUS status;

    g_ProcQueue = Q;
    status = PsSetCreateProcessNotifyRoutineEx(EdrProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        g_ProcQueue = NULL;
    }
    return status;
}

NTSTATUS EdrProcNotifyUnregister(VOID)
{
    NTSTATUS status;

    if (g_ProcQueue == NULL) {
        return STATUS_SUCCESS;
    }
    status = PsSetCreateProcessNotifyRoutineEx(EdrProcessNotify, TRUE);
    if (NT_SUCCESS(status)) {
        g_ProcQueue = NULL; /* only clear ownership after success */
    }
    return status;
}
