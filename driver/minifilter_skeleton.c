/*
 * minifilter_skeleton.c - Minifilter for file telemetry and BLOCK
 * enforcement on normalized NT-path prefixes.
 *
 * Compiled in only when EDR_ENABLE_MINIFILTER is defined to 1.
 * When disabled, init/unload are inert stubs.
 *
 * Enforcement (PHASE_BC_PLAN.md):
 *   - Pre-create enforces bounded case-insensitive normalized NT-path
 *     prefixes for SUPERSEDE, CREATE, OPEN_IF, and OVERWRITE_IF; a BLOCK
 *     match completes ACCESS_DENIED and emits a best-effort EDR_EVT_BLOCK
 *     audit (FILE_PATH + RULE_INDEX TLVs). No post callback is registered
 *     for a disallowed create.
 *   - Pre-set validates the disposition class/buffer and enforces the same
 *     table for legacy FileDispositionInformation (DeleteFile) and
 *     FileDispositionInformationEx (FILE_DISPOSITION_DELETE).
 *   - Telemetry: post-success CREATE (FILE_CREATED/FILE_SUPERSEDED),
 *     accepted-delete intent on post-success set-information.
 *
 * File path resolution uses FltGetFileNameInformation (NameNormalized)
 * bounded to EDR_STR_MAX_BYTES. No post-name allocation survives the
 * callback; everything is copied into a stack/local buffer then released.
 *
 * Include order: fltkernel.h (which pulls in ntifs.h) MUST come before
 * edrdrv.h (which includes ntddk.h), because ntifs.h and ntddk.h have
 * conflicting opaque-type definitions (PEPROCESS, PETHREAD).
 */
#ifndef EDR_ENABLE_MINIFILTER
#define EDR_ENABLE_MINIFILTER 0
#endif

#if EDR_ENABLE_MINIFILTER
#include <fltkernel.h>
#define _NTDDK_H_  /* prevent ntddk.h from being included by edrdrv.h */
#endif

#include "edrdrv.h"

#if EDR_ENABLE_MINIFILTER

static PFLT_FILTER g_EdrFilter;
static EDR_QUEUE* g_MiniQueue;
static PDRIVER_OBJECT g_EdrDriverObject;

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

static VOID TlvAppendU32(_Inout_ EDR_TLV_BUILDER* B, _In_ USHORT Tag,
                         _In_ ULONG Value)
{
    ULONG le = Value; /* little-endian on wire, as native on x64 */
    TlvAppendUtf16(B, Tag, &le, sizeof(le));
}

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
 * Best-effort normalized file path. Returns byte count (excl. terminator).
 * Caller must release nameInfo with FltReleaseFileNameInformation.
 */
static USHORT GetFilePathNormalized(_In_ PFLT_CALLBACK_DATA Data,
                                     _Out_writes_bytes_(CapBytes) WCHAR* Dst,
                                     _In_ USHORT CapBytes,
                                     _Out_ BOOLEAN* Truncated)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    UNICODE_STRING src;

    *Truncated = FALSE;
    Dst[0] = L'\0';

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED |
                                        FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return 0;
    }
    src.Buffer = nameInfo->Name.Buffer;
    src.Length = nameInfo->Name.Length;
    src.MaximumLength = nameInfo->Name.MaximumLength;

    USHORT outBytes = CopyUnicodeBounded(Dst, CapBytes, &src, Truncated);
    FltReleaseFileNameInformation(nameInfo);
    return outBytes;
}

/*
 * Best-effort BLOCK audit: EDR_EVT_BLOCK with FILE_PATH + RULE_INDEX TLVs.
 * Gated on the queue's EDR_ENABLE_BLOCK bit (mirrored from policy by ioctl
 * on successful replace; off at boot => fail-open before first push).
 */
static VOID EmitBlockFileEvent(_In_reads_bytes_(PathBytes) const WCHAR* Path,
                               _In_ USHORT PathBytes, _In_ ULONG RuleIndex)
{
    EDR_EVENT_HEADER hdr;
    EDR_TLV_BUILDER tlv;

    if (g_MiniQueue == NULL ||
        !EdrQueueIsEnabled(g_MiniQueue, EDR_ENABLE_BLOCK)) {
        return;
    }
    if (PathBytes == 0 || Path == NULL) {
        return;
    }

    memset(&hdr, 0, sizeof(hdr));
    memset(&tlv, 0, sizeof(tlv));
    hdr.magic = EDR_EVENT_MAGIC;
    hdr.version = (unsigned short)EDR_EVENT_VERSION;
    hdr.type = EDR_EVT_BLOCK;
    KeQuerySystemTime((PLARGE_INTEGER)&hdr.ts_100ns);
    hdr.pid = (unsigned int)(ULONG_PTR)PsGetCurrentProcessId();

    TlvAppendUtf16(&tlv, EDR_TAG_FILE_PATH, Path, PathBytes);
    TlvAppendU32(&tlv, EDR_TAG_RULE_INDEX, RuleIndex);

    if (tlv.Truncated) {
        hdr.flags |= EDR_FLAG_TRUNCATED;
    }

    EdrQueuePush(g_MiniQueue, &hdr, tlv.Buf, tlv.Used);
}

static VOID EmitFileEvent(_In_ USHORT EventType,
                           _In_reads_bytes_(PathBytes) const WCHAR* Path,
                           _In_ USHORT PathBytes)
{
    EDR_EVENT_HEADER hdr;
    EDR_TLV_BUILDER tlv;
    BOOLEAN truncPath = FALSE;

    if (g_MiniQueue == NULL ||
        !EdrQueueIsEnabled(g_MiniQueue, EDR_ENABLE_FILE)) {
        return;
    }
    if (PathBytes == 0 || Path == NULL) {
        return;
    }

    memset(&hdr, 0, sizeof(hdr));
    memset(&tlv, 0, sizeof(tlv));
    hdr.magic = EDR_EVENT_MAGIC;
    hdr.version = (unsigned short)EDR_EVENT_VERSION;
    hdr.type = EventType;
    KeQuerySystemTime((PLARGE_INTEGER)&hdr.ts_100ns);
    hdr.pid = (unsigned int)(ULONG_PTR)PsGetCurrentProcessId();

    TlvAppendUtf16(&tlv, EDR_TAG_FILE_PATH, Path, PathBytes);

    if (truncPath || tlv.Truncated) {
        hdr.flags |= EDR_FLAG_TRUNCATED;
    }

    EdrQueuePush(g_MiniQueue, &hdr, tlv.Buf, tlv.Used);
}

/*
 * Emit a file rename event with the old path as FILE_PATH and the old path
 * also duplicated as OLD_FILE_PATH for context.
 */
static VOID EmitRenameEvent(_In_reads_bytes_(OldPathBytes) const WCHAR* OldPath,
                            _In_ USHORT OldPathBytes)
{
    EDR_EVENT_HEADER hdr;
    EDR_TLV_BUILDER tlv;
    BOOLEAN truncPath = FALSE;

    if (g_MiniQueue == NULL ||
        !EdrQueueIsEnabled(g_MiniQueue, EDR_ENABLE_FILE)) {
        return;
    }
    if (OldPathBytes == 0 || OldPath == NULL) {
        return;
    }

    memset(&hdr, 0, sizeof(hdr));
    memset(&tlv, 0, sizeof(tlv));
    hdr.magic = EDR_EVENT_MAGIC;
    hdr.version = (unsigned short)EDR_EVENT_VERSION;
    hdr.type = (unsigned short)EDR_EVT_FILE_RENAME;
    KeQuerySystemTime((PLARGE_INTEGER)&hdr.ts_100ns);
    hdr.pid = (unsigned int)(ULONG_PTR)PsGetCurrentProcessId();

    /* Emit the old path as FILE_PATH (for backward compat with rules). */
    TlvAppendUtf16(&tlv, EDR_TAG_FILE_PATH, OldPath, OldPathBytes);
    /* Also emit as OLD_FILE_PATH for explicit rename rules. */
    TlvAppendUtf16(&tlv, EDR_TAG_OLD_FILE_PATH, OldPath, OldPathBytes);

    if (truncPath || tlv.Truncated) {
        hdr.flags |= EDR_FLAG_TRUNCATED;
    }

    EdrQueuePush(g_MiniQueue, &hdr, tlv.Buf, tlv.Used);
}

/*
 * Pre-create: enforce the file block table, and for allowed creates capture
 * the filename for later post-success processing. We allocate a small
 * context to pass the path to the post-op callback because
 * FltGetFileNameInformation cannot be called in the post-op path for
 * certain operations (e.g., file has been renamed/closed).
 */
/*
 * Context types for post-op completion. A discriminator field at offset 0
 * lets the shared post-op handler distinguish create/delete from rename.
 */
#define EDR_MINI_CTX_CREATE 0x43545245u /* 'ERTC' */
#define EDR_MINI_CTX_RENAME 0x4e4e4552u /* 'RENN' */

typedef struct _EDR_MINI_CREATE_CTX {
    ULONG CtxType; /* EDR_MINI_CTX_CREATE */
    WCHAR Path[EDR_STR_MAX_BYTES / sizeof(WCHAR)];
    USHORT PathBytes;
    BOOLEAN Truncated;
} EDR_MINI_CREATE_CTX;

static FLT_PREOP_CALLBACK_STATUS
EdrMiniPreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
                 _In_ PCFLT_RELATED_OBJECTS FltObjects,
                 _Outptr_result_maybenull_ PVOID* CompletionContext)
{
    EDR_MINI_CREATE_CTX* ctx;
    ULONG disposition;
    ULONG ruleIndex = 0;
    WCHAR path[EDR_STR_MAX_BYTES / sizeof(WCHAR)];
    USHORT pathBytes;
    BOOLEAN truncated = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    disposition = Data->Iopb->Parameters.Create.Options & 0xF;
    if (disposition != FILE_SUPERSEDE && disposition != FILE_CREATE &&
        disposition != FILE_OPEN_IF && disposition != FILE_OVERWRITE_IF) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (g_MiniQueue == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pathBytes = GetFilePathNormalized(Data, path, sizeof(path), &truncated);

    /* Enforce BLOCK before any telemetry when the queue says BLOCK on. */
    if (EdrQueueIsEnabled(g_MiniQueue, EDR_ENABLE_BLOCK) && pathBytes != 0) {
        if (EdrPolicyMatchFile(path, pathBytes / sizeof(WCHAR),
                               &ruleIndex)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            EmitBlockFileEvent(path, pathBytes, ruleIndex);
            return FLT_PREOP_DISALLOW_FSFILTER_IO;
        }
    }

    if (!EdrQueueIsEnabled(g_MiniQueue, EDR_ENABLE_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /*
     * Allocate context in nonpaged pool (must survive to post-op).
     * On allocation failure, skip telemetry gracefully.
     */
    ctx = (EDR_MINI_CREATE_CTX*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(EDR_MINI_CREATE_CTX), EDR_POOL_TAG);
    if (ctx == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    memset(ctx, 0, sizeof(EDR_MINI_CREATE_CTX));
    ctx->CtxType = EDR_MINI_CTX_CREATE;

    ctx->PathBytes = GetFilePathNormalized(Data, ctx->Path,
                                            sizeof(ctx->Path),
                                            &ctx->Truncated);

    *CompletionContext = ctx;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS
EdrMiniPostCreate(_Inout_ PFLT_CALLBACK_DATA Data,
                  _In_ PCFLT_RELATED_OBJECTS FltObjects,
                  _In_opt_ PVOID CompletionContext,
                  _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    EDR_MINI_CREATE_CTX* ctx = (EDR_MINI_CREATE_CTX*)CompletionContext;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (ctx == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Only emit telemetry on NT-success and actual create/supersede. */
    if (NT_SUCCESS(Data->IoStatus.Status) && ctx->PathBytes != 0) {
        if (Data->IoStatus.Information == FILE_CREATED ||
            Data->IoStatus.Information == FILE_SUPERSEDED) {
            EmitFileEvent((unsigned short)EDR_EVT_FILE_CREATE,
                          ctx->Path, ctx->PathBytes);
        }
    }

    ExFreePoolWithTag(ctx, EDR_POOL_TAG);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/*
 * Rename context: captures the old normalized path for post-op emission.
 * The new file name is not captured (it is available in the pre-op buffer
 * but the post-op may not have it safely; we emit the old path only).
 */
typedef struct _EDR_MINI_RENAME_CTX {
    ULONG CtxType; /* EDR_MINI_CTX_RENAME */
    WCHAR OldPath[EDR_STR_MAX_BYTES / sizeof(WCHAR)];
    USHORT OldPathBytes;
    BOOLEAN Truncated;
} EDR_MINI_RENAME_CTX;

/*
 * Pre-set-information: validate and enforce delete dispositions, and
 * capture file rename operations.
 */
static FLT_PREOP_CALLBACK_STATUS
EdrMiniPreSetInfo(_Inout_ PFLT_CALLBACK_DATA Data,
                  _In_ PCFLT_RELATED_OBJECTS FltObjects,
                  _Outptr_result_maybenull_ PVOID* CompletionContext)
{
    PFILE_DISPOSITION_INFORMATION dispInfo;
    EDR_MINI_CREATE_CTX* ctx;
    BOOLEAN deleteRequested = FALSE;
    BOOLEAN isEx = FALSE;
    WCHAR path[EDR_STR_MAX_BYTES / sizeof(WCHAR)];
    USHORT pathBytes;
    BOOLEAN truncated = FALSE;
    ULONG ruleIndex = 0;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (Data->Iopb->MajorFunction != IRP_MJ_SET_INFORMATION) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass ==
        FileDispositionInformation) {
        dispInfo = (PFILE_DISPOSITION_INFORMATION)
            Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (dispInfo == NULL ||
            Data->Iopb->Parameters.SetFileInformation.Length <
                sizeof(FILE_DISPOSITION_INFORMATION)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        deleteRequested = dispInfo->DeleteFile;
    } else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass ==
               FileDispositionInformationEx) {
        PFILE_DISPOSITION_INFORMATION_EX dispEx;
        isEx = TRUE;
        dispEx = (PFILE_DISPOSITION_INFORMATION_EX)
            Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (dispEx == NULL ||
            Data->Iopb->Parameters.SetFileInformation.Length <
                sizeof(FILE_DISPOSITION_INFORMATION_EX)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        deleteRequested = (dispEx->Flags & FILE_DISPOSITION_DELETE) != 0;
    } else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass ==
               FileRenameInformation) {
        /* File rename: capture the old path for post-op telemetry. */
        if (g_MiniQueue == NULL ||
            !EdrQueueIsEnabled(g_MiniQueue, EDR_ENABLE_FILE)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        EDR_MINI_RENAME_CTX* rctx = (EDR_MINI_RENAME_CTX*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(EDR_MINI_RENAME_CTX), EDR_POOL_TAG);
        if (rctx == NULL) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        memset(rctx, 0, sizeof(EDR_MINI_RENAME_CTX));
        rctx->CtxType = EDR_MINI_CTX_RENAME;
        rctx->OldPathBytes = GetFilePathNormalized(Data, rctx->OldPath,
                                                     sizeof(rctx->OldPath),
                                                     &rctx->Truncated);
        *CompletionContext = rctx;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    } else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass ==
               FileRenameInformationEx) {
        /* Extended rename: same handling as basic rename. */
        if (g_MiniQueue == NULL ||
            !EdrQueueIsEnabled(g_MiniQueue, EDR_ENABLE_FILE)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        EDR_MINI_RENAME_CTX* rctx = (EDR_MINI_RENAME_CTX*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(EDR_MINI_RENAME_CTX), EDR_POOL_TAG);
        if (rctx == NULL) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        memset(rctx, 0, sizeof(EDR_MINI_RENAME_CTX));
        rctx->CtxType = EDR_MINI_CTX_RENAME;
        rctx->OldPathBytes = GetFilePathNormalized(Data, rctx->OldPath,
                                                     sizeof(rctx->OldPath),
                                                     &rctx->Truncated);
        *CompletionContext = rctx;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    } else {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!deleteRequested) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (g_MiniQueue == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pathBytes = GetFilePathNormalized(Data, path, sizeof(path), &truncated);

    if (EdrQueueIsEnabled(g_MiniQueue, EDR_ENABLE_BLOCK) && pathBytes != 0) {
        if (EdrPolicyMatchFile(path, pathBytes / sizeof(WCHAR),
                               &ruleIndex)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            EmitBlockFileEvent(path, pathBytes, ruleIndex);
            return FLT_PREOP_DISALLOW_FSFILTER_IO;
        }
    }

    if (!EdrQueueIsEnabled(g_MiniQueue, EDR_ENABLE_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ctx = (EDR_MINI_CREATE_CTX*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(EDR_MINI_CREATE_CTX), EDR_POOL_TAG);
    if (ctx == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    memset(ctx, 0, sizeof(EDR_MINI_CREATE_CTX));
    ctx->CtxType = EDR_MINI_CTX_CREATE;

    ctx->PathBytes = GetFilePathNormalized(Data, ctx->Path,
                                            sizeof(ctx->Path),
                                            &ctx->Truncated);

    *CompletionContext = ctx;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS
EdrMiniPostSetInfo(_Inout_ PFLT_CALLBACK_DATA Data,
                   _In_ PCFLT_RELATED_OBJECTS FltObjects,
                   _In_opt_ PVOID CompletionContext,
                   _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    EDR_MINI_CREATE_CTX* ctx = (EDR_MINI_CREATE_CTX*)CompletionContext;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (ctx == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (ctx->CtxType == EDR_MINI_CTX_RENAME) {
        /* Rename post-op: emit FILE_RENAME event on success. */
        if (NT_SUCCESS(Data->IoStatus.Status) && ctx->PathBytes != 0) {
            EmitRenameEvent(ctx->Path, ctx->PathBytes);
        }
    } else {
        /* Delete post-op: emits accepted-delete intent only on success. */
        if (NT_SUCCESS(Data->IoStatus.Status) && ctx->PathBytes != 0) {
            EmitFileEvent((unsigned short)EDR_EVT_FILE_DELETE,
                          ctx->Path, ctx->PathBytes);
        }
    }

    ExFreePoolWithTag(ctx, EDR_POOL_TAG);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/*
 * Mandatory unload owner for the MINIFILTER/ALL binaries. The filter
 * manager always calls this on unload; the routine completes the
 * whole-driver teardown (queue, policy, device) after FltUnregisterFilter
 * has waited for every outstanding operation to drain.
 */
static NTSTATUS EdrMiniUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_EdrFilter != NULL) {
        FltUnregisterFilter(g_EdrFilter);
        g_EdrFilter = NULL;
    }
    g_MiniQueue = NULL;
    if (g_EdrDriverObject != NULL) {
        return EdrCommonTeardown(g_EdrDriverObject);
    }
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE, 0, EdrMiniPreCreate, EdrMiniPostCreate },
    { IRP_MJ_SET_INFORMATION, 0, EdrMiniPreSetInfo, EdrMiniPostSetInfo },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL,
    g_Callbacks, EdrMiniUnload, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS EdrMiniFilterStart(_In_ PDRIVER_OBJECT DriverObject,
                            _In_ PEDR_DEVICE_EXTENSION Ext)
{
    NTSTATUS status;

    g_MiniQueue = &Ext->Queue;
    g_EdrDriverObject = DriverObject;
    status = FltRegisterFilter(DriverObject, &g_FilterRegistration,
                               &g_EdrFilter);
    if (!NT_SUCCESS(status)) {
        g_MiniQueue = NULL;
        g_EdrDriverObject = NULL;
        return status;
    }

    status = FltStartFiltering(g_EdrFilter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_EdrFilter);
        g_EdrFilter = NULL;
        g_MiniQueue = NULL;
        g_EdrDriverObject = NULL;
    }
    return status;
}

/*
 * Startup-rollback helper. CalledFromUnload=FALSE: unregister exactly once
 * if we registered/started (DriverEntry rollback). CalledFromUnload=TRUE is
 * unused in this binary; the mandatory FilterUnloadCallback (EdrMiniUnload)
 * owns whole teardown.
 */
NTSTATUS EdrMiniFilterStop(_In_ BOOLEAN CalledFromUnload)
{
    UNREFERENCED_PARAMETER(CalledFromUnload);

    if (g_EdrFilter != NULL) {
        FltUnregisterFilter(g_EdrFilter);
        g_EdrFilter = NULL;
    }
    g_MiniQueue = NULL;
    g_EdrDriverObject = NULL;
    return STATUS_SUCCESS;
}

#else /* EDR_ENABLE_MINIFILTER == 0 */

/* EdrMiniFilterStart/EdrMiniFilterStop stubs are provided by
 * driver_entry.c in this configuration; this module contributes nothing. */

#endif /* EDR_ENABLE_MINIFILTER */
