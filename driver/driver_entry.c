/*
 * driver_entry.c - DriverEntry / unload topology, CRT intrinsics shims.
 *
 * Topology (PHASE_BC_PLAN.md "Compile-time-exclusive unload ownership"):
 *   - EDR_ENABLE_MINIFILTER == 1 (MINIFILTER/ALL): DriverEntry does not
 *     install a WDM DriverUnload. The minifilter's mandatory
 *     FilterUnloadCallback is the sole whole-driver teardown owner.
 *   - EDR_ENABLE_MINIFILTER == 0 (NONE/WFP): no filter, DriverEntry
 *     installs EdrWdmDriverUnload.
 *
 * Startup runs single-threaded at INITIALIZING:
 *   create unpublished device -> init queue, policy, remove lock ->
 *   register proc/reg -> WFP all-or-nothing -> minifilter register/start ->
 *   RUNNING -> create DOS link -> clear DO_DEVICE_INITIALIZING last.
 * Any failure rolls back in reverse order.
 */
#include "edrdrv.h"

#ifndef EDR_ENABLE_MINIFILTER
#define EDR_ENABLE_MINIFILTER 0
#endif

#ifndef EDR_ENABLE_WFP
#define EDR_ENABLE_WFP 0
#endif

#ifndef EDR_ENABLE_THREAD
#define EDR_ENABLE_THREAD 1
#endif

#ifndef EDR_ENABLE_IMAGE_LOAD
#define EDR_ENABLE_IMAGE_LOAD 1
#endif

#if EDR_ENABLE_MINIFILTER
NTSTATUS EdrMiniFilterStart(_In_ PDRIVER_OBJECT DriverObject,
                            _In_ PEDR_DEVICE_EXTENSION Ext);
NTSTATUS EdrMiniFilterStop(BOOLEAN CalledFromUnload);
#else
NTSTATUS EdrMiniFilterStart(_In_ PDRIVER_OBJECT DriverObject,
                            _In_ PEDR_DEVICE_EXTENSION Ext)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(Ext);
    return STATUS_SUCCESS;
}
NTSTATUS EdrMiniFilterStop(BOOLEAN CalledFromUnload)
{
    UNREFERENCED_PARAMETER(CalledFromUnload);
    return STATUS_SUCCESS;
}
#endif

static DRIVER_UNLOAD EdrWdmDriverUnload;

/*
 * /kernel + /NODEFAULTLIB: the compiler may emit memset/memcpy intrinsics.
 * Provide minimal implementations so linking against ntoskrnl only succeeds.
 */
#pragma function(memset)
void* memset(void* dst, int val, size_t n)
{
    unsigned char* p = (unsigned char*)dst;
    while (n--) {
        *p++ = (unsigned char)val;
    }
    return dst;
}

#pragma function(memcpy)
void* memcpy(void* dst, const void* src, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) {
        *d++ = *s++;
    }
    return dst;
}

volatile LONG EdrLifecycleState = EDR_STATE_INITIALIZING;

static PEDR_DEVICE_EXTENSION g_DeviceExt;

NTSTATUS EdrSetLifecycleState(EDR_LIFETIME_STATE State)
{
    /* Monotonic interlocked write; any reader sees old or new atomically. */
    InterlockedExchange(&EdrLifecycleState, (LONG)State);
    MemoryBarrier();
    return STATUS_SUCCESS;
}

EDR_LIFETIME_STATE EdrGetLifecycleState(void)
{
    return (EDR_LIFETIME_STATE)InterlockedCompareExchange(&EdrLifecycleState,
                                                          0, 0);
}

PEDR_DEVICE_EXTENSION EdrDeviceExtensionFromGlobal(void)
{
    return g_DeviceExt;
}

PDEVICE_OBJECT EdrControlDeviceObject(void)
{
    return g_DeviceExt != NULL ? g_DeviceExt->DeviceObject : NULL;
}

static NTSTATUS EdrStartupReverse(VOID)
{
    NTSTATUS status;

    /* Reverse-order rollback of whatever registered so far (registration
     * order: proc, reg, ob, thread, image). Image remove via
     * PsRemoveLoadImageNotifyRoutine, which also waits for in-flight
     * callbacks before the caller frees the queue. */
#if EDR_ENABLE_IMAGE_LOAD
    EdrImageNotifyStop();
#endif
#if EDR_ENABLE_THREAD
    status = EdrThreadNotifyUnregister();
#endif
    status = EdrObNotifyUnregister();
    status = EdrRegNotifyUnregister();
    status = EdrProcNotifyUnregister();
    (VOID)EdrUnpublishDeviceLink();
    return status;
}

static NTSTATUS EdrDriverEntryCommon(_In_ PDRIVER_OBJECT DriverObject,
                                     _In_opt_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PEDR_DEVICE_EXTENSION ext = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

#if EDR_ENABLE_MINIFILTER
    /* Sole unload owner is the mandatory FilterUnloadCallback. */
    DriverObject->DriverUnload = NULL;
#else
    DriverObject->DriverUnload = EdrWdmDriverUnload;
#endif
    DriverObject->MajorFunction[IRP_MJ_CREATE] = EdrDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = EdrDispatchCleanup;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = EdrDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EdrDispatchDeviceControl;

    status = EdrPolicyInit();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = EdrCreateDevice(DriverObject, &ext);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_DeviceExt = ext;

    status = EdrQueueInit(&ext->Queue);
    if (!NT_SUCCESS(status)) {
        EdrDeleteDevice(DriverObject);
        g_DeviceExt = NULL;
        return status;
    }

    /* Strean: hard failure to place the device unpublished. */
    EdrSetLifecycleState(EDR_STATE_INITIALIZING);

    status = EdrProcNotifyRegister(&ext->Queue);
    if (!NT_SUCCESS(status)) {
        goto Rollback;
    }
    status = EdrRegNotifyRegister(&ext->Queue);
    if (!NT_SUCCESS(status)) {
        goto Rollback;
    }
    status = EdrObNotifyRegister(&ext->Queue);
    if (!NT_SUCCESS(status)) {
        goto Rollback;
    }
#if EDR_ENABLE_THREAD
    status = EdrThreadNotifyRegister(&ext->Queue);
    if (!NT_SUCCESS(status)) {
        goto Rollback;
    }
#endif
#if EDR_ENABLE_IMAGE_LOAD
    status = EdrImageNotifyRegister(&ext->Queue);
    if (!NT_SUCCESS(status)) {
        goto Rollback;
    }
#endif

    status = EdrWfpSkeletonInit(ext->DeviceObject);
    if (!NT_SUCCESS(status)) {
        goto Rollback;
    }
    EdrWfpQueueSet(&ext->Queue);

    status = EdrMiniFilterStart(DriverObject, ext);
    if (!NT_SUCCESS(status)) {
        goto Rollback;
    }

    /* RUNNING before the DOS link; device still unpublished. */
    EdrSetLifecycleState(EDR_STATE_RUNNING);

    status = EdrPublishDeviceLink(ext);
    if (!NT_SUCCESS(status)) {
        EdrSetLifecycleState(EDR_STATE_QUIESCING);
        goto Rollback;
    }

    /* Final publication operation: clear DO_DEVICE_INITIALIZING last. */
    ext->DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;

Rollback:
    (VOID)EdrStartupReverse();
    /* Minifilter rollback unregisters exactly once if registered/started. */
    (VOID)EdrMiniFilterStop(FALSE);
    EdrWfpSkeletonUnload();
    EdrQueueCancelAll(&ext->Queue);
    EdrQueueDestroy(&ext->Queue);
    EdrDeleteDevice(DriverObject);
    g_DeviceExt = NULL;
    return status;
}

#if EDR_ENABLE_MINIFILTER
/* Minifilter module owns whole teardown; see minifilter_skeleton.c. */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    return EdrDriverEntryCommon(DriverObject, RegistryPath);
}
#else
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    return EdrDriverEntryCommon(DriverObject, RegistryPath);
}

static VOID EdrWdmDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    (VOID)EdrCommonTeardown(DriverObject);
}
#endif

/*
 * Shared whole-driver teardown for NONE/WFP (WDM) and reused at the end of
 * the minifilter mandatory unload after FltUnregisterFilter, or by
 * EdrMiniFilterStop(FALSE) on rollback for device/queue teardown only.
 */
NTSTATUS EdrCommonTeardown(_In_ PDRIVER_OBJECT DriverObject)
{
    PEDR_DEVICE_EXTENSION ext = g_DeviceExt;
    NTSTATUS status = STATUS_SUCCESS;

    if (ext == NULL) {
        return STATUS_SUCCESS;
    }

    EdrSetLifecycleState(EDR_STATE_QUIESCING);
    ext->Quiescing = TRUE;
    MemoryBarrier();

    EdrUnpublishDeviceLink();
    ext->Published = FALSE;

    /* Wait up to 5s for open control lifetimes to drain. */
    {
        LARGE_INTEGER due;
        NTSTATUS waitStatus;

        if (InterlockedCompareExchange(&ext->OpenCount, 0, 0) != 0) {
            due.QuadPart = -5LL * 1000LL * 1000LL * 10LL; /* 5s, 100ns */
            waitStatus = KeWaitForSingleObject(&ext->OpenCountZeroEvent,
                                               Executive, KernelMode, FALSE,
                                               &due);
            if (waitStatus == STATUS_TIMEOUT &&
                InterlockedCompareExchange(&ext->OpenCount, 0, 0) != 0) {
                /* Noncooperative client: do not destroy state. */
                EdrSetLifecycleState(EDR_STATE_FAIL_STOP);
                return STATUS_CANCELLED;
            }
        }
    }

    /* Drain short-lived dispatch/remove-lock acquisitions. */
    IoReleaseRemoveLockAndWait(&ext->RemoveLock, NULL);

    /* Unregister every producer before destroying the queue so no callback
     * (WFP classify at DISPATCH_LEVEL, proc/reg/thread notify) can still
     * reach the queue storage that EdrQueueDestroy frees. Same order as
     * Rollback. The image notify callback is removed via
     * EdrImageNotifyStop() (PsRemoveLoadImageNotifyRoutine), which removes
     * it from the kernel's notify list and waits for any in-flight
     * invocation to exit, so after it returns no callback body can run
     * against the queue storage freed below by EdrQueueDestroy. */
#if EDR_ENABLE_IMAGE_LOAD
    EdrImageNotifyStop();
#endif
#if EDR_ENABLE_THREAD
    status = EdrThreadNotifyUnregister();
#endif
    status = EdrObNotifyUnregister();
    status = EdrRegNotifyUnregister();
    status = EdrProcNotifyUnregister();

    EdrWfpSkeletonUnload();

    EdrQueueCancelAll(&ext->Queue);
    EdrQueueDestroy(&ext->Queue);

    EdrPolicyDestroy();
    EdrDeleteDevice(DriverObject);
    g_DeviceExt = NULL;
    EdrSetLifecycleState(EDR_STATE_STOPPED);
    return status;
}