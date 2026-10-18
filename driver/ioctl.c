/*
 * ioctl.c - IRP_MJ_CREATE / CLEANUP / CLOSE / DEVICE_CONTROL dispatch.
 *
 * Lifecycle (PHASE_BC_PLAN.md "Device, queue, and callback ownership"):
 *   - Every dispatch acquires one short-lived IO_REMOVE_LOCK reference
 *     before touching the extension and releases it exactly once after the
 *     final extension access.
 *   - CREATE succeeds only when lifecycle == RUNNING, the device is
 *     published, and quiescing is false. A successful CREATE owns one
 *     long-lived control-file lifetime (marked on the FILE_OBJECT);
 *     IRP_MJ_CLEANUP releases it exactly once. CLOSE never releases.
 *   - IOCTL_EDR_SET_POLICY validates the exact whole table and publishes
 *     atomically; any malformed field rejects the entire update and the
 *     committed generation stays unchanged. FETCH is unchanged.
 */
#include "edrdrv.h"

static NTSTATUS EdrDispatchCreateLocked(_In_ PEDR_DEVICE_EXTENSION Ext,
                                        _In_ PIO_STACK_LOCATION Stack,
                                        _Inout_ PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (EdrGetLifecycleState() != EDR_STATE_RUNNING ||
        !Ext->Published || Ext->Quiescing) {
        status = STATUS_DEVICE_NOT_READY;
    } else if (!EdrDeviceOpenLifetimeAcquire(Ext, Stack->FileObject)) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS EdrDispatchCloseLocked(_In_ PEDR_DEVICE_EXTENSION Ext,
                                       _In_ PIO_STACK_LOCATION Stack,
                                       _Inout_ PIRP Irp)
{
    /* CLOSE performs no lifetime release; IRP_MJ_CLEANUP did exactly once. */
    UNREFERENCED_PARAMETER(Ext);
    UNREFERENCED_PARAMETER(Stack);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS EdrDispatchCleanupLocked(_In_ PEDR_DEVICE_EXTENSION Ext,
                                         _In_ PIO_STACK_LOCATION Stack,
                                         _Inout_ PIRP Irp)
{
    EdrDeviceOpenLifetimeRelease(Ext, Stack->FileObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS EdrDispatchWithRemoveLock(
    _In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp,
    _In_ NTSTATUS (*Handler)(_In_ PEDR_DEVICE_EXTENSION Ext,
                             _In_ PIO_STACK_LOCATION Stack, _Inout_ PIRP Irp))
{
    PEDR_DEVICE_EXTENSION ext;
    NTSTATUS status;

    ext = (PEDR_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (ext == NULL) {
        Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DEVICE_NOT_READY;
    }
    status = IoAcquireRemoveLock(&ext->RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }
    status = Handler(ext, IoGetCurrentIrpStackLocation(Irp), Irp);
    IoReleaseRemoveLock(&ext->RemoveLock, Irp);
    return status;
}

NTSTATUS EdrDispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject,
                                _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    if (stack->MajorFunction == IRP_MJ_CREATE) {
        return EdrDispatchWithRemoveLock(DeviceObject, Irp,
                                         EdrDispatchCreateLocked);
    }
    return EdrDispatchWithRemoveLock(DeviceObject, Irp,
                                     EdrDispatchCloseLocked);
}

NTSTATUS EdrDispatchCleanup(_In_ PDEVICE_OBJECT DeviceObject,
                            _Inout_ PIRP Irp)
{
    return EdrDispatchWithRemoveLock(DeviceObject, Irp,
                                     EdrDispatchCleanupLocked);
}

NTSTATUS EdrDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject,
                                  _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    PEDR_DEVICE_EXTENSION ext;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;
    ULONG code;

    ext = (PEDR_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    stack = IoGetCurrentIrpStackLocation(Irp);
    code = stack->Parameters.DeviceIoControl.IoControlCode;

    status = IoAcquireRemoveLock(&ext->RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    switch (code) {
    case IOCTL_EDR_FETCH_EVENT:
        if (Irp->AssociatedIrp.SystemBuffer == NULL ||
            stack->Parameters.DeviceIoControl.OutputBufferLength == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        /* May complete inside or pend. */
        status = EdrQueueSubmitFetch(&ext->Queue, Irp);
        IoReleaseRemoveLock(&ext->RemoveLock, Irp);
        return status;

    case IOCTL_EDR_SET_POLICY: {
        const VOID* table = Irp->AssociatedIrp.SystemBuffer;
        ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

        if (EdrGetLifecycleState() != EDR_STATE_RUNNING) {
            status = STATUS_DEVICE_NOT_READY;
        } else if (table == NULL || size != sizeof(EDR_POLICY_V1)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            status = EdrPolicyReplace(table, size);
            if (NT_SUCCESS(status)) {
                /* Mirror the committed generation's bits into the queue
                 * mask (ioctl owns ConfigMask; policy.c never does). */
                ext->Queue.ConfigMask = EdrPolicyGetEnableMask();
            }
        }
        break;
    }

    case IOCTL_EDR_KILL_PROCESS: {
        const VOID* input = Irp->AssociatedIrp.SystemBuffer;
        ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;
        UINT32 pid = 0;

        if (EdrGetLifecycleState() != EDR_STATE_RUNNING) {
            status = STATUS_DEVICE_NOT_READY;
        } else if (!EdrDecodeKillProcessRequest(input, size, &pid)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            status = EdrKillProcessForResponse(
                (HANDLE)(ULONG_PTR)pid,
                PsGetCurrentProcessId());
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    IoReleaseRemoveLock(&ext->RemoveLock, Irp);
    return status;
}
