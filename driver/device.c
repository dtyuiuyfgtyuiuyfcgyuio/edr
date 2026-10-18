/*
 * device.c - Secured device object + symbolic link + control-file lifetime.
 *
 * SDDL "D:P(A;;GA;;;SY)(A;;GA;;;BA)": only LocalSystem and Builtin
 * Administrators may open the device (generic-all). No Everyone access.
 *
 * Publication order (PHASE_BC_PLAN.md "Device, queue, and callback
 * ownership"): the device is created with DO_DEVICE_INITIALIZING still set
 * and NO DOS link; the link is created only after RUNNING, and
 * DO_DEVICE_INITIALIZING is cleared last. CREATE rejects QUIESCING.
 *
 * Control-file lifetime: every successful CREATE owns one long-lived
 * lifetime, marked on the FILE_OBJECT (driver-owned FsContext sentinel) and
 * counted in OpenCount. IRP_MJ_CLEANUP releases it exactly once; CLOSE
 * never does. OpenCountZeroEvent is signaled iff the count is zero.
 */
#include "edrdrv.h"

#include <wdmsec.h> /* IoCreateDeviceSecure (link wdmsec.lib) */

static const WCHAR EdrSddl[] =
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";

#define EDR_FILE_SENTINEL ((PVOID)(ULONG_PTR)0xEDD1CE71)

NTSTATUS EdrCreateDevice(_In_ PDRIVER_OBJECT DriverObject,
                         _Outptr_ PEDR_DEVICE_EXTENSION* Ext)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING sddl;
    PDEVICE_OBJECT deviceObject = NULL;
    PEDR_DEVICE_EXTENSION ext;

    *Ext = NULL;
    RtlInitUnicodeString(&deviceName, EDR_DEVICE_NAME_W);
    RtlInitUnicodeString(&sddl, EdrSddl);

    status = IoCreateDeviceSecure(DriverObject,
                                  sizeof(EDR_DEVICE_EXTENSION),
                                  &deviceName,
                                  FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,
                                  &sddl,
                                  NULL,
                                  &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* DO_DEVICE_INITIALIZING remains set until final publication. */
    deviceObject->Flags |= DO_BUFFERED_IO;

    ext = (PEDR_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    ext->DeviceObject = deviceObject;
    ext->Published = FALSE;
    ext->Quiescing = FALSE;
    ext->OpenCount = 0;
    IoInitializeRemoveLock(&ext->RemoveLock, EDR_POOL_TAG, 1, 0);
    KeInitializeEvent(&ext->OpenCountZeroEvent, NotificationEvent, TRUE);

    *Ext = ext;
    return STATUS_SUCCESS;
}

NTSTATUS EdrPublishDeviceLink(_In_ PEDR_DEVICE_EXTENSION Ext)
{
    UNICODE_STRING symLink;
    UNICODE_STRING deviceName;
    NTSTATUS status;

    if (Ext == NULL || Ext->Published) {
        return STATUS_SUCCESS;
    }
    RtlInitUnicodeString(&symLink, EDR_SYMLINK_NAME_W);
    RtlInitUnicodeString(&deviceName, EDR_DEVICE_NAME_W);
    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (NT_SUCCESS(status)) {
        Ext->Published = TRUE;
    }
    return status;
}

VOID EdrUnpublishDeviceLink(VOID)
{
    UNICODE_STRING symLink;

    RtlInitUnicodeString(&symLink, EDR_SYMLINK_NAME_W);
    IoDeleteSymbolicLink(&symLink);
}

BOOLEAN EdrIsDevicePublished(VOID)
{
    /* The single device is reachable through the driver's DeviceObject. */
    return TRUE;
}

/*
 * Open-lifetime acquire. Called by IRP_MJ_CREATE after the IRP passed the
 * RUNNING/published/quiescing gate, while holding the RemoveLock short-lived
 * acquisition. Marks the file object and increments OpenCount; clears
 * OpenCountZeroEvent on the zero-to-one transition. Returns FALSE if the
 * caller must not complete CREATE successfully (never happens here, but the
 * contract is explicit).
 */
static BOOLEAN EdrDeviceOpenLifetimeAcquireLocked(
    _In_ PEDR_DEVICE_EXTENSION Ext, _In_ PFILE_OBJECT FileObject)
{
    if (FileObject->FsContext == EDR_FILE_SENTINEL) {
        return TRUE; /* already counted (defense; CREATE runs once) */
    }
    if (InterlockedIncrement(&Ext->OpenCount) == 1) {
        KeClearEvent(&Ext->OpenCountZeroEvent);
    }
    FileObject->FsContext = EDR_FILE_SENTINEL;
    return TRUE;
}

NTSTATUS EdrDeviceOpenLifetimeAcquire(_In_ PEDR_DEVICE_EXTENSION Ext,
                                      _In_ PFILE_OBJECT FileObject)
{
    if (!EdrDeviceOpenLifetimeAcquireLocked(Ext, FileObject)) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    return STATUS_SUCCESS;
}

VOID EdrDeviceOpenLifetimeRelease(_In_ PEDR_DEVICE_EXTENSION Ext,
                                  _In_ PFILE_OBJECT FileObject)
{
    if (FileObject->FsContext != EDR_FILE_SENTINEL) {
        return; /* no lifetime owned by this file object */
    }
    FileObject->FsContext = NULL;
    if (InterlockedDecrement(&Ext->OpenCount) == 0) {
        KeSetEvent(&Ext->OpenCountZeroEvent, IO_NO_INCREMENT, FALSE);
    }
}

VOID EdrDeleteDevice(_In_ PDRIVER_OBJECT DriverObject)
{
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}