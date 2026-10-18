/*
 * edrdrv.h - Internal driver-wide declarations. Pure C, kernel only.
 * No KMDF: this driver is a plain WDM-style NT driver on ntddk.h.
 */
#ifndef EDRDRV_H
#define EDRDRV_H

#include <ntddk.h>
#include "edr_event.h"
#include "edr_ioctl.h"

#define EDR_POOL_TAG 'vrde'

/* Queue geometry: fixed-size slots in a preallocated nonpaged ring. */
#define EDR_SLOT_SIZE       2048u   /* max bytes for one serialized event */
#define EDR_QUEUE_CAPACITY  4096u   /* slots; full ring = 8MB nonpaged */
#define EDR_STR_MAX_BYTES   512u    /* kernel string copy bound (bytes) */

typedef struct _EDR_PENDING_IRP {
    LIST_ENTRY Link;
    PIRP Irp;
} EDR_PENDING_IRP;

typedef struct _EDR_QUEUE {
    KSPIN_LOCK Lock;
    PUCHAR Slots;            /* EDR_QUEUE_CAPACITY * EDR_SLOT_SIZE bytes */
    ULONG Head;              /* oldest */
    ULONG Count;
    volatile LONG Dropped;   /* events overwritten because ring was full */
    ULONG StatsPending;      /* non-zero: a STATS event should be emitted */
    LIST_ENTRY PendingIrps;  /* EDR_PENDING_IRP list, protected by Lock */
    ULONG ConfigMask;        /* EDR_ENABLE_* bits */
    ULONG Stopping;          /* protected by Lock; rejects new FETCH IRPs */
    volatile LONG ActiveCancelCallbacks;
    KEVENT NoActiveCancelCallbacks; /* signaled iff active count is zero */
} EDR_QUEUE;

typedef struct _EDR_DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
    EDR_QUEUE Queue;
    IO_REMOVE_LOCK RemoveLock;
    volatile LONG OpenCount;       /* long-lived control-file lifetimes */
    KEVENT OpenCountZeroEvent;     /* signaled iff OpenCount == 0 */
    volatile BOOLEAN Quiescing;    /* reject new CREATE when set */
    BOOLEAN Published;             /* DOS symlink created */
} EDR_DEVICE_EXTENSION, *PEDR_DEVICE_EXTENSION;

/* Driver lifecycle states (single owner per binary, no cross-wait). */
typedef enum _EDR_LIFETIME_STATE {
    EDR_STATE_INITIALIZING = 0,
    EDR_STATE_RUNNING,
    EDR_STATE_QUIESCING,
    EDR_STATE_STOPPED,
    EDR_STATE_FAIL_STOP
} EDR_LIFETIME_STATE;

/* Lifecycle globals (single unload owner per binary). */
volatile LONG EdrLifecycleState;   /* EDR_LIFETIME_STATE, interlocked */
NTSTATUS EdrSetLifecycleState(EDR_LIFETIME_STATE State);
EDR_LIFETIME_STATE EdrGetLifecycleState(void);

/* Device linkage (only one control device exists). */
PEDR_DEVICE_EXTENSION EdrDeviceExtensionFromGlobal(void);
PDEVICE_OBJECT EdrControlDeviceObject(void);

/* Common whole-driver teardown (NONE/WFP: WDM unload; MINIFILTER/ALL:
 * mandatory FilterUnloadCallback). Returns the status to report.
 * Drivers without a minifilter install EdrWdmDriverUnload. */
NTSTATUS EdrCommonTeardown(_In_ PDRIVER_OBJECT DriverObject);

/* device.c */
NTSTATUS EdrCreateDevice(_In_ PDRIVER_OBJECT DriverObject,
                         _Outptr_ PEDR_DEVICE_EXTENSION* Ext);
NTSTATUS EdrPublishDeviceLink(_In_ PEDR_DEVICE_EXTENSION Ext);
VOID EdrUnpublishDeviceLink(VOID);
VOID EdrDeleteDevice(_In_ PDRIVER_OBJECT DriverObject);
BOOLEAN EdrIsDevicePublished(VOID);
NTSTATUS EdrDeviceOpenLifetimeAcquire(_In_ PEDR_DEVICE_EXTENSION Ext,
                                      _In_ PFILE_OBJECT FileObject);
VOID EdrDeviceOpenLifetimeRelease(_In_ PEDR_DEVICE_EXTENSION Ext,
                                  _In_ PFILE_OBJECT FileObject);

/* event_queue.c */
NTSTATUS EdrQueueInit(_In_ EDR_QUEUE* Q);
VOID EdrQueueDestroy(_In_ EDR_QUEUE* Q);
NTSTATUS EdrQueueSubmitFetch(_In_ EDR_QUEUE* Q, _In_ PIRP Irp);
VOID EdrQueueCancelAll(_In_ EDR_QUEUE* Q);
VOID EdrQueuePush(_In_ EDR_QUEUE* Q, _In_ const EDR_EVENT_HEADER* Header,
                  _In_reads_bytes_opt_(PayloadLen) const VOID* Payload,
                  _In_ ULONG PayloadLen);
BOOLEAN EdrQueueIsEnabled(_In_ EDR_QUEUE* Q, _In_ ULONG MaskBit);

/* proc_notify.c */
NTSTATUS EdrProcNotifyRegister(_In_ EDR_QUEUE* Q);
NTSTATUS EdrProcNotifyUnregister(VOID);

/* reg_notify.c */
NTSTATUS EdrRegNotifyRegister(_In_ EDR_QUEUE* Q);
NTSTATUS EdrRegNotifyUnregister(VOID);

/* thread_notify.c */
NTSTATUS EdrThreadNotifyRegister(_In_ EDR_QUEUE* Q);
NTSTATUS EdrThreadNotifyUnregister(VOID);

/* image_notify.c (removed via PsRemoveLoadImageNotifyRoutine, which waits
 * for in-flight callbacks; see EdrImageNotifyStop) */
NTSTATUS EdrImageNotifyRegister(_In_ EDR_QUEUE* Q);
VOID EdrImageNotifyStop(VOID);

/* policy.c */
NTSTATUS EdrPolicyInit(VOID);
VOID EdrPolicyDestroy(VOID);
NTSTATUS EdrPolicyReplace(_In_ const VOID* Data, _In_ ULONG Size);

/* kill_process.c - IOCTL_EDR_KILL_PROCESS response handler. Terminates
 * the target PID on behalf of the user-mode agent; refuses the calling
 * process and critical-system images. See kill_process.c for rules. */
NTSTATUS EdrKillProcessForResponse(_In_ HANDLE TargetPid,
                                   _In_ HANDLE CallerPid);

BOOLEAN EdrPolicyIsEnabled(_In_ ULONG MaskBit);
ULONG EdrPolicyGetEnableMask(VOID);
BOOLEAN EdrPolicyMatchFile(_In_ const WCHAR* Path, _In_ SIZE_T PathChars,
                           _Out_opt_ PULONG RuleIndex);
BOOLEAN EdrPolicyMatchNet(_In_ const UCHAR Ip[4], _In_ USHORT Port,
                          _Out_opt_ PULONG RuleIndex);

/* ioctl.c */
DRIVER_DISPATCH EdrDispatchCreateClose;
DRIVER_DISPATCH EdrDispatchCleanup;
DRIVER_DISPATCH EdrDispatchDeviceControl;

/* Minifilter (compiled out unless EDR_ENABLE_MINIFILTER == 1). */
NTSTATUS EdrMiniFilterStart(_In_ PDRIVER_OBJECT DriverObject,
                            _In_ PEDR_DEVICE_EXTENSION Ext);
NTSTATUS EdrMiniFilterStop(_In_ BOOLEAN CalledFromUnload);

/* WFP (compiled out unless EDR_ENABLE_WFP == 1). */
NTSTATUS EdrWfpSkeletonInit(_In_ PDEVICE_OBJECT DeviceObject);
VOID EdrWfpSkeletonUnload(VOID);
VOID EdrWfpQueueSet(_In_ EDR_QUEUE* Q);

/* ob_notify.c (ObRegisterCallbacks for process/thread handle open). */
NTSTATUS EdrObNotifyRegister(_In_ EDR_QUEUE* Q);
NTSTATUS EdrObNotifyUnregister(VOID);

#endif /* EDRDRV_H */
