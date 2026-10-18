/*
 * event_queue.c - Fixed-slot ring queue + pending IRP list.
 *
 * Design:
 *   - One KSPIN_LOCK protects everything (single lock order: the queue lock).
 *   - The ring is preallocated nonpaged memory: EDR_QUEUE_CAPACITY slots of
 *     EDR_SLOT_SIZE bytes each. Events always live here, independent of any
 *     IRP being present.
 *   - On overflow the oldest event is overwritten and Dropped++ is counted;
 *     a STATS event carrying the dropped count (header.reserved) is emitted
 *     when room allows.
 *   - A FETCH IRP with no events available is pended (cancel routine set).
 *   - Producers (notify callbacks) push events and, if a pending IRP exists,
 *     atomically detach it under the lock, release the lock, then fill and
 *     IoCompleteRequest it. IoCompleteRequest is NEVER called while holding
 *     the spin lock.
 *   - Cancel vs. completion ownership: whoever successfully detaches the IRP
 *     from the list AND clears its cancel routine owns it. If clearing the
 *     cancel routine fails, the entry is reinserted and the IRP is left for
 *     the cancel routine; the loser must not touch the IRP.
 */
#include "edrdrv.h"

static DRIVER_CANCEL EdrFetchCancel;

/*
 * Insert already-serialized bytes into the ring. Caller holds Q->Lock.
 * Overwrites the oldest slot when full and counts the drop.
 */
static VOID EdrRingInsertLocked(_Inout_ EDR_QUEUE* Q,
                                _In_reads_bytes_(Len) const VOID* Data,
                                _In_ ULONG Len)
{
    ULONG idx;

    if (Len > EDR_SLOT_SIZE) {
        InterlockedIncrement(&Q->Dropped);
        return;
    }
    if (Q->Count == EDR_QUEUE_CAPACITY) {
        Q->Head = (Q->Head + 1) % EDR_QUEUE_CAPACITY;
        Q->Count--;
        InterlockedIncrement(&Q->Dropped);
        Q->StatsPending = 1;
    }
    idx = (Q->Head + Q->Count) % EDR_QUEUE_CAPACITY;
    memcpy(Q->Slots + ((SIZE_T)idx * EDR_SLOT_SIZE), Data, Len);
    Q->Count++;
}

/*
 * Drain whole events into OutBuffer. Caller holds Q->Lock.
 * Stops before any event that would not fit entirely. If the very first
 * event does not fit, sets *Status to STATUS_BUFFER_TOO_SMALL and *OutBytes
 * to that event's total length.
 */
static VOID EdrRingDrainLocked(_Inout_ EDR_QUEUE* Q,
                               _Out_writes_bytes_(OutCap) UCHAR* OutBuffer,
                               _In_ ULONG OutCap,
                               _Out_ ULONG* OutBytes,
                               _Out_ NTSTATUS* Status)
{
    ULONG used = 0;

    *Status = STATUS_SUCCESS;
    while (Q->Count > 0) {
        const EDR_EVENT_HEADER* hdr;
        ULONG evLen;

        hdr = (const EDR_EVENT_HEADER*)(Q->Slots + ((SIZE_T)Q->Head * EDR_SLOT_SIZE));
        memcpy(&evLen, &hdr->length, sizeof(evLen));
        if (evLen < sizeof(EDR_EVENT_HEADER) || evLen > EDR_SLOT_SIZE) {
            /* Corrupt slot: drop defensively. */
            Q->Head = (Q->Head + 1) % EDR_QUEUE_CAPACITY;
            Q->Count--;
            continue;
        }
        if (used + evLen > OutCap) {
            if (used == 0) {
                *OutBytes = evLen;
                *Status = STATUS_BUFFER_TOO_SMALL;
                return;
            }
            break;
        }
        memcpy(OutBuffer + used, hdr, evLen);
        used += evLen;
        Q->Head = (Q->Head + 1) % EDR_QUEUE_CAPACITY;
        Q->Count--;
    }
    *OutBytes = used;
}

/*
 * Detach the head pending IRP. Caller holds Q->Lock.
 * Returns the context only if this caller owns the IRP (cancel routine
 * cleared). On ownership loss the entry is reinserted and NULL returned.
 */
static EDR_PENDING_IRP* EdrDetachPendingLocked(_Inout_ EDR_QUEUE* Q)
{
    LIST_ENTRY* entry;
    EDR_PENDING_IRP* ctx;

    if (IsListEmpty(&Q->PendingIrps)) {
        return NULL;
    }
    entry = RemoveHeadList(&Q->PendingIrps);
    ctx = CONTAINING_RECORD(entry, EDR_PENDING_IRP, Link);
    if (IoSetCancelRoutine(ctx->Irp, NULL) == NULL) {
        /* Cancel routine is running; it owns the IRP now. */
        InsertHeadList(&Q->PendingIrps, &ctx->Link);
        return NULL;
    }
    return ctx;
}

NTSTATUS EdrQueueInit(_In_ EDR_QUEUE* Q)
{
    memset(Q, 0, sizeof(*Q));
    KeInitializeSpinLock(&Q->Lock);
    InitializeListHead(&Q->PendingIrps);
    KeInitializeEvent(&Q->NoActiveCancelCallbacks, NotificationEvent, TRUE);
    Q->Slots = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                       (SIZE_T)EDR_QUEUE_CAPACITY * EDR_SLOT_SIZE,
                                       EDR_POOL_TAG);
    if (Q->Slots == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Q->ConfigMask = EDR_ENABLE_PROCESS | EDR_ENABLE_REGISTRY; /* boot mask */
    return STATUS_SUCCESS;
}

VOID EdrQueueDestroy(_In_ EDR_QUEUE* Q)
{
    NT_ASSERT(Q->Stopping != 0);
    NT_ASSERT(IsListEmpty(&Q->PendingIrps));
    NT_ASSERT(InterlockedCompareExchange(
                  &Q->ActiveCancelCallbacks, 0, 0) == 0);
    NT_ASSERT(KeReadStateEvent(&Q->NoActiveCancelCallbacks) != 0);
    if (Q->Slots != NULL) {
        ExFreePoolWithTag(Q->Slots, EDR_POOL_TAG);
        Q->Slots = NULL;
    }
}

BOOLEAN EdrQueueIsEnabled(_In_ EDR_QUEUE* Q, _In_ ULONG MaskBit)
{
    KIRQL irql;
    BOOLEAN enabled;

    KeAcquireSpinLock(&Q->Lock, &irql);
    enabled = (Q->ConfigMask & MaskBit) != 0;
    KeReleaseSpinLock(&Q->Lock, irql);
    return enabled;
}

/*
 * Push one event: serialize header+payload into the ring, then satisfy one
 * pending FETCH IRP if present.
 */
VOID EdrQueuePush(_In_ EDR_QUEUE* Q, _In_ const EDR_EVENT_HEADER* Header,
                  _In_reads_bytes_opt_(PayloadLen) const VOID* Payload,
                  _In_ ULONG PayloadLen)
{
    KIRQL irql;
    ULONG total;
    EDR_PENDING_IRP* ctx = NULL;
    NTSTATUS drainStatus = STATUS_SUCCESS;
    ULONG drainBytes = 0;
    UCHAR stackBuf[EDR_SLOT_SIZE];

    if (Q->Slots == NULL) {
        return;
    }
    if (PayloadLen > EDR_SLOT_SIZE - sizeof(EDR_EVENT_HEADER)) {
        InterlockedIncrement(&Q->Dropped);
        return;
    }
    total = (ULONG)sizeof(EDR_EVENT_HEADER) + PayloadLen;

    memcpy(stackBuf, Header, sizeof(EDR_EVENT_HEADER));
    {
        ULONG lenField = total;
        memcpy(stackBuf + FIELD_OFFSET(EDR_EVENT_HEADER, length), &lenField, sizeof(lenField));
    }
    if (PayloadLen != 0 && Payload != NULL) {
        memcpy(stackBuf + sizeof(EDR_EVENT_HEADER), Payload, PayloadLen);
    }

    KeAcquireSpinLock(&Q->Lock, &irql);

    EdrRingInsertLocked(Q, stackBuf, total);

    if (Q->StatsPending && Q->Count < EDR_QUEUE_CAPACITY) {
        EDR_EVENT_HEADER stats;

        memset(&stats, 0, sizeof(stats));
        stats.magic = EDR_EVENT_MAGIC;
        stats.version = (unsigned short)EDR_EVENT_VERSION;
        stats.type = (unsigned short)EDR_EVT_STATS;
        stats.length = sizeof(EDR_EVENT_HEADER);
        KeQuerySystemTime((PLARGE_INTEGER)&stats.ts_100ns);
        stats.reserved = (ULONG)InterlockedCompareExchange(&Q->Dropped, 0, 0);
        EdrRingInsertLocked(Q, &stats, sizeof(stats));
        Q->StatsPending = 0;
    }

    ctx = EdrDetachPendingLocked(Q);
    if (ctx != NULL) {
        EdrRingDrainLocked(Q,
                           (UCHAR*)ctx->Irp->AssociatedIrp.SystemBuffer,
                           IoGetCurrentIrpStackLocation(ctx->Irp)
                               ->Parameters.DeviceIoControl.OutputBufferLength,
                           &drainBytes,
                           &drainStatus);
    }

    KeReleaseSpinLock(&Q->Lock, irql);

    if (ctx != NULL) {
        PIRP irp = ctx->Irp;
        ExFreePoolWithTag(ctx, EDR_POOL_TAG);
        irp->IoStatus.Status = drainStatus;
        irp->IoStatus.Information = drainBytes;
        IoCompleteRequest(irp, IO_NO_INCREMENT); /* not holding the lock */
    }
}

/*
 * IOCTL_EDR_FETCH_EVENT path. Either drains immediately (completing the IRP
 * inside this call after the lock is released) or pends the IRP.
 */
NTSTATUS EdrQueueSubmitFetch(_In_ EDR_QUEUE* Q, _In_ PIRP Irp)
{
    KIRQL irql;
    PIO_STACK_LOCATION stack;
    ULONG outLen;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    BOOLEAN completeNow = FALSE;
    EDR_PENDING_IRP* ctx = NULL;

    stack = IoGetCurrentIrpStackLocation(Irp);
    outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (Q->Slots == NULL) {
        Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DEVICE_NOT_READY;
    }

    KeAcquireSpinLock(&Q->Lock, &irql);

    if (Q->Stopping != 0) {
        status = STATUS_DEVICE_NOT_READY;
        completeNow = TRUE;
    } else if (Q->Count > 0) {
        EdrRingDrainLocked(Q, (UCHAR*)Irp->AssociatedIrp.SystemBuffer,
                           outLen, &bytes, &status);
        completeNow = TRUE;
    } else {
        ctx = (EDR_PENDING_IRP*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                sizeof(*ctx), EDR_POOL_TAG);
        if (ctx == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            completeNow = TRUE;
        } else {
            ctx->Irp = Irp;
            IoMarkIrpPending(Irp);
            IoSetCancelRoutine(Irp, EdrFetchCancel);
            InsertTailList(&Q->PendingIrps, &ctx->Link);
            if (Irp->Cancel && IoSetCancelRoutine(Irp, NULL) != NULL) {
                /* Cancelled before we finished inserting; we still own it. */
                RemoveEntryList(&ctx->Link);
                status = STATUS_CANCELLED;
                completeNow = TRUE;
            } else {
                ctx = NULL; /* pended; cancel routine owns it on cancel */
            }
        }
    }

    KeReleaseSpinLock(&Q->Lock, irql);

    if (completeNow) {
        if (ctx != NULL && status == STATUS_CANCELLED) {
            ExFreePoolWithTag(ctx, EDR_POOL_TAG);
        }
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = bytes;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }
    return STATUS_PENDING;
}

static VOID EdrFetchCancel(_In_ PDEVICE_OBJECT DeviceObject,
                           _Inout_ PIRP Irp)
{
    EDR_QUEUE* q;
    PEDR_DEVICE_EXTENSION ext;
    KIRQL irql;
    KIRQL cancelIrql;
    LIST_ENTRY* entry;
    EDR_PENDING_IRP* ctx = NULL;
    BOOLEAN found = FALSE;

    ext = (PEDR_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    q = &ext->Queue;

    /* Register rundown while the I/O manager still holds the cancel spin
     * lock. If IoSetCancelRoutine returned NULL before this callback started,
     * the pending entry remains listed, so unload cannot miss this transition.
     * Interlocked operations provide the ordering around the event state. */
    if (InterlockedIncrement(&q->ActiveCancelCallbacks) == 1) {
        KeClearEvent(&q->NoActiveCancelCallbacks);
    }

    /* Submission and detach hold Q->Lock before touching the cancel routine.
     * Drop the cancel spin lock before taking Q->Lock to preserve that order. */
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    KeAcquireSpinLock(&q->Lock, &irql);
    for (entry = q->PendingIrps.Flink;
         entry != &q->PendingIrps;
         entry = entry->Flink) {
        EDR_PENDING_IRP* cur = CONTAINING_RECORD(entry, EDR_PENDING_IRP, Link);
        if (cur->Irp == Irp) {
            RemoveEntryList(entry);
            ctx = cur;
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&q->Lock, irql);

    if (found) {
        ExFreePoolWithTag(ctx, EDR_POOL_TAG);
        Irp->IoStatus.Status = STATUS_CANCELLED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
    /* Serialize zero/nonzero event transitions with callback entry. This
     * prevents a 1->0 callback from setting the event after a new 0->1
     * callback has already cleared it. No queue lock is held here. */
    IoAcquireCancelSpinLock(&cancelIrql);
    if (InterlockedDecrement(&q->ActiveCancelCallbacks) == 0) {
        KeSetEvent(&q->NoActiveCancelCallbacks, IO_NO_INCREMENT, FALSE);
    }
    IoReleaseCancelSpinLock(cancelIrql);
}

/*
 * Unload path: cancel every pending FETCH IRP. If clearing a cancel routine
 * fails the cancel routine owns that IRP and will remove/complete it; we
 * retry until the list is empty rather than touching a lost IRP.
 */
VOID EdrQueueCancelAll(_In_ EDR_QUEUE* Q)
{
    KIRQL stopIrql;

    KeAcquireSpinLock(&Q->Lock, &stopIrql);
    Q->Stopping = 1;
    KeReleaseSpinLock(&Q->Lock, stopIrql);

    for (;;) {
        KIRQL irql;
        EDR_PENDING_IRP* ctx;

        KeAcquireSpinLock(&Q->Lock, &irql);
        ctx = EdrDetachPendingLocked(Q);
        KeReleaseSpinLock(&Q->Lock, irql);

        if (ctx == NULL) {
            KIRQL irql2;
            BOOLEAN empty;
            LONG active;

            KeAcquireSpinLock(&Q->Lock, &irql2);
            empty = IsListEmpty(&Q->PendingIrps);
            KeReleaseSpinLock(&Q->Lock, irql2);
            if (empty) {
                /* A callback removes its entry before free/complete. Wait for
                 * all such callbacks, then recheck both list and count. */
                (VOID)KeWaitForSingleObject(
                    &Q->NoActiveCancelCallbacks, Executive, KernelMode,
                    FALSE, NULL);
                KeAcquireSpinLock(&Q->Lock, &irql2);
                empty = IsListEmpty(&Q->PendingIrps);
                active = InterlockedCompareExchange(
                    &Q->ActiveCancelCallbacks, 0, 0);
                KeReleaseSpinLock(&Q->Lock, irql2);
                if (empty && active == 0) {
                    return;
                }
                continue;
            }
            /* A cancel routine is in flight; yield and retry. */
            {
                LARGE_INTEGER interval;
                interval.QuadPart = -10 * 1000; /* 1ms */
                KeDelayExecutionThread(KernelMode, FALSE, &interval);
            }
            continue;
        }

        ctx->Irp->IoStatus.Status = STATUS_CANCELLED;
        ctx->Irp->IoStatus.Information = 0;
        IoCompleteRequest(ctx->Irp, IO_NO_INCREMENT);
        ExFreePoolWithTag(ctx, EDR_POOL_TAG);
    }
}
