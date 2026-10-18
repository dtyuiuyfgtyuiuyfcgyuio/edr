/*
 * thread_notify.c - Thread create notify via PsSetCreateThreadNotifyRoutine.
 *
 * Collects: target process id (header.pid) and thread id (EDR_TAG_THREAD_ID,
 * u32). The callback runs in the context of the process creating the thread
 * at PASSIVE_LEVEL or DISPATCH_LEVEL; it performs only a bounded copy plus
 * EdrQueuePush - no allocation, no waiting, no paged memory, and no query of
 * arbitrary process state. It cannot determine whether the thread was
 * created remotely (CreateRemoteThread), so it only reports "a thread was
 * created"; rules must not assume remote-thread semantics.
 */
#include "edrdrv.h"

static EDR_QUEUE* g_ThreadQueue;

static VOID EdrThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId,
                            _In_ BOOLEAN Create)
{
    EDR_EVENT_HEADER hdr;
    EDR_TLV_HEADER tlv;
    UCHAR payload[EDR_SLOT_SIZE - sizeof(EDR_EVENT_HEADER)];
    ULONG payloadBytes = 0;

    if (g_ThreadQueue == NULL ||
        !EdrQueueIsEnabled(g_ThreadQueue, EDR_ENABLE_PROCESS)) {
        return;
    }
    if (!Create) {
        return;
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = EDR_EVENT_MAGIC;
    hdr.version = (unsigned short)EDR_EVENT_VERSION;
    hdr.type = (unsigned short)EDR_EVT_THREAD_CREATE;
    KeQuerySystemTime((PLARGE_INTEGER)&hdr.ts_100ns);
    hdr.pid = (unsigned int)(ULONG_PTR)ProcessId;

    tlv.tag = EDR_TAG_THREAD_ID;
    tlv.len = sizeof(ULONG);
    memcpy(payload, &tlv, sizeof(tlv));
    {
        ULONG threadId = (ULONG)(ULONG_PTR)ThreadId;
        memcpy(payload + sizeof(tlv), &threadId, sizeof(threadId));
    }
    payloadBytes = (ULONG)sizeof(tlv) + sizeof(ULONG);

    EdrQueuePush(g_ThreadQueue, &hdr, payload, payloadBytes);
}

NTSTATUS EdrThreadNotifyRegister(_In_ EDR_QUEUE* Q)
{
    NTSTATUS status;

    g_ThreadQueue = Q;
    status = PsSetCreateThreadNotifyRoutine(EdrThreadNotify);
    if (!NT_SUCCESS(status)) {
        g_ThreadQueue = NULL;
    }
    return status;
}

NTSTATUS EdrThreadNotifyUnregister(VOID)
{
    NTSTATUS status;

    if (g_ThreadQueue == NULL) {
        return STATUS_SUCCESS;
    }
    status = PsRemoveCreateThreadNotifyRoutine(EdrThreadNotify);
    if (NT_SUCCESS(status)) {
        g_ThreadQueue = NULL; /* only clear ownership after success */
    }
    return status;
}