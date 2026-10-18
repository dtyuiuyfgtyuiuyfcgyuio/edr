/*
 * ob_notify.c - Process/thread handle open monitoring via ObRegisterCallbacks.
 *
 * Registers pre-operation callbacks for PsProcessType and PsThreadType.
 * On each handle create (OB_OPERATION_HANDLE_CREATE) the callback emits an
 * EDR_EVT_HANDLE_OPEN event with:
 *   - TARGET_PID (u32): the target process or thread ID
 *   - ACCESS_MASK (u32): the desired access mask
 *   - OBJECT_TYPE (u8): 0 = process, 1 = thread
 *
 * The callback runs at PASSIVE_LEVEL, is non-paged, and uses only bounded
 * stack copies. No allocation is performed in the callback path.
 *
 * ObRegisterCallbacks is called exactly once with two operation registrations
 * (process + thread) under a single altitude. Windows 8.1+ is required;
 * this driver targets Windows 10 1607 (RS1), so the API is available.
 */
#include "edrdrv.h"

/* Object type pointers imported through the WDK declarations. */
static POBJECT_TYPE* g_PsProcessType = NULL;
static POBJECT_TYPE* g_PsThreadType = NULL;

static PVOID g_ObRegistrationHandle = NULL;
static EDR_QUEUE* g_ObQueue;
static WCHAR g_ObAltitude[] = L"360000";

/*
 * Pre-operation callback: captures process/thread handle OPEN operations.
 * Emits HANDLE_OPEN telemetry when the OBJECT_HANDLE config bit is set.
 */
static OB_PREOP_CALLBACK_STATUS
EdrObPreHandleCreate(_In_ PVOID RegistrationContext,
                     _In_ POB_PRE_OPERATION_INFORMATION OperationInfo)
{
    EDR_EVENT_HEADER hdr;
    EDR_TLV_HEADER tlv;
    UCHAR payload[EDR_SLOT_SIZE - sizeof(EDR_EVENT_HEADER)];
    ULONG payloadBytes = 0;
    ULONG targetPid = 0;
    ULONG accessMask = 0;
    UCHAR objectType = 0;
    HANDLE pid;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (g_ObQueue == NULL ||
        !EdrQueueIsEnabled(g_ObQueue, EDR_ENABLE_OBJECT_HANDLE)) {
        return OB_PREOP_SUCCESS;
    }

    /* Only monitor CREATE, not DUPLICATE. */
    if (OperationInfo->Operation != OB_OPERATION_HANDLE_CREATE) {
        return OB_PREOP_SUCCESS;
    }

    /* Determine object type and extract target PID. */
    if (OperationInfo->ObjectType == *g_PsProcessType) {
        PEPROCESS proc = (PEPROCESS)OperationInfo->Object;
        if (proc == NULL) {
            return OB_PREOP_SUCCESS;
        }
        pid = PsGetProcessId(proc);
        if (pid == NULL) {
            return OB_PREOP_SUCCESS;
        }
        targetPid = (ULONG)(ULONG_PTR)pid;
        objectType = 0; /* process */
    } else if (OperationInfo->ObjectType == *g_PsThreadType) {
        PETHREAD thread = (PETHREAD)OperationInfo->Object;
        if (thread == NULL) {
            return OB_PREOP_SUCCESS;
        }
        pid = PsGetThreadProcessId(thread);
        if (pid == NULL) {
            return OB_PREOP_SUCCESS;
        }
        targetPid = (ULONG)(ULONG_PTR)pid;
        objectType = 1; /* thread */
    } else {
        return OB_PREOP_SUCCESS;
    }

    /* Extract the desired access mask from the handle create parameters. */
    if (OperationInfo->Parameters == NULL) return OB_PREOP_SUCCESS;
    accessMask = OperationInfo->Parameters->CreateHandleInformation.DesiredAccess;

    /* Build the event: header + TLV payload. */
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = EDR_EVENT_MAGIC;
    hdr.version = (unsigned short)EDR_EVENT_VERSION;
    hdr.type = (unsigned short)EDR_EVT_HANDLE_OPEN;
    KeQuerySystemTime((PLARGE_INTEGER)&hdr.ts_100ns);
    hdr.pid = (unsigned int)(ULONG_PTR)PsGetCurrentProcessId();

    /* TARGET_PID (u32, tag 13). */
    tlv.tag = EDR_TAG_TARGET_PID;
    tlv.len = sizeof(ULONG);
    memcpy(payload + payloadBytes, &tlv, sizeof(tlv));
    payloadBytes += (ULONG)sizeof(tlv);
    memcpy(payload + payloadBytes, &targetPid, sizeof(targetPid));
    payloadBytes += (ULONG)sizeof(targetPid);

    /* ACCESS_MASK (u32, tag 14). */
    tlv.tag = EDR_TAG_ACCESS_MASK;
    tlv.len = sizeof(ULONG);
    memcpy(payload + payloadBytes, &tlv, sizeof(tlv));
    payloadBytes += (ULONG)sizeof(tlv);
    memcpy(payload + payloadBytes, &accessMask, sizeof(accessMask));
    payloadBytes += (ULONG)sizeof(accessMask);

    /* OBJECT_TYPE (u8, tag 15). */
    tlv.tag = EDR_TAG_OBJECT_TYPE;
    tlv.len = sizeof(UCHAR);
    memcpy(payload + payloadBytes, &tlv, sizeof(tlv));
    payloadBytes += (ULONG)sizeof(tlv);
    memcpy(payload + payloadBytes, &objectType, sizeof(objectType));
    payloadBytes += (ULONG)sizeof(objectType);

    EdrQueuePush(g_ObQueue, &hdr, payload, payloadBytes);
    return OB_PREOP_SUCCESS;
}

NTSTATUS EdrObNotifyRegister(_In_ EDR_QUEUE* Q)
{
    OB_CALLBACK_REGISTRATION obReg;
    OB_OPERATION_REGISTRATION opRegs[2];
    UNICODE_STRING altitude;
    NTSTATUS status;

    g_ObQueue = Q;

    g_PsProcessType = PsProcessType;
    g_PsThreadType = PsThreadType;
    if (g_PsProcessType == NULL || g_PsThreadType == NULL ||
        *g_PsProcessType == NULL || *g_PsThreadType == NULL) {
        g_ObQueue = NULL;
        return STATUS_NOT_SUPPORTED;
    }

    /* Single ObRegisterCallbacks call with two operation entries. */
    RtlInitUnicodeString(&altitude, g_ObAltitude);
    memset(&obReg, 0, sizeof(obReg));
    obReg.Version = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 2;
    obReg.Altitude = altitude;
    obReg.RegistrationContext = NULL;
    obReg.OperationRegistration = opRegs;

    /* Process handle create. */
    opRegs[0].ObjectType = g_PsProcessType;
    opRegs[0].Operations = OB_OPERATION_HANDLE_CREATE;
    opRegs[0].PreOperation = EdrObPreHandleCreate;
    opRegs[0].PostOperation = NULL;

    /* Thread handle create (reports the owning process PID). */
    opRegs[1].ObjectType = g_PsThreadType;
    opRegs[1].Operations = OB_OPERATION_HANDLE_CREATE;
    opRegs[1].PreOperation = EdrObPreHandleCreate;
    opRegs[1].PostOperation = NULL;

    status = ObRegisterCallbacks(&obReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        g_ObQueue = NULL;
    }
    return status;
}

NTSTATUS EdrObNotifyUnregister(VOID)
{
    if (g_ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
    }
    g_ObQueue = NULL;
    return STATUS_SUCCESS;
}
