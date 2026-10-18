/*
 * wfp_skeleton.c - WFP ALE connect blocking + connectivity audit.
 *
 * Audited & enforced layers (when EDR_ENABLE_WFP == 1):
 *   - IPv4 ALE_AUTH_CONNECT_V4: BLOCK enforcement via EDR_EVT_BLOCK and,
 *     when EDR_ENABLE_NET is set, EDR_EVT_NET_CONNECT telemetry for
 *     permitted connects.
 *   - IPv6 ALE_AUTH_CONNECT_V6: EDR_EVT_NET_CONNECT telemetry only (no
 *     enforcement; policy net rules are IPv4-only).
 *
 * Sole INITGUID owner: the literal first line of this translation unit
 * defines INITGUID before every include, so DEFINE_GUID instantiations
 * (this module's callout/sub-layer GUIDs and the FWPM layer keys) get
 * definitions only here. No /DINITGUID anywhere; no other TU defines it.
 *
 * Enable: EDR_ENABLE_WFP == 1 (WFP/ALL variants). When disabled the
 * init/unload exports are inert stubs.
 *
 * Lifecycle facts tracked separately (PHASE_BC_PLAN.md):
 *   - Engine handle owned.
 *   - Transaction state: NONE / OPEN / OUTCOME_UNCERTAIN.
 *   - Management publication confirmed; sublayer key.
 *   - Management callout ID (FwpmCalloutAdd0) and FWPS runtime callout ID
 *     (FwpsCalloutRegister1) are distinct.
 *   - Filter ID (FwpmFilterAdd0) with a fixed UINT8 weight (0xF),
 *     not a pointer-backed weight.
 * Teardown: delete filter, delete management callout, delete sublayer,
 * unregister the FWPS callout, then close the engine (close is the
 * authority even when the transaction outcome is uncertain).
 *
 * Classify truth table (FWPS_LAYER_ALE_AUTH_CONNECT_V4):
 *   | incoming        | ACTION_WRITE | BLOCK enabled + match | message |
 *   | BLOCK           | any          | any                   | preserve incoming, no audit |
 *   | PERMIT/other    | absent       | any                   | preserve incoming, no audit |
 *   | PERMIT/other    | present      | no                    | preserve incoming, no NET_CONNECT if NET on |
 *   | PERMIT/other    | present      | yes                   | write BLOCK, clear ACTION_WRITE, best-effort audit |
 * No match never manufactures PERMIT. NET_CONNECT telemetry is emitted for
 * permitted connects only when EDR_ENABLE_NET is set and the typed
 * FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS field does not carry
 * FWP_CONDITION_FLAG_IS_REAUTHORIZE (reauthorization suppresses duplicate
 * NET telemetry; a reauthorization that newly writes BLOCK may still audit
 * BLOCK). IPv6 ALE_AUTH_CONNECT_V6 telemetry follows the same NET gate and
 * reauthorize suppression and never enforces.
 *
 * Classify code/data is nonpaged and allocation-free. IPv4 canonical
 * display-order octets are extracted MSB-first from the FWP_UINT32 field
 * (network byte order) into byte members of a real IN_ADDR for
 * RtlIpv4AddressToStringA. IPv6 uses the FWP_BYTE_ARRAY16_TYPE field whose
 * union member is a FWP_BYTE_ARRAY16 pointer (dereferenced with a NULL
 * check) copied into IN6_ADDR.u.Byte for RtlIpv6AddressToStringA.
 */
#define INITGUID
/* ndis.h: WDM driver target Windows 10 1607 (RS1) NDIS 6.60. */
#define NDIS_WDM
#define NDIS660
#include <ndis.h>
#include "edrdrv.h"

#ifndef EDR_ENABLE_WFP
#define EDR_ENABLE_WFP 0
#endif

#if EDR_ENABLE_WFP

#include <fwpsk.h>
#include <fwpmk.h>
#include <ip2string.h>
#include <ntstrsafe.h>

/* Own GUIDs (defined only in this TU via INITGUID). */
DEFINE_GUID(EDR_CALLOUT_GUID, 0x1a2b3c4d, 0x5e6f, 0x4707,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01);
DEFINE_GUID(EDR_SUBLAYER_GUID, 0x1a2b3c4d, 0x5e6f, 0x4707,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02);
DEFINE_GUID(EDR_CALLOUT_V6_GUID, 0x1a2b3c4d, 0x5e6f, 0x4707,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03);

typedef enum _EDR_WFP_TXN_STATE {
    EDR_TXN_NONE = 0,
    EDR_TXN_OPEN,
    EDR_TXN_OUTCOME_UNCERTAIN
} EDR_WFP_TXN_STATE;

typedef struct _EDR_TLV_BUILDER {
    UCHAR Buf[EDR_SLOT_SIZE - sizeof(EDR_EVENT_HEADER)];
    ULONG Used;
    BOOLEAN Truncated;
} EDR_TLV_BUILDER;

static HANDLE g_EngineHandle;        /* owned */
static UINT32 g_FwpsCalloutId;       /* FWPS runtime registration id (V4) */
static UINT32 g_FwpsCalloutId6;      /* FWPS runtime registration id (V6) */
static UINT32 g_MgmtCalloutId;       /* FwpmCalloutAdd0 id (V4) */
static UINT32 g_MgmtCalloutId6;      /* FwpmCalloutAdd0 id (V6) */
static UINT64 g_FilterId;            /* FwpmFilterAdd0 id (V4) */
static UINT64 g_FilterId6;           /* FwpmFilterAdd0 id (V6) */
static EDR_WFP_TXN_STATE g_TxnState;
static EDR_QUEUE* g_WfpQueue;

static VOID TlvAppendUtf16Bytes(_Inout_ EDR_TLV_BUILDER* B, _In_ USHORT Tag,
                                _In_reads_bytes_opt_(ByteLen) const VOID* Data,
                                _In_ USHORT ByteLen);
static VOID EmitBlockNetEvent(const UCHAR Ip[4], USHORT Port,
                              ULONG RuleIndex);
static VOID EmitNetConnectEvent(const CHAR* IpStr, USHORT IpBytes,
                                USHORT Port);

/*
 * WFP classify: see the truth table in the header comment. Runs at
 * DISPATCH_LEVEL, nonpaged, no allocation, no spin locks beyond the
 * queue's spin lock inside the emit helpers (EdrQueuePush).
 */
static VOID EdrWfpConnectClassify(_In_ const FWPS_INCOMING_VALUES0* FixedValues,
                                  _In_ const FWPS_INCOMING_METADATA_VALUES0* Meta,
                                  _Inout_opt_ VOID* LayerData,
                                  _In_opt_ const VOID* ClassifyContext,
                                  _In_ const FWPS_FILTER1* Filter,
                                  _In_ UINT64 FlowContext,
                                  _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    UINT32 remoteIp;
    UINT16 remotePort;
    UCHAR ip[4];
    ULONG ruleIndex = 0;
    BOOLEAN match;
    BOOLEAN reauthorize = FALSE;
    CHAR ipStr[16];
    IN_ADDR addr;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);
    UNREFERENCED_PARAMETER(Meta);

    if (FixedValues == NULL || ClassifyOut == NULL || g_WfpQueue == NULL) {
        return;
    }

    /* Preserve an incoming BLOCK exactly; no audit is generated. */
    if (ClassifyOut->actionType == FWP_ACTION_BLOCK) {
        return;
    }

    /* Typed reauthorization flag (absent fields read as not-reauthorize). */
    if (FixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS]
            .value.type == FWP_UINT32) {
        reauthorize =
            (FixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS]
                 .value.uint32 &
             FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0;
    }

    /* Typed reads for the remaining V4 fields (guaranteed present at this
     * ALE layer; check the discriminants as defense in depth). */
    if (FixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.type !=
        FWP_UINT32) {
        return;
    }
    if (FixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.type !=
        FWP_UINT16) {
        return;
    }

    remoteIp = FixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    remotePort = (UINT16)FixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;

    /* Network byte order -> canonical display octets, MSB first. */
    ip[0] = (UCHAR)(remoteIp >> 24);
    ip[1] = (UCHAR)(remoteIp >> 16);
    ip[2] = (UCHAR)(remoteIp >> 8);
    ip[3] = (UCHAR)(remoteIp);

    /* Enforcement branch: BLOCK enabled + write right + rule match. */
    if (EdrQueueIsEnabled(g_WfpQueue, EDR_ENABLE_BLOCK) &&
        (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        match = EdrPolicyMatchNet(ip, RtlUshortByteSwap(remotePort),
                                  &ruleIndex);
        if (match) {
            ClassifyOut->actionType = FWP_ACTION_BLOCK;
            ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            EmitBlockNetEvent(ip, RtlUshortByteSwap(remotePort), ruleIndex);
            return;
        }
    }

    /* Telemetry branch: NET enabled, permitted connect, not reauthorize.
     * Runs regardless of ACTION_WRITE (audit does not modify the action). */
    if (EdrQueueIsEnabled(g_WfpQueue, EDR_ENABLE_NET) && !reauthorize) {
        addr.S_un.S_un_b.s_b1 = ip[0];
        addr.S_un.S_un_b.s_b2 = ip[1];
        addr.S_un.S_un_b.s_b3 = ip[2];
        addr.S_un.S_un_b.s_b4 = ip[3];
        RtlIpv4AddressToStringA(&addr, ipStr);
        EmitNetConnectEvent(ipStr, (USHORT)strlen(ipStr),
                            RtlUshortByteSwap(remotePort));
    }
}

/*
 * WFP classify for IPv6 ALE connect: telemetry only, never enforces.
 * Same IRQL/alloc/lock discipline as the V4 callout.
 */
static VOID EdrWfpConnectV6Classify(_In_ const FWPS_INCOMING_VALUES0* FixedValues,
                                    _In_ const FWPS_INCOMING_METADATA_VALUES0* Meta,
                                    _Inout_opt_ VOID* LayerData,
                                    _In_opt_ const VOID* ClassifyContext,
                                    _In_ const FWPS_FILTER1* Filter,
                                    _In_ UINT64 FlowContext,
                                    _Out_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    const FWP_BYTE_ARRAY16* v6addr;
    UINT16 remotePort;
    BOOLEAN reauthorize = FALSE;
    IN6_ADDR addr;
    CHAR ipStr[46];

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);
    UNREFERENCED_PARAMETER(Meta);

    if (FixedValues == NULL || ClassifyOut == NULL || g_WfpQueue == NULL) {
        return;
    }

    /* Preserve an incoming BLOCK exactly; no audit is generated. */
    if (ClassifyOut->actionType == FWP_ACTION_BLOCK) {
        return;
    }

    if (!EdrQueueIsEnabled(g_WfpQueue, EDR_ENABLE_NET)) {
        return;
    }

    if (FixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS]
            .value.type == FWP_UINT32) {
        reauthorize =
            (FixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS]
                 .value.uint32 &
             FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0;
    }
    if (reauthorize) {
        return; /* suppress duplicate telemetry */
    }

    /* The FWP_BYTE_ARRAY16_TYPE field is a pointer member; NULL-check it. */
    if (FixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.type !=
        FWP_BYTE_ARRAY16_TYPE) {
        return;
    }
    v6addr = FixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
    if (v6addr == NULL) {
        return;
    }

    remotePort = (UINT16)FixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;

    memcpy(addr.u.Byte, v6addr->byteArray16, sizeof(addr.u.Byte));
    RtlIpv6AddressToStringA(&addr, ipStr);
    EmitNetConnectEvent(ipStr, (USHORT)strlen(ipStr),
                        RtlUshortByteSwap(remotePort));
}

static NTSTATUS EdrWfpConnectNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE Type,
                                    _In_ const GUID* FilterKey,
                                    _Inout_ FWPS_FILTER1* Filter)
{
    UNREFERENCED_PARAMETER(Type);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

static const FWPS_CALLOUT1 g_ConnectCallout = {
    { 0x1a2b3c4d, 0x5e6f, 0x4707,
      { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01 } },
    0, EdrWfpConnectClassify, EdrWfpConnectNotify, NULL
};

static const FWPS_CALLOUT1 g_ConnectV6Callout = {
    { 0x1a2b3c4d, 0x5e6f, 0x4707,
      { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03 } },
    0, EdrWfpConnectV6Classify, EdrWfpConnectNotify, NULL
};

/* ------------------------------------------------------------------ */

static VOID TlvAppendUtf16Bytes(_Inout_ EDR_TLV_BUILDER* B, _In_ USHORT Tag,
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

static VOID EmitBlockNetEvent(const UCHAR Ip[4], USHORT Port,
                              ULONG RuleIndex)
{
    EDR_EVENT_HEADER hdr;
    EDR_TLV_BUILDER tlv;
    CHAR ipBuf[16];
    IN_ADDR addr;
    USHORT portLe = Port;

    if (g_WfpQueue == NULL ||
        !EdrQueueIsEnabled(g_WfpQueue, EDR_ENABLE_BLOCK)) {
        return;
    }

    /* Real IN_ADDR built by byte members (plan: never cast for display). */
    addr.S_un.S_un_b.s_b1 = Ip[0];
    addr.S_un.S_un_b.s_b2 = Ip[1];
    addr.S_un.S_un_b.s_b3 = Ip[2];
    addr.S_un.S_un_b.s_b4 = Ip[3];
    RtlIpv4AddressToStringA(&addr, ipBuf);

    memset(&hdr, 0, sizeof(hdr));
    memset(&tlv, 0, sizeof(tlv));
    hdr.magic = EDR_EVENT_MAGIC;
    hdr.version = (unsigned short)EDR_EVENT_VERSION;
    hdr.type = EDR_EVT_BLOCK;
    KeQuerySystemTime((PLARGE_INTEGER)&hdr.ts_100ns);
    hdr.pid = (unsigned int)(ULONG_PTR)PsGetCurrentProcessId();

    TlvAppendUtf16Bytes(&tlv, EDR_TAG_DST_IP, ipBuf, (USHORT)strlen(ipBuf));
    TlvAppendUtf16Bytes(&tlv, EDR_TAG_DST_PORT, &portLe, sizeof(portLe));
    TlvAppendUtf16Bytes(&tlv, EDR_TAG_RULE_INDEX, &RuleIndex,
                        sizeof(RuleIndex));

    if (tlv.Truncated) {
        hdr.flags |= EDR_FLAG_TRUNCATED;
    }

    EdrQueuePush(g_WfpQueue, &hdr, tlv.Buf, tlv.Used);
}

/*
 * Best-effort NET_CONNECT telemetry for a permitted connect (V4 or V6).
 * Gated internally on the queue's EDR_ENABLE_NET bit; emits DST_IP (ascii)
 * and DST_PORT (u16 LE) only.
 */
static VOID EmitNetConnectEvent(const CHAR* IpStr, USHORT IpBytes,
                                USHORT Port)
{
    EDR_EVENT_HEADER hdr;
    EDR_TLV_BUILDER tlv;
    USHORT portLe = Port;

    if (g_WfpQueue == NULL ||
        !EdrQueueIsEnabled(g_WfpQueue, EDR_ENABLE_NET)) {
        return;
    }

    memset(&hdr, 0, sizeof(hdr));
    memset(&tlv, 0, sizeof(tlv));
    hdr.magic = EDR_EVENT_MAGIC;
    hdr.version = (unsigned short)EDR_EVENT_VERSION;
    hdr.type = EDR_EVT_NET_CONNECT;
    KeQuerySystemTime((PLARGE_INTEGER)&hdr.ts_100ns);
    hdr.pid = (unsigned int)(ULONG_PTR)PsGetCurrentProcessId();

    TlvAppendUtf16Bytes(&tlv, EDR_TAG_DST_IP, IpStr, IpBytes);
    TlvAppendUtf16Bytes(&tlv, EDR_TAG_DST_PORT, &portLe, sizeof(portLe));

    if (tlv.Truncated) {
        hdr.flags |= EDR_FLAG_TRUNCATED;
    }

    EdrQueuePush(g_WfpQueue, &hdr, tlv.Buf, tlv.Used);
}

/* ------------------------------------------------------------------ */

NTSTATUS EdrWfpSkeletonInit(_In_ PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS status;
    FWPM_SESSION0 session;
    FWPM_SUBLAYER0 subLayer;
    FWPM_CALLOUT0 mgmtCallout;
    FWPM_CALLOUT0 mgmtCallout6;
    FWPM_FILTER0 filter;
    FWPM_FILTER0 filter6;

    g_TxnState = EDR_TXN_NONE;

    /* Dynamic session: every object added in this session is removed by a
     * successful engine close, so a partial/crashed teardown cannot leave
     * residue that blocks the next load. */
    memset(&session, 0, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session,
                             &g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        g_EngineHandle = NULL;
        return status;
    }
    g_TxnState = EDR_TXN_OPEN;

    status = FwpsCalloutRegister1(DeviceObject, &g_ConnectCallout,
                                  &g_FwpsCalloutId);
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }

    status = FwpsCalloutRegister1(DeviceObject, &g_ConnectV6Callout,
                                  &g_FwpsCalloutId6);
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }

    memset(&subLayer, 0, sizeof(subLayer));
    subLayer.subLayerKey = EDR_SUBLAYER_GUID;
    subLayer.displayData.name = L"EDR block sublayer";
    subLayer.displayData.description = L"EDR IPv4/IPv6 connect sublayer";
    subLayer.flags = 0;
    subLayer.weight = 0;

    memset(&mgmtCallout, 0, sizeof(mgmtCallout));
    mgmtCallout.calloutKey = EDR_CALLOUT_GUID;
    mgmtCallout.displayData.name = L"EDR ALE connect callout";
    mgmtCallout.displayData.description = L"EDR IPv4 connect BLOCK callout";
    mgmtCallout.flags = 0;
    mgmtCallout.providerKey = NULL;
    mgmtCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    memset(&filter, 0, sizeof(filter));
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData.name = L"EDR ALE connect filter";
    filter.displayData.description = L"EDR IPv4 connect BLOCK filter";
    filter.flags = 0;
    filter.providerKey = NULL;
    filter.subLayerKey = EDR_SUBLAYER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    filter.numFilterConditions = 0;
    filter.filterCondition = NULL;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = EDR_CALLOUT_GUID;

    memset(&mgmtCallout6, 0, sizeof(mgmtCallout6));
    mgmtCallout6.calloutKey = EDR_CALLOUT_V6_GUID;
    mgmtCallout6.displayData.name = L"EDR ALE connect v6 callout";
    mgmtCallout6.displayData.description = L"EDR IPv6 connect telemetry callout";
    mgmtCallout6.flags = 0;
    mgmtCallout6.providerKey = NULL;
    mgmtCallout6.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

    memset(&filter6, 0, sizeof(filter6));
    filter6.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter6.displayData.name = L"EDR ALE connect v6 filter";
    filter6.displayData.description = L"EDR IPv6 connect telemetry filter";
    filter6.flags = 0;
    filter6.providerKey = NULL;
    filter6.subLayerKey = EDR_SUBLAYER_GUID;
    filter6.weight.type = FWP_UINT8;
    filter6.weight.uint8 = 0xF;
    filter6.numFilterConditions = 0;
    filter6.filterCondition = NULL;
    filter6.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter6.action.calloutKey = EDR_CALLOUT_V6_GUID;

    status = FwpmTransactionBegin0(g_EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        goto Fail;
    }

    status = FwpmSubLayerAdd0(g_EngineHandle, &subLayer, NULL);
    if (status == STATUS_FWP_ALREADY_EXISTS) {
        /* Dynamic session residue from a crashed session is impossible to
         * have via a session-scoped add, but tolerate a prior non-dynamic
         * leftover key so reload is never blocked. Deletion below uses the
         * shared key and is idempotent. */
        status = STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) {
        (VOID)FwpmTransactionAbort0(g_EngineHandle);
        g_TxnState = EDR_TXN_OUTCOME_UNCERTAIN;
        goto Fail;
    }

    status = FwpmCalloutAdd0(g_EngineHandle, &mgmtCallout, NULL,
                             &g_MgmtCalloutId);
    if (status == STATUS_FWP_ALREADY_EXISTS) {
        FWPM_CALLOUT0* existing = NULL;
        status = FwpmCalloutGetByKey0(g_EngineHandle, &EDR_CALLOUT_GUID,
                                      &existing);
        if (NT_SUCCESS(status) && existing != NULL) {
            g_MgmtCalloutId = existing->calloutId;
            FwpmFreeMemory0(&existing);
            status = STATUS_SUCCESS;
        }
    }
    if (!NT_SUCCESS(status)) {
        (VOID)FwpmTransactionAbort0(g_EngineHandle);
        g_TxnState = EDR_TXN_OUTCOME_UNCERTAIN;
        goto Fail;
    }

    status = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterId);
    if (!NT_SUCCESS(status)) {
        (VOID)FwpmTransactionAbort0(g_EngineHandle);
        g_TxnState = EDR_TXN_OUTCOME_UNCERTAIN;
        goto Fail;
    }

    status = FwpmCalloutAdd0(g_EngineHandle, &mgmtCallout6, NULL,
                             &g_MgmtCalloutId6);
    if (status == STATUS_FWP_ALREADY_EXISTS) {
        FWPM_CALLOUT0* existing6 = NULL;
        status = FwpmCalloutGetByKey0(g_EngineHandle, &EDR_CALLOUT_V6_GUID,
                                      &existing6);
        if (NT_SUCCESS(status) && existing6 != NULL) {
            g_MgmtCalloutId6 = existing6->calloutId;
            FwpmFreeMemory0(&existing6);
            status = STATUS_SUCCESS;
        }
    }
    if (!NT_SUCCESS(status)) {
        (VOID)FwpmTransactionAbort0(g_EngineHandle);
        g_TxnState = EDR_TXN_OUTCOME_UNCERTAIN;
        goto Fail;
    }

    status = FwpmFilterAdd0(g_EngineHandle, &filter6, NULL, &g_FilterId6);
    if (!NT_SUCCESS(status)) {
        (VOID)FwpmTransactionAbort0(g_EngineHandle);
        g_TxnState = EDR_TXN_OUTCOME_UNCERTAIN;
        goto Fail;
    }

    status = FwpmTransactionCommit0(g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        g_TxnState = EDR_TXN_OUTCOME_UNCERTAIN;
        goto Fail;
    }
    g_TxnState = EDR_TXN_NONE;

    return STATUS_SUCCESS;

Fail:
    /* Engine close is the authority for whatever is not provably gone. */
    if (g_EngineHandle != NULL) {
        (VOID)FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }
    /* Unregister every runtime callout registered before the failure. */
    if (g_FwpsCalloutId != 0) {
        (VOID)FwpsCalloutUnregisterById0(g_FwpsCalloutId);
        g_FwpsCalloutId = 0;
    }
    if (g_FwpsCalloutId6 != 0) {
        (VOID)FwpsCalloutUnregisterById0(g_FwpsCalloutId6);
        g_FwpsCalloutId6 = 0;
    }
    g_MgmtCalloutId = 0;
    g_MgmtCalloutId6 = 0;
    g_FilterId = 0;
    g_FilterId6 = 0;
    return status;
}

VOID EdrWfpSkeletonUnload(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (g_EngineHandle != NULL) {
        /* Order matters: filters first, then callouts, then sublayer. */
        if (g_FilterId != 0) {
            (VOID)FwpmFilterDeleteById0(g_EngineHandle, g_FilterId);
            g_FilterId = 0;
        }
        if (g_FilterId6 != 0) {
            (VOID)FwpmFilterDeleteById0(g_EngineHandle, g_FilterId6);
            g_FilterId6 = 0;
        }

        /* Teardown of the confirmed management state goes through a delete
         * transaction so a partial failure is not silently accepted. */
        status = FwpmTransactionBegin0(g_EngineHandle, 0);
        if (NT_SUCCESS(status)) {
            if (g_MgmtCalloutId != 0) {
                status = FwpmCalloutDeleteById0(g_EngineHandle,
                                                g_MgmtCalloutId);
            }
            if (NT_SUCCESS(status) && g_MgmtCalloutId6 != 0) {
                status = FwpmCalloutDeleteById0(g_EngineHandle,
                                                g_MgmtCalloutId6);
            }
            if (NT_SUCCESS(status)) {
                status = FwpmSubLayerDeleteByKey0(g_EngineHandle,
                                                  &EDR_SUBLAYER_GUID);
            }
            if (NT_SUCCESS(status)) {
                status = FwpmTransactionCommit0(g_EngineHandle);
            } else {
                (VOID)FwpmTransactionAbort0(g_EngineHandle);
            }
        }
        g_MgmtCalloutId = 0;
        g_MgmtCalloutId6 = 0;

        /* The dynamic session makes engine close authoritative: a failed or
         * uncertain delete transaction leaves no residue behind because the
         * close removes every object this session added. */
        (VOID)FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }
    if (g_FwpsCalloutId != 0) {
        (VOID)FwpsCalloutUnregisterById0(g_FwpsCalloutId);
        g_FwpsCalloutId = 0;
    }
    if (g_FwpsCalloutId6 != 0) {
        (VOID)FwpsCalloutUnregisterById0(g_FwpsCalloutId6);
        g_FwpsCalloutId6 = 0;
    }
    g_TxnState = EDR_TXN_NONE;
    g_WfpQueue = NULL;
}

/* Set the queue for audit emission; called from driver_entry after queue
 * exists and before RUNNING. */
VOID EdrWfpQueueSet(_In_ EDR_QUEUE* Q)
{
    g_WfpQueue = Q;
}

#else /* EDR_ENABLE_WFP == 0 */

NTSTATUS EdrWfpSkeletonInit(_In_ PDEVICE_OBJECT DeviceObject)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return STATUS_SUCCESS; /* inert: WFP support not compiled in */
}

VOID EdrWfpSkeletonUnload(VOID)
{
}

VOID EdrWfpQueueSet(_In_ EDR_QUEUE* Q)
{
    UNREFERENCED_PARAMETER(Q);
}

#endif /* EDR_ENABLE_WFP */
