/*
 * policy.c - Private fixed-size policy singleton (EDR_POLICY_V1).
 *
 * Publication model (PHASE_BC_PLAN.md "Protocol definitions and validation"):
 *   - Two fixed nonpaged immutable snapshots; readers pin one slot, writers
 *     build the inactive slot and atomically exchange the active index.
 *   - Readers never hold the publication lock, so WFP classify at DISPATCH
 *     level stays lock-free and allocation-free. Matching is bounded:
 *     at most 32 x 256 UTF-16 prefix comparisons (file) or 64 fixed
 *     comparisons (network).
 *   - The PASSIVE_LEVEL writer serializes replaces with a fast mutex.
 *   - Before the first push BLOCK is fail-open; a failed later push keeps
 *     the last complete generation (EdrPolicyReplace validates the whole
 *     table and rejects it atomically).
 *
 * Only the two snapshots are stored in this module; the queue holds events.
 */
#include "edrdrv.h"
#include "policy_validate.h"

#define EDR_POLICY_SLOTS 2u

typedef struct _EDR_POLICY_SLOT {
    volatile LONG Readers;     /* nonzero: pinned by an active reader */
    EDR_POLICY_V1 Snapshot;    /* immutable once published (writer-built) */
} EDR_POLICY_SLOT;

static EDR_POLICY_SLOT g_PolicySlots[EDR_POLICY_SLOTS];
static volatile LONG g_ActiveSlot;      /* 0 or 1, atomically exchanged */
static FAST_MUTEX g_PolicyMutex;        /* PASSIVE writer serialization */
static BOOLEAN g_PolicyInitialized;     /* set once at boot */

static VOID EdrPolicyBuildBoot(VOID)
{
    ULONG slot = 0;
    EDR_POLICY_V1* p = &g_PolicySlots[slot].Snapshot;

    memset(p, 0, sizeof(*p));
    p->version = EDR_POLICY_VERSION;
    p->struct_size = sizeof(EDR_POLICY_V1);
    p->generation = 1;
    p->enable_mask = EDR_ENABLE_PROCESS | EDR_ENABLE_REGISTRY;
    p->file_rule_count = 0;
    p->net_rule_count = 0;
}

NTSTATUS EdrPolicyInit(VOID)
{
    ULONG i;

    for (i = 0; i < EDR_POLICY_SLOTS; i++) {
        g_PolicySlots[i].Readers = 0;
        memset(&g_PolicySlots[i].Snapshot, 0,
               sizeof(g_PolicySlots[i].Snapshot));
    }
    g_ActiveSlot = 0;
    ExInitializeFastMutex(&g_PolicyMutex);
    EdrPolicyBuildBoot();
    g_PolicyInitialized = TRUE;
    return STATUS_SUCCESS;
}

VOID EdrPolicyDestroy(VOID)
{
    /* Only called after every producer/driver path is quiesced and open
     * count is zero; no reader can remain. The slot storage itself is
     * static and needs no free; just invalidate the flag. */
    g_PolicyInitialized = FALSE;
    MemoryBarrier();
}

/*
 * Reader pin: read the active index, increment its reader count, then
 * re-check the index. If the index moved while we incremented (a writer
 * exchanged during the pin), release and retry. Bounded: no spin-wait past
 * a small fixed number of attempts; on persistent racing we return NULL and
 * callers treat policy as absent (fail-open for enforcement).
 */
static const EDR_POLICY_V1* EdrPolicyPinRead(VOID)
{
    ULONG attempt;

    for (attempt = 0; attempt < 16; attempt++) {
        LONG slot = InterlockedCompareExchange(&g_ActiveSlot, 0, 0);
        EDR_POLICY_V1* p;

        if (slot < 0 || slot >= (LONG)EDR_POLICY_SLOTS) {
            return NULL;
        }
        p = &g_PolicySlots[slot].Snapshot;
        InterlockedIncrement(&g_PolicySlots[slot].Readers);
        MemoryBarrier();
        if (InterlockedCompareExchange(&g_ActiveSlot, 0, 0) == slot) {
            return p; /* pinned: this slot stayed active */
        }
        /* The writer exchanged during pin; release and retry. */
        InterlockedDecrement(&g_PolicySlots[slot].Readers);
        MemoryBarrier();
    }
    return NULL;
}

static VOID EdrPolicyUnpinRead(_In_ const EDR_POLICY_V1* Snapshot)
{
    ULONG slot;

    for (slot = 0; slot < EDR_POLICY_SLOTS; slot++) {
        if (&g_PolicySlots[slot].Snapshot == Snapshot) {
            InterlockedDecrement(&g_PolicySlots[slot].Readers);
            MemoryBarrier();
            return;
        }
    }
}

BOOLEAN EdrPolicyIsEnabled(_In_ ULONG MaskBit)
{
    const EDR_POLICY_V1* p = EdrPolicyPinRead();
    BOOLEAN enabled;

    if (p == NULL) {
        return FALSE; /* fail-open */
    }
    enabled = (p->enable_mask & MaskBit) != 0;
    EdrPolicyUnpinRead(p);
    return enabled;
}

/*
 * Return the active generation's enable_mask. Used by ioctl.c to mirror the
 * policy bits into the queue ConfigMask after a successful replace
 * ("no ConfigMask policy ownership": policy.c never writes the queue).
 */
ULONG EdrPolicyGetEnableMask(VOID)
{
    const EDR_POLICY_V1* p = EdrPolicyPinRead();
    ULONG mask;

    if (p == NULL) {
        return 0; /* fail-open */
    }
    mask = p->enable_mask;
    EdrPolicyUnpinRead(p);
    return mask;
}

/*
 * Replace the whole policy table. Caller (ioctl) passed the exact expected
 * size and a fully validated buffer; we still re-validate because this is
 * the single authority for publication and never trusts callers.
 * Rejection keeps the committed generation unchanged and the active index
 * untouched. On success the inactive slot is fully built before the
 * release-barrier + exchange.
 */
NTSTATUS EdrPolicyReplace(_In_ const VOID* Data, _In_ ULONG Size)
{
    EDR_POLICY_V1* target;
    LONG active;
    LONG next;

    if (!g_PolicyInitialized ||
        Data == NULL ||
        Size != sizeof(EDR_POLICY_V1) ||
        EdrPolicyValidate(Data, Size) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&g_PolicyMutex);

    active = InterlockedCompareExchange(&g_ActiveSlot, 0, 0);
    next = 1 - active;
    target = &g_PolicySlots[next].Snapshot;

    /* The inactive slot must be free of readers before we overwrite it.
     * Readers are short-lived pins; if any remain (a writer pinned a reader
     * against us is impossible: writers hold the mutex), wait briefly.
     * Reader pins never block, so this loop terminates under load; a
     * pathological >100ms wait is treated as failure without publishing. */
    {
        ULONG spin = 0;
        while (InterlockedCompareExchange(&g_PolicySlots[next].Readers,
                                          0, 0) != 0) {
            LARGE_INTEGER delay;
            spin++;
            if (spin > 1000) {
                ExReleaseFastMutex(&g_PolicyMutex);
                return STATUS_RETRY;
            }
            delay.QuadPart = -100; /* 10us */
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    memcpy(target, Data, sizeof(*target));
    MemoryBarrier();               /* full build is visible before exchange */
    InterlockedExchange(&g_ActiveSlot, next);
    MemoryBarrier();

    ExReleaseFastMutex(&g_PolicyMutex);
    return STATUS_SUCCESS;
}

/*
 * Bounded case-insensitive normalized NT-path prefix match. Prefixes are
 * stored as UTF-16LE with a leading backslash; the candidate path is a
 * normalized NT path (e.g. \Device\HarddiskVolume1\...). Comparison is
 * limited to the rule's declared length and never scans past the candidate
 * string. Returns the 0-based matched rule index via *RuleIndex.
 */
BOOLEAN EdrPolicyMatchFile(_In_ const WCHAR* Path, _In_ SIZE_T PathChars,
                           _Out_opt_ PULONG RuleIndex)
{
    const EDR_POLICY_V1* p = EdrPolicyPinRead();
    BOOLEAN matched = FALSE;
    ULONG i;

    if (p == NULL || Path == NULL) {
        return FALSE; /* fail-open */
    }

    for (i = 0; i < p->file_rule_count && !matched; i++) {
        const EDR_POLICY_FILE_RULE* r = &p->file_rules[i];
        SIZE_T need = r->length / sizeof(WCHAR);
        SIZE_T j;

        if (need == 0 || need > PathChars) {
            continue;
        }
        for (j = 0; j < need; j++) {
            WCHAR a = Path[j];
            WCHAR b = r->path[j];
            if (a >= L'a' && a <= L'z') a = (WCHAR)(a - L'a' + L'A');
            if (b >= L'a' && b <= L'z') b = (WCHAR)(b - L'a' + L'A');
            if (a != b) {
                break;
            }
        }
        if (j == need) {
            matched = TRUE;
            if (RuleIndex != NULL) {
                *RuleIndex = i;
            }
        }
    }

    EdrPolicyUnpinRead(p);
    return matched;
}

/*
 * Fixed IPv4/port match. ip is four display-order octets; port 0 means
 * "any port". Returns the 0-based matched rule index via *RuleIndex.
 * Bounded to p->net_rule_count <= 64 fixed comparisons.
 */
BOOLEAN EdrPolicyMatchNet(_In_ const UCHAR Ip[4], _In_ USHORT Port,
                          _Out_opt_ PULONG RuleIndex)
{
    const EDR_POLICY_V1* p = EdrPolicyPinRead();
    BOOLEAN matched = FALSE;
    ULONG i;

    if (p == NULL || Ip == NULL) {
        return FALSE; /* fail-open */
    }

    for (i = 0; i < p->net_rule_count && !matched; i++) {
        const EDR_POLICY_NET_RULE* r = &p->net_rules[i];
        if (r->ip[0] == Ip[0] && r->ip[1] == Ip[1] &&
            r->ip[2] == Ip[2] && r->ip[3] == Ip[3] &&
            (r->port == 0 || r->port == Port)) {
            matched = TRUE;
            if (RuleIndex != NULL) {
                *RuleIndex = i;
            }
        }
    }

    EdrPolicyUnpinRead(p);
    return matched;
}
