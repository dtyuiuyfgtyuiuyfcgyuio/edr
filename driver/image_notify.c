/*
 * image_notify.c - Image load notify via PsSetLoadImageNotifyRoutine.
 *
 * Collects: process id (header.pid) and the full image path
 * (EDR_TAG_IMAGE_LOADED, utf16le, truncated to EDR_STR_MAX_BYTES). The
 * callback runs inside a critical region with APCs disabled (Microsoft
 * documents this notify routine at PASSIVE_LEVEL); it only reads
 * FullImageName and pushes a bounded event - no allocation, no wait, no
 * paged memory, no query of arbitrary process state. The queue operations
 * below (EdrQueueIsEnabled / EdrQueuePush) use KSPIN_LOCK, which is legal at
 * either DISPATCH_LEVEL or PASSIVE_LEVEL, so the body is safe regardless of
 * the exact level the system uses on a given build.
 *
 * The callback is removed with PsRemoveLoadImageNotifyRoutine (the documented
 * counterpart of PsSetLoadImageNotifyRoutine, exported since Windows 2000).
 * That API waits for any callback invocation already in flight to complete
 * before it returns, so EdrImageNotifyStop() guarantees that after it
 * returns no callback body can run against the queue storage the caller is
 * about to free, AND the callback is gone from the kernel's notify list, so
 * no image load after driver unload can invoke a stale pointer into the
 * unloaded image.
 */
#include "edrdrv.h"

static EDR_QUEUE* volatile g_ImageQueue;

/*
 * Copy a UNICODE_STRING into a bounded WCHAR buffer with explicit
 * termination. Returns byte count (excluding terminator); sets *Truncated
 * when the source did not fit.
 */
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

static VOID EdrImageNotify(_In_opt_ PUNICODE_STRING FullImageName,
                           _In_ HANDLE ProcessId,
                           _In_ PIMAGE_INFO ImageInfo)
{
    EDR_EVENT_HEADER hdr;
    EDR_TLV_HEADER tlv;
    UCHAR payload[EDR_SLOT_SIZE - sizeof(EDR_EVENT_HEADER)];
    WCHAR image[EDR_STR_MAX_BYTES / sizeof(WCHAR)];
    EDR_QUEUE* Q;
    USHORT imageBytes = 0;
    BOOLEAN truncated = FALSE;
    ULONG payloadBytes = 0;

    UNREFERENCED_PARAMETER(ImageInfo);

    /* The queue pointer is only ever cleared after EdrImageNotifyStop()
     * (which removes this callback and waits for in-flight invocations), so
     * reaching the queue here is safe. Read once into a local so the whole
     * body works on one stable snapshot. */
    Q = g_ImageQueue;
    if (Q == NULL || !EdrQueueIsEnabled(Q, EDR_ENABLE_PROCESS)) {
        return;
    }
    if (FullImageName == NULL || FullImageName->Buffer == NULL ||
        FullImageName->Length == 0) {
        return;
    }

    imageBytes = CopyUnicodeBounded(image, sizeof(image), FullImageName,
                                    &truncated);

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = EDR_EVENT_MAGIC;
    hdr.version = (unsigned short)EDR_EVENT_VERSION;
    hdr.type = (unsigned short)EDR_EVT_IMAGE_LOAD;
    KeQuerySystemTime((PLARGE_INTEGER)&hdr.ts_100ns);
    hdr.pid = (unsigned int)(ULONG_PTR)ProcessId;

    tlv.tag = EDR_TAG_IMAGE_LOADED;
    tlv.len = imageBytes;
    memcpy(payload, &tlv, sizeof(tlv));
    memcpy(payload + sizeof(tlv), image, imageBytes);
    payloadBytes = (ULONG)sizeof(tlv) + imageBytes;

    if (truncated) {
        hdr.flags |= EDR_FLAG_TRUNCATED;
    }

    EdrQueuePush(Q, &hdr, payload, payloadBytes);
}

NTSTATUS EdrImageNotifyRegister(_In_ EDR_QUEUE* Q)
{
    NTSTATUS status;

    g_ImageQueue = Q;
    status = PsSetLoadImageNotifyRoutine(EdrImageNotify);
    if (!NT_SUCCESS(status)) {
        g_ImageQueue = NULL;
    }
    return status;
}

/*
 * Remove the image load notify callback. PsRemoveLoadImageNotifyRoutine
 * waits for any invocation already running to finish before returning, so
 * once this returns it is safe for the caller to free the queue storage and
 * for the driver to unload (no future image load will reach a stale
 * pointer into this image). It is a no-op when the callback was never
 * registered (PsSetLoadImageNotifyRoutine failed or was never called); the
 * kernel just does not find the entry to remove. Must be called at
 * PASSIVE_LEVEL (same requirement as the unload path).
 */
VOID EdrImageNotifyStop(VOID)
{
    PsRemoveLoadImageNotifyRoutine(EdrImageNotify);
    g_ImageQueue = NULL;
}