/*
 * kill_process.c - IOCTL_EDR_KILL_PROCESS kernel response handler.
 *
 * Purpose: give the user-mode agent a kernel-assisted kill for
 * tamper-protected malware (SilverFox / Gh0stRAT lineages strip handle
 * rights from openers and run anti-exit watchdogs, so a plain user-mode
 * TerminateProcess fails with ACCESS_DENIED). This is the defensive
 * counterpart of BYOVD abuse: our own signed driver performs the
 * termination instead of an attacker-imported vulnerable driver.
 *
 * Safety rules (all enforced here):
 *   - the caller must hold the control device open with write access
 *     (enforced by the IOCTL's FILE_WRITE_ACCESS transfer type);
 *   - the calling process itself is never a valid target;
 *   - the caller-supplied PID must resolve to a live process;
 *   - a small critical-system allowlist (System, smss.exe, csrss.exe,
 *     wininit.exe, winlogon.exe) is refused unconditionally: killing
 *     one of these bugchecks the machine and buys nothing;
 *   - termination happens via ZwTerminateProcess with a nonzero status.
 *
 * IRQL: runs at PASSIVE_LEVEL inside the dispatch path.
 */
#include <ntifs.h>
#include "edrdrv.h"
#include "response_policy.h"

/* Process-specific terminate right; kernel headers omit winnt.h's name. */
#define EDR_PROCESS_TERMINATE ((ACCESS_MASK)0x0001u)

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

NTSTATUS EdrKillProcessForResponse(_In_ HANDLE TargetPid,
                                   _In_ HANDLE CallerPid)
{
    PEPROCESS target = NULL;
    NTSTATUS status;

    if (TargetPid == NULL || TargetPid == CallerPid) {
        /* Refuse self-kill and the System idle pseudo-process. */
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(TargetPid, &target);
    if (!NT_SUCCESS(status)) {
        return status == STATUS_INVALID_PARAMETER
            ? STATUS_INVALID_PARAMETER : status;
    }
    if (target == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    {
        const CHAR* image = (const CHAR*)PsGetProcessImageFileName(target);
        /* ImageFileName is bounded to 15 bytes and may lack a terminator. */
        if (EdrIsProtectedResponseImage(image, 15)) {
            ObDereferenceObject(target);
            return STATUS_ACCESS_DENIED;
        }
    }

    /* Bind the handle to the checked object, even if the PID is reused. */
    {
        HANDLE targetHandle = NULL;
        status = ObOpenObjectByPointer(target, OBJ_KERNEL_HANDLE, NULL,
                                       EDR_PROCESS_TERMINATE, NULL, KernelMode,
                                       &targetHandle);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(target);
            return status;
        }

        status = ZwTerminateProcess(targetHandle, STATUS_FATAL_APP_EXIT);
        ZwClose(targetHandle);
    }

    ObDereferenceObject(target);
    return status;
}
