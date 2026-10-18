'use strict';

/*
 * Shared response status contract used by the native-channel client and the
 * response-audit API. Keep action-specific protocol statuses separate from
 * console transport/readiness states so filters cannot silently reject a
 * legitimate durable record.
 */
const CONSOLE_RESPONSE_STATUSES = Object.freeze([
    'local_only',
    'not_ready',
    'native_not_ready',
    'native_unavailable',
    'native_dry_run_accepted',
    'outcome_unknown',
    'planned',
    'target_invalid',
    /* Readiness may appear in legacy audit exports. */
    'ready',
]);

const TERMINATE_NATIVE_STATUSES = Object.freeze([
    'accepted',
    'rejected',
    'terminated',
    'termination_pending',
    'wait_failed',
    'policy_rejected',
    'critical_check_failed',
    'protection_check_failed',
    'session_check_failed',
    'token_check_failed',
    'identity_check_failed',
    'identity_mismatch',
    'identity_changed',
    'open_failed',
    'terminate_failed',
    'replay',
    'audit_failed',
    'tree_terminated',
    'tree_truncated',
    'partial_tree',
    'child_terminate_failed',
    'suspend_failed',
    'isolation_failed',
    'snapshot_failed',
    /* Legacy console audit vocabulary retained for durable records. */
    'timeout',
    'failed',
]);

const QUARANTINE_NATIVE_STATUSES = Object.freeze([
    'accepted',
    'rejected',
    'quarantined',
    'identity_check_failed',
    'identity_changed',
    'policy_rejected',
    'acl_failed',
    'acl_restore_failed',
    'metadata_seal_failed',
    'sidecar_failed',
    'rollback_conflict',
    'rollback_failed',
    'move_failed',
    'destination_exists',
    'quarantine_setup_failed',
    'open_failed',
    'file_too_large',
    'path_resolution_failed',
    'cross_volume',
    'hash_failed',
    'hash_mismatch',
    'replay',
    'audit_failed',
    /* Legacy console audit vocabulary retained for durable records. */
    'failed',
]);

const RESTORE_QUARANTINE_NATIVE_STATUSES = Object.freeze([
    'accepted',
    'rejected',
    'policy_rejected',
    'not_restorable',
    'metadata_invalid',
    'quarantine_setup_failed',
    'quarantine_file_missing',
    'identity_check_failed',
    'identity_changed',
    'content_mismatch',
    'file_too_large',
    'hash_failed',
    'path_resolution_failed',
    'destination_exists',
    'move_failed',
    'restore_acl_failed',
    'restored',
    'unavailable',
    'replay',
    'audit_failed',
]);

const ISOLATE_NATIVE_STATUSES = Object.freeze([
    'isolated',
    'enable_failed',
    'policy_mismatch',
    'unavailable',
    'replay',
    'audit_failed',
]);

const UNISOLATE_NATIVE_STATUSES = Object.freeze([
    'restored',
    'disable_failed',
    'policy_mismatch',
    'unavailable',
    'replay',
    'audit_failed',
]);

const DELETE_FILE_NATIVE_STATUSES = Object.freeze([
    'accepted',
    'rejected',
    'policy_rejected',
    'hash_mismatch',
    'already_gone',
    'deleted',
    'scheduled_for_delete',
    'delete_failed',
    'replay',
    'audit_failed',
]);

const SUSPEND_NATIVE_STATUSES = Object.freeze([
    'accepted',
    'rejected',
    'suspended',
    'suspend_failed',
    'policy_rejected',
    'identity_mismatch',
    'identity_changed',
    'identity_check_failed',
    'critical_check_failed',
    'protection_check_failed',
    'session_check_failed',
    'token_check_failed',
    'open_failed',
    'replay',
    'audit_failed',
]);

const RESUME_NATIVE_STATUSES = Object.freeze([
    'accepted',
    'rejected',
    'resumed',
    'resume_failed',
    'policy_rejected',
    'identity_mismatch',
    'identity_changed',
    'identity_check_failed',
    'critical_check_failed',
    'protection_check_failed',
    'session_check_failed',
    'token_check_failed',
    'open_failed',
    'replay',
    'audit_failed',
]);

function combined(...groups) {
    return Object.freeze([...new Set(groups.flat())].sort());
}

const RESPONSE_AUDIT_STATUSES_BY_ACTION = Object.freeze({
    terminate: combined(CONSOLE_RESPONSE_STATUSES, TERMINATE_NATIVE_STATUSES),
    quarantine: combined(CONSOLE_RESPONSE_STATUSES, QUARANTINE_NATIVE_STATUSES),
    restore_quarantine: combined(CONSOLE_RESPONSE_STATUSES, RESTORE_QUARANTINE_NATIVE_STATUSES),
    isolate: combined(CONSOLE_RESPONSE_STATUSES, ISOLATE_NATIVE_STATUSES),
    unisolate: combined(CONSOLE_RESPONSE_STATUSES, UNISOLATE_NATIVE_STATUSES),
    delete_file: combined(CONSOLE_RESPONSE_STATUSES, DELETE_FILE_NATIVE_STATUSES),
    suspend: combined(CONSOLE_RESPONSE_STATUSES, SUSPEND_NATIVE_STATUSES),
    resume: combined(CONSOLE_RESPONSE_STATUSES, RESUME_NATIVE_STATUSES),
});

const RESPONSE_AUDIT_STATUSES = combined(
    ...Object.values(RESPONSE_AUDIT_STATUSES_BY_ACTION));

/**
 * Reports whether a durable audit record with this action/status pair is
 * a legitimate native or console outcome.
 *
 * @param {string} action One of terminate, quarantine, isolate, unisolate.
 * @param {string} status Protocol or console transport status.
 * @returns {boolean} True when the pair is accepted by the audit filter.
 */
function responseAuditStatusSupported(action, status) {
    const statuses = RESPONSE_AUDIT_STATUSES_BY_ACTION[action];
    return Array.isArray(statuses) && statuses.includes(status);
}

module.exports = {
    CONSOLE_RESPONSE_STATUSES,
    DELETE_FILE_NATIVE_STATUSES,
    ISOLATE_NATIVE_STATUSES,
    QUARANTINE_NATIVE_STATUSES,
    RESTORE_QUARANTINE_NATIVE_STATUSES,
    RESPONSE_AUDIT_STATUSES,
    RESPONSE_AUDIT_STATUSES_BY_ACTION,
    RESUME_NATIVE_STATUSES,
    SUSPEND_NATIVE_STATUSES,
    TERMINATE_NATIVE_STATUSES,
    UNISOLATE_NATIVE_STATUSES,
    responseAuditStatusSupported,
};
