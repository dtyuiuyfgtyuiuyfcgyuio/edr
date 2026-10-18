'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const {
    DELETE_FILE_NATIVE_STATUSES,
    ISOLATE_NATIVE_STATUSES,
    QUARANTINE_NATIVE_STATUSES,
    RESTORE_QUARANTINE_NATIVE_STATUSES,
    RESUME_NATIVE_STATUSES,
    SUSPEND_NATIVE_STATUSES,
    TERMINATE_NATIVE_STATUSES,
    UNISOLATE_NATIVE_STATUSES,
} = require('./response_statuses');
const fatalUtf8 = new TextDecoder('utf-8', { fatal: true });

const MAX_PAYLOAD = 16 * 1024;
const FILETIME_EPOCH = 116444736000000000n;

function nowFiletime() {
    return (BigInt(Date.now()) * 10000n + FILETIME_EPOCH).toString();
}

function readCommandKey(file) {
    if (!file) throw new Error('response command key file is not configured');
    const encoded = fs.readFileSync(file, 'utf8').trim();
    if (!encoded || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded) || encoded.length % 4 !== 0)
        throw new Error('response command key is not valid base64');
    const key = Buffer.from(encoded, 'base64');
    if (key.length < 32 || key.length > 4096)
        throw new Error('response command key must contain 32..4096 bytes');
    return key;
}

function frame(payload, key) {
    const body = Buffer.from(JSON.stringify(payload), 'utf8');
    if (!body.length || body.length > MAX_PAYLOAD) throw new Error('response payload is oversized');
    const result = Buffer.allocUnsafe(4 + body.length + 32);
    result.writeUInt32LE(body.length, 0);
    body.copy(result, 4);
    crypto.createHmac('sha256', key).update(body).digest().copy(result, 4 + body.length);
    return result;
}

function parseFrame(data, key) {
    if (data.length < 36) throw new Error('response frame is truncated');
    const size = data.readUInt32LE(0);
    if (!size || size > MAX_PAYLOAD || data.length !== 4 + size + 32)
        throw new Error('response frame length is invalid');
    const body = data.subarray(4, 4 + size);
    const actual = data.subarray(4 + size);
    const expected = crypto.createHmac('sha256', key).update(body).digest();
    if (!crypto.timingSafeEqual(actual, expected)) throw new Error('response authentication failed');
    return JSON.parse(fatalUtf8.decode(body));
}

class ResponseClient {
    constructor({ pipeName = '\\\\.\\pipe\\edr-response-v1', keyFile, timeoutMs = 5000 } = {}) {
        this.pipeName = pipeName;
        this.key = readCommandKey(keyFile);
        this.timeoutMs = timeoutMs;
    }

    request(payload) {
        const requestFrame = frame(payload, this.key);
        return new Promise((resolve, reject) => {
            const socket = net.createConnection(this.pipeName);
            const chunks = [];
            let total = 0;
            let settled = false;
            let dispatched = false;
            const finish = (error, value) => {
                if (settled) return;
                settled = true;
                socket.destroy();
                if (error) {
                    error.dispatched = dispatched;
                    reject(error);
                } else resolve(value);
            };
            socket.setTimeout(this.timeoutMs, () => finish(new Error('response channel timed out')));
            socket.on('connect', () => {
                dispatched = true;
                socket.end(requestFrame);
            });
            socket.on('data', chunk => {
                total += chunk.length;
                if (total > MAX_PAYLOAD + 36) return finish(new Error('response frame is oversized'));
                chunks.push(chunk);
                if (total >= 4) {
                    const data = Buffer.concat(chunks, total);
                    const expected = 4 + data.readUInt32LE(0) + 32;
                    if (expected > MAX_PAYLOAD + 36) return finish(new Error('response frame length is invalid'));
                    if (total === expected) {
                        try { finish(null, parseFrame(data, this.key)); }
                        catch (error) { finish(error); }
                    } else if (total > expected) finish(new Error('response frame has trailing data'));
                }
            });
            socket.on('error', error => finish(error));
            socket.on('end', () => {
                if (!settled) finish(new Error('response channel closed before a complete response'));
            });
        });
    }

    async readiness() {
        const requestId = crypto.randomUUID();
        const result = await this.request({
            version: 1, requestId, timestamp: nowFiletime(), action: 'readiness',
        });
        if (!result || result.ok !== true || result.requestId !== requestId ||
            result.status !== 'ready' || !['dry_run', 'real'].includes(result.effective_mode))
            throw new Error('native response readiness was invalid');
        if (result.audit !== undefined) {
            const audit = result.audit;
            if (!audit || typeof audit !== 'object' || Array.isArray(audit) ||
                typeof audit.available !== 'boolean' ||
                typeof audit.pending !== 'boolean' ||
                typeof audit.writable !== 'boolean' ||
                audit.writable !== (audit.available && !audit.pending))
                throw new Error('native response audit state was invalid');
        }
        if (result.capabilities !== undefined) {
            const capabilities = result.capabilities;
            if (!capabilities || typeof capabilities !== 'object' || Array.isArray(capabilities))
                throw new Error('native response capabilities were invalid');
            for (const name of ['terminate', 'quarantine', 'quarantine_restore',
                'delete_file', 'suspend', 'resume']) {
                if (capabilities[name] !== undefined &&
                    !['dry_run', 'real'].includes(capabilities[name]))
                    throw new Error('native response capabilities were invalid');
            }
            for (const name of ['host_isolation', 'isolation_status']) {
                if (capabilities[name] !== undefined &&
                    !['unavailable', 'real'].includes(capabilities[name]))
                    throw new Error('native response capabilities were invalid');
            }
        }
        return result;
    }

    async terminate({ reason, target, maxTreeSize, suspendBeforeTerminate }) {
        const requestId = crypto.randomUUID();
        const payload = {
            version: 1, requestId, timestamp: nowFiletime(), action: 'terminate',
            reason, target: { pid: target.pid, createTime100ns: target.createTime100ns },
        };
        if (maxTreeSize !== undefined) payload.maxTreeSize = maxTreeSize;
        if (suspendBeforeTerminate !== undefined)
            payload.suspendBeforeTerminate = suspendBeforeTerminate;
        const result = await this.request(payload);
        if (!result || result.requestId !== requestId ||
            typeof result.ok !== 'boolean' ||
            !TERMINATE_NATIVE_STATUSES.includes(result.status) ||
            !['dry_run', 'real'].includes(result.effective_mode) ||
            typeof result.termination_requested !== 'boolean' ||
            typeof result.exit_observed !== 'boolean' ||
            !Number.isInteger(result.win32_error) || result.win32_error < 0 ||
            result.win32_error > 0xffffffff)
            throw new Error('native response result was invalid');
        return result;
    }

    async quarantine({ reason, target }) {
        const requestId = crypto.randomUUID();
        const result = await this.request({
            version: 1, requestId, timestamp: nowFiletime(), action: 'quarantine',
            reason, target: { path: target.path, sha256: target.sha256 },
        });
        if (!result || result.requestId !== requestId || typeof result.ok !== 'boolean' ||
            !['dry_run', 'real'].includes(result.effective_mode) ||
            !QUARANTINE_NATIVE_STATUSES.includes(result.status) ||
            typeof result.rolled_back !== 'boolean' ||
            !Number.isInteger(result.win32_error) || result.win32_error < 0 ||
            result.win32_error > 0xffffffff ||
            (result.sha256 !== undefined && !/^[a-f0-9]{64}$/i.test(result.sha256)) ||
            (result.sidecar_sha256 !== undefined &&
                !/^[a-f0-9]{64}$/i.test(result.sidecar_sha256)) ||
            (result.quarantine_path !== undefined && typeof result.quarantine_path !== 'string'))
            throw new Error('native quarantine result was invalid');
        return result;
    }

    async restoreQuarantine({ reason, sourceRequestId }) {
        if (typeof sourceRequestId !== 'string' ||
            !/^[A-Za-z0-9-]{16,64}$/.test(sourceRequestId) ||
            !sourceRequestId.includes('-'))
            throw new Error('native quarantine restore source request ID was invalid');
        const requestId = crypto.randomUUID();
        const result = await this.request({
            version: 1, requestId, timestamp: nowFiletime(),
            action: 'restore_quarantine', reason, sourceRequestId,
        });
        try {
            if (!result || result.requestId !== requestId ||
                result.source_request_id !== sourceRequestId ||
                typeof result.ok !== 'boolean' ||
                !['dry_run', 'real'].includes(result.effective_mode) ||
                !RESTORE_QUARANTINE_NATIVE_STATUSES.includes(result.status) ||
                typeof result.restored !== 'boolean' ||
                typeof result.partial_restore !== 'boolean' ||
                typeof result.audit_written !== 'boolean' ||
                !Number.isInteger(result.win32_error) || result.win32_error < 0 ||
                result.win32_error > 0xffffffff ||
                (result.original_path !== undefined &&
                    typeof result.original_path !== 'string') ||
                (result.quarantine_path !== undefined &&
                    typeof result.quarantine_path !== 'string') ||
                (result.sha256 !== undefined &&
                    !/^[a-f0-9]{64}$/i.test(result.sha256)) ||
                (result.sidecar_sha256 !== undefined &&
                    !/^[a-f0-9]{64}$/i.test(result.sidecar_sha256)))
                throw new Error('native quarantine restore result was invalid');
            if ((result.status === 'restored') !== result.restored ||
                (result.status === 'restored' && result.partial_restore) ||
                (result.ok && (!result.audit_written ||
                    !['restored', 'accepted'].includes(result.status))))
                throw new Error('native quarantine restore result was inconsistent');
            return result;
        } catch (error) {
            /* A complete authenticated reply means the native request was
             * dispatched even when its payload violates the response schema. */
            error.dispatched = true;
            throw error;
        }
    }

    async deleteFile({ reason, target }) {
        const requestId = crypto.randomUUID();
        const result = await this.request({
            version: 1, requestId, timestamp: nowFiletime(), action: 'delete_file',
            reason, target: { path: target.path, sha256: target.sha256 },
        });
        if (!result || result.requestId !== requestId ||
            typeof result.ok !== 'boolean' ||
            !['dry_run', 'real'].includes(result.effective_mode) ||
            !DELETE_FILE_NATIVE_STATUSES.includes(result.status) ||
            typeof result.path !== 'string' ||
            typeof result.deleted !== 'boolean' ||
            !Number.isInteger(result.win32_error) || result.win32_error < 0 ||
            result.win32_error > 0xffffffff)
            throw new Error('native delete_file result was invalid');
        return result;
    }

    async setIsolation({ reason, enable, managementIp, allowedPorts }) {
        const requestId = crypto.randomUUID();
        const result = await this.request({
            version: 1, requestId, timestamp: nowFiletime(), action: 'isolate',
            reason, enable, managementIp, allowedPorts,
        });
        const statuses = enable ? ISOLATE_NATIVE_STATUSES : UNISOLATE_NATIVE_STATUSES;
        if (!result || result.requestId !== requestId || typeof result.ok !== 'boolean' ||
            !statuses.includes(result.status) ||
            (result.error !== undefined && typeof result.error !== 'string'))
            throw new Error('native isolation result was invalid');
        return result;
    }

    isolate({ reason, managementIp, allowedPorts }) {
        return this.setIsolation({ reason, enable: true, managementIp, allowedPorts });
    }

    unisolate({ reason, managementIp, allowedPorts }) {
        return this.setIsolation({ reason, enable: false, managementIp, allowedPorts });
    }

    async isolationStatus() {
        const requestId = crypto.randomUUID();
        const result = await this.request({
            version: 1, requestId, timestamp: nowFiletime(), action: 'isolation_status',
        });
        if (!result || result.requestId !== requestId || result.ok !== true ||
            result.status !== 'ready' || typeof result.isolated !== 'boolean')
            throw new Error('native isolation status was invalid');
        if (result.isolated) {
            if (typeof result.managementIp !== 'string' ||
                typeof result.allowedPorts !== 'string' ||
                !Number.isSafeInteger(result.isolatedSinceMs) || result.isolatedSinceMs < 0 ||
                !Number.isSafeInteger(result.elapsedMs) || result.elapsedMs < 0)
                throw new Error('native isolation status was invalid');
        }
        return result;
    }

    async suspend({ reason, target }) {
        const requestId = crypto.randomUUID();
        const result = await this.request({
            version: 1, requestId, timestamp: nowFiletime(), action: 'suspend',
            reason, target: { pid: target.pid, createTime100ns: target.createTime100ns },
        });
        if (!result || result.requestId !== requestId ||
            typeof result.ok !== 'boolean' ||
            !SUSPEND_NATIVE_STATUSES.includes(result.status) ||
            !['dry_run', 'real'].includes(result.effective_mode) ||
            !Number.isInteger(result.win32_error) || result.win32_error < 0 ||
            result.win32_error > 0xffffffff)
            throw new Error('native suspend result was invalid');
        return result;
    }

    async resume({ reason, target }) {
        const requestId = crypto.randomUUID();
        const result = await this.request({
            version: 1, requestId, timestamp: nowFiletime(), action: 'resume',
            reason, target: { pid: target.pid, createTime100ns: target.createTime100ns },
        });
        if (!result || result.requestId !== requestId ||
            typeof result.ok !== 'boolean' ||
            !RESUME_NATIVE_STATUSES.includes(result.status) ||
            !['dry_run', 'real'].includes(result.effective_mode) ||
            !Number.isInteger(result.win32_error) || result.win32_error < 0 ||
            result.win32_error > 0xffffffff)
            throw new Error('native resume result was invalid');
        return result;
    }
}

function assertResponseAuditWritable(readiness) {
    if (readiness?.audit?.writable === true) return;
    const error = new Error('native response audit is unavailable or not writable');
    error.code = 'EDR_RESPONSE_AUDIT_UNAVAILABLE';
    error.status = 'audit_failed';
    error.httpStatus = 503;
    throw error;
}

module.exports = {
    MAX_PAYLOAD,
    ResponseClient,
    assertResponseAuditWritable,
    frame,
    nowFiletime,
    parseFrame,
    readCommandKey,
};
