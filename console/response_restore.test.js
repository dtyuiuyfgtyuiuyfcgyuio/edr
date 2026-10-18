'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createRuntime } = require('./server');
const { ResponseClient } = require('./response_client');

const quietLogger = { log() {}, warn() {}, error() {} };
const sourceRequestId = 'f1900000-1234-1234-1234-123456789abc';

async function fixture(t, { readiness, restore, restoreError, env = {} } = {}) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-restore-'));
    const calls = [];
    const responseClient = {
        async readiness() {
            calls.push(['readiness']);
            return readiness || {
                ok: true, effective_mode: 'real', status: 'ready',
                capabilities: { quarantine_restore: 'real' },
                audit: { available: true, pending: false, writable: true },
            };
        },
        async restoreQuarantine(input) {
            calls.push(['restoreQuarantine', input]);
            if (restoreError) throw restoreError;
            return restore || {
                ok: true, effective_mode: 'real', status: 'restored',
                requestId: 'native-restore', source_request_id: sourceRequestId,
                restored: true, partial_restore: false, audit_written: true,
                original_path: 'C:\\safe-test\\sample.bin',
                quarantine_path: 'C:\\edr-quarantine\\sample.quarantined',
                sha256: 'a'.repeat(64), sidecar_sha256: 'b'.repeat(64),
                win32_error: 0,
            };
        },
    };
    const runtime = createRuntime({
        dataDir,
        env: {
            EDR_ADMIN_API_KEY: 'admin-secret',
            EDR_RESPONSE_CHANNEL_ENABLE: 'true',
            EDR_ENABLE_QUARANTINE: 'true',
            ...env,
        },
        logger: quietLogger,
        responseClient,
    });
    await runtime.start(0, '127.0.0.1');
    t.after(async () => {
        await new Promise(resolve => runtime.server.close(resolve));
        fs.rmSync(dataDir, { recursive: true, force: true });
    });
    const base = `http://127.0.0.1:${runtime.server.address().port}`;
    const send = (url, { key, body, ...options } = {}) => fetch(`${base}${url}`, {
        ...options,
        headers: {
            ...(body === undefined ? {} : { 'content-type': 'application/json' }),
            ...(key === undefined ? {} : { 'x-api-key': key }),
            ...(options.headers || {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { ...runtime, calls, dataDir, send };
}

test('restore route requires admin, accepts only a source request ID, and dispatches audited native restore', async t => {
    const runtime = await fixture(t);
    const request = {
        method: 'POST',
        body: { reason: 'reviewed recovery', sourceRequestId },
    };
    assert.equal((await runtime.send('/api/response/restore_quarantine', request)).status, 401);
    assert.deepEqual(runtime.calls, []);

    for (const body of [
        { ...request.body, path: 'C:\\caller-controlled.bin' },
        { reason: 'reviewed recovery', sourceRequestId: '../outside-restore-id' },
        { reason: 'reviewed recovery', sourceRequestId: 'bad' },
    ]) {
        const rejected = await runtime.send('/api/response/restore_quarantine', {
            method: 'POST', key: 'admin-secret', body,
        });
        assert.equal(rejected.status, 400);
    }
    assert.equal((await runtime.send('/api/response/restore_quarantine?mode=real', {
        ...request, key: 'admin-secret',
    })).status, 400);
    assert.deepEqual(runtime.calls, []);

    const response = await runtime.send('/api/response/restore_quarantine', {
        ...request, key: 'admin-secret',
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.status, 'restored');
    assert.equal(result.restored, true);
    assert.equal(runtime.calls[0][0], 'readiness');
    assert.deepEqual(runtime.calls[1], ['restoreQuarantine', {
        reason: 'reviewed recovery', sourceRequestId,
    }]);
});

test('restore real mode fails closed when capability or writable audit is unavailable', async t => {
    for (const readiness of [
        { ok: true, effective_mode: 'real', status: 'ready',
            capabilities: { quarantine_restore: 'dry_run' },
            audit: { available: true, pending: false, writable: true } },
        { ok: true, effective_mode: 'real', status: 'ready',
            capabilities: { quarantine_restore: 'real' },
            audit: { available: false, pending: false, writable: false } },
    ]) {
        const runtime = await fixture(t, { readiness });
        const response = await runtime.send('/api/response/restore_quarantine', {
            method: 'POST', key: 'admin-secret',
            body: { reason: 'reviewed recovery', sourceRequestId },
        });
        assert.equal(response.status, 503);
        assert.equal((await response.json()).ok, false);
        assert.equal(runtime.calls.some(call => call[0] === 'restoreQuarantine'), false);
    }
});

test('restore remains local-only while real quarantine is disabled', async t => {
    const runtime = await fixture(t, { env: { EDR_ENABLE_QUARANTINE: 'false' } });
    const response = await runtime.send('/api/response/restore_quarantine', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'reviewed recovery', sourceRequestId },
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.effective_mode, 'dry_run');
    assert.equal(result.status, 'local_only');
    assert.deepEqual(runtime.calls, []);
});

test('restore route reports unknown outcome after a dispatched response fails validation', async t => {
    const dispatchedError = Object.assign(
        new Error('native quarantine restore result was invalid'),
        { dispatched: true });
    const runtime = await fixture(t, { restoreError: dispatchedError });
    const response = await runtime.send('/api/response/restore_quarantine', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'reviewed recovery', sourceRequestId },
    });
    assert.equal(response.status, 503);
    assert.equal((await response.json()).status, 'outcome_unknown');
    assert.equal(runtime.calls.some(call => call[0] === 'restoreQuarantine'), true);
});

test('native restore client sends no path and validates identity and outcome consistency', async () => {
    const client = Object.create(ResponseClient.prototype);
    let sent;
    client.request = async payload => {
        sent = payload;
        return {
            ok: true, requestId: payload.requestId,
            source_request_id: sourceRequestId,
            effective_mode: 'real', status: 'restored', restored: true,
            partial_restore: false, audit_written: true, win32_error: 0,
        };
    };
    const result = await client.restoreQuarantine({
        reason: 'reviewed recovery', sourceRequestId,
    });
    assert.equal(sent.action, 'restore_quarantine');
    assert.equal(sent.sourceRequestId, sourceRequestId);
    assert.deepEqual(Object.keys(sent).sort(), [
        'action', 'reason', 'requestId', 'sourceRequestId', 'timestamp', 'version',
    ]);
    assert.equal(result.restored, true);

    await assert.rejects(client.restoreQuarantine({
        reason: 'reviewed recovery', sourceRequestId: '../outside-restore-id',
    }), /source request ID was invalid/);
    client.request = async payload => ({
        ok: true, requestId: payload.requestId, source_request_id: 'another-source-id',
        effective_mode: 'real', status: 'restored', restored: true,
        partial_restore: false, audit_written: true, win32_error: 0,
    });
    await assert.rejects(client.restoreQuarantine({
        reason: 'reviewed recovery', sourceRequestId,
    }), /native quarantine restore result was invalid/);
    await assert.rejects(client.restoreQuarantine({
        reason: 'reviewed recovery', sourceRequestId,
    }), error => error.message === 'native quarantine restore result was invalid' &&
        error.dispatched === true);
});
