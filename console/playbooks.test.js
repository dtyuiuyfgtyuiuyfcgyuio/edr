'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createRuntime } = require('./server');

async function fixture(t, responseClient, extraEnv = {}) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-playbook-'));
    const runtime = createRuntime({
        dataDir,
        responseClient,
        env: {
            EDR_INGEST_API_KEY: 'ingest-key',
            EDR_ADMIN_API_KEY: 'admin-key',
            EDR_RESPONSE_CHANNEL_ENABLE: 'true',
            ...extraEnv,
        },
        logger: { log() {}, warn() {}, error() {} },
    });
    await runtime.start(0, '127.0.0.1');
    t.after(async () => {
        await new Promise(resolve => runtime.server.close(resolve));
        fs.rmSync(dataDir, { recursive: true, force: true });
    });
    const base = `http://127.0.0.1:${runtime.server.address().port}`;
    async function send(url, key = 'admin-key', method = 'GET', body) {
        return fetch(`${base}${url}`, {
            method,
            headers: {
                'x-api-key': key,
                ...(body === undefined ? {} : { 'content-type': 'application/json' }),
            },
            body: body === undefined ? undefined : JSON.stringify(body),
        });
    }
    async function alert(event) {
        const response = await send('/ingest', 'ingest-key', 'POST', {
            rule: 'EDR-472', severity: 'high', timestamp: '2026-09-25T00:00:00Z', event,
        });
        assert.equal(response.status, 200);
        return (await response.json()).alert.caseId;
    }
    return { dataDir, send, alert };
}

test('playbook refuses missing file identity, stops, and exposes correlated audit', async t => {
    let calls = 0;
    const responseClient = { readiness: async () => { calls += 1; return { effective_mode: 'dry_run' }; } };
    const runtime = await fixture(t, responseClient);
    const caseId = await runtime.alert({ type: 'PROCESS_START', pid: 1234, image: 'C:\\Temp\\sample.exe' });
    const run = await runtime.send('/api/playbooks/ransomware-contain/run', 'admin-key', 'POST', { caseIds: [caseId] });
    assert.equal(run.status, 200);
    const body = await run.json();
    assert.equal(body.ok, false);
    assert.equal(body.overall, 'failed');
    assert.equal(body.steps.length, 1);
    assert.equal(body.steps[0].status, 'target_invalid');
    assert.equal(calls, 0);
    const audit = await runtime.send(`/api/response/audit?runId=${body.runId}&caseId=${caseId}`);
    assert.equal(audit.status, 200);
    const entries = (await audit.json()).records;
    assert.equal(entries.length, 2);
    assert.deepEqual(entries.map(entry => entry.phase), ['outcome', 'attempt']);
    assert.equal(entries[0].status, 'target_invalid');
    assert.equal((await runtime.send(`/api/response/audit?runId=${body.runId}&phase=outcome`)).status, 200);
    assert.equal((await runtime.send('/api/response/audit?runId=bad')).status, 400);
    const chain = await (await runtime.send('/api/audit/chain/verify?file=response', 'admin-key')).json();
    assert.equal(chain.valid, true);
    assert.equal(chain.total, 2);
});

test('manual suspend playbook uses the native dry-run contract and records request ID', async t => {
    let suspendCalls = 0;
    const responseClient = {
        readiness: async () => ({ effective_mode: 'dry_run', capabilities: { suspend: 'dry_run' } }),
        suspend: async ({ target }) => {
            suspendCalls += 1;
            assert.deepEqual(target, { pid: 1234, createTime100ns: '134000000000000000' });
            return { ok: true, status: 'accepted', effective_mode: 'dry_run',
                requestId: '12345678-1234-1234-1234-123456789abc', win32_error: 0 };
        },
    };
    const runtime = await fixture(t, responseClient);
    const caseId = await runtime.alert({ type: 'PROCESS_START', pid: 1234,
        createTime100ns: '134000000000000000' });
    const run = await runtime.send('/api/playbooks/suspend-investigate/run', 'admin-key', 'POST', { caseIds: [caseId] });
    assert.equal(run.status, 200);
    const body = await run.json();
    assert.equal(body.ok, true);
    assert.equal(body.steps[0].status, 'native_dry_run_accepted');
    assert.equal(suspendCalls, 1);
    const audit = await (await runtime.send(`/api/response/audit?runId=${body.runId}&phase=outcome`)).json();
    assert.equal(audit.total, 1);
    assert.equal(audit.records[0].requestId, '12345678-1234-1234-1234-123456789abc');
});

test('failed step and uncertain dispatch prevent later playbook actions', async t => {
    let terminateCalls = 0;
    let quarantineCalls = 0;
    const responseClient = {
        readiness: async () => ({ effective_mode: 'real', capabilities: { terminate: 'real', quarantine: 'real' },
            audit: { available: true, pending: false, writable: true } }),
        terminate: async () => {
            terminateCalls += 1;
            return { ok: false, status: 'policy_rejected', effective_mode: 'real', win32_error: 5 };
        },
        quarantine: async () => { quarantineCalls += 1; throw new Error('must not run'); },
    };
    const runtime = await fixture(t, responseClient, { EDR_ENABLE_PROCESS_TERMINATION: 'true', EDR_ENABLE_QUARANTINE: 'true' });
    const event = { type: 'PROCESS_START', pid: 1234, createTime100ns: '134000000000000000',
        image: 'C:\\Temp\\sample.exe', sha256: 'a'.repeat(64) };
    const caseId = await runtime.alert(event);
    const run = await runtime.send('/api/playbooks/ransomware-contain/run', 'admin-key', 'POST', { caseIds: [caseId] });
    const body = await run.json();
    assert.equal(body.overall, 'failed');
    assert.equal(body.steps.length, 1);
    assert.equal(terminateCalls, 1);
    assert.equal(quarantineCalls, 0);

    responseClient.terminate = async () => {
        terminateCalls += 1;
        const error = new Error('connection closed');
        error.dispatched = true;
        throw error;
    };
    const secondCase = await runtime.alert({ ...event, pid: 1235 });
    const uncertain = await runtime.send('/api/playbooks/ransomware-contain/run', 'admin-key', 'POST',
        { caseIds: [caseId, secondCase] });
    assert.equal(uncertain.status, 503);
    const uncertainBody = await uncertain.json();
    assert.equal(uncertainBody.overall, 'outcome_unknown');
    assert.equal(uncertainBody.steps.length, 1);
    assert.equal(terminateCalls, 2);
    assert.equal(quarantineCalls, 0);
    assert.equal((await runtime.send('/api/playbooks/ransomware-contain/run', 'admin-key', 'POST',
        { caseIds: [caseId, caseId] })).status, 400);
});

test('playbook stops with audit_failed before a real action when audit readiness is unsafe', async t => {
    const states = [
        { available: true, pending: true, writable: false },
        { available: false, pending: false, writable: false },
        undefined,
    ];
    let terminateCalls = 0;
    const responseClient = {
        readiness: async () => ({ effective_mode: 'real', capabilities: { terminate: 'real' },
            audit: states[(terminateCalls + readinessCalls++) % states.length] }),
        terminate: async () => {
            terminateCalls += 1;
            return { ok: true, status: 'terminated', effective_mode: 'real' };
        },
    };
    let readinessCalls = 0;
    const runtime = await fixture(t, responseClient, { EDR_ENABLE_PROCESS_TERMINATION: 'true' });
    for (let index = 0; index < states.length; index += 1) {
        const caseId = await runtime.alert({ type: 'PROCESS_START', pid: 1234 + index,
            createTime100ns: '134000000000000000', image: 'C:\\Temp\\sample.exe',
            sha256: 'a'.repeat(64) });
        const run = await runtime.send('/api/playbooks/ransomware-contain/run', 'admin-key', 'POST',
            { caseIds: [caseId] });
        const body = await run.json();
        assert.equal(body.steps.length, 1);
        assert.equal(body.steps[0].status, 'audit_failed');
        assert.equal(body.overall, 'failed');
        assert.equal(terminateCalls, 0);
    }
    assert.equal(readinessCalls, states.length);
});

test('playbook does not dispatch if the attempt cannot be audited', async t => {
    let calls = 0;
    const responseClient = {
        readiness: async () => { calls += 1; return { effective_mode: 'dry_run' }; },
        suspend: async () => { calls += 1; return {}; },
    };
    const runtime = await fixture(t, responseClient);
    const caseId = await runtime.alert({ type: 'PROCESS_START', pid: 1234,
        createTime100ns: '134000000000000000' });
    fs.mkdirSync(path.join(runtime.dataDir, 'audit.jsonl'));
    const run = await runtime.send('/api/playbooks/suspend-investigate/run', 'admin-key', 'POST',
        { caseIds: [caseId] });
    assert.equal(run.status, 500);
    assert.equal(calls, 0);
});

test('a dry-run step cannot lead into a real isolation step', async t => {
    let isolationCalls = 0;
    const responseClient = {
        readiness: async () => ({ effective_mode: 'real', capabilities: { host_isolation: 'real' } }),
        isolate: async () => { isolationCalls += 1; return { ok: true, status: 'isolated' }; },
    };
    const runtime = await fixture(t, responseClient, {
        EDR_ENABLE_HOST_ISOLATION: 'true',
        EDR_HOST_ISOLATION_MANAGEMENT_IP: '127.0.0.1',
    });
    const caseId = await runtime.alert({ type: 'PROCESS_START', pid: 1234,
        createTime100ns: '134000000000000000', image: 'C:\\Temp\\sample.exe',
        sha256: 'a'.repeat(64) });
    const run = await runtime.send('/api/playbooks/ransomware-contain/run', 'admin-key', 'POST',
        { caseIds: [caseId] });
    const body = await run.json();
    assert.equal(body.overall, 'failed');
    assert.equal(body.steps.length, 3);
    assert.equal(body.steps[0].status, 'local_only');
    assert.equal(body.steps[1].status, 'local_only');
    assert.equal(body.steps[2].status, 'not_ready');
    assert.equal(isolationCalls, 0);
    const audit = await (await runtime.send(`/api/response/audit?runId=${body.runId}&phase=outcome`)).json();
    assert.equal(audit.records[0].error, 'a prior playbook step was dry_run');
});
