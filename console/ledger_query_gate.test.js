'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createRuntime } = require('./server');
const { appendChainedRecord, verifyFileStream } = require('./audit_chain');
const { loadIncidentsAsync } = require('./incidents');

const routes = [
    '/api/audit/chain/verify?file=incidents',
    '/api/incidents',
    '/api/incidents/summary',
    '/api/incidents/INC-1',
    '/api/incidents/INC-1/graph',
];

/* Delay only disk readers; route admission, validation, replay, integrity,
 * serialization and HTTP responses all run through production code. */
function readers() {
    const calls = [];
    let holding = true;
    let holdLimit = 2;
    let heldCount = 0;
    let failure;
    const wrap = (kind, read) => (...args) => {
        const call = { kind, args };
        calls.push(call);
        if (failure && failure.kind === kind) {
            const current = failure;
            failure = undefined;
            if (current.synchronous) throw current.error;
            return Promise.reject(current.error);
        }
        if (!holding || heldCount >= holdLimit) return read(...args);
        heldCount += 1;
        return new Promise(resolve => { call.release = resolve; }).then(() => read(...args));
    };
    return {
        calls,
        dependencies: {
            verifyFileStream: wrap('audit', verifyFileStream),
            loadIncidentsAsync: wrap('incidents', loadIncidentsAsync),
        },
        release(index) { calls[index].release(); },
        holdAnother() { holdLimit += 1; },
        releaseAll() {
            holding = false;
            for (const call of calls) if (call.release) call.release();
        },
        failNext(kind, synchronous) {
            failure = { kind, synchronous, error: new Error('controlled disk failure') };
        },
        async waitFor(count) {
            const deadline = Date.now() + 1500;
            while (calls.length < count && Date.now() < deadline)
                await new Promise(resolve => setTimeout(resolve, 5));
            assert.equal(calls.length, count, 'expected held scans to enter the reader');
        },
    };
}

async function fixture(t, controlled, env = {}) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-ledger-gate-'));
    const runtime = createRuntime({
        dataDir,
        env: { EDR_READ_API_KEY: 'reader', EDR_INGEST_API_KEY: 'writer', ...env },
        logger: { log() {}, warn() {}, error() {} },
        ...(controlled ? { ledgerReaders: controlled.dependencies } : {}),
    });
    await runtime.start(0, '127.0.0.1');
    const pending = [];
    t.after(async () => {
        if (controlled) controlled.releaseAll();
        await Promise.allSettled(pending);
        runtime.server.closeAllConnections();
        await new Promise(resolve => runtime.server.close(resolve));
        fs.rmSync(dataDir, { recursive: true, force: true });
    });
    const send = (route, key = 'reader') => {
        const request = (async () => {
            const response = await fetch(`http://127.0.0.1:${runtime.server.address().port}${route}`, {
                headers: key === undefined ? {} : { 'x-api-key': key },
                signal: AbortSignal.timeout(10000),
            });
            return { status: response.status, body: await response.json(), headers: response.headers };
        })();
        pending.push(request);
        return request;
    };
    return { ...runtime, dataDir, send };
}

function assertBusy(response) {
    assert.equal(response.status, 503);
    assert.equal(response.body.code, 'ledger_query_busy');
    assert.equal(response.headers.get('retry-after'), '1');
    assert.equal(Object.hasOwn(response.body, 'integrity'), false);
    assert.equal(Object.hasOwn(response.body, 'completeness'), false);
}

test('HTTP audit and all incident routes share two slots and refuse scans without queuing', async t => {
    const controlled = readers();
    const runtime = await fixture(t, controlled, { EDR_LEDGER_QUERY_ACTIVE: '99' });
    const first = runtime.send(routes[0]);
    const second = runtime.send(routes[1]);
    await controlled.waitFor(2);
    assert.deepEqual(controlled.calls.map(call => call.kind).sort(), ['audit', 'incidents']);
    assert.deepEqual(controlled.calls.find(call => call.kind === 'audit').args, [
        path.join(runtime.dataDir, 'incidents.jsonl'),
        { maxFileBytes: 268435456, maxRecordBytes: 65536, maxRecords: 200000 },
    ]);
    assert.deepEqual(controlled.calls.find(call => call.kind === 'incidents').args, [runtime.dataDir]);
    for (const route of [...routes, '/api/incidents?active=99']) assertBusy(await runtime.send(route));
    assert.equal(controlled.calls.length, 2, 'busy responses must not invoke either reader');
    const auditIndex = controlled.calls.findIndex(call => call.kind === 'audit');
    controlled.release(auditIndex);
    assert.equal((await first).status, 200);
    controlled.holdAnother();
    const replacement = runtime.send(routes[2]);
    await controlled.waitFor(3);
    assertBusy(await runtime.send(routes[0]));
    controlled.releaseAll();
    assert.equal((await replacement).status, 200);
    assert.equal((await second).status, 200);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(controlled.calls.length, 3, 'refused scans must not run later');
});

test('HTTP authentication and existing validation run before busy admission', async t => {
    const controlled = readers();
    const runtime = await fixture(t, controlled);
    const first = runtime.send(routes[0]);
    const second = runtime.send(routes[1]);
    await controlled.waitFor(2);
    for (const route of routes) {
        assert.equal((await runtime.send(route, 'writer')).status, 401, route);
        assert.equal((await runtime.send(route, '')).status, 401, route);
    }
    for (const route of [
        '/api/audit/chain/verify?file=unsupported',
        '/api/audit/chain/verify?file=incidents&active=99',
        '/api/incidents?severity=unsupported',
        '/api/incidents?state=unsupported',
        '/api/incidents?min_score=101',
        '/api/incidents/summary?unused=1',
        `/api/incidents/${'i'.repeat(65)}`,
        '/api/incidents/INC-1/graph?unused=1',
    ]) assert.equal((await runtime.send(route)).status, 400, route);
    assert.equal(controlled.calls.length, 2);
    controlled.releaseAll();
    await Promise.all([first, second]);
    assert.equal((await runtime.send(routes[2])).status, 200);
});

test('HTTP identical requests each scan and different runtime apps have independent slots', async t => {
    const controlled = readers();
    const firstRuntime = await fixture(t, controlled);
    const secondRuntime = await fixture(t);
    const first = firstRuntime.send(routes[1]);
    const second = firstRuntime.send(routes[1]);
    await controlled.waitFor(2);
    assertBusy(await firstRuntime.send(routes[1]));
    assert.equal((await secondRuntime.send(routes[1])).status, 200);
    assert.equal((await secondRuntime.send(routes[0])).status, 200);
    assert.equal(controlled.calls.length, 2);
    controlled.releaseAll();
    await Promise.all([first, second]);
    assert.equal((await firstRuntime.send(routes[1])).status, 200);
    assert.equal(controlled.calls.length, 3);
});

for (const kind of ['audit', 'incidents']) {
    for (const synchronous of [true, false]) {
        test(`HTTP ${kind} ${synchronous ? 'throw' : 'rejection'} releases its slot`, async t => {
            const controlled = readers();
            const runtime = await fixture(t, controlled);
            const held = runtime.send(routes[1]);
            await controlled.waitFor(1);
            const route = kind === 'audit' ? routes[0] : routes[1];
            controlled.failNext(kind, synchronous);
            assert.equal((await runtime.send(route)).status, 500);
            controlled.failNext(kind, synchronous);
            assert.equal((await runtime.send(route)).status, 500, 'failure must not leak a slot');
            const recovered = runtime.send(routes[0]);
            await controlled.waitFor(4);
            assertBusy(await runtime.send(routes[2]));
            controlled.releaseAll();
            assert.equal((await recovered).status, 200);
            assert.equal((await held).status, 200);
        });
    }
}

test('HTTP released slots re-read changed, deleted, oversized and over-capacity ledgers', async t => {
    const controlled = readers();
    const runtime = await fixture(t, controlled);
    const file = path.join(runtime.dataDir, 'incidents.jsonl');
    appendChainedRecord(file, { id: 'INC-1', kind: 'open', host: 'original-host' });
    const first = runtime.send(routes[0]);
    const second = runtime.send(routes[1]);
    await controlled.waitFor(2);
    assertBusy(await runtime.send(routes[2]));
    controlled.releaseAll();
    assert.equal((await first).body.valid, true);
    assert.equal((await second).body.incidents[0].host, 'original-host');

    fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('original-host', 'modified-host'));
    for (const route of routes.slice(1)) {
        const response = await runtime.send(route);
        assert.equal(response.status, 503, route);
        assert.equal(response.body.integrity.status, 'broken');
        assert.equal(JSON.stringify(response.body).includes('modified-host'), false);
    }
    assert.equal((await runtime.send(routes[0])).body.valid, false);
    fs.unlinkSync(file);
    assert.equal((await runtime.send(routes[0])).body.status, 'missing');
    for (const route of routes.slice(1)) {
        const response = await runtime.send(route);
        assert.equal(response.status, route.includes('/INC-1') ? 404 : 200, route);
        assert.equal(response.body.integrity.status, 'missing');
        assert.equal(response.body.completeness.status, 'complete');
    }

    fs.writeFileSync(file, '');
    fs.truncateSync(file, 268435457);
    const auditOversized = await runtime.send(routes[0]);
    assert.equal(auditOversized.status, 503);
    assert.equal(auditOversized.body.status, 'limit_exceeded');
    for (const route of routes.slice(1)) {
        const response = await runtime.send(route);
        assert.equal(response.status, 503, route);
        assert.equal(response.body.completeness.status, 'limit_exceeded');
        assert.equal(response.body.completeness.reason, 'file_bytes');
    }

    const records = [];
    for (let index = 0; index <= 50000; index += 1)
        records.push(JSON.stringify({ id: `INC-${index}`, kind: 'open' }));
    fs.writeFileSync(file, `${records.join('\n')}\n`);
    for (const route of routes.slice(1)) {
        const response = await runtime.send(route);
        assert.equal(response.status, 503, route);
        assert.equal(response.body.error, 'incident replay incomplete');
        assert.equal(response.body.completeness.status, 'limit_exceeded');
        assert.equal(response.body.completeness.reason, 'state_count');
    }
    fs.writeFileSync(file, `${JSON.stringify({ id: 'INC-1', kind: 'open', host: 'restored-host' })}\n`);
    assert.equal((await runtime.send(routes[1])).body.incidents[0].host, 'restored-host');
});
