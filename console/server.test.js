const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { LIMITS, createRuntime, readJsonLinesTail, readJsonLinesTailAsync } = require('./server');
const { frame, parseFrame } = require('./response_client');
const { RESPONSE_AUDIT_STATUSES_BY_ACTION } = require('./response_statuses');
const { appendChainedRecord } = require('./audit_chain');

const quietLogger = { log() {}, warn() {}, error() {} };

// Test a native loopback HTTP server without Fetch's browser port denylist.
// Windows listen(0) may assign a restricted browser port; no retry/rebind is
// needed because node:http supports the server's actual assigned address.
function localHttpRequest(url, { method = 'GET', headers, body } = {}) {
    return new Promise((resolve, reject) => {
        const request = http.request(url, { method, headers }, response => {
            const chunks = [];
            response.on('data', chunk => chunks.push(chunk));
            response.on('error', reject);
            response.on('end', () => {
                try {
                    const emptyBody = [204, 205, 304].includes(response.statusCode);
                    resolve(new Response(emptyBody ? null : Buffer.concat(chunks), {
                        status: response.statusCode,
                        statusText: response.statusMessage,
                        headers: response.headers,
                    }));
                } catch (error) { reject(error); }
            });
        });
        request.on('error', reject);
        request.end(body);
    });
}

test('response binary frame authenticates exact payload bytes', () => {
    const key = Buffer.alloc(32, 0x5a);
    const payload = { version: 1, requestId: '12345678-1234-1234-1234-123456789abc' };
    const encoded = frame(payload, key);
    assert.deepEqual(parseFrame(encoded, key), payload);
    encoded[5] ^= 1;
    assert.throws(() => parseFrame(encoded, key), /authentication failed/);
});

async function fixture(t, env = {}, options = {}) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-'));
    const runtime = createRuntime({ dataDir, env, logger: quietLogger, ...options });
    await runtime.start(0, '127.0.0.1');
    t.after(async () => {
        await new Promise(resolve => runtime.server.close(resolve));
        fs.rmSync(dataDir, { recursive: true, force: true });
    });
    const base = `http://127.0.0.1:${runtime.server.address().port}`;
    const send = (url, { key, body, ...options } = {}) => localHttpRequest(`${base}${url}`, {
        ...options,
        headers: {
            ...(body === undefined ? {} : { 'content-type': 'application/json' }),
            ...(key === undefined ? {} : { 'x-api-key': key }),
            ...(options.headers || {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { ...runtime, base, dataDir, send };
}

test('incident queries fail closed after chained record tampering and retain read role', async t => {
    const runtime = await fixture(t, { EDR_READ_API_KEY: 'reader', EDR_INGEST_API_KEY: 'writer' });
    const file = path.join(runtime.dataDir, 'incidents.jsonl');
    const record = { id: 'INC-1', kind: 'open', severity: 'high', host: 'host-a', score: 80 };
    appendChainedRecord(file, record);
    const routes = ['/api/incidents', '/api/incidents/summary', '/api/incidents/INC-1', '/api/incidents/INC-1/graph'];
    assert.equal((await runtime.send(routes[0], { key: 'writer' })).status, 401);
    assert.equal((await runtime.send(routes[0], { key: 'reader' })).status, 200);
    fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('host-a', 'host-b'));
    for (const route of routes) {
        const response = await runtime.send(route, { key: 'reader' });
        assert.equal(response.status, 503, route);
        const body = await response.json();
        assert.equal(body.integrity.status, 'broken');
        assert.equal(JSON.stringify(body).includes('host-b'), false);
    }
});

test('incident queries expose missing and legacy integrity states', async t => {
    const runtime = await fixture(t, { EDR_READ_API_KEY: 'reader' });
    const file = path.join(runtime.dataDir, 'incidents.jsonl');
    const missing = await (await runtime.send('/api/incidents', { key: 'reader' })).json();
    assert.equal(missing.integrity.status, 'missing');
    assert.deepEqual(missing.incidents, []);
    fs.writeFileSync(file, `${JSON.stringify({ id: 'INC-OLD', kind: 'open', host: 'legacy-host' })}\n`);
    const legacy = await (await runtime.send('/api/incidents', { key: 'reader' })).json();
    assert.equal(legacy.integrity.status, 'legacy');
    assert.equal(legacy.integrity.legacyPrefix, 1);
    assert.equal(legacy.incidents[0].host, 'legacy-host');
    appendChainedRecord(file, { id: 'INC-NEW', kind: 'open', host: 'new-host' });
    const mixed = await (await runtime.send('/api/incidents', { key: 'reader' })).json();
    assert.equal(mixed.integrity.status, 'mixed');
    assert.equal(mixed.integrity.legacyPrefix, 1);
    assert.equal(mixed.incidents.length, 2);
    assert.equal((await runtime.send('/api/incidents/INC-OLD', { key: 'reader' })).status, 200);
    assert.equal((await runtime.send('/api/incidents/INC-NEW', { key: 'reader' })).status, 200);
});

test('incident queries reject a parseable unfinished append', async t => {
    const runtime = await fixture(t, { EDR_READ_API_KEY: 'reader' });
    const file = path.join(runtime.dataDir, 'incidents.jsonl');
    appendChainedRecord(file, { id: 'INC-1', kind: 'open', host: 'host-a' });
    fs.appendFileSync(file, JSON.stringify({ id: 'INC-2', kind: 'open', host: 'uncommitted' }));
    const response = await runtime.send('/api/incidents', { key: 'reader' });
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.equal(body.integrity.status, 'broken');
    assert.equal(JSON.stringify(body).includes('uncommitted'), false);
});

test('incident routes preserve the unreadable ledger response', async t => {
    const runtime = await fixture(t, { EDR_READ_API_KEY: 'reader' });
    fs.mkdirSync(path.join(runtime.dataDir, 'incidents.jsonl'));
    const response = await runtime.send('/api/incidents/summary', { key: 'reader' });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), {
        error: 'incident ledger unavailable',
        integrity: { status: 'unreadable' },
    });
});

test('incident list pagination returns newest records first and keeps reader authorization', async t => {
    const runtime = await fixture(t, { EDR_READ_API_KEY: 'reader', EDR_INGEST_API_KEY: 'writer' });
    const file = path.join(runtime.dataDir, 'incidents.jsonl');
    fs.writeFileSync(file, [
        JSON.stringify({ id: 'oldest', kind: 'open', lastSeen100ns: 1 }),
        JSON.stringify({ id: 'middle', kind: 'open', lastSeen100ns: 2 }),
        JSON.stringify({ id: 'newest', kind: 'open', lastSeen100ns: 3 }),
    ].join('\n') + '\n');

    assert.equal((await runtime.send('/api/incidents?limit=1&offset=0', { key: 'writer' })).status, 401);
    const newest = await (await runtime.send('/api/incidents?limit=1&offset=0', { key: 'reader' })).json();
    const next = await (await runtime.send('/api/incidents?limit=1&offset=1', { key: 'reader' })).json();
    assert.equal(newest.incidents[0].id, 'newest');
    assert.equal(next.incidents[0].id, 'middle');
    assert.equal(newest.total, 3);
});

test('all incident routes fail closed when replay crosses the record ceiling', async t => {
    const runtime = await fixture(t, { EDR_READ_API_KEY: 'reader' });
    const { MAX_RECORDS_SCANNED } = require('./incidents');
    const file = path.join(runtime.dataDir, 'incidents.jsonl');
    const rows = [JSON.stringify({ id: 'known', kind: 'open', host: 'private-host' })];
    for (let index = 1; index < MAX_RECORDS_SCANNED; index += 1)
        rows.push(JSON.stringify({ id: `noise-${index}`, kind: 'open', lastSeen100ns: index }));
    rows.push(JSON.stringify({ id: 'known', kind: 'incident', host: 'private-host', lastSeen100ns: 200001 }));
    fs.writeFileSync(file, rows.join('\n') + '\n');

    const routes = ['/api/incidents', '/api/incidents/summary', '/api/incidents/known', '/api/incidents/known/graph'];
    for (const route of routes) {
        const response = await runtime.send(route, { key: 'reader' });
        assert.equal(response.status, 503, route);
        const body = await response.json();
        assert.deepEqual(Object.keys(body).sort(), ['completeness', 'error', 'integrity']);
        assert.equal(body.error, 'incident replay incomplete');
        assert.deepEqual(body.completeness, {
            status: 'limit_exceeded', scanned: MAX_RECORDS_SCANNED,
            limit: MAX_RECORDS_SCANNED, reason: 'record_count',
        });
        assert.deepEqual(body.integrity, { status: 'unavailable', reason: 'record_count' });
        assert.equal(JSON.stringify(body).includes('private-host'), false);
        assert.equal(Object.hasOwn(body, 'incidents'), false);
        assert.equal(Object.hasOwn(body, 'summary'), false);
    }
});

test('incident query window includes states beyond the former 1000-result cap', async t => {
    const runtime = await fixture(t, { EDR_READ_API_KEY: 'reader' });
    const file = path.join(runtime.dataDir, 'incidents.jsonl');
    const rows = Array.from({ length: 1005 }, (_, index) => JSON.stringify({
        id: `case-${index}`,
        kind: 'open',
        severity: index === 0 ? 'critical' : 'low',
        host: index === 0 ? 'old-host' : `host-${index}`,
        lastSeen100ns: index,
    }));
    fs.writeFileSync(file, `${rows.join('\n')}\n`);

    const all = await (await runtime.send('/api/incidents?limit=1000', { key: 'reader' })).json();
    assert.equal(all.total, 1005);
    assert.equal(all.summary.total, 1005);
    assert.equal(all.incidents.length, 1000);
    assert.equal(all.completeness.status, 'complete');
    const lastPage = await (await runtime.send('/api/incidents?limit=1000&offset=1000', { key: 'reader' })).json();
    assert.equal(lastPage.total, 1005);
    assert.equal(lastPage.incidents.length, 5);
    assert.equal(lastPage.incidents.at(-1).id, 'case-0');
    const summary = await (await runtime.send('/api/incidents/summary', { key: 'reader' })).json();
    assert.equal(summary.total, 1005);
    assert.equal(summary.completeness.status, 'complete');

    const filtered = await (await runtime.send('/api/incidents?severity=critical', { key: 'reader' })).json();
    assert.equal(filtered.total, 1);
    assert.equal(filtered.incidents[0].id, 'case-0');

    const detail = await runtime.send('/api/incidents/case-0', { key: 'reader' });
    assert.equal(detail.status, 200);
    assert.equal((await detail.json()).incident.id, 'case-0');
});

test('incident q filter totals, summary, and pagination include matches beyond 200', async t => {
    const runtime = await fixture(t, { EDR_READ_API_KEY: 'reader' });
    const file = path.join(runtime.dataDir, 'incidents.jsonl');
    const rows = Array.from({ length: 250 }, (_, index) => JSON.stringify({
        id: `search-case-${index}`,
        kind: 'open',
        severity: 'medium',
        host: `shared-host-${index}`,
        lastSeen100ns: index,
    }));
    fs.writeFileSync(file, `${rows.join('\n')}\n`);

    const firstPage = await (await runtime.send('/api/incidents?q=shared&limit=50', { key: 'reader' })).json();
    assert.equal(firstPage.total, 250);
    assert.equal(firstPage.summary.total, 250);
    assert.equal(firstPage.summary.bySeverity.medium, 250);
    assert.equal(firstPage.completeness.status, 'complete');
    assert.equal(firstPage.incidents.length, 50);

    const afterFormerCap = await (await runtime.send('/api/incidents?q=shared&limit=50&offset=200', { key: 'reader' })).json();
    assert.equal(afterFormerCap.total, 250);
    assert.equal(afterFormerCap.summary.total, 250);
    assert.equal(afterFormerCap.completeness.status, 'complete');
    assert.equal(afterFormerCap.incidents.length, 50);
    assert.equal(afterFormerCap.incidents[0].id, 'search-case-49');
    assert.equal(afterFormerCap.incidents.at(-1).id, 'search-case-0');
});

test('audit chain verification endpoint reports bounded stream limit failures', async t => {
    const runtime = await fixture(t, { EDR_READ_API_KEY: 'reader' });
    const file = path.join(runtime.dataDir, 'alerts.jsonl');
    appendChainedRecord(file, { rule: 'small-record' });
    const verifiedResponse = await runtime.send('/api/audit/chain/verify?file=alerts', { key: 'reader' });
    assert.equal(verifiedResponse.status, 200);
    const verified = await verifiedResponse.json();
    assert.equal(verified.status, 'verified');
    assert.equal(verified.valid, true);
    assert.equal(verified.total, 1);
    assert.equal(verified.legacyPrefix, 0);
    assert.ok(Array.isArray(verified.issues));

    fs.writeFileSync(file, `${JSON.stringify({ rule: 'too-large', value: 'x'.repeat(70 * 1024) })}\n`);

    const response = await runtime.send('/api/audit/chain/verify?file=alerts', { key: 'reader' });
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.equal(body.status, 'limit_exceeded');
    assert.equal(body.limit, 'record_bytes');
    assert.equal(body.valid, false);
    assert.equal(body.total, 0);
    assert.ok(Array.isArray(body.issues));
});

test('role keys are separate, legacy fallback works, and query keys are rejected', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'ingest-secret',
        EDR_READ_API_KEY: 'read-secret',
        EDR_ADMIN_API_KEY: 'admin-secret',
        EDR_API_KEY: 'legacy-secret',
    });
    assert.equal((await runtime.send('/api/stats', { key: 'ingest-secret' })).status, 401);
    assert.equal((await runtime.send('/api/stats', { key: 'read-secret' })).status, 200);
    assert.equal((await runtime.send('/api/stats?api_key=read-secret')).status, 400);
    assert.equal((await runtime.send('/ingest', {
        method: 'POST', key: 'legacy-secret', body: { rule: 'R1', severity: 'high' },
    })).status, 401);

    const legacy = await fixture(t, { EDR_API_KEY: 'legacy-secret' });
    assert.equal((await legacy.send('/api/stats', { key: 'legacy-secret' })).status, 200);
    assert.equal((await legacy.send('/api/response/terminate', {
        method: 'POST', key: 'legacy-secret', body: { reason: 'test', target: { pid: 10, createTime100ns: '123' } },
    })).status, 503);
});

test('non-loopback binding fails closed without ingest and read keys', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-bind-'));
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    const runtime = createRuntime({ dataDir, env: {}, logger: quietLogger });
    await assert.rejects(runtime.start(0, '0.0.0.0'), /requires ingest and read API keys/);
});

test('legacy ruleId records load as canonical rule and conflicting schemas fail', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-schema-'));
    fs.writeFileSync(path.join(dataDir, 'alerts.jsonl'), `${JSON.stringify({
        ruleId: 'EDR-OLD', severity: 'high', timestamp: '2026-01-01T00:00:00Z', event: { type: 'PROCESS_START' },
    })}\n`);
    const runtime = createRuntime({ dataDir, env: {}, logger: quietLogger });
    await runtime.start(0, '127.0.0.1');
    t.after(async () => {
        await new Promise(resolve => runtime.server.close(resolve));
        fs.rmSync(dataDir, { recursive: true, force: true });
    });
    const base = `http://127.0.0.1:${runtime.server.address().port}`;
    const loaded = await (await localHttpRequest(`${base}/api/alerts`)).json();
    assert.equal(loaded.alerts[0].rule, 'EDR-OLD');
    assert.equal('ruleId' in loaded.alerts[0], false);
    assert.equal(loaded.total >= 1, true);
    const before = fs.readFileSync(path.join(dataDir, 'alerts.jsonl'), 'utf8');
    const conflict = await localHttpRequest(`${base}/ingest`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ rule: 'NEW', ruleId: 'OLD', severity: 'high' }),
    });
    assert.equal(conflict.status, 400);
    assert.equal(fs.readFileSync(path.join(dataDir, 'alerts.jsonl'), 'utf8'), before);
});

test('actual native reporter schema preserves FILETIME event time and fields', async t => {
    const runtime = await fixture(t, { EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'reader' });
    const payload = {
        rule: 'EDR-001', severity: 'high', action: 'alert',
        ts_100ns: '134296776001230000', pid: 4242, type: 'PROCESS_START',
        fields: { image: 'C:\\Windows\\System32\\cmd.exe', source: 'etw' },
        mitre_attack: ['T1059.001', 'T1059'],
        mitre_tactic: ['Execution'],
    };
    const response = await runtime.send('/ingest', {
        method: 'POST', key: 'sensor-key', body: payload,
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.alert.rule, 'EDR-001');
    assert.equal(result.alert.event.pid, 4242);
    assert.equal(result.alert.event.image, payload.fields.image);
    assert.deepEqual(result.alert.mitre_attack, ['T1059.001', 'T1059']);
    assert.deepEqual(result.alert.mitre_tactic, ['Execution']);
    assert.deepEqual(result.alert.event.mitre_attack, ['T1059.001', 'T1059']);
    assert.deepEqual(result.alert.event.mitre_tactic, ['Execution']);
    assert.equal(result.alert.timestamp, new Date(Number((BigInt(payload.ts_100ns) - 116444736000000000n) / 10000n)).toISOString());
});

test('Falco ingestion validates official fields, preserves bounded raw data, and ignores hostname for identity', async t => {
    const runtime = await fixture(t, { EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'reader' });
    const falco = {
        time: '2026-07-30T10:00:00.123Z', rule: 'Terminal shell in container', priority: 'Warning',
        source: 'syscall', hostname: 'untrusted-host', tags: ['container', 'mitre_execution'],
        output: 'A shell was spawned', output_fields: { 'proc.pid': 42, 'proc.name': 'bash' },
    };
    const response = await runtime.send('/ingest/falco', { method: 'POST', key: 'sensor-key', body: falco });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.alert.rule, falco.rule);
    assert.equal(result.alert.severity, 'medium');
    assert.equal(result.alert.raw.hostname, 'untrusted-host');
    assert.match(result.alert.sourceId, /^sensor-[a-f0-9]{24}$/);
    assert.notEqual(result.alert.sourceId, falco.hostname);
    const invalid = await runtime.send('/ingest/falco', { method: 'POST', key: 'sensor-key', body: { ...falco, tags: 'container' } });
    assert.equal(invalid.status, 400);
});

test('raw event dedup is source scoped and PID reuse creates distinct process instances', async t => {
    const runtime = await fixture(t, { EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'reader' });
    const event = {
        eventId: 'evt-1', type: 'PROCESS_START', timestamp: '2026-07-30T10:00:00Z',
        host: 'host-a', boot_id: 'boot-a', pid: 900, start_time: '2026-07-30T10:00:00Z', image: 'first.exe',
    };
    let response = await runtime.send('/ingest/events', { method: 'POST', key: 'sensor-key', body: event });
    assert.deepEqual(await response.json(), { ok: true, accepted: 1, dedup: 0 });
    response = await runtime.send('/ingest/events', { method: 'POST', key: 'sensor-key', body: event });
    assert.deepEqual(await response.json(), { ok: true, accepted: 0, dedup: 1 });
    response = await runtime.send('/ingest/events', {
        method: 'POST', key: 'sensor-key', body: { ...event, eventId: 'evt-2', timestamp: '2026-07-30T11:00:00Z', start_time: '2026-07-30T11:00:00Z', image: 'second.exe' },
    });
    assert.equal(response.status, 200);
    const processes = await (await runtime.send('/api/processes', { key: 'reader' })).json();
    assert.equal(processes.length, 2);
    assert.equal(new Set(processes.map(process => process.processKey)).size, 2);
    assert.deepEqual(new Set(processes.map(process => process.pid)), new Set([900]));
});

test('alert triage is admin-only, exact, durable, and reflected in alert statistics', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key',
        EDR_READ_API_KEY: 'read-key',
        EDR_ADMIN_API_KEY: 'admin-key',
    });
    const payload = {
        id: 'stable-event-1', rule: 'EDR-TRIAGE', severity: 'critical',
        timestamp: '2026-07-30T10:00:00Z',
        event: { type: 'PROCESS_START', image: 'C:\\Windows\\System32\\cmd.exe' },
    };
    const ingest = await runtime.send('/ingest', {
        method: 'POST', key: 'sensor-key', body: payload,
    });
    assert.equal(ingest.status, 200);
    const created = (await ingest.json()).alert;
    assert.match(created.caseId, /^alert-[a-f0-9]{32}$/);
    assert.deepEqual(created.triage, {
        status: 'new', note: '', assignee: '', priority: 'normal',
        updatedAt: null, updatedBy: null,
    });

    const listed = await (await runtime.send('/api/alerts', { key: 'read-key' })).json();
    assert.equal(listed.alerts[0].caseId, created.caseId);
    assert.equal(listed.alerts[0].id, payload.id);
    assert.equal(listed.total, 1);
    assert.equal((await runtime.send(`/api/alerts/${created.caseId}/triage`, {
        method: 'PATCH', key: 'read-key', body: { status: 'investigating' },
    })).status, 401);
    assert.equal((await runtime.send(`/api/alerts/${created.caseId}/triage`, {
        method: 'PATCH', key: 'admin-key', body: { status: 'unsupported' },
    })).status, 400);
    assert.equal((await runtime.send(`/api/alerts/${created.caseId}/triage`, {
        method: 'PATCH', key: 'admin-key', body: { status: 'resolved', unexpected: true },
    })).status, 400);
    assert.equal((await runtime.send('/api/alerts/alert-does-not-exist/triage', {
        method: 'PATCH', key: 'admin-key', body: { status: 'resolved' },
    })).status, 404);
    const duplicate = await localHttpRequest(`${runtime.base}/api/alerts/${created.caseId}/triage`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json', 'x-api-key': 'admin-key' },
        body: '{"status":"investigating","status":"resolved"}',
    });
    assert.equal(duplicate.status, 400);

    const update = await runtime.send(`/api/alerts/${created.caseId}/triage`, {
        method: 'PATCH', key: 'admin-key',
        body: { status: 'investigating', note: 'Review parent process and command line.' },
    });
    assert.equal(update.status, 200);
    const updated = await update.json();
    assert.equal(updated.alert.triage.status, 'investigating');
    assert.equal(updated.activity.note, 'Review parent process and command line.');
    const activity = await (await runtime.send(`/api/alerts/${created.caseId}/activity`, { key: 'read-key' })).json();
    assert.equal(activity.length, 1);
    assert.equal(activity[0].status, 'investigating');
    const diskActivity = fs.readFileSync(runtime.files.triage, 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(diskActivity.length, 1);
    assert.equal(diskActivity[0].caseId, created.caseId);

    const resolved = await runtime.send(`/api/alerts/${created.caseId}/triage`, {
        method: 'PATCH', key: 'admin-key', body: { status: 'resolved', note: 'Contained.' },
    });
    assert.equal(resolved.status, 200);
    const stats = await (await runtime.send('/api/stats', { key: 'read-key' })).json();
    assert.equal(stats.total, 1);
    assert.equal(stats.open, 0);
    assert.equal(stats.byStatus.resolved, 1);
    const resolvedAlerts = await (await runtime.send('/api/alerts?status=resolved', { key: 'read-key' })).json();
    assert.equal(resolvedAlerts.alerts.length, 1);
    assert.equal(resolvedAlerts.alerts[0].triage.note, 'Contained.');
});

test('triage state and stable case identity survive a console restart', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-restart-'));
    const env = {
        EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'read-key', EDR_ADMIN_API_KEY: 'admin-key',
    };
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    const first = createRuntime({ dataDir, env, logger: quietLogger });
    await first.start(0, '127.0.0.1');
    const firstBase = `http://127.0.0.1:${first.server.address().port}`;
    const ingest = await localHttpRequest(`${firstBase}/ingest`, {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'sensor-key' },
        body: JSON.stringify({
            id: 'restart-alert', rule: 'EDR-RESTART', severity: 'high',
            timestamp: '2026-07-30T11:00:00Z', event: { b: 2, a: 1, type: 'PROCESS_START' },
        }),
    });
    const caseId = (await ingest.json()).alert.caseId;
    await localHttpRequest(`${firstBase}/api/alerts/${caseId}/triage`, {
        method: 'PATCH', headers: { 'content-type': 'application/json', 'x-api-key': 'admin-key' },
        body: JSON.stringify({ status: 'false_positive', note: 'Known administrator activity.' }),
    });
    await new Promise(resolve => first.server.close(resolve));

    const second = createRuntime({ dataDir, env, logger: quietLogger });
    await second.start(0, '127.0.0.1');
    t.after(() => new Promise(resolve => second.server.close(resolve)));
    const secondBase = `http://127.0.0.1:${second.server.address().port}`;
    const alerts = await (await localHttpRequest(`${secondBase}/api/alerts`, { headers: { 'x-api-key': 'read-key' } })).json();
    assert.equal(alerts.alerts[0].caseId, caseId);
    assert.equal(alerts.alerts[0].triage.status, 'false_positive');
    assert.equal(alerts.alerts[0].triage.note, 'Known administrator activity.');
});

test('endpoint inventory aggregates risk, host telemetry, and open alert state', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'read-key', EDR_ADMIN_API_KEY: 'admin-key',
    });
    const now = new Date().toISOString();
    for (const alert of [
        { id: 'endpoint-a1', rule: 'EDR-A', severity: 'critical', timestamp: now, event: { type: 'DNS_QUERY', hostname: 'LAB-WS11' } },
        { id: 'endpoint-a2', rule: 'EDR-B', severity: 'high', timestamp: now, event: { type: 'PROCESS_START', hostname: 'LAB-WS11' } },
    ]) {
        assert.equal((await runtime.send('/ingest', { method: 'POST', key: 'sensor-key', body: alert })).status, 200);
    }
    const rawEvent = {
        eventId: 'endpoint-event', type: 'PROCESS_START', timestamp: now,
        hostname: 'LAB-WS11', boot_id: 'boot-1', pid: 4321, start_time: now,
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    };
    assert.equal((await runtime.send('/ingest/events', { method: 'POST', key: 'sensor-key', body: rawEvent })).status, 200);
    const alerts = await (await runtime.send('/api/alerts', { key: 'read-key' })).json();
    await runtime.send(`/api/alerts/${alerts.alerts[0].caseId}/triage`, {
        method: 'PATCH', key: 'admin-key', body: { status: 'resolved', note: 'Reviewed.' },
    });

    const response = await runtime.send('/api/endpoints', { key: 'read-key' });
    assert.equal(response.status, 200);
    const inventory = await response.json();
    assert.equal(inventory.total, 1);
    assert.equal(inventory.endpoints[0].reportedHost, 'LAB-WS11');
    assert.equal(inventory.endpoints[0].alerts, 2);
    assert.equal(inventory.endpoints[0].openAlerts, 1);
    assert.equal(inventory.endpoints[0].critical, 1);
    assert.equal(inventory.endpoints[0].high, 1);
    assert.equal(inventory.endpoints[0].events, 1);
    assert.equal(inventory.endpoints[0].processes, 1);
    assert.equal(inventory.endpoints[0].risk, 'critical');
    assert.equal(inventory.endpoints[0].telemetryState, 'recent');
    const details = await (await runtime.send(`/api/endpoints/${encodeURIComponent(inventory.endpoints[0].sourceId)}`, { key: 'read-key' })).json();
    assert.equal(details.recentAlerts.length, 2);
    assert.equal(details.recentEvents[0].summary, rawEvent.image);
});

test('event hunt filters bounded security fields, source, process, type, and time', async t => {
    const runtime = await fixture(t, { EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'read-key' });
    const records = [
        { eventId: 'hunt-1', type: 'PROCESS_START', timestamp: '2026-07-30T10:00:00Z', host: 'lab-one', boot_id: 'boot', pid: 100, start_time: '2026-07-30T10:00:00Z', image: 'powershell.exe', command_line: 'powershell -enc AAAA' },
        { eventId: 'hunt-2', type: 'DNS_QUERY', timestamp: '2026-07-30T10:05:00Z', host: 'lab-one', dns_query: 'suspicious.example' },
        { eventId: 'hunt-4', type: 'POWERSHELL_SCRIPT', timestamp: '2026-07-30T10:30:00Z', host: 'lab-one', fields: { script_path: 'C:\\Scripts\\audit.ps1', script_block_id: 'block-1', script_block_text: '[redacted]' } },
        { eventId: 'hunt-3', type: 'FILE_CREATE', timestamp: '2026-07-30T11:00:00Z', host: 'lab-one', path: 'C:\\Temp\\dropper.bin' },
    ];
    assert.equal((await runtime.send('/ingest/events', { method: 'POST', key: 'sensor-key', body: records })).status, 200);
    let result = await (await runtime.send('/api/events?type=DNS_QUERY&q=suspicious', { key: 'read-key' })).json();
    assert.equal(result.total, 1);
    assert.equal(result.events[0].eventId, 'hunt-2');
    assert.equal(result.events[0].summary, 'suspicious.example');
    result = await (await runtime.send('/api/events?type=POWERSHELL_SCRIPT&q=audit', { key: 'read-key' })).json();
    assert.equal(result.total, 1);
    assert.equal(result.events[0].eventId, 'hunt-4');
    assert.equal(result.events[0].summary, 'C:\\Scripts\\audit.ps1');
    result = await (await runtime.send('/api/events?since=2026-07-30T10%3A01%3A00Z&until=2026-07-30T10%3A59%3A00Z', { key: 'read-key' })).json();
    assert.deepEqual(result.events.map(event => event.eventId), ['hunt-4', 'hunt-2']);
    const processKey = runtime.state.events.find(event => event.eventId === 'hunt-1').processKey;
    result = await (await runtime.send(`/api/events?processKey=${encodeURIComponent(processKey)}`, { key: 'read-key' })).json();
    assert.deepEqual(result.events.map(event => event.eventId), ['hunt-1']);
    const sourceId = runtime.state.events[0].sourceId;
    result = await (await runtime.send(`/api/events?sourceId=${encodeURIComponent(sourceId)}&limit=2`, { key: 'read-key' })).json();
    assert.equal(result.total, 4);
    assert.deepEqual(result.events.map(event => event.eventId), ['hunt-3', 'hunt-4']);
    assert.equal((await runtime.send('/api/events?since=2026-07-31T00%3A00%3A00Z&until=2026-07-30T00%3A00%3A00Z', { key: 'read-key' })).status, 400);
    assert.equal((await runtime.send('/api/events?since=not-a-time', { key: 'read-key' })).status, 400);
});

test('terminate and quarantine are forced dry-run, require identity and reason, and append audit JSONL', async t => {
    const runtime = await fixture(t, { EDR_ADMIN_API_KEY: 'admin-secret' });
    assert.equal((await runtime.send('/api/response/terminate', {
        method: 'POST', key: 'wrong', body: { reason: 'test', target: { pid: 10, createTime100ns: '123' } },
    })).status, 401);
    assert.equal((await runtime.send('/api/response/terminate', {
        method: 'POST', key: 'admin-secret', body: { reason: '', target: { pid: 10, createTime100ns: '123' } },
    })).status, 400);
    for (const [action, target] of [['terminate', { pid: 10, createTime100ns: '18446744073709551615', processKey: 'p1' }], ['quarantine', { path: 'C:\\sample.exe', sha256: 'a'.repeat(64) }]]) {
        const response = await runtime.send(`/api/response/${action}`, {
            method: 'POST', key: 'admin-secret', body: { reason: 'analyst validation', target },
        });
        assert.equal(response.status, 200);
        const result = await response.json();
        assert.equal(result.effective_mode, 'dry_run');
    }
    const audit = fs.readFileSync(path.join(runtime.dataDir, 'audit.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(audit.map(entry => entry.action), ['terminate', 'quarantine']);
    assert.ok(audit.every(entry => entry.effective_mode === 'dry_run'));
});

test('terminate schema is exact and createTime100ns never accepts numeric input', async t => {
    const runtime = await fixture(t, { EDR_ADMIN_API_KEY: 'admin-secret' });
    for (const body of [
        { reason: 'test', target: { pid: 10, createTime100ns: 123 } },
        { reason: 'test', target: { pid: 10, createTime100ns: '0' } },
        { reason: 'test', target: { pid: 10, createTime100ns: '123', extra: true } },
        { reason: 'test', target: { pid: 4, createTime100ns: '123' } },
        { reason: 'test', target: { pid: 10, createTime100ns: '123' }, extra: true },
    ]) {
        const response = await runtime.send('/api/response/terminate', {
            method: 'POST', key: 'admin-secret', body,
        });
        assert.equal(response.status, 400);
    }
    assert.equal((await runtime.send('/api/response/terminate?unused=1', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'test', target: { pid: 10, createTime100ns: '123' } },
    })).status, 400);
});

test('terminate tree fields are optional, validated, and forwarded to native', async t => {
    const calls = [];
    const fake = {
        async readiness() { return { effective_mode: 'dry_run' }; },
        async terminate(value) { calls.push(['terminate', value]); return { effective_mode: 'dry_run' }; },
    };
    const runtime = await fixture(t, {
        EDR_ADMIN_API_KEY: 'admin-secret', EDR_RESPONSE_CHANNEL_ENABLE: 'true',
    }, { responseClient: fake });
    for (const body of [
        { reason: 'test', target: { pid: 10, createTime100ns: '123' }, maxTreeSize: 3 },
        { reason: 'test', target: { pid: 10, createTime100ns: '123' }, maxTreeSize: 65 },
        { reason: 'test', target: { pid: 10, createTime100ns: '123' }, maxTreeSize: 8.5 },
        { reason: 'test', target: { pid: 10, createTime100ns: '123' }, maxTreeSize: 0 },
        { reason: 'test', target: { pid: 10, createTime100ns: '123' }, suspendBeforeTerminate: 1 },
        { reason: 'test', target: { pid: 10, createTime100ns: '123' }, suspendBeforeTerminate: 'true' },
    ]) {
        const rejected = await runtime.send('/api/response/terminate', {
            method: 'POST', key: 'admin-secret', body,
        });
        assert.equal(rejected.status, 400);
    }
    const coerced = await runtime.send('/api/response/terminate', {
        method: 'POST', key: 'admin-secret',
        body: {
            reason: 'test', target: { pid: 10, createTime100ns: '123' },
            maxTreeSize: '8',
        },
    });
    assert.equal(coerced.status, 200); /* numeric strings are coerced, as for pid */
    assert.equal(calls[0][1].maxTreeSize, 8); /* coerced numeric string */
    const response = await runtime.send('/api/response/terminate', {
        method: 'POST', key: 'admin-secret',
        body: {
            reason: 'test', target: { pid: 10, createTime100ns: '123' },
            maxTreeSize: 8, suspendBeforeTerminate: true,
        },
    });
    assert.equal((await response.json()).status, 'native_dry_run_accepted');
    assert.equal(calls[1][1].maxTreeSize, 8);
    assert.equal(calls[1][1].suspendBeforeTerminate, true);
    assert.equal(calls[1][1].target.createTime100ns, '123');
});

test('terminate dispatch requires enabled foundation and dry-run readiness; quarantine never dispatches', async t => {
    const calls = [];
    const fake = {
        async readiness() { calls.push('readiness'); return true; },
        async terminate(value) { calls.push(['terminate', value]); return { effective_mode: 'dry_run' }; },
    };
    const disabled = await fixture(t, { EDR_ADMIN_API_KEY: 'admin-secret' }, { responseClient: fake });
    let response = await disabled.send('/api/response/terminate', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'test', target: { pid: 10, createTime100ns: '123' } },
    });
    assert.equal((await response.json()).status, 'local_only');
    assert.deepEqual(calls, []);

    const enabled = await fixture(t, {
        EDR_ADMIN_API_KEY: 'admin-secret', EDR_RESPONSE_CHANNEL_ENABLE: 'true',
    }, { responseClient: fake });
    response = await enabled.send('/api/response/terminate', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'test', target: { pid: 10, createTime100ns: '123' } },
    });
    assert.equal((await response.json()).status, 'native_dry_run_accepted');
    assert.equal(calls[0], 'readiness');
    assert.equal(calls[1][1].target.createTime100ns, '123');
    await enabled.send('/api/response/quarantine', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'test', target: { path: 'C:\\sample.exe', sha256: 'a'.repeat(64) } },
    });
    assert.equal(calls.length, 2);
});

test('failed readiness fails closed without terminate dispatch', async t => {
    let terminateCalls = 0;
    const runtime = await fixture(t, {
        EDR_ADMIN_API_KEY: 'admin-secret', EDR_RESPONSE_CHANNEL_ENABLE: 'true',
    }, { responseClient: {
        async readiness() { return false; },
        async terminate() { terminateCalls += 1; },
    } });
    const response = await runtime.send('/api/response/terminate', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'test', target: { pid: 10, createTime100ns: '123' } },
    });
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.equal(body.ok, false);
    assert.equal(body.status, 'native_not_ready');
    assert.equal(terminateCalls, 0);
});

test('real termination requires console flag and real readiness', async t => {
    let terminateCalls = 0;
    const fake = {
        async readiness() { return { ok: true, effective_mode: 'dry_run', status: 'ready' }; },
        async terminate() { terminateCalls += 1; },
    };
    const runtime = await fixture(t, {
        EDR_ADMIN_API_KEY: 'admin-secret', EDR_RESPONSE_CHANNEL_ENABLE: 'true',
        EDR_ENABLE_PROCESS_TERMINATION: 'true',
    }, { responseClient: fake });
    const response = await runtime.send('/api/response/terminate', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'test', target: { pid: 10, createTime100ns: '123' } },
    });
    assert.equal(response.status, 503);
    assert.equal((await response.json()).status, 'not_ready');
    assert.equal(terminateCalls, 0);
});

test('real console flag without response foundation is not ready', async t => {
    const runtime = await fixture(t, {
        EDR_ADMIN_API_KEY: 'admin-secret', EDR_ENABLE_PROCESS_TERMINATION: 'true',
    });
    const response = await runtime.send('/api/response/terminate', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'test', target: { pid: 10, createTime100ns: '123' } },
    });
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.equal(body.ok, false);
    assert.equal(body.status, 'not_ready');
    assert.equal(body.effective_mode, 'real');
});

test('real transport loss after dispatch is outcome unknown', async t => {
    const error = new Error('lost response');
    error.dispatched = true;
    const runtime = await fixture(t, {
        EDR_ADMIN_API_KEY: 'admin-secret', EDR_RESPONSE_CHANNEL_ENABLE: 'true',
        EDR_ENABLE_PROCESS_TERMINATION: 'true',
    }, { responseClient: {
        async readiness() { return { ok: true, effective_mode: 'real', status: 'ready',
            audit: { available: true, pending: false, writable: true } }; },
        async terminate() { throw error; },
    } });
    const response = await runtime.send('/api/response/terminate', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'test', target: { pid: 10, createTime100ns: '123' } },
    });
    assert.equal(response.status, 503);
    const body = await response.json();
    assert.equal(body.ok, false);
    assert.equal(body.status, 'outcome_unknown');
});

test('real quarantine and host isolation require capabilities and dispatch exact native actions', async t => {
    const calls = [];
    const fake = {
        async readiness() {
            return { ok: true, effective_mode: 'dry_run', status: 'ready', capabilities: {
                terminate: 'dry_run', quarantine: 'real', host_isolation: 'real', isolation_status: 'real',
            }, audit: { available: true, pending: false, writable: true } };
        },
        async quarantine(value) {
            calls.push(['quarantine', value]);
            return { ok: true, effective_mode: 'real', status: 'quarantined',
                requestId: 'native-q', rolled_back: false, win32_error: 0,
                quarantine_path: 'C:\\quarantine\\sample.exe', sha256: 'a'.repeat(64) };
        },
        async isolate(value) {
            calls.push(['isolate', value]);
            return { ok: true, status: 'isolated', requestId: 'native-i' };
        },
        async unisolate(value) {
            calls.push(['unisolate', value]);
            return { ok: true, status: 'restored', requestId: 'native-u' };
        },
        async isolationStatus() {
            calls.push(['status']);
            return { ok: true, status: 'ready', requestId: 'native-s', isolated: true,
                managementIp: '192.0.2.10', allowedPorts: '443', isolatedSinceMs: 1, elapsedMs: 2 };
        },
    };
    const runtime = await fixture(t, {
        EDR_ADMIN_API_KEY: 'admin-secret', EDR_RESPONSE_CHANNEL_ENABLE: 'true',
        EDR_ENABLE_QUARANTINE: 'true', EDR_ENABLE_HOST_ISOLATION: 'true',
        EDR_HOST_ISOLATION_MANAGEMENT_IP: '192.0.2.10',
        EDR_HOST_ISOLATION_ALLOWED_PORTS: '443',
    }, { responseClient: fake });

    let response = await runtime.send('/api/response/quarantine', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'contain sample', target: { path: 'C:\\sample.exe', sha256: 'a'.repeat(64) } },
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).status, 'quarantined');
    response = await runtime.send('/api/response/isolate', {
        method: 'POST', key: 'admin-secret', body: { reason: 'contain host' },
    });
    assert.equal(response.status, 200);
    response = await runtime.send('/api/response/unisolate', {
        method: 'POST', key: 'admin-secret', body: { reason: 'restore host' },
    });
    assert.equal(response.status, 200);
    response = await runtime.send('/api/response/isolation/status', { key: 'admin-secret' });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).isolated, true);
    assert.deepEqual(calls[1], ['isolate', { reason: 'contain host',
        managementIp: '192.0.2.10', allowedPorts: '443' }]);
    assert.deepEqual(calls[2], ['unisolate', { reason: 'restore host',
        managementIp: '192.0.2.10', allowedPorts: '443' }]);
});

test('real response mutations require writable audit readiness while isolation status stays read-only', async t => {
    const states = [
        { available: true, pending: true, writable: false },
        { available: false, pending: false, writable: false },
        undefined,
    ];
    let readinessCalls = 0;
    const mutationCalls = [];
    const fake = {
        async readiness() {
            const audit = states[readinessCalls++ % states.length];
            return { ok: true, effective_mode: 'real', status: 'ready', audit,
                capabilities: { terminate: 'real', quarantine: 'real', delete_file: 'real',
                    suspend: 'real', resume: 'real', host_isolation: 'real', isolation_status: 'real' } };
        },
    };
    for (const method of ['terminate', 'quarantine', 'deleteFile', 'suspend', 'resume', 'isolate', 'unisolate']) {
        fake[method] = async () => { mutationCalls.push(method); return { ok: true, status: 'done', effective_mode: 'real' }; };
    }
    fake.isolationStatus = async () => ({ ok: true, status: 'ready', isolated: false });
    const runtime = await fixture(t, {
        EDR_ADMIN_API_KEY: 'admin-secret', EDR_RESPONSE_CHANNEL_ENABLE: 'true',
        EDR_ENABLE_PROCESS_TERMINATION: 'true', EDR_ENABLE_QUARANTINE: 'true',
        EDR_ENABLE_DELETE_FILE: 'true', EDR_ENABLE_PROCESS_SUSPEND: 'true',
        EDR_ENABLE_PROCESS_RESUME: 'true', EDR_ENABLE_HOST_ISOLATION: 'true',
        EDR_HOST_ISOLATION_MANAGEMENT_IP: '192.0.2.10',
    }, { responseClient: fake });
    const hash = 'a'.repeat(64);
    const requests = [
        ['/api/response/terminate', { reason: 'test', target: { pid: 1234, createTime100ns: '123' } }],
        ['/api/response/quarantine', { reason: 'test', target: { path: 'C:\\sample.exe', sha256: hash } }],
        ['/api/response/delete_file', { reason: 'test', target: { path: 'C:\\sample.exe', sha256: hash } }],
        ['/api/response/suspend', { reason: 'test', target: { pid: 1234, createTime100ns: '123' } }],
        ['/api/response/resume', { reason: 'test', target: { pid: 1234, createTime100ns: '123' } }],
        ['/api/response/isolate', { reason: 'test' }],
        ['/api/response/unisolate', { reason: 'test' }],
    ];
    for (const [url, body] of requests) {
        const response = await runtime.send(url, { method: 'POST', key: 'admin-secret', body });
        assert.equal(response.status, 503, url);
        assert.equal((await response.json()).status, 'audit_failed', url);
    }
    assert.deepEqual(mutationCalls, []);
    const isolationStatus = await runtime.send('/api/response/isolation/status', { key: 'admin-secret' });
    assert.equal(isolationStatus.status, 200);
    assert.equal((await isolationStatus.json()).isolated, false);
    assert.deepEqual(mutationCalls, []);
});

test('new response actions remain disabled and reject caller-supplied isolation policy', async t => {
    const runtime = await fixture(t, { EDR_ADMIN_API_KEY: 'admin-secret' });
    let response = await runtime.send('/api/response/quarantine', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'test', target: { path: 'C:\\sample.exe', sha256: 'a'.repeat(64) } },
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).effective_mode, 'dry_run');
    response = await runtime.send('/api/response/isolate', {
        method: 'POST', key: 'admin-secret',
        body: { reason: 'test', managementIp: '203.0.113.2' },
    });
    assert.equal(response.status, 400);
    assert.equal((await runtime.send('/api/response/isolation/status', {
        key: 'admin-secret',
    })).status, 503);
    assert.equal((await runtime.send('/api/response/isolate', {
        method: 'POST', key: 'wrong', body: { reason: 'test' },
    })).status, 401);
});

test('delete_file is forced dry-run, validates target sha256, and mirrors quarantine dry-run', async t => {
    const runtime = await fixture(t, { EDR_ADMIN_API_KEY: 'admin-secret' });
    // without admin key -> 401, and server without admin key -> 503
    assert.equal((await runtime.send('/api/response/delete_file', {
        method: 'POST', key: 'wrong', body: { reason: 'test', target: { path: 'C:\\a.exe', sha256: 'a'.repeat(64) } },
    })).status, 401);
    const noAdmin = await fixture(t, { EDR_READ_API_KEY: 'read-key' });
    assert.equal((await noAdmin.send('/api/response/delete_file', {
        method: 'POST', key: 'read-key', body: { reason: 'test', target: { path: 'C:\\a.exe', sha256: 'a'.repeat(64) } },
    })).status, 503);
    // flat body (sha256 at top level), missing sha256, illegal sha -> 400
    assert.equal((await runtime.send('/api/response/delete_file', {
        method: 'POST', key: 'admin-secret', body: { reason: 'test', path: 'C:\\a.exe', sha256: 'a'.repeat(64) },
    })).status, 400);
    assert.equal((await runtime.send('/api/response/delete_file', {
        method: 'POST', key: 'admin-secret', body: { reason: 'test', target: { path: 'C:\\a.exe' } },
    })).status, 400);
    assert.equal((await runtime.send('/api/response/delete_file', {
        method: 'POST', key: 'admin-secret', body: { reason: 'test', target: { path: 'C:\\a.exe', sha256: 'zzzz' } },
    })).status, 400);
    assert.equal((await runtime.send('/api/response/delete_file', {
        method: 'POST', key: 'admin-secret', body: { reason: 'test', target: { path: 'C:\\a.exe', sha256: 'g'.repeat(64) } },
    })).status, 400);
    // query param -> 400
    assert.equal((await runtime.send('/api/response/delete_file?unused=1', {
        method: 'POST', key: 'admin-secret', body: { reason: 'test', target: { path: 'C:\\a.exe', sha256: 'a'.repeat(64) } },
    })).status, 400);
    // dry_run without channel mirrors quarantine dry_run: accepted or not_ready, effective_mode dry_run
    const response = await runtime.send('/api/response/delete_file', {
        method: 'POST', key: 'admin-secret', body: { reason: 'analyst validation', target: { path: 'C:\\sample.exe', sha256: 'a'.repeat(64) } },
    });
    assert.ok([200, 503].includes(response.status));
    const body = await response.json();
    assert.equal(body.effective_mode, 'dry_run');
    assert.ok(['accepted', 'not_ready', 'native_not_ready', 'native_dry_run_accepted'].includes(body.status));
    const audit = fs.readFileSync(path.join(runtime.dataDir, 'audit.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.ok(audit.some(entry => entry.action === 'delete_file' && entry.effective_mode === 'dry_run'));
});

test('response API rejects duplicate JSON keys', async t => {
    const runtime = await fixture(t, { EDR_ADMIN_API_KEY: 'admin-secret' });
    const response = await localHttpRequest(`${runtime.base}/api/response/terminate`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-api-key': 'admin-secret' },
        body: '{"reason":"one","reason":"two","target":{"pid":10,"createTime100ns":"123"}}',
    });
    assert.equal(response.status, 400);
});

test('response audit is admin-only, filtered, paginated, newest-first, durable, and secret-safe', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-audit-'));
    const env = {
        EDR_READ_API_KEY: 'read-key', EDR_ADMIN_API_KEY: 'admin-key',
    };
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dataDir, 'audit.jsonl'), [
        JSON.stringify({
            timestamp: '2026-07-30T10:00:00.000Z', action: 'terminate', status: 'local_only',
            effective_mode: 'dry_run', reason: 'first', target: { pid: 10 },
            apiKey: 'must-not-leak', accessToken: 'camel-secret', password: 'password-secret',
            nested: { command_key: 'also-secret', safe: 'retained',
                message: 'Authorization: Bearer embedded-secret',
                url: 'https://example.invalid/?api_key=query-secret&safe=1' },
            items: [{ clientSecret: 'array-secret', safe: 'array-retained' }],
        }),
        '{broken-json',
        JSON.stringify({
            timestamp: '2026-07-30T11:00:00.000Z', action: 'quarantine', status: 'quarantined',
            effective_mode: 'real', reason: 'second', target: { path: 'C:\\sample.exe' },
        }),
        JSON.stringify({
            timestamp: '2026-07-30T12:00:00.000Z', action: 'terminate', status: 'outcome_unknown',
            effective_mode: 'real', reason: 'third', target: { pid: 20 },
        }),
    ].join('\n') + '\n');

    const first = createRuntime({ dataDir, env, logger: quietLogger });
    await first.start(0, '127.0.0.1');
    t.after(() => first.server.listening
        ? new Promise(resolve => first.server.close(resolve)) : undefined);
    const base = `http://127.0.0.1:${first.server.address().port}`;
    /* Undici intentionally refuses a few well-known HTTP ports. Windows may
     * allocate one of them for listen(0), so use node:http for this local
     * server test rather than making the test depend on the fetch port list. */
    const get = (query = '', key = 'admin-key') => new Promise((resolve, reject) => {
        const request = http.get(`${base}/api/response/audit${query}`, {
            headers: { 'x-api-key': key },
        }, response => {
            const chunks = [];
            response.on('data', chunk => chunks.push(chunk));
            response.on('end', () => {
                const body = Buffer.concat(chunks).toString('utf8');
                resolve({ status: response.statusCode,
                    json: async () => JSON.parse(body) });
            });
        });
        request.on('error', reject);
    });

    assert.equal((await get('', 'read-key')).status, 401);
    assert.equal((await get('', 'wrong')).status, 401);
    let response = await get('?limit=2&offset=0');
    assert.equal(response.status, 200);
    let body = await response.json();
    assert.equal(body.total, 3); /* malformed JSONL is skipped */
    assert.deepEqual(body.records.map(record => record.status), ['outcome_unknown', 'quarantined']);
    assert.equal(body.total_within_scan_window, 3);
    assert.equal(body.integrity.malformed_count, 1);
    assert.equal(body.integrity.window_truncated, false);
    assert.equal(body.has_more, true);
    assert.ok(body.supported_statuses.includes('termination_pending'));
    assert.ok(body.supported_statuses.includes('rollback_failed'));

    body = await (await get('?action=terminate&status=local_only&since=2026-07-30T09%3A00%3A00Z&until=2026-07-30T10%3A30%3A00Z')).json();
    assert.equal(body.total, 1);
    assert.equal(body.records[0].reason, 'first');
    assert.equal(body.records[0].nested.safe, 'retained');
    const serialized = JSON.stringify(body.records[0]);
    for (const secret of ['must-not-leak', 'also-secret', 'camel-secret',
        'password-secret', 'embedded-secret', 'query-secret', 'array-secret']) {
        assert.equal(serialized.includes(secret), false, secret);
    }
    assert.ok(serialized.includes('[redacted]'));
    assert.equal(body.records[0].items[0].safe, 'array-retained');
    body = await (await get('?limit=1&offset=1')).json();
    assert.deepEqual(body.records.map(record => record.status), ['quarantined']);

    for (const query of [
        '?unknown=1', '?limit=0', '?limit=1001', '?offset=-1', '?action=delete',
        '?status=made_up', '?since=nope', '?until=nope',
        '?since=2026-07-31T00%3A00%3A00Z&until=2026-07-30T00%3A00%3A00Z',
    ]) assert.equal((await get(query)).status, 400, query);

    await new Promise(resolve => first.server.close(resolve));
    const second = createRuntime({ dataDir, env, logger: quietLogger });
    await second.start(0, '127.0.0.1');
    t.after(() => new Promise(resolve => second.server.close(resolve)));
    const restarted = await new Promise((resolve, reject) => {
        const request = http.get(`http://127.0.0.1:${second.server.address().port}/api/response/audit`, {
            headers: { 'x-api-key': 'admin-key' },
        }, response => {
            const chunks = [];
            response.on('data', chunk => chunks.push(chunk));
            response.on('end', () => {
                const body = Buffer.concat(chunks).toString('utf8');
                resolve({ status: response.statusCode,
                    json: async () => JSON.parse(body) });
            });
        });
        request.on('error', reject);
    });
    assert.equal(restarted.status, 200);
    assert.equal((await restarted.json()).total, 3);
});

test('response audit status contract accepts every legitimate action/status pair', async t => {
    const runtime = await fixture(t, { EDR_ADMIN_API_KEY: 'admin-key' });
    for (const [action, statuses] of Object.entries(RESPONSE_AUDIT_STATUSES_BY_ACTION)) {
        const contract = await (await runtime.send(
            `/api/response/audit?action=${encodeURIComponent(action)}`,
            { key: 'admin-key' })).json();
        assert.deepEqual(contract.supported_statuses, statuses);
        for (const status of statuses) {
            const response = await runtime.send(
                `/api/response/audit?action=${encodeURIComponent(action)}&status=${encodeURIComponent(status)}`,
                { key: 'admin-key' });
            assert.equal(response.status, 200, `${action}/${status}`);
        }
    }
    assert.equal((await runtime.send(
        '/api/response/audit?action=terminate&status=quarantined',
        { key: 'admin-key' })).status, 400);
    assert.equal((await runtime.send(
        '/api/response/audit?status=not-a-native-status',
        { key: 'admin-key' })).status, 400);
});

test('bounded audit tail reader limits bytes and reports UTF-8, oversized, and crash-tail damage', t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-audit-tail-'));
    const file = path.join(dataDir, 'audit.jsonl');
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));

    const descriptor = fs.openSync(file, 'w+');
    try {
        fs.ftruncateSync(descriptor, 1024 * 1024);
        const valid = JSON.stringify({ timestamp: '2026-07-30T12:00:00Z',
            action: 'terminate', status: 'terminated', reason: 'UTF-8 边界' });
        const oversized = JSON.stringify({ value: 'x'.repeat(300) });
        const tail = Buffer.concat([
            Buffer.from(`\n${valid}\r\n{malformed}\n${oversized}\n`, 'utf8'),
            Buffer.from([0xff, 0xfe]),
            Buffer.from('\n{"truncated":', 'utf8'),
        ]);
        fs.writeSync(descriptor, tail, 0, tail.length, 1024 * 1024 - tail.length);
    } finally {
        fs.closeSync(descriptor);
    }

    const result = readJsonLinesTail(file, {
        maxBytes: 4096, maxLineBytes: 128, maxRecords: 20, maxPhysicalLines: 50,
    });
    assert.ok(result.scanned_bytes <= 4096);
    assert.equal(result.window_truncated, true);
    assert.equal(result.records.length, 1);
    assert.equal(result.records[0].reason, 'UTF-8 边界');
    assert.equal(result.oversized_count, 1);
    assert.equal(result.invalid_utf8_count, 1);
    assert.equal(result.malformed_count, 2);
    assert.equal(result.truncated_tail, true);
});

test('async audit tail reader preserves bounded tail parsing semantics', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-audit-async-tail-'));
    const file = path.join(dataDir, 'audit.jsonl');
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    const content = Buffer.concat([
        Buffer.from(`${JSON.stringify({ action: 'old' })}\n`, 'utf8'),
        Buffer.from(`${JSON.stringify({ action: 'new', reason: '边界' })}\r\n{bad}\n`, 'utf8'),
        Buffer.from([0xff, 0xfe, 0x0a]),
        Buffer.from(`{"oversized":"${'x'.repeat(200)}"}\n{"truncated":`, 'utf8'),
    ]);
    fs.writeFileSync(file, content);
    const options = { maxBytes: 4096, maxLineBytes: 128, maxRecords: 20, maxPhysicalLines: 50 };
    assert.deepEqual(await readJsonLinesTailAsync(file, options), readJsonLinesTail(file, options));
});

test('async audit tail reader rejects a file that changes after its captured snapshot', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-audit-snapshot-'));
    const file = path.join(dataDir, 'audit.jsonl');
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    fs.writeFileSync(file, `${JSON.stringify({ action: 'before' })}\n`);
    const promisesFs = require('node:fs/promises');
    const originalOpen = promisesFs.open;
    promisesFs.open = async (...args) => {
        const handle = await originalOpen(...args);
        if (args[0] !== file) return handle;
        const originalRead = handle.read.bind(handle);
        let changed = false;
        handle.read = async (...readArgs) => {
            const result = await originalRead(...readArgs);
            if (!changed) {
                changed = true;
                fs.appendFileSync(file, `${JSON.stringify({ action: 'after' })}\n`);
            }
            return result;
        };
        return handle;
    };
    try {
        await assert.rejects(readJsonLinesTailAsync(file), error =>
            error.code === 'EDR_AUDIT_SNAPSHOT_CHANGED');
    } finally {
        promisesFs.open = originalOpen;
    }
});

test('async audit tail reader rejects a short read instead of returning partial records', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-audit-short-read-'));
    const file = path.join(dataDir, 'audit.jsonl');
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    fs.writeFileSync(file, `${JSON.stringify({ action: 'record' })}\n`);
    const promisesFs = require('node:fs/promises');
    const originalOpen = promisesFs.open;
    promisesFs.open = async (...args) => {
        const handle = await originalOpen(...args);
        if (args[0] === file) handle.read = async () => ({ bytesRead: 0, buffer: Buffer.alloc(0) });
        return handle;
    };
    try {
        await assert.rejects(readJsonLinesTailAsync(file), error =>
            error.code === 'EDR_AUDIT_SHORT_READ');
    } finally {
        promisesFs.open = originalOpen;
    }
});

test('response audit route returns unavailable for an unreadable ledger path', async t => {
    const runtime = await fixture(t, { EDR_ADMIN_API_KEY: 'admin-key' });
    fs.mkdirSync(runtime.files.audit);
    const response = await runtime.send('/api/response/audit', { key: 'admin-key' });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), {
        error: 'response audit ledger unavailable', status: 'unavailable',
    });
});

test('response audit async scan yields while parsing a large captured window', async t => {
    const records = Array.from({ length: 20000 }, (_, index) => JSON.stringify({
        timestamp: `2026-07-30T12:${String(Math.floor(index / 60) % 60).padStart(2, '0')}:${String(index % 60).padStart(2, '0')}.000Z`,
        action: 'terminate', status: 'planned', reason: `record-${index}`,
    }));
    const runtime = await fixture(t, { EDR_ADMIN_API_KEY: 'admin-key' });
    fs.writeFileSync(path.join(runtime.dataDir, 'audit.jsonl'), `${records.join('\n')}\n`);

    let ticks = 0;
    const timer = setInterval(() => { ticks += 1; }, 0);
    let response;
    try {
        response = await runtime.send('/api/response/audit?limit=1000', { key: 'admin-key' });
    } finally {
        clearInterval(timer);
    }
    const responseText = await response.text();
    assert.equal(response.status, 200, responseText);
    const body = JSON.parse(responseText);
    assert.equal(body.total, 20000);
    assert.equal(body.records.length, 1000);
    assert.ok(ticks > 0, 'the event loop should run while reading and parsing the audit window');
});

test('response audit API scans a bounded tail of a sparse large ledger', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-audit-sparse-'));
    const file = path.join(dataDir, 'audit.jsonl');
    const size = LIMITS.auditScanBytes + 4 * 1024 * 1024;
    const tail = Buffer.from(`\n${JSON.stringify({
        timestamp: '2026-07-30T12:00:00.000Z', action: 'terminate',
        status: 'termination_pending', reason: 'tail record',
    })}\n`, 'utf8');
    const descriptor = fs.openSync(file, 'w+');
    try {
        fs.ftruncateSync(descriptor, size);
        fs.writeSync(descriptor, tail, 0, tail.length, size - tail.length);
    } finally {
        fs.closeSync(descriptor);
    }
    const runtime = createRuntime({ dataDir,
        env: { EDR_ADMIN_API_KEY: 'admin-key' }, logger: quietLogger });
    await runtime.start(0, '127.0.0.1');
    t.after(async () => {
        await new Promise(resolve => runtime.server.close(resolve));
        fs.rmSync(dataDir, { recursive: true, force: true });
    });
    const response = await localHttpRequest(
        `http://127.0.0.1:${runtime.server.address().port}/api/response/audit`,
        { headers: { 'x-api-key': 'admin-key' } });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.records[0].status, 'termination_pending');
    assert.equal(body.integrity.window_truncated, true);
    assert.ok(body.integrity.scanned_bytes <= LIMITS.auditScanBytes);
    assert.equal(body.has_more, false);
});

test('response GUI locks ambiguous submissions until explicit reconciliation', () => {
    const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
    for (const marker of [
        'uncertainResponseTargets', 'lockUncertainResponse',
        "result.status === 'outcome_unknown'", 'transport_failure_after_submit',
        'invalid_response_body', 'button.disabled', 'acknowledgeUncertainResponse',
        'I manually reconciled this outcome', 'Do not retry blindly',
    ]) assert.ok(html.includes(marker), marker);
});

test('response audit fails closed when the admin key is not configured', async t => {
    const runtime = await fixture(t, { EDR_READ_API_KEY: 'read-key' });
    assert.equal((await runtime.send('/api/response/audit', { key: 'read-key' })).status, 503);
});

test('stats timeseries buckets alerts into continuous hour windows', async t => {
    const runtime = await fixture(t, { EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'read-key' });
    const hourMillis = 60 * 60 * 1000;
    const now = Date.now();
    const alignedHour = Math.floor(now / hourMillis) * hourMillis;
    const alerts = [
        { id: 'ts-hour-1', rule: 'EDR-TS', severity: 'critical', timestamp: new Date(alignedHour - 2 * hourMillis).toISOString(), event: { type: 'PROCESS_START', hostname: 'LAB-WS1' } },
        { id: 'ts-hour-2', rule: 'EDR-TS', severity: 'high', timestamp: new Date(alignedHour - 2 * hourMillis).toISOString(), event: { type: 'PROCESS_START', hostname: 'LAB-WS1' } },
        { id: 'ts-hour-3', rule: 'EDR-TS', severity: 'medium', timestamp: new Date(alignedHour - 5 * hourMillis - 30 * 60 * 1000).toISOString(), event: { type: 'DNS_QUERY', hostname: 'LAB-WS2' } },
    ];
    for (const alert of alerts) {
        assert.equal((await runtime.send('/ingest', { method: 'POST', key: 'sensor-key', body: alert })).status, 200);
    }

    const response = await runtime.send('/api/stats/timeseries?bucket=hour&days=7', { key: 'read-key' });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.bucket, 'hour');
    assert.equal(result.days, 7);
    assert.equal(result.points.length, 7);
    const firstStart = alignedHour - 6 * hourMillis;
    assert.equal(result.points[0].start, new Date(firstStart).toISOString());
    assert.equal(result.points[6].end, new Date(alignedHour + hourMillis).toISOString());
    const index = millis => Math.floor((millis - firstStart) / hourMillis);
    const shared = index(Date.parse(alerts[0].timestamp));
    assert.equal(result.points[shared].count, 2);
    assert.deepEqual(result.points[shared].bySeverity, { critical: 1, high: 1, medium: 0, low: 0 });
    assert.equal(result.points[index(Date.parse(alerts[2].timestamp))].count, 1);
    assert.equal(result.points.reduce((sum, point) => sum + point.count, 0), 3);

    const defaults = await (await runtime.send('/api/stats/timeseries', { key: 'read-key' })).json();
    assert.equal(defaults.bucket, 'hour');
    assert.equal(defaults.days, 7);
    assert.equal(defaults.points.length, 7);
    assert.equal((await runtime.send('/api/stats/timeseries', {})).status, 401);
});

test('stats timeseries buckets alerts into continuous day windows and rejects bad parameters', async t => {
    const runtime = await fixture(t, { EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'read-key' });
    const dayMillis = 24 * 60 * 60 * 1000;
    const now = new Date();
    const alignedDay = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
    const alerts = [
        { id: 'ts-day-1', rule: 'EDR-TS', severity: 'critical', timestamp: new Date(alignedDay - 2 * dayMillis + 12 * 60 * 60 * 1000).toISOString(), event: { type: 'PROCESS_START', hostname: 'LAB-WS1' } },
        { id: 'ts-day-2', rule: 'EDR-TS', severity: 'high', timestamp: new Date(alignedDay - 2 * dayMillis + 12 * 60 * 60 * 1000).toISOString(), event: { type: 'PROCESS_START', hostname: 'LAB-WS1' } },
        { id: 'ts-day-3', rule: 'EDR-TS', severity: 'medium', timestamp: new Date(alignedDay - 4 * dayMillis + 6 * 60 * 60 * 1000).toISOString(), event: { type: 'DNS_QUERY', hostname: 'LAB-WS2' } },
    ];
    for (const alert of alerts) {
        assert.equal((await runtime.send('/ingest', { method: 'POST', key: 'sensor-key', body: alert })).status, 200);
    }

    const response = await runtime.send('/api/stats/timeseries?bucket=day&days=7', { key: 'read-key' });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.bucket, 'day');
    assert.equal(result.days, 7);
    assert.equal(result.points.length, 7);
    const firstStart = alignedDay - 6 * dayMillis;
    const index = millis => Math.floor((millis - firstStart) / dayMillis);
    const shared = index(Date.parse(alerts[0].timestamp));
    assert.equal(result.points[shared].count, 2);
    assert.deepEqual(result.points[shared].bySeverity, { critical: 1, high: 1, medium: 0, low: 0 });
    assert.equal(result.points[index(Date.parse(alerts[2].timestamp))].count, 1);
    assert.equal(result.points.reduce((sum, point) => sum + point.count, 0), 3);

    for (const query of ['bucket=week', 'days=0', 'days=200', 'days=1.5', 'days=abc']) {
        assert.equal((await runtime.send(`/api/stats/timeseries?${query}`, { key: 'read-key' })).status, 400);
    }
});

test('stats health aggregates endpoint state, risk, and critical endpoints', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-health-'));
    const env = {
        EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'read-key', EDR_ADMIN_API_KEY: 'admin-key',
    };
    const now = new Date().toISOString();
    const stale = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
    fs.writeFileSync(path.join(dataDir, 'alerts.jsonl'), [
        { sourceId: 'sensor-aaa', id: 'health-a1', rule: 'EDR-H', severity: 'critical', timestamp: now, event: { type: 'PROCESS_START', hostname: 'LAB-WS1' } },
        { sourceId: 'sensor-aaa', id: 'health-a2', rule: 'EDR-H', severity: 'high', timestamp: now, event: { type: 'PROCESS_START', hostname: 'LAB-WS1' } },
        { sourceId: 'sensor-bbb', id: 'health-b1', rule: 'EDR-H', severity: 'low', timestamp: now, event: { type: 'DNS_QUERY', hostname: 'LAB-WS2' } },
        { sourceId: 'sensor-ccc', id: 'health-c1', rule: 'EDR-H', severity: 'medium', timestamp: stale, event: { type: 'FILE_CREATE', hostname: 'LAB-WS3' } },
    ].map(alert => JSON.stringify(alert)).join('\n') + '\n');
    const runtime = createRuntime({ dataDir, env, logger: quietLogger });
    await runtime.start(0, '127.0.0.1');
    t.after(async () => {
        await new Promise(resolve => runtime.server.close(resolve));
        fs.rmSync(dataDir, { recursive: true, force: true });
    });
    const base = `http://127.0.0.1:${runtime.server.address().port}`;
    const send = (url, { key, body, ...options } = {}) => localHttpRequest(`${base}${url}`, {
        ...options,
        headers: {
            ...(body === undefined ? {} : { 'content-type': 'application/json' }),
            ...(key === undefined ? {} : { 'x-api-key': key }),
            ...(options.headers || {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
    });

    const health = await (await send('/api/stats/health', { key: 'read-key' })).json();
    assert.equal(health.total, 3);
    assert.deepEqual(health.byState, { recent: 2, stale: 0, inactive: 1, unknown: 0 });
    assert.deepEqual(health.byRisk, { critical: 1, high: 0, medium: 1, low: 1, none: 0 });
    assert.equal(health.openAlerts, 4);
    assert.equal(health.criticalEndpoints.length, 3);
    assert.equal(health.criticalEndpoints[0].sourceId, 'sensor-aaa');
    assert.equal(health.criticalEndpoints[0].reportedHost, 'LAB-WS1');
    assert.equal(health.criticalEndpoints[0].openAlerts, 2);
    assert.equal(health.criticalEndpoints[0].risk, 'critical');
    assert.equal(health.criticalEndpoints[1].reportedHost, 'LAB-WS3');
    assert.equal(health.criticalEndpoints[1].openAlerts, 1);
    assert.equal(health.criticalEndpoints[1].risk, 'medium');
    assert.equal(health.criticalEndpoints[2].reportedHost, 'LAB-WS2');
    assert.equal(health.criticalEndpoints[2].openAlerts, 1);
    assert.equal(health.criticalEndpoints[2].risk, 'low');
    assert.equal((await send('/api/stats/health', {})).status, 401);

    const alerts = await (await send('/api/alerts', { key: 'read-key' })).json();
    const criticalCase = alerts.alerts.find(alert => alert.id === 'health-a1').caseId;
    assert.equal((await send(`/api/alerts/${criticalCase}/triage`, {
        method: 'PATCH', key: 'admin-key', body: { status: 'resolved', note: 'Reviewed.' },
    })).status, 200);
    const updated = await (await send('/api/stats/health', { key: 'read-key' })).json();
    assert.equal(updated.openAlerts, 3);
    assert.deepEqual(updated.byRisk, { critical: 0, high: 1, medium: 1, low: 1, none: 0 });
    assert.equal(updated.criticalEndpoints[0].risk, 'high');
    assert.equal(updated.criticalEndpoints[0].openAlerts, 1);
});

test('alert pagination returns offset windows with total', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'read-key', EDR_ADMIN_API_KEY: 'admin-key',
    });
    for (let i = 0; i < 5; i++) {
        await runtime.send('/ingest', {
            method: 'POST', key: 'sensor-key',
            body: { id: `page-a${i}`, rule: 'EDR-PAGE', severity: 'high', timestamp: new Date(Date.now() + i * 1000).toISOString() },
        });
    }
    const first = await (await runtime.send('/api/alerts?limit=2&offset=0', { key: 'read-key' })).json();
    assert.equal(first.total, 5);
    assert.equal(first.alerts.length, 2);
    assert.equal(first.alerts[0].id, 'page-a4'); /* newest first */
    const second = await (await runtime.send('/api/alerts?limit=2&offset=2', { key: 'read-key' })).json();
    assert.equal(second.alerts.length, 2);
    assert.equal(second.alerts[0].id, 'page-a2');
    const last = await (await runtime.send('/api/alerts?limit=2&offset=4', { key: 'read-key' })).json();
    assert.equal(last.alerts.length, 1);
    assert.equal(last.alerts[0].id, 'page-a0');
    /* offset beyond total yields empty page */
    const empty = await (await runtime.send('/api/alerts?limit=2&offset=99', { key: 'read-key' })).json();
    assert.equal(empty.alerts.length, 0);
    assert.equal(empty.total, 5);
});

test('alert timeline returns related events around the alert time', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'read-key', EDR_ADMIN_API_KEY: 'admin-key',
    });
    const ts = Date.now();
    const events = [];
    for (let i = 0; i < 6; i++) {
        events.push({
            eventId: `ev-${i}`, type: 'PROCESS_START',
            timestamp: new Date(ts + (i - 3) * 100000).toISOString(),
            pid: 100 + i, image: `C:\\tools\\bin${i}.exe`,
        });
    }
    for (const ev of events) {
        await runtime.send('/ingest/events', { method: 'POST', key: 'sensor-key', body: ev });
    }
    const created = (await (await runtime.send('/ingest', {
        method: 'POST', key: 'sensor-key',
        body: { id: 'tl-a', rule: 'EDR-TL', severity: 'high', timestamp: new Date(ts).toISOString() },
    })).json()).alert;
    const timeline = await (await runtime.send(`/api/alerts/${created.caseId}/timeline`, { key: 'read-key' })).json();
    assert.equal(timeline.sourceId, created.sourceId);
    assert.equal(timeline.total, 6);
    assert.equal(timeline.timeline.length, 6);
    /* events strictly before the alert ts come first, ascending */
    assert.ok(timeline.timeline.every((event, index, arr) =>
        index === 0 || Date.parse(arr[index - 1].timestamp) <= Date.parse(event.timestamp)));
    /* 404 for unknown case */
    assert.equal((await runtime.send('/api/alerts/nope/timeline', { key: 'read-key' })).status, 404);

    /* Small limit truncates the window symmetrically around the alert time. */
    const narrow = await (await runtime.send(`/api/alerts/${created.caseId}/timeline?limit=4`, { key: 'read-key' })).json();
    assert.equal(narrow.timeline.length, 4);
    assert.equal(narrow.total, 6);
    /* 2 before (ceil(4/2)) + 2 after (floor(4/2)): before events ev-1,ev-2 (ts-200k,ts-100k),
       after events ev-3,ev-4 (ts,ts+100k) — the two oldest (ev-0) and newest (ev-5) are cut. */
    const narrowIds = narrow.timeline.map(event => event.eventId).sort();
    assert.deepEqual(narrowIds, ['ev-1', 'ev-2', 'ev-3', 'ev-4']);
});

test('alert filters support time range, priority, assignee, and full-text search', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key',
        EDR_READ_API_KEY: 'read-key',
        EDR_ADMIN_API_KEY: 'admin-key',
    });
    const ingest = async (id, rule, timestamp, extra = {}) => {
        const res = await runtime.send('/ingest', {
            method: 'POST', key: 'sensor-key',
            body: { id, rule, severity: 'high', timestamp, event: { type: 'PROCESS_START', image: 'C:\\evil.exe' }, ...extra },
        });
        assert.equal(res.status, 200);
        return (await res.json()).alert;
    };
    const old = await ingest('a1', 'EDR-FILTER-A', '2026-07-29T10:00:00Z');
    const recent = await ingest('a2', 'EDR-FILTER-B', '2026-07-30T10:00:00Z');
    const now = await ingest('a3', 'EDR-FILTER-B', '2026-07-31T10:00:00Z');

    /* Full-text search by rule and by summary image. */
    const byRule = await (await runtime.send('/api/alerts?q=EDR-FILTER-A', { key: 'read-key' })).json();
    assert.equal(byRule.total, 1);
    assert.equal(byRule.alerts[0].id, 'a1');
    const byImage = await (await runtime.send('/api/alerts?q=evil.exe', { key: 'read-key' })).json();
    assert.equal(byImage.total, 3);

    /* Time range. */
    const since = await (await runtime.send('/api/alerts?since=2026-07-30T00:00:00Z', { key: 'read-key' })).json();
    assert.equal(since.total, 2);
    const until = await (await runtime.send('/api/alerts?until=2026-07-29T23:59:59Z', { key: 'read-key' })).json();
    assert.equal(until.total, 1);
    assert.equal(until.alerts[0].id, 'a1');
    const range = await (await runtime.send(
        '/api/alerts?since=2026-07-30T00:00:00Z&until=2026-07-30T23:59:59Z', { key: 'read-key' })).json();
    assert.equal(range.total, 1);
    assert.equal(range.alerts[0].id, 'a2');

    /* Assignee + priority filters after triage. */
    await runtime.send(`/api/alerts/${old.caseId}/triage`, {
        method: 'PATCH', key: 'admin-key',
        body: { status: 'investigating', assignee: 'alice', priority: 'urgent' },
    });
    await runtime.send(`/api/alerts/${recent.caseId}/triage`, {
        method: 'PATCH', key: 'admin-key', body: { status: 'investigating' },
    });
    const assigned = await (await runtime.send('/api/alerts?assignee=alice', { key: 'read-key' })).json();
    assert.equal(assigned.total, 1);
    assert.equal(assigned.alerts[0].id, 'a1');
    const urgent = await (await runtime.send('/api/alerts?priority=urgent', { key: 'read-key' })).json();
    assert.equal(urgent.total, 1);
    assert.equal(urgent.alerts[0].id, 'a1');

    /* Invalid filters rejected. */
    assert.equal((await runtime.send('/api/alerts?since=not-a-date', { key: 'read-key' })).status, 400);
    assert.equal((await runtime.send('/api/alerts?priority=bogus', { key: 'read-key' })).status, 400);
});

test('batch triage updates many alerts and reports missing cases', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key',
        EDR_READ_API_KEY: 'read-key',
        EDR_ADMIN_API_KEY: 'admin-key',
    });
    const ingest = async (id, rule) => {
        const res = await runtime.send('/ingest', {
            method: 'POST', key: 'sensor-key',
            body: { id, rule, severity: 'medium', timestamp: '2026-07-30T10:00:00Z',
                event: { type: 'PROCESS_START', image: 'C:\\batch.exe' } },
        });
        assert.equal(res.status, 200);
        return (await res.json()).alert;
    };
    const first = await ingest('b1', 'EDR-BATCH-A');
    const second = await ingest('b2', 'EDR-BATCH-B');

    /* Non-admin rejected. */
    assert.equal((await runtime.send('/api/alerts/triage/batch', {
        method: 'POST', key: 'read-key',
        body: { caseIds: [first.caseId], status: 'resolved' },
    })).status, 401);

    /* Batch update both. */
    const batch = await runtime.send('/api/alerts/triage/batch', {
        method: 'POST', key: 'admin-key',
        body: { caseIds: [first.caseId, second.caseId], status: 'resolved',
            note: 'Batch triage', assignee: 'bob', priority: 'high' },
    });
    assert.equal(batch.status, 200);
    const batchBody = await batch.json();
    assert.equal(batchBody.updated, 2);
    assert.deepEqual(batchBody.missing, []);
    for (const alert of batchBody.alerts) {
        assert.equal(alert.triage.status, 'resolved');
        assert.equal(alert.triage.note, 'Batch triage');
        assert.equal(alert.triage.assignee, 'bob');
        assert.equal(alert.triage.priority, 'high');
    }

    /* Missing caseId reported, valid ones still updated. */
    const partial = await runtime.send('/api/alerts/triage/batch', {
        method: 'POST', key: 'admin-key',
        body: { caseIds: ['alert-does-not-exist', first.caseId], status: 'false_positive' },
    });
    assert.equal(partial.status, 200);
    const partialBody = await partial.json();
    assert.equal(partialBody.updated, 1);
    assert.equal(partialBody.missing.length, 1);

    /* Validation: empty caseIds, bad status, duplicate keys. */
    assert.equal((await runtime.send('/api/alerts/triage/batch', {
        method: 'POST', key: 'admin-key', body: { caseIds: [], status: 'resolved' },
    })).status, 400);
    assert.equal((await runtime.send('/api/alerts/triage/batch', {
        method: 'POST', key: 'admin-key', body: { caseIds: [first.caseId], status: 'bogus' },
    })).status, 400);
    const duplicate = await localHttpRequest(`${runtime.base}/api/alerts/triage/batch`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-api-key': 'admin-key' },
        body: '{"caseIds":["x"],"status":"resolved","status":"resolved"}',
    });
    assert.equal(duplicate.status, 400);
});

test('rules endpoint returns details with search, severity filter, and pagination', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key',
        EDR_READ_API_KEY: 'read-key',
        EDR_ADMIN_API_KEY: 'admin-key',
    });
    const ingest = async (id, rule, severity, mitreTactic = []) => {
        const res = await runtime.send('/ingest', {
            method: 'POST', key: 'sensor-key',
            body: { id, rule, severity, timestamp: '2026-07-30T10:00:00Z',
                event: { type: 'PROCESS_START', image: 'C:\\rules.exe', mitre_tactic: mitreTactic } },
        });
        assert.equal(res.status, 200);
    };
    await ingest('r1', 'EDR-RULES-A', 'critical', ['Execution']);
    await ingest('r2', 'EDR-RULES-A', 'critical', ['Execution']);
    await ingest('r3', 'EDR-RULES-B', 'high', ['Persistence']);

    const all = await (await runtime.send('/api/rules', { key: 'read-key' })).json();
    assert.equal(all.total, 2);
    const ruleA = all.rules.find(entry => entry.rule === 'EDR-RULES-A');
    assert.equal(ruleA.count, 2);
    assert.equal(ruleA.bySeverity.critical, 2);
    assert.equal(ruleA.endpointCount, 1);
    assert.deepEqual(ruleA.mitreTactic, ['Execution']);
    assert.equal(ruleA.actions.length, 0); /* no action field on native alerts */

    /* Search. */
    const searched = await (await runtime.send('/api/rules?q=EDR-RULES-B', { key: 'read-key' })).json();
    assert.equal(searched.total, 1);
    assert.equal(searched.rules[0].rule, 'EDR-RULES-B');

    /* Severity filter. */
    const bySeverity = await (await runtime.send('/api/rules?severity=critical', { key: 'read-key' })).json();
    assert.equal(bySeverity.total, 1);
    assert.equal(bySeverity.rules[0].rule, 'EDR-RULES-A');

    /* Pagination. */
    const paged = await (await runtime.send('/api/rules?limit=1&offset=1', { key: 'read-key' })).json();
    assert.equal(paged.rules.length, 1);
    assert.equal(paged.total, 2);
});

test('health endpoint is unauthenticated and reports liveness', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key',
        EDR_READ_API_KEY: 'read-key',
        EDR_ADMIN_API_KEY: 'admin-key',
    });
    const res = await localHttpRequest(`${runtime.base}/api/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'ok');
    assert.equal(typeof body.uptime, 'number');
    assert.equal(body.alerts, 0);
});

test('alert export supports assignee, priority, rule, and time filters', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key',
        EDR_READ_API_KEY: 'read-key',
        EDR_ADMIN_API_KEY: 'admin-key',
    });
    const ingest = async (id, rule, timestamp, severity = 'high') => {
        const res = await runtime.send('/ingest', {
            method: 'POST', key: 'sensor-key',
            body: { id, rule, severity, timestamp, event: { type: 'PROCESS_START', image: 'C:\\export.exe' } },
        });
        assert.equal(res.status, 200);
        return (await res.json()).alert;
    };
    const first = await ingest('e1', 'EDR-EXPORT-A', '2026-07-29T10:00:00Z');
    const second = await ingest('e2', 'EDR-EXPORT-B', '2026-07-31T10:00:00Z');
    await runtime.send(`/api/alerts/${first.caseId}/triage`, {
        method: 'PATCH', key: 'admin-key',
        body: { status: 'investigating', assignee: 'carol', priority: 'high' },
    });
    /* CSV export filtered by assignee. */
    const res = await runtime.send('/api/export/alerts?assignee=carol', { key: 'read-key' });
    assert.equal(res.status, 200);
    const csv = await res.text();
    /* localHttpRequest().text() decodes UTF-8 and consumes the BOM; the server emits
     * \uFEFF for Excel compatibility, so accept both forms. */
    assert.ok(csv.startsWith('timestamp,rule') || csv.startsWith('\uFEFFtimestamp,rule'));
    assert.ok(csv.includes('EDR-EXPORT-A'));
    assert.ok(!csv.includes('EDR-EXPORT-B'));
    assert.ok(csv.includes('carol'));
    assert.ok(csv.includes('high')); /* priority column */
    /* Time range export. */
    const ranged = await (await runtime.send(
        '/api/export/alerts?since=2026-07-30T00:00:00Z', { key: 'read-key' })).text();
    assert.ok(ranged.includes('EDR-EXPORT-B'));
    assert.ok(!ranged.includes('EDR-EXPORT-A'));
    /* Invalid filter. */
    assert.equal((await runtime.send('/api/export/alerts?priority=bogus', { key: 'read-key' })).status, 400);
});

test('event hunt and export support pid, process, and time filters', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key',
        EDR_READ_API_KEY: 'read-key',
        EDR_ADMIN_API_KEY: 'admin-key',
    });
    const sendEvents = async events => {
        const res = await runtime.send('/ingest/events', {
            method: 'POST', key: 'sensor-key', body: events,
        });
        assert.equal(res.status, 200);
    };
    await sendEvents([
        { eventId: 'ev-p1', sourceId: 'host-a', timestamp: '2026-07-30T10:00:00Z', type: 'PROCESS_START',
            raw: { pid: 100, image: 'C:\\a.exe' } },
        { eventId: 'ev-p2', sourceId: 'host-a', timestamp: '2026-07-30T10:01:00Z', type: 'NET_CONNECT',
            raw: { pid: 100, image: 'C:\\a.exe' } },
        { eventId: 'ev-p3', sourceId: 'host-b', timestamp: '2026-07-30T10:02:00Z', type: 'PROCESS_START',
            raw: { pid: 200, image: 'C:\\b.exe' } },
    ]);
    const byPid = await (await runtime.send('/api/events?pid=100', { key: 'read-key' })).json();
    assert.equal(byPid.total, 2);
    const byPidAndType = await (await runtime.send('/api/events?pid=100&type=NET_CONNECT', { key: 'read-key' })).json();
    assert.equal(byPidAndType.total, 1);
    /* Export by pid. */
    const exported = await (await runtime.send('/api/export/events?pid=200', { key: 'read-key' })).text();
    assert.ok(exported.includes('ev-p3'));
    assert.ok(!exported.includes('ev-p1'));
    /* Invalid pid. */
    assert.equal((await runtime.send('/api/events?pid=not-a-number', { key: 'read-key' })).status, 400);
});

test('similar alerts endpoint clusters same rule and source', async t => {
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key',
        EDR_READ_API_KEY: 'read-key',
        EDR_ADMIN_API_KEY: 'admin-key',
    });
    const ingest = async (id, rule, sourceId) => {
        const res = await runtime.send('/ingest', {
            method: 'POST', key: 'sensor-key',
            body: { id, rule, sourceId, severity: 'high', timestamp: '2026-07-30T10:00:00Z',
                event: { type: 'PROCESS_START', image: 'C:\\similar.exe' } },
            headers: { 'x-api-key': 'sensor-key' },
        });
        assert.equal(res.status, 200);
        return (await res.json()).alert;
    };
    const a1 = await ingest('sim-1', 'EDR-SIM', 'host-a');
    const a2 = await ingest('sim-2', 'EDR-SIM', 'host-a');
    await ingest('sim-3', 'EDR-SIM', 'host-b'); /* different source */
    await ingest('sim-4', 'EDR-OTHER', 'host-a'); /* different rule */
    const similar = await (await runtime.send(
        `/api/alerts/${a1.caseId}/similar`, { key: 'read-key' })).json();
    assert.equal(similar.total, 1);
    assert.equal(similar.alerts[0].id, 'sim-2');
    assert.equal(similar.rule, 'EDR-SIM');
    assert.equal(similar.sourceId, 'host-a');
    const second = await (await runtime.send(
        `/api/alerts/${a2.caseId}/similar`, { key: 'read-key' })).json();
    assert.equal(second.total, 1);
    assert.equal(second.alerts[0].id, 'sim-1');
    assert.equal((await runtime.send('/api/alerts/alert-missing/similar', { key: 'read-key' })).status, 404);
});

test('rule coverage report joins catalog with fired alerts', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-cov-'));
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dataDir, 'rules.json'), JSON.stringify({
        comment: 'test catalog',
        rules: [
            { id: 'EDR-COV-A', severity: 'high', mitre_attack: ['T1059.001'], mitre_tactic: ['Execution'],
              match: { image: { contains: 'powershell' } } },
            { id: 'EDR-COV-B', severity: 'medium', mitre_attack: [], mitre_tactic: ['Discovery'],
              match: { image: { contains: 'net.exe' } } },
            { id: 'EDR-COV-C', severity: 'low',
              match: { image: { contains: 'nothing' } } },
        ],
    }));
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'read-key',
    }, { rulesPath: path.join(dataDir, 'rules.json') });
    const res = await runtime.send('/ingest', {
        method: 'POST', key: 'sensor-key',
        body: { rule: 'EDR-COV-A', severity: 'high', timestamp: '2026-08-01T00:00:00Z',
            event: { type: 'PROCESS_START' } },
    });
    assert.equal(res.status, 200);
    /* Auth is required. */
    assert.equal((await runtime.send('/api/rules/coverage')).status, 401);
    const coverage = await (await runtime.send('/api/rules/coverage', { key: 'read-key' })).json();
    assert.equal(coverage.totalRules, 3);
    assert.equal(coverage.bySeverity.high, 1);
    assert.equal(coverage.bySeverity.medium, 1);
    assert.equal(coverage.bySeverity.low, 1);
    assert.deepEqual(coverage.firedRules, ['EDR-COV-A']);
    assert.deepEqual(coverage.neverFired, ['EDR-COV-B', 'EDR-COV-C']);
    assert.equal(coverage.coveragePct, 33.3);
    /* Tactic/technique matrix includes the tactic-only rule. */
    const execution = coverage.tactics.find(entry => entry.tactic === 'Execution');
    assert.ok(execution);
    const ps = execution.techniques.find(entry => entry.technique === 'T1059.001');
    assert.deepEqual(ps.ruleIds, ['EDR-COV-A']);
    const discovery = coverage.tactics.find(entry => entry.tactic === 'Discovery');
    assert.ok(discovery.techniques.some(entry => entry.technique === '(tactic-level only)'));
    /* Rule without any MITRE mapping lands in unmappedRules. */
    assert.deepEqual(coverage.unmappedRules, ['EDR-COV-C']);
    /* Reference gaps list known techniques missing from the catalog. */
    assert.ok(coverage.referenceGaps.includes('T1486'));
});

test('evidence list mirrors alerts and coverage filtering with pagination metadata', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-ev-'));
    const evidenceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-evidence-'));
    t.after(() => {
        fs.rmSync(dataDir, { recursive: true, force: true });
        fs.rmSync(evidenceDir, { recursive: true, force: true });
    });
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key',
        EDR_READ_API_KEY: 'read-key',
        EDR_EVIDENCE_DIR: evidenceDir,
    });
    const ridA = '11111111-1111-4111-8111-111111111111';
    const ridB = '22222222-2222-4222-8222-222222222222';
    const ridC = '33333333-3333-4333-8333-333333333333';
    for (const [rid, rule, severity, ts] of [
        [ridA, 'EDR-EVICT-A', 'high', '2026-07-30T10:00:00Z'],
        [ridB, 'EDR-EVICT-B', 'critical', '2026-07-30T11:00:00Z'],
        [ridC, 'EDR-EVICT-A', 'low', '2026-07-31T10:00:00Z'],
    ]) {
        const res = await runtime.send('/ingest', {
            method: 'POST', key: 'sensor-key',
            body: { rule, severity, timestamp: ts, event: { type: 'PROCESS_START', auto_response_request_id: rid, auto_response_evidence_path: `C:\\ProgramData\\EDR\\evidence\\${rid}\\snapshot.txt` } },
        });
        assert.equal(res.status, 200);
    }
    let body = await (await runtime.send('/api/evidence', { key: 'read-key' })).json();
    assert.equal(body.total, 3);
    assert.equal(body.limit, 100);
    assert.equal(body.offset, 0);
    assert.equal(body.evidence.length, 3);
    // requestId contains (case-insensitive)
    body = await (await runtime.send(`/api/evidence?requestId=${ridA.slice(0, 8)}`, { key: 'read-key' })).json();
    assert.equal(body.total, 1);
    assert.equal(body.evidence[0].requestId, ridA);
    // requestId case-insensitive
    body = await (await runtime.send(`/api/evidence?requestId=${ridA.slice(0, 8).toUpperCase()}`, { key: 'read-key' })).json();
    assert.equal(body.total, 1);
    // rule contains
    body = await (await runtime.send('/api/evidence?rule=evict-a', { key: 'read-key' })).json();
    assert.equal(body.total, 2);
    // rule case-insensitive
    body = await (await runtime.send('/api/evidence?rule=EVICT-A', { key: 'read-key' })).json();
    assert.equal(body.total, 2);
    // severity exact
    body = await (await runtime.send('/api/evidence?severity=high', { key: 'read-key' })).json();
    assert.equal(body.total, 1);
    assert.equal(body.evidence[0].severity, 'high');
    // since / until ISO-8601
    body = await (await runtime.send('/api/evidence?since=2026-07-30T10%3A30%3A00Z', { key: 'read-key' })).json();
    assert.equal(body.total, 2);
    body = await (await runtime.send('/api/evidence?until=2026-07-30T10%3A30%3A00Z', { key: 'read-key' })).json();
    assert.equal(body.total, 1);
    // since + until range
    body = await (await runtime.send('/api/evidence?since=2026-07-30T10%3A00%3A00Z&until=2026-07-30T11%3A00%3A00Z', { key: 'read-key' })).json();
    assert.equal(body.total, 2);
    // pagination
    body = await (await runtime.send('/api/evidence?limit=1&offset=1', { key: 'read-key' })).json();
    assert.equal(body.total, 3);
    assert.equal(body.limit, 1);
    assert.equal(body.offset, 1);
    assert.equal(body.evidence.length, 1);
    // limit caps at 1000
    body = await (await runtime.send('/api/evidence?limit=5000', { key: 'read-key' })).json();
    assert.equal(body.limit, 1000);
    // strict query validation and ISO8601
    assert.equal((await runtime.send('/api/evidence?unknown=1', { key: 'read-key' })).status, 400);
    assert.equal((await runtime.send('/api/evidence?since=not-a-date', { key: 'read-key' })).status, 400);
    assert.equal((await runtime.send('/api/evidence?until=not-a-date', { key: 'read-key' })).status, 400);
});

test('coverage gaps export supports severity/tactic/since filtering and strict validation', async t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-gaps-'));
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    fs.writeFileSync(path.join(dataDir, 'rules.json'), JSON.stringify({
        rules: [
            { id: 'EDR-GAP-A', severity: 'high', mitre_attack: ['T1059.001'], mitre_tactic: ['Execution'], match: {} },
            { id: 'EDR-GAP-B', severity: 'medium', mitre_attack: ['T1003'], mitre_tactic: ['Credential Access'], match: {} },
            { id: 'EDR-GAP-C', severity: 'low', mitre_attack: ['T1003.001'], mitre_tactic: ['Credential Access'], match: {} },
        ],
    }));
    const runtime = await fixture(t, {
        EDR_INGEST_API_KEY: 'sensor-key', EDR_READ_API_KEY: 'read-key',
    }, { rulesPath: path.join(dataDir, 'rules.json') });
    // fire one rule before since filter
    await runtime.send('/ingest', { method: 'POST', key: 'sensor-key', body: { rule: 'EDR-GAP-A', severity: 'high', timestamp: '2026-08-01T00:00:00Z', event: { type: 'PROCESS_START' } } });
    // format json with severity filter
    let body = await (await runtime.send('/api/rules/coverage/gaps/export?severity=high', { key: 'read-key' })).json();
    assert.ok(body.gaps.length > 0);
    assert.ok(body.gaps.every(g => g.technique));
    // tactic filter
    body = await (await runtime.send('/api/rules/coverage/gaps/export?tactic=Execution', { key: 'read-key' })).json();
    assert.ok(body.gaps.length > 0);
    // since filter (only alerts >= since count as fired, so neverFired changes but gaps derived from catalog still filtered by catalog side)
    body = await (await runtime.send('/api/rules/coverage/gaps/export?since=2026-09-01T00:00:00Z', { key: 'read-key' })).json();
    assert.ok(body.gaps.length > 0);
    // csv format also respects filters
    const csv = await (await runtime.send('/api/rules/coverage/gaps/export?format=csv&severity=high', { key: 'read-key' })).text();
    assert.ok(csv.startsWith('technique,configKey') || csv.startsWith('\uFEFFtechnique,configKey'));
    // illegal since 400
    assert.equal((await runtime.send('/api/rules/coverage/gaps/export?since=not-a-date', { key: 'read-key' })).status, 400);
    // unknown key 400
    assert.equal((await runtime.send('/api/rules/coverage/gaps/export?unknown=1', { key: 'read-key' })).status, 400);
});
