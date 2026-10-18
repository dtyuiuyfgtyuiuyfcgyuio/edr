/* Smoke test for the new console features against a live runtime. */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRuntime } = require('./server');

const quietLogger = { log() {}, warn() {}, error() {} };
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-smoke-'));
/* Keys come from the environment; throwaway random keys keep local runs
 * working without shipping reusable credentials in source. */
const ingestKey = process.env.EDR_INGEST_API_KEY || crypto.randomUUID();
const readKey = process.env.EDR_READ_API_KEY || crypto.randomUUID();
const adminKey = process.env.EDR_ADMIN_API_KEY || crypto.randomUUID();
const runtime = createRuntime({ dataDir, logger: quietLogger, env: {
    EDR_INGEST_API_KEY: ingestKey,
    EDR_READ_API_KEY: readKey,
    EDR_ADMIN_API_KEY: adminKey,
} });

(async () => {
    await runtime.start(0, '127.0.0.1');
    const base = `http://127.0.0.1:${runtime.server.address().port}`;
    const send = (url, { key, body, ...options } = {}) => fetch(`${base}${url}`, {
        ...options,
        headers: {
            ...(body === undefined ? {} : { 'content-type': 'application/json' }),
            ...(key === undefined ? {} : { 'x-api-key': key }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
    });

    /* Ingest two alerts. */
    for (const [id, rule, severity, ts] of [
        ['s1', 'EDR-SMOKE-A', 'critical', '2026-07-29T10:00:00Z'],
        ['s2', 'EDR-SMOKE-B', 'high', '2026-07-31T10:00:00Z'],
    ]) {
        const res = await send('/ingest', { method: 'POST', key: ingestKey,
            body: { id, rule, severity, timestamp: ts, event: { type: 'PROCESS_START', image: 'C:\\smoke.exe' } } });
        assert.equal(res.status, 200);
    }

    /* Health endpoint (no auth). */
    const health = await (await fetch(`${base}/api/health`)).json();
    assert.equal(health.status, 'ok');
    assert.equal(health.alerts, 2);

    /* Alert filters: since/until/priority/assignee. */
    const since = await (await send('/api/alerts?since=2026-07-30T00:00:00Z', { key: readKey })).json();
    assert.equal(since.total, 1);
    assert.equal(since.alerts[0].id, 's2');

    const q = await (await send('/api/alerts?q=SMOKE-B', { key: readKey })).json();
    assert.equal(q.total, 1);

    /* Batch triage. */
    const list1 = await (await send('/api/alerts', { key: readKey })).json();
    const caseId1 = list1.alerts.find(a => a.id === 's1').caseId;
    const caseId2 = list1.alerts.find(a => a.id === 's2').caseId;
    const batch = await send('/api/alerts/triage/batch', { method: 'POST', key: adminKey,
        body: { caseIds: [caseId1, caseId2], status: 'investigating', assignee: 'alice', priority: 'urgent' } });
    assert.equal(batch.status, 200);
    const batchBody = await batch.json();
    assert.equal(batchBody.updated, 2);

    const urgent = await (await send('/api/alerts?priority=urgent', { key: readKey })).json();
    assert.equal(urgent.total, 2);
    const assigned = await (await send('/api/alerts?assignee=alice', { key: readKey })).json();
    assert.equal(assigned.total, 2);

    /* Rules endpoint details. */
    const rules = await (await send('/api/rules', { key: readKey })).json();
    assert.equal(rules.total, 2);
    const ruleA = rules.rules.find(r => r.rule === 'EDR-SMOKE-A');
    assert.equal(ruleA.count, 1);
    assert.equal(ruleA.openCount, 1); /* investigating counts as open */
    const rulesSearch = await (await send('/api/rules?q=SMOKE-B', { key: readKey })).json();
    assert.equal(rulesSearch.total, 1);

    /* Endpoint count reflects both. */
    const stats = await (await send('/api/stats', { key: readKey })).json();
    assert.equal(stats.total, 2);

    console.log('smoke test: all checks passed');
    await new Promise(resolve => runtime.server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
    process.exit(0);
})().catch(err => { console.error('SMOKE FAIL:', err); process.exit(1); });
