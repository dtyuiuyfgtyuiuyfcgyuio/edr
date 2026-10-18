'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createRuntime } = require('./server');

const quietLogger = { log() {}, warn() {}, error() {} };

function request(port, pathname, { method = 'GET', key, body } = {}) {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: '127.0.0.1', port, path: pathname, method,
            headers: {
                ...(key ? { 'x-api-key': key } : {}),
                ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}),
            },
        }, response => {
            const chunks = [];
            response.on('data', chunk => chunks.push(chunk));
            response.on('end', () => resolve({
                status: response.statusCode,
                body: Buffer.concat(chunks).toString('utf8'),
            }));
        });
        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
    });
}

async function startRuntime(t, eventRows) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-process-hunt-'));
    fs.writeFileSync(path.join(dataDir, 'events.jsonl'), `${eventRows.map(row => JSON.stringify(row)).join('\n')}\n`);
    const runtime = createRuntime({
        dataDir,
        env: { EDR_INGEST_API_KEY: 'sensor-ingest', EDR_READ_API_KEY: 'reader' },
        logger: quietLogger,
    });
    await runtime.start(0, '127.0.0.1');
    t.after(async () => {
        await new Promise(resolve => runtime.server.close(resolve));
        fs.rmSync(dataDir, { recursive: true, force: true });
    });
    return runtime.server.address().port;
}

const alpha = 'sensor-alpha';
const beta = 'sensor-beta';
const rootKey = `${alpha}:guid:root`;

test('GET /api/process-hunt returns only the same-source root subtree with HTTP metadata', async t => {
    const port = await startRuntime(t, [
        { eventId: 'root-event', sourceId: alpha, type: 'PROCESS_START', timestamp: '2026-10-04T10:00:00.000Z', ProcessGuid: 'root' },
        { eventId: 'child-event', sourceId: alpha, type: 'PROCESS_START', timestamp: '2026-10-04T10:00:01.000Z', ProcessGuid: 'child', parent_ProcessGuid: 'root' },
        { eventId: 'grandchild-event', sourceId: alpha, type: 'PROCESS_START', timestamp: '2026-10-04T10:00:02.000Z', ProcessGuid: 'grandchild', parent_ProcessGuid: 'child' },
        { eventId: 'other-source-event', sourceId: beta, type: 'PROCESS_START', timestamp: '2026-10-04T10:00:03.000Z', ProcessGuid: 'other', parent_ProcessGuid: 'root' },
        { eventId: 'unrelated-event', sourceId: alpha, type: 'PROCESS_START', timestamp: '2026-10-04T10:00:04.000Z', ProcessGuid: 'unrelated' },
    ]);

    const response = await request(port, `/api/process-hunt?processKey=${encodeURIComponent(rootKey)}`, { key: 'reader' });

    assert.equal(response.status, 200);
    const body = JSON.parse(response.body);
    assert.deepEqual(body.nodes.map(node => [node.processKey, node.depth]), [
        [rootKey, 0], [`${alpha}:guid:child`, 1], [`${alpha}:guid:grandchild`, 2],
    ]);
    assert.deepEqual(body.events.map(event => event.eventId), ['root-event', 'child-event', 'grandchild-event']);
    assert.equal(body.completeness.status, 'complete');
    assert.equal(body.completeness.scope, 'retained_window');
    assert.equal(body.truncated, false);

    const partialResponse = await request(port,
        `/api/process-hunt?processKey=${encodeURIComponent(rootKey)}&maxDepth=1&eventLimit=1`,
        { key: 'reader' });
    assert.equal(partialResponse.status, 200);
    const partial = JSON.parse(partialResponse.body);
    assert.equal(partial.completeness.status, 'partial');
    assert.equal(partial.completeness.scope, 'retained_window');
    assert.equal(partial.truncated, true);
    assert.deepEqual(partial.reasons, ['depth_limit', 'event_limit']);
    assert.deepEqual(partial.events.map(event => event.eventId), ['child-event']);

    const legacyTree = await request(port, '/api/process-tree', { key: 'reader' });
    assert.equal(legacyTree.status, 200);
    assert.equal(Array.isArray(JSON.parse(legacyTree.body)), true);

    const { buildHandlers } = await import('./mcp/src/tools.mjs');
    const mcpCalls = [];
    const mcpHandlers = buildHandlers({
        retrying: operation => operation(),
        get: async (pathname, { query }) => {
            mcpCalls.push({ pathname, query });
            const search = new URLSearchParams();
            for (const [name, value] of Object.entries(query)) search.set(name, String(value));
            const mcpResponse = await request(port, `${pathname}?${search}`, { key: 'reader' });
            assert.equal(mcpResponse.status, 200);
            return JSON.parse(mcpResponse.body);
        },
    });
    const mcpResult = await mcpHandlers.edr_process_hunt({
        process_key: rootKey, max_nodes: 2, max_depth: 2, event_limit: 1,
    });
    assert.deepEqual(mcpCalls, [{
        pathname: '/api/process-hunt',
        query: { processKey: rootKey, maxNodes: 2, maxDepth: 2, eventLimit: 1 },
    }]);
    assert.deepEqual(mcpResult.events.map(event => event.eventId), ['child-event']);
    assert.equal(mcpResult.truncated, true);
    assert.deepEqual(mcpResult.reasons, ['node_limit', 'event_limit']);
    assert.deepEqual(mcpResult.completeness, { scope: 'retained_window', status: 'partial' });
});

test('GET /api/process-hunt requires read auth and an existing exact process key', async t => {
    const port = await startRuntime(t, [
        { eventId: 'root-event', sourceId: alpha, type: 'PROCESS_START', timestamp: '2026-10-04T10:00:00.000Z', ProcessGuid: 'root' },
    ]);

    assert.equal((await request(port, `/api/process-hunt?processKey=${encodeURIComponent(rootKey)}`)).status, 401);
    assert.equal((await request(port, '/api/process-hunt?processKey=missing', { key: 'reader' })).status, 404);
});

test('GET /api/process-hunt rejects duplicate, array, unknown, and noncanonical limit parameters', async t => {
    const port = await startRuntime(t, [
        { eventId: 'root-event', sourceId: alpha, type: 'PROCESS_START', timestamp: '2026-10-04T10:00:00.000Z', ProcessGuid: 'root' },
    ]);
    const invalid = [
        '/api/process-hunt',
        '/api/process-hunt?processKey=a&processKey=b',
        '/api/process-hunt?processKey%5B%5D=a&processKey%5B%5D=b',
        `/api/process-hunt?processKey=${encodeURIComponent(rootKey)}&unknown=x`,
        `/api/process-hunt?processKey=${'x'.repeat(1025)}`,
        `/api/process-hunt?processKey=${encodeURIComponent(rootKey)}&maxNodes=01`,
        `/api/process-hunt?processKey=${encodeURIComponent(rootKey)}&maxDepth=65`,
        `/api/process-hunt?processKey=${encodeURIComponent(rootKey)}&eventLimit=0`,
        `/api/process-hunt?processKey=${encodeURIComponent(rootKey)}&maxNodes=1001`,
    ];
    for (const pathname of invalid) {
        const response = await request(port, pathname, { key: 'reader' });
        assert.equal(response.status, 400, pathname);
    }
});
