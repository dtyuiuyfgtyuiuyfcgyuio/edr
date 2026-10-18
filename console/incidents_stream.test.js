'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { loadIncidentsAsync, MAX_INCIDENT_FILE_BYTES,
    MAX_INCIDENT_RECORD_BYTES, MAX_INCIDENT_STATES } = require('./incidents');
const { verifyFileStream, ZERO_HASH, chainHashFor, payloadHashFor } = require('./audit_chain');

function fixture(t, content = '') {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-incidents-stream-'));
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    const file = path.join(dataDir, 'incidents.jsonl');
    fs.writeFileSync(file, content);
    return { dataDir, file };
}

function makeChain(count) {
    let previous = ZERO_HASH;
    const lines = [];
    for (let seq = 1; seq <= count; seq += 1) {
        const payload = {
            id: `chain-${seq}`,
            kind: seq === count ? 'incident' : 'open',
            lastSeen100ns: seq,
        };
        const hash = chainHashFor(seq, previous, payloadHashFor(payload));
        lines.push(JSON.stringify({ ...payload, chain_seq: seq,
            chain_prev: previous, chain_hash: hash }));
        previous = hash;
    }
    return lines;
}

test('async replay yields to timers while rebuilding newest states', async t => {
    const rows = [JSON.stringify({ id: 'same', kind: 'open', lastSeen100ns: 1 })];
    for (let index = 0; index < 20000; index += 1) {
        rows.push(JSON.stringify({ id: `noise-${index}`, kind: 'open',
            lastSeen100ns: index + 2 }));
    }
    rows.push(JSON.stringify({ id: 'same', kind: 'incident', lastSeen100ns: 30000 }));
    const input = fixture(t, `${rows.join('\n')}\n`);

    let timerRan = false;
    const timer = setTimeout(() => { timerRan = true; }, 0);
    const loaded = await loadIncidentsAsync(input.dataDir, { maxIncidents: 5 });
    clearTimeout(timer);

    assert.equal(timerRan, true, 'stream replay must yield while processing a large ledger');
    assert.equal(loaded.integrity.status, 'legacy');
    assert.deepEqual(loaded.completeness, {
        status: 'truncated', scanned: rows.length, limit: 5,
        available: 20001, reason: 'result_count',
    });
    assert.equal(loaded.scanned, rows.length);
    assert.equal(loaded.incidents[0].id, 'same');
    assert.equal(loaded.incidents[0].state, 'closed');
    assert.equal(loaded.incidents[0].lastSeen100ns, 30000);
    assert.equal(loaded.incidents.length, 5);
});

test('async replay verifies a damaged early chain record and suppresses partial state', async t => {
    const lines = makeChain(4096);
    lines[0] = lines[0].replace('chain-1', 'tampered-prefix');
    const input = fixture(t, `${lines.join('\n')}\n`);

    const loaded = await loadIncidentsAsync(input.dataDir);
    assert.equal(loaded.integrity.status, 'broken');
    assert.equal(loaded.integrity.brokenAt, 1);
    assert.deepEqual(loaded.incidents, []);
});

test('async verifier rejects invalid UTF-8 and caps issue retention', async t => {
    const input = fixture(t, Buffer.concat([
        Buffer.from('{"id":"bad-'), Buffer.from([0xff]), Buffer.from('"}\n{bad\n[]\nnull\n'),
    ]));

    const result = await verifyFileStream(input.file, { maxIssues: 2 });
    assert.equal(result.status, 'broken');
    assert.equal(result.valid, false);
    assert.equal(result.brokenAt, 1);
    assert.ok(result.issues.some(issue => issue.includes('UTF-8')));
    assert.equal(result.issues.length, 2);
    assert.equal(result.issuesTruncated, true);
    assert.ok(result.issueCount > result.issues.length);
});

test('async verifier rejects oversized records and files without claiming validity', async t => {
    assert.ok(MAX_INCIDENT_RECORD_BYTES > 0);
    assert.ok(MAX_INCIDENT_FILE_BYTES > MAX_INCIDENT_RECORD_BYTES);
    const line = JSON.stringify({ id: 'oversized', value: 'x'.repeat(200) });
    const recordInput = fixture(t, `${line}\n`);
    const recordResult = await verifyFileStream(recordInput.file, { maxRecordBytes: 64 });
    assert.equal(recordResult.status, 'limit_exceeded');
    assert.equal(recordResult.valid, false);
    assert.equal(recordResult.limit, 'record_bytes');

    const fileInput = fixture(t, `${JSON.stringify({ id: 'too-large' })}\n`);
    const fileResult = await verifyFileStream(fileInput.file, { maxFileBytes: 1 });
    assert.equal(fileResult.status, 'limit_exceeded');
    assert.equal(fileResult.valid, false);
    assert.equal(fileResult.limit, 'file_bytes');
});

test('state-count limit returns no partial incident index', async t => {
    assert.ok(MAX_INCIDENT_STATES > 0);
    const input = fixture(t, [
        JSON.stringify({ id: 'one', kind: 'open' }),
        JSON.stringify({ id: 'two', kind: 'open' }),
    ].join('\n') + '\n');
    const loaded = await loadIncidentsAsync(input.dataDir, { maxStates: 1 });
    assert.equal(loaded.integrity.status, 'legacy');
    assert.equal(loaded.completeness.status, 'limit_exceeded');
    assert.equal(loaded.completeness.reason, 'state_count');
    assert.deepEqual(loaded.incidents, []);
});

test('descriptor snapshot mutation during replay is unavailable, not a mixed view', async t => {
    const input = fixture(t, `${JSON.stringify({ id: 'first', kind: 'open' })}\n`);
    let appended = false;
    const result = await verifyFileStream(input.file, {
        onRecord() {
            if (appended) return;
            appended = true;
            fs.appendFileSync(input.file,
                `${JSON.stringify({ id: 'second', kind: 'open' })}\n`);
        },
    });
    assert.equal(appended, true);
    assert.equal(result.valid, false);
    assert.equal(result.status, 'unreadable');
    assert.equal(result.reason, 'snapshot_changed');
});

test('parseable unterminated tail stays broken in async reconstruction', async t => {
    const lines = makeChain(2);
    const input = fixture(t, `${lines.join('\n')}\n${JSON.stringify({
        id: 'uncommitted', kind: 'open',
    })}`);
    const loaded = await loadIncidentsAsync(input.dataDir);
    assert.equal(loaded.integrity.status, 'broken');
    assert.deepEqual(loaded.incidents, []);
});
