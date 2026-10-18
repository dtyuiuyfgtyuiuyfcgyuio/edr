'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { loadIncidents, findIncident, MAX_RECORDS_SCANNED } = require('./incidents');

function writeLedger(t, lines) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-incidents-'));
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    const file = path.join(dataDir, 'incidents.jsonl');
    fs.writeFileSync(file, lines.join('\n') + '\n');
    return { dataDir, file };
}

function record(id, lastSeen100ns, kind = 'open') {
    return JSON.stringify({ id, kind, lastSeen100ns });
}

test('latest incident precedes capacity truncation and ties sort deterministically', t => {
    const lines = Array.from({ length: 1001 }, (_, index) => record(`case-${index}`, index));
    const fixture = writeLedger(t, lines);
    const latest = loadIncidents(fixture.dataDir, { maxIncidents: 1 });
    assert.deepEqual(latest.incidents.map(item => item.id), ['case-1000']);

    const ties = writeLedger(t, [record('case-z', 50), record('case-a', 50), record('case-B', 50)]);
    const first = loadIncidents(ties.dataDir).incidents.map(item => item.id);
    const second = loadIncidents(ties.dataDir).incidents.map(item => item.id);
    assert.deepEqual(first, ['case-B', 'case-a', 'case-z']);
    assert.deepEqual(second, first);
});

test('incident replay marks only a nonempty record beyond the scan ceiling incomplete', t => {
    assert.equal(MAX_RECORDS_SCANNED, 200000);
    const lines = [record('known', MAX_RECORDS_SCANNED + 1)];
    for (let index = 1; index < MAX_RECORDS_SCANNED; index += 1) lines.push(record(`noise-${index}`, index));
    lines.push('');
    const atCeiling = writeLedger(t, lines);
    const complete = loadIncidents(atCeiling.dataDir);
    assert.deepEqual(complete.completeness, { status: 'complete', scanned: MAX_RECORDS_SCANNED, limit: MAX_RECORDS_SCANNED });
    assert.equal(complete.integrity.status, 'legacy');
    assert.equal(complete.incidents.some(item => item.id === 'known'), true);

    lines.push(record('known', 200001, 'incident'));
    const overCeiling = writeLedger(t, lines);
    const incomplete = loadIncidents(overCeiling.dataDir);
    assert.deepEqual(incomplete.completeness, { status: 'limit_exceeded', scanned: MAX_RECORDS_SCANNED, limit: MAX_RECORDS_SCANNED });
    assert.deepEqual(incomplete.incidents, []);
    assert.equal(incomplete.integrity.status, 'legacy');
    assert.equal(incomplete.integrity.total, MAX_RECORDS_SCANNED + 1);
    assert.equal(findIncident(overCeiling.dataDir, 'known'), null);
});

test('all load branches include completeness without changing integrity states', t => {
    const missingDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-incidents-missing-'));
    t.after(() => fs.rmSync(missingDir, { recursive: true, force: true }));
    const missing = loadIncidents(missingDir);
    assert.deepEqual(missing.completeness, { status: 'complete', scanned: 0, limit: MAX_RECORDS_SCANNED });
    assert.equal(missing.integrity.status, 'missing');

    const broken = writeLedger(t, ['{bad']);
    assert.equal(loadIncidents(broken.dataDir).integrity.status, 'broken');
    assert.equal(loadIncidents(broken.dataDir).completeness.status, 'complete');

    const unreadableDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-incidents-unreadable-'));
    t.after(() => fs.rmSync(unreadableDir, { recursive: true, force: true }));
    const unreadableFile = path.join(unreadableDir, 'ledger.jsonl');
    fs.mkdirSync(unreadableFile);
    const unreadable = loadIncidents(unreadableDir, { file: unreadableFile });
    assert.equal(unreadable.integrity.status, 'unreadable');
    assert.deepEqual(unreadable.completeness, { status: 'complete', scanned: 0, limit: MAX_RECORDS_SCANNED });
});
