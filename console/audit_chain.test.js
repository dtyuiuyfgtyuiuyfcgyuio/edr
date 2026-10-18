const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { verifyChain, verifyFile, appendChainedRecord, sha256Hex, stableStringify, chainHashFor, payloadHashFor, ZERO_HASH } = require('./audit_chain');

function makeRecord(seq, prev, payload) {
    const pHash = payloadHashFor(payload);
    const ch = chainHashFor(seq, prev, pHash);
    return { ...payload, chain_seq: seq, chain_prev: prev, chain_hash: ch };
}
function toLine(obj){ return JSON.stringify(obj); }

test('valid chain passes', () => {
    const p1={rule:'R1', severity:'high'};
    const p2={rule:'R2', severity:'medium'};
    const p3={rule:'R3'};
    const r1=makeRecord(1, ZERO_HASH, p1);
    const r2=makeRecord(2, r1.chain_hash, p2);
    const r3=makeRecord(3, r2.chain_hash, p3);
    const text=[toLine(r1),toLine(r2),toLine(r3)].join('\n')+'\n';
    const res=verifyChain(text);
    assert.equal(res.valid,true);
    assert.equal(res.brokenAt,null);
    assert.equal(res.total,3);
    assert.equal(res.legacyPrefix,0);
    assert.equal(res.issues.length,0);
});

test('console writer chains records after a legacy prefix and resumes external appends', t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-audit-writer-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const file = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(file, `${JSON.stringify({ action: 'legacy' })}\n`);
    appendChainedRecord(file, { action: 'suspend', status: 'planned' });
    appendChainedRecord(file, { action: 'suspend', status: 'suspended' });
    let records = fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(records[1].chain_seq, 1);
    assert.equal(records[2].chain_seq, 2);
    assert.equal(verifyFile(file).valid, true);
    const external = makeRecord(3, records[2].chain_hash, { action: 'resume', status: 'resumed' });
    fs.appendFileSync(file, `${JSON.stringify(external)}\n`);
    appendChainedRecord(file, { action: 'playbook', status: 'complete' });
    records = fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(records[4].chain_seq, 4);
    assert.equal(verifyFile(file).valid, true);
});

test('console writer refuses damaged chains and partial tails', t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-audit-writer-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const file = path.join(dir, 'audit.jsonl');
    appendChainedRecord(file, { action: 'terminate', status: 'planned' });
    const damaged = fs.readFileSync(file, 'utf8').replace('planned', 'compromised');
    fs.writeFileSync(file, damaged);
    assert.throws(() => appendChainedRecord(file, { action: 'terminate', status: 'failed' }), /audit chain is broken/);
    fs.writeFileSync(file, '{"legacy":true}');
    assert.throws(() => appendChainedRecord(file, { action: 'terminate', status: 'failed' }), /incomplete tail/);
});

test('console writer hashes the serialized payload when optional fields are absent', t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-audit-writer-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const file = path.join(dir, 'audit.jsonl');
    appendChainedRecord(file, { action: 'isolate', target: undefined, status: 'not_ready' });
    assert.equal(verifyFile(file).valid, true);
});

test('single-byte tamper detected', () => {
    const p={rule:'R1'};
    const r=makeRecord(1,ZERO_HASH,p);
    let line=toLine(r);
    // tamper payload
    line=line.replace('R1','R2');
    const res=verifyChain(line);
    assert.equal(res.valid,false);
    assert.equal(res.brokenAt,1);
    assert.ok(res.issues.some(s=>s.includes('chain_hash mismatch')));
});

test('special JSON keys remain covered by the chain hash', () => {
    // JSON.parse creates an own __proto__ property, unlike object literal syntax.
    const payload = JSON.parse('{"rule":"R1","__proto__":{"source":"sensor-a"}}');
    const record = makeRecord(1, ZERO_HASH, payload);
    const original = toLine(record);
    assert.equal(verifyChain(original).valid, true);

    const altered = original.replace('sensor-a', 'sensor-b');
    const result = verifyChain(altered);
    assert.equal(result.valid, false);
    assert.equal(result.brokenAt, 1);
    assert.ok(result.issues.some(s => s.includes('chain_hash mismatch')));

    // Adding an unsigned field to an otherwise valid record was previously
    // accepted because the plain-object copy discarded this specific key.
    const ordinary = makeRecord(1, ZERO_HASH, {rule:'R1'});
    const injected = toLine(ordinary).replace('"rule":"R1"',
        '"rule":"R1","__proto__":{"source":"attacker"}');
    const injectionResult = verifyChain(injected);
    assert.equal(injectionResult.valid, false);
    assert.ok(injectionResult.issues.some(s => s.includes('chain_hash mismatch')));
});

test('legacy prefix remains compatible before a chained special-key record', () => {
    const payload = JSON.parse('{"__proto__":"audit-value","rule":"R2"}');
    const record = makeRecord(1, ZERO_HASH, payload);
    const result = verifyChain([toLine({rule:'OLD'}), toLine(record)].join('\n'));
    assert.equal(result.valid, true);
    assert.equal(result.legacyPrefix, 1);
    assert.equal(result.total, 2);
});

test('truncation detected via reorder/seq', () => {
    const p1={a:1},p2={a:2},p3={a:3};
    const r1=makeRecord(1,ZERO_HASH,p1);
    const r2=makeRecord(2,r1.chain_hash,p2);
    const r3=makeRecord(3,r2.chain_hash,p3);
    // reorder: swap r2 and r3
    const text=[toLine(r1),toLine(r3),toLine(r2)].join('\n');
    const res=verifyChain(text);
    assert.equal(res.valid,false);
    assert.ok(res.brokenAt!==null);
    assert.ok(res.issues.some(s=> s.includes('chain_seq')||s.includes('chain_prev')));
});

test('reorder detected', () => {
    const p1={x:1},p2={x:2};
    const r1=makeRecord(1,ZERO_HASH,p1);
    const r2=makeRecord(2,r1.chain_hash,p2);
    const res=verifyChain([toLine(r2),toLine(r1)].join('\n'));
    assert.equal(res.valid,false);
    assert.ok(res.issues.some(s=>s.includes('chain_prev')||s.includes('chain_seq')));
});

test('legacy prefix accepted + chain verified from upgrade point', () => {
    const legacy=[JSON.stringify({rule:'OLD'}), JSON.stringify({rule:'OLD2'})];
    const p={rule:'NEW'};
    const r=makeRecord(1,ZERO_HASH,p);
    const r2=makeRecord(2,r.chain_hash,{rule:'NEW2'});
    const text=[...legacy, toLine(r), toLine(r2)].join('\n');
    const res=verifyChain(text);
    assert.equal(res.valid,true);
    assert.equal(res.legacyPrefix,2);
    assert.equal(res.total,4);
});

test('empty file', () => {
    const res=verifyChain('');
    assert.equal(res.valid,true);
    assert.equal(res.total,0);
    assert.equal(res.legacyPrefix,0);
    assert.equal(res.brokenAt,null);
});

test('broken mid-file then legacy handling policy', () => {
    // legacy prefix then valid chain then tamper in middle
    const legacy=[JSON.stringify({a:1})];
    const p1={b:1},p2={b:2},p3={b:3};
    const r1=makeRecord(1,ZERO_HASH,p1);
    const r2=makeRecord(2,r1.chain_hash,p2);
    // tamper r2
    let tampered=toLine(r2).replace('"b":2','"b":999');
    const r3=makeRecord(3,r2.chain_hash,p3); // r3 prev points to original r2 hash, but r2 was tampered
    const text=[legacy[0], toLine(r1), tampered, toLine(r3)].join('\n');
    const res=verifyChain(text);
    assert.equal(res.valid,false);
    assert.equal(res.legacyPrefix,1);
    assert.equal(res.brokenAt,3); // tampered line
    assert.ok(res.issues.length>0);
});

test('duplicate seq detected', () => {
    const p1={x:1},p2={x:2};
    const r1=makeRecord(1,ZERO_HASH,p1);
    const r2=makeRecord(1,r1.chain_hash,p2); // duplicate seq
    const text=[toLine(r1),toLine(r2)].join('\n');
    const res=verifyChain(text);
    assert.equal(res.valid,false);
    assert.ok(res.issues.some(s=>s.includes('duplicate')));
});

test('append forgery after break detected', () => {
    const p1={a:1},p2={a:2};
    const r1=makeRecord(1,ZERO_HASH,p1);
    // forge r2 with wrong prev
    const fakePrev='a'.repeat(64);
    const r2=makeRecord(2,fakePrev,p2);
    const text=[toLine(r1),toLine(r2)].join('\n');
    const res=verifyChain(text);
    assert.equal(res.valid,false);
    assert.ok(res.issues.some(s=>s.includes('chain_prev')));
});

test('file path verify', () => {
    const dir=fs.mkdtempSync(path.join(os.tmpdir(),'edr-chain-'));
    const file=path.join(dir,'test.jsonl');
    const p={rule:'X'};
    const r=makeRecord(1,ZERO_HASH,p);
    fs.writeFileSync(file,toLine(r)+'\n');
    const res=verifyFile(file);
    assert.equal(res.valid,true);
    fs.rmSync(dir,{recursive:true,force:true});
});

test('file verification rejects a parseable record with an incomplete tail', t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-chain-tail-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const file = path.join(dir, 'audit.jsonl');
    const record = makeRecord(1, ZERO_HASH, { action: 'terminate', status: 'planned' });
    fs.writeFileSync(file, toLine(record));

    const result = verifyFile(file);
    assert.equal(result.valid, false);
    assert.equal(result.brokenAt, 1);
    assert.ok(result.issues.some(issue => issue.includes('incomplete tail')));
});

test('all legacy file accepted', () => {
    const text=[JSON.stringify({a:1}),JSON.stringify({b:2})].join('\n');
    const res=verifyChain(text);
    assert.equal(res.valid,true);
    assert.equal(res.legacyPrefix,2);
});

test('first chained record must start at one, including after a legacy prefix', () => {
    const forged=makeRecord(2,ZERO_HASH,{rule:'R2'});
    for (const lines of [[toLine(forged)], [toLine({rule:'OLD'}),toLine(forged)]]) {
        const res=verifyChain(lines.join('\n'));
        assert.equal(res.valid,false);
        assert.equal(res.brokenAt,lines.length);
        assert.ok(res.issues.some(s=>s.includes('chain_seq must start at 1')));
    }
});

test('non-object JSON audit records report damage instead of crashing', () => {
    const genesis=makeRecord(1,ZERO_HASH,{rule:'R1'});
    for (const bad of ['null','[]','42','"text"']) {
        const legacy=verifyChain([toLine({rule:'OLD'}),bad,toLine(genesis)].join('\n'));
        assert.equal(legacy.valid,false);
        assert.equal(legacy.brokenAt,2);
        assert.ok(legacy.issues.some(s=>s.includes('line 2: audit record must be an object')));

        const chained=verifyChain([toLine(genesis),bad].join('\n'));
        assert.equal(chained.valid,false);
        assert.equal(chained.brokenAt,2);
        assert.ok(chained.issues.some(s=>s.includes('line 2: audit record must be an object')));
    }
});

test('unsafe chain sequence numbers fail closed', () => {
    const record=makeRecord(Number.MAX_SAFE_INTEGER+1,ZERO_HASH,{rule:'R1'});
    const res=verifyChain(toLine(record));
    assert.equal(res.valid,false);
    assert.equal(res.brokenAt,1);
    assert.ok(res.issues.some(s=>s.includes('invalid chain_seq')));
});
