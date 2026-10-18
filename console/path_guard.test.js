'use strict';

/* Regression tests for the console JSONL path containment guard. Locks in
 * the accept/reject behaviour that createRuntime, playbooks.js and
 * incidents.js rely on before any ledger file I/O. */
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { resolveWithinBase } = require('./path_guard');

test('resolveWithinBase accepts ledger paths that stay inside the base', () => {
    const base = path.join(os.tmpdir(), 'edr-path-guard-base');
    assert.equal(resolveWithinBase(base, 'alerts.jsonl'),
        path.resolve(base, 'alerts.jsonl'));
    assert.equal(resolveWithinBase(base, path.join('sub', 'dir', 'audit.jsonl')),
        path.resolve(base, 'sub', 'dir', 'audit.jsonl'));
    assert.equal(resolveWithinBase(base + path.sep, 'alerts.jsonl'),
        path.resolve(base, 'alerts.jsonl'));
    /* `.` segments and repeated separators normalise away. */
    assert.equal(resolveWithinBase(base, path.join('.', 'alerts.jsonl')),
        path.resolve(base, 'alerts.jsonl'));
});

test('resolveWithinBase rejects traversal outside the base', () => {
    const base = path.join(os.tmpdir(), 'edr-path-guard-base');
    assert.throws(() => resolveWithinBase(base, '../alerts.jsonl'), /escapes/);
    assert.throws(() => resolveWithinBase(base, path.join('..', '..', 'etc', 'passwd')), /escapes/);
    assert.throws(() => resolveWithinBase(base, path.join('sub', '..', '..', 'x.jsonl')), /escapes/);
    /* The candidate must be a file inside the base, not the base itself. */
    assert.throws(() => resolveWithinBase(base, '.'), /escapes/);
    assert.throws(() => resolveWithinBase(base, ''), /escapes/);
});

test('resolveWithinBase rejects absolute paths and sibling-prefix directories', () => {
    const base = path.join(os.tmpdir(), 'edr-path-guard-base');
    const elsewhere = path.join(path.dirname(base), 'elsewhere.jsonl');
    assert.notEqual(path.resolve(elsewhere), path.resolve(base, path.basename(elsewhere)));
    assert.throws(() => resolveWithinBase(base, elsewhere), /escapes/);
    /* baseEvil must not be treated as inside base. */
    const sibling = base + 'Evil';
    assert.throws(() => resolveWithinBase(base, path.join(sibling, 'alerts.jsonl')), /escapes/);
});
