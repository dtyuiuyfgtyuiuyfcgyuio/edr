'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('query gate refuses the third operation without starting or queuing it', async () => {
    const { createQueryGate, LedgerQueryBusyError } = require('./query_gate');
    const gate = createQueryGate();
    const releases = [];
    const hold = () => new Promise(resolve => releases.push(resolve));
    const first = gate.run(hold);
    const second = gate.run(hold);
    let rejectedStarted = false;
    await assert.rejects(gate.run(() => { rejectedStarted = true; }), error =>
        error instanceof LedgerQueryBusyError && error.code === 'ledger_query_busy');
    assert.equal(rejectedStarted, false);
    releases[0]('first');
    assert.equal(await first, 'first');
    assert.equal(await gate.run(() => 'replacement'), 'replacement');
    releases[1]('second');
    assert.equal(await second, 'second');
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(rejectedStarted, false);
});

test('query gate releases operations after synchronous throws and asynchronous rejections', async () => {
    const { createQueryGate } = require('./query_gate');
    const gate = createQueryGate();
    let releaseHeld;
    const held = gate.run(() => new Promise(resolve => { releaseHeld = resolve; }));
    const synchronous = new Error('synchronous failure');
    const asynchronous = new Error('asynchronous failure');
    for (let attempt = 0; attempt < 3; attempt += 1) {
        await assert.rejects(gate.run(() => { throw synchronous; }), error => error === synchronous);
        await assert.rejects(gate.run(() => Promise.reject(asynchronous)), error => error === asynchronous);
        assert.equal(await gate.run(async () => attempt), attempt);
    }
    releaseHeld();
    await held;
});

test('query gates have separate capacity and start a new operation on every accepted call', async () => {
    const { createQueryGate } = require('./query_gate');
    const firstGate = createQueryGate();
    const secondGate = createQueryGate();
    const releases = [];
    const first = firstGate.run(() => new Promise(resolve => releases.push(resolve)));
    const second = firstGate.run(() => new Promise(resolve => releases.push(resolve)));
    let executions = 0;
    const operation = () => ++executions;
    assert.equal(await secondGate.run(operation), 1);
    assert.equal(await secondGate.run(operation), 2);
    await assert.rejects(firstGate.run(operation), { code: 'ledger_query_busy' });
    assert.equal(executions, 2);
    releases.forEach(resolve => resolve());
    await Promise.all([first, second]);
    assert.equal(await firstGate.run(operation), 3);
});
