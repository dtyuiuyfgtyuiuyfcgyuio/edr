'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { ResponseClient, assertResponseAuditWritable } = require('./response_client');

function readinessClient(value) {
    const client = Object.create(ResponseClient.prototype);
    client.request = async request => ({
        ok: true,
        requestId: request.requestId,
        status: 'ready',
        effective_mode: 'real',
        ...value,
    });
    return client;
}

test('readiness accepts a consistent writable audit snapshot', async () => {
    const audit = { available: true, pending: false, writable: true };
    const result = await readinessClient({ audit }).readiness();
    assert.deepEqual(result.audit, audit);
    assert.equal(assertResponseAuditWritable(result), undefined);
});

test('readiness remains compatible with historical responses without audit state', async () => {
    const result = await readinessClient({}).readiness();
    assert.equal(Object.hasOwn(result, 'audit'), false);
    assert.throws(() => assertResponseAuditWritable(result), error =>
        error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE' &&
        error.status === 'audit_failed' && error.httpStatus === 503);
});

test('readiness rejects non-boolean audit fields', async () => {
    await assert.rejects(
        readinessClient({ audit: { available: 1, pending: false, writable: false } }).readiness(),
        /native response audit state was invalid/,
    );
});

test('readiness rejects audit snapshots whose writable value contradicts the state', async () => {
    await assert.rejects(
        readinessClient({ audit: { available: true, pending: true, writable: true } }).readiness(),
        /native response audit state was invalid/,
    );
});

test('mutation gate rejects pending, unavailable, and unverified audit states', () => {
    for (const audit of [
        { available: true, pending: true, writable: false },
        { available: false, pending: false, writable: false },
        { available: true, pending: false, writable: false },
    ]) {
        assert.throws(() => assertResponseAuditWritable({ audit }), error =>
            error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE' &&
            error.status === 'audit_failed' && error.httpStatus === 503);
    }
});
