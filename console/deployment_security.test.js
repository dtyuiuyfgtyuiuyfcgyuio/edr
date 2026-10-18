'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createRuntime } = require('./server');

const quietLogger = { log() {}, warn() {}, error() {} };
const strongKeys = Object.freeze({
    EDR_READ_API_KEY: crypto.randomBytes(32).toString('base64url'),
    EDR_INGEST_API_KEY: crypto.randomBytes(32).toString('base64url'),
    EDR_ADMIN_API_KEY: crypto.randomBytes(32).toString('base64url'),
});

function runtimeFixture(t, env) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-deployment-'));
    const runtime = createRuntime({ dataDir, env, logger: quietLogger });
    t.after(async () => {
        if (runtime.server.listening)
            await new Promise(resolve => runtime.server.close(resolve));
        fs.rmSync(dataDir, { recursive: true, force: true });
    });
    return runtime;
}

function installHttpsServerStub(t) {
    const original = https.createServer;
    const created = [];
    https.createServer = (options, listener) => {
        const server = new EventEmitter();
        server.listening = false;
        server.listen = (port, host, callback) => {
            server.listening = true;
            server.bindAddress = host;
            server.boundPort = port || 8443;
            setImmediate(callback);
            return server;
        };
        server.address = () => ({ address: server.bindAddress, port: server.boundPort });
        server.close = callback => {
            server.listening = false;
            if (callback) setImmediate(callback);
            return server;
        };
        created.push({ options, listener, server });
        return server;
    };
    t.after(() => { https.createServer = original; });
    return created;
}

test('production requires separate explicit viewer, operator, and admin credentials', () => {
    assert.throws(() => createRuntime({
        env: { EDR_CONSOLE_MODE: 'production', EDR_API_KEY: 'legacy-shared-key' },
        logger: quietLogger,
    }), /production.*(read|viewer|credential)/i);
});

test('production rejects short, low-diversity, or shared role credentials', () => {
    const cases = [
        { ...strongKeys, EDR_READ_API_KEY: 'short' },
        { ...strongKeys, EDR_READ_API_KEY: 'x'.repeat(64) },
        { ...strongKeys, EDR_ADMIN_API_KEY: strongKeys.EDR_READ_API_KEY },
    ];
    for (const keys of cases) {
        assert.throws(() => createRuntime({
            env: { EDR_CONSOLE_MODE: 'production', ...keys,
                EDR_CONSOLE_TLS_PROXY_MODE: 'loopback' },
            logger: quietLogger,
        }), /credential|key/i);
    }
});

test('production requires HTTPS or the explicit loopback TLS-proxy mode', () => {
    assert.throws(() => createRuntime({
        env: { EDR_CONSOLE_MODE: 'production', ...strongKeys },
        logger: quietLogger,
    }), /TLS|HTTPS/i);
});

test('loopback TLS-proxy mode keeps proxy headers untrusted and enforces role keys', async t => {
    const runtime = runtimeFixture(t, {
        EDR_CONSOLE_MODE: 'production',
        EDR_CONSOLE_TLS_PROXY_MODE: 'loopback',
        ...strongKeys,
    });
    assert.equal(runtime.app.get('trust proxy'), false);
    await runtime.start(0, '127.0.0.1');
    const url = `http://127.0.0.1:${runtime.server.address().port}/api/stats`;

    const anonymous = await fetch(url, { headers: { 'x-forwarded-proto': 'https' } });
    assert.equal(anonymous.status, 401);
    const wrongRole = await fetch(url, { headers: {
        'x-api-key': strongKeys.EDR_INGEST_API_KEY,
        'x-forwarded-proto': 'https',
    } });
    assert.equal(wrongRole.status, 401);
    const viewer = await fetch(url, { headers: {
        'x-api-key': strongKeys.EDR_READ_API_KEY,
        'x-forwarded-proto': 'http',
    } });
    assert.equal(viewer.status, 200);
});

test('loopback TLS-proxy mode refuses a non-loopback backend bind before listening', async t => {
    const runtime = runtimeFixture(t, {
        EDR_CONSOLE_MODE: 'production',
        EDR_CONSOLE_TLS_PROXY_MODE: 'loopback',
        ...strongKeys,
    });
    await assert.rejects(runtime.start(0, '255.255.255.255'), /proxy.*loopback/i);
    assert.equal(runtime.server.listening, false);
});

test('cleartext HTTP never binds non-loopback, even with API keys', async t => {
    const runtime = runtimeFixture(t, strongKeys);
    await assert.rejects(runtime.start(0, '255.255.255.255'), /TLS|HTTPS|cleartext/i);
    assert.equal(runtime.server.listening, false);
});

test('direct HTTPS loads the configured key and certificate into an HTTPS server', async t => {
    const created = installHttpsServerStub(t);
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-tls-'));
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    const certFile = path.join(dataDir, 'cert.pem');
    const keyFile = path.join(dataDir, 'key.pem');
    fs.writeFileSync(certFile, 'test certificate bytes');
    fs.writeFileSync(keyFile, 'test private key bytes');
    const runtime = createRuntime({
        dataDir,
        env: {
            EDR_CONSOLE_MODE: 'production',
            EDR_CONSOLE_TLS_CERT_FILE: certFile,
            EDR_CONSOLE_TLS_KEY_FILE: keyFile,
            ...strongKeys,
        },
        logger: quietLogger,
    });
    t.after(() => {
        if (runtime.server.listening) runtime.server.close();
    });

    assert.equal(created.length, 1);
    assert.equal(runtime.server, created[0].server);
    assert.equal(Buffer.from(created[0].options.cert).toString(), 'test certificate bytes');
    assert.equal(Buffer.from(created[0].options.key).toString(), 'test private key bytes');
    await runtime.start(8443, '203.0.113.10');
    assert.equal(runtime.server.bindAddress, '203.0.113.10');
});

test('direct HTTPS rejects unreadable or invalid TLS identity files at startup', t => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-console-bad-tls-'));
    t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
    const certFile = path.join(dataDir, 'cert.pem');
    const keyFile = path.join(dataDir, 'key.pem');
    fs.writeFileSync(certFile, 'not a PEM certificate');
    fs.writeFileSync(keyFile, 'not a PEM private key');
    assert.throws(() => createRuntime({
        dataDir,
        env: {
            EDR_CONSOLE_MODE: 'production',
            EDR_CONSOLE_TLS_CERT_FILE: certFile,
            EDR_CONSOLE_TLS_KEY_FILE: keyFile,
            ...strongKeys,
        },
        logger: quietLogger,
    }), /PEM|certificate|key/i);
});

test('development keeps the unauthenticated loopback HTTP default', async t => {
    const runtime = runtimeFixture(t, {});
    await runtime.start(0, '127.0.0.1');
    const response = await fetch(`http://127.0.0.1:${runtime.server.address().port}/api/stats`);
    assert.equal(response.status, 200);
});
