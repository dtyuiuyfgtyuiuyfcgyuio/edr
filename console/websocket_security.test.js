'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const WebSocket = require('ws');

const reader = 'WebSocketReaderFixture-0123456789abcdef';
const writer = 'WebSocketWriterFixture-0123456789abcdef';
const admin = 'WebSocketAdminFixture-0123456789abcdef';

// An unhandled connection error must fail this assertion, not kill the test runner.
async function fixture(t) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-ws-security-'));
    const child = spawn(process.execPath, ['-e', `
        const { createRuntime } = require('./server');
        const runtime = createRuntime({
            dataDir: process.argv[1], env: JSON.parse(process.argv[2]),
            logger: { log() {}, warn() {}, error() {} },
        });
        runtime.start(0, '127.0.0.1').then(() => {
            process.send({ port: runtime.server.address().port });
        }).catch(error => { console.error(error); process.exit(1); });
    `, dataDir, JSON.stringify({
        EDR_CONSOLE_MODE: 'production', EDR_CONSOLE_TLS_PROXY_MODE: 'loopback',
        EDR_READ_API_KEY: reader, EDR_INGEST_API_KEY: writer, EDR_ADMIN_API_KEY: admin,
    })], { cwd: __dirname, windowsHide: true, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    let stderr = '';
    child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
    const stopped = new Promise(resolve => child.once('exit', resolve));
    t.after(async () => {
        if (child.exitCode === null && child.signalCode === null) child.kill();
        await stopped;
        fs.rmSync(dataDir, { recursive: true, force: true });
    });
    const { port } = await new Promise((resolve, reject) => {
        child.once('message', resolve);
        child.once('error', reject);
        child.once('exit', code => reject(new Error(`console exited before ready (${code}): ${stderr}`)));
    });
    const base = `http://127.0.0.1:${port}`;
    const request = (url, key = reader, options = {}) => fetch(`${base}${url}`, {
        ...options,
        headers: { 'X-API-Key': key, ...options.headers },
        signal: AbortSignal.timeout(3000),
    });
    return {
        child, port, request,
        async connect() {
            const socket = new WebSocket(`ws://127.0.0.1:${port}/ws`);
            socket.on('error', () => {});
            t.after(() => socket.terminate());
            await new Promise((resolve, reject) => {
                socket.once('open', resolve);
                socket.once('error', reject);
            });
            return socket;
        },
        async assertAlive() {
            const response = await request('/api/health');
            assert.equal(response.status, 200, stderr);
            assert.equal((await response.json()).status, 'ok');
            assert.equal(child.exitCode, null, stderr);
            assert.equal(child.signalCode, null, stderr);
        },
    };
}

function nextMessage(socket) {
    return new Promise((resolve, reject) => {
        socket.once('message', data => {
            try { resolve(JSON.parse(data.toString())); } catch (error) { reject(error); }
        });
    });
}

function closed(socket) {
    return new Promise(resolve => socket.once('close', resolve));
}

async function authenticate(socket) {
    const reply = nextMessage(socket);
    socket.send(JSON.stringify({ type: 'auth', apiKey: reader }));
    assert.deepEqual(await reply, { type: 'auth', ok: true });
}

// Raw wire fixtures bypass the client's encoder and exercise the server's parser.
const malformedFrames = [
    ['reserved bit', Buffer.from([0xc1, 0x80, 0, 0, 0, 0])],
    ['unmasked client frame', Buffer.from([0x81, 0x00])],
    ['invalid UTF-8', Buffer.from([0x81, 0x82, 0, 0, 0, 0, 0xc3, 0x28])],
];

for (const [name, frame] of malformedFrames) {
    test(`WebSocket pre-auth ${name} closes only the offending connection`, { timeout: 10000 }, async t => {
        const runtime = await fixture(t);
        const peer = await runtime.connect();
        const disconnected = closed(peer);
        peer._socket.write(frame);
        await disconnected;
        await runtime.assertAlive();
        const status = await (await runtime.request('/api/system/status')).json();
        assert.equal(status.connectedClients, 0);
        await authenticate(await runtime.connect());
    });
}

test('WebSocket malformed frame in upgrade head cannot terminate the console', { timeout: 10000 }, async t => {
    const runtime = await fixture(t);
    const peer = net.connect({ host: '127.0.0.1', port: runtime.port });
    peer.on('error', () => {});
    t.after(() => peer.destroy());
    let response = '';
    peer.on('data', chunk => { response = (response + chunk.toString()).slice(0, 2048); });
    const disconnected = new Promise(resolve => peer.once('close', resolve));
    await new Promise((resolve, reject) => {
        peer.once('connect', resolve);
        peer.once('error', reject);
    });
    const upgrade = Buffer.from([
        'GET /ws HTTP/1.1', `Host: 127.0.0.1:${runtime.port}`,
        'Connection: Upgrade', 'Upgrade: websocket',
        'Sec-WebSocket-Version: 13', `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}`, '', '',
    ].join('\r\n'));
    peer.write(Buffer.concat([upgrade, malformedFrames[0][1]]));
    await disconnected;
    assert.match(response, /^HTTP\/1\.1 101 /);
    await runtime.assertAlive();
    await authenticate(await runtime.connect());
});

test('WebSocket post-auth protocol error preserves another subscriber and broadcast', { timeout: 10000 }, async t => {
    const runtime = await fixture(t);
    const healthy = await runtime.connect();
    const offender = await runtime.connect();
    await authenticate(healthy);
    await authenticate(offender);
    const disconnected = closed(offender);
    offender._socket.write(malformedFrames[0][1]);
    await disconnected;
    await runtime.assertAlive();
    const status = await (await runtime.request('/api/system/status')).json();
    assert.equal(status.connectedClients, 1);

    const broadcast = nextMessage(healthy);
    const response = await runtime.request('/ingest', writer, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule: 'WS-REGRESSION', severity: 'high', event: { type: 'PROCESS_START', pid: 42 } }),
    });
    assert.equal(response.status, 200);
    const message = await broadcast;
    assert.equal(message.type, 'alert');
    assert.equal(message.data.rule, 'WS-REGRESSION');
});

test('WebSocket wrong key and malformed auth JSON retain policy close semantics', { timeout: 10000 }, async t => {
    const runtime = await fixture(t);
    for (const payload of ['{', JSON.stringify({ type: 'auth', apiKey: 'wrong-key' })]) {
        const peer = await runtime.connect();
        const disconnected = closed(peer);
        peer.send(payload);
        assert.equal(await disconnected, 1008);
        await runtime.assertAlive();
    }
    assert.equal((await runtime.request('/api/stats', 'wrong-key')).status, 401);
    await authenticate(await runtime.connect());
});
