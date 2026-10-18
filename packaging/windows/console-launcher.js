'use strict';
// Installed entry point. Mutable ledgers and credentials stay outside Program Files.
const fs = require('node:fs');
const path = require('node:path');
const state = path.resolve(process.argv[2] || '');
if (!process.argv[2] || !path.isAbsolute(process.argv[2])) throw new Error('Absolute state directory required');
const keys = JSON.parse(fs.readFileSync(path.join(state, 'console-keys.json'), 'utf8').replace(/^\uFEFF/, ''));
for (const role of ['ingest', 'read', 'admin']) {
    if (!/^[a-f0-9]{64}$/.test(keys[role])) throw new Error(`Invalid installed ${role} key`);
}
if (new Set(Object.values(keys)).size !== 3) throw new Error('Installed role keys must differ');
Object.assign(process.env, {
    EDR_CONSOLE_MODE: 'development', EDR_BIND_HOST: '127.0.0.1', PORT: '8080',
    EDR_INGEST_API_KEY: keys.ingest, EDR_READ_API_KEY: keys.read, EDR_ADMIN_API_KEY: keys.admin,
    EDR_RESPONSE_CHANNEL_ENABLE: 'false', EDR_ENABLE_PROCESS_TERMINATION: 'false',
    EDR_ENABLE_QUARANTINE: 'false', EDR_ENABLE_DELETE_FILE: 'false',
    EDR_ENABLE_PROCESS_SUSPEND: 'false', EDR_ENABLE_PROCESS_RESUME: 'false',
    EDR_ENABLE_HOST_ISOLATION: 'false',
    EDR_RULES_PATH: path.join(__dirname, '..', 'rules', 'rules.json'),
});
delete process.env.EDR_CONSOLE_TLS_CERT_FILE;
delete process.env.EDR_CONSOLE_TLS_KEY_FILE;
delete process.env.EDR_CONSOLE_TLS_PROXY_MODE;
const data = path.join(state, 'console');
fs.mkdirSync(data, { recursive: true });
const logFile = path.join(data, 'service.log');
const logger = {};
for (const level of ['log', 'warn', 'error']) logger[level] = (...args) => {
    fs.appendFileSync(logFile, `${new Date().toISOString()} ${level} ${args.map(String).join(' ')}\n`);
};
const runtime = require('./server').createRuntime({ dataDir: data, logger });
const sockets = new Set();
runtime.server.on('connection', socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
});
const stopFile = path.join(data, 'shutdown.request');
if (fs.existsSync(stopFile)) fs.unlinkSync(stopFile);
let stopping = false;
function stop() {
    if (stopping) return;
    stopping = true;
    clearInterval(timer);
    for (const socket of sockets) socket.destroy();
    runtime.server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
}
const timer = setInterval(() => { if (fs.existsSync(stopFile)) stop(); }, 500);
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
runtime.start(8080, '127.0.0.1').catch(error => {
    logger.error('console start failed:', error.message);
    clearInterval(timer);
    process.exitCode = 1;
});
