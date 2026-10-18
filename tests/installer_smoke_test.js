'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const http = require('node:http');
const root = path.resolve(process.argv[2] || '');
assert(process.argv[2], 'Installed verification directory required');
const json = file => JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
const state = path.join(root, 'TestData');
const manifest = json(path.join(root, 'payload-manifest.json'));
let checked = 0;
for (const file of manifest.files) {
    if (file.path.startsWith('driver/')) continue; // Default installation leaves the optional driver unselected.
    const actual = fs.readFileSync(path.join(root, file.path));
    assert.equal(actual.length, file.bytes, `size ${file.path}`);
    assert.equal(crypto.createHash('sha256').update(actual).digest('hex'), file.sha256, `hash ${file.path}`);
    checked++;
}
function request(url, key) {
    return new Promise((resolve, reject) => {
        const req = http.get(`http://127.0.0.1:8080${url}`, { headers: key ? { 'X-API-Key': key } : {} }, res => {
            const chunks = [];
            res.on('data', data => chunks.push(data));
            res.on('end', () => resolve({ status: res.statusCode, data: Buffer.concat(chunks).toString() }));
        });
        req.on('error', reject);
        req.setTimeout(1000, () => req.destroy(new Error('HTTP timeout')));
    });
}
async function main() {
    const keys = json(path.join(state, 'console-keys.json'));
    const child = spawn(path.join(root, 'runtime', 'node.exe'), [path.join(root, 'console', 'installed-launcher.js'), state],
        { cwd: root, windowsHide: true, stdio: 'ignore' });
    const exited = new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
    try {
        let ready = false;
        for (let i = 0; i < 100 && !ready; i++) {
            try { ready = (await request('/api/alerts', keys.read)).status === 200; } catch (_) {}
            if (!ready) await new Promise(resolve => setTimeout(resolve, 100));
        }
        assert(ready, 'Installed console starts with its bundled Node runtime and role keys');
        assert.equal((await request('/api/alerts')).status, 401, 'Unauthenticated access is rejected');
        assert.equal((await request('/api/rules/coverage', keys.read)).status, 200, 'Installed production rule catalog is available');
        const cfg = json(path.join(state, 'config', 'edr.config.json'));
        cfg.reporter.enable = false;
        cfg.health.enable = false;
        cfg.correlation.enable = false;
        cfg.alerts_path = path.join(state, 'selftest-alerts.jsonl');
        const config = path.join(state, 'selftest-config.json');
        fs.writeFileSync(config, JSON.stringify(cfg));
        const run = spawnSync(path.join(root, 'edr.exe'), ['--selftest', '--config', config],
            { cwd: root, windowsHide: true, encoding: 'utf8', timeout: 20000 });
        assert.equal(run.status, 0, 'Installed agent selftest succeeds with its app-local CRT');
        const alerts = fs.readFileSync(cfg.alerts_path, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
        const ids = new Set(alerts.map(alert => alert.rule || alert.rule_id));
        assert(ids.has('EDR-001') && ids.has('EDR-004'), 'Existing detection pipeline remains functional');
        fs.writeFileSync(path.join(state, 'console', 'shutdown.request'), 'stop');
        const stopped = await Promise.race([exited, new Promise((_, reject) => {
            const timer = setTimeout(() => reject(new Error('Console failed to stop gracefully')), 8000);
            timer.unref();
        })]);
        assert.equal(stopped, 0, 'Console stops gracefully through its protected state directory');
        console.log(JSON.stringify({ filesVerified: checked, consoleAuthentication: true, ruleCatalog: true,
            nativeSelftestAlerts: alerts.length, gracefulConsoleStop: true }));
    } finally {
        if (child.exitCode === null) { child.kill(); await exited; }
    }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
