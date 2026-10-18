'use strict';

const fs = require('fs');
const { resolveWithinBase } = require('./path_guard');

const PLAYBOOK_ACTIONS = Object.freeze(new Set(['terminate', 'quarantine', 'isolate', 'unisolate', 'suspend', 'resume']));

const BUILTIN_PLAYBOOKS = Object.freeze([
    {
        id: 'ransomware-contain',
        name: 'ransomware-contain',
        description: 'Ransomware containment: terminate by alert pid \u2192 quarantine by sha256 \u2192 isolate host',
        steps: [
            { action: 'terminate', description: 'Terminate suspicious process (pid/createTime100ns from alert)' },
            { action: 'quarantine', description: 'Quarantine file by sha256 from alert' },
            { action: 'isolate', description: 'Isolate host (management IP exact match enforced)' },
        ],
    },
    {
        id: 'suspend-investigate',
        name: 'suspend-investigate',
        description: 'Suspend an alert process for manual investigation; resume requires a separate manual run',
        steps: [
            { action: 'suspend', description: 'Suspend process by alert pid and createTime100ns' },
        ],
    },
]);

function stepSucceeded(action, status, mode) {
    if (mode === 'dry_run') return status === 'local_only' || status === 'native_dry_run_accepted';
    if (mode !== 'real') return false;
    return ({
        terminate: 'terminated', quarantine: 'quarantined',
        isolate: 'isolated', unisolate: 'restored',
        suspend: 'suspended', resume: 'resumed',
    })[action] === status;
}

function playbookFile(dataDir) {
    return resolveWithinBase(dataDir, 'playbooks.jsonl');
}

function appendPlaybook(dataDir, playbook) {
    const file = playbookFile(dataDir);
    const descriptor = fs.openSync(file, 'a', 0o600);
    try {
        fs.writeFileSync(descriptor, `${JSON.stringify(playbook)}\n`, 'utf8');
        fs.fsyncSync(descriptor);
    } finally {
        fs.closeSync(descriptor);
    }
    try { fs.chmodSync(file, 0o600); } catch (_) {}
}

function loadPlaybooks(dataDir) {
    const map = new Map();
    for (const pb of BUILTIN_PLAYBOOKS) {
        map.set(pb.id, { ...pb, builtin: true });
    }
    const file = playbookFile(dataDir);
    if (!fs.existsSync(file)) return [...map.values()];
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch (_) { return [...map.values()]; }
    const lines = text.split(/\r?\n/).filter(Boolean);
    for (const line of lines) {
        try {
            const obj = JSON.parse(line);
            if (!obj || typeof obj.id !== 'string') continue;
            if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(obj.id)) continue;
            map.set(obj.id, obj);
        } catch (_) {}
    }
    return [...map.values()];
}

function findPlaybook(dataDir, id) {
    const list = loadPlaybooks(dataDir);
    return list.find(pb => pb.id === id) || null;
}

module.exports = {
    BUILTIN_PLAYBOOKS,
    PLAYBOOK_ACTIONS,
    playbookFile,
    appendPlaybook,
    loadPlaybooks,
    findPlaybook,
    stepSucceeded,
};
