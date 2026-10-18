const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const fsPromises = require('node:fs/promises');
const http = require('http');
const https = require('https');
const path = require('path');
const { setImmediate: yieldToLoop } = require('node:timers/promises');
const { ResponseClient, assertResponseAuditWritable } = require('./response_client');
const {
    RESPONSE_AUDIT_STATUSES,
    RESPONSE_AUDIT_STATUSES_BY_ACTION,
    responseAuditStatusSupported,
} = require('./response_statuses');
const playbooks = require('./playbooks');
const incidents = require('./incidents');
const { resolveWithinBase } = require('./path_guard');
const { TECHNIQUE_CONFIG_MAP } = require('./technique_config_map');
const { resolveDeploymentSecurity, assertBindAllowed } = require('./deployment_security');
const { buildProcessHunt } = require('./process_hunt');
const { createQueryGate, LedgerQueryBusyError } = require('./query_gate');

const LIMITS = Object.freeze({
    bodyBytes: 256 * 1024,
    alerts: 10000,
    events: 20000,
    dedupIds: 50000,
    string: 2048,
    output: 8192,
    rawBytes: 128 * 1024,
    fields: 128,
    tags: 64,
    queryLimit: 1000,
    triageEvents: 20000,
    auditEvents: 20000,
    auditScanBytes: 16 * 1024 * 1024,
    auditLineBytes: 64 * 1024,
    auditReadChunkBytes: 64 * 1024,
    auditVerifyBytes: 256 * 1024 * 1024,
    auditVerifyRecords: 200000,
});

class ValidationError extends Error {}

const TRIAGE_STATUSES = new Set(['new', 'investigating', 'resolved', 'false_positive']);
const TRIAGE_PRIORITIES = new Set(['low', 'normal', 'high', 'urgent']);
const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });

/* Reference set of widely-abused ATT&CK Enterprise techniques used by
 * /api/rules/coverage to surface blind spots in the deployed rule catalog.
 * Includes every technique that has a wired detector behind it (2026-10-04
 * sweep added the 24 implemented-but-unlisted ones). */
const REFERENCE_TECHNIQUES = Object.freeze([
    'T1003', 'T1003.001', 'T1003.003', 'T1005', 'T1007', 'T1012', 'T1016', 'T1018',
    'T1021', 'T1021.001', 'T1021.002', 'T1021.003', 'T1021.004', 'T1021.006', 'T1027',
    'T1036', 'T1041', 'T1046', 'T1047', 'T1053.005', 'T1055',
    'T1055.001', 'T1057', 'T1059.001', 'T1059.003', 'T1059.007',
    'T1068', 'T1069.002', 'T1070.001', 'T1070.004',
    'T1071.001', 'T1071.004', 'T1078', 'T1082', 'T1083',
    'T1087.002', 'T1090.001', 'T1090.003', 'T1098', 'T1098.002', 'T1105',
    'T1110', 'T1112', 'T1113', 'T1114.003', 'T1115',
    'T1134', 'T1136.001', 'T1201', 'T1218.002', 'T1486',
    'T1490', 'T1497', 'T1531',
    'T1543.003', 'T1546.005', 'T1546.016', 'T1547.001', 'T1547.002',
    'T1552.005', 'T1552.006', 'T1555.005', 'T1556.008', 'T1557.001', 'T1557.002', 'T1558.004',
    'T1561.001', 'T1562.001', 'T1562.002', 'T1562.004', 'T1564.002', 'T1570', 'T1583.001', 'T1654',
]);

const EVIDENCE_FILES = Object.freeze(['snapshot.txt', 'process_tree.json', 'alert.json', 'response.json', 'manifest.json']);
const EVIDENCE_MAX_BYTES = 8 * 1024 * 1024;
const REQUEST_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function evidenceAllowedFile(name) {
    return EVIDENCE_FILES.includes(name);
}

function parseEvidenceRequestId(alert) {
    const event = alert.event || {};
    const rid = event.auto_response_request_id || event.auto_response_requestId;
    if (typeof rid === 'string' && REQUEST_ID_RE.test(rid.trim().toLowerCase())) {
        return rid.trim().toLowerCase();
    }
    const ep = event.auto_response_evidence_path;
    if (typeof ep === 'string' && ep) {
        const normalized = ep.replace(/\\/g, '/');
        const parts = normalized.split('/').filter(Boolean);
        for (let idx = parts.length - 1; idx >= 0; idx -= 1) {
            const candidate = parts[idx].toLowerCase();
            if (REQUEST_ID_RE.test(candidate)) return candidate;
            const extracted = candidate.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/);
            if (extracted && REQUEST_ID_RE.test(extracted[0])) return extracted[0];
        }
        const trimmed = ep.trim().toLowerCase();
        if (REQUEST_ID_RE.test(trimmed)) return trimmed;
    }
    return null;
}

function validateRequestIdParam(value) {
    const text = boundedString(value, 'requestId', 64, true);
    if (!REQUEST_ID_RE.test(text)) throw new ValidationError('requestId must be a lowercase UUID');
    return text;
}

function evidenceFilePathWithinBase(baseDir, requestId, fileName) {
    const baseResolved = path.resolve(baseDir);
    const target = path.resolve(baseResolved, requestId, fileName);
    const relative = path.relative(baseResolved, target);
    if (!relative || relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
        throw new ValidationError('path traversal is not allowed');
    }
    return target;
}

function stableValue(value) {
    if (Array.isArray(value)) return value.map(stableValue);
    if (!isObject(value)) return value;
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]));
}

function alertCaseId(alert) {
    const identity = [alert.sourceId, alert.id || '', alert.rule, alert.timestamp, stableValue(alert.event || {})];
    return `alert-${crypto.createHash('sha256').update(JSON.stringify(identity)).digest('hex').slice(0, 32)}`;
}

function isObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, allowed, name) {
    const unknown = Object.keys(value).filter(key => !allowed.includes(key));
    if (unknown.length) throw new ValidationError(`${name} contains unknown field ${unknown[0]}`);
}

function decimalUint64String(value, name, nonzero = false) {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value))
        throw new ValidationError(`${name} must be a decimal uint64 string`);
    const parsed = BigInt(value);
    if (parsed > 0xffffffffffffffffn || (nonzero && parsed === 0n))
        throw new ValidationError(`${name} is out of range`);
    return value;
}

function boundedString(value, name, max = LIMITS.string, required = false) {
    if (value === undefined || value === null || value === '') {
        if (required) throw new ValidationError(`${name} is required`);
        return undefined;
    }
    if (typeof value !== 'string' && typeof value !== 'number') {
        throw new ValidationError(`${name} must be a string`);
    }
    const result = String(value);
    if (result.length > max) throw new ValidationError(`${name} exceeds ${max} characters`);
    return result;
}

function boundedNote(value, name = 'note') {
    const note = boundedString(value, name, 2048) || '';
    for (const character of note) {
        const code = character.charCodeAt(0);
        if ((code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) || code === 0x7f)
            throw new ValidationError(`${name} contains forbidden control characters`);
    }
    return note;
}

function boundedInteger(value, name) {
    if (value === undefined || value === null || value === '') return undefined;
    const result = Number(value);
    if (!Number.isSafeInteger(result) || result < 0 || result > 0xffffffff) {
        throw new ValidationError(`${name} must be an unsigned 32-bit integer`);
    }
    return result;
}

function boundedTimestamp(value, name = 'timestamp', required = false) {
    if (value === undefined || value === null || value === '') {
        if (required) throw new ValidationError(`${name} is required`);
        return new Date().toISOString();
    }
    const text = boundedString(value, name, 64, true);
    const millis = Date.parse(text);
    if (!Number.isFinite(millis)) throw new ValidationError(`${name} must be an ISO-8601 timestamp`);
    return new Date(millis).toISOString();
}

function filetimeToIso8601(value) {
    if (value === undefined || value === null || value === '') return undefined;
    let ticks;
    try { ticks = BigInt(value); } catch (_) {
        throw new ValidationError('ts_100ns must be an unsigned integer');
    }
    if (ticks < 116444736000000000n) throw new ValidationError('ts_100ns predates Unix epoch');
    const unixMillis = (ticks - 116444736000000000n) / 10000n;
    if (unixMillis > BigInt(Number.MAX_SAFE_INTEGER))
        throw new ValidationError('ts_100ns is out of range');
    const date = new Date(Number(unixMillis));
    if (!Number.isFinite(date.getTime())) throw new ValidationError('ts_100ns is out of range');
    return date.toISOString();
}

function boundedObject(value, name, maxFields = LIMITS.fields) {
    if (value === undefined || value === null) return {};
    if (!isObject(value)) throw new ValidationError(`${name} must be an object`);
    const entries = Object.entries(value);
    if (entries.length > maxFields) throw new ValidationError(`${name} has too many fields`);
    const result = {};
    for (const [key, item] of entries) {
        const safeKey = boundedString(key, `${name} key`, 128, true);
        if (item === null || typeof item === 'boolean' || typeof item === 'number') {
            result[safeKey] = item;
        } else {
            result[safeKey] = boundedString(item, `${name}.${safeKey}`, LIMITS.output, false);
        }
    }
    return result;
}

function boundedStringArray(value, name) {
    if (value === undefined || value === null) return undefined;
    if (!Array.isArray(value)) throw new ValidationError(`${name} must be an array`);
    if (value.length > LIMITS.tags) {
        throw new ValidationError(`${name} has too many entries`);
    }
    return value.map((item, index) => boundedString(item, `${name}[${index}]`, 128, true));
}

function boundedRaw(value) {
    const json = JSON.stringify(value);
    if (json === undefined || Buffer.byteLength(json) > LIMITS.rawBytes) {
        throw new ValidationError(`raw data exceeds ${LIMITS.rawBytes} bytes`);
    }
    return JSON.parse(json);
}

function safeEqual(actual, expected) {
    const actualDigest = crypto.createHash('sha256').update(String(actual || '')).digest();
    const expectedDigest = crypto.createHash('sha256').update(String(expected || '')).digest();
    return crypto.timingSafeEqual(actualDigest, expectedDigest) &&
        typeof actual === 'string' && actual.length === expected.length;
}

function sourceIdentity(apiKey) {
    if (!apiKey) return 'local-unauthenticated';
    return `sensor-${crypto.createHash('sha256').update(apiKey).digest('hex').slice(0, 24)}`;
}

function priorityToSeverity(priority) {
    const value = String(priority).toLowerCase();
    if (['emergency', 'alert', 'critical', 'error'].includes(value)) return 'high';
    if (['warning', 'notice'].includes(value)) return 'medium';
    if (value === 'informational') return 'low';
    return 'info';
}

function normalizeNativeAlert(input, sourceId) {
    if (!isObject(input)) throw new ValidationError('alert must be an object');
    if (input.rule !== undefined && input.ruleId !== undefined && input.rule !== input.ruleId) {
        throw new ValidationError('rule and ruleId conflict');
    }
    const rule = boundedString(input.rule ?? input.ruleId, 'rule', 256, true);
    const severity = boundedString(input.severity, 'severity', 32, true).toLowerCase();
    if (!['critical', 'high', 'medium', 'low', 'info'].includes(severity)) {
        throw new ValidationError('severity is not supported');
    }
    const fields = boundedObject(input.fields, 'fields');
    const legacyEvent = input.event === undefined ? {} : input.event;
    if (!isObject(legacyEvent)) throw new ValidationError('event must be an object');
    const eventFields = boundedObject(legacyEvent.fields, 'event.fields');
    const event = {
        ...fields,
        ...eventFields,
        type: boundedString(legacyEvent.type ?? input.type, 'type', 128),
        pid: boundedInteger(legacyEvent.pid ?? input.pid, 'pid'),
        ppid: boundedInteger(legacyEvent.ppid ?? input.ppid, 'ppid'),
    };
    for (const [key, value] of Object.entries(legacyEvent)) {
        if (['fields', 'type', 'pid', 'ppid', 'raw'].includes(key)) continue;
        if (Object.keys(event).length >= LIMITS.fields) throw new ValidationError('event has too many fields');
        const safeKey = boundedString(key, 'event key', 128, true);
        if (Array.isArray(value)) {
            if (value.length > LIMITS.tags) throw new ValidationError(`event.${key} has too many entries`);
            event[safeKey] = value.map((item, index) => boundedString(item, `event.${key}[${index}]`, 128, true));
        } else if (isObject(value)) {
            event[safeKey] = boundedObject(value, `event.${key}`);
        } else {
            event[safeKey] = boundedString(value, `event.${key}`, LIMITS.output);
        }
    }
    Object.keys(event).forEach(key => event[key] === undefined && delete event[key]);
    const mitreAttack = boundedStringArray(
        input.mitre_attack ?? event.mitre_attack, 'mitre_attack');
    const mitreTactic = boundedStringArray(
        input.mitre_tactic ?? event.mitre_tactic, 'mitre_tactic');
    if (mitreAttack) event.mitre_attack = mitreAttack;
    if (mitreTactic) event.mitre_tactic = mitreTactic;
    const alert = {
        id: boundedString(input.id ?? input.eventId, 'id', 256),
        sourceId,
        timestamp: input.timestamp ? boundedTimestamp(input.timestamp) :
            (input.time ? boundedTimestamp(input.time) :
                (filetimeToIso8601(input.ts_100ns) || new Date().toISOString())),
        rule,
        severity,
        action: boundedString(input.action, 'action', 128),
        event,
        raw: input.raw === undefined && legacyEvent.raw === undefined ? undefined :
            boundedRaw(input.raw ?? legacyEvent.raw),
    };
    if (mitreAttack) alert.mitre_attack = mitreAttack;
    if (mitreTactic) alert.mitre_tactic = mitreTactic;
    return alert;
}

function normalizePersistedAlert(input) {
    try {
        const normalized = normalizeNativeAlert(input, boundedString(input.sourceId, 'sourceId', 256) || 'legacy');
        if (input.raw !== undefined) normalized.raw = boundedRaw(input.raw);
        return normalized;
    } catch (_) {
        return null;
    }
}

function normalizeFalcoAlert(input, sourceId) {
    if (!isObject(input)) throw new ValidationError('Falco alert must be an object');
    const required = ['time', 'rule', 'priority', 'source', 'hostname', 'output', 'output_fields'];
    for (const field of required) {
        if (input[field] === undefined || input[field] === null) {
            throw new ValidationError(`${field} is required`);
        }
    }
    if (!Array.isArray(input.tags) || input.tags.length > LIMITS.tags) {
        throw new ValidationError(`tags must be an array with at most ${LIMITS.tags} entries`);
    }
    const tags = input.tags.map((tag, index) => boundedString(tag, `tags[${index}]`, 128, true));
    const outputFields = boundedObject(input.output_fields, 'output_fields');
    const time = boundedTimestamp(input.time, 'time', true);
    const rule = boundedString(input.rule, 'rule', 256, true);
    const priority = boundedString(input.priority, 'priority', 32, true).toLowerCase();
    const falcoSource = boundedString(input.source, 'source', 128, true);
    const hostname = boundedString(input.hostname, 'hostname', 255, true);
    const output = boundedString(input.output, 'output', LIMITS.output, true);
    return {
        id: boundedString(input.uuid ?? input.event_id, 'event id', 256),
        sourceId,
        timestamp: time,
        rule,
        severity: priorityToSeverity(priority),
        action: 'alert',
        event: { type: 'FALCO_ALERT', source: falcoSource, hostname, priority, tags, output, output_fields: outputFields },
        raw: boundedRaw(input),
    };
}

function valueFrom(input, names) {
    const fields = isObject(input.fields) ? input.fields : {};
    for (const name of names) {
        if (input[name] !== undefined) return input[name];
        if (fields[name] !== undefined) return fields[name];
    }
    return undefined;
}

function processIdentity(input, sourceId, prefix = '') {
    const parent = prefix === 'parent_';
    const guidNames = parent ? ['parent_ProcessGuid', 'parent_process_guid', 'parentProcessGuid', 'ParentProcessGuid'] : ['ProcessGuid', 'process_guid', 'processGuid'];
    const hostNames = parent ? ['parent_host', 'parent_hostname', 'ParentHost', 'ParentHostname'] : ['host', 'hostname', 'Host', 'Hostname'];
    const bootNames = parent ? ['parent_boot_id', 'parent_bootId', 'ParentBootId'] : ['boot_id', 'bootId', 'BootId'];
    const pidNames = parent ? ['parent_pid', 'parentProcessId', 'ParentProcessId'] : ['pid', 'ProcessId'];
    const startNames = parent ? ['parent_start_time', 'parent_startTime', 'ParentStartTime'] : ['start_time', 'startTime', 'StartTime'];
    const guid = boundedString(valueFrom(input, guidNames), 'ProcessGuid', 256);
    if (guid) return `${sourceId}:guid:${guid}`;
    const host = boundedString(valueFrom(input, hostNames), 'host', 255);
    const boot = boundedString(valueFrom(input, bootNames), 'boot id', 256);
    const pid = boundedInteger(valueFrom(input, pidNames), 'pid');
    const start = boundedString(valueFrom(input, startNames), 'start time', 128);
    if (host && boot && pid !== undefined && start) return `${sourceId}:tuple:${host}:${boot}:${pid}:${start}`;
    return undefined;
}

function normalizeRawEvent(input, sourceId) {
    if (!isObject(input)) throw new ValidationError('event must be an object');
    const eventId = boundedString(input.eventId ?? input.event_id ?? input.id, 'eventId', 256, true);
    const type = boundedString(input.type ?? valueFrom(input, ['event_type', 'EventType']), 'type', 128, true);
    const timestamp = boundedTimestamp(input.timestamp ?? input.time, 'timestamp', true);
    boundedObject(input.fields, 'fields');
    const processKey = processIdentity(input, sourceId);
    const parentProcessKey = processIdentity(input, sourceId, 'parent_');
    return { eventId, sourceId, type, timestamp, processKey, parentProcessKey, raw: boundedRaw(input.raw ?? input) };
}

function appendJsonLineImpl(file, value) {
    if (path.basename(file) === 'audit.jsonl') {
        require('./audit_chain').appendChainedRecord(file, value);
        return;
    }
    const descriptor = fs.openSync(file, 'a', 0o600);
    try {
        fs.writeFileSync(descriptor, `${JSON.stringify(value)}\n`, 'utf8');
        fs.fsyncSync(descriptor);
    } finally {
        fs.closeSync(descriptor);
    }
}

function rejectDuplicateJsonKeys(text) {
    let offset = 0;
    const fail = () => { throw new ValidationError('request JSON contains duplicate keys'); };
    const whitespace = () => { while (/\s/.test(text[offset] || '')) offset += 1; };
    const string = () => {
        if (text[offset++] !== '"') fail();
        const start = offset - 1;
        let escaped = false;
        while (offset < text.length) {
            const character = text[offset++];
            if (!escaped && character === '"') return JSON.parse(text.slice(start, offset));
            if (!escaped && character === '\\') escaped = true;
            else escaped = false;
        }
        fail();
    };
    const value = () => {
        whitespace();
        if (text[offset] === '{') return object();
        if (text[offset] === '[') {
            offset += 1; whitespace();
            if (text[offset] === ']') { offset += 1; return; }
            for (;;) {
                value(); whitespace();
                if (text[offset] === ']') { offset += 1; return; }
                if (text[offset++] !== ',') fail();
            }
        }
        if (text[offset] === '"') { string(); return; }
        const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/
            .exec(text.slice(offset));
        if (!match) fail();
        offset += match[0].length;
    };
    const object = () => {
        offset += 1; whitespace();
        const keys = new Set();
        if (text[offset] === '}') { offset += 1; return; }
        for (;;) {
            whitespace();
            const key = string();
            if (keys.has(key)) fail();
            keys.add(key); whitespace();
            if (text[offset++] !== ':') fail();
            value(); whitespace();
            if (text[offset] === '}') { offset += 1; return; }
            if (text[offset++] !== ',') fail();
        }
    };
    value(); whitespace();
    if (offset !== text.length) fail();
}

function readJsonLinesImpl(file, maxLines) {
    try {
        if (!fs.existsSync(file)) return [];
        return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).slice(-maxLines).flatMap(line => {
            try { return [JSON.parse(line)]; } catch (_) { return []; }
        });
    } catch (_) {
        return [];
    }
}

/* Direct-importers entry point: unguarded, resolves to the raw
 * implementation. createRuntime installs dataDir-contained wrappers for all
 * of its own call sites. */
function readJsonLinesTail(file, options = {}) {
    return readJsonLinesTailImpl(file, options);
}

/* Read only a bounded tail of an append-only JSONL ledger. Records are
 * returned newest-first. Starting in the middle of a line is safe: the
 * incomplete prefix is discarded before parsing. */
function readJsonLinesTailImpl(file, options = {}) {
    const maxBytes = options.maxBytes ?? LIMITS.auditScanBytes;
    const maxLineBytes = options.maxLineBytes ?? LIMITS.auditLineBytes;
    const maxRecords = options.maxRecords ?? LIMITS.auditEvents;
    const maxPhysicalLines = options.maxPhysicalLines ?? Math.max(maxRecords * 5, 100000);
    const metadata = {
        scanned_bytes: 0,
        window_truncated: false,
        malformed_count: 0,
        oversized_count: 0,
        invalid_utf8_count: 0,
        truncated_tail: false,
    };
    if (!fs.existsSync(file)) return { records: [], ...metadata };

    let descriptor;
    try {
        descriptor = fs.openSync(file, 'r');
        const size = fs.fstatSync(descriptor).size;
        const bytesToRead = Math.min(size, maxBytes);
        const start = size - bytesToRead;
        const buffer = Buffer.allocUnsafe(bytesToRead);
        let total = 0;
        while (total < bytesToRead) {
            const count = fs.readSync(descriptor, buffer, total,
                Math.min(bytesToRead - total, LIMITS.auditReadChunkBytes),
                start + total);
            if (count === 0) break;
            total += count;
        }
        metadata.scanned_bytes = total;
        metadata.window_truncated = start > 0 || total < bytesToRead;
        const data = total === buffer.length ? buffer : buffer.subarray(0, total);
        if (!data.length) return { records: [], ...metadata };

        let contentStart = 0;
        if (start > 0) {
            const newline = data.indexOf(0x0a);
            if (newline < 0) return { records: [], ...metadata };
            contentStart = newline + 1;
        }
        const hasFinalNewline = data[data.length - 1] === 0x0a;
        let lineEnd = hasFinalNewline ? data.length - 1 : data.length;
        let physicalLines = 0;
        const records = [];
        const decoder = new TextDecoder('utf-8', { fatal: true });

        while (lineEnd > contentStart && records.length < maxRecords &&
               physicalLines < maxPhysicalLines) {
            let separator = data.lastIndexOf(0x0a, lineEnd - 1);
            if (separator < contentStart - 1) separator = contentStart - 1;
            let lineStart = separator + 1;
            let actualEnd = lineEnd;
            if (actualEnd > lineStart && data[actualEnd - 1] === 0x0d)
                actualEnd -= 1;
            physicalLines += 1;
            if (actualEnd > lineStart) {
                const lineBytes = actualEnd - lineStart;
                if (lineBytes > maxLineBytes) {
                    metadata.oversized_count += 1;
                } else {
                    try {
                        const text = decoder.decode(data.subarray(lineStart, actualEnd));
                        try {
                            records.push(JSON.parse(text));
                        } catch (_) {
                            metadata.malformed_count += 1;
                            if (!hasFinalNewline && lineEnd === data.length)
                                metadata.truncated_tail = true;
                        }
                    } catch (_) {
                        metadata.invalid_utf8_count += 1;
                        if (!hasFinalNewline && lineEnd === data.length)
                            metadata.truncated_tail = true;
                    }
                }
            }
            if (separator < contentStart) break;
            lineEnd = separator;
        }
        if (records.length >= maxRecords || physicalLines >= maxPhysicalLines)
            metadata.window_truncated = true;
        return { records, ...metadata };
    } catch (error) {
        error.message = `response audit read failed: ${error.message}`;
        throw error;
    } finally {
        if (descriptor !== undefined) fs.closeSync(descriptor);
    }
}

function sameAuditSnapshot(left, right) {
    return left.dev === right.dev && left.ino === right.ino &&
        left.size === right.size && left.mtimeNs === right.mtimeNs &&
        left.ctimeNs === right.ctimeNs;
}

function auditReadError(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
}

/* Async equivalent of readJsonLinesTailImpl. Capture the EOF and bounded byte
 * range once, read by explicit position from one handle, then reject any
 * short read or metadata change rather than returning a mixed snapshot. */
async function readJsonLinesTailAsyncImpl(file, options = {}) {
    const maxBytes = options.maxBytes ?? LIMITS.auditScanBytes;
    const maxLineBytes = options.maxLineBytes ?? LIMITS.auditLineBytes;
    const maxRecords = options.maxRecords ?? LIMITS.auditEvents;
    const maxPhysicalLines = options.maxPhysicalLines ?? Math.max(maxRecords * 5, 100000);
    const metadata = {
        scanned_bytes: 0,
        window_truncated: false,
        malformed_count: 0,
        oversized_count: 0,
        invalid_utf8_count: 0,
        truncated_tail: false,
    };
    let descriptor;
    try {
        descriptor = await fsPromises.open(file, 'r');
        const before = await descriptor.stat({ bigint: true });
        if (!before.isFile()) throw auditReadError('EDR_AUDIT_UNAVAILABLE', 'audit path is not a file');
        if (before.size > BigInt(Number.MAX_SAFE_INTEGER))
            throw auditReadError('EDR_AUDIT_UNAVAILABLE', 'audit file size is not safely addressable');

        const size = Number(before.size);
        const bytesToRead = Math.min(size, maxBytes);
        const start = size - bytesToRead;
        const buffer = Buffer.allocUnsafe(bytesToRead);
        let total = 0;
        let chunksSinceYield = 0;
        while (total < bytesToRead) {
            const length = Math.min(bytesToRead - total, LIMITS.auditReadChunkBytes);
            const { bytesRead } = await descriptor.read(buffer, total, length, start + total);
            if (bytesRead === 0)
                throw auditReadError('EDR_AUDIT_SHORT_READ', 'audit snapshot ended before its captured range');
            total += bytesRead;
            chunksSinceYield += 1;
            if (chunksSinceYield >= 16) {
                chunksSinceYield = 0;
                await yieldToLoop();
            }
        }

        const after = await descriptor.stat({ bigint: true });
        const named = await fsPromises.stat(file, { bigint: true });
        if (!sameAuditSnapshot(before, after) || !sameAuditSnapshot(before, named))
            throw auditReadError('EDR_AUDIT_SNAPSHOT_CHANGED', 'audit snapshot changed during read');

        metadata.scanned_bytes = total;
        metadata.window_truncated = start > 0;
        const data = total === buffer.length ? buffer : buffer.subarray(0, total);
        if (!data.length) return { records: [], ...metadata };

        let contentStart = 0;
        if (start > 0) {
            const newline = data.indexOf(0x0a);
            if (newline < 0) return { records: [], ...metadata };
            contentStart = newline + 1;
        }
        const hasFinalNewline = data[data.length - 1] === 0x0a;
        let lineEnd = hasFinalNewline ? data.length - 1 : data.length;
        let physicalLines = 0;
        let sinceParseYield = 0;
        const records = [];
        const decoder = new TextDecoder('utf-8', { fatal: true });

        while (lineEnd > contentStart && records.length < maxRecords &&
               physicalLines < maxPhysicalLines) {
            let separator = data.lastIndexOf(0x0a, lineEnd - 1);
            if (separator < contentStart - 1) separator = contentStart - 1;
            const lineStart = separator + 1;
            let actualEnd = lineEnd;
            if (actualEnd > lineStart && data[actualEnd - 1] === 0x0d)
                actualEnd -= 1;
            physicalLines += 1;
            sinceParseYield += 1;
            if (actualEnd > lineStart) {
                const lineBytes = actualEnd - lineStart;
                if (lineBytes > maxLineBytes) {
                    metadata.oversized_count += 1;
                } else {
                    try {
                        const text = decoder.decode(data.subarray(lineStart, actualEnd));
                        try {
                            records.push(JSON.parse(text));
                        } catch (_) {
                            metadata.malformed_count += 1;
                            if (!hasFinalNewline && lineEnd === data.length)
                                metadata.truncated_tail = true;
                        }
                    } catch (_) {
                        metadata.invalid_utf8_count += 1;
                        if (!hasFinalNewline && lineEnd === data.length)
                            metadata.truncated_tail = true;
                    }
                }
            }
            if (separator < contentStart) break;
            lineEnd = separator;
            if (sinceParseYield >= 512) {
                sinceParseYield = 0;
                await yieldToLoop();
            }
        }
        if (records.length >= maxRecords || physicalLines >= maxPhysicalLines)
            metadata.window_truncated = true;
        return { records, ...metadata };
    } catch (error) {
        if (error.code === 'ENOENT' && descriptor === undefined)
            return { records: [], ...metadata };
        error.message = `response audit read failed: ${error.message}`;
        throw error;
    } finally {
        if (descriptor) {
            try { await descriptor.close(); } catch (_) { /* best-effort close after read failure */ }
        }
    }
}

/* Direct-importers entry point; runtime call sites install a contained wrapper. */
function readJsonLinesTailAsync(file, options = {}) {
    return readJsonLinesTailAsyncImpl(file, options);
}

/* --------------------- Threat Intelligence Integration --------------------- */

const threatIntelCache = new Map();
const THREAT_INTEL_CACHE_TTL = 24 * 60 * 60 * 1000;
const THREAT_INTEL_CACHE_MAX = 2000;

function cleanThreatIntelCache() {
    const now = Date.now();
    for (const [key, entry] of threatIntelCache) {
        if (now - entry.timestamp > THREAT_INTEL_CACHE_TTL) {
            threatIntelCache.delete(key);
        }
    }
    if (threatIntelCache.size > THREAT_INTEL_CACHE_MAX) {
        const sorted = [...threatIntelCache.entries()].sort((a, b) => a[1].timestamp - b[1].timestamp);
        for (let i = 0; i < sorted.length - THREAT_INTEL_CACHE_MAX / 2; i++) {
            threatIntelCache.delete(sorted[i][0]);
        }
    }
}

async function lookupThreatIntel(type, value, apiKey) {
    const cacheKey = `${type}:${value}`;
    const cached = threatIntelCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < THREAT_INTEL_CACHE_TTL) {
        return { ...cached.data, cached: true };
    }
    if (!apiKey) {
        return { error: 'Threat intelligence API key not configured (set EDR_THREAT_INTEL_API_KEY)', cached: false };
    }
    const resource = encodeURIComponent(value);
    let url, options;
    if (type === 'hash') {
        url = `https://www.virustotal.com/api/v3/files/${resource}`;
    } else if (type === 'ip') {
        url = `https://www.virustotal.com/api/v3/ip_addresses/${resource}`;
    } else if (type === 'domain') {
        url = `https://www.virustotal.com/api/v3/domains/${resource}`;
    } else {
        return { error: 'Invalid lookup type; must be hash, ip, or domain', cached: false };
    }
    options = {
        method: 'GET',
        headers: { 'x-apikey': apiKey, 'Accept': 'application/json' },
    };
    try {
        const response = await fetch(url, options);
        const data = await response.json();
        if (!response.ok) {
            const result = {
                error: data.error?.message || `VirusTotal API error (${response.status})`,
                status: response.status,
                cached: false,
            };
            threatIntelCache.set(cacheKey, { data: result, timestamp: Date.now() });
            return result;
        }
        const stats = data.data?.attributes?.last_analysis_stats || {};
        const result = {
            type,
            value,
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            total_scanners: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0),
            reputation: data.data?.attributes?.reputation,
            names: data.data?.attributes?.names,
            creation_date: data.data?.attributes?.creation_date,
            last_modification_date: data.data?.attributes?.last_modification_date,
            cached: false,
            raw_link: data.data?.links?.self,
        };
        threatIntelCache.set(cacheKey, { data: result, timestamp: Date.now() });
        cleanThreatIntelCache();
        return result;
    } catch (error) {
        return { error: `Threat intel lookup failed: ${error.message}`, cached: false };
    }
}

function mitreTactics(alert) {
    return alert.mitre_tactic || alert.event?.mitre_tactic || [];
}
function mitreTechniques(alert) {
    return alert.mitre_attack || alert.event?.mitre_attack || [];
}

function createRuntime(options = {}) {
    const env = options.env || process.env;
    const dataDir = options.dataDir || __dirname;
    const logger = options.logger || console;
    // Local dependency injection for deterministic disk-reader tests. These
    // functions cannot be selected or configured through an HTTP request.
    const verifyLedger = options.ledgerReaders?.verifyFileStream || require('./audit_chain').verifyFileStream;
    const loadIncidentLedger = options.ledgerReaders?.loadIncidentsAsync || incidents.loadIncidentsAsync;
    const ledgerQueryGate = createQueryGate();
    const deploymentSecurity = resolveDeploymentSecurity(env);
    const evidenceDir = env.EDR_EVIDENCE_DIR || 'C:\\ProgramData\\EDR\\evidence';
    const responseFoundationEnabled = env.EDR_RESPONSE_CHANNEL_ENABLE === 'true';
    const realTerminationEnabled = env.EDR_ENABLE_PROCESS_TERMINATION === 'true';
    const realQuarantineEnabled = env.EDR_ENABLE_QUARANTINE === 'true';
    const realDeleteFileEnabled = env.EDR_ENABLE_DELETE_FILE === 'true';
    const realSuspendEnabled = env.EDR_ENABLE_PROCESS_SUSPEND === 'true';
    const realResumeEnabled = env.EDR_ENABLE_PROCESS_RESUME === 'true';
    const hostIsolationEnabled = env.EDR_ENABLE_HOST_ISOLATION === 'true';
    const hostIsolationManagementIp = env.EDR_HOST_ISOLATION_MANAGEMENT_IP || '';
    const hostIsolationAllowedPorts = env.EDR_HOST_ISOLATION_ALLOWED_PORTS || '';
    let responseClient = options.responseClient || null;
    if (responseFoundationEnabled && !responseClient) {
        try {
            responseClient = new ResponseClient({
                pipeName: env.EDR_RESPONSE_PIPE_NAME || '\\\\.\\pipe\\edr-response-v1',
                keyFile: env.EDR_RESPONSE_COMMAND_KEY_FILE || '',
            });
        } catch (error) {
            throw new Error(`native dry-run response initialization failed: ${error.message}`);
        }
    }
    const keys = {
        ingest: env.EDR_INGEST_API_KEY ?? env.EDR_API_KEY ?? '',
        read: env.EDR_READ_API_KEY ?? env.EDR_API_KEY ?? '',
        admin: env.EDR_ADMIN_API_KEY ?? '',
    };
    const files = {
        alerts: path.join(dataDir, 'alerts.jsonl'),
        events: path.join(dataDir, 'events.jsonl'),
        audit: path.join(dataDir, 'audit.jsonl'),
        triage: path.join(dataDir, 'triage.jsonl'),
        playbooks: path.join(dataDir, 'playbooks.jsonl'),
    };
    /* Sink-side containment for the JSONL persistence layer: every ledger
     * path this runtime touches must resolve inside dataDir, so even a
     * future caller that forwards request-controlled strings cannot point
     * reads or appends outside it. These locals shadow the unguarded module
     * helpers for every in-runtime call site. */
    const withinDataDir = (file) => {
        try {
            return resolveWithinBase(dataDir, file);
        } catch (_) {
            throw new ValidationError('ledger path escapes the data directory');
        }
    };
    const appendJsonLine = (file, value) => appendJsonLineImpl(withinDataDir(file), value);
    const readJsonLines = (file, maxLines) => readJsonLinesImpl(withinDataDir(file), maxLines);
    const readJsonLinesTail = (file, options) => readJsonLinesTailImpl(withinDataDir(file), options);
    const readJsonLinesTailAsync = (file, options) => readJsonLinesTailAsyncImpl(withinDataDir(file), options);
    /* Detection rule catalog used by the coverage report: explicit option,
     * then env override, then the conventional repo layouts. Resolved to a
     * concrete existing file so /api/rules/coverage can stat it later. */
    files.rulesCatalog = options.rulesPath || env.EDR_RULES_PATH ||
        [path.join(dataDir, 'rules.json'),
         path.join(dataDir, '..', 'rules', 'rules.json')]
            .find(candidate => fs.existsSync(candidate)) || null;
    let alerts = readJsonLines(files.alerts, LIMITS.alerts).map(normalizePersistedAlert).filter(Boolean);
    let events = [];
    const eventIds = new Map();
    const processes = new Map();
    const wsClients = new Set();
    const recentAlerts = new Map();
    const alertTriage = new Map();
    const triageHistory = [];

    for (const stored of readJsonLines(files.triage, LIMITS.triageEvents)) {
        try {
            if (!isObject(stored)) continue;
            const caseId = boundedString(stored.caseId, 'caseId', 64, true);
            const status = boundedString(stored.status, 'status', 32, true);
            if (!TRIAGE_STATUSES.has(status)) continue;
            const activity = {
                caseId,
                status,
                note: boundedNote(stored.note),
                assignee: boundedString(stored.assignee, 'assignee', 256) || '',
                priority: TRIAGE_PRIORITIES.has(stored.priority)
                    ? stored.priority : 'normal',
                timestamp: boundedTimestamp(stored.timestamp, 'timestamp', true),
                actor: boundedString(stored.actor, 'actor', 256) || 'legacy',
            };
            triageHistory.push(activity);
            alertTriage.set(caseId, activity);
        } catch (_) {}
    }

    function triageState(alert) {
        const activity = alertTriage.get(alertCaseId(alert));
        return activity ? {
            status: activity.status,
            note: activity.note,
            assignee: activity.assignee || '',
            priority: activity.priority || 'normal',
            updatedAt: activity.timestamp,
            updatedBy: activity.actor,
        } : { status: 'new', note: '', assignee: '', priority: 'normal', updatedAt: null, updatedBy: null };
    }

    function decorateAlert(alert) {
        return { ...alert, caseId: alertCaseId(alert), triage: triageState(alert) };
    }

    function eventSummary(event) {
        const raw = event.raw || {};
        for (const names of [
            ['image', 'Image'],
            ['command_line', 'CommandLine'],
            ['path', 'file_path', 'TargetFilename'],
            ['script_path', 'script_block_id'],
            ['reg_key', 'TargetObject'],
            ['dns_query', 'QueryName'],
            ['remote_ip', 'DestinationIp'],
            ['output'],
        ]) {
            const value = valueFrom(raw, names);
            if (value !== undefined && value !== null && value !== '') return String(value).slice(0, LIMITS.output);
        }
        return '';
    }

    function eventMatchesQuery(event, query) {
        if (!query) return true;
        const raw = event.raw || {};
        const values = [
            event.eventId, event.sourceId, event.type, event.processKey, event.parentProcessKey,
            eventSummary(event),
            valueFrom(raw, ['user', 'User']),
            valueFrom(raw, ['hash', 'sha256', 'Hashes']),
            valueFrom(raw, ['domain', 'hostname', 'host']),
        ];
        return values.some(value => value !== undefined && value !== null &&
            String(value).toLowerCase().includes(query));
    }

    function endpointInventory() {
        const endpoints = new Map();
        const ensure = sourceId => {
            if (!endpoints.has(sourceId)) endpoints.set(sourceId, {
                sourceId,
                reportedHost: '',
                firstSeen: null,
                lastSeen: null,
                alerts: 0,
                openAlerts: 0,
                critical: 0,
                high: 0,
                events: 0,
                processes: 0,
                risk: 'none',
                _riskRank: -1,
                _hostSeen: '',
            });
            return endpoints.get(sourceId);
        };
        const touch = (endpoint, timestamp, host) => {
            if (timestamp) {
                if (!endpoint.firstSeen || timestamp < endpoint.firstSeen) endpoint.firstSeen = timestamp;
                if (!endpoint.lastSeen || timestamp > endpoint.lastSeen) endpoint.lastSeen = timestamp;
            }
            if (host && (!endpoint._hostSeen || !timestamp || timestamp >= endpoint._hostSeen)) {
                endpoint.reportedHost = String(host).slice(0, 255);
                endpoint._hostSeen = timestamp || endpoint._hostSeen;
            }
        };

        for (const alert of alerts) {
            const endpoint = ensure(alert.sourceId);
            endpoint.alerts += 1;
            if (alert.severity === 'critical') endpoint.critical += 1;
            if (alert.severity === 'high') endpoint.high += 1;
            const status = triageState(alert).status;
            if (status !== 'resolved' && status !== 'false_positive') {
                endpoint.openAlerts += 1;
                const rank = SEVERITY_RANK[alert.severity] ?? -1;
                if (rank > endpoint._riskRank) {
                    endpoint._riskRank = rank;
                    endpoint.risk = alert.severity;
                }
            }
            touch(endpoint, alert.timestamp, alert.event?.hostname || alert.event?.host);
        }
        for (const event of events) {
            const endpoint = ensure(event.sourceId);
            endpoint.events += 1;
            touch(endpoint, event.timestamp, valueFrom(event.raw || {}, ['hostname', 'host', 'Host', 'Hostname']));
        }
        for (const process of processes.values()) {
            const endpoint = ensure(process.sourceId);
            endpoint.processes += 1;
            touch(endpoint, process.lastSeen, '');
        }

        const now = Date.now();
        return [...endpoints.values()].map(endpoint => {
            const lastSeenMillis = Date.parse(endpoint.lastSeen || '');
            const age = Number.isFinite(lastSeenMillis) ? Math.max(0, now - lastSeenMillis) : Number.POSITIVE_INFINITY;
            const telemetryState = !endpoint.lastSeen ? 'unknown' :
                (age <= 15 * 60 * 1000 ? 'recent' : (age <= 24 * 60 * 60 * 1000 ? 'stale' : 'inactive'));
            const { _riskRank, _hostSeen, ...publicEndpoint } = endpoint;
            return { ...publicEndpoint, telemetryState };
        }).sort((left, right) => {
            const riskDifference = (SEVERITY_RANK[right.risk] ?? -1) - (SEVERITY_RANK[left.risk] ?? -1);
            return riskDifference || String(right.lastSeen || '').localeCompare(String(left.lastSeen || ''));
        });
    }

    function addProcessEvent(event) {
        if (!event.processKey) return;
        let process = processes.get(event.processKey);
        if (!process) {
            const raw = event.raw;
            process = {
                processKey: event.processKey,
                sourceId: event.sourceId,
                parentProcessKey: event.parentProcessKey,
                pid: boundedInteger(valueFrom(raw, ['pid', 'ProcessId']), 'pid'),
                image: boundedString(valueFrom(raw, ['image', 'Image']), 'image', LIMITS.output),
                commandLine: boundedString(valueFrom(raw, ['command_line', 'CommandLine']), 'command line', LIMITS.output),
                startTime: boundedString(valueFrom(raw, ['start_time', 'startTime']), 'start time', 128) || event.timestamp,
                lastSeen: event.timestamp,
                eventCount: 0,
            };
            processes.set(event.processKey, process);
        }
        process.lastSeen = event.timestamp;
        process.eventCount += 1;
        if (!process.parentProcessKey && event.parentProcessKey) process.parentProcessKey = event.parentProcessKey;
    }

    function addEvent(event, persist) {
        const dedupKey = `${event.sourceId}\u0000${event.eventId}`;
        if (eventIds.has(dedupKey)) return false;
        eventIds.set(dedupKey, true);
        if (eventIds.size > LIMITS.dedupIds) eventIds.delete(eventIds.keys().next().value);
        events.push(event);
        if (events.length > LIMITS.events) events = events.slice(-Math.floor(LIMITS.events / 2));
        addProcessEvent(event);
        if (persist) appendJsonLine(files.events, event);
        return true;
    }

    for (const stored of readJsonLines(files.events, LIMITS.events)) {
        try {
            const sourceId = boundedString(stored.sourceId, 'sourceId', 256, true);
            const event = stored.raw ? normalizeRawEvent(stored.raw, sourceId) : normalizeRawEvent(stored, sourceId);
            addEvent(event, false);
        } catch (_) {}
    }

    function broadcast(type, data) {
        const message = JSON.stringify({ type, data });
        for (const ws of wsClients) {
            if (ws.readyState === ws.OPEN) ws.send(message);
        }
    }

    function addAlert(alert) {
        const fingerprint = crypto.createHash('sha256').update(JSON.stringify([
            alert.sourceId, alert.id || '', alert.rule, alert.timestamp, alert.event,
        ])).digest('hex');
        if (recentAlerts.has(fingerprint)) return false;
        recentAlerts.set(fingerprint, true);
        if (recentAlerts.size > LIMITS.dedupIds) recentAlerts.delete(recentAlerts.keys().next().value);
        alerts.push(alert);
        if (alerts.length > LIMITS.alerts) alerts = alerts.slice(-Math.floor(LIMITS.alerts / 2));
        appendJsonLine(files.alerts, alert);
        broadcast('alert', decorateAlert(alert));
        return true;
    }

    function auth(role) {
        return (req, res, next) => {
            const expected = keys[role];
            const supplied = req.get('x-api-key');
            if (role === 'admin' && !expected) {
                return res.status(503).json({ error: 'admin API key is not configured' });
            }
            if (!expected) {
                if (deploymentSecurity.production)
                    return res.status(503).json({ error: `${role} API key is not configured` });
                req.auth = { role, sourceId: sourceIdentity('') };
                return next();
            }
            if (!safeEqual(supplied, expected)) return res.status(401).json({ error: 'unauthorized' });
            req.auth = { role, sourceId: sourceIdentity(supplied) };
            return next();
        };
    }

    const app = express();
    app.disable('x-powered-by');
    /* The loopback TLS-proxy deployment keeps Express proxy trust disabled.
     * Forwarded headers are informational only and never satisfy auth or
     * alter transport/security decisions. */
    app.set('trust proxy', false);
    app.use((req, res, next) => {
        if (Object.prototype.hasOwnProperty.call(req.query, 'api_key')) {
            return res.status(400).json({ error: 'query-string API keys are not accepted' });
        }
        return next();
    });
    app.use(express.json({
        limit: LIMITS.bodyBytes,
        strict: true,
        verify(req, _res, buffer) { req.rawJsonBody = buffer.toString('utf8'); },
    }));
    app.use(express.static(path.join(__dirname, 'public')));

    app.post('/ingest', auth('ingest'), (req, res, next) => {
        try {
            const sourceId = isObject(req.body) && req.body.sourceId !== undefined
                ? boundedString(req.body.sourceId, 'sourceId', 256)
                : req.auth.sourceId;
            const alert = normalizeNativeAlert(req.body, sourceId);
            const dedup = !addAlert(alert);
            res.json({ ok: true, dedup, alert: decorateAlert(alert) });
        } catch (error) { next(error); }
    });

    app.post('/ingest/falco', auth('ingest'), (req, res, next) => {
        try {
            const alert = normalizeFalcoAlert(req.body, req.auth.sourceId);
            const dedup = !addAlert(alert);
            res.json({ ok: true, dedup, alert: decorateAlert(alert) });
        } catch (error) { next(error); }
    });

    app.post('/ingest/events', auth('ingest'), (req, res, next) => {
        try {
            const inputs = Array.isArray(req.body) ? req.body : [req.body];
            if (inputs.length === 0 || inputs.length > 100) throw new ValidationError('event batch must contain 1 to 100 events');
            let accepted = 0;
            let dedup = 0;
            for (const input of inputs) {
                const event = normalizeRawEvent(input, req.auth.sourceId);
                if (addEvent(event, true)) accepted += 1;
                else dedup += 1;
            }
            res.json({ ok: true, accepted, dedup });
        } catch (error) { next(error); }
    });

    app.get('/api/alerts', auth('read'), (req, res) => {
        const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 100, 1), LIMITS.queryLimit);
        const offset = Math.max(Number.parseInt(req.query.offset, 10) || 0, 0);
        const severity = boundedString(req.query.severity, 'severity', 32);
        const rule = boundedString(req.query.rule, 'rule', 256);
        const status = boundedString(req.query.status, 'status', 32);
        const tactic = boundedString(req.query.tactic, 'tactic', 64);
        const assignee = boundedString(req.query.assignee, 'assignee', 256);
        const priority = boundedString(req.query.priority, 'priority', 32);
        const q = boundedString(req.query.q, 'q', 256);
        const since = boundedString(req.query.since, 'since', 64);
        const until = boundedString(req.query.until, 'until', 64);
        if (status && !TRIAGE_STATUSES.has(status)) throw new ValidationError('status is not supported');
        if (priority && !TRIAGE_PRIORITIES.has(priority)) throw new ValidationError('priority is not supported');
        if (since && !Number.isFinite(Date.parse(since))) throw new ValidationError('since must be an ISO-8601 timestamp');
        if (until && !Number.isFinite(Date.parse(until))) throw new ValidationError('until must be an ISO-8601 timestamp');
        let result = alerts;
        if (severity) result = result.filter(alert => alert.severity === severity);
        if (rule) result = result.filter(alert => alert.rule === rule);
        if (status) result = result.filter(alert => triageState(alert).status === status);
        if (assignee) result = result.filter(alert => triageState(alert).assignee === assignee);
        if (priority) result = result.filter(alert => triageState(alert).priority === priority);
        if (tactic) result = result.filter(alert => mitreTactics(alert).includes(tactic));
        if (q) {
            const needle = q.toLowerCase();
            result = result.filter(alert => {
                const event = alert.event || {};
                const summary = event.image || event.command_line || event.output ||
                    event.file_path || event.reg_key || event.pipe_name || '';
                return alert.rule.toLowerCase().includes(needle) ||
                    String(alert.sourceId || '').toLowerCase().includes(needle) ||
                    String(alert.id || '').toLowerCase().includes(needle) ||
                    String(summary).toLowerCase().includes(needle);
            });
        }
        if (since) {
            const sinceMillis = Date.parse(since);
            result = result.filter(alert => Date.parse(alert.timestamp) >= sinceMillis);
        }
        if (until) {
            const untilMillis = Date.parse(until);
            result = result.filter(alert => Date.parse(alert.timestamp) <= untilMillis);
        }
        const total = result.length;
        const start = Math.max(0, total - offset - limit);
        const page = result.slice(start, total - offset).reverse().map(decorateAlert);
        res.json({ total, alerts: page });
    });

    app.get('/api/alerts/:caseId/timeline', auth('read'), (req, res, next) => {
        try {
            const caseId = boundedString(req.params.caseId, 'caseId', 64, true);
            const alert = alerts.find(item => alertCaseId(item) === caseId);
            if (!alert) return res.status(404).json({ error: 'alert not found' });
            const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 30, 1), LIMITS.queryLimit);
            const sourceEvents = events
                .filter(event => event.sourceId === alert.sourceId)
                .sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp));
            const alertTimeMs = Date.parse(alert.timestamp);
            const alertTs = Number.isFinite(alertTimeMs) ? alertTimeMs : 0;
            let before = sourceEvents.filter(event => Date.parse(event.timestamp) < alertTs);
            let after = sourceEvents.filter(event => Date.parse(event.timestamp) >= alertTs);
            before = before.slice(-Math.ceil(limit / 2));
            after = after.slice(0, Math.floor(limit / 2));
            const timeline = before.concat(after)
                .map(event => ({ ...event, summary: eventSummary(event) }));
            return res.json({ caseId, sourceId: alert.sourceId, total: sourceEvents.length, timeline });
        } catch (error) { return next(error); }
    });

    app.get('/api/stats', auth('read'), (_req, res) => {
        const stats = {
            total: alerts.length,
            open: 0,
            endpoints: endpointInventory().length,
            events: events.length,
            processes: processes.size,
            bySeverity: {},
            byRule: {},
            byStatus: {},
            byTactic: {},
            bySource: {},
        };
        for (const alert of alerts) {
            stats.bySeverity[alert.severity] = (stats.bySeverity[alert.severity] || 0) + 1;
            stats.byRule[alert.rule] = (stats.byRule[alert.rule] || 0) + 1;
            const status = triageState(alert).status;
            stats.byStatus[status] = (stats.byStatus[status] || 0) + 1;
            const sourceId = alert.sourceId || 'unknown';
            stats.bySource[sourceId] = (stats.bySource[sourceId] || 0) + 1;
            if (status !== 'resolved' && status !== 'false_positive') stats.open += 1;
            const tactics = mitreTactics(alert);
            for (const tactic of tactics) {
                stats.byTactic[tactic] = (stats.byTactic[tactic] || 0) + 1;
            }
        }
        res.json(stats);
    });

    app.get('/api/stats/timeseries', auth('read'), (req, res, next) => {
        try {
            const bucket = boundedString(req.query.bucket, 'bucket', 32) || 'hour';
            if (bucket !== 'hour' && bucket !== 'day')
                throw new ValidationError('bucket must be hour or day');
            const days = boundedInteger(req.query.days, 'days') ?? 7;
            if (days < 1 || days > 90) throw new ValidationError('days must be an integer in [1, 90]');
            const bucketMillis = bucket === 'day' ? 24 * 60 * 60 * 1000 : 60 * 60 * 1000;
            const now = new Date();
            const alignedNow = bucket === 'day'
                ? Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())
                : Math.floor(now.getTime() / bucketMillis) * bucketMillis;
            const firstStart = alignedNow - (days - 1) * bucketMillis;
            const points = [];
            for (let index = 0; index < days; index += 1) {
                const start = firstStart + index * bucketMillis;
                points.push({
                    start: new Date(start).toISOString(),
                    end: new Date(start + bucketMillis).toISOString(),
                    count: 0,
                    bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
                });
            }
            for (const alert of alerts) {
                const millis = new Date(alert.timestamp).getTime();
                if (!Number.isFinite(millis)) continue;
                const index = Math.floor((millis - firstStart) / bucketMillis);
                if (index < 0 || index >= days) continue;
                const point = points[index];
                point.count += 1;
                if (point.bySeverity[alert.severity] !== undefined) point.bySeverity[alert.severity] += 1;
            }
            res.json({ bucket, days, points });
        } catch (error) { next(error); }
    });

    app.get('/api/stats/health', auth('read'), (_req, res) => {
        const inventory = endpointInventory();
        const byState = { recent: 0, stale: 0, inactive: 0, unknown: 0 };
        const byRisk = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
        let openAlerts = 0;
        for (const endpoint of inventory) {
            byState[endpoint.telemetryState] = (byState[endpoint.telemetryState] || 0) + 1;
            // risk values outside the five spec keys (e.g. 'info' from
            // info-severity alerts) are counted dynamically so byRisk sums to total
            byRisk[endpoint.risk] = (byRisk[endpoint.risk] || 0) + 1;
            openAlerts += endpoint.openAlerts;
        }
        const criticalEndpoints = inventory
            .filter(endpoint => endpoint.risk === 'critical' || endpoint.openAlerts > 0)
            .sort((left, right) => right.openAlerts - left.openAlerts)
            .slice(0, 10)
            .map(endpoint => ({
                sourceId: endpoint.sourceId,
                reportedHost: endpoint.reportedHost,
                openAlerts: endpoint.openAlerts,
                risk: endpoint.risk,
            }));
        res.json({ total: inventory.length, byState, byRisk, openAlerts, criticalEndpoints });
    });

    app.get('/api/endpoints', auth('read'), (req, res, next) => {
        try {
            const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 200, 1), LIMITS.queryLimit);
            const state = boundedString(req.query.state, 'state', 32);
            const query = (boundedString(req.query.q, 'q', 256) || '').toLowerCase();
            if (state && !['recent', 'stale', 'inactive', 'unknown'].includes(state))
                throw new ValidationError('state is not supported');
            let result = endpointInventory();
            if (state) result = result.filter(endpoint => endpoint.telemetryState === state);
            if (query) result = result.filter(endpoint =>
                endpoint.sourceId.toLowerCase().includes(query) || endpoint.reportedHost.toLowerCase().includes(query));
            res.json({ total: result.length, endpoints: result.slice(0, limit) });
        } catch (error) { next(error); }
    });

    app.get('/api/endpoints/:sourceId', auth('read'), (req, res, next) => {
        try {
            const sourceId = boundedString(req.params.sourceId, 'sourceId', 256, true);
            const endpoint = endpointInventory().find(item => item.sourceId === sourceId);
            if (!endpoint) return res.status(404).json({ error: 'endpoint not found' });
            const recentAlerts = alerts.filter(alert => alert.sourceId === sourceId)
                .slice(-25).reverse().map(decorateAlert);
            const recentEvents = events.filter(event => event.sourceId === sourceId)
                .slice(-50).reverse().map(event => ({ ...event, summary: eventSummary(event) }));
            return res.json({ ...endpoint, recentAlerts, recentEvents });
        } catch (error) { return next(error); }
    });

    app.get('/api/events', auth('read'), (req, res, next) => {
        try {
            const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 200, 1), LIMITS.queryLimit);
            const type = boundedString(req.query.type, 'type', 128);
            const sourceId = boundedString(req.query.sourceId, 'sourceId', 256);
            const processKey = boundedString(req.query.processKey, 'processKey', 1024);
            const pid = boundedInteger(req.query.pid, 'pid');
            const query = (boundedString(req.query.q, 'q', 256) || '').toLowerCase();
            const since = req.query.since === undefined ? undefined : boundedTimestamp(req.query.since, 'since', true);
            const until = req.query.until === undefined ? undefined : boundedTimestamp(req.query.until, 'until', true);
            if (since && until && since > until) throw new ValidationError('since must not be after until');
            let result = events;
            if (type) result = result.filter(event => event.type === type);
            if (sourceId) result = result.filter(event => event.sourceId === sourceId);
            if (processKey) result = result.filter(event => event.processKey === processKey);
            if (pid !== undefined) {
                result = result.filter(event => {
                    const raw = event.raw || {};
                    const eventPid = Number(valueFrom(raw, ['pid', 'ProcessId']));
                    return eventPid === pid;
                });
            }
            if (since) result = result.filter(event => event.timestamp >= since);
            if (until) result = result.filter(event => event.timestamp <= until);
            if (query) result = result.filter(event => eventMatchesQuery(event, query));
            const total = result.length;
            const selected = [...result].sort((left, right) => right.timestamp.localeCompare(left.timestamp)).slice(0, limit);
            res.json({ total, events: selected.map(event => ({ ...event, summary: eventSummary(event) })) });
        } catch (error) { next(error); }
    });

    app.get('/api/alerts/:caseId/activity', auth('read'), (req, res, next) => {
        try {
            const caseId = boundedString(req.params.caseId, 'caseId', 64, true);
            if (!alerts.some(alert => alertCaseId(alert) === caseId))
                return res.status(404).json({ error: 'alert not found' });
            return res.json(triageHistory.filter(activity => activity.caseId === caseId).slice().reverse());
        } catch (error) { return next(error); }
    });

    /* Similar alerts: same rule + same source, for clustering/review. */
    app.get('/api/alerts/:caseId/similar', auth('read'), (req, res, next) => {
        try {
            const caseId = boundedString(req.params.caseId, 'caseId', 64, true);
            const alert = alerts.find(item => alertCaseId(item) === caseId);
            if (!alert) return res.status(404).json({ error: 'alert not found' });
            const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 20, 1), LIMITS.queryLimit);
            const similar = alerts
                .filter(item => item.rule === alert.rule && item.sourceId === alert.sourceId && alertCaseId(item) !== caseId)
                .sort((left, right) => right.timestamp.localeCompare(left.timestamp))
                .slice(0, limit)
                .map(decorateAlert);
            return res.json({ total: similar.length, rule: alert.rule, sourceId: alert.sourceId, alerts: similar });
        } catch (error) { return next(error); }
    });

    app.patch('/api/alerts/:caseId/triage', auth('admin'), (req, res, next) => {
        try {
            if (Object.keys(req.query).length) throw new ValidationError('query parameters are not accepted');
            rejectDuplicateJsonKeys(req.rawJsonBody || '');
            if (!isObject(req.body)) throw new ValidationError('request body must be an object');
            exactKeys(req.body, ['status', 'note', 'assignee', 'priority'], 'request body');
            const caseId = boundedString(req.params.caseId, 'caseId', 64, true);
            const alert = alerts.find(item => alertCaseId(item) === caseId);
            if (!alert) return res.status(404).json({ error: 'alert not found' });
            const status = boundedString(req.body.status, 'status', 32, true);
            if (!TRIAGE_STATUSES.has(status)) throw new ValidationError('status is not supported');
            const assignee = boundedString(req.body.assignee, 'assignee', 256) || '';
            const priority = req.body.priority === undefined
                ? (alertTriage.get(caseId)?.priority || 'normal')
                : String(req.body.priority);
            if (!TRIAGE_PRIORITIES.has(priority)) throw new ValidationError('priority is not supported');
            const activity = {
                caseId,
                status,
                note: boundedNote(req.body.note),
                assignee,
                priority,
                timestamp: new Date().toISOString(),
                actor: sourceIdentity(req.get('x-api-key')),
            };
            appendJsonLine(files.triage, activity);
            triageHistory.push(activity);
            if (triageHistory.length > LIMITS.triageEvents)
                triageHistory.splice(0, triageHistory.length - Math.floor(LIMITS.triageEvents / 2));
            alertTriage.set(caseId, activity);
            const decorated = decorateAlert(alert);
            broadcast('alert_updated', decorated);
            return res.json({ ok: true, alert: decorated, activity });
        } catch (error) { return next(error); }
    });

    /* Batch triage: update status/note/assignee/priority for many cases. */
    app.post('/api/alerts/triage/batch', auth('admin'), (req, res, next) => {
        try {
            if (Object.keys(req.query).length) throw new ValidationError('query parameters are not accepted');
            rejectDuplicateJsonKeys(req.rawJsonBody || '');
            if (!isObject(req.body)) throw new ValidationError('request body must be an object');
            exactKeys(req.body, ['caseIds', 'status', 'note', 'assignee', 'priority'], 'request body');
            const caseIds = req.body.caseIds;
            if (!Array.isArray(caseIds) || caseIds.length === 0 || caseIds.length > 100)
                throw new ValidationError('caseIds must be an array of 1 to 100 case IDs');
            const status = boundedString(req.body.status, 'status', 32, true);
            if (!TRIAGE_STATUSES.has(status)) throw new ValidationError('status is not supported');
            const assignee = boundedString(req.body.assignee, 'assignee', 256) || '';
            const priority = req.body.priority === undefined
                ? undefined
                : String(req.body.priority);
            if (priority !== undefined && !TRIAGE_PRIORITIES.has(priority))
                throw new ValidationError('priority is not supported');
            const note = boundedNote(req.body.note);
            const actor = sourceIdentity(req.get('x-api-key'));
            const now = new Date().toISOString();
            const updated = [];
            const missing = [];
            for (const rawCaseId of caseIds) {
                const caseId = boundedString(rawCaseId, 'caseId', 64, true);
                const alert = alerts.find(item => alertCaseId(item) === caseId);
                if (!alert) { missing.push(caseId); continue; }
                const previous = alertTriage.get(caseId);
                const activity = {
                    caseId,
                    status,
                    note: note !== '' ? note : (previous?.note || ''),
                    assignee: assignee !== '' ? assignee : (previous?.assignee || ''),
                    priority: priority !== undefined ? priority : (previous?.priority || 'normal'),
                    timestamp: now,
                    actor,
                };
                appendJsonLine(files.triage, activity);
                triageHistory.push(activity);
                if (triageHistory.length > LIMITS.triageEvents)
                    triageHistory.splice(0, triageHistory.length - Math.floor(LIMITS.triageEvents / 2));
                alertTriage.set(caseId, activity);
                const decorated = decorateAlert(alert);
                broadcast('alert_updated', decorated);
                updated.push(decorated);
            }
            return res.json({ ok: true, updated: updated.length, missing, alerts: updated });
        } catch (error) { return next(error); }
    });

    app.get('/api/processes', auth('read'), (req, res, next) => {
        try {
            const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 200, 1), LIMITS.queryLimit);
            const sourceId = boundedString(req.query.sourceId, 'sourceId', 256);
            let result = [...processes.values()];
            if (sourceId) result = result.filter(process => process.sourceId === sourceId);
            result.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
            res.json(result.slice(0, limit));
        } catch (error) { next(error); }
    });

    app.get('/api/process-hunt', auth('read'), (req, res, next) => {
        try {
            const allowed = new Set(['processKey', 'maxNodes', 'maxDepth', 'eventLimit']);
            if (Object.keys(req.query).some(key => !allowed.has(key)))
                throw new ValidationError('query parameter is not supported');
            const processKey = req.query.processKey;
            if (typeof processKey !== 'string' || !processKey || processKey.length > 1024)
                throw new ValidationError('processKey must be a single non-empty string of at most 1024 characters');

            const positiveInteger = (value, name, fallback, maximum) => {
                if (value === undefined) return fallback;
                if (typeof value !== 'string' || !/^[1-9]\d*$/.test(value))
                    throw new ValidationError(`${name} must be a positive integer string`);
                const parsed = Number(value);
                if (!Number.isSafeInteger(parsed) || parsed > maximum)
                    throw new ValidationError(`${name} must be in [1, ${maximum}]`);
                return parsed;
            };
            const result = buildProcessHunt(processes, events, processKey, {
                maxNodes: positiveInteger(req.query.maxNodes, 'maxNodes', 200, 1000),
                maxDepth: positiveInteger(req.query.maxDepth, 'maxDepth', 16, 64),
                eventLimit: positiveInteger(req.query.eventLimit, 'eventLimit', 500, 1000),
            });
            if (!result) return res.status(404).json({ error: 'process not found' });
            return res.json(result);
        } catch (error) { return next(error); }
    });

    app.get('/api/process-tree', auth('read'), (_req, res) => {
        const nodes = [...processes.values()].map(process => ({ ...process, children: [] }));
        const byKey = new Map(nodes.map(node => [node.processKey, node]));
        const roots = [];
        for (const node of nodes) {
            const parent = byKey.get(node.parentProcessKey);
            if (parent && parent !== node) parent.children.push(node);
            else roots.push(node);
        }
        res.json(roots);
    });

    app.get('/api/process-timeline', auth('read'), (req, res, next) => {
        try {
            const processKey = boundedString(req.query.processKey, 'processKey', 1024, true);
            const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 500, 1), LIMITS.queryLimit);
            res.json(events.filter(event => event.processKey === processKey)
                .sort((a, b) => a.timestamp.localeCompare(b.timestamp)).slice(-limit));
        } catch (error) { next(error); }
    });

    function dryRunResponse(action) {
        return async (req, res, next) => {
            try {
                if (Object.keys(req.query).length)
                    throw new ValidationError('query parameters are not accepted');
                rejectDuplicateJsonKeys(req.rawJsonBody || '');
                if (!isObject(req.body)) throw new ValidationError('request body must be an object');
                exactKeys(req.body, ['reason', 'target', 'maxTreeSize', 'suspendBeforeTerminate'], 'request body');
                const reason = boundedString(req.body.reason, 'reason', 1024, true);
                for (const character of reason) {
                    const code = character.charCodeAt(0);
                    if ((code < 0x20 && code !== 0x09) || code === 0x7f)
                        throw new ValidationError('reason contains forbidden control characters');
                }
                let maxTreeSize;
                let suspendBeforeTerminate;
                if (req.body.maxTreeSize !== undefined) {
                    const tree = Number(req.body.maxTreeSize);
                    if (!Number.isSafeInteger(tree) || tree < 4 || tree > 64)
                        throw new ValidationError('maxTreeSize must be an integer in [4, 64]');
                    maxTreeSize = tree;
                }
                if (req.body.suspendBeforeTerminate !== undefined) {
                    if (typeof req.body.suspendBeforeTerminate !== 'boolean')
                        throw new ValidationError('suspendBeforeTerminate must be boolean');
                    suspendBeforeTerminate = req.body.suspendBeforeTerminate;
                }
                if (!isObject(req.body.target)) throw new ValidationError('target identity is required');
                let target;
                let channelStatus = 'local_only';
                if (action === 'terminate') {
                    exactKeys(req.body.target, ['pid', 'createTime100ns', 'processKey'], 'target');
                    const pid = boundedInteger(req.body.target.pid, 'target.pid');
                    if (pid === undefined || pid === 0 || pid === 4)
                        throw new ValidationError('target.pid is required and must not be protected');
                    const createTime100ns = decimalUint64String(
                        req.body.target.createTime100ns, 'target.createTime100ns', true);
                    const processKey = boundedString(req.body.target.processKey,
                        'target.processKey', 1024);
                    target = { pid, createTime100ns };
                    if (processKey !== undefined) target.processKey = processKey;
                    if (realTerminationEnabled && (!responseFoundationEnabled || !responseClient)) {
                        appendJsonLine(files.audit, {
                            timestamp: new Date().toISOString(), action,
                            effective_mode: 'real', status: 'not_ready',
                            reason, target, requestedBy: sourceIdentity(req.get('x-api-key')),
                        });
                        return res.status(503).json({ ok: false, action,
                            effective_mode: 'real', status: 'not_ready', target });
                    }
                    if (responseFoundationEnabled && responseClient) {
                        try {
                            const readiness = await responseClient.readiness();
                            const readinessMode = readiness === true ? 'dry_run' :
                                readiness && readiness.effective_mode;
                            if (realTerminationEnabled && readiness.effective_mode !== 'real') {
                                appendJsonLine(files.audit, {
                                    timestamp: new Date().toISOString(), action,
                                    effective_mode: 'real', status: 'not_ready',
                                    reason, target, requestedBy: sourceIdentity(req.get('x-api-key')),
                                });
                                return res.status(503).json({ ok: false, action,
                                    effective_mode: 'real', status: 'not_ready', target });
                            }
                            if (realTerminationEnabled) assertResponseAuditWritable(readiness);
                            if (!realTerminationEnabled && readinessMode !== 'dry_run') {
                                if (readinessMode === 'real') {
                                    const audit = {
                                        timestamp: new Date().toISOString(), action,
                                        effective_mode: 'dry_run', status: 'local_only',
                                        reason, target,
                                        requestedBy: sourceIdentity(req.get('x-api-key')),
                                    };
                                    appendJsonLine(files.audit, audit);
                                    return res.json({ ok: true, action,
                                        effective_mode: 'dry_run', status: 'local_only',
                                        target, audit_timestamp: audit.timestamp });
                                }
                                appendJsonLine(files.audit, {
                                    timestamp: new Date().toISOString(), action,
                                    effective_mode: 'dry_run', status: 'native_not_ready',
                                    reason, target, requestedBy: sourceIdentity(req.get('x-api-key')),
                                });
                                return res.status(503).json({ ok: false, action,
                                    effective_mode: 'dry_run', status: 'native_not_ready', target });
                            }
                            const result = await responseClient.terminate({ reason, target,
                                maxTreeSize, suspendBeforeTerminate });
                            if (realTerminationEnabled) {
                                if (result.effective_mode !== 'real')
                                    return res.status(503).json({ ok: false, action,
                                        effective_mode: 'real', status: 'outcome_unknown', target });
                                let consoleAuditWritten = true;
                                try {
                                    appendJsonLine(files.audit, {
                                        timestamp: new Date().toISOString(), action,
                                        ...result, reason, target,
                                        requestedBy: sourceIdentity(req.get('x-api-key')),
                                    });
                                } catch (auditError) {
                                    consoleAuditWritten = false;
                                    logger.error('[edr-console] native result audit failed',
                                        auditError.message);
                                }
                                return res.status(result.ok ? 200 : 503).json({
                                    action, target, ...result,
                                    console_audit_written: consoleAuditWritten,
                                });
                            }
                            if (readinessMode === 'dry_run' &&
                                result.effective_mode === 'dry_run' && result.ok !== false) {
                                channelStatus = 'native_dry_run_accepted';
                            } else {
                                return res.status(503).json({ ok: false, action,
                                    effective_mode: 'dry_run', status: 'native_not_ready', target });
                            }
                        } catch (error) {
                            const uncertain = realTerminationEnabled && error.dispatched;
                            logger.warn('[edr-console] native response unavailable', error.message);
                            appendJsonLine(files.audit, {
                                timestamp: new Date().toISOString(), action,
                                effective_mode: realTerminationEnabled ? 'real' : 'dry_run',
                                status: error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE' ? 'audit_failed' :
                                    (uncertain ? 'outcome_unknown' :
                                        (realTerminationEnabled ? 'not_ready' : 'native_unavailable')),
                                reason, target, requestedBy: sourceIdentity(req.get('x-api-key')),
                            });
                            return res.status(503).json({ ok: false, action,
                                effective_mode: realTerminationEnabled ? 'real' : 'dry_run',
                                status: error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE' ? 'audit_failed' :
                                    (uncertain ? 'outcome_unknown' :
                                        (realTerminationEnabled ? 'not_ready' : 'native_unavailable')), target });
                        }
                    }
                }
                if (action === 'quarantine') {
                    exactKeys(req.body.target, ['path', 'sha256'], 'target');
                    target = boundedObject(req.body.target, 'target', 2);
                    boundedString(target.path, 'target.path', LIMITS.output, true);
                    const hash = boundedString(target.sha256, 'target.sha256', 64, true);
                    if (!/^[a-f0-9]{64}$/i.test(hash))
                        throw new ValidationError('target.sha256 must be a SHA-256 digest');
                    if (realQuarantineEnabled) {
                        if (!responseFoundationEnabled || !responseClient) {
                            appendJsonLine(files.audit, {
                                timestamp: new Date().toISOString(), action,
                                effective_mode: 'real', status: 'not_ready', reason, target,
                                requestedBy: sourceIdentity(req.get('x-api-key')),
                            });
                            return res.status(503).json({ ok: false, action,
                                effective_mode: 'real', status: 'not_ready', target });
                        }
                        try {
                            const readiness = await responseClient.readiness();
                            if (readiness.capabilities?.quarantine !== 'real') {
                                appendJsonLine(files.audit, {
                                    timestamp: new Date().toISOString(), action,
                                    effective_mode: 'real', status: 'native_not_ready', reason, target,
                                    requestedBy: sourceIdentity(req.get('x-api-key')),
                                });
                                return res.status(503).json({ ok: false, action,
                                    effective_mode: 'real', status: 'native_not_ready', target });
                            }
                            assertResponseAuditWritable(readiness);
                            const result = await responseClient.quarantine({ reason, target });
                            if (result.effective_mode !== 'real')
                                return res.status(503).json({ ok: false, action,
                                    effective_mode: 'real', status: 'outcome_unknown', target });
                            let consoleAuditWritten = true;
                            try {
                                appendJsonLine(files.audit, {
                                    timestamp: new Date().toISOString(), action, ...result,
                                    reason, target, requestedBy: sourceIdentity(req.get('x-api-key')),
                                });
                            } catch (auditError) {
                                consoleAuditWritten = false;
                                logger.error('[edr-console] native result audit failed', auditError.message);
                            }
                            return res.status(result.ok ? 200 : 503).json({
                                action, target, ...result,
                                console_audit_written: consoleAuditWritten,
                            });
                        } catch (error) {
                            const status = error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE' ? 'audit_failed' :
                                (error.dispatched ? 'outcome_unknown' : 'native_unavailable');
                            logger.warn('[edr-console] native response unavailable', error.message);
                            appendJsonLine(files.audit, {
                                timestamp: new Date().toISOString(), action,
                                effective_mode: 'real', status, reason, target,
                                requestedBy: sourceIdentity(req.get('x-api-key')),
                            });
                            return res.status(503).json({ ok: false, action,
                                effective_mode: 'real', status, target });
                        }
                    }
                }
                const audit = {
                    timestamp: new Date().toISOString(), action,
                    effective_mode: 'dry_run', status: channelStatus, reason, target,
                    requestedBy: sourceIdentity(req.get('x-api-key')),
                };
                appendJsonLine(files.audit, audit);
                res.json({ ok: true, action, effective_mode: 'dry_run',
                    status: channelStatus, target, audit_timestamp: audit.timestamp });
            } catch (error) { next(error); }
        };
    }

    function suspendResumeResponse(action) {
        const enableReal = action === 'suspend' ? realSuspendEnabled : realResumeEnabled;
        const capabilityKey = action;
        const clientMethod = action;
        return async (req, res, next) => {
            try {
                if (Object.keys(req.query).length)
                    throw new ValidationError('query parameters are not accepted');
                rejectDuplicateJsonKeys(req.rawJsonBody || '');
                if (!isObject(req.body)) throw new ValidationError('request body must be an object');
                exactKeys(req.body, ['reason', 'target'], 'request body');
                const reason = boundedString(req.body.reason, 'reason', 1024, true);
                for (const character of reason) {
                    const code = character.charCodeAt(0);
                    if ((code < 0x20 && code !== 0x09) || code === 0x7f)
                        throw new ValidationError('reason contains forbidden control characters');
                }
                if (!isObject(req.body.target)) throw new ValidationError('target is required');
                exactKeys(req.body.target, ['pid', 'createTime100ns'], 'target');
                const pid = boundedInteger(req.body.target.pid, 'target.pid');
                if (pid === undefined || pid === 0 || pid === 4)
                    throw new ValidationError('target.pid is required and must not be protected');
                const createTime100ns = decimalUint64String(req.body.target.createTime100ns, 'target.createTime100ns', true);
                const target = { pid, createTime100ns };
                const requestedBy = sourceIdentity(req.get('x-api-key'));
                if (!enableReal || !responseFoundationEnabled || !responseClient) {
                    if (responseFoundationEnabled && responseClient) {
                        try {
                            await responseClient.readiness();
                            const result = await responseClient[clientMethod]({ reason, target });
                            if (result.effective_mode === 'dry_run') {
                                let consoleAuditWritten = true;
                                try {
                                    appendJsonLine(files.audit, {
                                        timestamp: new Date().toISOString(), action, ...result, reason, target, requestedBy,
                                    });
                                } catch (auditError) {
                                    consoleAuditWritten = false;
                                    logger.error('[edr-console] native result audit failed', auditError.message);
                                }
                                return res.status(result.ok ? 200 : 503).json({
                                    action, target, ...result, console_audit_written: consoleAuditWritten,
                                });
                            }
                            const audit = {
                                timestamp: new Date().toISOString(), action,
                                effective_mode: 'dry_run', status: 'native_not_ready', reason, target, requestedBy,
                            };
                            appendJsonLine(files.audit, audit);
                            return res.status(503).json({ ok: false, action, effective_mode: 'dry_run', status: 'native_not_ready', target });
                        } catch (error) {
                            if (error instanceof ValidationError) throw error;
                            const dispatched = Boolean(error.dispatched);
                            const status = dispatched ? 'outcome_unknown' : 'native_not_ready';
                            logger.warn('[edr-console] native response unavailable', error.message);
                            appendJsonLine(files.audit, {
                                timestamp: new Date().toISOString(), action,
                                effective_mode: 'dry_run', status, reason, target, requestedBy,
                            });
                            return res.status(503).json({ ok: false, action, effective_mode: 'dry_run', status, target });
                        }
                    }
                    const audit = {
                        timestamp: new Date().toISOString(), action,
                        effective_mode: 'dry_run', status: 'not_ready', reason, target, requestedBy,
                    };
                    appendJsonLine(files.audit, audit);
                    return res.status(503).json({ ok: false, action, effective_mode: 'dry_run', status: 'not_ready', target });
                }
                try {
                    const readiness = await responseClient.readiness();
                    if (readiness.capabilities?.[capabilityKey] !== 'real') {
                        const audit = {
                            timestamp: new Date().toISOString(), action,
                            effective_mode: 'dry_run', status: 'native_not_ready', reason, target, requestedBy,
                        };
                        appendJsonLine(files.audit, audit);
                        return res.status(503).json({ ok: false, action, effective_mode: 'dry_run', status: 'native_not_ready', target });
                    }
                    assertResponseAuditWritable(readiness);
                    const result = await responseClient[clientMethod]({ reason, target });
                    if (result.effective_mode !== 'real') {
                        const audit = {
                            timestamp: new Date().toISOString(), action,
                            effective_mode: 'real', status: 'outcome_unknown', reason, target, requestedBy,
                        };
                        appendJsonLine(files.audit, audit);
                        return res.status(503).json({ ok: false, action, effective_mode: 'real', status: 'outcome_unknown', target });
                    }
                    let consoleAuditWritten = true;
                    try {
                        appendJsonLine(files.audit, {
                            timestamp: new Date().toISOString(), action, ...result, reason, target, requestedBy,
                        });
                    } catch (auditError) {
                        consoleAuditWritten = false;
                        logger.error('[edr-console] native result audit failed', auditError.message);
                    }
                    return res.status(result.ok ? 200 : 503).json({
                        action, target, ...result, console_audit_written: consoleAuditWritten,
                    });
                } catch (error) {
                    if (error instanceof ValidationError) throw error;
                    const dispatched = Boolean(error.dispatched);
                    const status = error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE' ? 'audit_failed' :
                        (dispatched ? 'outcome_unknown' : 'native_unavailable');
                    logger.warn('[edr-console] native response unavailable', error.message);
                    appendJsonLine(files.audit, {
                        timestamp: new Date().toISOString(), action,
                        effective_mode: 'real', status, reason, target, requestedBy,
                    });
                    return res.status(503).json({ ok: false, action, effective_mode: 'real', status, target });
                }
            } catch (error) { return next(error); }
        };
    }

    app.post('/api/response/terminate', auth('admin'), dryRunResponse('terminate'));
    app.post('/api/response/quarantine', auth('admin'), dryRunResponse('quarantine'));
    app.post('/api/response/restore_quarantine', auth('admin'), async (req, res, next) => {
        try {
            if (Object.keys(req.query).length)
                throw new ValidationError('query parameters are not accepted');
            rejectDuplicateJsonKeys(req.rawJsonBody || '');
            if (!isObject(req.body)) throw new ValidationError('request body must be an object');
            exactKeys(req.body, ['reason', 'sourceRequestId'], 'request body');
            const reason = boundedString(req.body.reason, 'reason', 1024, true);
            const sourceRequestId = boundedString(req.body.sourceRequestId,
                'sourceRequestId', 64, true);
            if (sourceRequestId.length < 16 || !/^[A-Za-z0-9-]+$/.test(sourceRequestId) ||
                !sourceRequestId.includes('-'))
                throw new ValidationError('sourceRequestId must be a valid quarantine request ID');
            const target = { sourceRequestId };
            const requestedBy = sourceIdentity(req.get('x-api-key'));
            if (!realQuarantineEnabled) {
                const audit = {
                    timestamp: new Date().toISOString(), action: 'restore_quarantine',
                    effective_mode: 'dry_run', status: 'local_only', reason, target,
                    requestedBy,
                };
                appendJsonLine(files.audit, audit);
                return res.json({ ok: true, action: 'restore_quarantine',
                    effective_mode: 'dry_run', status: 'local_only', target,
                    audit_timestamp: audit.timestamp });
            }
            if (!responseFoundationEnabled || !responseClient) {
                appendJsonLine(files.audit, {
                    timestamp: new Date().toISOString(), action: 'restore_quarantine',
                    effective_mode: 'real', status: 'not_ready', reason, target,
                    requestedBy,
                });
                return res.status(503).json({ ok: false, action: 'restore_quarantine',
                    effective_mode: 'real', status: 'not_ready', target });
            }
            try {
                const readiness = await responseClient.readiness();
                if (readiness.capabilities?.quarantine_restore !== 'real') {
                    appendJsonLine(files.audit, {
                        timestamp: new Date().toISOString(), action: 'restore_quarantine',
                        effective_mode: 'real', status: 'native_not_ready', reason, target,
                        requestedBy,
                    });
                    return res.status(503).json({ ok: false,
                        action: 'restore_quarantine', effective_mode: 'real',
                        status: 'native_not_ready', target });
                }
                assertResponseAuditWritable(readiness);
                const result = await responseClient.restoreQuarantine({
                    reason, sourceRequestId,
                });
                if (result.effective_mode !== 'real')
                    return res.status(503).json({ ok: false,
                        action: 'restore_quarantine', effective_mode: 'real',
                        status: 'outcome_unknown', target });
                let consoleAuditWritten = true;
                try {
                    appendJsonLine(files.audit, {
                        timestamp: new Date().toISOString(),
                        action: 'restore_quarantine', ...result, reason, target,
                        requestedBy,
                    });
                } catch (auditError) {
                    consoleAuditWritten = false;
                    logger.error('[edr-console] native restore result audit failed',
                        auditError.message);
                }
                return res.status(result.ok ? 200 : 503).json({
                    action: 'restore_quarantine', target, ...result,
                    console_audit_written: consoleAuditWritten,
                });
            } catch (error) {
                const status = error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE'
                    ? 'audit_failed' :
                    (error.dispatched ? 'outcome_unknown' : 'native_unavailable');
                logger.warn('[edr-console] native quarantine restore unavailable',
                    error.message);
                appendJsonLine(files.audit, {
                    timestamp: new Date().toISOString(), action: 'restore_quarantine',
                    effective_mode: 'real', status, reason, target, requestedBy,
                });
                return res.status(503).json({ ok: false,
                    action: 'restore_quarantine', effective_mode: 'real',
                    status, target });
            }
        } catch (error) { return next(error); }
    });
    app.post('/api/response/suspend', auth('admin'), suspendResumeResponse('suspend'));
    app.post('/api/response/resume', auth('admin'), suspendResumeResponse('resume'));
    app.post('/api/response/delete_file', auth('admin'), async (req, res, next) => {
        try {
            if (Object.keys(req.query).length)
                throw new ValidationError('query parameters are not accepted');
            rejectDuplicateJsonKeys(req.rawJsonBody || '');
            if (!isObject(req.body)) throw new ValidationError('request body must be an object');
            exactKeys(req.body, ['reason', 'target'], 'request body');
            const reason = boundedString(req.body.reason, 'reason', 1024, true);
            for (const character of reason) {
                const code = character.charCodeAt(0);
                if ((code < 0x20 && code !== 0x09) || code === 0x7f)
                    throw new ValidationError('reason contains forbidden control characters');
            }
            if (!isObject(req.body.target)) throw new ValidationError('target is required');
            exactKeys(req.body.target, ['path', 'sha256'], 'target');
            const rawTarget = boundedObject(req.body.target, 'target', 2);
            const filePath = boundedString(rawTarget.path, 'target.path', 1024, true);
            const hashRaw = boundedString(rawTarget.sha256, 'target.sha256', 64, true);
            if (!/^[a-f0-9]{64}$/i.test(hashRaw))
                throw new ValidationError('target.sha256 must be a SHA-256 digest');
            const sha256 = hashRaw.toLowerCase();
            const target = { path: filePath, sha256 };
            const requestedBy = sourceIdentity(req.get('x-api-key'));
            if (!realDeleteFileEnabled || !responseFoundationEnabled || !responseClient) {
                if (responseFoundationEnabled && responseClient) {
                    try {
                        await responseClient.readiness();
                        const result = await responseClient.deleteFile({ reason, target });
                        if (result.effective_mode === 'dry_run') {
                            let consoleAuditWritten = true;
                            try {
                                appendJsonLine(files.audit, {
                                    timestamp: new Date().toISOString(), action: 'delete_file', ...result, reason, target, requestedBy,
                                });
                            } catch (auditError) {
                                consoleAuditWritten = false;
                                logger.error('[edr-console] native result audit failed', auditError.message);
                            }
                            return res.status(result.ok ? 200 : 503).json({
                                action: 'delete_file', target, ...result, console_audit_written: consoleAuditWritten,
                            });
                        }
                        const audit = {
                            timestamp: new Date().toISOString(), action: 'delete_file',
                            effective_mode: 'dry_run', status: 'native_not_ready', reason, target, requestedBy,
                        };
                        appendJsonLine(files.audit, audit);
                        return res.status(503).json({ ok: false, action: 'delete_file', effective_mode: 'dry_run', status: 'native_not_ready', target });
                    } catch (error) {
                        if (error instanceof ValidationError) throw error;
                        const dispatched = Boolean(error.dispatched);
                        const status = dispatched ? 'outcome_unknown' : 'native_not_ready';
                        logger.warn('[edr-console] native response unavailable', error.message);
                        appendJsonLine(files.audit, {
                            timestamp: new Date().toISOString(), action: 'delete_file',
                            effective_mode: 'dry_run', status, reason, target, requestedBy,
                        });
                        return res.status(503).json({ ok: false, action: 'delete_file', effective_mode: 'dry_run', status, target });
                    }
                }
                const audit = {
                    timestamp: new Date().toISOString(), action: 'delete_file',
                    effective_mode: 'dry_run', status: 'not_ready', reason, target, requestedBy,
                };
                appendJsonLine(files.audit, audit);
                return res.status(503).json({ ok: false, action: 'delete_file', effective_mode: 'dry_run', status: 'not_ready', target });
            }
            try {
                const readiness = await responseClient.readiness();
                if (readiness.capabilities?.delete_file !== 'real') {
                    const audit = {
                        timestamp: new Date().toISOString(), action: 'delete_file',
                        effective_mode: 'dry_run', status: 'native_not_ready', reason, target, requestedBy,
                    };
                    appendJsonLine(files.audit, audit);
                    return res.status(503).json({ ok: false, action: 'delete_file', effective_mode: 'dry_run', status: 'native_not_ready', target });
                }
                assertResponseAuditWritable(readiness);
                const result = await responseClient.deleteFile({ reason, target });
                if (result.effective_mode !== 'real') {
                    const audit = {
                        timestamp: new Date().toISOString(), action: 'delete_file',
                        effective_mode: 'real', status: 'outcome_unknown', reason, target, requestedBy,
                    };
                    appendJsonLine(files.audit, audit);
                    return res.status(503).json({ ok: false, action: 'delete_file', effective_mode: 'real', status: 'outcome_unknown', target });
                }
                let consoleAuditWritten = true;
                try {
                    appendJsonLine(files.audit, {
                        timestamp: new Date().toISOString(), action: 'delete_file', ...result, reason, target, requestedBy,
                    });
                } catch (auditError) {
                    consoleAuditWritten = false;
                    logger.error('[edr-console] native result audit failed', auditError.message);
                }
                return res.status(result.ok ? 200 : 503).json({
                    action: 'delete_file', target, ...result, console_audit_written: consoleAuditWritten,
                });
            } catch (error) {
                if (error instanceof ValidationError) throw error;
                const dispatched = Boolean(error.dispatched);
                const status = error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE' ? 'audit_failed' :
                    (dispatched ? 'outcome_unknown' : 'native_unavailable');
                const effectiveMode = dispatched ? 'real' : 'real';
                logger.warn('[edr-console] native response unavailable', error.message);
                appendJsonLine(files.audit, {
                    timestamp: new Date().toISOString(), action: 'delete_file',
                    effective_mode: effectiveMode, status, reason, target, requestedBy,
                });
                return res.status(503).json({ ok: false, action: 'delete_file', effective_mode: effectiveMode, status, target });
            }
        } catch (error) { return next(error); }
    });

    function isolationMutation(enable) {
        const action = enable ? 'isolate' : 'unisolate';
        return async (req, res, next) => {
            try {
                if (Object.keys(req.query).length)
                    throw new ValidationError('query parameters are not accepted');
                rejectDuplicateJsonKeys(req.rawJsonBody || '');
                if (!isObject(req.body)) throw new ValidationError('request body must be an object');
                exactKeys(req.body, ['reason'], 'request body');
                const reason = boundedString(req.body.reason, 'reason', 1024, true);
                for (const character of reason) {
                    const code = character.charCodeAt(0);
                    if ((code < 0x20 && code !== 0x09) || code === 0x7f)
                        throw new ValidationError('reason contains forbidden control characters');
                }
                if (!hostIsolationEnabled || !responseFoundationEnabled || !responseClient ||
                    !hostIsolationManagementIp) {
                    appendJsonLine(files.audit, {
                        timestamp: new Date().toISOString(), action,
                        effective_mode: 'real', status: 'not_ready', reason,
                        requestedBy: sourceIdentity(req.get('x-api-key')),
                    });
                    return res.status(503).json({ ok: false, action,
                        effective_mode: 'real', status: 'not_ready' });
                }
                try {
                    const readiness = await responseClient.readiness();
                    if (readiness.capabilities?.host_isolation !== 'real') {
                        appendJsonLine(files.audit, {
                            timestamp: new Date().toISOString(), action,
                            effective_mode: 'real', status: 'native_not_ready', reason,
                            requestedBy: sourceIdentity(req.get('x-api-key')),
                        });
                        return res.status(503).json({ ok: false, action,
                            effective_mode: 'real', status: 'native_not_ready' });
                    }
                    assertResponseAuditWritable(readiness);
                    const method = enable ? 'isolate' : 'unisolate';
                    const result = await responseClient[method]({ reason,
                        managementIp: hostIsolationManagementIp,
                        allowedPorts: hostIsolationAllowedPorts });
                    let consoleAuditWritten = true;
                    try {
                        appendJsonLine(files.audit, {
                            timestamp: new Date().toISOString(), action, ...result, reason,
                            managementIp: hostIsolationManagementIp,
                            allowedPorts: hostIsolationAllowedPorts,
                            requestedBy: sourceIdentity(req.get('x-api-key')),
                        });
                    } catch (auditError) {
                        consoleAuditWritten = false;
                        logger.error('[edr-console] native result audit failed', auditError.message);
                    }
                    return res.status(result.ok ? 200 : 503).json({ action, ...result,
                        console_audit_written: consoleAuditWritten });
                } catch (error) {
                    const status = error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE' ? 'audit_failed' :
                        (error.dispatched ? 'outcome_unknown' : 'native_unavailable');
                    logger.warn('[edr-console] native response unavailable', error.message);
                    appendJsonLine(files.audit, {
                        timestamp: new Date().toISOString(), action,
                        effective_mode: 'real', status, reason,
                        requestedBy: sourceIdentity(req.get('x-api-key')),
                    });
                    return res.status(503).json({ ok: false, action,
                        effective_mode: 'real', status });
                }
            } catch (error) { next(error); }
        };
    }

    app.post('/api/response/isolate', auth('admin'), isolationMutation(true));
    app.post('/api/response/unisolate', auth('admin'), isolationMutation(false));
    app.get('/api/response/isolation/status', auth('admin'), async (req, res, next) => {
        try {
            if (Object.keys(req.query).length)
                throw new ValidationError('query parameters are not accepted');
            if (!hostIsolationEnabled || !responseFoundationEnabled || !responseClient)
                return res.status(503).json({ ok: false, status: 'not_ready' });
            const readiness = await responseClient.readiness();
            if (readiness.capabilities?.isolation_status !== 'real')
                return res.status(503).json({ ok: false, status: 'native_not_ready' });
            return res.json(await responseClient.isolationStatus());
        } catch (error) {
            if (error instanceof ValidationError) return next(error);
            logger.warn('[edr-console] native isolation status unavailable', error.message);
            return res.status(503).json({ ok: false,
                status: error.dispatched ? 'outcome_unknown' : 'native_unavailable' });
        }
    });

    const RESPONSE_AUDIT_ACTIONS = new Set(['terminate', 'quarantine', 'restore_quarantine', 'isolate', 'unisolate', 'delete_file', 'suspend', 'resume']);
    const RESPONSE_AUDIT_STATUS_SET = new Set(RESPONSE_AUDIT_STATUSES);
    const SECRET_AUDIT_KEYS = new Set([
        'apikey', 'xapikey', 'authorization', 'commandkey', 'token',
        'accesstoken', 'refreshtoken', 'bearertoken', 'authtoken',
        'secret', 'clientsecret', 'password', 'credential', 'credentials',
        'cookie', 'setcookie',
    ]);
    function secretAuditKey(key) {
        const canonical = key.toLowerCase().replace(/[^a-z0-9]/g, '');
        return SECRET_AUDIT_KEYS.has(canonical) ||
            canonical.endsWith('token') || canonical.endsWith('secret') ||
            canonical.includes('password') ||
            canonical.startsWith('credential') ||
            canonical.startsWith('authorization') ||
            canonical.startsWith('cookie') || canonical.startsWith('setcookie');
    }

    function redactAuditText(value) {
        return value
            .replace(/((?:authorization\s*:\s*)?(?:bearer|basic)\s+)[^\s,;]+/gi,
                '$1[redacted]')
            .replace(/((?:cookie|set-cookie)\s*:\s*)[^\r\n]+/gi,
                '$1[redacted]')
            .replace(/((?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|credential)\s*[=:]\s*)[^\s,;]+/gi,
                '$1[redacted]')
            .replace(/([?&](?:api[_-]?key|access[_-]?token|token|password)=)[^&#\s]+/gi,
                '$1[redacted]');
    }

    function publicAuditValue(value, depth = 0) {
        if (depth > 12) return '[redacted-depth-limit]';
        if (typeof value === 'string') return redactAuditText(value);
        if (Array.isArray(value)) return value.slice(0, LIMITS.fields)
            .map(item => publicAuditValue(item, depth + 1));
        if (!isObject(value)) return value;
        const result = Object.create(null);
        for (const [key, item] of Object.entries(value).slice(0, LIMITS.fields)) {
            result[key] = secretAuditKey(key)
                ? '[redacted]'
                : publicAuditValue(item, depth + 1);
        }
        return result;
    }

    app.get('/api/response/audit', auth('admin'), async (req, res, next) => {
        try {
            exactKeys(req.query, ['limit', 'offset', 'action', 'status', 'phase', 'since', 'until', 'runId', 'caseId'], 'query');
            const parseQueryInteger = (value, name, fallback, minimum, maximum) => {
                if (value === undefined) return fallback;
                if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value))
                    throw new ValidationError(`${name} must be an integer in [${minimum}, ${maximum}]`);
                const parsed = Number(value);
                if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum)
                    throw new ValidationError(`${name} must be an integer in [${minimum}, ${maximum}]`);
                return parsed;
            };
            const limit = parseQueryInteger(req.query.limit, 'limit', 100, 1, LIMITS.queryLimit);
            const offset = parseQueryInteger(req.query.offset, 'offset', 0, 0, LIMITS.auditEvents);
            const action = boundedString(req.query.action, 'action', 32);
            const status = boundedString(req.query.status, 'status', 64);
            const phase = boundedString(req.query.phase, 'phase', 16);
            if (phase && !['attempt', 'outcome'].includes(phase)) throw new ValidationError('phase is not supported');
            const runId = boundedString(req.query.runId, 'runId', 64);
            const caseId = boundedString(req.query.caseId, 'caseId', 64);
            if (runId && !REQUEST_ID_RE.test(runId)) throw new ValidationError('runId must be a lowercase UUID');
            const since = req.query.since === undefined ? undefined : boundedTimestamp(req.query.since, 'since', true);
            const until = req.query.until === undefined ? undefined : boundedTimestamp(req.query.until, 'until', true);
            if (action && !RESPONSE_AUDIT_ACTIONS.has(action))
                throw new ValidationError('action is not supported');
            if (status && !RESPONSE_AUDIT_STATUS_SET.has(status))
                throw new ValidationError('status is not supported');
            if (action && status && !responseAuditStatusSupported(action, status))
                throw new ValidationError('status is not supported for action');
            if (since && until && since > until) throw new ValidationError('since must not be after until');

            let tail;
            try {
                tail = await readJsonLinesTailAsync(files.audit, {
                    maxBytes: LIMITS.auditScanBytes,
                    maxLineBytes: LIMITS.auditLineBytes,
                    maxRecords: LIMITS.auditEvents,
                });
            } catch (_) {
                return res.status(503).json({
                    error: 'response audit ledger unavailable',
                    status: 'unavailable',
                });
            }
            let records = tail.records.filter(isObject);
            if (action) records = records.filter(record => record.action === action);
            if (status) records = records.filter(record => record.status === status);
            if (phase) records = records.filter(record => record.phase === phase);
            if (runId) records = records.filter(record => record.runId === runId);
            if (caseId) records = records.filter(record => record.caseId === caseId);
            if (since) records = records.filter(record => typeof record.timestamp === 'string' && record.timestamp >= since);
            if (until) records = records.filter(record => typeof record.timestamp === 'string' && record.timestamp <= until);
            const total = records.length;
            return res.json({
                total,
                total_within_scan_window: total,
                records: records.slice(offset, offset + limit).map(publicAuditValue),
                has_more: offset + limit < total,
                supported_statuses: action
                    ? RESPONSE_AUDIT_STATUSES_BY_ACTION[action]
                    : RESPONSE_AUDIT_STATUSES,
                integrity: {
                    scanned_bytes: tail.scanned_bytes,
                    window_truncated: tail.window_truncated,
                    malformed_count: tail.malformed_count,
                    oversized_count: tail.oversized_count,
                    invalid_utf8_count: tail.invalid_utf8_count,
                    truncated_tail: tail.truncated_tail,
                },
            });
        } catch (error) { return next(error); }
    });

    app.get('/api/audit/chain/verify', auth('read'), async (req, res, next) => {
        try {
            const file = boundedString(req.query.file, 'file', 32, true);
            if (!['alerts','incidents','response'].includes(file)) throw new ValidationError('file must be alerts|incidents|response');
            const map = { alerts: files.alerts, incidents: withinDataDir('incidents.jsonl'), response: files.audit };
            if (Object.keys(req.query).some(k=>k!=='file')) throw new ValidationError('unknown query param');
            return await ledgerQueryGate.run(async () => {
                const result = await verifyLedger(map[file], {
                    maxFileBytes: LIMITS.auditVerifyBytes,
                    maxRecordBytes: LIMITS.auditLineBytes,
                    maxRecords: LIMITS.auditVerifyRecords,
                });
                if (result.status === 'limit_exceeded' || result.status === 'unreadable')
                    return res.status(503).json(result);
                return res.json(result);
            });
        } catch(e){ next(e); }
    });

    /* Correlated incidents (kill chain). Read-only: the console never creates
     * or mutates an incident - the native agent's correlation engine owns
     * them, and incidents.jsonl is the only source of truth. */
    /* NOTE: /summary must be registered before /:incidentId, otherwise Express
     * matches the parameterised route first and 'summary' is read as an id. */
    function incidentUnavailable(res, loaded) {
        if (loaded.completeness.status === 'limit_exceeded' ||
            loaded.completeness.status === 'truncated') {
            res.status(503).json({
                error: 'incident replay incomplete',
                integrity: loaded.integrity,
                completeness: loaded.completeness,
            });
            return true;
        }
        if (loaded.integrity.status !== 'broken' && loaded.integrity.status !== 'unreadable') return false;
        res.status(503).json({ error: 'incident ledger unavailable', integrity: loaded.integrity });
        return true;
    }
    app.get('/api/incidents/summary', auth('read'), async (req, res, next) => {
        try {
            if (Object.keys(req.query).length) throw new ValidationError('query parameters are not accepted');
            return await ledgerQueryGate.run(async () => {
                const loaded = await loadIncidentLedger(dataDir);
                if (incidentUnavailable(res, loaded)) return;
                return res.json({
                    ...incidents.summarize(loaded.incidents),
                    malformed: loaded.malformed,
                    source: 'incidents.jsonl',
                    integrity: loaded.integrity,
                    completeness: loaded.completeness,
                });
            });
        } catch (error) { return next(error); }
    });

    app.get('/api/incidents', auth('read'), async (req, res, next) => {
        try {
            const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), LIMITS.queryLimit);
            const offset = Math.max(Number.parseInt(req.query.offset, 10) || 0, 0);
            const severity = boundedString(req.query.severity, 'severity', 16);
            const state = boundedString(req.query.state, 'state', 16);
            const host = boundedString(req.query.host, 'host', 256);
            const tactic = boundedString(req.query.tactic, 'tactic', 64);
            const q = boundedString(req.query.q, 'q', 256);
            const minScoreRaw = req.query.min_score;
            if (severity && !Object.prototype.hasOwnProperty.call(SEVERITY_RANK, severity))
                throw new ValidationError('severity is not supported');
            if (state && state !== 'open' && state !== 'closed')
                throw new ValidationError('state must be open or closed');
            let minScore;
            if (minScoreRaw !== undefined) {
                minScore = Number.parseInt(minScoreRaw, 10);
                if (!Number.isFinite(minScore) || minScore < 0 || minScore > 100)
                    throw new ValidationError('min_score must be an integer between 0 and 100');
            }
            return await ledgerQueryGate.run(async () => {
                const loaded = await loadIncidentLedger(dataDir);
                if (incidentUnavailable(res, loaded)) return;
                const filtered = incidents.filterIncidents(loaded.incidents, {
                    severity, state, host, tactic, q, minScore,
                });
                const total = filtered.length;
                const page = filtered.slice(offset, offset + limit);
                return res.json({
                    total,
                    malformed: loaded.malformed,
                    incidents: page,
                    summary: incidents.summarize(filtered),
                    integrity: loaded.integrity,
                    completeness: loaded.completeness,
                });
            });
        } catch (error) { return next(error); }
    });

    app.get('/api/incidents/:incidentId', auth('read'), async (req, res, next) => {
        try {
            if (Object.keys(req.query).length) throw new ValidationError('query parameters are not accepted');
            const incidentId = boundedString(req.params.incidentId, 'incidentId', 64, true);
            return await ledgerQueryGate.run(async () => {
                const loaded = await loadIncidentLedger(dataDir);
                if (incidentUnavailable(res, loaded)) return;
                const found = loaded.incidents.find(item => item.id === incidentId);
                if (!found) return res.status(404).json({ error: 'incident not found', integrity: loaded.integrity,
                    completeness: loaded.completeness });
                return res.json({ incident: found, integrity: loaded.integrity,
                    completeness: loaded.completeness });
            });
        } catch (error) { return next(error); }
    });

    app.get('/api/incidents/:incidentId/graph', auth('read'), async (req, res, next) => {
        try {
            if (Object.keys(req.query).length) throw new ValidationError('query parameters are not accepted');
            const incidentId = boundedString(req.params.incidentId, 'incidentId', 64, true);
            return await ledgerQueryGate.run(async () => {
                const loaded = await loadIncidentLedger(dataDir);
                if (incidentUnavailable(res, loaded)) return;
                const found = loaded.incidents.find(item => item.id === incidentId);
                if (!found) return res.status(404).json({ error: 'incident not found', integrity: loaded.integrity,
                    completeness: loaded.completeness });
                const graph = incidents.buildGraph(found);
                if (!graph) return res.status(404).json({ error: 'incident not found', integrity: loaded.integrity,
                    completeness: loaded.completeness });
                return res.json({ graph, integrity: loaded.integrity,
                    completeness: loaded.completeness });
            });
        } catch (error) { return next(error); }
    });


    /* SOAR playbooks - manual trigger only */
    app.get('/api/playbooks', auth('admin'), (req, res, next) => {
        try {
            if (Object.keys(req.query).length) throw new ValidationError('query parameters are not accepted');
            const list = playbooks.loadPlaybooks(dataDir);
            return res.json({ playbooks: list });
        } catch (error) { return next(error); }
    });

    app.post('/api/playbooks', auth('admin'), (req, res, next) => {
        try {
            if (Object.keys(req.query).length) throw new ValidationError('query parameters are not accepted');
            rejectDuplicateJsonKeys(req.rawJsonBody || '');
            if (!isObject(req.body)) throw new ValidationError('request body must be an object');
            exactKeys(req.body, ['id', 'name', 'description', 'steps'], 'request body');
            const configuredId = req.body.id === undefined ? undefined : boundedString(req.body.id, 'id', 64, true);
            if (configuredId !== undefined && !/^[a-z0-9][a-z0-9-]{1,63}$/.test(configuredId))
                throw new ValidationError('id must be a lowercase alphanumeric dash string');
            const name = boundedString(req.body.name, 'name', 128, true);
            const description = boundedString(req.body.description, 'description', 2048) || '';
            const stepsRaw = req.body.steps;
            if (!Array.isArray(stepsRaw) || stepsRaw.length === 0 || stepsRaw.length > 10)
                throw new ValidationError('steps must be an array of 1 to 10 steps');
            const steps = stepsRaw.map((item, index) => {
                if (!isObject(item)) throw new ValidationError(`steps[${index}] must be an object`);
                exactKeys(item, ['action', 'description', 'target', 'reason'], `steps[${index}]`);
                const action = boundedString(item.action, `steps[${index}].action`, 32, true);
                if (!playbooks.PLAYBOOK_ACTIONS.has(action))
                    throw new ValidationError(`steps[${index}].action is not supported`);
                const stepDescription = boundedString(item.description, `steps[${index}].description`, 512) || '';
                let target;
                if (item.target !== undefined) {
                    if (!isObject(item.target)) throw new ValidationError(`steps[${index}].target must be an object`);
                    target = boundedObject(item.target, `steps[${index}].target`);
                    const targetKeys = action === 'quarantine' ? ['path', 'sha256'] :
                        ['terminate', 'suspend', 'resume'].includes(action) ? ['pid', 'createTime100ns'] : [];
                    exactKeys(target, targetKeys, `steps[${index}].target`);
                }
                const reason = boundedString(item.reason, `steps[${index}].reason`, 1024) || undefined;
                const out = { action };
                if (stepDescription) out.description = stepDescription;
                if (target) out.target = target;
                if (reason) out.reason = reason;
                return out;
            });
            const finalId = configuredId || `playbook-${crypto.randomUUID().slice(0, 8)}`;
            if (playbooks.findPlaybook(dataDir, finalId))
                throw new ValidationError('playbook id already exists');
            const playbook = {
                id: finalId,
                name,
                description,
                steps,
                createdAt: new Date().toISOString(),
                createdBy: sourceIdentity(req.get('x-api-key')),
            };
            playbooks.appendPlaybook(dataDir, playbook);
            return res.json({ ok: true, playbook });
        } catch (error) { return next(error); }
    });

    app.post('/api/playbooks/:id/run', auth('admin'), async (req, res, next) => {
        try {
            if (Object.keys(req.query).length) throw new ValidationError('query parameters are not accepted');
            rejectDuplicateJsonKeys(req.rawJsonBody || '');
            if (!isObject(req.body)) throw new ValidationError('request body must be an object');
            exactKeys(req.body, ['caseIds', 'reason'], 'request body');
            const caseIdsRaw = req.body.caseIds;
            if (!Array.isArray(caseIdsRaw) || caseIdsRaw.length === 0 || caseIdsRaw.length > 100)
                throw new ValidationError('caseIds must be an array of 1 to 100 case IDs');
            const caseIds = caseIdsRaw.map((value, index) => boundedString(value, `caseIds[${index}]`, 64, true));
            if (new Set(caseIds).size !== caseIds.length)
                throw new ValidationError('caseIds must not contain duplicates');
            const runReason = boundedString(req.body.reason, 'reason', 1024) || 'playbook run';
            const playbookId = boundedString(req.params.id, 'id', 64, true);
            const pb = playbooks.findPlaybook(dataDir, playbookId);
            if (!pb) return res.status(404).json({ error: 'playbook not found' });
            const runId = crypto.randomUUID();

            const hostIsolationIp = hostIsolationManagementIp;
            const hostIsolationPorts = hostIsolationAllowedPorts;

            const results = [];
            const missing = [];
            let hasUncertain = false;
            let hasFailed = false;

            for (const caseId of caseIds) {
                const alert = alerts.find(item => alertCaseId(item) === caseId);
                if (!alert) {
                    missing.push(caseId);
                    const auditMissing = {
                        timestamp: new Date().toISOString(),
                        action: 'playbook',
                        playbookId,
                        runId,
                        step: 0,
                        caseId,
                        status: 'not_found',
                        effective_mode: 'dry_run',
                        reason: runReason,
                        requestedBy: sourceIdentity(req.get('x-api-key')),
                    };
                    appendJsonLine(files.audit, auditMissing);
                    hasFailed = true;
                    results.push({ caseId, status: 'not_found', action: 'playbook', step: 0 });
                    break;
                }
                let sawDryRun = false;
                for (let index = 0; index < pb.steps.length; index += 1) {
                    const step = pb.steps[index];
                    const action = step.action;
                    const stepNumber = index + 1;
                    const stepReason = step.reason || runReason;
                    let target;
                    let status = 'unknown';
                    let effectiveMode = 'dry_run';
                    let outcomeDetail = null;
                    let dispatched = false;
                    const stepWouldBeReal = (action === 'terminate' && realTerminationEnabled) ||
                        (action === 'quarantine' && realQuarantineEnabled) ||
                        (action === 'suspend' && realSuspendEnabled) ||
                        (action === 'resume' && realResumeEnabled) ||
                        action === 'isolate' || action === 'unisolate';
                    appendJsonLine(files.audit, {
                        timestamp: new Date().toISOString(), action, playbookId, runId,
                        step: stepNumber, caseId, phase: 'attempt', status: 'planned',
                        requested_mode: stepWouldBeReal ? 'real' : 'dry_run',
                        reason: stepReason,
                        requestedBy: sourceIdentity(req.get('x-api-key')),
                    });
                    try {
                        if (sawDryRun && stepWouldBeReal) {
                            status = 'not_ready';
                            effectiveMode = 'real';
                            outcomeDetail = { error: 'a prior playbook step was dry_run' };
                        } else if (action === 'terminate' || action === 'suspend' || action === 'resume') {
                            const pidRaw = alert.event?.pid ?? alert.event?.ProcessId ?? valueFrom(alert.event || {}, ['pid', 'ProcessId']);
                            const pid = boundedInteger(step.target?.pid ?? pidRaw, 'target.pid');
                            if (pid === undefined || pid === 0 || pid === 4) throw new ValidationError('process target pid missing or protected');
                            if (pidRaw !== undefined && step.target?.pid !== undefined && pid !== boundedInteger(pidRaw, 'alert.pid'))
                                throw new ValidationError('target.pid does not match the alert');
                            const createTimeRaw = step.target?.createTime100ns ?? alert.event?.createTime100ns ?? alert.event?.CreateTime100ns;
                            const createTime100ns = decimalUint64String(createTimeRaw, 'target.createTime100ns', true);
                            const alertCreateTime = alert.event?.createTime100ns ?? alert.event?.CreateTime100ns;
                            if (alertCreateTime !== undefined && step.target?.createTime100ns !== undefined &&
                                createTime100ns !== String(alertCreateTime))
                                throw new ValidationError('target.createTime100ns does not match the alert');
                            target = { pid, createTime100ns };
                            const enableReal = action === 'terminate' ? realTerminationEnabled :
                                action === 'suspend' ? realSuspendEnabled : realResumeEnabled;
                            if (responseFoundationEnabled && responseClient) {
                                try {
                                    const readiness = await responseClient.readiness();
                                    const readinessMode = readiness === true ? 'dry_run' : readiness && readiness.effective_mode;
                                    if (enableReal) {
                                        if ((action === 'terminate' &&
                                            (readiness.effective_mode !== 'real' || readiness.capabilities?.terminate === 'dry_run')) ||
                                            (action !== 'terminate' && readiness.capabilities?.[action] !== 'real')) {
                                            status = 'not_ready';
                                            effectiveMode = 'real';
                                        } else {
                                            assertResponseAuditWritable(readiness);
                                            const result = await responseClient[action]({ reason: stepReason, target });
                                            status = result.status || 'failed';
                                            effectiveMode = result.effective_mode || 'real';
                                            outcomeDetail = result;
                                            if (result.effective_mode !== 'real') {
                                                status = 'outcome_unknown';
                                                effectiveMode = 'real';
                                            }
                                        }
                                    } else {
                                        if (readinessMode !== 'dry_run') {
                                            if (readinessMode === 'real') {
                                                status = 'local_only';
                                                effectiveMode = 'dry_run';
                                            } else {
                                                status = 'native_not_ready';
                                                effectiveMode = 'dry_run';
                                            }
                                        } else {
                                            const result = await responseClient[action]({ reason: stepReason, target });
                                            if (result.effective_mode === 'dry_run' && result.ok !== false) {
                                                status = 'native_dry_run_accepted';
                                                effectiveMode = 'dry_run';
                                                outcomeDetail = result;
                                            } else {
                                                status = 'native_not_ready';
                                                effectiveMode = 'dry_run';
                                            }
                                        }
                                    }
                                } catch (error) {
                                    dispatched = Boolean(error.dispatched);
                                    status = error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE' ? 'audit_failed' :
                                        (dispatched ? 'outcome_unknown' : (enableReal ? 'not_ready' : 'native_unavailable'));
                                    effectiveMode = enableReal ? 'real' : 'dry_run';
                                    outcomeDetail = { error: error.message, dispatched };
                                }
                            } else {
                                if (enableReal) {
                                    status = 'not_ready';
                                    effectiveMode = 'real';
                                } else {
                                    status = 'local_only';
                                    effectiveMode = 'dry_run';
                                }
                            }
                        } else if (action === 'quarantine') {
                            const alertSha = alert.event?.sha256 ?? alert.event?.hash ?? valueFrom(alert.event || {}, ['sha256', 'hash', 'Hashes']);
                            let sha = step.target?.sha256 ?? alertSha;
                            if (Array.isArray(sha)) sha = sha[0];
                            if (typeof sha !== 'string' || !/^[a-f0-9]{64}$/i.test(sha))
                                throw new ValidationError('quarantine requires a SHA-256 digest');
                            const p = step.target?.path ?? alert.event?.file_path ?? alert.event?.path ?? alert.event?.image;
                            if (p === undefined) throw new ValidationError('quarantine requires a file path');
                            const filePath = boundedString(String(p), 'target.path', LIMITS.output, true);
                            target = { path: filePath, sha256: sha.toLowerCase() };
                            const alertPaths = [alert.event?.file_path, alert.event?.path, alert.event?.image]
                                .filter(value => typeof value === 'string' && value);
                            if (step.target?.path && alertPaths.length && !alertPaths.includes(step.target.path))
                                throw new ValidationError('target.path does not match the alert');
                            if (step.target?.sha256 && typeof alertSha === 'string' && /^[a-f0-9]{64}$/i.test(alertSha) &&
                                step.target.sha256.toLowerCase() !== alertSha.toLowerCase())
                                throw new ValidationError('target.sha256 does not match the alert');
                            if (realQuarantineEnabled && responseFoundationEnabled && responseClient) {
                                try {
                                    const readiness = await responseClient.readiness();
                                    if (readiness.capabilities?.quarantine !== 'real') {
                                        status = 'native_not_ready';
                                        effectiveMode = 'real';
                                    } else {
                                        assertResponseAuditWritable(readiness);
                                        const result = await responseClient.quarantine({ reason: stepReason, target });
                                        if (result.effective_mode !== 'real') {
                                            status = 'outcome_unknown';
                                            effectiveMode = 'real';
                                        } else {
                                            status = result.status || (result.ok ? 'quarantined' : 'failed');
                                            effectiveMode = 'real';
                                            outcomeDetail = result;
                                        }
                                    }
                                } catch (error) {
                                    dispatched = Boolean(error.dispatched);
                                    status = error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE' ? 'audit_failed' :
                                        (dispatched ? 'outcome_unknown' : 'native_unavailable');
                                    effectiveMode = 'real';
                                    outcomeDetail = { error: error.message, dispatched };
                                }
                            } else if (realQuarantineEnabled) {
                                status = 'not_ready';
                                effectiveMode = 'real';
                            } else {
                                status = 'local_only';
                                effectiveMode = 'dry_run';
                            }
                        } else if (action === 'isolate' || action === 'unisolate') {
                            const enable = action === 'isolate';
                            if (!hostIsolationEnabled || !responseFoundationEnabled || !responseClient || !hostIsolationIp) {
                                status = 'not_ready';
                                effectiveMode = 'real';
                            } else {
                                try {
                                    const readiness = await responseClient.readiness();
                                    if (readiness.capabilities?.host_isolation !== 'real') {
                                        status = 'native_not_ready';
                                        effectiveMode = 'real';
                                    } else {
                                        assertResponseAuditWritable(readiness);
                                        const method = enable ? 'isolate' : 'unisolate';
                                        const result = await responseClient[method]({ reason: stepReason, managementIp: hostIsolationIp, allowedPorts: hostIsolationPorts });
                                        status = result.status || (result.ok ? (enable ? 'isolated' : 'restored') : 'failed');
                                        effectiveMode = result.effective_mode || 'real';
                                        outcomeDetail = result;
                                    }
                                } catch (error) {
                                    dispatched = Boolean(error.dispatched);
                                    status = error.code === 'EDR_RESPONSE_AUDIT_UNAVAILABLE' ? 'audit_failed' :
                                        (dispatched ? 'outcome_unknown' : 'native_unavailable');
                                    effectiveMode = 'real';
                                    outcomeDetail = { error: error.message, dispatched };
                                }
                            }
                        } else {
                            status = 'not_ready';
                            effectiveMode = 'dry_run';
                        }
                    } catch (error) {
                        if (error instanceof ValidationError) {
                            status = 'target_invalid';
                            outcomeDetail = { error: error.message };
                        } else {
                            dispatched = Boolean(error.dispatched);
                            status = dispatched ? 'outcome_unknown' : 'native_unavailable';
                            outcomeDetail = { error: error.message, dispatched };
                        }
                    }

                    if (status === 'outcome_unknown') hasUncertain = true;

                    const auditEntry = {
                        timestamp: new Date().toISOString(),
                        action,
                        playbookId,
                        runId,
                        step: stepNumber,
                        caseId,
                        phase: 'outcome',
                        status,
                        effective_mode: effectiveMode,
                        reason: stepReason,
                        target: target || undefined,
                        requestedBy: sourceIdentity(req.get('x-api-key')),
                        outcome_unknown: status === 'outcome_unknown',
                    };
                    if (outcomeDetail && typeof outcomeDetail === 'object') {
                        if (outcomeDetail.win32_error !== undefined) auditEntry.win32_error = outcomeDetail.win32_error;
                        if (outcomeDetail.requestId) auditEntry.requestId = outcomeDetail.requestId;
                        if (outcomeDetail.error) auditEntry.error = outcomeDetail.error;
                    }
                    try { appendJsonLine(files.audit, auditEntry); }
                    catch (error) {
                        logger.error('[edr-console] playbook outcome audit failed', error.message);
                        hasUncertain = true;
                        return res.status(503).json({ ok: false, playbookId, runId,
                            overall: 'outcome_unknown', hasUncertain: true, missing, steps: results });
                    }

                    results.push({
                        caseId,
                        runId,
                        step: stepNumber,
                        action,
                        status,
                        effective_mode: effectiveMode,
                        target,
                        reason: stepReason,
                        outcome_unknown: status === 'outcome_unknown',
                        detail: outcomeDetail,
                    });
                    if (!playbooks.stepSucceeded(action, status, effectiveMode) || outcomeDetail?.ok === false) {
                        hasFailed = true;
                        break;
                    }
                    if (effectiveMode === 'dry_run') sawDryRun = true;
                }
                if (hasFailed || hasUncertain) break;
            }

            const overall = hasUncertain ? 'outcome_unknown' :
                (hasFailed ? (missing.length && results.length === missing.length ? 'not_found' : 'failed') : 'success');
            return res.status(hasUncertain ? 503 : 200).json({ ok: !hasFailed && !hasUncertain,
                playbookId, runId, overall, hasUncertain, missing, steps: results });
        } catch (error) { return next(error); }
    });

    /* Export alerts as CSV */
    app.get('/api/export/alerts', auth('read'), (req, res, next) => {
        try {
            const severity = boundedString(req.query.severity, 'severity', 32);
            const status = req.query.status ? boundedString(req.query.status, 'status', 32) : undefined;
            const assignee = boundedString(req.query.assignee, 'assignee', 256);
            const priority = boundedString(req.query.priority, 'priority', 32);
            const rule = boundedString(req.query.rule, 'rule', 256);
            const since = boundedString(req.query.since, 'since', 64);
            const until = boundedString(req.query.until, 'until', 64);
            if (status && !TRIAGE_STATUSES.has(status)) throw new ValidationError('status is not supported');
            if (priority && !TRIAGE_PRIORITIES.has(priority)) throw new ValidationError('priority is not supported');
            if (since && !Number.isFinite(Date.parse(since))) throw new ValidationError('since must be an ISO-8601 timestamp');
            if (until && !Number.isFinite(Date.parse(until))) throw new ValidationError('until must be an ISO-8601 timestamp');
            let filtered = alerts;
            if (severity) filtered = filtered.filter(alert => alert.severity === severity);
            if (status) filtered = filtered.filter(alert => triageState(alert).status === status);
            if (assignee) filtered = filtered.filter(alert => triageState(alert).assignee === assignee);
            if (priority) filtered = filtered.filter(alert => triageState(alert).priority === priority);
            if (rule) filtered = filtered.filter(alert => alert.rule === rule);
            if (since) {
                const sinceMillis = Date.parse(since);
                filtered = filtered.filter(alert => Date.parse(alert.timestamp) >= sinceMillis);
            }
            if (until) {
                const untilMillis = Date.parse(until);
                filtered = filtered.filter(alert => Date.parse(alert.timestamp) <= untilMillis);
            }
            const columns = ['timestamp', 'rule', 'severity', 'status', 'priority', 'assignee', 'type', 'sourceId', 'mitre_tactics', 'mitre_techniques', 'summary'];
            const rows = filtered.slice(-LIMITS.queryLimit).map(alert => {
                const event = alert.event || {};
                const triage = triageState(alert);
                const summary = event.image || event.command_line || event.output || event.file_path || event.reg_key || event.pipe_name || '';
                return [
                    alert.timestamp || '',
                    alert.rule || '',
                    alert.severity || '',
                    triage.status || 'new',
                    triage.priority || 'normal',
                    triage.assignee || '',
                    event.type || '',
                    alert.sourceId || '',
                    (mitreTactics(alert) || []).join('; '),
                    (mitreTechniques(alert) || []).join('; '),
                    summary,
                ].map(value => `"${String(value).replace(/"/g, '""')}"`);
            });
            const csv = '\uFEFF' + columns.join(',') + '\n' + rows.map(row => row.join(',')).join('\n');
            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader('Content-Disposition', 'attachment; filename="edr_alerts_export.csv"');
            res.send(csv);
        } catch (error) { next(error); }
    });

    /* Export events as CSV */
    app.get('/api/export/events', auth('read'), (req, res, next) => {
        try {
            const type = boundedString(req.query.type, 'type', 128);
            const sourceId = boundedString(req.query.sourceId, 'sourceId', 256);
            const processKey = boundedString(req.query.processKey, 'processKey', 1024);
            const pid = boundedInteger(req.query.pid, 'pid');
            const query = (boundedString(req.query.q, 'q', 256) || '').toLowerCase();
            const since = req.query.since === undefined ? undefined : boundedTimestamp(req.query.since, 'since', true);
            const until = req.query.until === undefined ? undefined : boundedTimestamp(req.query.until, 'until', true);
            if (since && until && since > until) throw new ValidationError('since must not be after until');
            let filtered = events;
            if (type) filtered = filtered.filter(event => event.type === type);
            if (sourceId) filtered = filtered.filter(event => event.sourceId === sourceId);
            if (processKey) filtered = filtered.filter(event => event.processKey === processKey);
            if (pid !== undefined) {
                filtered = filtered.filter(event => {
                    const raw = event.raw || {};
                    return Number(valueFrom(raw, ['pid', 'ProcessId'])) === pid;
                });
            }
            if (since) filtered = filtered.filter(event => event.timestamp >= since);
            if (until) filtered = filtered.filter(event => event.timestamp <= until);
            if (query) filtered = filtered.filter(event => eventMatchesQuery(event, query));
            const columns = ['timestamp', 'eventId', 'type', 'sourceId', 'processKey', 'summary'];
            const rows = filtered.slice(-LIMITS.queryLimit).map(event => [
                event.timestamp || '',
                event.eventId || '',
                event.type || '',
                event.sourceId || '',
                event.processKey || '',
                eventSummary(event),
            ].map(value => `"${String(value).replace(/"/g, '""')}"`));
            const csv = '\uFEFF' + columns.join(',') + '\n' + rows.map(row => row.join(',')).join('\n');
            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader('Content-Disposition', 'attachment; filename="edr_events_export.csv"');
            res.send(csv);
        } catch (error) { next(error); }
    });

    /* Rules listing with statistics */
    app.get('/api/rules', auth('read'), (req, res) => {
        const q = boundedString(req.query.q, 'q', 256);
        const severity = boundedString(req.query.severity, 'severity', 32);
        const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 100, 1), LIMITS.queryLimit);
        const offset = Math.max(Number.parseInt(req.query.offset, 10) || 0, 0);
        const ruleMap = new Map();
        for (const alert of alerts) {
            const rule = alert.rule || 'unknown';
            if (!ruleMap.has(rule)) {
                ruleMap.set(rule, {
                    rule,
                    count: 0,
                    bySeverity: {},
                    byStatus: {},
                    byPriority: {},
                    bySource: {},
                    firstSeen: null,
                    lastSeen: null,
                    actions: new Set(),
                    mitreAttack: new Set(),
                    mitreTactic: new Set(),
                });
            }
            const entry = ruleMap.get(rule);
            entry.count += 1;
            entry.bySeverity[alert.severity] = (entry.bySeverity[alert.severity] || 0) + 1;
            const status = triageState(alert).status;
            entry.byStatus[status] = (entry.byStatus[status] || 0) + 1;
            const priority = triageState(alert).priority;
            entry.byPriority[priority] = (entry.byPriority[priority] || 0) + 1;
            const sourceId = alert.sourceId || 'unknown';
            entry.bySource[sourceId] = (entry.bySource[sourceId] || 0) + 1;
            if (alert.action) entry.actions.add(alert.action);
            for (const technique of mitreTechniques(alert)) entry.mitreAttack.add(technique);
            for (const tactic of mitreTactics(alert)) entry.mitreTactic.add(tactic);
            if (alert.timestamp) {
                if (!entry.firstSeen || alert.timestamp < entry.firstSeen) entry.firstSeen = alert.timestamp;
                if (!entry.lastSeen || alert.timestamp > entry.lastSeen) entry.lastSeen = alert.timestamp;
            }
        }
        let rules = [...ruleMap.values()].map(entry => ({
            rule: entry.rule,
            count: entry.count,
            bySeverity: entry.bySeverity,
            byStatus: entry.byStatus,
            byPriority: entry.byPriority,
            bySource: entry.bySource,
            firstSeen: entry.firstSeen,
            lastSeen: entry.lastSeen,
            actions: [...entry.actions].sort(),
            mitreAttack: [...entry.mitreAttack].sort(),
            mitreTactic: [...entry.mitreTactic].sort(),
            endpointCount: Object.keys(entry.bySource).length,
            openCount: (entry.byStatus.new || 0) + (entry.byStatus.investigating || 0),
        })).sort((a, b) => b.count - a.count || String(a.rule).localeCompare(String(b.rule)));
        if (q) {
            const needle = q.toLowerCase();
            rules = rules.filter(entry => entry.rule.toLowerCase().includes(needle) ||
                entry.mitreAttack.some(t => t.toLowerCase().includes(needle)) ||
                entry.mitreTactic.some(t => t.toLowerCase().includes(needle)));
        }
        if (severity) {
            rules = rules.filter(entry => entry.bySeverity[severity] > 0);
        }
        const total = rules.length;
        const page = rules.slice(offset, offset + limit);
        res.json({ total, rules: page });
    });

    /* System status */
    app.get('/api/system/status', auth('read'), (_req, res) => {
        const now = Date.now();
        const inventory = endpointInventory();
        const activeEndpoints = inventory.filter(e => e.telemetryState === 'recent').length;
        const staleEndpoints = inventory.filter(e => e.telemetryState === 'stale').length;
        const inactiveEndpoints = inventory.filter(e => e.telemetryState === 'inactive').length;
        const unknownEndpoints = inventory.filter(e => e.telemetryState === 'unknown').length;
        const openAlerts = alerts.filter(a => {
            const status = triageState(a).status;
            return status !== 'resolved' && status !== 'false_positive';
        }).length;
        const alertRate = alerts.length > 0 && alerts.length > 1 ? (() => {
            const sorted = [...alerts].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
            const first = Date.parse(sorted[0].timestamp);
            const last = Date.parse(sorted[sorted.length - 1].timestamp);
            const hours = (last - first) / (1000 * 60 * 60);
            return hours > 0 ? (alerts.length / hours).toFixed(1) : 'N/A';
        })() : 'N/A';
        const topRules = (() => {
            const counts = {};
            for (const alert of alerts) {
                counts[alert.rule] = (counts[alert.rule] || 0) + 1;
            }
            return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([rule, count]) => ({ rule, count }));
        })();
        const lastIngest = events.length > 0 ? events[events.length - 1].timestamp : 'N/A';
        res.json({
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            endpoints: { total: inventory.length, active: activeEndpoints, stale: staleEndpoints, inactive: inactiveEndpoints, unknown: unknownEndpoints },
            alerts: { total: alerts.length, open: openAlerts, rate: alertRate },
            events: { total: events.length, lastIngest },
            processes: processes.size,
            topRules,
            connectedClients: wsClients.size,
            lastGc: global.gc ? 'available' : 'not_available',
        });
    });

    /* Liveness probe (unauthenticated, for orchestration/monitoring). */
    app.get('/api/health', (_req, res) => {
        res.json({
            status: 'ok',
            uptime: process.uptime(),
            timestamp: new Date().toISOString(),
            alerts: alerts.length,
            events: events.length,
        });
    });

    /* MITRE ATT&CK statistics */
    app.get('/api/stats/mitre', auth('read'), (_req, res) => {
        const tactics = {};
        const techniques = {};
        for (const alert of alerts) {
            const alertTactics = mitreTactics(alert);
            const alertTechniques = mitreTechniques(alert);
            for (const tactic of alertTactics) {
                tactics[tactic] = (tactics[tactic] || 0) + 1;
            }
            for (const technique of alertTechniques) {
                techniques[technique] = (techniques[technique] || 0) + 1;
            }
        }
        res.json({
            tactics: Object.entries(tactics).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count })),
            techniques: Object.entries(techniques).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count })),
        });
    });

    /* ATT&CK coverage report over the rule CATALOG (rules.json), joined
     * with fired rules from the alert store. Unlike /api/stats/mitre this
     * answers "which of my deployed detections have ever fired and which
     * reference techniques have no rule at all". */
    let coverageCache = null; /* { mtimeMs, size, sha256, doc } */
    app.get('/api/rules/coverage', auth('read'), (req, res, next) => {
        try {
            exactKeys(req.query, ['severity', 'tactic', 'since', 'format'], 'query');
            const severity = boundedString(req.query.severity, 'severity', 32);
            const tactic = boundedString(req.query.tactic, 'tactic', 64);
            const sinceRaw = boundedString(req.query.since, 'since', 64);
            const format = boundedString(req.query.format, 'format', 32);
            if (format && format !== 'csv') throw new ValidationError('format must be csv');
            let sinceMillis = null;
            if (sinceRaw) {
                const parsed = Date.parse(sinceRaw);
                if (!Number.isFinite(parsed)) throw new ValidationError('since must be an ISO-8601 timestamp');
                sinceMillis = parsed;
            }
            if (!files.rulesCatalog)
                return res.status(503).json({ error: 'rule catalog unavailable (set EDR_RULES_PATH)' });
            let stat;
            try { stat = fs.statSync(files.rulesCatalog); } catch (_) {
                return res.status(503).json({ error: 'rule catalog unreadable' });
            }
            // mtime granularity trap: some filesystems report mtime at 1s (FAT) or reduced
            // resolution; two rapid rewrites within the same tick can keep mtimeMs+size
            // identical while content differs and would falsely hit cache. File is small
            // (403 rules, ~hundreds KB), re-reading and sha256 hashing per request is cheap
            // and guarantees correctness beyond mtime/size.
            const raw = fs.readFileSync(files.rulesCatalog, 'utf8');
            const sha256 = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
            if (!coverageCache || coverageCache.mtimeMs !== stat.mtimeMs ||
                coverageCache.size !== stat.size || coverageCache.sha256 !== sha256) {
                try {
                    const doc = JSON.parse(raw);
                    coverageCache = { mtimeMs: stat.mtimeMs, size: stat.size, sha256, doc };
                } catch (_) {
                    return res.status(503).json({ error: 'rule catalog is not valid JSON' });
                }
            }
            let catalogRules = Array.isArray(coverageCache.doc?.rules)
                ? coverageCache.doc.rules.filter(isObject) : [];
            // severity/tactic filters act on catalog side (operator slice of deployed rules)
            if (severity) {
                catalogRules = catalogRules.filter(rule => rule.severity === severity);
            }
            if (tactic) {
                catalogRules = catalogRules.filter(rule => Array.isArray(rule.mitre_tactic) && rule.mitre_tactic.includes(tactic));
            }
            const catalogIds = catalogRules
                .map(rule => (typeof rule.id === 'string' ? rule.id : null))
                .filter(Boolean);
            const catalogIdSet = new Set(catalogIds);
            // since filters the fired set by alert timestamp (alerts side)
            let effectiveAlerts = alerts;
            if (sinceMillis !== null) {
                effectiveAlerts = alerts.filter(alert => {
                    const ms = Date.parse(alert.timestamp);
                    return Number.isFinite(ms) && ms >= sinceMillis;
                });
            }
            const firedCatalogIds = new Set(
                effectiveAlerts.map(alert => alert.rule).filter(rule => catalogIdSet.has(rule)));

            const bySeverity = {};
            const tacticsMap = new Map(); /* tactic -> Map(technique -> [ruleId]) */
            const knownTechniques = new Set();
            const unmappedRules = [];
            for (const rule of catalogRules) {
                if (typeof rule.id !== 'string') continue;
                const severityValue = typeof rule.severity === 'string' ? rule.severity : 'unknown';
                bySeverity[severityValue] = (bySeverity[severityValue] || 0) + 1;
                const attack = Array.isArray(rule.mitre_attack)
                    ? rule.mitre_attack.filter(t => typeof t === 'string') : [];
                const tacticList = Array.isArray(rule.mitre_tactic)
                    ? rule.mitre_tactic.filter(t => typeof t === 'string') : [];
                if (!attack.length && !tacticList.length) {
                    unmappedRules.push(rule.id);
                    continue;
                }
                for (const technique of attack) knownTechniques.add(technique);
                const tacticsForRule = tacticList.length ? tacticList : ['Unmapped'];
                const techniquesForRule = attack.length ? attack : ['(tactic-level only)'];
                for (const tac of tacticsForRule) {
                    if (!tacticsMap.has(tac)) tacticsMap.set(tac, new Map());
                    const techniqueMap = tacticsMap.get(tac);
                    for (const technique of techniquesForRule) {
                        if (!techniqueMap.has(technique)) techniqueMap.set(technique, []);
                        techniqueMap.get(technique).push(rule.id);
                    }
                }
            }
            const neverFired = catalogIds.filter(id => !firedCatalogIds.has(id));
            const referenceGaps = REFERENCE_TECHNIQUES
                .filter(technique => !knownTechniques.has(technique));
            // Build technique -> ruleIds for suggestion export (reuses coverage aggregation)
            const techniqueToRuleIds = new Map();
            for (const rule of catalogRules) {
                const attack = Array.isArray(rule.mitre_attack) ? rule.mitre_attack.filter(t => typeof t === 'string') : [];
                for (const technique of attack) {
                    if (!techniqueToRuleIds.has(technique)) techniqueToRuleIds.set(technique, []);
                    techniqueToRuleIds.get(technique).push(rule.id);
                }
            }
            const gapsWithSuggestion = referenceGaps.map(technique => {
                const mapping = TECHNIQUE_CONFIG_MAP[technique] || { configKey: null, detector: null };
                return {
                    technique,
                    configKey: mapping.configKey,
                    detector: mapping.detector,
                    ruleIds: techniqueToRuleIds.get(technique) || [],
                };
            });
            if (format === 'csv') {
                // Reuse export route BOM+LIMITS style: BOM for Excel, quoted CSV, LIMITS.queryLimit cap
                const columns = ['type', 'value'];
                const combined = [
                    ...neverFired.map(id => ['neverFired', id]),
                    ...referenceGaps.map(t => ['referenceGap', t]),
                ];
                const limited = combined.slice(0, LIMITS.queryLimit);
                const rows = limited.map(row => row.map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));
                const csv = '\uFEFF' + columns.join(',') + '\n' + rows.join('\n');
                res.setHeader('Content-Type', 'text/csv; charset=utf-8');
                res.setHeader('Content-Disposition', 'attachment; filename="coverage_export.csv"');
                return res.send(csv);
            }
            res.json({
                rulesFile: path.basename(files.rulesCatalog),
                totalRules: catalogIds.length,
                bySeverity,
                firedRules: [...firedCatalogIds].sort(),
                neverFired,
                coveragePct: catalogIds.length
                    ? Math.round((firedCatalogIds.size / catalogIds.length) * 1000) / 10
                    : 0,
                tactics: [...tacticsMap.entries()]
                    .sort((a, b) => String(a[0]).localeCompare(String(b[0])))
                    .map(([tac, techniqueMap]) => ({
                        tactic: tac,
                        ruleCount: [...techniqueMap.values()].flat().length,
                        techniques: [...techniqueMap.entries()]
                            .sort((a, b) => String(a[0]).localeCompare(String(b[0])))
                            .map(([technique, ruleIds]) => ({ technique, ruleIds })),
                    })),
                unmappedRules: unmappedRules.sort(),
                referenceGaps,
                gapsWithSuggestion,
            });
        } catch (error) { return next(error); }
    });

    /* Coverage gaps export: actionable blind-spot list (read-only). */
    app.get('/api/rules/coverage/gaps/export', auth('read'), (req, res, next) => {
        try {
            exactKeys(req.query, ['format', 'severity', 'tactic', 'since'], 'query');
            const format = boundedString(req.query.format, 'format', 32);
            const severity = boundedString(req.query.severity, 'severity', 32);
            const tactic = boundedString(req.query.tactic, 'tactic', 64);
            const sinceRaw = boundedString(req.query.since, 'since', 64);
            if (format && format !== 'json' && format !== 'csv') throw new ValidationError('format must be json or csv');
            const effectiveFormat = format || 'json';
            let sinceMillis = null;
            if (sinceRaw) {
                const parsed = Date.parse(sinceRaw);
                if (!Number.isFinite(parsed)) throw new ValidationError('since must be an ISO-8601 timestamp');
                sinceMillis = parsed;
            }
            if (!files.rulesCatalog)
                return res.status(503).json({ error: 'rule catalog unavailable (set EDR_RULES_PATH)' });
            let stat;
            try { stat = fs.statSync(files.rulesCatalog); } catch (_) {
                return res.status(503).json({ error: 'rule catalog unreadable' });
            }
            const raw = fs.readFileSync(files.rulesCatalog, 'utf8');
            const sha256 = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
            if (!coverageCache || coverageCache.mtimeMs !== stat.mtimeMs ||
                coverageCache.size !== stat.size || coverageCache.sha256 !== sha256) {
                try {
                    const doc = JSON.parse(raw);
                    coverageCache = { mtimeMs: stat.mtimeMs, size: stat.size, sha256, doc };
                } catch (_) {
                    return res.status(503).json({ error: 'rule catalog is not valid JSON' });
                }
            }
            let catalogRules = Array.isArray(coverageCache.doc?.rules)
                ? coverageCache.doc.rules.filter(isObject) : [];
            if (severity) {
                catalogRules = catalogRules.filter(rule => rule.severity === severity);
            }
            if (tactic) {
                catalogRules = catalogRules.filter(rule => Array.isArray(rule.mitre_tactic) && rule.mitre_tactic.includes(tactic));
            }
            const catalogIds = catalogRules.map(rule => (typeof rule.id === 'string' ? rule.id : null)).filter(Boolean);
            const catalogIdSet = new Set(catalogIds);
            let effectiveAlerts = alerts;
            if (sinceMillis !== null) {
                effectiveAlerts = alerts.filter(alert => {
                    const ms = Date.parse(alert.timestamp);
                    return Number.isFinite(ms) && ms >= sinceMillis;
                });
            }
            const firedCatalogIds = new Set(
                effectiveAlerts.map(alert => alert.rule).filter(rule => catalogIdSet.has(rule)));
            const knownTechniques = new Set();
            for (const rule of catalogRules) {
                const attack = Array.isArray(rule.mitre_attack) ? rule.mitre_attack.filter(t => typeof t === 'string') : [];
                for (const technique of attack) knownTechniques.add(technique);
            }
            const referenceGaps = REFERENCE_TECHNIQUES.filter(technique => !knownTechniques.has(technique));
            const neverFired = catalogIds.filter(id => !firedCatalogIds.has(id));
            const techniqueToRuleIds = new Map();
            for (const rule of catalogRules) {
                const attack = Array.isArray(rule.mitre_attack) ? rule.mitre_attack.filter(t => typeof t === 'string') : [];
                for (const technique of attack) {
                    if (!techniqueToRuleIds.has(technique)) techniqueToRuleIds.set(technique, []);
                    techniqueToRuleIds.get(technique).push(rule.id);
                }
            }
            // Gap items reuse referenceGaps + neverFired aggregation concept:
            // primary source is referenceGaps (technique blind spots); ruleIds are catalog rules covering that technique.
            const gaps = referenceGaps.map(technique => {
                const mapping = TECHNIQUE_CONFIG_MAP[technique] || { configKey: null, detector: null };
                return {
                    technique,
                    configKey: mapping.configKey,
                    detector: mapping.detector,
                    ruleIds: techniqueToRuleIds.get(technique) || [],
                };
            });
            // Also expose neverFired rule-centric gaps as additional rows for completeness (technique derived from rule)
            // but keep export stable: sorted by technique, limited by LIMITS.queryLimit
            const limited = gaps.slice(0, LIMITS.queryLimit);
            if (effectiveFormat === 'csv') {
                const columns = ['technique', 'configKey', 'detector', 'ruleIds'];
                const rows = limited.map(item => [
                    item.technique || '',
                    item.configKey || '',
                    item.detector || '',
                    (item.ruleIds || []).join(';'),
                ].map(value => `"${String(value).replace(/"/g, '""')}"`).join(','));
                const csv = '\uFEFF' + columns.join(',') + '\n' + rows.join('\n');
                res.setHeader('Content-Type', 'text/csv; charset=utf-8');
                res.setHeader('Content-Disposition', 'attachment; filename="gaps_export.csv"');
                return res.send(csv);
            }
            return res.json({ gaps: limited, total: gaps.length, referenceGaps, neverFired });
        } catch (error) { return next(error); }
    });

    /* Evidence browsing — read-only, never triggers response actions. */
    app.get('/api/evidence', auth('read'), (req, res, next) => {
        try {
            exactKeys(req.query, ['requestId', 'rule', 'severity', 'since', 'until', 'limit', 'offset'], 'query');
            const requestIdFilter = boundedString(req.query.requestId, 'requestId', 256);
            const ruleFilter = boundedString(req.query.rule, 'rule', 256);
            const severityFilter = boundedString(req.query.severity, 'severity', 32);
            const sinceRaw = boundedString(req.query.since, 'since', 64);
            const untilRaw = boundedString(req.query.until, 'until', 64);
            if (sinceRaw && !Number.isFinite(Date.parse(sinceRaw))) throw new ValidationError('since must be an ISO-8601 timestamp');
            if (untilRaw && !Number.isFinite(Date.parse(untilRaw))) throw new ValidationError('until must be an ISO-8601 timestamp');
            const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 100, 1), LIMITS.queryLimit);
            const offset = Math.max(Number.parseInt(req.query.offset, 10) || 0, 0);
            const dedup = new Map();
            for (const alert of alerts) {
                const requestId = parseEvidenceRequestId(alert);
                if (!requestId) continue;
                if (dedup.has(requestId)) continue;
                dedup.set(requestId, {
                    requestId,
                    rule: alert.rule || '',
                    severity: alert.severity || '',
                    timestamp: alert.timestamp || '',
                });
            }
            try {
                if (fs.existsSync(evidenceDir)) {
                    const entries = fs.readdirSync(evidenceDir, { withFileTypes: true });
                    for (const entry of entries) {
                        if (!entry.isDirectory()) continue;
                        const name = entry.name.toLowerCase();
                        if (!REQUEST_ID_RE.test(name)) continue;
                        if (dedup.has(name)) continue;
                        let rule = '';
                        let severity = '';
                        let timestamp = '';
                        try {
                            const target = evidenceFilePathWithinBase(evidenceDir, name, 'manifest.json');
                            if (fs.existsSync(target)) {
                                const lstat = fs.lstatSync(target);
                                if (!lstat.isSymbolicLink() && lstat.isFile() && lstat.size <= EVIDENCE_MAX_BYTES) {
                                    const raw = fs.readFileSync(target, 'utf8');
                                    const doc = JSON.parse(raw);
                                    if (doc && doc.schema === 'edr.snapshot.manifest.v1') {
                                        if (typeof doc.ruleId === 'string') rule = doc.ruleId;
                                        if (typeof doc.severity === 'string') severity = doc.severity;
                                        if (typeof doc.generatedAt === 'string') timestamp = doc.generatedAt;
                                    }
                                }
                            }
                        } catch (_) {}
                        dedup.set(name, { requestId: name, rule, severity, timestamp });
                    }
                }
            } catch (_) {}
            let evidence = [...dedup.values()].sort((left, right) =>
                String(right.timestamp || '').localeCompare(String(left.timestamp || '')));
            if (requestIdFilter) {
                const needle = requestIdFilter.toLowerCase();
                evidence = evidence.filter(item => String(item.requestId || '').toLowerCase().includes(needle));
            }
            if (ruleFilter) {
                const needle = ruleFilter.toLowerCase();
                evidence = evidence.filter(item => String(item.rule || '').toLowerCase().includes(needle));
            }
            if (severityFilter) evidence = evidence.filter(item => item.severity === severityFilter);
            if (sinceRaw) {
                const sinceMillis = Date.parse(sinceRaw);
                evidence = evidence.filter(item => Number.isFinite(Date.parse(item.timestamp || '')) && Date.parse(item.timestamp) >= sinceMillis);
            }
            if (untilRaw) {
                const untilMillis = Date.parse(untilRaw);
                evidence = evidence.filter(item => Number.isFinite(Date.parse(item.timestamp || '')) && Date.parse(item.timestamp) <= untilMillis);
            }
            const total = evidence.length;
            const paged = evidence.slice(offset, offset + limit);
            return res.json({ total, limit, offset, evidence: paged });
        } catch (error) { return next(error); }
    });

    app.get('/api/evidence/:requestId/manifest', auth('read'), (req, res, next) => {
        try {
            exactKeys(req.query, [], 'query');
            const requestId = validateRequestIdParam(req.params.requestId);
            const manifestPath = evidenceFilePathWithinBase(evidenceDir, requestId, 'manifest.json');
            let stat;
            try { stat = fs.lstatSync(manifestPath); } catch (_) {
                return res.status(404).json({ error: 'evidence not found' });
            }
            if (stat.isSymbolicLink()) return res.status(400).json({ error: 'symbolic link is not allowed' });
            if (!stat.isFile()) return res.status(404).json({ error: 'evidence not found' });
            if (stat.size > EVIDENCE_MAX_BYTES) return res.status(413).json({ error: 'file exceeds 8MB limit' });
            const raw = fs.readFileSync(manifestPath, 'utf8');
            let doc;
            try { doc = JSON.parse(raw); } catch (_) {
                return res.status(500).json({ error: 'manifest is not valid JSON' });
            }
            if (!doc || doc.schema !== 'edr.snapshot.manifest.v1') {
                return res.status(500).json({ error: 'manifest schema mismatch' });
            }
            return res.json(doc);
        } catch (error) { return next(error); }
    });

    app.get('/api/evidence/:requestId/file', auth('read'), (req, res, next) => {
        try {
            const requestId = validateRequestIdParam(req.params.requestId);
            exactKeys(req.query, ['file'], 'query');
            const fileName = boundedString(req.query.file, 'file', 64, true);
            if (!evidenceAllowedFile(fileName)) throw new ValidationError('file must be one of snapshot.txt, process_tree.json, alert.json, response.json, manifest.json');
            const filePath = evidenceFilePathWithinBase(evidenceDir, requestId, fileName);
            let stat;
            try { stat = fs.lstatSync(filePath); } catch (_) {
                return res.status(404).json({ error: 'evidence not found' });
            }
            if (stat.isSymbolicLink()) return res.status(400).json({ error: 'symbolic link is not allowed' });
            if (!stat.isFile()) return res.status(404).json({ error: 'evidence not found' });
            if (stat.size > EVIDENCE_MAX_BYTES) return res.status(413).json({ error: 'file exceeds 8MB limit' });
            const data = fs.readFileSync(filePath);
            const contentType = fileName.endsWith('.json') ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8';
            res.setHeader('Content-Type', contentType);
            res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
            res.setHeader('Content-Length', String(stat.size));
            return res.send(data);
        } catch (error) { return next(error); }
    });

    /* Threat Intelligence lookup */
    const threatIntelApiKey = env.EDR_THREAT_INTEL_API_KEY || '';
    app.get('/api/threat-intel/lookup', auth('read'), async (req, res, next) => {
        try {
            const hash = boundedString(req.query.hash, 'hash', 64);
            const ip = boundedString(req.query.ip, 'ip', 45);
            const domain = boundedString(req.query.domain, 'domain', 253);
            let type, value;
            if (hash) { type = 'hash'; value = hash; }
            else if (ip) { type = 'ip'; value = ip; }
            else if (domain) { type = 'domain'; value = domain; }
            else throw new ValidationError('Provide one of: hash, ip, or domain as query parameter');
            const result = await lookupThreatIntel(type, value, threatIntelApiKey);
            res.json(result);
        } catch (error) { next(error); }
    });

    app.get('/api/threat-intel/cache-stats', auth('read'), (_req, res) => {
        cleanThreatIntelCache();
        const entries = [];
        for (const [key, entry] of threatIntelCache) {
            entries.push({ key, ...entry.data, cached_at: new Date(entry.timestamp).toISOString() });
        }
        res.json({ total: threatIntelCache.size, entries: entries.slice(-100).reverse() });
    });

    app.use((error, _req, res, _next) => {
        if (error instanceof ValidationError) return res.status(400).json({ error: error.message });
        if (error instanceof LedgerQueryBusyError) {
            return res.status(503).set('Retry-After', '1').json({
                error: 'ledger query capacity is busy', code: 'ledger_query_busy',
            });
        }
        if (error && (error.type === 'entity.too.large' || error.type === 'entity.parse.failed')) {
            return res.status(400).json({ error: 'invalid or oversized JSON body' });
        }
        logger.error('[edr-console] request failed', error);
        return res.status(500).json({ error: 'internal error' });
    });

    const server = deploymentSecurity.usesHttps
        ? https.createServer(deploymentSecurity.tlsOptions, app)
        : http.createServer(app);
    try {
        const { WebSocketServer } = require('ws');
        const wss = new WebSocketServer({ noServer: true });
        server.on('upgrade', (req, socket, head) => {
            const url = new URL(req.url, 'http://localhost');
            if (url.pathname !== '/ws' || url.search) return socket.destroy();
            wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws));
        });
        wss.on('connection', ws => {
            // Protocol errors can arrive before the authentication message.
            ws.on('error', () => ws.terminate());
            let authenticated = false;
            const timer = setTimeout(() => ws.close(1008, 'authentication required'), 5000);
            ws.once('message', data => {
                try {
                    const message = JSON.parse(data.toString());
                    const expected = keys.read;
                    if (!isObject(message) || message.type !== 'auth' || (expected && !safeEqual(message.apiKey, expected))) {
                        return ws.close(1008, 'unauthorized');
                    }
                    authenticated = true;
                    clearTimeout(timer);
                    wsClients.add(ws);
                    ws.send(JSON.stringify({ type: 'auth', ok: true }));
                } catch (_) { ws.close(1008, 'unauthorized'); }
            });
            ws.on('close', () => { clearTimeout(timer); if (authenticated) wsClients.delete(ws); });
        });
    } catch (_) {
        logger.warn('[edr-console] WebSocket unavailable');
    }

    function start(port = Number.parseInt(env.PORT, 10) || 8080, host = env.EDR_BIND_HOST || '127.0.0.1') {
        try {
            assertBindAllowed(deploymentSecurity, keys, host);
        } catch (error) {
            return Promise.reject(error);
        }
        return new Promise((resolve, reject) => {
            server.once('error', reject);
            server.listen(port, host, () => {
                server.removeListener('error', reject);
                const protocol = deploymentSecurity.usesHttps ? 'https' : 'http';
                logger.log(`[edr-console] listening on ${protocol}://${host}:${server.address().port}`);
                resolve(server);
            });
        });
    }

    return { app, server, start, state: { get alerts() { return alerts; }, get events() { return events; }, processes }, files };
}

if (require.main === module) {
    const runtime = createRuntime();
    runtime.start().catch(error => {
        console.error('[edr-console] failed to start', error);
        process.exitCode = 1;
    });
}

module.exports = {
    LIMITS,
    ValidationError,
    createRuntime,
    normalizeFalcoAlert,
    normalizeNativeAlert,
    normalizeRawEvent,
    readJsonLinesTail,
    readJsonLinesTailAsync,
    safeEqual,
};
