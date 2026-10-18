'use strict';

/**
 * Incident store reader for the Web console.
 *
 * The native agent's correlation engine folds alerts into incidents and
 * appends one JSON record per state change to `incidents.jsonl`:
 *   {"kind":"open",     ...incident...}   first sighting of a chain
 *   {"kind":"incident", ...incident...}   the incident closed / rolled up
 *
 * Replaying the file in order and keeping the last record per incident id
 * rebuilds the current state of every chain without the agent needing to
 * expose an in-memory index. This module owns that replay plus the derived
 * kill-chain graph the UI renders.
 *
 * Records are produced by the native agent, but this file never trusts them:
 * every field is coerced and bounded before it reaches a response, because a
 * corrupted or hand-edited incidents.jsonl must not be able to inject
 * arbitrary content into the console.
 */

const fs = require('fs');
const { verifyChain, verifyFileStream } = require('./audit_chain');
const { resolveWithinBase } = require('./path_guard');

/* Mirrors LIMITS.queryLimit in server.js; kept local so this module has no
 * dependency on the server and stays unit-testable. */
const MAX_INCIDENTS = 1000;
const MAX_RECORDS_SCANNED = 200000;
const MAX_INCIDENT_FILE_BYTES = 256 * 1024 * 1024;
const MAX_INCIDENT_RECORD_BYTES = 64 * 1024;
const MAX_INCIDENT_STATES = 50000;
const MAX_STAGES = 32;
const MAX_LIST = 64;
const FIELD_MAX = 512;
const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });
function sameFile(left, right) {
    return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
        left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

/* The compatibility sync reader deliberately does not retain a whole-file
 * cache. Production routes use loadIncidentsAsync below. */
function readSnapshot(file) {
    let descriptor;
    try {
        descriptor = fs.openSync(file, 'r');
        const before = fs.fstatSync(descriptor, { bigint: true });
        const text = fs.readFileSync(descriptor, 'utf8');
        const after = fs.fstatSync(descriptor, { bigint: true });
        if (!sameFile(before, after)) return { integrity: { status: 'unreadable' }, text: '' };
        const verified = verifyChain(text);
        const incompleteTail = text.length > 0 && !text.endsWith('\n');
        const integrity = !verified.valid || incompleteTail
            ? { status: 'broken', brokenAt: verified.brokenAt || verified.total, legacyPrefix: verified.legacyPrefix,
                issues: incompleteTail ? [...verified.issues, 'incomplete tail (missing newline)'] : verified.issues }
            : { status: verified.legacyPrefix === verified.total && verified.total > 0 ? 'legacy'
                : verified.legacyPrefix > 0 ? 'mixed' : 'verified',
                legacyPrefix: verified.legacyPrefix, total: verified.total };
        return { text: integrity.status === 'broken' ? '' : text, integrity };
    } catch (error) {
        if (error.code === 'ENOENT') return { text: '', integrity: { status: 'missing' } };
        return { text: '', integrity: { status: 'unreadable' } };
    } finally {
        if (descriptor !== undefined) fs.closeSync(descriptor);
    }
}

function incidentFile(dataDir) {
    return resolveWithinBase(dataDir, 'incidents.jsonl');
}

/* Coerce any parsed value into a bounded plain string. */
function asText(value, max = FIELD_MAX) {
    if (value === undefined || value === null) return '';
    if (typeof value === 'string') return value.slice(0, max);
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    return '';
}

function asInt(value, fallback = 0) {
    const num = typeof value === 'number' ? value : Number.parseInt(value, 10);
    if (!Number.isFinite(num)) return fallback;
    return Math.trunc(num);
}

/* Bounded string list: drops non-strings, caps length and entry count. */
function asTextList(value, maxEntries = MAX_LIST) {
    if (!Array.isArray(value)) return [];
    const out = [];
    for (const item of value) {
        if (typeof item !== 'string' || !item) continue;
        out.push(item.slice(0, FIELD_MAX));
        if (out.length >= maxEntries) break;
    }
    return out;
}

function normalizeStage(raw) {
    if (!raw || typeof raw !== 'object') return null;
    const tactic = asText(raw.tactic, 64);
    if (!tactic) return null;
    return {
        tactic,
        rule: asText(raw.rule, 64),
        severity: asText(raw.severity, 16),
        alertCount: asInt(raw.alertCount),
        firstSeen100ns: asInt(raw.firstSeen100ns),
        lastSeen100ns: asInt(raw.lastSeen100ns),
    };
}

/* Normalize one raw JSONL record into a trusted incident shape. */
function normalizeIncident(raw) {
    if (!raw || typeof raw !== 'object') return null;
    const id = asText(raw.id, 64);
    if (!id) return null;
    const stages = [];
    if (Array.isArray(raw.stages)) {
        for (const item of raw.stages) {
            const stage = normalizeStage(item);
            if (stage) stages.push(stage);
            if (stages.length >= MAX_STAGES) break;
        }
    }
    const severity = asText(raw.severity, 16);
    return {
        id,
        host: asText(raw.host, 256),
        image: asText(raw.image, 512),
        user: asText(raw.user, 256),
        severity: Object.prototype.hasOwnProperty.call(SEVERITY_RANK, severity) ? severity : 'info',
        score: Math.max(0, Math.min(100, asInt(raw.score))),
        alertCount: Math.max(0, asInt(raw.alertCount)),
        firstSeen100ns: asInt(raw.firstSeen100ns),
        lastSeen100ns: asInt(raw.lastSeen100ns),
        rules: asTextList(raw.rules),
        tactics: asTextList(raw.tactics).map(t => t.slice(0, 64)),
        stages,
    };
}

/**
 * Read incidents.jsonl and return the latest state of every incident.
 *
 * `kind` on the last record per incident determines open vs closed: a chain
 * that was opened but never closed is `open`, otherwise `closed`. A broken
 * chain or torn append never contributes records to the returned state.
 */
function loadIncidents(dataDir, options = {}) {
    const file = options.file || incidentFile(dataDir);
    const maxIncidents = options.maxIncidents || MAX_INCIDENTS;
    const latest = new Map();
    let malformed = 0;
    let scanned = 0;

    const snapshot = readSnapshot(file);
    const { text, integrity } = snapshot;
    const completeness = () => ({
        status: scanned > MAX_RECORDS_SCANNED ? 'limit_exceeded' : 'complete',
        scanned: Math.min(scanned, MAX_RECORDS_SCANNED),
        limit: MAX_RECORDS_SCANNED,
    });
    if (integrity.status === 'missing') return { incidents: [], malformed, scanned, exists: false, integrity, completeness: completeness() };
    if (integrity.status === 'broken' || integrity.status === 'unreadable')
        return { incidents: [], malformed, scanned, exists: true, integrity, completeness: completeness() };

    const lines = text.split('\n');
    for (const line of lines) {
        if (!line) continue;
        if (scanned >= MAX_RECORDS_SCANNED) {
            scanned += 1;
            break;
        }
        scanned += 1;
        let parsed;
        try {
            parsed = JSON.parse(line);
        } catch (_) {
            malformed += 1;
            continue;
        }
        const incident = normalizeIncident(parsed);
        if (!incident) { malformed += 1; continue; }
        latest.set(incident.id, {
            incident,
            kind: asText(parsed.kind, 16) === 'open' ? 'open' : 'closed',
        });
    }

    if (scanned > MAX_RECORDS_SCANNED) {
        scanned = MAX_RECORDS_SCANNED;
        return {
            incidents: [], malformed, scanned, exists: true, integrity,
            completeness: { status: 'limit_exceeded', scanned, limit: MAX_RECORDS_SCANNED },
        };
    }

    const incidents = [];
    for (const entry of latest.values()) {
        incidents.push({ ...entry.incident, state: entry.kind });
    }
    /* Sort the full replay before applying the service capacity limit. */
    incidents.sort((left, right) => {
        if (left.lastSeen100ns !== right.lastSeen100ns)
            return left.lastSeen100ns > right.lastSeen100ns ? -1 : 1;
        if (left.id === right.id) return 0;
        return left.id < right.id ? -1 : 1;
    });
    return {
        incidents: incidents.slice(0, maxIncidents), malformed, scanned, exists: true, integrity,
        completeness: { status: 'complete', scanned, limit: MAX_RECORDS_SCANNED },
    };
}

function asyncIntegrity(result) {
    if (result.status === 'missing') return { status: 'missing' };
    if (result.status === 'unreadable') return { status: 'unreadable' };
    if (result.status === 'limit_exceeded')
        return { status: 'unavailable', reason: result.limit || 'verification_limit' };
    if (result.status === 'broken') {
        const integrity = {
            status: 'broken',
            brokenAt: result.brokenAt,
            legacyPrefix: result.legacyPrefix,
            issues: result.issues,
        };
        if (result.issuesTruncated) {
            integrity.issueCount = result.issueCount;
            integrity.issuesTruncated = true;
        }
        return integrity;
    }
    return {
        status: result.status,
        legacyPrefix: result.legacyPrefix,
        total: result.total,
    };
}

/**
 * Stream one stable incidents.jsonl descriptor snapshot, verifying its full
 * chain while rebuilding a bounded latest-state index. Partial scan or index
 * results are never returned as complete incidents.
 */
async function loadIncidentsAsync(dataDir, options = {}) {
    const file = options.file || incidentFile(dataDir);
    const maxStates = Number.isSafeInteger(options.maxStates) && options.maxStates > 0
        ? options.maxStates : MAX_INCIDENT_STATES;
    const maxIncidents = Number.isSafeInteger(options.maxIncidents) && options.maxIncidents > 0
        ? options.maxIncidents : maxStates;
    const maxRecords = Number.isSafeInteger(options.maxRecords) && options.maxRecords > 0
        ? options.maxRecords : MAX_RECORDS_SCANNED;
    const maxRecordBytes = Number.isSafeInteger(options.maxRecordBytes) && options.maxRecordBytes > 0
        ? options.maxRecordBytes : MAX_INCIDENT_RECORD_BYTES;
    const maxFileBytes = Number.isSafeInteger(options.maxFileBytes) && options.maxFileBytes > 0
        ? options.maxFileBytes : MAX_INCIDENT_FILE_BYTES;
    const latest = new Map();
    let malformed = 0;
    let stateLimitExceeded = false;

    const verification = await verifyFileStream(file, {
        maxFileBytes,
        maxRecordBytes,
        maxRecords,
        maxIssues: options.maxIssues,
        yieldEveryRecords: options.yieldEveryRecords,
        highWaterMark: options.highWaterMark,
        onRecord(raw) {
            const incident = normalizeIncident(raw);
            if (!incident) {
                malformed += 1;
                return;
            }
            if (!latest.has(incident.id) && latest.size >= maxStates) {
                stateLimitExceeded = true;
                return;
            }
            latest.set(incident.id, {
                incident,
                kind: asText(raw.kind, 16) === 'open' ? 'open' : 'closed',
            });
        },
    });
    const integrity = asyncIntegrity(verification);
    const scanned = verification.total || 0;
    const complete = () => ({
        status: 'complete',
        scanned,
        limit: maxRecords,
    });

    if (verification.status === 'missing') {
        return { incidents: [], malformed, scanned: 0, exists: false, integrity,
            completeness: { status: 'complete', scanned: 0, limit: maxRecords } };
    }
    if (verification.status === 'unreadable' || verification.status === 'broken') {
        return { incidents: [], malformed, scanned, exists: true, integrity,
            completeness: complete() };
    }
    if (verification.status === 'limit_exceeded') {
        return {
            incidents: [], malformed, scanned: Math.min(scanned, maxRecords),
            exists: true, integrity,
            completeness: {
                status: 'limit_exceeded',
                scanned: Math.min(scanned, maxRecords),
                limit: maxRecords,
                reason: verification.limit || 'verification_limit',
            },
        };
    }
    if (stateLimitExceeded) {
        return {
            incidents: [], malformed, scanned, exists: true, integrity,
            completeness: {
                status: 'limit_exceeded',
                scanned,
                limit: maxStates,
                reason: 'state_count',
            },
        };
    }

    const incidents = [];
    for (const entry of latest.values())
        incidents.push({ ...entry.incident, state: entry.kind });
    incidents.sort((left, right) => {
        if (left.lastSeen100ns !== right.lastSeen100ns)
            return left.lastSeen100ns > right.lastSeen100ns ? -1 : 1;
        if (left.id === right.id) return 0;
        return left.id < right.id ? -1 : 1;
    });
    const truncated = incidents.length > maxIncidents;
    return {
        incidents: incidents.slice(0, maxIncidents),
        malformed,
        scanned,
        exists: true,
        integrity,
        completeness: truncated
            ? { status: 'truncated', scanned, limit: maxIncidents,
                available: incidents.length, reason: 'result_count' }
            : complete(),
    };
}

function findIncident(dataDir, id, options = {}) {
    const loaded = loadIncidents(dataDir, options);
    if (loaded.completeness.status !== 'complete') return null;
    const { incidents } = loaded;
    return incidents.find(item => item.id === id) || null;
}

/**
 * Build the kill-chain graph for one incident.
 *
 * Nodes are the distinct tactics in first-sighting order; the first node is
 * the entry stage. Edges are the observed successions between consecutive
 * stages, which is what a UI needs to draw a chain rather than a star. Every
 * tactic the incident recorded gets a node even when no rule mapped a
 * transition, so a gap in the chain is visible instead of silently closed.
 */
function buildGraph(incident) {
    if (!incident) return null;
    const ordered = [...incident.stages].sort(
        (left, right) => left.firstSeen100ns - right.firstSeen100ns);

    const nodes = ordered.map((stage, index) => ({
        id: `stage-${index}`,
        tactic: stage.tactic,
        rule: stage.rule,
        severity: stage.severity,
        alertCount: stage.alertCount,
        firstSeen100ns: stage.firstSeen100ns,
        lastSeen100ns: stage.lastSeen100ns,
        order: index,
    }));

    const edges = [];
    for (let i = 0; i + 1 < nodes.length; i += 1) {
        edges.push({
            from: nodes[i].id,
            to: nodes[i + 1].id,
            fromTactic: nodes[i].tactic,
            toTactic: nodes[i + 1].tactic,
        });
    }

    return {
        id: incident.id,
        host: incident.host,
        image: incident.image,
        severity: incident.severity,
        score: incident.score,
        alertCount: incident.alertCount,
        state: incident.state,
        entryTactic: nodes.length ? nodes[0].tactic : '',
        tacticCount: nodes.length,
        nodes,
        edges,
    };
}

/* Apply the console's incident filters. Absent filters are no-ops. */
function filterIncidents(incidents, filters = {}) {
    let result = incidents;
    if (filters.severity) result = result.filter(i => i.severity === filters.severity);
    if (filters.state) result = result.filter(i => i.state === filters.state);
    if (filters.host) {
        const needle = filters.host.toLowerCase();
        result = result.filter(i => i.host.toLowerCase().includes(needle));
    }
    if (filters.tactic) {
        const needle = filters.tactic.toLowerCase();
        result = result.filter(i => i.tactics.some(t => t.toLowerCase() === needle));
    }
    if (filters.minScore !== undefined) {
        result = result.filter(i => i.score >= filters.minScore);
    }
    if (filters.q) {
        const needle = filters.q.toLowerCase();
        result = result.filter(i =>
            i.id.toLowerCase().includes(needle) ||
            i.image.toLowerCase().includes(needle) ||
            i.user.toLowerCase().includes(needle) ||
            i.host.toLowerCase().includes(needle) ||
            i.rules.some(r => r.toLowerCase().includes(needle)) ||
            i.tactics.some(t => t.toLowerCase().includes(needle)));
    }
    return result;
}

/* Aggregate counters for a dashboard tile. */
function summarize(incidents) {
    const bySeverity = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
    const byTactic = new Map();
    let open = 0;
    let maxScore = 0;
    for (const incident of incidents) {
        bySeverity[incident.severity] = (bySeverity[incident.severity] || 0) + 1;
        if (incident.state === 'open') open += 1;
        if (incident.score > maxScore) maxScore = incident.score;
        for (const tactic of incident.tactics) {
            byTactic.set(tactic, (byTactic.get(tactic) || 0) + 1);
        }
    }
    const tactics = [...byTactic.entries()]
        .map(([tactic, count]) => ({ tactic, count }))
        .sort((left, right) => right.count - left.count || left.tactic.localeCompare(right.tactic));
    return {
        total: incidents.length,
        open,
        closed: incidents.length - open,
        maxScore,
        bySeverity,
        tactics,
    };
}

module.exports = {
    incidentFile,
    loadIncidents,
    loadIncidentsAsync,
    findIncident,
    buildGraph,
    filterIncidents,
    summarize,
    normalizeIncident,
    MAX_INCIDENTS,
    MAX_RECORDS_SCANNED,
    MAX_INCIDENT_FILE_BYTES,
    MAX_INCIDENT_RECORD_BYTES,
    MAX_INCIDENT_STATES,
};
