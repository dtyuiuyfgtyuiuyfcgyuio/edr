'use strict';

const MAX_PROCESS_SCAN = 20000;
const MAX_EVENT_SCAN = 20000;
const MAX_NODE_BYTES = 2 * 1024 * 1024;
const MAX_EVENT_BYTES = 2 * 1024 * 1024;
const MAX_NODES = 1000;
const MAX_DEPTH = 64;
const MAX_EVENTS = 1000;

function validateLimit(value, name, max) {
    if (!Number.isSafeInteger(value) || value < 1 || value > max) {
        throw new RangeError(`${name} must be an integer in [1, ${max}]`);
    }
}

function compareText(left, right) {
    const leftText = String(left ?? '');
    const rightText = String(right ?? '');
    return leftText < rightText ? -1 : (leftText > rightText ? 1 : 0);
}

function buildProcessHunt(processes, events, rootProcessKey, options = {}) {
    const maxNodes = options.maxNodes ?? 200;
    const maxDepth = options.maxDepth ?? 16;
    const eventLimit = options.eventLimit ?? 500;
    validateLimit(maxNodes, 'maxNodes', MAX_NODES);
    validateLimit(maxDepth, 'maxDepth', MAX_DEPTH);
    validateLimit(eventLimit, 'eventLimit', MAX_EVENTS);
    if (!(processes instanceof Map)) throw new TypeError('processes must be a Map');
    if (!Array.isArray(events)) throw new TypeError('events must be an array');

    // A Map lookup is constant time and guarantees that the requested root is
    // included even when it falls after the bounded inventory scan window.
    const root = processes.get(rootProcessKey);
    if (!root) return null;
    const sourceId = root.sourceId;
    const scannedProcesses = new Map([[rootProcessKey, root]]);
    let scannedProcessCount = 1;
    for (const [key, process] of processes) {
        if (key === rootProcessKey) continue;
        if (scannedProcessCount >= MAX_PROCESS_SCAN) break;
        scannedProcesses.set(key, process);
        scannedProcessCount += 1;
    }

    const reasons = new Set();
    if (processes.size > scannedProcesses.size) reasons.add('process_scan_limit');

    const childrenByParent = new Map();
    for (const [key, process] of scannedProcesses) {
        if (!process || process.sourceId !== sourceId || typeof process.parentProcessKey !== 'string') continue;
        const parent = scannedProcesses.get(process.parentProcessKey);
        if (!parent || parent.sourceId !== sourceId) continue;
        const children = childrenByParent.get(process.parentProcessKey) || [];
        children.push(key);
        childrenByParent.set(process.parentProcessKey, children);
    }
    for (const children of childrenByParent.values()) children.sort(compareText);

    const nodes = [{ ...root, processKey: rootProcessKey, depth: 0 }];
    let responseNodeBytes = Buffer.byteLength(JSON.stringify(nodes[0]), 'utf8');
    const visited = new Set([rootProcessKey]);
    const queue = [{ processKey: rootProcessKey, depth: 0 }];
    let stopTraversal = false;
    for (let cursor = 0; cursor < queue.length && !stopTraversal; cursor += 1) {
        const current = queue[cursor];
        const children = childrenByParent.get(current.processKey) || [];
        for (const childKey of children) {
            if (visited.has(childKey)) {
                reasons.add('cycle_detected');
                continue;
            }
            const depth = current.depth + 1;
            if (depth > maxDepth) {
                reasons.add('depth_limit');
                continue;
            }
            if (nodes.length >= maxNodes) {
                reasons.add('node_limit');
                stopTraversal = true;
                break;
            }
            const child = scannedProcesses.get(childKey);
            // Relationships are canonical keys, but retain an explicit source
            // check so malformed persisted state can never cross endpoints.
            if (!child || child.sourceId !== sourceId) continue;
            const outputNode = { ...child, processKey: childKey, depth };
            const nodeBytes = Buffer.byteLength(JSON.stringify(outputNode), 'utf8');
            if (responseNodeBytes + nodeBytes > MAX_NODE_BYTES) {
                reasons.add('node_byte_limit');
                stopTraversal = true;
                break;
            }
            visited.add(childKey);
            nodes.push(outputNode);
            responseNodeBytes += nodeBytes;
            queue.push({ processKey: childKey, depth });
        }
    }

    const scannedEvents = Math.min(events.length, MAX_EVENT_SCAN);
    if (events.length > scannedEvents) reasons.add('event_scan_limit');
    const includedProcessKeys = new Set(nodes.map(node => node.processKey));
    const matchingEvents = [];
    const eventStart = events.length - scannedEvents;
    for (let index = eventStart; index < events.length; index += 1) {
        const event = events[index];
        if (event && event.sourceId === sourceId && includedProcessKeys.has(event.processKey)) {
            matchingEvents.push({ event, inputIndex: index });
        }
    }
    matchingEvents.sort((left, right) =>
        compareText(left.event.timestamp, right.event.timestamp) ||
        compareText(left.event.eventId, right.event.eventId) ||
        compareText(left.event.processKey, right.event.processKey) ||
        left.inputIndex - right.inputIndex);
    if (matchingEvents.length > eventLimit) reasons.add('event_limit');
    const selectedEvents = matchingEvents.slice(-eventLimit).reverse();

    const resultEvents = [];
    let responseEventBytes = 0;
    for (const candidate of selectedEvents) {
        const event = candidate.event;
        const serialized = JSON.stringify(event);
        const byteLength = Buffer.byteLength(serialized, 'utf8');
        if (responseEventBytes + byteLength > MAX_EVENT_BYTES) {
            reasons.add('event_byte_limit');
            break;
        }
        resultEvents.push(event);
        responseEventBytes += byteLength;
    }
    resultEvents.reverse();

    const orderedReasons = [
        'process_scan_limit', 'event_scan_limit', 'node_limit', 'node_byte_limit',
        'depth_limit', 'event_limit', 'event_byte_limit', 'cycle_detected',
    ].filter(reason => reasons.has(reason));
    const truncated = orderedReasons.some(reason => reason !== 'cycle_detected');
    return {
        rootProcessKey,
        sourceId,
        nodes,
        events: resultEvents,
        truncated,
        reasons: orderedReasons,
        scanned: { processes: scannedProcessCount, events: scannedEvents },
        matchingEventsScanned: matchingEvents.length,
        completeness: {
            scope: 'retained_window',
            status: orderedReasons.length ? 'partial' : 'complete',
        },
    };
}

module.exports = { buildProcessHunt };
