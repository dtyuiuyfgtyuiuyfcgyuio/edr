'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { buildProcessHunt } = require('./process_hunt');

const sourceId = 'sensor-a';
const rootKey = `${sourceId}:guid:root`;
const childKey = `${sourceId}:guid:child`;
const grandchildKey = `${sourceId}:guid:grandchild`;
const siblingKey = `${sourceId}:guid:sibling`;
const otherSourceKey = `sensor-b:guid:cross-source`;

function process(processKey, parentProcessKey = undefined, source = sourceId) {
    return { processKey, sourceId: source, parentProcessKey, pid: 100, image: processKey, commandLine: processKey, lastSeen: '2026-10-04T10:00:00.000Z', eventCount: 1 };
}

function event(eventId, processKey, timestamp, source = sourceId, raw = {}) {
    return { eventId, processKey, sourceId: source, type: 'PROCESS_ACTIVITY', timestamp, parentProcessKey: undefined, raw };
}

test('buildProcessHunt walks a deterministic source-bound process subtree and returns only its events', () => {
    const processes = new Map([
        [rootKey, process(rootKey)],
        [siblingKey, process(siblingKey, rootKey)],
        [childKey, process(childKey, rootKey)],
        [grandchildKey, process(grandchildKey, childKey)],
        [otherSourceKey, process(otherSourceKey, rootKey, 'sensor-b')],
        [`${sourceId}:guid:unrelated`, process(`${sourceId}:guid:unrelated`)],
    ]);
    const events = [
        event('grand-late', grandchildKey, '2026-10-04T10:00:03.000Z'),
        event('child', childKey, '2026-10-04T10:00:02.000Z'),
        event('cross', otherSourceKey, '2026-10-04T10:00:04.000Z', 'sensor-b'),
        event('root', rootKey, '2026-10-04T10:00:01.000Z'),
        event('other-root', `${sourceId}:guid:unrelated`, '2026-10-04T10:00:00.000Z'),
    ];

    const result = buildProcessHunt(processes, events, rootKey);

    assert.deepEqual(result.nodes.map(node => [node.processKey, node.depth]), [
        [rootKey, 0], [childKey, 1], [siblingKey, 1], [grandchildKey, 2],
    ]);
    assert.deepEqual(result.events.map(item => item.eventId), ['root', 'child', 'grand-late']);
    assert.equal(result.sourceId, sourceId);
    assert.equal(result.truncated, false);
    assert.deepEqual(result.reasons, []);
    assert.equal(result.completeness.status, 'complete');
    assert.equal(result.completeness.scope, 'retained_window');
});

test('buildProcessHunt reports node and depth truncation without traversing beyond limits', () => {
    const processes = new Map([
        [rootKey, process(rootKey)], [childKey, process(childKey, rootKey)],
        [grandchildKey, process(grandchildKey, childKey)], [siblingKey, process(siblingKey, rootKey)],
    ]);

    const depthLimited = buildProcessHunt(processes, [], rootKey, { maxDepth: 1 });
    assert.deepEqual(depthLimited.nodes.map(node => node.processKey), [rootKey, childKey, siblingKey]);
    assert.equal(depthLimited.truncated, true);
    assert.deepEqual(depthLimited.reasons, ['depth_limit']);
    assert.equal(depthLimited.completeness.status, 'partial');

    const nodeLimited = buildProcessHunt(processes, [], rootKey, { maxNodes: 2 });
    assert.equal(nodeLimited.nodes.length, 2);
    assert.equal(nodeLimited.reasons.includes('node_limit'), true);
    assert.equal(nodeLimited.completeness.status, 'partial');
});

test('buildProcessHunt stops a reachable root self-loop and marks topology partial', () => {
    const processes = new Map([[rootKey, process(rootKey, rootKey)]]);

    const result = buildProcessHunt(processes, [], rootKey);

    assert.deepEqual(result.nodes.map(node => [node.processKey, node.depth]), [[rootKey, 0]]);
    assert.deepEqual(result.reasons, ['cycle_detected']);
    assert.equal(result.nodes.length, 1);
    assert.equal(result.truncated, false);
    assert.equal(result.completeness.status, 'partial');
    assert.equal(result.completeness.scope, 'retained_window');
});

test('buildProcessHunt stops multi-node cycles and ignores unreachable self-loops', () => {
    const cycleKey = `${sourceId}:guid:cycle`;
    const processes = new Map([
        [rootKey, process(rootKey, cycleKey)],
        [childKey, process(childKey, rootKey)],
        [cycleKey, process(cycleKey, childKey)],
        [siblingKey, process(siblingKey, siblingKey)],
    ]);

    const result = buildProcessHunt(processes, [], rootKey);

    assert.deepEqual(result.nodes.map(node => node.processKey), [rootKey, childKey, cycleKey]);
    assert.equal(result.reasons.includes('cycle_detected'), true);
    assert.equal(result.truncated, false);
    assert.equal(result.completeness.status, 'partial');
    assert.equal(result.completeness.scope, 'retained_window');
});

test('buildProcessHunt always includes the selected root and reports capped input scans', () => {
    const processes = new Map();
    for (let index = 0; index < 20005; index += 1) {
        const key = `${sourceId}:guid:noise-${String(index).padStart(5, '0')}`;
        processes.set(key, process(key));
    }
    processes.set(rootKey, process(rootKey));
    const events = Array.from({ length: 20005 }, (_, index) =>
        event(`event-${String(index).padStart(5, '0')}`, rootKey, new Date(Date.parse('2026-10-04T10:00:00.000Z') + index * 1000).toISOString()));

    const result = buildProcessHunt(processes, events, rootKey, { eventLimit: 2 });

    assert.equal(result.nodes[0].processKey, rootKey);
    assert.equal(result.scanned.processes, 20000);
    assert.equal(result.scanned.events, 20000);
    assert.equal(result.truncated, true);
    assert.equal(result.reasons.includes('process_scan_limit'), true);
    assert.equal(result.reasons.includes('event_scan_limit'), true);
    assert.equal(result.reasons.includes('event_limit'), true);
    assert.equal(result.events.length, 2);
    assert.deepEqual(result.events.map(item => item.eventId), ['event-20003', 'event-20004']);
    assert.deepEqual(result.events.map(item => item.timestamp), [
        events[20003].timestamp, events[20004].timestamp,
    ]);
    assert.equal(result.completeness.status, 'partial');
    assert.equal(result.completeness.scope, 'retained_window');
});

test('buildProcessHunt stops event output at a byte budget and rejects missing roots', () => {
    const processes = new Map([[rootKey, process(rootKey)]]);
    const events = Array.from({ length: 40 }, (_, index) => event(
        `large-${index}`, rootKey, `2026-10-04T10:00:${String(index).padStart(2, '0')}.000Z`, sourceId,
        { output: '界'.repeat(40000) },
    ));

    const result = buildProcessHunt(processes, events, rootKey);

    assert.ok(result.events.length > 0 && result.events.length < events.length);
    assert.ok(result.events.reduce((total, item) =>
        total + Buffer.byteLength(JSON.stringify(item), 'utf8'), 0) <= 2 * 1024 * 1024);
    assert.equal(result.reasons.includes('event_byte_limit'), true);
    assert.equal(result.truncated, true);
    assert.deepEqual(result.events.map(item => item.eventId),
        events.slice(-result.events.length).map(item => item.eventId));
    assert.equal(result.events.at(-1).eventId, 'large-39');
    assert.equal(result.completeness.scope, 'retained_window');
    assert.equal(result.completeness.status, 'partial');
    assert.equal(buildProcessHunt(processes, events, 'missing'), null);
});

test('buildProcessHunt applies a node byte budget and reports retained-window scope', () => {
    const processes = new Map([[rootKey, process(rootKey)]]);
    for (let index = 0; index < 300; index += 1) {
        const key = `${sourceId}:guid:large-${String(index).padStart(3, '0')}`;
        processes.set(key, { ...process(key, rootKey), commandLine: '界'.repeat(8192) });
    }

    const result = buildProcessHunt(processes, [], rootKey, { maxNodes: 1000 });
    const serializedNodeBytes = result.nodes.reduce((total, node) =>
        total + Buffer.byteLength(JSON.stringify(node), 'utf8'), 0);

    assert.equal(result.reasons.includes('node_byte_limit'), true);
    assert.equal(result.truncated, true);
    assert.ok(serializedNodeBytes <= 2 * 1024 * 1024);
    assert.equal(result.completeness.scope, 'retained_window');
    assert.equal(result.completeness.status, 'partial');
});

test('buildProcessHunt rejects invalid positive integer limits', () => {
    const processes = new Map([[rootKey, process(rootKey)]]);
    for (const options of [{ maxNodes: 0 }, { maxNodes: 1001 }, { maxDepth: 65 }, { eventLimit: -1 }]) {
        assert.throws(() => buildProcessHunt(processes, [], rootKey, options), RangeError);
    }
});
