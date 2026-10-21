'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

const source = fs.readFileSync(process.env.INCIDENTS_UI_SOURCE ||
    path.join(__dirname, 'public', 'incidents.js'), 'utf8');

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
}

function response(status, data, jsonPromise) {
    return { status, ok: status >= 200 && status < 300,
        json: () => jsonPromise || Promise.resolve(data) };
}

function harness(request, summaryRequest) {
    const elements = new Map();
    const listeners = new Map();
    const statuses = [];
    function element(id) {
        if (!elements.has(id)) {
            const handlers = new Map();
            elements.set(id, {
                id, value: '', innerHTML: '', textContent: '', disabled: false, style: {},
                dataset: {}, handlers,
                classList: { add() {}, remove() {} },
                addEventListener(name, callback) {
                    handlers.set(name, [...(handlers.get(name) || []), callback]);
                    listeners.set(`${id}:${name}`, handlers.get(name));
                },
            });
        }
        return elements.get(id);
    }
    const tab = {
        addEventListener(name, callback) {
            listeners.set(`tab:${name}`, [...(listeners.get(`tab:${name}`) || []), callback]);
        },
        click() { for (const callback of listeners.get('tab:click') || []) callback(); },
    };
    const document = {
        getElementById: element,
        querySelector: () => tab,
    };
    const context = vm.createContext({
        document,
        location: { search: '' },
        URLSearchParams,
        request: url => url === '/api/incidents/summary'
            ? (summaryRequest ? summaryRequest(url) : Promise.resolve(response(200,
                { total: 0, open: 0, closed: 0, maxScore: 0, bySeverity: {} })))
            : request(url),
        setStatus: (...args) => statuses.push(args),
        escapeHtml: value => String(value ?? ''),
    });
    vm.runInContext(source, context, { filename: 'incidents.js' });
    return {
        elements,
        statuses,
        trigger(id, event, payload = {}) {
            for (const callback of listeners.get(`${id}:${event}`) || []) callback(payload);
        },
        clickIncident(index) {
            const row = { dataset: { incidentIndex: String(index) } };
            this.trigger('incidentList', 'click', { target: { closest: () => row } });
        },
    };
}

function incident(id) {
    return { id, state: 'open', severity: 'high', score: 80, alertCount: 1,
        firstSeen100ns: 0, lastSeen100ns: 0, host: 'host', user: 'user',
        image: 'image.exe', rules: [], tactics: [], stages: [] };
}

function page(ids, total = ids.length) {
    return { incidents: ids.map(incident), total, malformed: 0,
        integrity: { status: 'verified' } };
}

async function settle() {
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));
}

test('late list success cannot replace the newest page, summary, pagination, or row mapping', async () => {
    const calls = [];
    const app = harness(url => {
        const item = deferred();
        calls.push({ url, ...item });
        return item.promise;
    });
    app.trigger('tab', 'click');
    calls[0].resolve(response(200, page(['initial-0', 'initial-1'], 250)));
    await settle();

    app.trigger('incidentsNext', 'click');
    app.trigger('incidentsNext', 'click');
    assert.match(calls[2].url, /offset=200/);
    calls[2].resolve(response(200, page(['newest-page'], 250)));
    await settle();
    calls[1].resolve(response(200, page(['stale-page'], 250)));
    await settle();

    assert.match(app.elements.get('incidentList').innerHTML, /newest-page/);
    assert.doesNotMatch(app.elements.get('incidentList').innerHTML, /stale-page/);
    assert.match(app.elements.get('incidentSummary').textContent, /^250 incident/);
    assert.equal(app.elements.get('incidentsPageInfo').textContent, 'Page 3 / 3 (250 incidents)');

    app.clickIncident(0);
    await settle();
    assert.ok(calls.some(call => call.url === '/api/incidents/newest-page'));
    assert.ok(!calls.some(call => call.url === '/api/incidents/stale-page'));
});

test('late HTTP error and network failure cannot clear a newer successful list or summary', async t => {
    for (const failure of ['http', 'network']) {
        await t.test(failure, async () => {
            const calls = [];
            const app = harness(url => {
                const item = deferred();
                calls.push({ url, ...item });
                return item.promise;
            });
            app.trigger('tab', 'click');
            calls[0].resolve(response(200, page(['first'], 250)));
            await settle();
            app.trigger('incidentsNext', 'click');
            app.trigger('incidentsNext', 'click');
            calls[2].resolve(response(200, page(['current'], 250)));
            await settle();
            if (failure === 'http') calls[1].resolve(response(500, { error: 'old failure' }));
            else calls[1].reject(new Error('old network failure'));
            await settle();
            assert.match(app.elements.get('incidentList').innerHTML, /current/);
            assert.doesNotMatch(app.elements.get('incidentList').innerHTML, /Unable to load/);
            assert.equal(app.elements.get('incidentSummary').textContent, '250 incident(s)');
        });
    }
});

test('late list JSON and 401 cannot overwrite rows, pagination, summary, or auth status', async t => {
    await t.test('delayed JSON body', async () => {
        const calls = [];
        const oldJson = deferred();
        const app = harness(url => {
            const item = deferred();
            calls.push({ url, ...item });
            return item.promise;
        });
        app.trigger('tab', 'click');
        calls[0].resolve(response(200, null, oldJson.promise));
        await settle();
        app.trigger('incidentsRefresh', 'click');
        calls[1].resolve(response(200, page(['latest'], 1)));
        await settle();
        oldJson.resolve(page(['late-json'], 300));
        await settle();
        assert.match(app.elements.get('incidentList').innerHTML, /latest/);
        assert.equal(app.elements.get('incidentsPageInfo').textContent, 'Page 1 / 1 (1 incidents)');
        assert.equal(app.elements.get('incidentSummary').textContent, '1 incident(s)');
    });
    await t.test('stale 401', async () => {
        const calls = [];
        const app = harness(url => {
            const item = deferred();
            calls.push({ url, ...item });
            return item.promise;
        });
        app.trigger('tab', 'click');
        app.trigger('incidentsRefresh', 'click');
        calls[1].resolve(response(200, page(['authorized'], 4)));
        await settle();
        calls[0].resolve(response(401, { error: 'expired old request' }));
        await settle();
        assert.match(app.elements.get('incidentList').innerHTML, /authorized/);
        assert.equal(app.elements.get('incidentSummary').textContent, '4 incident(s)');
        assert.deepEqual(app.statuses, []);
    });
});

test('late global summary responses cannot replace newer cards or report stale auth failures', async t => {
    for (const stale of ['success', 'http', 'unauthorized']) {
        await t.test(stale, async () => {
            const listCalls = [];
            const summaryCalls = [];
            const app = harness(url => {
                const item = deferred();
                listCalls.push({ url, ...item });
                return item.promise;
            }, () => {
                const item = deferred();
                summaryCalls.push(item);
                return item.promise;
            });
            app.trigger('tab', 'click');
            app.trigger('incidentsRefresh', 'click');
            summaryCalls[1].resolve(response(200, { total: 9, open: 7, closed: 2,
                maxScore: 91, bySeverity: { high: 9 } }));
            await settle();
            if (stale === 'success') summaryCalls[0].resolve(response(200, {
                total: 2, open: 1, closed: 1, maxScore: 10, bySeverity: { low: 2 },
            }));
            else if (stale === 'http') summaryCalls[0].resolve(response(500, { error: 'stale summary failure' }));
            else summaryCalls[0].resolve(response(401, { error: 'expired summary request' }));
            await settle();
            assert.match(app.elements.get('incidentStats').innerHTML, />9<\/div><div class="label">incidents/);
            assert.doesNotMatch(app.elements.get('incidentStats').innerHTML, />2<\/div><div class="label">incidents/);
            assert.deepEqual(app.statuses, []);
            assert.equal(listCalls.length, 2);
        });
    }
});

test('reopening the same incident ignores older detail and graph responses', async () => {
    const calls = [];
    const app = harness(url => {
        const item = deferred();
        calls.push({ url, ...item });
        if (url === '/api/incidents?limit=100&offset=0')
            return Promise.resolve(response(200, page(['same'], 1)));
        return item.promise;
    });
    app.trigger('tab', 'click');
    await settle();
    app.clickIncident(0);
    const detailCalls = calls.filter(call => call.url === '/api/incidents/same');
    detailCalls[0].resolve(response(200, { incident: { ...incident('same'), image: 'first.exe' } }));
    await settle();
    const graphCalls = calls.filter(call => call.url === '/api/incidents/same/graph');
    assert.equal(graphCalls.length, 1);
    app.clickIncident(0);
    const repeatedDetailCalls = calls.filter(call => call.url === '/api/incidents/same');
    repeatedDetailCalls[1].resolve(response(200, { incident: { ...incident('same'), image: 'newer.exe' } }));
    await settle();
    assert.equal(calls.filter(call => call.url === '/api/incidents/same/graph').length, 2);
    const allGraphs = calls.filter(call => call.url === '/api/incidents/same/graph');
    const currentGraph = { entryTactic: 'Current chain', tacticCount: 1,
        severity: 'high', score: 80, alertCount: 1, state: 'open',
        nodes: [{ tactic: 'Current chain', order: 0 }], edges: [] };
    allGraphs[1].resolve(response(200, { graph: currentGraph }));
    await settle();
    allGraphs[0].resolve(response(200, { graph: { ...currentGraph,
        entryTactic: 'Old chain', nodes: [{ tactic: 'Old chain', order: 0 }] } }));
    await settle();
    assert.match(app.elements.get('incidentDetailBody').innerHTML, /newer\.exe/);
    assert.doesNotMatch(app.elements.get('incidentDetailBody').innerHTML, /first\.exe/);
    assert.match(app.elements.get('incidentChainBody').innerHTML, /Current chain/);
    assert.doesNotMatch(app.elements.get('incidentChainBody').innerHTML, /Old chain/);
});

test('closing an incident invalidates late detail and graph responses, then allows reopening', async t => {
    const outcomes = ['success', 'unauthorized', 'http-error', 'network-error'];
    for (const surface of ['detail', 'graph']) {
        for (const outcome of outcomes) {
            await t.test(`${surface} ${outcome}`, async () => {
                const calls = [];
                const app = harness(url => {
                    if (url === '/api/incidents?limit=100&offset=0')
                        return Promise.resolve(response(200, page(['same'], 1)));
                    const item = deferred();
                    calls.push({ url, ...item });
                    return item.promise;
                });
                app.trigger('tab', 'click');
                await settle();
                const detailUrl = '/api/incidents/same';
                const graphUrl = `${detailUrl}/graph`;
                if (surface === 'graph') {
                    app.clickIncident(0);
                    calls.find(call => call.url === detailUrl).resolve(response(200,
                        { incident: { ...incident('same'), image: 'before-close.exe' } }));
                    await settle();
                    assert.ok(calls.some(call => call.url === graphUrl));
                } else {
                    app.clickIncident(0);
                    assert.ok(calls.some(call => call.url === detailUrl));
                }

                app.trigger('incidentDetailClose', 'click');
                const detailBody = app.elements.get('incidentDetailBody').innerHTML;
                const chainBody = app.elements.get('incidentChainBody').innerHTML;
                const staleCall = calls.find(call => call.url === (surface === 'detail' ? detailUrl : graphUrl));
                if (outcome === 'success') {
                    if (surface === 'detail') staleCall.resolve(response(200,
                        { incident: { ...incident('same'), image: 'late.exe' } }));
                    else staleCall.resolve(response(200, { graph: {
                        entryTactic: 'Late chain', tacticCount: 1, severity: 'high',
                        score: 80, alertCount: 1, state: 'open',
                        nodes: [{ tactic: 'Late chain', order: 0 }], edges: [],
                    } }));
                } else if (outcome === 'unauthorized') {
                    staleCall.resolve(response(401, { error: 'expired request' }));
                } else if (outcome === 'http-error') {
                    staleCall.resolve(response(500, { error: 'late failure' }));
                } else {
                    staleCall.reject(new Error('late network failure'));
                }
                await settle();
                assert.equal(app.elements.get('incidentDetail').style.display, 'none');
                assert.equal(app.elements.get('incidentDetailBody').innerHTML, detailBody);
                assert.equal(app.elements.get('incidentChainBody').innerHTML, chainBody);
                assert.deepEqual(app.statuses, []);
                if (surface === 'detail') assert.equal(calls.filter(call => call.url === graphUrl).length, 0);

                app.clickIncident(0);
                const currentDetail = calls.filter(call => call.url === detailUrl).at(-1);
                assert.notEqual(currentDetail, staleCall);
                currentDetail.resolve(response(200,
                    { incident: { ...incident('same'), image: 'reopened.exe' } }));
                await settle();
                const currentGraph = calls.filter(call => call.url === graphUrl).at(-1);
                assert.ok(currentGraph, 'reopening starts a fresh graph request');
                currentGraph.resolve(response(200, { graph: {
                    entryTactic: 'Reopened chain', tacticCount: 1, severity: 'high',
                    score: 80, alertCount: 1, state: 'open',
                    nodes: [{ tactic: 'Reopened chain', order: 0 }], edges: [],
                } }));
                await settle();
                assert.equal(app.elements.get('incidentDetail').style.display, 'block');
                assert.match(app.elements.get('incidentDetailBody').innerHTML, /reopened\.exe/);
                assert.match(app.elements.get('incidentChainBody').innerHTML, /Reopened chain/);
                assert.deepEqual(app.statuses, []);
            });
        }
    }
});
