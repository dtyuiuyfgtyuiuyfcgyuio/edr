/* Incidents console page — read-only kill-chain view.
 *
 * Backend contract (console/server.js routes, all auth 'read' via request() /
 * X-API-Key: readKey; console/incidents.js owns the record shape):
 *  - GET /api/incidents/summary   rejects every query parameter (server.js:2125)
 *        -> {total, open, closed, maxScore, bySeverity, tactics:[{tactic,count}], malformed, source, integrity}
 *  - GET /api/incidents           limit (1..LIMITS.queryLimit=1000, default 50), offset (>=0),
 *                                 severity (info|low|medium|high|critical), state (open|closed),
 *                                 host (substring), tactic (exact, case-insensitive),
 *                                 q (substring over id/image/user/host/rules/tactics, capped at 200 matches),
 *                                 min_score (integer 0..100)
 *        -> {total, malformed, incidents:[...], summary:{...}, integrity}
 *  - GET /api/incidents/:id       rejects query params -> {incident, integrity} | 404 {error, integrity}
 *  - GET /api/incidents/:id/graph rejects query params -> {graph, integrity} | 404 {error, integrity}
 *        graph: {id, host, image, severity, score, alertCount, state, entryTactic, tacticCount,
 *                nodes:[{id, tactic, rule, severity, alertCount, firstSeen100ns, lastSeen100ns, order}],
 *                edges:[{from, to, fromTactic, toTactic}]}  (nodes are stages in first-sighting order)
 *  Incident record (normalizeIncident + state):
 *    {id, host, image, user, severity, score, alertCount,
 *     firstSeen100ns, lastSeen100ns, rules[], tactics[],
 *     stages:[{tactic, rule, severity, alertCount, firstSeen100ns, lastSeen100ns}], state}
 *  All four routes answer 503 {error, integrity[, completeness]} when incidents.jsonl is
 *  broken / unreadable / replay-limited, and 401 when the read key is missing.
 *
 * firstSeen100ns/lastSeen100ns are Windows FILETIME ticks (1601-01-01 UTC epoch, 100ns
 * units) produced by the native agent (user/correlation_engine.cpp reuses event.ts100ns).
 *
 * Read-only page: the backend exposes no incident mutation endpoints and none are
 * called here. Triage and response actions stay in the Alerts / Response tabs.
 */
(function () {
    'use strict';

    /* 100/page matches the Alerts and Evidence tabs; the server clamps limit at
     * LIMITS.queryLimit = 1000 and the replay caps the ledger at 1000 incidents. */
    const INCIDENTS_PAGE_SIZE = 100;
    let incidentsOffset = 0;
    let incidentsTotal = 0;
    let incidentItems = [];
    let incidentDetailId = '';
    let incidentListRequestId = 0;
    let incidentSummaryRequestId = 0;
    let incidentDetailRequestId = 0;
    let incidentChainRequestId = 0;

    /* Windows FILETIME 100ns ticks -> JS epoch milliseconds. */
    function filetimeMs(ticks) {
        const value = Number(ticks);
        if (!Number.isFinite(value) || value <= 0) return 0;
        return value / 10000 - 11644473600000;
    }
    function formatFiletime(ticks) {
        const ms = filetimeMs(ticks);
        return ms ? new Date(ms).toLocaleString() : 'N/A';
    }
    function filetimeTitle(ticks) {
        const ms = filetimeMs(ticks);
        return ms ? new Date(ms).toISOString() : '';
    }
    /* Server 400/404/503 bodies carry {error, integrity[, completeness]}. */
    function apiErrorMessage(data, fallback) {
        const integrity = data && data.integrity && data.integrity.status ? ` (integrity: ${data.integrity.status})` : '';
        const message = data && (data.error || data.message);
        return message ? `${message}${integrity}` : fallback;
    }
    function scoreRiskClass(score) {
        const value = Number(score) || 0;
        if (value >= 80) return 'risk-critical';
        if (value >= 60) return 'risk-high';
        if (value >= 40) return 'risk-medium';
        return 'risk-low';
    }
    function tacticBadges(tactics) {
        return (tactics || []).map(tactic => `<span class="mitre" style="margin:2px" title="${escapeHtml(tactic)}">${escapeHtml(tactic)}</span>`).join(' ');
    }

    /* ---- Stat cards (global totals from /api/incidents/summary) ---- */
    function incidentStatCards(summary) {
        const bySeverity = summary.bySeverity || {};
        return ['critical', 'high', 'medium', 'low', 'info'].map(severity =>
            `<div class="stat sev-${severity}"><div class="num">${bySeverity[severity] || 0}</div><div class="label">${severity}</div></div>`).join('') +
            `<div class="stat"><div class="num">${summary.total ?? 0}</div><div class="label">incidents</div></div>` +
            `<div class="stat"><div class="num">${summary.open ?? 0}</div><div class="label">open</div></div>` +
            `<div class="stat"><div class="num">${summary.closed ?? 0}</div><div class="label">closed</div></div>` +
            `<div class="stat"><div class="num">${summary.maxScore ?? 0}</div><div class="label">max score</div></div>`;
    }
    async function loadIncidentSummary() {
        const requestId = ++incidentSummaryRequestId;
        const target = document.getElementById('incidentStats');
        if (!target) return;
        try {
            /* /api/incidents/summary rejects every query parameter — called bare. */
            const response = await request('/api/incidents/summary');
            if (requestId !== incidentSummaryRequestId) return;
            if (response.status === 401) { setStatus('read auth required', false); throw new Error('read API key required'); }
            const data = await response.json().catch(() => ({}));
            if (requestId !== incidentSummaryRequestId) return;
            if (!response.ok) throw new Error(apiErrorMessage(data, `HTTP ${response.status}`));
            target.innerHTML = incidentStatCards(data);
        } catch (error) {
            if (requestId !== incidentSummaryRequestId) return;
            target.innerHTML = `<div class="stat"><div class="label">summary unavailable</div><div class="muted" style="text-transform:none">${escapeHtml(error.message)}</div></div>`;
        }
    }

    /* ---- List (paginated + filtered /api/incidents) ---- */
    function incidentQueryUrl() {
        const params = new URLSearchParams({ limit: String(INCIDENTS_PAGE_SIZE), offset: String(incidentsOffset) });
        const severity = document.getElementById('incidentSeverity')?.value;
        const state = document.getElementById('incidentState')?.value;
        const host = document.getElementById('incidentHost')?.value.trim();
        const tactic = document.getElementById('incidentTactic')?.value.trim();
        const search = document.getElementById('incidentSearch')?.value.trim();
        const minScoreRaw = document.getElementById('incidentMinScore')?.value.trim();
        if (severity) params.set('severity', severity);
        if (state) params.set('state', state);
        if (host) params.set('host', host);
        if (tactic) params.set('tactic', tactic);
        if (search) params.set('q', search);
        if (minScoreRaw !== '') {
            const minScore = Number(minScoreRaw);
            /* the route rejects non-integer / out-of-range min_score with 400 — skip invalid input */
            if (Number.isInteger(minScore) && minScore >= 0 && minScore <= 100) params.set('min_score', String(minScore));
        }
        return `/api/incidents?${params.toString()}`;
    }
    function renderIncidentPageInfo() {
        const info = document.getElementById('incidentsPageInfo');
        if (!info) return;
        const pages = Math.max(1, Math.ceil(incidentsTotal / INCIDENTS_PAGE_SIZE));
        const current = Math.min(incidentsOffset / INCIDENTS_PAGE_SIZE + 1, pages);
        info.textContent = `Page ${current} / ${pages} (${incidentsTotal} incidents)`;
        const prev = document.getElementById('incidentsPrev');
        const next = document.getElementById('incidentsNext');
        if (prev) prev.disabled = incidentsOffset <= 0;
        if (next) next.disabled = incidentsOffset + INCIDENTS_PAGE_SIZE >= incidentsTotal;
    }
    function renderIncidentList() {
        const body = document.getElementById('incidentList');
        if (!body) return;
        if (!incidentItems.length) {
            body.innerHTML = `<tr><td colspan="11" class="muted">${incidentsOffset ? 'No incidents on this page' : 'No incidents'}</td></tr>`;
            renderIncidentPageInfo();
            return;
        }
        body.innerHTML = incidentItems.map((incident, index) => {
            const state = incident.state === 'open' ? 'open' : 'closed';
            const rules = (incident.rules || []).join(', ');
            return `<tr data-incident-index="${index}">
                <td><span class="badge ${state === 'open' ? 'state-recent' : 'muted'}">${escapeHtml(state)}</span></td>
                <td class="rule" title="${escapeHtml(incident.id)}">${escapeHtml(incident.id)}</td>
                <td class="sev-${escapeHtml(incident.severity)}">${escapeHtml(incident.severity)}</td>
                <td class="${scoreRiskClass(incident.score)}">${Number(incident.score) || 0}</td>
                <td>${Number(incident.alertCount) || 0}</td>
                <td class="muted" title="${escapeHtml(filetimeTitle(incident.firstSeen100ns))}">${escapeHtml(formatFiletime(incident.firstSeen100ns))}</td>
                <td class="muted" title="${escapeHtml(filetimeTitle(incident.lastSeen100ns))}">${escapeHtml(formatFiletime(incident.lastSeen100ns))}</td>
                <td title="${escapeHtml(incident.host)}">${escapeHtml(incident.host || 'Unknown')}</td>
                <td class="mitre-cell">${tacticBadges(incident.tactics)}</td>
                <td class="optional-col" title="${escapeHtml(incident.user)}">${escapeHtml(incident.user || '')}</td>
                <td class="optional-col muted" title="${escapeHtml(rules)}">${escapeHtml(rules)}</td>
            </tr>`;
        }).join('');
        renderIncidentPageInfo();
    }
    async function loadIncidents() {
        const requestId = ++incidentListRequestId;
        const body = document.getElementById('incidentList');
        const summary = document.getElementById('incidentSummary');
        if (!body) return;
        body.innerHTML = '<tr><td colspan="11" class="muted">Loading...</td></tr>';
        if (summary) summary.textContent = 'Loading...';
        try {
            const response = await request(incidentQueryUrl());
            if (requestId !== incidentListRequestId) return;
            if (response.status === 401) { setStatus('read auth required', false); throw new Error('read API key required'); }
            const data = await response.json().catch(() => ({}));
            if (requestId !== incidentListRequestId) return;
            if (!response.ok) throw new Error(apiErrorMessage(data, `HTTP ${response.status}`));
            incidentItems = Array.isArray(data.incidents) ? data.incidents : [];
            incidentsTotal = typeof data.total === 'number' ? data.total : incidentItems.length;
            renderIncidentList();
            const warnings = [];
            if (data.malformed) warnings.push(`${data.malformed} malformed ledger record(s)`);
            if (data.integrity?.status && data.integrity.status !== 'verified' && data.integrity.status !== 'missing')
                warnings.push(`ledger integrity: ${data.integrity.status}`);
            if (summary) summary.textContent = `${incidentsTotal} incident(s)${warnings.length ? ` — ${warnings.join('; ')}` : ''}`;
        } catch (error) {
            if (requestId !== incidentListRequestId) return;
            incidentItems = [];
            incidentsTotal = 0;
            renderIncidentPageInfo();
            body.innerHTML = `<tr><td colspan="11" class="muted">Unable to load incidents: ${escapeHtml(error.message)}</td></tr>`;
            if (summary) summary.textContent = `Unable to load incidents: ${error.message}`;
        }
    }
    function incidentsPage(delta) {
        const next = incidentsOffset + delta * INCIDENTS_PAGE_SIZE;
        if (next < 0 || (incidentsTotal > 0 && next >= incidentsTotal)) return;
        incidentsOffset = Math.max(0, next);
        loadIncidents();
    }

    /* ---- Detail (/api/incidents/:id) + kill chain (/api/incidents/:id/graph) ---- */
    function incidentDetailHtml(incident) {
        const rules = Array.isArray(incident.rules) ? incident.rules : [];
        const tactics = Array.isArray(incident.tactics) ? incident.tactics : [];
        const field = (label, value, valueClass) =>
            `<div class="field"><label>${escapeHtml(label)}</label><div${valueClass ? ` class="${valueClass}"` : ''}>${value === undefined || value === null || value === '' ? '<span class="muted">N/A</span>' : escapeHtml(String(value))}</div></div>`;
        const fields = [
            field('Incident ID', incident.id, 'rule'),
            field('State', incident.state || 'closed'),
            field('Severity', incident.severity),
            field('Score', `${Number(incident.score) || 0} / 100`),
            field('Alerts folded', Number(incident.alertCount) || 0),
            field('Host', incident.host),
            field('Image', incident.image),
            field('User', incident.user),
            field('First seen', formatFiletime(incident.firstSeen100ns)),
            field('Last seen', formatFiletime(incident.lastSeen100ns)),
        ].join('');
        const tacticsHtml = tactics.length ? tacticBadges(tactics) : '<span class="muted">None recorded</span>';
        const rulesHtml = rules.length
            ? rules.map(rule => `<code style="margin:2px;display:inline-block">${escapeHtml(rule)}</code>`).join(' ')
            : '<span class="muted">None recorded</span>';
        const stages = (Array.isArray(incident.stages) ? incident.stages : []).slice()
            .sort((left, right) => (left.firstSeen100ns || 0) - (right.firstSeen100ns || 0));
        const stagesHtml = stages.length
            ? `<div class="table-wrap"><table><thead><tr><th>#</th><th>Tactic</th><th>Rule</th><th>Severity</th><th>Alerts</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>` +
              stages.map((stage, index) => `<tr>
                    <td>${index + 1}</td>
                    <td><span class="mitre" title="${escapeHtml(stage.tactic)}">${escapeHtml(stage.tactic)}</span></td>
                    <td class="rule">${escapeHtml(stage.rule || 'N/A')}</td>
                    <td class="sev-${escapeHtml(stage.severity)}">${escapeHtml(stage.severity || 'info')}</td>
                    <td>${Number(stage.alertCount) || 0}</td>
                    <td class="muted" title="${escapeHtml(filetimeTitle(stage.firstSeen100ns))}">${escapeHtml(formatFiletime(stage.firstSeen100ns))}</td>
                    <td class="muted" title="${escapeHtml(filetimeTitle(stage.lastSeen100ns))}">${escapeHtml(formatFiletime(stage.lastSeen100ns))}</td>
                </tr>`).join('') + '</tbody></table></div>'
            : '<span class="muted">No stages recorded</span>';
        return `<div class="case-grid">
                <section>${fields}</section>
                <section>
                    <h3>Observed tactics / rules</h3>
                    <div class="field"><label>Tactics (${tactics.length})</label><div>${tacticsHtml}</div></div>
                    <div class="field"><label>Rules (${rules.length})</label><div>${rulesHtml}</div></div>
                    <div class="muted" style="font-size:12px">The ledger folds alerts into counters only — the incident record carries no per-alert list, entity objects beyond host/image/user, or event timeline; stages below are the recorded view.</div>
                </section>
            </div>
            <div class="modal-section"><h3>Stage timeline (first-sighting order)</h3>${stagesHtml}</div>
            <details class="modal-section"><summary class="muted">Raw incident JSON</summary><pre class="preview">${escapeHtml(JSON.stringify(incident, null, 2))}</pre></details>`;
    }
    function killChainHtml(graph) {
        if (!graph) return '<span class="muted">No attack chain data</span>';
        const nodes = (Array.isArray(graph.nodes) ? graph.nodes : []).slice()
            .sort((left, right) => (left.order || 0) - (right.order || 0));
        const edges = Array.isArray(graph.edges) ? graph.edges : [];
        if (!nodes.length) return '<span class="muted">No chain stages recorded</span>';
        const header = `<div class="muted" style="font-size:12px;margin-bottom:6px">entry tactic: ${escapeHtml(graph.entryTactic || 'N/A')} · ${Number(graph.tacticCount) || 0} stage(s) · severity ${escapeHtml(graph.severity || 'info')} · score ${Number(graph.score) || 0} · ${Number(graph.alertCount) || 0} alert(s) · state ${escapeHtml(graph.state || 'closed')}</div>`;
        const rows = nodes.map((node, index) => {
            /* edge i connects node i -> node i+1 (buildGraph orders nodes first-sighting first) */
            const edge = edges[index];
            const connector = edge
                ? `<div class="muted" style="font-size:12px;padding:2px 0 2px 18px">↓ observed succession: ${escapeHtml(edge.fromTactic)} → ${escapeHtml(edge.toTactic)}</div>`
                : '';
            const rule = node.rule ? escapeHtml(node.rule) : 'N/A';
            return `<div class="tree-row" style="padding-left:${12 + 0}px">
                    <strong>${escapeHtml(String(index + 1))}. ${escapeHtml(node.tactic)}</strong>
                    <span class="tree-meta">rule ${rule}</span>
                    <span class="tree-meta">sev ${escapeHtml(node.severity || 'info')}</span>
                    <span class="tree-meta">${Number(node.alertCount) || 0} alert(s)</span>
                    <div class="muted" style="font-size:12px;margin-top:2px">${escapeHtml(formatFiletime(node.firstSeen100ns))} → ${escapeHtml(formatFiletime(node.lastSeen100ns))}</div>
                </div>${connector}`;
        }).join('');
        return header + rows;
    }
    async function loadIncidentChain(id) {
        const requestId = ++incidentChainRequestId;
        const chain = document.getElementById('incidentChainBody');
        if (!chain) return;
        try {
            const response = await request(`/api/incidents/${encodeURIComponent(id)}/graph`);
            if (requestId !== incidentChainRequestId || incidentDetailId !== id) return;
            if (response.status === 401) { setStatus('read auth required', false); throw new Error('read API key required'); }
            const data = await response.json().catch(() => ({}));
            if (requestId !== incidentChainRequestId || incidentDetailId !== id) return;
            if (!response.ok) throw new Error(apiErrorMessage(data, `HTTP ${response.status}`));
            chain.classList.remove('muted');
            chain.innerHTML = killChainHtml(data.graph);
        } catch (error) {
            if (requestId === incidentChainRequestId && incidentDetailId === id)
                chain.innerHTML = `<span class="muted">Attack chain unavailable: ${escapeHtml(error.message)}</span>`;
        }
    }
    async function showIncidentDetail(index) {
        const incident = incidentItems[index];
        if (!incident || !incident.id) return;
        const requestId = ++incidentDetailRequestId;
        ++incidentChainRequestId;
        incidentDetailId = incident.id;
        const panel = document.getElementById('incidentDetail');
        const heading = document.getElementById('incidentDetailHeading');
        const body = document.getElementById('incidentDetailBody');
        const chain = document.getElementById('incidentChainBody');
        if (!panel || !body) return;
        panel.style.display = 'block';
        if (heading) heading.textContent = `Incident ${incident.id}`;
        body.innerHTML = '<span class="muted">Loading incident detail...</span>';
        if (chain) { chain.classList.add('muted'); chain.textContent = 'Loading attack chain...'; }
        try {
            const response = await request(`/api/incidents/${encodeURIComponent(incident.id)}`);
            if (requestId !== incidentDetailRequestId || incidentDetailId !== incident.id) return;
            if (response.status === 401) { setStatus('read auth required', false); throw new Error('read API key required'); }
            const data = await response.json().catch(() => ({}));
            if (requestId !== incidentDetailRequestId || incidentDetailId !== incident.id) return;
            if (!response.ok) throw new Error(apiErrorMessage(data, `HTTP ${response.status}`));
            body.classList.remove('muted');
            body.innerHTML = incidentDetailHtml(data.incident || incident);
            loadIncidentChain(incident.id);
        } catch (error) {
            if (requestId === incidentDetailRequestId && incidentDetailId === incident.id)
                body.innerHTML = `<span class="muted">Incident detail unavailable: ${escapeHtml(error.message)}</span>`;
        }
    }
    function closeIncidentDetail() {
        ++incidentDetailRequestId;
        ++incidentChainRequestId;
        incidentDetailId = '';
        const panel = document.getElementById('incidentDetail');
        if (panel) panel.style.display = 'none';
    }

    /* ---- Wiring ---- */
    function incidentFiltersChanged() {
        incidentsOffset = 0;
        loadIncidents();
    }
    function refreshIncidents() {
        incidentsOffset = 0;
        loadIncidents();
        loadIncidentSummary();
    }
    function wireIncidentsTab() {
        const tab = document.querySelector('[data-view="incidentsView"]');
        /* the main inline script already registered activateTab on .tab buttons;
         * this extra listener only triggers the data load for this view */
        if (tab) tab.addEventListener('click', refreshIncidents);
        const refresh = document.getElementById('incidentsRefresh');
        if (refresh) refresh.addEventListener('click', refreshIncidents);
        for (const id of ['incidentSeverity', 'incidentState']) {
            const element = document.getElementById(id);
            if (element) element.addEventListener('change', incidentFiltersChanged);
        }
        for (const id of ['incidentHost', 'incidentTactic', 'incidentMinScore', 'incidentSearch']) {
            const element = document.getElementById(id);
            if (element) element.addEventListener('keydown', event => { if (event.key === 'Enter') incidentFiltersChanged(); });
        }
        const prev = document.getElementById('incidentsPrev');
        const next = document.getElementById('incidentsNext');
        if (prev) prev.addEventListener('click', () => incidentsPage(-1));
        if (next) next.addEventListener('click', () => incidentsPage(1));
        const close = document.getElementById('incidentDetailClose');
        if (close) close.addEventListener('click', closeIncidentDetail);
        const listBody = document.getElementById('incidentList');
        if (listBody) listBody.addEventListener('click', event => {
            const row = event.target.closest('tr[data-incident-index]');
            if (row) showIncidentDetail(Number(row.dataset.incidentIndex));
        });
        /* deep link: index.html's initialize() view map does not know this view,
         * so handle ?view=incidents here; tab.click() fires both listeners */
        if (new URLSearchParams(location.search).get('view') === 'incidents' && tab) tab.click();
    }
    wireIncidentsTab();
})();
