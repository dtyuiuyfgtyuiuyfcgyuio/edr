# Console Investigation MCP

A dependency-free MCP server that exposes the EDR web console's **read-only**
investigation surface to an assistant. Hand-rolled JSON-RPC 2.0 over stdio, no
third-party packages — same shape as `tools/ghidra-mcp`.

It wraps `console/server.js` and nothing else. It does not detect, does not
detect anything new, and does not execute responses.

## Read-only by construction

Only `read`-role console routes are exposed. There is deliberately no tool for
`/api/response/*` (terminate, quarantine, isolate, delete_file, suspend, resume),
none for triage writes, and none for playbook execution. Those are the console's
admin surface; this server has no code path to them at all, so no amount of model
misjudgment can reach them. The test suite asserts the absence.

Containment stays a human decision in the console UI, which is the same posture
the agent itself takes (all response actions default to dry-run).

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `EDR_CONSOLE_URL` | `http://127.0.0.1:8080` | Console base URL. Must be loopback unless `EDR_CONSOLE_ALLOW_REMOTE=1`. |
| `EDR_READ_API_KEY` | unset | Sent as the raw `x-api-key` header. There is no Bearer scheme. |
| `EDR_CONSOLE_TIMEOUT_MS` | `15000` | Per-request timeout. |
| `EDR_CONSOLE_ALLOW_REMOTE` | unset | Set to `1` to allow a non-loopback console host. |

The console binds `127.0.0.1:8080` by default and itself refuses non-loopback
binding without ingest and read keys (`console/server.js:3092-3106`). This server
mirrors that fail-closed check: a remote host is an error unless you say
otherwise.

Give it the **`read`** key only. A read key cannot satisfy an admin route and an
admin key is not needed for anything here. The key is never logged and never
echoed back in a tool result.

## Run it

```powershell
cd console\mcp
npm start          # speaks MCP on stdio
npm test           # node --test
```

## Tests

`test/server.test.mjs` starts the **real** `console/server.js` via
`createRuntime()` on an ephemeral port with a temporary `dataDir`, then drives the
handlers against it. The point is drift detection: if a route is renamed, a
parameter is changed, or an `exactKeys` allow-list tightens, this fails here
rather than at runtime. The rule-coverage tests point `EDR_RULES_PATH` at the
repository's real `rules/rules.json` so they exercise a populated 466-rule report.

## Tools (25)

**Orientation**
- `edr_console_status` — reachability, counts, top rules, whether the read key is configured.

**Alerts**
- `edr_search_alerts` — filter by severity, status, priority, rule, tactic, assignee, text, time window. Returns `case_id`.
- `edr_alert_timeline` — surrounding raw events for one case.
- `edr_alert_activity` — triage history and actors for one case.
- `edr_similar_alerts` — same rule and endpoint, to tell a burst from an outlier.

**Endpoints and telemetry**
- `edr_list_endpoints`, `edr_endpoint_detail` — inventory, risk, isolation state, recency.
- `edr_search_events` — raw events by type, endpoint, process or PID.
- `edr_process_tree` — parent/child ancestry, filtered client-side by `source_id`.
- `edr_process_timeline` — everything one process did.
- `edr_list_processes` — observed processes with command lines.

**Incidents**
- `edr_list_incidents`, `edr_incident_detail`, `edr_incident_graph`, `edr_incident_summary`.

**Coverage and rules**
- `edr_rule_coverage`, `edr_rule_gaps` — ATT&CK blind spots against `rules/rules.json` and `console/technique_config_map.js`.
- `edr_rule_stats` — per-rule hit counts and breakdowns.

**Stats**
- `edr_stats`, `edr_stats_health`, `edr_stats_timeseries`, `edr_stats_mitre`.

**Intel, evidence, integrity**
- `edr_threat_intel_lookup` — hash / IP / domain via the console's configured provider.
- `edr_list_evidence` — artifacts snapshotted before an automatic response.
- `edr_audit_chain_verify` — SHA-256 hash chain over `alerts`, `incidents` or `response`.

## Behaviours worth knowing

These reflect real properties of `console/server.js`, not preferences.

**Incident integrity is load-bearing.** The console returns **503** when the
incident ledger's hash chain is broken or its tail is truncated
(`incidents.js:53-61`, `server.js:1977-1981`). A missing ledger returns 200 with
`status: "missing"`. The incident tools surface that as
`{unavailable, reason, integrity}` instead of throwing, and the server's
`initialize` instructions tell the model to call the data untrusted rather than
reason from it. The chain has no external trusted anchor — anyone with write
access to the JSONL can recompute or truncate it — so `edr_audit_chain_verify`
is the only check available, and it only proves internal consistency.

**`/api/incidents` pagination is inverted.** Incidents are sorted newest-first
(`incidents.js:194`) but the route slices from the tail without reversing
(`server.js:2022-2023`), so `offset=0` returns the **oldest** page. `/api/alerts`
does reverse and behaves the conventional way. `edr_list_incidents` returns a
`paginationNote` saying so rather than papering over it.

**`/api/process-tree` takes no parameters** and returns every root unfiltered.
`edr_process_tree` filters by `source_id` client-side and says so in its `note`.

**`exactKeys` routes reject unknown query parameters.** `/api/rules/coverage*`,
`/api/evidence`, `/api/audit/chain/verify` and others answer 400 for extra keys.
Unknown arguments are rejected in the handler before the request is built, so a
model typo becomes a precise message instead of an opaque 400.

**A missing rule catalog is a state, not an error.** Without `EDR_RULES_PATH` the
coverage routes answer 503. `edr_rule_coverage` and `edr_rule_gaps` return
`{unavailable: true, reason, hint}` instead of throwing.

**`/api/threat-intel/lookup` answers HTTP 200 even on failure**, signalling the
problem in an `error` field (`server.js:581-630`). `edr_threat_intel_lookup`
rewrites that as `{failed: true, ...}`.

**A wrong API key surfaces loudly.** A 401 becomes a thrown `ConsoleError` rather
than an empty result, so "no data" is never silently confused with "not
authorised". Repeat query parameters are refused client-side because Express turns
them into arrays and the console's `Number.parseInt` then throws.

## Security boundaries

- Read-only; no response, triage or playbook routes.
- Loopback-only console by default; remote requires an explicit opt-in.
- `EDR_READ_API_KEY` only, sent as a raw `x-api-key` value; never logged, never returned.
- All string and integer arguments are bounded before use; unknown arguments rejected.
- Network calls retried only on transport errors, never on an HTTP status.
- Query-string API keys are refused, matching the console's own rule.
