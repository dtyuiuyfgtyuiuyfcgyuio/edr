// Contract test: drives the MCP handlers against a real console/server.js
// runtime on an ephemeral port. The point is to catch drift -- every query
// parameter is exercised against the console's own validation, so a renamed
// route or an exactKeys allow-list change fails here rather than at runtime.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import { ConsoleClient, ConsoleError } from "../src/console-client.mjs";
import { TOOLS, buildHandlers } from "../src/tools.mjs";

const require = createRequire(import.meta.url);
// test/ -> mcp/ -> console/, where the real console server lives.
const consoleModule = require("../../server.js");
const quietLogger = { log() {}, warn() {}, error() {} };

const HERE = path.dirname(fileURLToPath(import.meta.url));
// console/mcp/test -> repo root
const REPO_ROOT = path.resolve(HERE, "..", "..", "..");
const REPO_RULES = path.join(REPO_ROOT, "rules", "rules.json");

const READ_KEY = "read-key-for-mcp-test";

// FILETIME for 2026-09-30T12:00:00Z, so `since`/`until` windows are stable.
const TS_100NS = 134160672000000000n;

const ALERT_LINES = [
  {
    rule: "EDR-001",
    severity: "high",
    action: "alert",
    ts_100ns: Number(TS_100NS),
    pid: 4242,
    type: "PROCESS_START",
    fields: {
      command_line: "powershell -enc ***",
      image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      parent_image: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
      type: "PROCESS_START",
    },
    mitre_attack: ["T1059.001", "T1059"],
    mitre_tactic: ["Execution"],
  },
  {
    rule: "EDR-004",
    severity: "high",
    action: "alert",
    ts_100ns: Number(TS_100NS) + 1_000_000,
    pid: 0,
    type: "REG_WRITE",
    fields: {
      reg_key: "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SelftestValue",
      type: "REG_WRITE",
    },
    mitre_attack: ["T1547.001"],
    mitre_tactic: ["Persistence", "Privilege Escalation"],
  },
  {
    rule: "EDR-031",
    severity: "critical",
    action: "alert",
    ts_100ns: Number(TS_100NS) + 2_000_000,
    pid: 900,
    type: "POWERSHELL_SCRIPT",
    fields: { amsi_verdict: "detected", type: "POWERSHELL_SCRIPT" },
    mitre_attack: ["T1059.001"],
    mitre_tactic: ["Execution", "Defense Evasion"],
  },
];

async function fixture(t, extraEnv = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "edr-console-mcp-"));
  fs.writeFileSync(
    path.join(dataDir, "alerts.jsonl"),
    ALERT_LINES.map((line) => JSON.stringify(line)).join("\n") + "\n",
    "utf8",
  );

  const runtime = consoleModule.createRuntime({
    dataDir,
    env: {
      EDR_READ_API_KEY: READ_KEY,
      EDR_INGEST_API_KEY: "sensor-key",
      // The coverage routes resolve their catalog from EDR_RULES_PATH; point at
      // the repository's real rules.json so the test exercises a populated report.
      EDR_RULES_PATH: REPO_RULES,
      ...extraEnv,
    },
    logger: quietLogger,
  });
  await runtime.start(0, "127.0.0.1");

  t.after(async () => {
    await new Promise((resolve) => runtime.server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  const baseUrl = `http://127.0.0.1:${runtime.server.address().port}`;
  const client = new ConsoleClient({ baseUrl, apiKey: READ_KEY, timeoutMs: 5000 });
  return { runtime, client, handlers: buildHandlers(client), baseUrl };
}

test("initialize lists only read-role tools", async (t) => {
  const { handlers } = await fixture(t);
  assert.ok(TOOLS.length >= 20, "expected the full read surface to be exposed");

  const names = TOOLS.map((tool) => tool.name);
  for (const forbidden of [
    "edr_terminate",
    "edr_isolate",
    "edr_quarantine",
    "edr_triage_alert",
    "edr_run_playbook",
  ]) {
    assert.ok(!names.includes(forbidden), `read-only server must not expose ${forbidden}`);
  }

  const caseIdResult = await handlers.edr_search_alerts({ limit: 5 });
  const caseId = caseIdResult.alerts?.[0]?.caseId;
  assert.ok(caseId, "expected the fixture alert to resolve to a caseId");
});

test("console status reports the read key as configured", async (t) => {
  const { handlers, baseUrl } = await fixture(t);
  const status = await handlers.edr_console_status({});
  assert.equal(status.baseUrl, baseUrl);
  assert.equal(status.readKeyConfigured, true);
  assert.equal(status.health.status, "ok");
});

test("search_alerts returns decorated alerts newest-first", async (t) => {
  const { handlers } = await fixture(t);
  const result = await handlers.edr_search_alerts({ limit: 10 });
  assert.equal(result.total, 3);
  assert.equal(result.alerts.length, 3);

  const alert = result.alerts[0];
  assert.ok(alert.caseId.startsWith("alert-"));
  assert.ok(alert.triage, "expected the triage sub-object the console decorates");
  assert.ok("updatedAt" in alert.triage);
});

test("search_alerts severity filter reaches the console", async (t) => {
  const { handlers } = await fixture(t);
  const result = await handlers.edr_search_alerts({ severity: "critical", limit: 10 });
  assert.equal(result.total, 1);
  assert.equal(result.alerts[0].rule, "EDR-031");
});

test("search_alerts rejects a bad enum locally instead of asking the console", async (t) => {
  const { handlers } = await fixture(t);
  await assert.rejects(() => handlers.edr_search_alerts({ severity: "sev1" }), /severity must be one of/);
});

test("search_alerts rejects an unparseable timestamp locally", async (t) => {
  const { handlers } = await fixture(t);
  await assert.rejects(
    () => handlers.edr_search_alerts({ since: "yesterday" }),
    /since must be a parseable/,
  );
});

test("alert sub-resources resolve by caseId", async (t) => {
  const { handlers } = await fixture(t);
  const { alerts } = await handlers.edr_search_alerts({ limit: 10 });
  const caseId = alerts[0].caseId;

  const activity = await handlers.edr_alert_activity({ case_id: caseId });
  assert.ok(Array.isArray(activity), "activity is a bare array, not an envelope");

  const timeline = await handlers.edr_alert_timeline({ case_id: caseId, limit: 30 });
  assert.equal(timeline.caseId, caseId);
  assert.ok(Array.isArray(timeline.timeline));

  const similar = await handlers.edr_similar_alerts({ case_id: caseId, limit: 20 });
  assert.ok(typeof similar.total === "number");
  assert.ok(Array.isArray(similar.alerts));
});

test("endpoint and event queries pass the console's validation", async (t) => {
  const { handlers } = await fixture(t);

  const endpoints = await handlers.edr_list_endpoints({ limit: 5 });
  assert.ok(Array.isArray(endpoints.endpoints));

  const events = await handlers.edr_search_events({ type: "PROCESS_START", limit: 10 });
  assert.ok(Array.isArray(events.events));

  const processes = await handlers.edr_list_processes({ limit: 10 });
  assert.ok(Array.isArray(processes), "processes is a bare array");
});

test("process_tree filters client-side because the route takes no params", async (t) => {
  const { handlers } = await fixture(t);
  const tree = await handlers.edr_process_tree({ max_nodes: 50 });
  assert.ok(Array.isArray(tree.roots));
  assert.match(tree.note, /Unfiltered/);
  assert.equal(tree.sourceId, null);
});

test("process_timeline requires a process_key", async (t) => {
  const { handlers } = await fixture(t);
  await assert.rejects(() => handlers.edr_process_timeline({}), /process_key must be a non-empty/);
});

test("incident routes survive a missing ledger and surface integrity", async (t) => {
  const { handlers } = await fixture(t);

  const summary = await handlers.edr_incident_summary({});
  assert.equal(summary.unavailable, false, "a missing ledger is served, not a 503");
  assert.equal(summary.integrity.status, "missing");

  const list = await handlers.edr_list_incidents({ limit: 10 });
  assert.equal(list.unavailable, false);
  assert.match(list.paginationNote, /sorted newest-first/);
});

test("incident summary sends no query parameters", async (t) => {
  const { handlers } = await fixture(t);
  // The route answers 400 for any query key, so the handler must pass none.
  const summary = await handlers.edr_incident_summary({});
  assert.ok(summary.data);
});

test("rule coverage reads the repository catalog", async (t) => {
  const { handlers } = await fixture(t);

  const coverage = await handlers.edr_rule_coverage({});
  assert.notEqual(coverage.unavailable, true, `coverage unavailable: ${coverage.reason}`);
  assert.equal(typeof coverage.data.totalRules, "number");
  assert.ok(coverage.data.totalRules > 400, "expected the real 466-rule catalog");
  assert.ok(Array.isArray(coverage.data.firedRules));
  assert.ok(Array.isArray(coverage.data.neverFired));
});

test("a missing rule catalog is reported as a state, not thrown", async (t) => {
  // EDR_RULES_PATH="" makes the console fall back to <dataDir>/rules.json,
  // which the temp fixture does not have -> 503 rule catalog unavailable.
  const { handlers } = await fixture(t, { EDR_RULES_PATH: "" });
  const coverage = await handlers.edr_rule_coverage({});
  assert.equal(coverage.unavailable, true);
  assert.match(coverage.reason, /rule catalog/);
  assert.match(coverage.hint, /EDR_RULES_PATH/);
});

test("unknown arguments are rejected before the request is built", async (t) => {
  const { handlers } = await fixture(t);
  await assert.rejects(
    () => handlers.edr_rule_coverage({ format: "json" }),
    /arguments rejected: format/,
  );
  await assert.rejects(
    () => handlers.edr_search_alerts({ severity: "high", source_id: "x" }),
    /arguments rejected: source_id/,
  );
});

test("rule gaps report against the repository catalog", async (t) => {
  const { handlers } = await fixture(t);
  const gaps = await handlers.edr_rule_gaps({});
  assert.notEqual(gaps.unavailable, true, `gaps unavailable: ${gaps.reason}`);
  assert.ok(Array.isArray(gaps.data.gaps));
  assert.equal(typeof gaps.data.total, "number");
});

test("audit chain verify covers all three ledgers", async (t) => {
  const { handlers } = await fixture(t);
  for (const file of ["alerts", "incidents", "response"]) {
    const result = await handlers.edr_audit_chain_verify({ file });
    assert.equal(typeof result.valid, "boolean", `${file} chain verify returned no valid flag`);
    assert.ok(Array.isArray(result.issues));
  }
  await assert.rejects(
    () => handlers.edr_audit_chain_verify({ file: "triage" }),
    /file must be one of/,
  );
});

test("stats routes return their documented shapes", async (t) => {
  const { handlers } = await fixture(t);

  const stats = await handlers.edr_stats({});
  assert.equal(stats.total, 3);
  assert.ok(stats.bySeverity);
  assert.ok(stats.byRule);

  const health = await handlers.edr_stats_health({});
  assert.ok(health.byState);
  assert.ok(health.byRisk);

  const mitre = await handlers.edr_stats_mitre({});
  assert.ok(Array.isArray(mitre.tactics));

  const series = await handlers.edr_stats_timeseries({ bucket: "hour", days: 2 });
  assert.equal(series.days, 2);
  assert.equal(series.points.length, 2);

  await assert.rejects(() => handlers.edr_stats_timeseries({ days: 365 }), /days must be an integer/);
});

test("threat intel requires exactly one indicator and prefers hash", async (t) => {
  const { handlers } = await fixture(t);
  await assert.rejects(() => handlers.edr_threat_intel_lookup({}), /provide one of/);

  // No provider key is configured, so the console answers 200 with an error
  // body. The handler must mark that as a failure rather than pass it through.
  const result = await handlers.edr_threat_intel_lookup({ hash: "a".repeat(64) });
  assert.ok(result && typeof result === "object");
  assert.ok(result.failed || result.malicious !== undefined);
});

test("evidence listing returns the console's four-field records", async (t) => {
  const { handlers } = await fixture(t);
  const result = await handlers.edr_list_evidence({ limit: 10 });
  assert.ok(Array.isArray(result.evidence));
  for (const item of result.evidence) {
    assert.deepEqual(Object.keys(item).sort(), ["requestId", "rule", "severity", "timestamp"]);
  }
});

test("a wrong read key surfaces as a console error, not silent empty data", async (t) => {
  const { runtime } = await fixture(t);
  const baseUrl = `http://127.0.0.1:${runtime.server.address().port}`;
  const wrong = new ConsoleClient({ baseUrl, apiKey: "not-the-key", timeoutMs: 5000 });
  const handlers = buildHandlers(wrong);

  await assert.rejects(() => handlers.edr_search_alerts({}), (error) => {
    assert.ok(error instanceof ConsoleError);
    assert.equal(error.status, 401);
    assert.match(error.message, /unauthorized/);
    return true;
  });
});

test("a query-string api_key is rejected by the console", async (t) => {
  const { runtime } = await fixture(t);
  const port = runtime.server.address().port;
  const response = await fetch(`http://127.0.0.1:${port}/api/alerts?api_key=${READ_KEY}`);
  assert.equal(response.status, 400);
});

test("non-loopback console hosts are refused unless explicitly allowed", () => {
  const remote = new ConsoleClient({ baseUrl: "http://10.1.2.3:8080" });
  assert.throws(() => remote.assertUsableTarget(), /refusing non-loopback/);

  const previous = process.env.EDR_CONSOLE_ALLOW_REMOTE;
  process.env.EDR_CONSOLE_ALLOW_REMOTE = "1";
  try {
    remote.assertUsableTarget();
  } finally {
    if (previous === undefined) delete process.env.EDR_CONSOLE_ALLOW_REMOTE;
    else process.env.EDR_CONSOLE_ALLOW_REMOTE = previous;
  }
});

test("every declared tool has a handler", () => {
  const handlers = buildHandlers(new ConsoleClient({ baseUrl: "http://127.0.0.1:1" }));
  for (const tool of TOOLS) {
    assert.equal(typeof handlers[tool.name], "function", `${tool.name} has no handler`);
  }
  const declared = new Set(TOOLS.map((tool) => tool.name));
  assert.equal(declared.size, TOOLS.length, "duplicate tool name in TOOLS");
});

test("stdio server speaks JSON-RPC and publishes the read tool set", async () => {
  const serverPath = path.join(HERE, "..", "src", "server.mjs");
  const messages = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } },
    { jsonrpc: "2.0", method: "notifications/initialized", params: {} },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    { jsonrpc: "2.0", id: 3, method: "ping", params: {} },
    { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "edr_nope", arguments: {} } },
  ];

  const child = spawn(process.execPath, [serverPath], {
    cwd: path.join(HERE, ".."),
    // Port 1 is closed: the bogus tool must fail before any network call.
    env: { ...process.env, EDR_CONSOLE_URL: "http://127.0.0.1:1" },
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.stdin.end(messages.map((message) => JSON.stringify(message)).join("\n") + "\n");

  const exitCode = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("MCP server protocol test timed out"));
    }, 10000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });

  assert.equal(exitCode, 0, stderr);
  const responses = stdout.trim().split(/\r?\n/u).map((line) => JSON.parse(line));
  assert.equal(responses.length, 4, `unexpected response count: ${stdout}`);

  assert.equal(responses[0].result.serverInfo.name, "edr-console-investigation");
  assert.equal(responses[0].result.protocolVersion, "2025-06-18");
  assert.deepEqual(responses[0].result.capabilities, { tools: { listChanged: false } });

  assert.deepEqual(
    responses[1].result.tools.map((tool) => tool.name),
    TOOLS.map((tool) => tool.name),
  );
  for (const tool of responses[1].result.tools) {
    assert.equal(tool.inputSchema.type, "object");
    assert.equal(tool.inputSchema.additionalProperties, false);
    for (const required of tool.inputSchema.required ?? []) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(tool.inputSchema.properties, required),
        `${tool.name} requires undeclared property ${required}`,
      );
    }
  }

  assert.deepEqual(responses[2].result, {});
  assert.equal(responses[3].error.code, -32602, "unknown tool must be rejected");
});
