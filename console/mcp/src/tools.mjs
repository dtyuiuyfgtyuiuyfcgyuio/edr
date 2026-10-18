// Tool catalogue and handlers for the console MCP server.
//
// Kept separate from server.mjs because server.mjs attaches stdin handlers at
// module load; importing it from a test would hijack the test process's stdin.
// Same split as tools/ghidra-mcp, which unit-tests validation.mjs and spawns
// server.mjs only for the protocol test.

import { ConsoleError } from "./console-client.mjs";
import {
  INCIDENT_STATES,
  LEDGER_FILES,
  PRIORITIES,
  SEVERITIES,
  TELEMETRY_STATES,
  TRIAGE_STATUSES,
  buildQuery,
  boundedInteger,
  optionalCaseId,
  optionalEnum,
  optionalString,
  optionalTimestamp,
  rejectUnknownArgs,
  requireObject,
  requireString,
} from "./validation.mjs";

// console/server.js LIMITS.queryLimit
export const QUERY_LIMIT_MAX = 1000;

const pagination = {
  limit: {
    type: "integer",
    description: `Maximum records to return (console clamps to 1..${QUERY_LIMIT_MAX}).`,
    minimum: 1,
    maximum: QUERY_LIMIT_MAX,
  },
  offset: {
    type: "integer",
    description:
      "Record offset. Note: /api/alerts counts from the newest end, while " +
      "/api/incidents sorts newest-first but slices from the oldest end.",
    minimum: 0,
  },
};

const caseIdProperty = {
  type: "string",
  description: "Case ID from edr_search_alerts (alert-<32 hex chars>).",
  minLength: 1,
  maxLength: 64,
};

export const TOOLS = [
  {
    name: "edr_console_status",
    description:
      "Check that the EDR console is reachable and report what it holds: uptime, " +
      "alert and event counts, endpoint telemetry state, top rules, and whether the " +
      "read API key is configured. Call this first when queries return nothing.",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
  },
  {
    name: "edr_search_alerts",
    description:
      "Search the alert ledger. Start investigations here and cite the case_id it " +
      "returns. Returns newest-first; offset 0 is the newest page.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        severity: { type: "string", enum: SEVERITIES },
        status: { type: "string", enum: TRIAGE_STATUSES },
        priority: { type: "string", enum: PRIORITIES },
        rule: { type: "string", description: "Exact rule ID, e.g. EDR-001.", maxLength: 256 },
        tactic: { type: "string", description: "ATT&CK tactic name.", maxLength: 64 },
        assignee: { type: "string", maxLength: 256 },
        q: {
          type: "string",
          description: "Substring over rule, sourceId, id, or event summary.",
          maxLength: 256,
        },
        since: { type: "string", description: "ISO-8601 lower bound.", maxLength: 64 },
        until: { type: "string", description: "ISO-8601 upper bound.", maxLength: 64 },
        ...pagination,
      },
    },
  },
  {
    name: "edr_alert_timeline",
    description:
      "Raw events from the same endpoint surrounding one alert, split before and " +
      "after the detection and returned in ascending chronological order.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["case_id"],
      properties: {
        case_id: caseIdProperty,
        limit: { ...pagination.limit, default: 30 },
      },
    },
  },
  {
    name: "edr_alert_activity",
    description:
      "Triage history for one alert case: status, note, assignee, priority, timestamp " +
      "and actor, newest first. Shows what an analyst already did with this alert.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["case_id"],
      properties: { case_id: caseIdProperty },
    },
  },
  {
    name: "edr_similar_alerts",
    description:
      "Alerts sharing the same rule and source endpoint as one case. Use it to judge " +
      "whether a finding is isolated or part of a burst.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["case_id"],
      properties: {
        case_id: caseIdProperty,
        limit: { ...pagination.limit, default: 20 },
      },
    },
  },
  {
    name: "edr_list_endpoints",
    description:
      "Endpoint inventory with alert counts, risk rating, agent last-seen state and " +
      "telemetry health. Sorted by risk then recency. source_id is the identifier used " +
      "by every other endpoint tool.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        state: { type: "string", enum: TELEMETRY_STATES },
        q: { type: "string", description: "Substring over sourceId or host.", maxLength: 256 },
        limit: { ...pagination.limit, default: 200 },
      },
    },
  },
  {
    name: "edr_endpoint_detail",
    description:
      "One endpoint in full: OS, agent version, isolation state, plus its 25 most " +
      "recent alerts and 50 most recent events.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["source_id"],
      properties: { source_id: { type: "string", maxLength: 256 } },
    },
  },
  {
    name: "edr_search_events",
    description:
      "Raw telemetry events by type, endpoint, process or PID. Types include " +
      "PROCESS_START, REG_WRITE, FILE_CREATE, NET_CONNECT, DNS_QUERY, IMAGE_LOAD, " +
      "PROCESS_ACCESS, LOGON, NAMED_PIPE and others. Each record carries a summary.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        type: { type: "string", maxLength: 128 },
        source_id: { type: "string", maxLength: 256 },
        process_key: { type: "string", maxLength: 1024 },
        pid: { type: "integer", minimum: 0, maximum: 4294967295 },
        q: { type: "string", maxLength: 256 },
        since: { type: "string", maxLength: 64 },
        until: { type: "string", maxLength: 64 },
        limit: { ...pagination.limit, default: 200 },
      },
    },
  },
  {
    name: "edr_process_tree",
    description:
      "Process ancestry as parent/child nodes. The console route returns every root " +
      "unfiltered, so this tool filters client-side by source_id. Note that PIDs " +
      "recycle: correlate with process_key or a timestamp before concluding ancestry.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        source_id: { type: "string", description: "Filter roots to one endpoint.", maxLength: 256 },
        max_nodes: { type: "integer", minimum: 1, maximum: 2000, default: 200 },
      },
    },
  },
  {
    name: "edr_process_timeline",
    description:
      "Every event for one process key, oldest first. Requires process_key from " +
      "edr_list_processes or edr_search_events; this is the strongest single view " +
      "of what a process actually did.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["process_key"],
      properties: {
        process_key: { type: "string", maxLength: 1024 },
        limit: { ...pagination.limit, default: 500 },
      },
    },
  },
  {
    name: "edr_process_hunt",
    description:
      "Bounded read-only investigation of a process and its descendants on one " +
      "endpoint, using canonical process keys. Returns flat nodes, recent events " +
      "and explicit truncation/completeness metadata for the retained window.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["process_key"],
      properties: {
        process_key: { type: "string", minLength: 1, maxLength: 1024 },
        max_nodes: { type: "integer", minimum: 1, maximum: 1000, default: 200 },
        max_depth: { type: "integer", minimum: 1, maximum: 64, default: 16 },
        event_limit: { type: "integer", minimum: 1, maximum: 1000, default: 500 },
      },
    },
  },
  {
    name: "edr_list_processes",
    description:
      "Observed processes with parent key, PID, image, command line, start time, " +
      "last-seen and event count, most recent first.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        source_id: { type: "string", maxLength: 256 },
        limit: { ...pagination.limit, default: 200 },
      },
    },
  },
  {
    name: "edr_list_incidents",
    description:
      "Correlated multi-alert incidents with score, stage count and tactic spread. " +
      "Rejects queries when the incident ledger's audit chain is broken and returns " +
      "the integrity report instead of data -- treat that response as no evidence.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        severity: { type: "string", enum: SEVERITIES },
        state: { type: "string", enum: INCIDENT_STATES },
        host: { type: "string", maxLength: 256 },
        tactic: { type: "string", maxLength: 64 },
        q: { type: "string", maxLength: 256 },
        min_score: { type: "integer", minimum: 0, maximum: 100 },
        limit: { ...pagination.limit, default: 50 },
        offset: pagination.offset,
      },
    },
  },
  {
    name: "edr_incident_detail",
    description:
      "One incident in full: score, contributing rules, tactics and per-stage detail. " +
      "Requires integrity status to be verified or missing before the data is trusted.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["incident_id"],
      properties: { incident_id: { type: "string", maxLength: 64 } },
    },
  },
  {
    name: "edr_incident_graph",
    description:
      "Attack-chain graph for one incident: tactic nodes in first-seen order joined " +
      "by a linear edge chain. Useful for narrating how a compromise progressed.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["incident_id"],
      properties: { incident_id: { type: "string", maxLength: 64 } },
    },
  },
  {
    name: "edr_incident_summary",
    description:
      "Counts and tactic distribution across all incidents, plus the ledger integrity " +
      "status. Cheap health check before trusting anything incident-shaped.",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
  },
  {
    name: "edr_rule_coverage",
    description:
      "ATT&CK coverage report: which rules in rules.json have ever fired, which have " +
      "not, unmapped rules, and reference gaps against console/technique_config_map.js. " +
      "Finds blind spots rather than incidents.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        severity: { type: "string", enum: SEVERITIES },
        tactic: { type: "string", maxLength: 64 },
        since: { type: "string", maxLength: 64 },
      },
    },
  },
  {
    name: "edr_rule_gaps",
    description:
      "ATT&CK techniques with no enabled detector, listing the config key and detector " +
      "file each one expects. Use it to plan new detection work.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        severity: { type: "string", enum: SEVERITIES },
        tactic: { type: "string", maxLength: 64 },
        since: { type: "string", maxLength: 64 },
      },
    },
  },
  {
    name: "edr_rule_stats",
    description:
      "Per-rule alert statistics: hit count, severity/status/priority/source " +
      "breakdowns, MITRE mapping and open-alert count.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        q: { type: "string", maxLength: 256 },
        severity: { type: "string", enum: SEVERITIES },
        ...pagination,
      },
    },
  },
  {
    name: "edr_stats",
    description:
      "Global counters: total and open alerts, endpoint and event counts, breakdowns " +
      "by severity, rule, status, tactic and source. No parameters.",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
  },
  {
    name: "edr_stats_health",
    description:
      "Telemetry and alert posture: endpoint recency buckets, risk distribution, open " +
      "alert count, and the worst endpoints by open alerts. Use it to tell an empty " +
      "result set from a dead sensor.",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
  },
  {
    name: "edr_stats_timeseries",
    description:
      "Alert counts bucketed by hour or day over a trailing window, with a per-bucket " +
      "severity split. Use it to spot bursts and quiet periods.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        bucket: { type: "string", enum: ["hour", "day"], default: "hour" },
        days: { type: "integer", minimum: 1, maximum: 90, default: 7 },
      },
    },
  },
  {
    name: "edr_stats_mitre",
    description: "ATT&CK tactic and technique hit counts across all alerts.",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
  },
  {
    name: "edr_threat_intel_lookup",
    description:
      "Look up a hash, IP or domain against the console's configured intelligence " +
      "provider (VirusTotal). Requires EDR_THREAT_INTEL_API_KEY server-side. The " +
      "console answers HTTP 200 even on failure, so check the returned error field.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        hash: { type: "string", maxLength: 64 },
        ip: { type: "string", maxLength: 45 },
        domain: { type: "string", maxLength: 253 },
      },
    },
  },
  {
    name: "edr_audit_chain_verify",
    description:
      "Verify the SHA-256 hash chain over a JSONL ledger (alerts, incidents or " +
      "response). Reports the first broken line and the specific issues. A false " +
      "result means records were altered, reordered or truncated -- do not build " +
      "conclusions from that ledger.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["file"],
      properties: { file: { type: "string", enum: LEDGER_FILES } },
    },
  },
  {
    name: "edr_list_evidence",
    description:
      "Evidence artifacts captured before an automatic response action: request id, " +
      "rule, severity and timestamp, sourced from alert records and the evidence " +
      "directory. Use it to see what the agent snapshotted.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        request_id: { type: "string", maxLength: 256 },
        rule: { type: "string", maxLength: 256 },
        severity: { type: "string", enum: SEVERITIES },
        since: { type: "string", maxLength: 64 },
        until: { type: "string", maxLength: 64 },
        ...pagination,
      },
    },
  },
];

function pageArgs(args, defaultLimit) {
  return {
    limit: boundedInteger(args.limit, "limit", defaultLimit, 1, QUERY_LIMIT_MAX),
    offset: boundedInteger(args.offset, "offset", 0, 0, Number.MAX_SAFE_INTEGER),
  };
}

export function buildHandlers(client) {
  const read = (path, options) => client.retrying(() => client.get(path, options));
  const readIntegrity = (path, options) =>
    client.retrying(() => client.getWithIntegrity(path, options));

  return {
    async edr_console_status() {
      const health = await client.retrying(() => client.health());
      let status = null;
      try {
        status = await read("/api/system/status");
      } catch (error) {
        // /api/health is public, /api/system/status is read-role. A missing or
        // wrong read key is a state worth reporting, not a failure of this tool.
        if (!(error instanceof ConsoleError)) throw error;
        status = { unavailable: true, reason: error.message };
      }
      return {
        baseUrl: client.baseUrl,
        readKeyConfigured: Boolean(client.apiKey),
        health: health.body,
        systemStatus: status,
      };
    },

    async edr_search_alerts(raw) {
      const args = rejectUnknownArgs(requireObject(raw), [
        "severity", "status", "priority", "rule", "tactic", "assignee",
        "q", "since", "until", "limit", "offset",
      ]);
      const query = buildQuery({
        severity: optionalEnum(args.severity, "severity", SEVERITIES),
        status: optionalEnum(args.status, "status", TRIAGE_STATUSES),
        priority: optionalEnum(args.priority, "priority", PRIORITIES),
        rule: optionalString(args.rule, "rule", 256),
        tactic: optionalString(args.tactic, "tactic", 64),
        assignee: optionalString(args.assignee, "assignee", 256),
        q: optionalString(args.q, "q", 256),
        since: optionalTimestamp(args.since, "since"),
        until: optionalTimestamp(args.until, "until"),
        ...pageArgs(args, 100),
      });
      return read("/api/alerts", { query });
    },

    async edr_alert_timeline(raw) {
      const args = requireObject(raw);
      const caseId = optionalCaseId(args.case_id);
      return read(`/api/alerts/${encodeURIComponent(caseId)}/timeline`, {
        query: buildQuery({ limit: boundedInteger(args.limit, "limit", 30, 1, QUERY_LIMIT_MAX) }),
      });
    },

    async edr_alert_activity(raw) {
      const args = requireObject(raw);
      const caseId = optionalCaseId(args.case_id);
      return read(`/api/alerts/${encodeURIComponent(caseId)}/activity`);
    },

    async edr_similar_alerts(raw) {
      const args = requireObject(raw);
      const caseId = optionalCaseId(args.case_id);
      return read(`/api/alerts/${encodeURIComponent(caseId)}/similar`, {
        query: buildQuery({ limit: boundedInteger(args.limit, "limit", 20, 1, QUERY_LIMIT_MAX) }),
      });
    },

    async edr_list_endpoints(raw) {
      const args = rejectUnknownArgs(requireObject(raw), ["state", "q", "limit"]);
      const query = buildQuery({
        state: optionalEnum(args.state, "state", TELEMETRY_STATES),
        q: optionalString(args.q, "q", 256),
        limit: boundedInteger(args.limit, "limit", 200, 1, QUERY_LIMIT_MAX),
      });
      return read("/api/endpoints", { query });
    },

    async edr_endpoint_detail(raw) {
      const args = requireObject(raw);
      const sourceId = requireString(args.source_id, "source_id", 256);
      return read(`/api/endpoints/${encodeURIComponent(sourceId)}`);
    },

    async edr_search_events(raw) {
      const args = rejectUnknownArgs(requireObject(raw), [
        "type", "source_id", "process_key", "pid", "q", "since", "until", "limit",
      ]);
      const query = buildQuery({
        type: optionalString(args.type, "type", 128),
        sourceId: optionalString(args.source_id, "source_id", 256),
        processKey: optionalString(args.process_key, "process_key", 1024),
        pid:
          args.pid === undefined
            ? undefined
            : boundedInteger(args.pid, "pid", undefined, 0, 4294967295),
        q: optionalString(args.q, "q", 256),
        since: optionalTimestamp(args.since, "since"),
        until: optionalTimestamp(args.until, "until"),
        limit: boundedInteger(args.limit, "limit", 200, 1, QUERY_LIMIT_MAX),
      });
      return read("/api/events", { query });
    },

    async edr_process_tree(raw) {
      const args = requireObject(raw);
      const sourceId = optionalString(args.source_id, "source_id", 256);
      const maxNodes = boundedInteger(args.max_nodes, "max_nodes", 200, 1, 2000);
      // Bare array, unfiltered and uncapped server-side (server.js:1306-1316).
      const roots = await read("/api/process-tree");
      if (!Array.isArray(roots)) {
        throw new Error("console returned an unexpected process-tree shape");
      }
      const filtered = sourceId ? roots.filter((node) => node?.sourceId === sourceId) : roots;
      return {
        sourceId: sourceId ?? null,
        rootCount: filtered.length,
        truncated: filtered.length > maxNodes,
        note: sourceId
          ? "Filtered client-side: the console route takes no parameters."
          : "Unfiltered. Pass source_id to narrow to one endpoint.",
        roots: filtered.slice(0, maxNodes),
      };
    },

    async edr_process_timeline(raw) {
      const args = requireObject(raw);
      const processKey = requireString(args.process_key, "process_key", 1024);
      return read("/api/process-timeline", {
        query: buildQuery({
          processKey,
          limit: boundedInteger(args.limit, "limit", 500, 1, QUERY_LIMIT_MAX),
        }),
      });
    },

    async edr_process_hunt(raw) {
      const args = rejectUnknownArgs(requireObject(raw), [
        "process_key", "max_nodes", "max_depth", "event_limit",
      ]);
      return read("/api/process-hunt", {
        query: buildQuery({
          processKey: requireString(args.process_key, "process_key", 1024),
          maxNodes: boundedInteger(args.max_nodes, "max_nodes", 200, 1, QUERY_LIMIT_MAX),
          maxDepth: boundedInteger(args.max_depth, "max_depth", 16, 1, 64),
          eventLimit: boundedInteger(args.event_limit, "event_limit", 500, 1, QUERY_LIMIT_MAX),
        }),
      });
    },

    async edr_list_processes(raw) {
      const args = requireObject(raw);
      const query = buildQuery({
        sourceId: optionalString(args.source_id, "source_id", 256),
        limit: boundedInteger(args.limit, "limit", 200, 1, QUERY_LIMIT_MAX),
      });
      return read("/api/processes", { query });
    },

    async edr_list_incidents(raw) {
      const args = rejectUnknownArgs(requireObject(raw), [
        "severity", "state", "host", "tactic", "q", "min_score", "limit", "offset",
      ]);
      const query = buildQuery({
        severity: optionalEnum(args.severity, "severity", SEVERITIES),
        state: optionalEnum(args.state, "state", INCIDENT_STATES),
        host: optionalString(args.host, "host", 256),
        tactic: optionalString(args.tactic, "tactic", 64),
        q: optionalString(args.q, "q", 256),
        min_score: boundedInteger(args.min_score, "min_score", undefined, 0, 100),
        limit: boundedInteger(args.limit, "limit", 50, 1, QUERY_LIMIT_MAX),
        offset: boundedInteger(args.offset, "offset", 0, 0, Number.MAX_SAFE_INTEGER),
      });
      const result = await readIntegrity("/api/incidents", { query });
      if (result.unavailable) return result;
      // The route sorts newest-first but slices from the tail (server.js:2022-2023),
      // so offset 0 yields the OLDEST page. Say so rather than hide it.
      return {
        ...result,
        paginationNote:
          "incidents are sorted newest-first but sliced from the oldest end; " +
          "offset 0 returns the oldest records in the filtered set.",
        data: result.data,
      };
    },

    async edr_incident_detail(raw) {
      const args = requireObject(raw);
      const incidentId = requireString(args.incident_id, "incident_id", 64);
      return readIntegrity(`/api/incidents/${encodeURIComponent(incidentId)}`);
    },

    async edr_incident_graph(raw) {
      const args = requireObject(raw);
      const incidentId = requireString(args.incident_id, "incident_id", 64);
      return readIntegrity(`/api/incidents/${encodeURIComponent(incidentId)}/graph`);
    },

    async edr_incident_summary() {
      // This route rejects every query parameter (server.js:1975-1994).
      return readIntegrity("/api/incidents/summary");
    },

    async edr_rule_coverage(raw) {
      const args = rejectUnknownArgs(requireObject(raw), ["severity", "tactic", "since"]);
      // Console exactKeys: severity, tactic, since, format.
      const query = buildQuery({
        severity: optionalEnum(args.severity, "severity", SEVERITIES),
        tactic: optionalString(args.tactic, "tactic", 64),
        since: optionalTimestamp(args.since, "since"),
      });
      // A console with no rule catalog answers 503 (server.js:2667-2687). That is
      // a configuration state, not a failed call, so report it instead of throwing.
      const result = await readIntegrity("/api/rules/coverage", { query });
      return result.unavailable
        ? { unavailable: true, reason: result.reason, hint: "Set EDR_RULES_PATH on the console to the repository rules/rules.json." }
        : result;
    },

    async edr_rule_gaps(raw) {
      const args = rejectUnknownArgs(requireObject(raw), ["severity", "tactic", "since"]);
      const query = buildQuery({
        severity: optionalEnum(args.severity, "severity", SEVERITIES),
        tactic: optionalString(args.tactic, "tactic", 64),
        since: optionalTimestamp(args.since, "since"),
      });
      const result = await readIntegrity("/api/rules/coverage/gaps/export", { query });
      return result.unavailable
        ? { unavailable: true, reason: result.reason, hint: "Set EDR_RULES_PATH on the console to the repository rules/rules.json." }
        : result;
    },

    async edr_rule_stats(raw) {
      const args = rejectUnknownArgs(requireObject(raw), ["q", "severity", "limit", "offset"]);
      const query = buildQuery({
        q: optionalString(args.q, "q", 256),
        severity: optionalEnum(args.severity, "severity", SEVERITIES),
        ...pageArgs(args, 100),
      });
      return read("/api/rules", { query });
    },

    async edr_stats() {
      return read("/api/stats");
    },

    async edr_stats_health() {
      return read("/api/stats/health");
    },

    async edr_stats_timeseries(raw) {
      const args = rejectUnknownArgs(requireObject(raw), ["bucket", "days"]);
      const query = buildQuery({
        bucket: optionalEnum(args.bucket, "bucket", ["hour", "day"]),
        days: boundedInteger(args.days, "days", undefined, 1, 90),
      });
      return read("/api/stats/timeseries", { query });
    },

    async edr_stats_mitre() {
      return read("/api/stats/mitre");
    },

    async edr_threat_intel_lookup(raw) {
      const args = rejectUnknownArgs(requireObject(raw), ["hash", "ip", "domain"]);
      const query = buildQuery({
        hash: optionalString(args.hash, "hash", 64),
        ip: optionalString(args.ip, "ip", 45),
        domain: optionalString(args.domain, "domain", 253),
      });
      if (Object.keys(query).length === 0) {
        throw new Error("provide one of: hash, ip, or domain");
      }
      // Console precedence is hash > ip > domain, so never send more than one.
      if (Object.keys(query).length > 1) {
        const kept = ["hash", "ip", "domain"].find((key) => query[key] !== undefined);
        for (const key of Object.keys(query)) if (key !== kept) delete query[key];
      }
      const result = await read("/api/threat-intel/lookup", { query });
      // HTTP 200 on failure; the console signals it in the body.
      return result && typeof result === "object" && result.error
        ? { failed: true, ...result }
        : result;
    },

    async edr_audit_chain_verify(raw) {
      const args = rejectUnknownArgs(requireObject(raw), ["file"]);
      const file = optionalEnum(args.file, "file", LEDGER_FILES);
      // Console exactKeys: `file` only. Missing file yields 400 (server.js:1961-1970).
      return read("/api/audit/chain/verify", { query: { file } });
    },

    async edr_list_evidence(raw) {
      const args = rejectUnknownArgs(requireObject(raw), [
        "request_id", "rule", "severity", "since", "until", "limit", "offset",
      ]);
      const query = buildQuery({
        requestId: optionalString(args.request_id, "request_id", 256),
        rule: optionalString(args.rule, "rule", 256),
        severity: optionalEnum(args.severity, "severity", SEVERITIES),
        since: optionalTimestamp(args.since, "since"),
        until: optionalTimestamp(args.until, "until"),
        ...pageArgs(args, 100),
      });
      return read("/api/evidence", { query });
    },
  };
}
