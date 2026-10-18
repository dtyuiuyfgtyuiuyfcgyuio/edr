// Argument validation shared by the tool handlers. Same shape as
// tools/ghidra-mcp/src/validation.mjs so both MCP servers in this workspace
// behave identically at the boundary.

export function requireObject(value, label = "arguments") {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

export function requireString(value, label, maxLength = 4096) {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new Error(`${label} must be a non-empty string no longer than ${maxLength} characters`);
  }
  if (/[\0\r\n]/u.test(value)) {
    throw new Error(`${label} contains a forbidden control character`);
  }
  return value;
}

export function optionalString(value, label, maxLength = 4096) {
  if (value === undefined || value === null) return undefined;
  return requireString(value, label, maxLength);
}

export function boundedInteger(value, label, fallback, minimum, maximum) {
  if (value === undefined || value === null) return fallback;
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

export function optionalBoolean(value, label, fallback) {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

export function optionalEnum(value, label, allowed) {
  if (value === undefined || value === null) return undefined;
  if (!allowed.includes(value)) {
    throw new Error(`${label} must be one of: ${allowed.join(", ")}`);
  }
  return value;
}

// Console routes validate enums and return 400 on a bad value. Reject locally so
// the model gets a precise message instead of an opaque HTTP 400.
export const SEVERITIES = ["info", "low", "medium", "high", "critical"];
export const TRIAGE_STATUSES = ["new", "investigating", "resolved", "false_positive"];
export const PRIORITIES = ["low", "normal", "high", "urgent"];
export const TELEMETRY_STATES = ["recent", "stale", "inactive", "unknown"];
export const INCIDENT_STATES = ["open", "closed"];
export const LEDGER_FILES = ["alerts", "incidents", "response"];

// `since` / `until` are Date.parse'd by the console on several routes and
// rejected with 400 when unparseable. Mirror that check before spending a call.
export function optionalTimestamp(value, label) {
  const text = optionalString(value, label, 64);
  if (text === undefined) return undefined;
  if (!Number.isFinite(Date.parse(text))) {
    throw new Error(`${label} must be a parseable ISO-8601 timestamp`);
  }
  return text;
}

export function optionalCaseId(value, label = "case_id") {
  return requireString(value, label, 64);
}

// Several routes use exactKeys and answer 400 for any unknown query key. Build
// the query object from an explicit allow-list so we cannot drift out of sync.
export function buildQuery(spec) {
  const query = {};
  for (const [key, value] of Object.entries(spec)) {
    if (value === undefined || value === null || value === "") continue;
    query[key] = value;
  }
  return query;
}

// Several routes use exactKeys and answer 400 for any unknown query key.
//
// Guard the INCOMING arguments, not the built query. Building the query from an
// explicit spec means an unrecognised argument would be silently dropped, so
// validating the built object would be a tautology and give false assurance.
export function rejectUnknownArgs(args, allowed, label = "arguments") {
  const extra = Object.keys(args).filter((key) => !allowed.includes(key));
  if (extra.length > 0) {
    throw new Error(
      `${label} rejected: ${extra.join(", ")}. Accepted: ${allowed.join(", ")}`,
    );
  }
  return args;
}

export function assertExactKeys(query, allowed) {
  const extra = Object.keys(query).filter((key) => !allowed.includes(key));
  if (extra.length > 0) {
    throw new Error(`query parameters rejected by the console: ${extra.join(", ")}`);
  }
  return query;
}
