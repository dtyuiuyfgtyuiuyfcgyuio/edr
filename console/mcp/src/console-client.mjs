// Read-only HTTP client for the EDR web console (console/server.js).
//
// Auth: the console reads a raw API key from the `x-api-key` header -- there is
// no Bearer scheme (console/server.js:899-914). Roles are resolved statically
// per route, so a read key can never satisfy an admin route. This client only
// ever sends the read key, and only ever calls `read`-role routes.

import { setTimeout as delay } from "node:timers/promises";

const DEFAULT_BASE_URL = "http://127.0.0.1:8080";
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);

export class ConsoleError extends Error {
  constructor(message, { status = null, body = null, integrity = null } = {}) {
    super(message);
    this.name = "ConsoleError";
    this.status = status;
    this.body = body;
    this.integrity = integrity;
  }
}

export class ConsoleClient {
  constructor({ baseUrl = DEFAULT_BASE_URL, apiKey = null, timeoutMs = 15000 } = {}) {
    this.baseUrl = String(baseUrl).replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
  }

  // A console bound to a non-loopback address is reachable by anything that can
  // route to it. Refuse that unless the operator says otherwise, mirroring the
  // console's own fail-closed bind check (console/server.js:3092-3106).
  assertUsableTarget() {
    let parsed;
    try {
      parsed = new URL(this.baseUrl);
    } catch {
      throw new ConsoleError(`EDR_CONSOLE_URL is not a valid URL: ${this.baseUrl}`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new ConsoleError(`console URL must be http or https, got ${parsed.protocol}`);
    }
    if (process.env.EDR_CONSOLE_ALLOW_REMOTE === "1") return;
    if (!LOOPBACK_HOSTS.has(parsed.hostname)) {
      throw new ConsoleError(
        `refusing non-loopback console host '${parsed.hostname}'. The console binds ` +
          "127.0.0.1 by default; set EDR_CONSOLE_ALLOW_REMOTE=1 only when that host " +
          "is intentionally in scope and protected by the network.",
      );
    }
  }

  async request(method, path, { query, allowStatus = [] } = {}) {
    this.assertUsableTarget();

    const url = new URL(this.baseUrl + path);
    // Express turns a repeated query key into an array, which the console's
    // Number.parseInt(... , 10) then throws on (500 internal error). Send scalars.
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value === undefined || value === null || value === "") continue;
      if (Array.isArray(value) || (typeof value === "object")) {
        throw new ConsoleError(`query parameter '${key}' must be a scalar`);
      }
      url.searchParams.set(key, String(value));
    }

    const headers = { accept: "application/json" };
    if (this.apiKey) headers["x-api-key"] = this.apiKey;

    let response;
    try {
      response = await fetch(url, {
        method,
        headers,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new ConsoleError(`console unreachable at ${this.baseUrl}: ${reason}`);
    }

    const text = await response.text();
    let body = null;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = null;
      }
    }

    if (!response.ok && !allowStatus.includes(response.status)) {
      const detail =
        (body && typeof body === "object" && typeof body.error === "string")
          ? body.error
          : text.slice(0, 300) || response.statusText;
      const integrity = body && typeof body === "object" ? body.integrity ?? null : null;
      throw new ConsoleError(`console HTTP ${response.status}: ${detail}`, {
        status: response.status,
        body,
        integrity,
      });
    }

    return { status: response.status, body };
  }

  async get(path, options) {
    const result = await this.request("GET", path, options);
    return result.body;
  }

  // /api/health is the only public route; used as the reachability probe.
  async health() {
    return this.request("GET", "/api/health");
  }

  // The incident ledger gates reads on the audit hash chain: chain corruption or
  // an incomplete tail returns 503 with an `integrity` object (server.js:1977-1981,
  // incidents.js:53-61). `missing` / `legacy` / `mixed` are served normally.
  //
  // Surface 503 as a readable refusal instead of an exception so the model can
  // tell "no trustworthy data" apart from "request rejected".
  async getWithIntegrity(path, options) {
    const result = await this.request("GET", path, { ...options, allowStatus: [503] });
    const body = result.body;
    if (result.status === 503) {
      return {
        unavailable: true,
        reason: body && typeof body === "object" && body.error ? body.error : "incident ledger unavailable",
        integrity: body && typeof body === "object" ? body.integrity ?? null : null,
      };
    }
    return {
      unavailable: false,
      integrity: body && typeof body === "object" ? body.integrity ?? null : null,
      data: body,
    };
  }

  async retrying(operation, attempts = 2) {
    let lastError;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        // Only transport hiccups are worth a second try; a 4xx will not change.
        if (error instanceof ConsoleError && error.status !== null) throw error;
        if (attempt === attempts) break;
        await delay(150 * attempt);
      }
    }
    throw lastError;
  }
}

export function clientFromEnvironment(env = process.env) {
  return new ConsoleClient({
    baseUrl: env.EDR_CONSOLE_URL || DEFAULT_BASE_URL,
    apiKey: env.EDR_READ_API_KEY || null,
    timeoutMs: env.EDR_CONSOLE_TIMEOUT_MS
      ? Number.parseInt(env.EDR_CONSOLE_TIMEOUT_MS, 10)
      : 15000,
  });
}
