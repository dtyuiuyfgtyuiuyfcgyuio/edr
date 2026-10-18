// Dependency-free MCP server exposing the EDR web console's read-only
// investigation surface. Mirrors the structure of tools/ghidra-mcp/src/server.mjs
// (hand-rolled JSON-RPC 2.0 over stdio, no third-party packages).
//
// Read-only by construction: only `read`-role console routes are exposed. No
// `/api/response/*`, no triage writes, no playbook execution. Those are the
// console's admin surface and this server has no route to them at all.

import { ConsoleClient, clientFromEnvironment } from "./console-client.mjs";
import { TOOLS, buildHandlers } from "./tools.mjs";

const SERVER_NAME = "edr-console-investigation";
const SERVER_VERSION = "1.0.0";
const MAX_MESSAGE_BYTES = 4 * 1024 * 1024;

const handlers = buildHandlers(clientFromEnvironment());

function writeMessage(message) {
  process.stdout.write(JSON.stringify(message) + "\n");
}

function writeResult(id, result) {
  writeMessage({ jsonrpc: "2.0", id, result });
}

function writeError(id, code, message) {
  writeMessage({ jsonrpc: "2.0", id, error: { code, message } });
}

function toolResult(value) {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    structuredContent: value,
    isError: false,
  };
}

async function handleMessage(message) {
  if (message === null || typeof message !== "object" || Array.isArray(message)) {
    writeError(null, -32600, "Invalid Request");
    return;
  }

  const hasId = Object.prototype.hasOwnProperty.call(message, "id");
  const id = hasId ? message.id : null;
  const method = message.method;

  if (method === "initialize") {
    if (!hasId) return;
    const requestedVersion = message.params?.protocolVersion;
    writeResult(id, {
      protocolVersion: typeof requestedVersion === "string" ? requestedVersion : "2025-06-18",
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      instructions:
        "Read-only investigation over the EDR console. Cite case_id and incident_id in " +
        "answers. If incident or audit-chain results report an integrity failure, say the " +
        "data is untrusted instead of drawing conclusions from it.",
    });
    return;
  }

  if (method === "ping") {
    if (hasId) writeResult(id, {});
    return;
  }

  if (method === "tools/list") {
    if (hasId) writeResult(id, { tools: TOOLS });
    return;
  }

  if (method === "tools/call") {
    if (!hasId) return;
    const name = message.params?.name;
    const handler = handlers[name];
    if (!handler) {
      writeError(id, -32602, "Unknown tool");
      return;
    }
    try {
      writeResult(id, toolResult(await handler(message.params?.arguments ?? {})));
    } catch (error) {
      // Never echo the API key or a full request URL back to the model.
      const text = error instanceof ConsoleError ? error.message
        : error instanceof Error ? error.message
        : "Console query failed";
      writeResult(id, {
        content: [{ type: "text", text }],
        isError: true,
      });
    }
    return;
  }

  if (method === "shutdown") {
    if (hasId) writeResult(id, null);
    return;
  }

  if (method === "exit") {
    process.exitCode = 0;
    process.stdin.pause();
    return;
  }

  if (hasId) writeError(id, -32601, "Method not found");
}

let input = "";
let chain = Promise.resolve();

process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  if (Buffer.byteLength(input, "utf8") > MAX_MESSAGE_BYTES) {
    writeError(null, -32600, "Message exceeds size limit");
    input = "";
    process.exitCode = 1;
    process.stdin.pause();
    return;
  }

  for (;;) {
    const newline = input.indexOf("\n");
    if (newline < 0) break;
    const line = input.slice(0, newline).trim();
    input = input.slice(newline + 1);
    if (!line) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      writeError(null, -32700, "Parse error");
      continue;
    }
    chain = chain
      .then(() => handleMessage(message))
      .catch((error) => {
        process.stderr.write(
          `MCP request failure: ${error instanceof Error ? error.message : String(error)}\n`,
        );
      });
  }
});

process.stdin.on("end", () => {
  if (input.trim()) {
    try {
      const message = JSON.parse(input);
      chain = chain.then(() => handleMessage(message));
    } catch {
      writeError(null, -32700, "Parse error");
    }
  }
});
