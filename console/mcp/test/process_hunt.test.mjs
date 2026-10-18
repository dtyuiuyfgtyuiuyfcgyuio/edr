import test from "node:test";
import assert from "node:assert/strict";
import { TOOLS, buildHandlers } from "../src/tools.mjs";

function fixture() {
  const calls = [];
  const result = { rootProcessKey: "endpoint:opaque@123", sourceId: "endpoint",
    nodes: [], events: [], truncated: true, reasons: ["process_scan_limit"] };
  const handlers = buildHandlers({
    retrying: async (operation) => operation(),
    get: async (path, options) => { calls.push({ path, options }); return result; },
  });
  return { calls, result, handlers };
}

test("process hunt declares bounded read-only inputs", () => {
  const tool = TOOLS.find((item) => item.name === "edr_process_hunt");
  assert.ok(tool);
  assert.deepEqual(tool.inputSchema.required, ["process_key"]);
  assert.equal(tool.inputSchema.additionalProperties, false);
  assert.equal(tool.inputSchema.properties.max_nodes.maximum, 1000);
  assert.equal(tool.inputSchema.properties.max_depth.maximum, 64);
  assert.equal(tool.inputSchema.properties.event_limit.maximum, 1000);
});

test("process hunt forwards defaults and preserves incomplete evidence", async () => {
  const { calls, result, handlers } = fixture();
  assert.strictEqual(await handlers.edr_process_hunt({ process_key: "endpoint:opaque@123" }), result);
  assert.deepEqual(calls, [{ path: "/api/process-hunt", options: { query: {
    processKey: "endpoint:opaque@123", maxNodes: 200, maxDepth: 16, eventLimit: 500,
  } } }]);
});

test("process hunt forwards validated explicit limits", async () => {
  const { calls, handlers } = fixture();
  await handlers.edr_process_hunt({ process_key: "host:pid:9@123", max_nodes: 1000,
    max_depth: 64, event_limit: 1 });
  assert.deepEqual(calls[0].options.query, { processKey: "host:pid:9@123",
    maxNodes: 1000, maxDepth: 64, eventLimit: 1 });
});

test("process hunt rejects malformed input before making a request", async () => {
  const { calls, handlers } = fixture();
  const badInputs = [{}, { process_key: "" }, { process_key: "a".repeat(1025) },
    { process_key: ["x"] }, { process_key: "x", source_id: "other" },
    ...[0, -1, 1.5, 1001, [], {}, "2oops"].map((max_nodes) => ({ process_key: "x", max_nodes })),
    { process_key: "x", max_depth: 65 }, { process_key: "x", event_limit: 1001 }];
  for (const input of badInputs) await assert.rejects(() => handlers.edr_process_hunt(input));
  assert.equal(calls.length, 0);
});
