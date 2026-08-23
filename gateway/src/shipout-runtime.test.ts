import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createFileEvidenceStore,
  createFileOutboxAdapter,
  createHttpOutboxDispatcher,
  type DispatchPermit,
  IngestPausedError,
  type OutboxDispatchResult,
} from "@veritio/storage";

import { buildOutcomeEvent, type RequestOutcome } from "./evidence";
import { createShipOutSink } from "./shipout";
import { createShipOutRuntime } from "./shipout-runtime";

const directories: string[] = [];
const TENANT = "tenant_runtime";
const CANARY: DispatchPermit = {
  kind: "automatic",
  maxEntries: 1,
  maxBytes: 250_000,
  maxElapsedMs: 100,
  leaseMs: 1_000,
};

/** Returns zeroed accounting for a test dispatcher outcome. */
function emptyResult(overrides: Partial<OutboxDispatchResult> = {}): OutboxDispatchResult {
  return { dispatched: 0, retried: 0, paused: 0, rejected: 0, bytes: 0, ...overrides };
}

/** Waits for an asynchronous runtime condition without using a fixed long delay. */
async function waitFor(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("runtime condition timed out");
    await Bun.sleep(5);
  }
}

/** Builds one gateway request outcome for durable outbox setup. */
function outcome(requestId: string): RequestOutcome {
  return {
    kind: "completed",
    requestId,
    occurredAt: "2026-08-02T00:00:00.000Z",
    keyId: "vk_runtime",
    provider: "anthropic",
    endpoint: "messages",
    model: "claude-sonnet-5",
    stream: false,
    status: 200,
    latencyMs: 1,
    policyDecision: "allow",
  };
}

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("ship-out runtime", () => {
  test("held startup runs maintenance serially but performs zero dispatches", async () => {
    let active = 0;
    let maximumActive = 0;
    let maintenanceRuns = 0;
    let dispatches = 0;
    const runtime = createShipOutRuntime({
      intervalMs: 5,
      maintenance: async () => {
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await Bun.sleep(15);
        maintenanceRuns += 1;
        active -= 1;
      },
      delivery: () => ({
        tenantId: TENANT,
        startupMode: "held",
        permit: CANARY,
        outbox: { list: async () => [] },
        dispatcher: { dispatchBatch: async () => ((dispatches += 1), emptyResult()) },
      }),
    });
    runtime.start();
    await waitFor(() => maintenanceRuns >= 3);
    runtime.stop();

    expect(maximumActive).toBe(1);
    expect(dispatches).toBe(0);
    expect(runtime.snapshot()).toMatchObject({ state: "held", canaryAttempted: false });
  });

  test("an armed startup canary uses exactly one finite permit across later ticks", async () => {
    let pending = true;
    const calls: unknown[] = [];
    const runtime = createShipOutRuntime({
      intervalMs: 5,
      maintenance: async () => {},
      delivery: () => ({
        tenantId: TENANT,
        startupMode: "canary",
        permit: CANARY,
        outbox: {
          list: async () =>
            pending ? ([{ status: "pending", tenantId: TENANT }] as never) : ([{ status: "dispatched" }] as never),
        },
        dispatcher: {
          dispatchBatch: async (options) => {
            calls.push(options);
            pending = false;
            return emptyResult({ dispatched: 1, bytes: 100 });
          },
        },
      }),
    });
    runtime.start();
    await waitFor(() => runtime.snapshot().state === "canary_complete");
    await Bun.sleep(40);
    runtime.stop();

    expect(calls).toEqual([{ tenantId: TENANT, permit: CANARY }]);
    expect(runtime.snapshot()).toMatchObject({ state: "canary_complete", canaryAttempted: true });
  });

  test("a pause remains durable across runtime instances and health omits its circuit id", async () => {
    const directory = mkdtempSync(join(tmpdir(), "veritio-gateway-runtime-"));
    directories.push(directory);
    const outbox = createFileOutboxAdapter(join(directory, "outbox"));
    const sink = createShipOutSink(createFileEvidenceStore(join(directory, "evidence")), { outbox, tenantId: TENANT });
    await sink.recordEvent(buildOutcomeEvent(outcome("req_pause"), { tenantId: TENANT, gatewayId: "gw_runtime" }));
    const dispatcher = createHttpOutboxDispatcher({
      adapter: outbox,
      target: {
        dispatchEntry: async () => Promise.reject(new IngestPausedError(503, { circuitId: "secret_circuit" })),
      },
    });
    const first = createShipOutRuntime({
      intervalMs: 5,
      maintenance: async () => {},
      delivery: () => ({ tenantId: TENANT, startupMode: "canary", permit: CANARY, outbox, dispatcher }),
    });
    first.start();
    await waitFor(() => first.snapshot().state === "paused");
    first.stop();
    expect((await outbox.list({ tenantId: TENANT }))[0]?.status).toBe("paused");

    let dispatches = 0;
    const second = createShipOutRuntime({
      intervalMs: 5,
      maintenance: async () => {},
      delivery: () => ({
        tenantId: TENANT,
        startupMode: "canary",
        permit: CANARY,
        outbox,
        dispatcher: { dispatchBatch: async () => ((dispatches += 1), emptyResult()) },
      }),
    });
    second.start();
    await waitFor(() => second.snapshot().state === "paused");
    second.stop();

    expect(dispatches).toBe(0);
    expect(JSON.stringify(second.snapshot())).not.toContain("secret_circuit");
  });

  test("dispatcher failures expose a value-free error state", async () => {
    const runtime = createShipOutRuntime({
      intervalMs: 5,
      maintenance: async () => {},
      delivery: () => ({
        tenantId: TENANT,
        startupMode: "canary",
        permit: CANARY,
        outbox: { list: async () => [{ status: "pending" }] as never },
        dispatcher: { dispatchBatch: async () => Promise.reject(new Error("vrt_secret_key")) },
      }),
    });
    runtime.start();
    await waitFor(() => runtime.snapshot().state === "error");
    runtime.stop();

    expect(JSON.stringify(runtime.snapshot())).not.toContain("vrt_secret_key");
    expect(runtime.snapshot().canaryAttempted).toBe(true);
  });
});
