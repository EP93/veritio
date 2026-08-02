import { afterAll, beforeAll, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createFileOutboxAdapter,
  createHttpIngestTarget,
  createHttpOutboxDispatcher,
  type OutboxDispatchResult,
} from "../src";

const WORKERS = 50;
const ENTRIES = 200;
let dir: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "veritio-outbox-stress-"));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

test("50 concurrent dispatchers deliver 200 entries exactly once within finite permits", async () => {
  const path = join(dir, "outbox");
  const adapter = createFileOutboxAdapter(path);
  await adapter.transaction(async (tx) => {
    for (let index = 0; index < ENTRIES; index += 1) {
      await tx.enqueue({ id: `entry_${index}`, tenantId: "tenant_stress", payload: payload(index) });
    }
  });

  const received = new Map<string, number>();
  let inFlight = 0;
  let maxInFlight = 0;
  const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { events: Array<{ id: string }> };
    const id = body.events[0]!.id;
    received.set(id, (received.get(id) ?? 0) + 1);
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    try {
      await Bun.sleep(Math.floor(Math.random() * 3));
      return Response.json({ appended: { events: 1, edges: 0 } });
    } finally {
      inFlight -= 1;
    }
  }) as typeof fetch;

  const results: OutboxDispatchResult[] = [];
  for (let round = 0; round < 20 && received.size < ENTRIES; round += 1) {
    const roundResults = await Promise.all(
      Array.from({ length: WORKERS }, (_, worker) =>
        createHttpOutboxDispatcher({
          adapter: createFileOutboxAdapter(path),
          target: createHttpIngestTarget({ baseUrl: "http://127.0.0.1", key: "vrt_stress", fetchImpl }),
        }).dispatchBatch({
          tenantId: "tenant_stress",
          permit: {
            kind: "operator",
            approvalId: `stress_${round}_${worker}`,
            maxEntries: 10,
            maxBytes: 1024 * 1024,
            maxElapsedMs: 30_000,
            leaseMs: 60_000,
          },
        }),
      ),
    );
    results.push(...roundResults);
  }

  expect(results.reduce((sum, result) => sum + result.dispatched, 0)).toBe(ENTRIES);
  expect(received.size).toBe(ENTRIES);
  expect([...received.values()].every((count) => count === 1)).toBe(true);
  expect(maxInFlight).toBe(1);
  expect((await createFileOutboxAdapter(path).list()).every((entry) => entry.status === "dispatched")).toBe(true);
}, 60_000);

/** Builds a minimal tenant-scoped payload with a unique deterministic id. */
function payload(index: number) {
  return {
    schemaVersion: "2026-06-23" as const,
    mutationBinding: "best_effort" as const,
    records: [
      {
        id: `evt_${index}`,
        actor: { type: "service", id: "stress" },
        action: "stress.delivery",
        target: { type: "entry", id: `target_${index}` },
        scope: { tenantId: "tenant_stress" },
        metadata: {},
      },
    ],
    edges: [],
  };
}
