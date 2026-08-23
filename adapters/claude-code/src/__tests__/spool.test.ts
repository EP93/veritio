import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditEvent } from "@veritio/core";

import { deliveryDispositionOf, IngestHttpError, isRetryableIngestFailure } from "../ingest";
import {
  DEFAULT_SPOOL_LIMITS,
  flushSpool,
  inspectSpool,
  pauseSpool,
  quarantinedSpoolEntries,
  type ReplayPermit,
  resumeSpool,
  saveToSpool,
  shipWithSpool,
} from "../spool";

/**
 * Regression suite for the durable delivery queue. It pins the economic-safety
 * invariant that ordinary capture never turns a held/backlogged queue into an
 * implicit drain, while every rejected or paused payload remains recoverable.
 */

const EVENT = (id: string) =>
  ({
    id,
    schemaVersion: "1.0",
    occurredAt: "2026-08-02T00:00:00.000Z",
    actor: { id: "yan", type: "user" },
    action: "debug.spool.test",
    target: { id: "t1", type: "diagnostic" },
    metadata: {},
  }) as unknown as AuditEvent;

function payloadOf(id: string, count = 1) {
  return { events: Array.from({ length: count }, (_, index) => EVENT(`${id}_${index}`)), edges: [] };
}

const dirs: string[] = [];

/** Allocates one isolated queue root and schedules deterministic cleanup. */
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "veritio-spool-"));
  dirs.push(dir);
  return dir;
}

const received: string[] = [];
const deliveries: string[] = [];
let requests = 0;
let mode: "ok" | "retry" | "pause" | "reject" | "slow" = "ok";
const server = Bun.serve({
  port: 0,
  async fetch(request) {
    requests += 1;
    deliveries.push(request.headers.get("x-veritio-delivery") ?? "missing");
    if (mode === "retry") {
      return Response.json({ error: "temporary failure", deliveryDisposition: "retry" }, { status: 503 });
    }
    if (mode === "pause") {
      return Response.json(
        {
          error: "ingest paused",
          code: "economic_safety_hold",
          deliveryDisposition: "pause",
          retryable: false,
          circuitId: "cir_cost_01",
        },
        { status: 503 },
      );
    }
    if (mode === "reject") {
      return Response.json(
        { error: "scope mismatch", code: "scope_mismatch", deliveryDisposition: "reject", retryable: false },
        { status: 403 },
      );
    }
    if (mode === "slow") {
      await Bun.sleep(75);
    }
    const body = (await request.json()) as { events: { id: string }[] };
    received.push(...body.events.map((event) => event.id));
    return Response.json({ appended: { events: body.events.length, edges: 0 } });
  },
});
const INGEST = { url: server.url.href, key: "vrt_test", timeoutMs: 2_000 };

/** Creates an explicit finite replay epoch; no queue API may invent one. */
function permit(overrides: Partial<ReplayPermit> = {}): ReplayPermit {
  return {
    id: "drain_test_01",
    kind: "drain",
    maxBatches: 10,
    maxRecords: 100,
    maxBytes: 1_000_000,
    maxElapsedMs: 5_000,
    ...overrides,
  };
}

afterEach(() => {
  mode = "ok";
  received.length = 0;
  requests = 0;
  deliveries.length = 0;
});

afterAll(() => {
  server.stop(true);
  for (const dir of dirs) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("delivery disposition compatibility", () => {
  test("transport and legacy 5xx retry while an explicit pause never does", () => {
    expect(isRetryableIngestFailure(new IngestHttpError(503))).toBe(true);
    expect(deliveryDispositionOf(new IngestHttpError(403))).toBe("reject");
    expect(
      deliveryDispositionOf(new IngestHttpError(503, { deliveryDisposition: "pause", code: "economic_safety_hold" })),
    ).toBe("pause");
    expect(deliveryDispositionOf(new Error("fetch failed"))).toBe("retry");
  });
});

describe("shipWithSpool", () => {
  test("a healthy empty queue ships the current batch directly", async () => {
    const dir = tempDir();
    await shipWithSpool(INGEST, dir, payloadOf("evt_direct"));

    expect(received).toEqual(["evt_direct_0"]);
    expect(inspectSpool(dir)).toMatchObject({ pending: 0, held: 0, quarantined: 0 });
  });

  test("a retry response preserves the batch as pending", async () => {
    const dir = tempDir();
    mode = "retry";
    await shipWithSpool(INGEST, dir, payloadOf("evt_retry"));

    expect(inspectSpool(dir)).toMatchObject({ pending: 1, held: 0, quarantined: 0 });
  });

  test("a pause response creates a sticky circuit and later hooks make zero attempts", async () => {
    const dir = tempDir();
    mode = "pause";
    await shipWithSpool(INGEST, dir, payloadOf("evt_paused"));
    expect(requests).toBe(1);

    mode = "ok";
    for (let index = 0; index < 50; index += 1) {
      await shipWithSpool(INGEST, dir, payloadOf(`evt_held_${index}`));
    }

    expect(requests).toBe(1);
    expect(inspectSpool(dir)).toMatchObject({
      pending: 0,
      held: 51,
      circuit: { code: "economic_safety_hold", circuitId: "cir_cost_01" },
    });
  });

  test("a permanent rejection is quarantined with its payload instead of thrown away", async () => {
    const dir = tempDir();
    mode = "reject";
    await shipWithSpool(INGEST, dir, payloadOf("evt_rejected"));

    expect(inspectSpool(dir)).toMatchObject({ pending: 0, held: 0, quarantined: 1 });
    expect(quarantinedSpoolEntries(dir)[0]?.payload.events[0]?.id).toBe("evt_rejected_0");
  });

  test("ordinary capture appends behind a backlog but never drains it", async () => {
    const dir = tempDir();
    saveToSpool(dir, payloadOf("evt_old"));

    await shipWithSpool(INGEST, dir, payloadOf("evt_new"));

    expect(requests).toBe(0);
    expect(inspectSpool(dir)).toMatchObject({ pending: 2, held: 0 });
  });
});

describe("explicit replay permits", () => {
  test("marks explicit spool drains as replay traffic for server-side replay budgets", async () => {
    const dir = tempDir();
    saveToSpool(dir, payloadOf("evt_replay"));

    await flushSpool(INGEST, dir, permit({ maxBatches: 1 }));

    expect(deliveries).toEqual(["replay-v1"]);
  });

  test("flush refuses a missing, non-finite, or unbounded permit before network I/O", async () => {
    const dir = tempDir();
    saveToSpool(dir, payloadOf("evt_kept"));

    for (const invalid of [
      undefined,
      permit({ maxBatches: Number.POSITIVE_INFINITY }),
      permit({ maxRecords: 0 }),
      permit({ maxBytes: Number.NaN }),
      permit({ maxElapsedMs: 60_000 }),
    ]) {
      await expect(flushSpool(INGEST, dir, invalid as never)).rejects.toThrow("finite replay permit");
    }
    expect(requests).toBe(0);
  });

  test("one epoch stops before exceeding its aggregate batch and record budgets", async () => {
    const dir = tempDir();
    saveToSpool(dir, payloadOf("evt_a", 2));
    saveToSpool(dir, payloadOf("evt_b", 2));
    saveToSpool(dir, payloadOf("evt_c", 2));

    const result = await flushSpool(INGEST, dir, permit({ maxBatches: 2, maxRecords: 4 }));

    expect(result).toMatchObject({ attemptedBatches: 2, attemptedRecords: 4, dispatchedBatches: 2 });
    expect(received).toEqual(["evt_a_0", "evt_a_1", "evt_b_0", "evt_b_1"]);
    expect(inspectSpool(dir).pending).toBe(1);
  });

  test("a pause during replay holds the whole remaining queue and persists the circuit", async () => {
    const dir = tempDir();
    saveToSpool(dir, payloadOf("evt_a"));
    saveToSpool(dir, payloadOf("evt_b"));
    mode = "pause";

    await flushSpool(INGEST, dir, permit());

    expect(requests).toBe(1);
    expect(inspectSpool(dir)).toMatchObject({
      pending: 0,
      held: 2,
      circuit: { code: "economic_safety_hold", circuitId: "cir_cost_01" },
    });
  });

  test("a rejected replay entry is quarantined and the finite epoch may continue", async () => {
    const dir = tempDir();
    saveToSpool(dir, payloadOf("evt_bad"));
    mode = "reject";

    const result = await flushSpool(INGEST, dir, permit());

    expect(result.quarantinedBatches).toBe(1);
    expect(quarantinedSpoolEntries(dir)[0]?.payload.events[0]?.id).toBe("evt_bad_0");
  });

  test("concurrent replay commands cannot duplicate one remote request", async () => {
    const dir = tempDir();
    saveToSpool(dir, payloadOf("evt_once"));
    mode = "slow";

    const outcomes = await Promise.allSettled([
      flushSpool(INGEST, dir, permit({ id: "drain_a" })),
      flushSpool(INGEST, dir, permit({ id: "drain_b" })),
    ]);

    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
    expect(requests).toBe(1);
    expect(received).toEqual(["evt_once_0"]);
  });
});

describe("operator hold and bounds", () => {
  test("pause moves pending batches to held and resume never dispatches them", () => {
    const dir = tempDir();
    saveToSpool(dir, payloadOf("evt_pending"));

    pauseSpool(dir, { code: "operator_pause", reason: "investigating transfer spike" });
    expect(inspectSpool(dir)).toMatchObject({ pending: 0, held: 1 });

    resumeSpool(dir, "I reviewed the provider headroom");
    expect(inspectSpool(dir)).toMatchObject({ pending: 1, held: 0, circuit: null });
    expect(requests).toBe(0);
  });

  test("the hard bound retains old entries, refuses the new remote copy, and enters hold", () => {
    const dir = tempDir();
    const limits = { hardBatches: 2, hardBytes: DEFAULT_SPOOL_LIMITS.hardBytes };
    expect(saveToSpool(dir, payloadOf("evt_oldest"), limits)).toBe("saved");
    expect(saveToSpool(dir, payloadOf("evt_second"), limits)).toBe("saved");
    expect(saveToSpool(dir, payloadOf("evt_refused"), limits)).toBe("full");

    const status = inspectSpool(dir);
    expect(status).toMatchObject({ pending: 0, held: 2, quarantined: 0, queueFull: true });
    expect(status.total).toBe(2);
  });

  test("quarantine counts toward the hard bound and suppresses later hook requests", async () => {
    const dir = tempDir();
    const limits = { hardBatches: 1, hardBytes: DEFAULT_SPOOL_LIMITS.hardBytes };
    mode = "reject";
    await shipWithSpool(INGEST, dir, payloadOf("evt_quarantined"), limits);
    expect(requests).toBe(1);

    mode = "ok";
    await shipWithSpool(INGEST, dir, payloadOf("evt_refused"), limits);

    expect(requests).toBe(1);
    expect(inspectSpool(dir)).toMatchObject({ pending: 0, held: 0, quarantined: 1, queueFull: true });
  });

  test("a missing state file cannot reset sequence numbers and overwrite an older entry", () => {
    const dir = tempDir();
    saveToSpool(dir, payloadOf("evt_first"));
    unlinkSync(join(dir, "spool", "state.json"));

    saveToSpool(dir, payloadOf("evt_second"));

    expect(inspectSpool(dir)).toMatchObject({ pending: 2, held: 0 });
  });

  test("a corrupt state file enters a persistent fail-closed hold", () => {
    const dir = tempDir();
    saveToSpool(dir, payloadOf("evt_first"));
    writeFileSync(join(dir, "spool", "state.json"), "{not-json", "utf8");

    expect(inspectSpool(dir)).toMatchObject({ pending: 0, held: 1, circuit: { code: "queue_state_corrupt" } });
    expect(inspectSpool(dir)).toMatchObject({ pending: 0, held: 1, circuit: { code: "queue_state_corrupt" } });
  });

  test("concurrent hook processes allocate unique durable entries", async () => {
    const dir = tempDir();
    const writer = fileURLToPath(new URL("./fixtures/spool-writer.ts", import.meta.url));
    const processes = Array.from({ length: 20 }, (_, index) =>
      Bun.spawn([process.execPath, writer, dir, `evt_process_${index}`], {
        stdout: "ignore",
        stderr: "pipe",
      }),
    );

    expect(await Promise.all(processes.map((child) => child.exited))).toEqual(Array(20).fill(0));
    expect(inspectSpool(dir)).toMatchObject({ pending: 20, held: 0, quarantined: 0, total: 20 });
  });

  test("legacy root entries upgrade into manual hold instead of auto-draining", () => {
    const dir = tempDir();
    mkdirSync(join(dir, "spool"), { recursive: true });
    writeFileSync(join(dir, "spool", "000000000000001-legacy.json"), JSON.stringify(payloadOf("evt_legacy")));

    expect(inspectSpool(dir)).toMatchObject({
      pending: 0,
      held: 1,
      circuit: { code: "legacy_queue_upgrade" },
    });
  });
});
