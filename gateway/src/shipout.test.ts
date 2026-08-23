import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createFileEvidenceStore,
  createFileOutboxAdapter,
  createHttpIngestTarget,
  createHttpOutboxDispatcher,
  DEFAULT_DELIVERY_SAFETY_POLICY,
} from "@veritio/storage";
import { buildOutcomeEvent, type RequestOutcome } from "./evidence";
import { createShipOutSink } from "./shipout";

const CFG = { tenantId: "tenant_ship", gatewayId: "gw_ship" };

/** Creates a finite operator permit for direct dispatcher integration tests. */
function permit(approvalId: string) {
  return {
    kind: "operator" as const,
    approvalId,
    maxEntries: 10,
    maxBytes: DEFAULT_DELIVERY_SAFETY_POLICY.hard.rollingSendBytes,
    maxElapsedMs: 5_000,
    leaseMs: 30_000,
  };
}

function outcome(requestId: string): RequestOutcome {
  return {
    kind: "completed",
    requestId,
    occurredAt: "2026-07-12T12:00:00.000Z",
    keyId: "vk_ship",
    provider: "anthropic",
    endpoint: "messages",
    model: "claude-sonnet-5",
    stream: false,
    status: 200,
    latencyMs: 5,
    policyDecision: "allow",
  };
}

function tempDirs(): { evidenceDir: string; outboxDir: string } {
  const base = mkdtempSync(join(tmpdir(), "veritio-gateway-shipout-"));
  return { evidenceDir: join(base, "evidence"), outboxDir: join(base, "outbox") };
}

describe("createShipOutSink", () => {
  test("records locally first, then enqueues one outbox entry per event", async () => {
    const { evidenceDir, outboxDir } = tempDirs();
    const store = createFileEvidenceStore(evidenceDir);
    const outbox = createFileOutboxAdapter(outboxDir);
    const sink = createShipOutSink(store, { outbox, tenantId: CFG.tenantId });

    const record = await sink.recordEvent(buildOutcomeEvent(outcome("req_1"), CFG));
    expect(record.sequence).toBe(1);

    const entries = await outbox.listDispatchable();
    expect(entries).toHaveLength(1);
    expect(entries[0]!.id).toBe(`obx_${record.event.id}`);
    expect(entries[0]!.payload.records[0]).toEqual(record.event);
    expect(entries[0]!.payload.edges).toEqual([]);
  });

  test("local append failure means NO enqueue (local store is authoritative)", async () => {
    const { outboxDir } = tempDirs();
    const outbox = createFileOutboxAdapter(outboxDir);
    const sink = createShipOutSink(
      { recordEvent: () => Promise.reject(new Error("disk full")) },
      { outbox, tenantId: CFG.tenantId },
    );
    await expect(sink.recordEvent(buildOutcomeEvent(outcome("req_1"), CFG))).rejects.toThrow("disk full");
    expect(await outbox.listDispatchable()).toHaveLength(0);
  });

  test("enqueue failure is best-effort: record still returned, warning hook fired", async () => {
    const { evidenceDir } = tempDirs();
    const store = createFileEvidenceStore(evidenceDir);
    const warned: string[] = [];
    const sink = createShipOutSink(store, {
      outbox: {
        transaction: () => Promise.reject(new Error("outbox unwritable")),
        list: () => Promise.resolve([]),
        listDispatchable: () => Promise.resolve([]),
        markDispatched: () => Promise.reject(new Error("unused")),
        markFailed: () => Promise.reject(new Error("unused")),
      },
      tenantId: CFG.tenantId,
      onEnqueueError: (eventId) => warned.push(eventId),
    });

    const record = await sink.recordEvent(buildOutcomeEvent(outcome("req_1"), CFG));
    expect(record.sequence).toBe(1);
    expect(warned).toEqual([record.event.id]);
  });

  test("a full outbox drops only the remote copy and reports the hold reason", async () => {
    const { evidenceDir, outboxDir } = tempDirs();
    const store = createFileEvidenceStore(evidenceDir);
    // A ceiling smaller than one gateway event: the very first enqueue holds.
    const outbox = createFileOutboxAdapter(outboxDir, { maxQueuedBytes: 10 });
    const warned: Array<{ eventId: string; reason: string }> = [];
    const sink = createShipOutSink(store, {
      outbox,
      tenantId: CFG.tenantId,
      onEnqueueError: (eventId, reason) => warned.push({ eventId, reason }),
    });

    const record = await sink.recordEvent(buildOutcomeEvent(outcome("req_1"), CFG));
    expect(record.sequence).toBe(1); // authoritative local append still succeeded
    expect(warned).toEqual([{ eventId: record.event.id, reason: "queue_full" }]);
    expect(await outbox.listDispatchable()).toHaveLength(0);
  });

  test("outbox drains to an ingest endpoint via the HTTP dispatcher; failures stay pending", async () => {
    const { evidenceDir, outboxDir } = tempDirs();
    const store = createFileEvidenceStore(evidenceDir);
    const outbox = createFileOutboxAdapter(outboxDir);
    const sink = createShipOutSink(store, { outbox, tenantId: CFG.tenantId });
    await sink.recordEvent(buildOutcomeEvent(outcome("req_1"), CFG));
    await sink.recordEvent(buildOutcomeEvent(outcome("req_2"), CFG));

    let ingestUp = false;
    const received: { auth: string | null; events: number }[] = [];
    const fetchImpl = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      if (!ingestUp) return new Response("unavailable", { status: 503 });
      const body = JSON.parse(String(init?.body)) as { events: unknown[] };
      received.push({ auth: new Headers(init?.headers).get("authorization"), events: body.events.length });
      return new Response(
        JSON.stringify({ appended: { events: body.events.length, edges: 0 }, tips: { event: "h", edge: null } }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    const dispatcher = createHttpOutboxDispatcher({
      adapter: outbox,
      target: createHttpIngestTarget({ baseUrl: "https://cloud.test", key: "vrt_test_key", fetchImpl }),
    });

    // Ingest down: entries stay pending (retryable 503), nothing lost.
    const down = await dispatcher.dispatchBatch({ tenantId: CFG.tenantId, permit: permit("down") });
    expect(down).toMatchObject({ dispatched: 0, retried: 1, paused: 0, rejected: 0 });
    expect(await outbox.listDispatchable()).toHaveLength(2);

    // Ingest recovers: both entries deliver with the scoped key.
    ingestUp = true;
    const up = await dispatcher.dispatchBatch({ tenantId: CFG.tenantId, permit: permit("up") });
    expect(up).toMatchObject({ dispatched: 2, retried: 0, paused: 0, rejected: 0 });
    expect(received).toHaveLength(2);
    expect(received.every((r) => r.auth === "Bearer vrt_test_key" && r.events === 1)).toBe(true);
    expect(await outbox.listDispatchable()).toHaveLength(0);
  });
});
