import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_DELIVERY_SAFETY_POLICY } from "../delivery-safety";
import {
  createHttpIngestTarget,
  createHttpOutboxDispatcher,
  IngestClientError,
  IngestConflictError,
  IngestPausedError,
  IngestRejectedError,
  IngestRetryableError,
} from "../ingest-target";
import { createFileOutboxAdapter, type OutboxPayload } from "../outbox";

const BASE_URL = "https://console.example.test";
const KEY = "vrt_test_secret_value";

/**
 * Builds a fetch double that returns the queued responses in order (repeating
 * the last) and records every call so tests can assert URL, headers, and body.
 */
function fetchReturning(...responses: Array<{ status: number; body?: unknown }>) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  let index = 0;
  const impl = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const spec = responses[Math.min(index, responses.length - 1)] ?? { status: 200, body: {} };
    index += 1;
    return new Response(spec.body === undefined ? null : JSON.stringify(spec.body), {
      status: spec.status,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

function payloadOf(records: number, edges: number): OutboxPayload {
  return {
    schemaVersion: "2026-06-23",
    mutationBinding: "same_transaction",
    records: Array.from({ length: records }, (_, i) => ({
      id: `evt_${i}`,
      actor: { type: "user", id: "usr_1" },
      action: "change.declared",
      target: { type: "change", id: `chg_${i}` },
      scope: { tenantId: "proj_1" },
      metadata: {},
    })),
    edges: Array.from({ length: edges }, (_, i) => ({
      id: `edge_${i}`,
      from: { type: "change", id: "chg_0" },
      relation: "has_output",
      to: { type: "revision", id: `rev_${i}` },
      scope: { tenantId: "proj_1" },
    })),
  };
}

describe("http ingest target", () => {
  test("dispatchEntry posts one batched request with the bearer key and parses the result", async () => {
    const { impl, calls } = fetchReturning({
      status: 200,
      body: { appended: { events: 3, edges: 4 }, tips: { event: "sha256:e", edge: "sha256:x" } },
    });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });

    const result = await target.dispatchEntry(payloadOf(3, 4));

    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`${BASE_URL}/api/ingest`);
    expect((calls[0]!.init.headers as Record<string, string>).authorization).toBe(`Bearer ${KEY}`);
    expect((calls[0]!.init.headers as Record<string, string>)["x-veritio-delivery"]).toBe("replay-v1");
    const body = JSON.parse(calls[0]!.init.body as string);
    expect(body.events).toHaveLength(3);
    expect(body.edges).toHaveLength(4);
    expect(result).toEqual({ appended: { events: 3, edges: 4 }, tips: { event: "sha256:e", edge: "sha256:x" } });
  });

  test("postBatch identifies live traffic separately from durable replay", async () => {
    const { impl, calls } = fetchReturning({
      status: 200,
      body: { appended: { events: 1, edges: 0 }, tips: { event: "sha256:e", edge: null } },
    });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });

    await target.postBatch({ events: payloadOf(1, 0).records, edges: [] });

    expect((calls[0]!.init.headers as Record<string, string>)["x-veritio-delivery"]).toBe("live-v1");
  });

  test("an empty payload makes no network call", async () => {
    const { impl, calls } = fetchReturning({ status: 200, body: {} });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });
    const result = await target.dispatchEntry(payloadOf(0, 0));
    expect(calls).toHaveLength(0);
    expect(result.appended).toEqual({ events: 0, edges: 0 });
  });

  test("the record cap is the server's: an oversized batch surfaces as the 413 client error", async () => {
    const { impl, calls } = fetchReturning({
      status: 413,
      body: { error: "too many records in one request (max 1000)" },
    });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });
    const error = await target.dispatchEntry(payloadOf(1001, 0)).catch((e) => e);
    expect(error).toBeInstanceOf(IngestClientError);
    expect((error as IngestClientError).status).toBe(413);
    expect((error as IngestClientError).retryable).toBe(false);
    // The client no longer pre-caps; the server is the single authority.
    expect(calls).toHaveLength(1);
  });

  test("a configured SDK hard batch-byte limit stops the request before network I/O", async () => {
    const { impl, calls } = fetchReturning({ status: 200, body: {} });
    const target = createHttpIngestTarget({
      baseUrl: BASE_URL,
      key: KEY,
      fetchImpl: impl,
      deliverySafety: {
        recommended: { queuedBytes: 500, rollingSendBytes: 100 },
        hard: {
          batchBytes: 100,
          queuedBytes: 1_000,
          rollingSendBytes: 100,
          rollingRequests: 1,
          windowMs: 60_000,
          automaticReplayBatches: 1,
        },
      },
    });
    const error = await target.dispatchEntry(payloadOf(1, 0)).catch((caught) => caught);
    expect(error).toBeInstanceOf(IngestClientError);
    expect((error as IngestClientError).status).toBe(413);
    expect(calls).toHaveLength(0);
  });

  test("a 409 maps to a non-retryable conflict carrying partial appended counts", async () => {
    const { impl } = fetchReturning({
      status: 409,
      body: { error: "append conflict", appended: { events: 1, edges: 0 }, retryable: false },
    });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });
    try {
      await target.dispatchEntry(payloadOf(2, 1));
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(IngestConflictError);
      expect((error as IngestConflictError).retryable).toBe(false);
      expect((error as IngestConflictError).appended).toEqual({ events: 1, edges: 0 });
    }
  });

  test("a 5xx maps to a retryable error", async () => {
    const { impl } = fetchReturning({ status: 503, body: { error: "append failed", retryable: true } });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });
    const error = await target.dispatchEntry(payloadOf(1, 0)).catch((e) => e);
    expect(error).toBeInstanceOf(IngestRetryableError);
    expect((error as IngestRetryableError).retryable).toBe(true);
    expect((error as IngestRetryableError).disposition).toBe("retry");
  });

  test("an explicit terminal 5xx disposition is rejected instead of replayed", async () => {
    const { impl } = fetchReturning({
      status: 500,
      body: {
        code: "derived_processing_failed",
        deliveryDisposition: "reject",
        retryable: false,
        appended: { events: 1, edges: 0 },
      },
    });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });
    const error = await target.dispatchEntry(payloadOf(1, 0)).catch((caught) => caught);
    expect(error).toBeInstanceOf(IngestRejectedError);
    expect((error as IngestRejectedError).disposition).toBe("reject");
    expect((error as IngestRejectedError).retryable).toBe(false);
    expect((error as IngestRejectedError).appended).toEqual({ events: 1, edges: 0 });
  });

  test("a validated economic safety hold maps to pause with sanitized control metadata", async () => {
    const { impl } = fetchReturning({
      status: 503,
      body: {
        code: "economic_safety_hold",
        deliveryDisposition: "pause",
        retryable: false,
        circuitId: "circuit_123",
        retryAfterSeconds: 120,
        error: `must not leak ${KEY}`,
      },
    });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });
    const error = await target.dispatchEntry(payloadOf(1, 0)).catch((caught) => caught);
    expect(error).toBeInstanceOf(IngestPausedError);
    expect((error as IngestPausedError).disposition).toBe("pause");
    expect((error as IngestPausedError).retryable).toBe(false);
    expect((error as IngestPausedError).circuitId).toBe("circuit_123");
    expect((error as IngestPausedError).retryAfterSeconds).toBe(120);
    expect(String(error)).not.toContain(KEY);
  });

  test("an explicit pause disposition holds delivery regardless of its code", async () => {
    // Portable contract: a conforming self-hosted target signals pause via
    // deliveryDisposition alone (e.g. operator_pause); requiring the hosted
    // economic_safety_hold code would silently downgrade it to plain retry.
    const { impl } = fetchReturning({
      status: 503,
      body: { deliveryDisposition: "pause", code: "operator_pause", circuitId: "circuit_op" },
    });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });
    const error = await target.dispatchEntry(payloadOf(1, 0)).catch((caught) => caught);
    expect(error).toBeInstanceOf(IngestPausedError);
    expect((error as IngestPausedError).disposition).toBe("pause");
    expect((error as IngestPausedError).circuitId).toBe("circuit_op");
  });

  test("an explicit retry disposition on a 4xx status stays retryable", async () => {
    const { impl } = fetchReturning({
      status: 429,
      body: { deliveryDisposition: "retry", code: "rate_limited" },
    });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });
    const error = await target.dispatchEntry(payloadOf(1, 0)).catch((caught) => caught);
    expect(error).toBeInstanceOf(IngestRetryableError);
    expect((error as IngestRetryableError).disposition).toBe("retry");
  });

  test("an explicit reject disposition is terminal without the legacy retryable field", async () => {
    const { impl } = fetchReturning({
      status: 500,
      body: { deliveryDisposition: "reject", code: "derived_processing_failed" },
    });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });
    const error = await target.dispatchEntry(payloadOf(1, 0)).catch((caught) => caught);
    expect(error).toBeInstanceOf(IngestRejectedError);
    expect((error as IngestRejectedError).disposition).toBe("reject");
  });

  test("a known legacy pause code without a disposition field still pauses", async () => {
    const { impl } = fetchReturning({
      status: 503,
      body: { code: "tenant_db_quota_blocked", circuitId: "circuit_quota" },
    });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });
    const error = await target.dispatchEntry(payloadOf(1, 0)).catch((caught) => caught);
    expect(error).toBeInstanceOf(IngestPausedError);
    expect((error as IngestPausedError).circuitId).toBe("circuit_quota");
  });

  test("aborts a hanging fetch at the finite configured timeout", async () => {
    let signal: AbortSignal | null | undefined;
    const hanging = (async (_url: string | URL | Request, init?: RequestInit) => {
      signal = init?.signal;
      return await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
      });
    }) as typeof fetch;
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, timeoutMs: 25, fetchImpl: hanging });
    const started = Date.now();
    await expect(target.dispatchEntry(payloadOf(1, 0))).rejects.toThrow();
    expect(signal?.aborted).toBe(true);
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  test("a 4xx maps to a non-retryable client error and never leaks the key", async () => {
    const { impl } = fetchReturning({ status: 403, body: { error: "record tenant scope does not match credentials" } });
    const target = createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: impl });
    const error = await target.dispatchEntry(payloadOf(1, 0)).catch((e) => e);
    expect(error).toBeInstanceOf(IngestClientError);
    expect((error as IngestClientError).status).toBe(403);
    expect(String((error as Error).message)).not.toContain(KEY);
  });
});

describe("http outbox dispatcher", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "veritio-ingest-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  test("retries a 5xx then succeeds, dispatching each entry as one POST", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    await adapter.transaction(async (tx) => {
      await tx.enqueue({ id: "entry_1", tenantId: "proj_1", payload: payloadOf(3, 4) });
    });

    const failing = fetchReturning({ status: 503, body: { retryable: true } });
    const firstPass = createHttpOutboxDispatcher({
      adapter,
      target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: failing.impl }),
    });
    const failed = await firstPass.dispatchBatch({ tenantId: "proj_1", permit: permit("retry-1") });
    expect(failed).toMatchObject({ dispatched: 0, retried: 1, paused: 0, rejected: 0 });
    expect(failed.bytes).toBeGreaterThan(0);
    expect((await adapter.list({ tenantId: "proj_1" }))[0]).toMatchObject({ status: "pending", attempts: 1 });

    const ok = fetchReturning({
      status: 200,
      body: { appended: { events: 3, edges: 4 }, tips: { event: "sha256:e", edge: "sha256:x" } },
    });
    const retry = createHttpOutboxDispatcher({
      adapter,
      target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: ok.impl }),
    });
    const recovered = await retry.dispatchBatch({ tenantId: "proj_1", permit: permit("retry-2") });
    expect(recovered.dispatched).toBe(1);
    expect(recovered.retried).toBe(0);
    expect(recovered.bytes).toBeGreaterThan(0);
    expect(ok.calls).toHaveLength(1); // one POST for the whole entry, not one per record
    expect((await adapter.list({ tenantId: "proj_1" }))[0]).toMatchObject({ status: "dispatched" });

    // A second dispatch is a no-op: the entry is already dispatched.
    expect((await retry.dispatchBatch({ tenantId: "proj_1", permit: permit("retry-3") })).dispatched).toBe(0);
  });

  test("a non-retryable 4xx dead-letters the row and is never re-dispatched", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    await adapter.transaction(async (tx) => {
      await tx.enqueue({ id: "entry_dead", tenantId: "proj_1", payload: payloadOf(1, 0) });
    });

    const rejecting = fetchReturning({ status: 403, body: { error: "scope mismatch" } });
    const firstPass = createHttpOutboxDispatcher({
      adapter,
      target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: rejecting.impl }),
    });
    expect((await firstPass.dispatchBatch({ tenantId: "proj_1", permit: permit("reject-1") })).rejected).toBe(1);
    expect((await adapter.list({ tenantId: "proj_1" }))[0]).toMatchObject({ status: "dead", attempts: 1 });
    // A dead row drops out of the dispatchable set.
    expect(await adapter.listDispatchable({ tenantId: "proj_1" })).toHaveLength(0);

    // A second pass with a would-succeed fetch never touches the dead row.
    const ok = fetchReturning({ status: 200, body: { appended: { events: 1, edges: 0 } } });
    const retry = createHttpOutboxDispatcher({
      adapter,
      target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: ok.impl }),
    });
    expect((await retry.dispatchBatch({ tenantId: "proj_1", permit: permit("reject-2") })).dispatched).toBe(0);
    expect(ok.calls).toHaveLength(0); // proves no forever-retry
  });

  test("a 409 conflict dead-letters the row", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    await adapter.transaction(async (tx) => {
      await tx.enqueue({ id: "entry_conflict", tenantId: "proj_1", payload: payloadOf(2, 0) });
    });
    const conflict = fetchReturning({ status: 409, body: { error: "append conflict" } });
    const pass = createHttpOutboxDispatcher({
      adapter,
      target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: conflict.impl }),
    });
    expect((await pass.dispatchBatch({ tenantId: "proj_1", permit: permit("conflict") })).rejected).toBe(1);
    expect((await adapter.list({ tenantId: "proj_1" }))[0]).toMatchObject({ status: "dead" });
    expect(await adapter.listDispatchable({ tenantId: "proj_1" })).toHaveLength(0);
  });

  test("requires a finite explicit permit and enforces its byte ceiling before POST", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    await adapter.transaction((tx) => tx.enqueue({ id: "bounded", tenantId: "proj_1", payload: payloadOf(3, 4) }));
    const ok = fetchReturning({ status: 200, body: { appended: { events: 3, edges: 4 } } });
    const dispatcher = createHttpOutboxDispatcher({
      adapter,
      target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: ok.impl }),
    });
    await expect(dispatcher.dispatchBatch({} as never)).rejects.toThrow("permit");
    await expect(dispatcher.dispatchBatch({ permit: permit("unscoped") } as never)).rejects.toThrow("tenantId");
    await expect(
      dispatcher.dispatchBatch({
        tenantId: "proj_1",
        permit: { ...permit("automatic"), kind: "automatic", maxEntries: 2 },
      }),
    ).rejects.toThrow("canary");
    await expect(
      dispatcher.dispatchBatch({
        tenantId: "proj_1",
        permit: {
          ...permit("long-window"),
          maxElapsedMs: DEFAULT_DELIVERY_SAFETY_POLICY.hard.windowMs + 1,
          leaseMs: DEFAULT_DELIVERY_SAFETY_POLICY.hard.windowMs + 2,
        },
      }),
    ).rejects.toThrow("rolling window");
    const result = await dispatcher.dispatchBatch({
      tenantId: "proj_1",
      permit: { ...permit("tiny"), maxBytes: 1 },
    });
    expect(result.dispatched).toBe(0);
    expect(ok.calls).toHaveLength(0);
    expect((await adapter.list({ tenantId: "proj_1" }))[0]!.status).toBe("pending");
  });

  test("one pause response creates a durable tenant barrier across dispatcher instances", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    await adapter.transaction(async (tx) => {
      await tx.enqueue({ id: "pause_1", tenantId: "proj_1", payload: payloadOf(1, 0) });
      await tx.enqueue({ id: "pause_2", tenantId: "proj_1", payload: payloadOf(1, 0) });
    });
    const held = fetchReturning({
      status: 503,
      body: { code: "economic_safety_hold", deliveryDisposition: "pause", circuitId: "circuit_1" },
    });
    const first = createHttpOutboxDispatcher({
      adapter,
      target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: held.impl }),
    });
    expect((await first.dispatchBatch({ tenantId: "proj_1", permit: permit("pause") })).paused).toBe(1);
    expect(held.calls).toHaveLength(1);

    const wouldSucceed = fetchReturning({ status: 200, body: { appended: { events: 1, edges: 0 } } });
    const second = createHttpOutboxDispatcher({
      adapter: createFileOutboxAdapter(join(dir, "outbox")),
      target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: wouldSucceed.impl }),
    });
    expect((await second.dispatchBatch({ tenantId: "proj_1", permit: permit("blocked") })).dispatched).toBe(0);
    expect(wouldSucceed.calls).toHaveLength(0);

    await expect(
      adapter.resumePaused({ tenantId: "proj_1", expectedCircuitId: "stale_circuit", limit: 10 }),
    ).rejects.toThrow("circuit");
    expect(await adapter.resumePaused({ tenantId: "proj_1", expectedCircuitId: "circuit_1", limit: 10 })).toBe(1);
    expect((await second.dispatchBatch({ tenantId: "proj_1", permit: permit("resumed") })).dispatched).toBe(2);
    expect(wouldSucceed.calls).toHaveLength(2);
  });

  test("the rolling request ceiling holds across repeated one-entry permits", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    await adapter.transaction(async (tx) => {
      for (let index = 0; index < 3; index += 1) {
        await tx.enqueue({ id: `rolling_${index}`, tenantId: "proj_1", payload: payloadOf(1, 0) });
      }
    });
    const ok = fetchReturning({ status: 200, body: { appended: { events: 1, edges: 0 } } });
    const deliverySafety = {
      recommended: { queuedBytes: 1_000_000, rollingSendBytes: 1_000_000 },
      hard: {
        batchBytes: 1_000_000,
        queuedBytes: 2_000_000,
        rollingSendBytes: 1_000_000,
        rollingRequests: 2,
        windowMs: 60_000,
        automaticReplayBatches: 1 as const,
      },
    };
    const dispatcher = createHttpOutboxDispatcher({
      adapter,
      target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: ok.impl }),
      deliverySafety,
    });
    const onePermit = (id: string) => ({ ...permit(id), maxEntries: 1, maxBytes: 1_000_000 });
    expect((await dispatcher.dispatchBatch({ tenantId: "proj_1", permit: onePermit("roll-1") })).dispatched).toBe(1);
    expect((await dispatcher.dispatchBatch({ tenantId: "proj_1", permit: onePermit("roll-2") })).dispatched).toBe(1);
    // Third pass inside the same window: the cross-pass ledger refuses more work.
    expect((await dispatcher.dispatchBatch({ tenantId: "proj_1", permit: onePermit("roll-3") })).dispatched).toBe(0);
    expect(ok.calls).toHaveLength(2);
    expect((await adapter.list({ tenantId: "proj_1", limit: 3 })).filter((e) => e.status === "pending")).toHaveLength(
      1,
    );
  });

  test("the rolling byte ceiling holds across repeated permits", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    const payload = payloadOf(1, 0);
    const entryBytes = new TextEncoder().encode(
      JSON.stringify({ events: payload.records, edges: payload.edges }),
    ).byteLength;
    await adapter.transaction(async (tx) => {
      await tx.enqueue({ id: "bytes_1", tenantId: "proj_1", payload });
      await tx.enqueue({ id: "bytes_2", tenantId: "proj_1", payload: payloadOf(1, 0) });
    });
    const ok = fetchReturning({ status: 200, body: { appended: { events: 1, edges: 0 } } });
    const rollingSendBytes = entryBytes + 5; // one entry fits, a second cannot
    const dispatcher = createHttpOutboxDispatcher({
      adapter,
      target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: ok.impl }),
      deliverySafety: {
        recommended: { queuedBytes: rollingSendBytes, rollingSendBytes },
        hard: {
          batchBytes: rollingSendBytes,
          queuedBytes: 2_000_000,
          rollingSendBytes,
          rollingRequests: 30,
          windowMs: 60_000,
          automaticReplayBatches: 1 as const,
        },
      },
    });
    const bytePermit = (id: string) => ({ ...permit(id), maxBytes: rollingSendBytes });
    expect((await dispatcher.dispatchBatch({ tenantId: "proj_1", permit: bytePermit("byte-1") })).dispatched).toBe(1);
    expect((await dispatcher.dispatchBatch({ tenantId: "proj_1", permit: bytePermit("byte-2") })).dispatched).toBe(0);
    expect(ok.calls).toHaveLength(1);
  });

  test("clamps the in-flight request to the permit deadline", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    await adapter.transaction((tx) => tx.enqueue({ id: "slow", tenantId: "proj_1", payload: payloadOf(1, 0) }));
    const hanging = (async (_url: string | URL | Request, init?: RequestInit) => {
      return await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
      });
    }) as typeof fetch;
    const dispatcher = createHttpOutboxDispatcher({
      adapter,
      // The target keeps its default 10-second timeout; the permit is shorter.
      target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl: hanging }),
    });
    const started = Date.now();
    const result = await dispatcher.dispatchBatch({
      tenantId: "proj_1",
      permit: { ...permit("deadline"), maxElapsedMs: 50, leaseMs: 200 },
    });
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(result).toMatchObject({ dispatched: 0, retried: 1 });
    expect((await adapter.list({ tenantId: "proj_1" }))[0]).toMatchObject({ status: "pending", attempts: 1 });
  });

  test("50 concurrent dispatchers claim one row exactly once", async () => {
    const path = join(dir, "outbox");
    const adapter = createFileOutboxAdapter(path);
    await adapter.transaction((tx) => tx.enqueue({ id: "race", tenantId: "proj_1", payload: payloadOf(1, 0) }));
    let posts = 0;
    const fetchImpl = (async () => {
      posts += 1;
      await Bun.sleep(10);
      return Response.json({ appended: { events: 1, edges: 0 } });
    }) as typeof fetch;
    const results = await Promise.all(
      Array.from({ length: 50 }, (_, index) =>
        createHttpOutboxDispatcher({
          adapter: createFileOutboxAdapter(path),
          target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl }),
        }).dispatchBatch({ tenantId: "proj_1", permit: permit(`race-${index}`) }),
      ),
    );
    expect(posts).toBe(1);
    expect(results.reduce((sum, result) => sum + result.dispatched, 0)).toBe(1);
  });

  test("a tenant-wide pause response allows only one concurrent request to escape", async () => {
    const path = join(dir, "pause-race-outbox");
    const adapter = createFileOutboxAdapter(path);
    await adapter.transaction(async (tx) => {
      for (let index = 0; index < 50; index += 1) {
        await tx.enqueue({ id: `pause_race_${index}`, tenantId: "proj_1", payload: payloadOf(1, 0) });
      }
    });
    let posts = 0;
    const fetchImpl = (async () => {
      posts += 1;
      await Bun.sleep(10);
      return Response.json(
        { code: "economic_safety_hold", deliveryDisposition: "pause", circuitId: "circuit_race" },
        { status: 503 },
      );
    }) as typeof fetch;
    const results = await Promise.all(
      Array.from({ length: 50 }, (_, index) =>
        createHttpOutboxDispatcher({
          adapter: createFileOutboxAdapter(path),
          target: createHttpIngestTarget({ baseUrl: BASE_URL, key: KEY, fetchImpl }),
        }).dispatchBatch({ tenantId: "proj_1", permit: permit(`pause-race-${index}`) }),
      ),
    );
    expect(posts).toBe(1);
    expect(results.reduce((sum, result) => sum + result.paused, 0)).toBe(1);
  });
});

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
