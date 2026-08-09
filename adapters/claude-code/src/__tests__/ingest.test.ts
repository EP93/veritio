import { afterAll, describe, expect, test } from "bun:test";
import type { AuditEvent } from "@veritio/core";

import { resolveConfig } from "../config";
import * as ingestModule from "../ingest";
import { DEFAULT_INGEST_TIMEOUT_MS, IngestHttpError, postToIngest } from "../ingest";

const { deliveryDispositionOf, MAX_INGEST_TIMEOUT_MS } = ingestModule as typeof ingestModule & {
  deliveryDispositionOf(error: unknown): "retry" | "pause" | "reject";
  MAX_INGEST_TIMEOUT_MS: number;
};

/**
 * Regression suite for the ship-out abort bound. An UNBOUNDED postToIngest once
 * froze Claude Code for minutes when the hosted ingest endpoint stalled
 * (SessionStart hook sat on Bun's 5-minute fetch default), so these tests pin:
 * a stalled endpoint aborts within the configured bound, and the bound is
 * resolved only at the env process boundary.
 */

const EVENT = {
  id: "evt_test",
  schemaVersion: "1.0",
  occurredAt: "2026-07-14T00:00:00.000Z",
  actor: { id: "yan", type: "user" },
  action: "debug.ingest.test",
  target: { id: "t1", type: "diagnostic" },
  metadata: {},
} as unknown as AuditEvent;

let requests = 0;
/** Never resolves: simulates the prod hang that froze Claude Code. */
const hangingServer = Bun.serve({
  port: 0,
  fetch() {
    requests += 1;
    return new Promise<Response>(() => {});
  },
});

let lastAuth: string | null = null;
let lastDelivery: string | null = null;
const okServer = Bun.serve({
  port: 0,
  fetch(request) {
    lastAuth = request.headers.get("authorization");
    lastDelivery = request.headers.get("x-veritio-delivery");
    return Promise.resolve(Response.json({ appended: { events: 1, edges: 0 } }));
  },
});

const failingServer = Bun.serve({
  port: 0,
  fetch() {
    return Promise.resolve(new Response("nope", { status: 503 }));
  },
});

const dispositionServer = Bun.serve({
  port: 0,
  fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === "/pause") {
      return Response.json(
        {
          error: "ingest is temporarily paused",
          code: "economic_safety_hold",
          deliveryDisposition: "pause",
          retryable: false,
          retryAt: "2026-08-03T00:00:00.000Z",
          circuitId: "cir_01",
        },
        { status: 503 },
      );
    }
    if (path === "/legacy-pause") {
      return Response.json(
        { error: "monthly event quota exceeded", code: "monthly_event_quota_exceeded", retryable: false },
        { status: 402 },
      );
    }
    if (path === "/reject") {
      return Response.json(
        { error: "scope mismatch", code: "scope_mismatch", deliveryDisposition: "reject", retryable: false },
        { status: 403 },
      );
    }
    return Response.json({ error: "temporary failure" }, { status: 503 });
  },
});

afterAll(() => {
  hangingServer.stop(true);
  okServer.stop(true);
  failingServer.stop(true);
  dispositionServer.stop(true);
});

describe("postToIngest — bounded abort (the un-freeze invariant)", () => {
  test("a never-responding endpoint rejects within the configured bound, not minutes", async () => {
    const started = Date.now();
    expect(
      postToIngest({ url: hangingServer.url.href, key: "vrt_test", timeoutMs: 250 }, { events: [EVENT], edges: [] }),
    ).rejects.toThrow();
    // Await the rejection to measure elapsed wall-clock.
    await postToIngest(
      { url: hangingServer.url.href, key: "vrt_test", timeoutMs: 250 },
      { events: [EVENT], edges: [] },
    ).catch(() => {});
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  test("the default bound exists and is finite (no unbounded ship-out ever again)", () => {
    expect(DEFAULT_INGEST_TIMEOUT_MS).toBeGreaterThan(0);
    expect(Number.isFinite(DEFAULT_INGEST_TIMEOUT_MS)).toBe(true);
  });

  test("success path still posts with the bearer key", async () => {
    await postToIngest({ url: okServer.url.href, key: "vrt_ok", timeoutMs: 2_000 }, { events: [EVENT], edges: [] });
    expect(lastAuth).toBe("Bearer vrt_ok");
    expect(lastDelivery).toBe("live-v1");
  });

  test("non-2xx still surfaces a typed-ish error for the fail-open hook boundary to log", () => {
    expect(
      postToIngest({ url: failingServer.url.href, key: "vrt_test", timeoutMs: 2_000 }, { events: [EVENT], edges: [] }),
    ).rejects.toThrow("ingest POST failed with status 503");
  });

  test("empty payload never opens a connection (so it cannot stall either)", async () => {
    const before = requests;
    await postToIngest({ url: hangingServer.url.href, key: "vrt_test", timeoutMs: 250 }, { events: [], edges: [] });
    expect(requests).toBe(before);
  });

  test("a portable pause response survives as a typed non-retry disposition", async () => {
    const error = await postToIngest(
      { url: new URL("/pause", dispositionServer.url).href, key: "vrt_test", timeoutMs: 2_000 },
      { events: [EVENT], edges: [] },
    ).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(IngestHttpError);
    expect(error).toMatchObject({
      status: 503,
      deliveryDisposition: "pause",
      code: "economic_safety_hold",
      retryAt: "2026-08-03T00:00:00.000Z",
      circuitId: "cir_01",
    });
    expect(deliveryDispositionOf(error)).toBe("pause");
  });

  test("a recognized legacy quota code pauses even without deliveryDisposition", async () => {
    const error = await postToIngest(
      { url: new URL("/legacy-pause", dispositionServer.url).href, key: "vrt_test", timeoutMs: 2_000 },
      { events: [EVENT], edges: [] },
    ).catch((caught: unknown) => caught);

    expect(deliveryDispositionOf(error)).toBe("pause");
  });

  test("explicit reject and legacy status fallback classify without inspecting secrets", async () => {
    const rejected = await postToIngest(
      { url: new URL("/reject", dispositionServer.url).href, key: "vrt_test", timeoutMs: 2_000 },
      { events: [EVENT], edges: [] },
    ).catch((caught: unknown) => caught);
    const legacyRetry = await postToIngest(
      { url: dispositionServer.url.href, key: "vrt_test", timeoutMs: 2_000 },
      { events: [EVENT], edges: [] },
    ).catch((caught: unknown) => caught);

    expect(deliveryDispositionOf(rejected)).toBe("reject");
    expect(deliveryDispositionOf(legacyRetry)).toBe("retry");
    expect((rejected as Error).message).not.toContain("scope mismatch");
  });

  test("direct callers cannot disable the timeout with non-finite or oversized values", async () => {
    for (const timeoutMs of [0, -1, Number.POSITIVE_INFINITY, MAX_INGEST_TIMEOUT_MS + 1]) {
      const error = await postToIngest(
        { url: okServer.url.href, key: "vrt_test", timeoutMs },
        { events: [EVENT], edges: [] },
      ).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(TypeError);
    }
  });
});

describe("resolveConfig — VERITIO_INGEST_TIMEOUT_MS (process boundary only)", () => {
  const base = {
    VERITIO_INGEST_URL: "https://example.invalid/ingest",
    VERITIO_INGEST_KEY: "vrt_test",
  };

  test("unset: ingest config carries no timeout (postToIngest applies the default)", () => {
    const config = resolveConfig({ ...base } as NodeJS.ProcessEnv);
    expect(config.ingest?.timeoutMs).toBeUndefined();
  });

  test("set: a positive integer flows into ingest.timeoutMs", () => {
    const config = resolveConfig({ ...base, VERITIO_INGEST_TIMEOUT_MS: "3000" } as NodeJS.ProcessEnv);
    expect(config.ingest?.timeoutMs).toBe(3_000);
  });

  test("invalid values fail closed instead of capturing with a broken bound", () => {
    for (const bad of ["0", "-5", "abc", "1.5", String(MAX_INGEST_TIMEOUT_MS + 1)]) {
      expect(() => resolveConfig({ ...base, VERITIO_INGEST_TIMEOUT_MS: bad } as NodeJS.ProcessEnv)).toThrow(
        "VERITIO_INGEST_TIMEOUT_MS",
      );
    }
  });

  test("ignored when ingest itself is not configured", () => {
    expect(() => resolveConfig({ VERITIO_INGEST_TIMEOUT_MS: "abc" } as NodeJS.ProcessEnv)).not.toThrow();
  });
});
