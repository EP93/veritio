import { afterAll, describe, expect, test } from "bun:test";
import type { AuditEvent } from "@veritio/core";

import { resolveConfig } from "../config";
import { DEFAULT_INGEST_TIMEOUT_MS, MAX_INGEST_TIMEOUT_MS, postToIngest } from "../ingest";

/**
 * Mirrors `@veritio/claude-code`'s ingest regression suite (capture-adapter
 * parity): a stalled ingest endpoint must abort within the configured bound —
 * never hang the notify hook — and the bound is resolved only at the env
 * process boundary.
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
/** Never resolves: simulates the prod hang that froze the capturing agent. */
const hangingServer = Bun.serve({
  port: 0,
  fetch() {
    requests += 1;
    return new Promise<Response>(() => {});
  },
});

afterAll(() => {
  hangingServer.stop(true);
});

describe("postToIngest — bounded abort", () => {
  test("a never-responding endpoint rejects within the configured bound, not minutes", async () => {
    const started = Date.now();
    await postToIngest(
      { url: hangingServer.url.href, key: "vrt_test", timeoutMs: 250 },
      { events: [EVENT], edges: [] },
    ).catch(() => {});
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(
      postToIngest({ url: hangingServer.url.href, key: "vrt_test", timeoutMs: 250 }, { events: [EVENT], edges: [] }),
    ).rejects.toThrow();
  });

  test("the default bound exists and is finite", () => {
    expect(DEFAULT_INGEST_TIMEOUT_MS).toBeGreaterThan(0);
    expect(Number.isFinite(DEFAULT_INGEST_TIMEOUT_MS)).toBe(true);
    expect(MAX_INGEST_TIMEOUT_MS).toBe(30_000);
  });

  test("a direct caller cannot bypass the maximum timeout", () => {
    expect(
      postToIngest(
        { url: hangingServer.url.href, key: "vrt_test", timeoutMs: MAX_INGEST_TIMEOUT_MS + 1 },
        { events: [EVENT], edges: [] },
      ),
    ).rejects.toThrow(/between 1 and 30000/);
  });

  test("empty payload never opens a connection", async () => {
    const before = requests;
    await postToIngest({ url: hangingServer.url.href, key: "vrt_test", timeoutMs: 250 }, { events: [], edges: [] });
    expect(requests).toBe(before);
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
