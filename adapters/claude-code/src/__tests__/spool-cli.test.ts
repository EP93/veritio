import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AuditEvent } from "@veritio/core";

import { pauseSpool, saveToSpool } from "../spool";
import { runSpoolCli } from "../spool-cli";

const directories: string[] = [];
const received: string[] = [];
let requests = 0;
const server = Bun.serve({
  port: 0,
  async fetch(request) {
    requests += 1;
    const body = (await request.json()) as { events: Array<{ id: string }> };
    received.push(...body.events.map((event) => event.id));
    return Response.json({ appended: { events: body.events.length, edges: 0 } });
  },
});

/** Creates an isolated queue root for one CLI boundary test. */
function tempDir(): string {
  const directory = mkdtempSync(join(tmpdir(), "veritio-spool-cli-"));
  directories.push(directory);
  return directory;
}

/** Produces a small redacted batch while retaining a sentinel id for leak tests. */
function payloadOf(id: string) {
  return {
    events: [
      {
        id,
        schemaVersion: "1.0",
        occurredAt: "2026-08-02T00:00:00.000Z",
        actor: { id: "operator", type: "user" },
        action: "debug.spool.cli",
        target: { id: "queue", type: "diagnostic" },
        metadata: {},
      } as unknown as AuditEvent,
    ],
    edges: [],
  };
}

/** Runs the CLI with captured output and injected environment state. */
async function run(args: string[], localDir: string, remote = false) {
  let stdout = "";
  let stderr = "";
  const env = {
    VERITIO_LOCAL_DIR: localDir,
    ...(remote ? { VERITIO_INGEST_URL: server.url.href, VERITIO_INGEST_KEY: "vrt_test", VERITIO_TENANT_ID: "t1" } : {}),
  } as NodeJS.ProcessEnv;
  const exitCode = await runSpoolCli(args, env, {
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
  });
  return { exitCode, stdout, stderr };
}

afterEach(() => {
  requests = 0;
  received.length = 0;
});

afterAll(() => {
  server.stop(true);
  for (const directory of directories) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("spool operator CLI", () => {
  test("status and quarantine output metadata but never queued payload ids", async () => {
    const directory = tempDir();
    saveToSpool(directory, payloadOf("evt_do_not_print"));
    pauseSpool(directory, { code: "operator_pause", reason: "cost review" });

    const status = await run(["status"], directory);
    expect(status.exitCode).toBe(0);
    expect(JSON.parse(status.stdout)).toMatchObject({ pending: 0, held: 1, circuit: { code: "operator_pause" } });
    expect(status.stdout).not.toContain("evt_do_not_print");

    const quarantine = await run(["quarantine"], directory);
    expect(quarantine.exitCode).toBe(0);
    expect(JSON.parse(quarantine.stdout)).toEqual([]);
  });

  test("pause and resume mutate queue state without granting a replay", async () => {
    const directory = tempDir();
    saveToSpool(directory, payloadOf("evt_pending"));

    expect((await run(["pause", "--reason", "provider transfer alarm"], directory)).exitCode).toBe(0);
    expect((await run(["resume", "--acknowledge", "headroom reviewed"], directory)).exitCode).toBe(0);
    expect(requests).toBe(0);
    expect(JSON.parse((await run(["status"], directory)).stdout)).toMatchObject({ pending: 1, held: 0 });
  });

  test("drain refuses any omitted or unbounded budget before network I/O", async () => {
    const directory = tempDir();
    saveToSpool(directory, payloadOf("evt_kept"));

    const incomplete = await run(
      ["drain", "--max-batches", "1", "--max-records", "10", "--max-bytes", "100000"],
      directory,
      true,
    );
    expect(incomplete.exitCode).toBe(2);
    expect(incomplete.stderr).toContain("all four finite replay budgets");

    const unbounded = await run(
      [
        "drain",
        "--max-batches",
        "Infinity",
        "--max-records",
        "10",
        "--max-bytes",
        "100000",
        "--max-elapsed-ms",
        "5000",
      ],
      directory,
      true,
    );
    expect(unbounded.exitCode).toBe(2);
    expect(requests).toBe(0);
  });

  test("canary grants exactly one bounded request and leaves the remaining queue", async () => {
    const directory = tempDir();
    saveToSpool(directory, payloadOf("evt_canary"));
    saveToSpool(directory, payloadOf("evt_later"));

    const result = await run(["canary"], directory, true);

    expect(result.exitCode).toBe(0);
    expect(requests).toBe(1);
    expect(received).toEqual(["evt_canary"]);
    expect(JSON.parse(result.stdout)).toMatchObject({ attemptedBatches: 1, dispatchedBatches: 1 });
    expect(JSON.parse((await run(["status"], directory)).stdout).pending).toBe(1);
  });
});
