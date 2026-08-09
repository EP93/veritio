import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ensureLayout, prepareQueue, readEntry, stateDir, writeEntry, writeState } from "../spool-files";
import type { SpoolEntry, SpoolPayload } from "../spool-types";

/**
 * Regression suite for durable queue file recovery. It pins the crash-restart
 * invariant that legacy migration can never mint a sequence filename that
 * atomically replaces an already-migrated held entry (evidence loss).
 */

const dirs: string[] = [];

/** Allocates one isolated queue root and schedules deterministic cleanup. */
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "veritio-spool-files-"));
  dirs.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/** Builds one minimal valid spool payload with a distinguishable marker id. */
function payloadOf(marker: string): SpoolPayload {
  return { events: [{ id: marker } as unknown as SpoolPayload["events"][number]], edges: [] };
}

/** Builds one already-migrated durable entry envelope at a fixed sequence. */
function heldEntry(sequence: number, marker: string): SpoolEntry {
  const payload = payloadOf(marker);
  return {
    version: 1,
    sequence,
    capturedAt: "2026-08-02T00:00:00.000Z",
    payload,
    encodedBytes: Buffer.byteLength(JSON.stringify(payload)),
    recordCount: 1,
    attempts: 0,
    disposition: "pause",
    code: "legacy_queue_upgrade",
    reason: "Legacy queue requires an explicit operator replay permit.",
  };
}

describe("prepareQueue crash recovery", () => {
  test("interrupted legacy migration never overwrites an already-migrated entry", () => {
    const dir = tempDir();
    ensureLayout(dir);
    // Simulate a migration that crashed after moving one legacy batch into the
    // held queue (sequence 1) but BEFORE persisting state.json: state still
    // says nextSequence 1 while a remaining legacy root file awaits migration.
    writeEntry(dir, "held", "000000000000001.json", heldEntry(1, "already-migrated"));
    writeState(dir, { version: 1, nextSequence: 1, circuit: null, queueFull: false });
    writeFileSync(join(dir, "spool", "batch-legacy.json"), JSON.stringify(payloadOf("still-legacy")), "utf8");

    const state = prepareQueue(dir);

    const held = readdirSync(stateDir(dir, "held")).sort();
    expect(held).toEqual(["000000000000001.json", "000000000000002.json"]);
    const first = readEntry(join(stateDir(dir, "held"), "000000000000001.json"));
    const second = readEntry(join(stateDir(dir, "held"), "000000000000002.json"));
    expect((first.payload.events[0] as unknown as { id: string }).id).toBe("already-migrated");
    expect((second.payload.events[0] as unknown as { id: string }).id).toBe("still-legacy");
    expect(state.nextSequence).toBe(3);
    expect(state.circuit?.code).toBe("legacy_queue_upgrade");
  });
});
