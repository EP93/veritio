import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

import type { SpoolCircuit, SpoolEntry, SpoolPayload } from "./spool-types.js";

export type DurableQueueState = "pending" | "held" | "quarantine";

/** Durable queue metadata is mutated only while the cross-process lock is held. */
export interface SpoolState {
  version: 1;
  nextSequence: number;
  circuit: SpoolCircuit | null;
  queueFull: boolean;
}

const STATE_VERSION = 1;
const ENTRY_VERSION = 1;
const MUTATION_LOCK_WAIT_MS = 2_000;
const MUTATION_LOCK_STALE_MS = 30_000;
const LOCK_SLEEP_ARRAY = new Int32Array(new SharedArrayBuffer(4));

/** Resolves the queue root without depending on process environment state. */
export function spoolDir(localDir: string): string {
  return join(localDir, "spool");
}

/** Resolves one durable queue-state directory. */
export function stateDir(localDir: string, state: DurableQueueState): string {
  return join(spoolDir(localDir), state);
}

/** Creates the queue layout before a lock or atomic rename is attempted. */
export function ensureLayout(localDir: string): void {
  mkdirSync(stateDir(localDir, "pending"), { recursive: true });
  mkdirSync(stateDir(localDir, "held"), { recursive: true });
  mkdirSync(stateDir(localDir, "quarantine"), { recursive: true });
}

/** Blocks briefly while another process completes an atomic queue mutation. */
function sleepSync(milliseconds: number): void {
  Atomics.wait(LOCK_SLEEP_ARRAY, 0, 0, milliseconds);
}

/** Returns whether an unknown filesystem error is a specific Node error code. */
function hasErrorCode(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}

/**
 * Acquires a cross-process directory lock. Stale locks are recoverable because
 * every permitted replay is capped at 15 seconds and mutations never await I/O.
 */
export function acquireDirectoryLock(path: string, waitMs: number, staleMs: number): () => void {
  const deadline = Date.now() + waitMs;
  while (true) {
    try {
      mkdirSync(path);
      try {
        writeFileSync(join(path, "owner"), `${process.pid}\n${Date.now()}\n`, "utf8");
      } catch (error) {
        rmSync(path, { recursive: true, force: true });
        throw error;
      }
      return () => rmSync(path, { recursive: true, force: true });
    } catch (error) {
      if (!hasErrorCode(error, "EEXIST")) {
        throw error;
      }
      try {
        if (Date.now() - statSync(path).mtimeMs > staleMs) {
          rmSync(path, { recursive: true, force: true });
          continue;
        }
      } catch {
        continue;
      }
      if (Date.now() >= deadline) {
        throw new Error("spool queue is busy");
      }
      sleepSync(10);
    }
  }
}

/** Runs one synchronous queue mutation under a cross-process lock. */
export function withMutationLock<T>(localDir: string, operation: () => T): T {
  ensureLayout(localDir);
  const release = acquireDirectoryLock(
    join(spoolDir(localDir), ".mutation.lock"),
    MUTATION_LOCK_WAIT_MS,
    MUTATION_LOCK_STALE_MS,
  );
  try {
    return operation();
  } finally {
    release();
  }
}

/** Writes a file through fsync and atomic rename so partial JSON is never visible. */
function writeAtomic(path: string, contents: string): void {
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const descriptor = openSync(temporary, "wx", 0o600);
  try {
    writeFileSync(descriptor, contents, "utf8");
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  renameSync(temporary, path);
}

/** Produces the initial fail-closed queue state. */
function initialState(): SpoolState {
  return { version: STATE_VERSION, nextSequence: 1, circuit: null, queueFull: false };
}

/** Reads queue state, preserving malformed state bytes and entering manual hold. */
function readState(localDir: string): SpoolState {
  const path = join(spoolDir(localDir), "state.json");
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<SpoolState>;
    if (
      parsed.version !== STATE_VERSION ||
      !Number.isSafeInteger(parsed.nextSequence) ||
      (parsed.nextSequence ?? 0) < 1 ||
      typeof parsed.queueFull !== "boolean" ||
      !(parsed.circuit === null || typeof parsed.circuit === "object")
    ) {
      throw new Error("invalid spool state");
    }
    return parsed as SpoolState;
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) {
      return initialState();
    }
    try {
      renameSync(path, join(spoolDir(localDir), `state.corrupt-${Date.now()}.json`));
    } catch {
      // The original failure is still represented by the fail-closed circuit.
    }
    const recovered: SpoolState = {
      ...initialState(),
      circuit: {
        code: "queue_state_corrupt",
        reason: "Queue state could not be decoded; operator acknowledgement is required.",
        openedAt: new Date().toISOString(),
      },
    };
    writeAtomic(path, JSON.stringify(recovered));
    return recovered;
  }
}

/** Persists queue state atomically while the caller holds the mutation lock. */
export function writeState(localDir: string, state: SpoolState): void {
  writeAtomic(join(spoolDir(localDir), "state.json"), JSON.stringify(state));
}

/** Returns lexically ordered entry names, which are also capture order. */
export function entryNames(localDir: string, state: DurableQueueState): string[] {
  try {
    return readdirSync(stateDir(localDir, state))
      .filter((name) => name.endsWith(".json") && !name.includes(".tmp-"))
      .sort();
  } catch {
    return [];
  }
}

/** Validates and decodes one durable entry without normalizing its payload. */
export function readEntry(path: string): SpoolEntry {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<SpoolEntry>;
  if (
    parsed.version !== ENTRY_VERSION ||
    !Number.isSafeInteger(parsed.sequence) ||
    typeof parsed.encodedBytes !== "number" ||
    typeof parsed.recordCount !== "number" ||
    !parsed.payload ||
    !Array.isArray(parsed.payload.events) ||
    !Array.isArray(parsed.payload.edges)
  ) {
    throw new Error("invalid spool entry");
  }
  return parsed as SpoolEntry;
}

/** Persists one entry envelope atomically in its current state. */
export function writeEntry(localDir: string, state: DurableQueueState, name: string, entry: SpoolEntry): void {
  writeAtomic(join(stateDir(localDir, state), name), JSON.stringify(entry));
}

/** Allocates one monotonically ordered entry while holding the mutation lock. */
export function createEntry(state: SpoolState, payload: SpoolPayload): { entry: SpoolEntry; name: string } {
  const payloadJson = JSON.stringify(payload);
  const sequence = state.nextSequence;
  state.nextSequence += 1;
  return {
    name: `${String(sequence).padStart(15, "0")}.json`,
    entry: {
      version: ENTRY_VERSION,
      sequence,
      capturedAt: new Date().toISOString(),
      payload,
      encodedBytes: Buffer.byteLength(payloadJson),
      recordCount: payload.events.length + payload.edges.length,
      attempts: 0,
    },
  };
}

/** Moves an entry between durable states without rewriting its payload. */
export function moveEntry(localDir: string, name: string, from: DurableQueueState, to: DurableQueueState): void {
  if (from !== to) {
    renameSync(join(stateDir(localDir, from), name), join(stateDir(localDir, to), name));
  }
}

/** Moves all entries between queue states in deterministic order. */
export function moveAll(localDir: string, from: "pending" | "held", to: "pending" | "held"): void {
  for (const name of entryNames(localDir, from)) {
    moveEntry(localDir, name, from, to);
  }
}

/** Opens a sticky circuit while preserving an existing, more specific hold. */
export function openCircuit(
  state: SpoolState,
  details: { code: string; reason: string; circuitId?: string; retryAt?: string },
): void {
  state.circuit = {
    code: details.code,
    reason: details.reason,
    openedAt: new Date().toISOString(),
    ...(details.circuitId ? { circuitId: details.circuitId } : {}),
    ...(details.retryAt ? { retryAt: details.retryAt } : {}),
  };
}

/** Upgrades pre-state-machine root JSON batches into a manual held queue. */
function migrateLegacyEntries(localDir: string, state: SpoolState): boolean {
  const root = spoolDir(localDir);
  let migrated = false;
  const names = readdirSync(root)
    .filter(
      (name) =>
        name.endsWith(".json") &&
        name !== "state.json" &&
        !name.startsWith("state.corrupt-") &&
        !name.includes(".tmp-"),
    )
    .sort();
  for (const legacyName of names) {
    const legacyPath = join(root, legacyName);
    try {
      const payload = JSON.parse(readFileSync(legacyPath, "utf8")) as SpoolPayload;
      if (!Array.isArray(payload.events) || !Array.isArray(payload.edges)) {
        throw new Error("invalid legacy spool payload");
      }
      const created = createEntry(state, payload);
      created.entry.disposition = "pause";
      created.entry.code = "legacy_queue_upgrade";
      created.entry.reason = "Legacy queue requires an explicit operator replay permit.";
      writeEntry(localDir, "held", created.name, created.entry);
      rmSync(legacyPath, { force: true });
    } catch {
      renameSync(legacyPath, join(stateDir(localDir, "quarantine"), `legacy-${Date.now()}-${legacyName}`));
    }
    migrated = true;
  }
  if (migrated) {
    moveAll(localDir, "pending", "held");
    openCircuit(state, {
      code: "legacy_queue_upgrade",
      reason: "Legacy queue requires an explicit operator replay permit.",
    });
  }
  return migrated;
}

/** Reconstructs the next sequence from durable filenames after state loss. */
function reconcileNextSequence(localDir: string, state: SpoolState): boolean {
  let maximum = 0;
  for (const queueState of ["pending", "held", "quarantine"] as const) {
    for (const name of entryNames(localDir, queueState)) {
      const match = name.match(/^(\d+)\.json$/);
      const sequence = match?.[1] ? Number(match[1]) : 0;
      if (Number.isSafeInteger(sequence)) maximum = Math.max(maximum, sequence);
    }
  }
  if (state.nextSequence <= maximum) {
    state.nextSequence = maximum + 1;
    return true;
  }
  return false;
}

/** Reads state, repairs sequence metadata, and applies fail-closed migrations. */
export function prepareQueue(localDir: string): SpoolState {
  const state = readState(localDir);
  // Sequence reconciliation MUST precede legacy migration: if a prior migration
  // crashed after writing held entries but before persisting state.json, a
  // stale nextSequence would mint filenames that atomically replace those
  // already-migrated entries (silent evidence loss). Deriving the floor from
  // durable filenames first makes the migration crash-restartable.
  let changed = reconcileNextSequence(localDir, state);
  if (migrateLegacyEntries(localDir, state)) changed = true;
  if (state.circuit && entryNames(localDir, "pending").length > 0) {
    moveAll(localDir, "pending", "held");
    changed = true;
  }
  if (changed) writeState(localDir, state);
  return state;
}

/** Sums recorded payload bytes without decoding or re-encoding the payloads. */
export function bytesIn(localDir: string, state: DurableQueueState): number {
  let total = 0;
  for (const name of entryNames(localDir, state)) {
    try {
      total += readEntry(join(stateDir(localDir, state), name)).encodedBytes;
    } catch {
      total += statSync(join(stateDir(localDir, state), name)).size;
    }
  }
  return total;
}

/** Counts every durable remote-delivery copy, including quarantine. */
export function totalEntryCount(localDir: string): number {
  return (
    entryNames(localDir, "pending").length +
    entryNames(localDir, "held").length +
    entryNames(localDir, "quarantine").length
  );
}

/** Sums every durable remote-delivery copy against the shared hard byte bound. */
export function totalEntryBytes(localDir: string): number {
  return bytesIn(localDir, "pending") + bytesIn(localDir, "held") + bytesIn(localDir, "quarantine");
}
