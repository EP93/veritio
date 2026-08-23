import { rmSync } from "node:fs";
import { join } from "node:path";

import { deliveryDispositionOf, IngestHttpError, postToIngest } from "./ingest.js";
import {
  appendForState,
  holdQueueFull,
  pauseSpool,
  saveToSpool,
  validateSpoolLimits,
  wouldExceedLimits,
} from "./spool-control.js";
import {
  acquireDirectoryLock,
  createEntry,
  ensureLayout,
  entryNames,
  moveEntry,
  prepareQueue,
  readEntry,
  spoolDir,
  stateDir,
  withMutationLock,
  writeEntry,
  writeState,
} from "./spool-files.js";
import {
  DEFAULT_SPOOL_LIMITS,
  FLUSH_TIMEOUT_MS,
  MAX_REPLAY_PERMIT,
  type ReplayPermit,
  type ReplayResult,
  type SpoolEntry,
  type SpoolLimits,
  type SpoolPayload,
} from "./spool-types.js";

export {
  inspectSpool,
  listSpool,
  pauseSpool,
  quarantinedSpoolEntries,
  resumeSpool,
  saveToSpool,
} from "./spool-control.js";
export * from "./spool-types.js";

interface EntryLocation {
  entry: SpoolEntry;
  name: string;
  state: "pending" | "held";
}

const REPLAY_LOCK_STALE_MS = 60_000;

/** Returns whether one permit dimension is a positive integer under its hard ceiling. */
function isFinitePositiveWithin(value: unknown, maximum: number): boolean {
  return Number.isSafeInteger(value) && (value as number) > 0 && (value as number) <= maximum;
}

/** Validates that a replay request is finite, bounded, and explicit. */
function validateReplayPermit(permit: ReplayPermit | undefined): asserts permit is ReplayPermit {
  if (
    !permit ||
    typeof permit.id !== "string" ||
    !permit.id.trim() ||
    (permit.kind !== "canary" && permit.kind !== "drain") ||
    !isFinitePositiveWithin(permit.maxBatches, MAX_REPLAY_PERMIT.maxBatches) ||
    !isFinitePositiveWithin(permit.maxRecords, MAX_REPLAY_PERMIT.maxRecords) ||
    !isFinitePositiveWithin(permit.maxBytes, MAX_REPLAY_PERMIT.maxBytes) ||
    !isFinitePositiveWithin(permit.maxElapsedMs, MAX_REPLAY_PERMIT.maxElapsedMs) ||
    (permit.kind === "canary" && permit.maxBatches !== 1) ||
    (permit.kind === "canary" && permit.maxRecords > 500)
  ) {
    throw new Error("flush requires a finite replay permit within hard safety bounds");
  }
}

/** Selects the oldest held batch during a circuit, otherwise the oldest pending batch. */
function oldestReplayEntry(localDir: string): EntryLocation | null {
  return withMutationLock(localDir, () => {
    const state = prepareQueue(localDir);
    const held = entryNames(localDir, "held")[0];
    const pending = entryNames(localDir, "pending")[0];
    const selectedState = state.circuit && held ? "held" : pending ? "pending" : held ? "held" : null;
    const name = selectedState === "held" ? held : selectedState === "pending" ? pending : undefined;
    if (!selectedState || !name) return null;
    try {
      return {
        entry: readEntry(join(stateDir(localDir, selectedState), name)),
        name,
        state: selectedState,
      };
    } catch {
      moveEntry(localDir, name, selectedState, "quarantine");
      return null;
    }
  });
}

/** Finds an entry that may have moved between pending and held during a request. */
function findActiveState(localDir: string, name: string): "pending" | "held" | null {
  if (entryNames(localDir, "pending").includes(name)) return "pending";
  if (entryNames(localDir, "held").includes(name)) return "held";
  return null;
}

/** Deletes a successfully dispatched entry under the queue mutation lock. */
function removeDispatchedEntry(localDir: string, name: string): void {
  withMutationLock(localDir, () => {
    const activeState = findActiveState(localDir, name);
    if (activeState) rmSync(join(stateDir(localDir, activeState), name), { force: true });
  });
}

/** Records a retry outcome without deleting or silently transforming payload bytes. */
function retainRetryEntry(localDir: string, location: EntryLocation, error: unknown): void {
  withMutationLock(localDir, () => {
    const activeState = findActiveState(localDir, location.name);
    if (!activeState) return;
    const details = error instanceof IngestHttpError ? error : undefined;
    writeEntry(localDir, activeState, location.name, {
      ...location.entry,
      attempts: location.entry.attempts + 1,
      disposition: "retry",
      ...(details?.code ? { code: details.code } : {}),
      ...(details?.retryAt ? { retryAt: details.retryAt } : {}),
    });
  });
}

/** Moves a rejected entry to durable quarantine with bounded response metadata. */
function quarantineEntry(localDir: string, location: EntryLocation, error: unknown): void {
  withMutationLock(localDir, () => {
    const activeState = findActiveState(localDir, location.name);
    if (!activeState) return;
    const details = error instanceof IngestHttpError ? error : undefined;
    writeEntry(localDir, activeState, location.name, {
      ...location.entry,
      attempts: location.entry.attempts + 1,
      disposition: "reject",
      ...(details?.code ? { code: details.code } : {}),
      reason: details
        ? `Remote ingest rejected the batch with HTTP ${details.status}.`
        : "Remote ingest rejected the batch.",
    });
    moveEntry(localDir, location.name, activeState, "quarantine");
  });
}

/** Persists a newly rejected direct ship-out without bypassing shared queue bounds. */
function quarantinePayload(
  localDir: string,
  payload: SpoolPayload,
  error: unknown,
  limits: SpoolLimits,
): "quarantined" | "full" {
  return withMutationLock(localDir, () => {
    const state = prepareQueue(localDir);
    if (state.queueFull || wouldExceedLimits(localDir, payload, limits)) {
      holdQueueFull(localDir, state);
      return "full";
    }
    const created = createEntry(state, payload);
    const details = error instanceof IngestHttpError ? error : undefined;
    created.entry.attempts = 1;
    created.entry.disposition = "reject";
    if (details?.code) created.entry.code = details.code;
    created.entry.reason = details
      ? `Remote ingest rejected the batch with HTTP ${details.status}.`
      : "Remote ingest rejected the batch.";
    writeEntry(localDir, "quarantine", created.name, created.entry);
    writeState(localDir, state);
    return "quarantined";
  });
}

/** Converts a pause response into a sticky circuit and holds the entire queue. */
function holdForPause(localDir: string, error: unknown): void {
  const details = error instanceof IngestHttpError ? error : undefined;
  pauseSpool(localDir, {
    code: details?.code ?? "remote_delivery_paused",
    reason: details ? `Remote ingest paused delivery with HTTP ${details.status}.` : "Remote ingest paused delivery.",
    ...(details?.circuitId ? { circuitId: details.circuitId } : {}),
    ...(details?.retryAt ? { retryAt: details.retryAt } : {}),
  });
}

/**
 * Replays only under an explicit finite permit. Aggregate batch, record, byte,
 * and elapsed budgets are checked before every request; ordinary hooks never
 * call this function.
 */
export async function flushSpool(
  ingest: { url: string; key: string; timeoutMs?: number },
  localDir: string,
  permit: ReplayPermit,
): Promise<ReplayResult> {
  validateReplayPermit(permit);
  ensureLayout(localDir);
  const releaseReplay = acquireDirectoryLock(join(spoolDir(localDir), ".replay.lock"), 0, REPLAY_LOCK_STALE_MS);
  const result: ReplayResult = {
    attemptedBatches: 0,
    attemptedRecords: 0,
    attemptedBytes: 0,
    dispatchedBatches: 0,
    quarantinedBatches: 0,
    paused: false,
  };
  const startedAt = Date.now();
  try {
    while (result.attemptedBatches < permit.maxBatches) {
      const remainingMs = permit.maxElapsedMs - (Date.now() - startedAt);
      if (remainingMs < 1) break;
      const location = oldestReplayEntry(localDir);
      if (!location) break;
      if (
        result.attemptedRecords + location.entry.recordCount > permit.maxRecords ||
        result.attemptedBytes + location.entry.encodedBytes > permit.maxBytes
      ) {
        break;
      }
      result.attemptedBatches += 1;
      result.attemptedRecords += location.entry.recordCount;
      result.attemptedBytes += location.entry.encodedBytes;
      try {
        await postToIngest(
          { ...ingest, timeoutMs: Math.max(1, Math.min(ingest.timeoutMs ?? FLUSH_TIMEOUT_MS, remainingMs)) },
          location.entry.payload,
          "replay-v1",
        );
        removeDispatchedEntry(localDir, location.name);
        result.dispatchedBatches += 1;
      } catch (error) {
        const disposition = deliveryDispositionOf(error);
        if (disposition === "pause") {
          holdForPause(localDir, error);
          result.paused = true;
          break;
        }
        if (disposition === "reject") {
          quarantineEntry(localDir, location, error);
          result.quarantinedBatches += 1;
          continue;
        }
        retainRetryEntry(localDir, location, error);
        break;
      }
    }
    return result;
  } finally {
    releaseReplay();
  }
}

/** Atomically queues behind any existing backlog or circuit without dispatching it. */
function queueIfBlocked(
  localDir: string,
  payload: SpoolPayload,
  limits: SpoolLimits,
): "queued" | "clear" | "full" | "failed" {
  try {
    validateSpoolLimits(limits);
    return withMutationLock(localDir, () => {
      const state = prepareQueue(localDir);
      if (state.queueFull || wouldExceedLimits(localDir, payload, limits)) {
        holdQueueFull(localDir, state);
        return "full";
      }
      const backlogged = entryNames(localDir, "pending").length + entryNames(localDir, "held").length > 0;
      if (!state.circuit && !backlogged) return "clear";
      appendForState(localDir, state, payload);
      return "queued";
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    process.stderr.write(`veritio-claude-code: queue check failed: ${message}\n`);
    return "failed";
  }
}

/**
 * Ships only when the durable queue is clear. Any backlog or sticky circuit
 * turns ordinary capture into append-only local persistence with zero replay.
 */
export async function shipWithSpool(
  ingest: { url: string; key: string; timeoutMs?: number },
  localDir: string,
  payload: SpoolPayload,
  limits: SpoolLimits = DEFAULT_SPOOL_LIMITS,
): Promise<void> {
  if (payload.events.length === 0 && payload.edges.length === 0) return;
  const blocked = queueIfBlocked(localDir, payload, limits);
  if (blocked !== "clear") {
    if (blocked === "full") {
      process.stderr.write(
        "veritio-claude-code: queue full; retained existing evidence and refused newest remote copy\n",
      );
    }
    return;
  }
  try {
    await postToIngest(ingest, payload);
  } catch (error) {
    const disposition = deliveryDispositionOf(error);
    if (disposition === "pause") {
      holdForPause(localDir, error);
      saveToSpool(localDir, payload, limits);
      process.stderr.write("veritio-claude-code: remote delivery paused; batch retained in held queue\n");
      return;
    }
    if (disposition === "reject") {
      const quarantineResult = quarantinePayload(localDir, payload, error, limits);
      process.stderr.write(
        quarantineResult === "quarantined"
          ? "veritio-claude-code: remote delivery rejected; batch retained in quarantine\n"
          : "veritio-claude-code: queue full after remote rejection; local evidence remains authoritative\n",
      );
      return;
    }
    saveToSpool(localDir, payload, limits);
    process.stderr.write("veritio-claude-code: ingest unavailable; batch retained for explicit replay\n");
  }
}
