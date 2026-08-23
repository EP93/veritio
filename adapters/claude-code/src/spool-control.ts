import { join } from "node:path";

import {
  bytesIn,
  createEntry,
  entryNames,
  moveAll,
  openCircuit,
  prepareQueue,
  readEntry,
  stateDir,
  totalEntryBytes,
  totalEntryCount,
  withMutationLock,
  writeEntry,
  writeState,
} from "./spool-files.js";
import {
  DEFAULT_SPOOL_LIMITS,
  type SpoolEntry,
  type SpoolLimits,
  type SpoolPayload,
  type SpoolStatus,
} from "./spool-types.js";

/** Validates local hard bounds before they influence evidence retention. */
export function validateSpoolLimits(limits: SpoolLimits): void {
  if (
    !Number.isSafeInteger(limits.hardBatches) ||
    limits.hardBatches < 1 ||
    !Number.isSafeInteger(limits.hardBytes) ||
    limits.hardBytes < 1
  ) {
    throw new Error("spool limits must be finite positive integers");
  }
}

/** Applies the active sticky circuit metadata to a newly held entry. */
function applyCircuit(entry: SpoolEntry, circuit: NonNullable<ReturnType<typeof prepareQueue>["circuit"]>): void {
  entry.disposition = "pause";
  entry.code = circuit.code;
  entry.reason = circuit.reason;
  if (circuit.circuitId) entry.circuitId = circuit.circuitId;
  if (circuit.retryAt) entry.retryAt = circuit.retryAt;
}

/** Opens the queue-full circuit without deleting any existing remote-delivery copy. */
export function holdQueueFull(localDir: string, state: ReturnType<typeof prepareQueue>): void {
  state.queueFull = true;
  moveAll(localDir, "pending", "held");
  openCircuit(state, {
    code: "queue_full",
    reason: "Local queue hard bound reached; newest remote-delivery copy was not stored.",
  });
  writeState(localDir, state);
}

/** Returns whether another payload would exceed the shared pending/held/quarantine bound. */
export function wouldExceedLimits(localDir: string, payload: SpoolPayload, limits: SpoolLimits): boolean {
  const newBytes = Buffer.byteLength(JSON.stringify(payload));
  return totalEntryCount(localDir) + 1 > limits.hardBatches || totalEntryBytes(localDir) + newBytes > limits.hardBytes;
}

/** Writes a new entry to pending or held according to the active circuit. */
export function appendForState(
  localDir: string,
  state: ReturnType<typeof prepareQueue>,
  payload: SpoolPayload,
): "saved" | "held" {
  const destination = state.circuit ? "held" : "pending";
  const created = createEntry(state, payload);
  if (state.circuit) applyCircuit(created.entry, state.circuit);
  writeEntry(localDir, destination, created.name, created.entry);
  writeState(localDir, state);
  return destination === "held" ? "held" : "saved";
}

/**
 * Queues a batch without evicting prior evidence. When the hard bound is hit,
 * the existing queue enters sticky hold and the newest remote copy is refused.
 */
export function saveToSpool(
  localDir: string,
  payload: SpoolPayload,
  limits: SpoolLimits = DEFAULT_SPOOL_LIMITS,
): "saved" | "held" | "full" | "failed" {
  try {
    validateSpoolLimits(limits);
    return withMutationLock(localDir, () => {
      const state = prepareQueue(localDir);
      if (state.queueFull || wouldExceedLimits(localDir, payload, limits)) {
        holdQueueFull(localDir, state);
        process.stderr.write(
          "veritio-claude-code: queue full; retained existing evidence and refused newest remote copy\n",
        );
        return "full";
      }
      return appendForState(localDir, state, payload);
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    process.stderr.write(`veritio-claude-code: spool write failed: ${message}\n`);
    return "failed";
  }
}

/** Returns pending entry names for compatibility with pre-state-machine callers. */
export function listSpool(localDir: string): string[] {
  try {
    return withMutationLock(localDir, () => {
      prepareQueue(localDir);
      return entryNames(localDir, "pending");
    });
  } catch {
    return [];
  }
}

/** Returns payload-free queue counts, bytes, and current sticky circuit. */
export function inspectSpool(localDir: string): SpoolStatus {
  return withMutationLock(localDir, () => {
    const state = prepareQueue(localDir);
    const pending = entryNames(localDir, "pending").length;
    const held = entryNames(localDir, "held").length;
    const quarantined = entryNames(localDir, "quarantine").length;
    const pendingBytes = bytesIn(localDir, "pending");
    const heldBytes = bytesIn(localDir, "held");
    const quarantinedBytes = bytesIn(localDir, "quarantine");
    return {
      pending,
      held,
      quarantined,
      total: pending + held + quarantined,
      pendingBytes,
      heldBytes,
      quarantinedBytes,
      totalBytes: pendingBytes + heldBytes + quarantinedBytes,
      queueFull: state.queueFull,
      circuit: state.circuit,
    };
  });
}

/** Places all pending batches into a sticky operator-visible hold. */
export function pauseSpool(
  localDir: string,
  details: { code: string; reason: string; circuitId?: string; retryAt?: string },
): void {
  if (!details.code.trim() || !details.reason.trim()) {
    throw new Error("pause requires a code and reason");
  }
  withMutationLock(localDir, () => {
    const state = prepareQueue(localDir);
    moveAll(localDir, "pending", "held");
    openCircuit(state, details);
    writeState(localDir, state);
  });
}

/**
 * Clears a sticky hold after explicit acknowledgement and moves held entries to
 * pending; it deliberately performs no network I/O and grants no replay epoch.
 */
export function resumeSpool(localDir: string, acknowledgement: string): void {
  if (!acknowledgement.trim()) {
    throw new Error("resume requires an operator acknowledgement");
  }
  withMutationLock(localDir, () => {
    const state = prepareQueue(localDir);
    moveAll(localDir, "held", "pending");
    state.circuit = null;
    state.queueFull = false;
    writeState(localDir, state);
  });
}

/** Returns decodable quarantined envelopes for explicit operator inspection. */
export function quarantinedSpoolEntries(localDir: string): SpoolEntry[] {
  return withMutationLock(localDir, () => {
    prepareQueue(localDir);
    const entries: SpoolEntry[] = [];
    for (const name of entryNames(localDir, "quarantine")) {
      try {
        entries.push(readEntry(join(stateDir(localDir, "quarantine"), name)));
      } catch {
        // Raw corrupt bytes remain counted by inspectSpool and are never deleted.
      }
    }
    return entries;
  });
}
