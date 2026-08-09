import {
  DEFAULT_DELIVERY_SAFETY_POLICY,
  type DeliverySafetyPolicy,
  parseDeliverySafetyPolicy,
} from "./delivery-safety.js";
import { assertNonEmpty, outboxPayloadByteLength, validateListOptions, validatePayload } from "./outbox-shared.js";
import type {
  DispatchPermit,
  OutboxAdapter,
  OutboxDispatcher,
  OutboxDispatchOptions,
  OutboxDispatchResult,
  OutboxEvidenceTarget,
  OutboxPayload,
} from "./outbox-types.js";

/**
 * Durable-window transport accounting shared by every dispatch pass of one
 * dispatcher instance. Permits only authorize a single pass; the ledger is
 * what makes `hard.rollingRequests` / `hard.rollingSendBytes` hold ACROSS
 * passes, so a caller looping one-entry permits cannot bypass the ceiling.
 * Scope boundary: the ledger is per dispatcher instance (per process). The
 * per-tenant single active lease serializes concurrent dispatchers, and the
 * server-side economic-safety circuit is the cross-process backstop.
 */
export interface RollingWindowLedger {
  /** Requests still permitted inside the current rolling window. */
  remainingRequests(now: number): number;
  /** Bytes still permitted inside the current rolling window. */
  remainingBytes(now: number): number;
  /** Reserves one delivery attempt of `bytes` before the send happens. */
  record(now: number, bytes: number): void;
}

/** Creates a rolling request/byte ledger over the policy's hard window. */
export function createRollingWindowLedger(policy: Readonly<DeliverySafetyPolicy>): RollingWindowLedger {
  let sends: Array<{ at: number; bytes: number }> = [];
  /** Drops attempts that have aged out of the rolling window. */
  const prune = (now: number): void => {
    sends = sends.filter((send) => now - send.at < policy.hard.windowMs);
  };
  return {
    remainingRequests(now) {
      prune(now);
      return policy.hard.rollingRequests - sends.length;
    },
    remainingBytes(now) {
      prune(now);
      return policy.hard.rollingSendBytes - sends.reduce((total, send) => total + send.bytes, 0);
    },
    record(now, bytes) {
      prune(now);
      sends.push({ at: now, bytes });
    },
  };
}

/** Creates a bounded lease-aware dispatcher for a local evidence target. */
export function createOutboxDispatcher(options: {
  adapter: OutboxAdapter;
  target: OutboxEvidenceTarget;
  deliverySafety?: DeliverySafetyPolicy;
}): OutboxDispatcher {
  const policy = parseDeliverySafetyPolicy(options.deliverySafety);
  const ledger = createRollingWindowLedger(policy);
  return {
    async dispatchBatch(dispatchOptions) {
      validateDispatchOptions(dispatchOptions, policy);
      const result = emptyDispatchResult();
      const startedAt = Date.now();
      for (let index = 0; index < dispatchOptions.permit.maxEntries; index += 1) {
        if (Date.now() - startedAt >= dispatchOptions.permit.maxElapsedMs) break;
        if (ledger.remainingRequests(Date.now()) <= 0) break;
        const remainingBytes = Math.min(
          dispatchOptions.permit.maxBytes - result.bytes,
          ledger.remainingBytes(Date.now()),
        );
        if (remainingBytes <= 0) break;
        const [entry] = await options.adapter.claimDispatchable({
          tenantId: dispatchOptions.tenantId,
          ...(dispatchOptions.now === undefined ? {} : { now: dispatchOptions.now }),
          leaseId: dispatchLeaseId(dispatchOptions.permit, index),
          leaseMs: dispatchOptions.permit.leaseMs,
          limit: 1,
          maxPayloadBytes: Math.min(remainingBytes, policy.hard.batchBytes),
        });
        if (!entry) break;
        const entryBytes = outboxPayloadByteLength(entry.payload);
        ledger.record(Date.now(), entryBytes);
        result.bytes += entryBytes;
        try {
          await dispatchOutboxEntry(entry.payload, options.target);
          await options.adapter.markDispatched(
            entry.id,
            dispatchOptions.now === undefined
              ? { leaseId: entry.leaseId }
              : { leaseId: entry.leaseId, dispatchedAt: dispatchOptions.now },
          );
          result.dispatched += 1;
        } catch (error) {
          await options.adapter.markFailed(
            entry.id,
            error,
            dispatchOptions.now === undefined
              ? { leaseId: entry.leaseId, disposition: "retry" }
              : { leaseId: entry.leaseId, disposition: "retry", now: dispatchOptions.now },
          );
          result.retried += 1;
          break;
        }
      }
      return result;
    },
  };
}

/** Delivers one minimized payload to a local idempotent evidence target. */
export async function dispatchOutboxEntry(payload: OutboxPayload, target: OutboxEvidenceTarget): Promise<void> {
  validatePayload(payload);
  for (const record of payload.records) await target.recordEvent(record);
  for (const edge of payload.edges) await target.recordEdge(edge);
}

/** Validates that a dispatch pass is explicitly finite. */
export function validateDispatchOptions(
  options: unknown,
  deliverySafety: Readonly<DeliverySafetyPolicy> = DEFAULT_DELIVERY_SAFETY_POLICY,
): asserts options is OutboxDispatchOptions {
  if (!isRecordObject(options) || !isRecordObject(options.permit)) {
    throw new TypeError("a finite dispatch permit is required");
  }
  assertNonEmpty(options.tenantId, "tenantId");
  const permit = options.permit as unknown as DispatchPermit;
  if (permit.kind !== "automatic" && permit.kind !== "canary" && permit.kind !== "operator") {
    throw new TypeError("permit.kind is invalid");
  }
  for (const field of ["maxEntries", "maxBytes", "maxElapsedMs", "leaseMs"] as const) {
    if (!Number.isSafeInteger(permit[field]) || permit[field] <= 0) {
      throw new TypeError(`permit.${field} must be a positive safe integer`);
    }
  }
  if (permit.leaseMs <= permit.maxElapsedMs) throw new TypeError("permit.leaseMs must exceed permit.maxElapsedMs");
  if (permit.kind === "operator") assertNonEmpty(permit.approvalId, "permit.approvalId");
  if (permit.maxBytes > deliverySafety.hard.rollingSendBytes) {
    throw new TypeError("permit.maxBytes exceeds the hard rolling send limit");
  }
  if (permit.maxEntries > deliverySafety.hard.rollingRequests) {
    throw new TypeError("permit.maxEntries exceeds the hard rolling request limit");
  }
  if (permit.maxElapsedMs > deliverySafety.hard.windowMs) {
    throw new TypeError("permit.maxElapsedMs exceeds the hard rolling window");
  }
  if (permit.kind === "automatic" && permit.maxEntries > deliverySafety.hard.automaticReplayBatches) {
    throw new TypeError("automatic permit exceeds the hard replay canary limit");
  }
  validateListOptions(options as unknown as OutboxDispatchOptions);
}

/** Returns zeroed accounting for a new dispatch pass. */
export function emptyDispatchResult(): OutboxDispatchResult {
  return { dispatched: 0, retried: 0, paused: 0, rejected: 0, bytes: 0 };
}

/** Builds a unique opaque claim id from its permit and pass index. */
export function dispatchLeaseId(permit: DispatchPermit, index: number): string {
  return `${permit.approvalId ?? permit.kind}:${index}:${crypto.randomUUID()}`;
}

export { outboxPayloadByteLength } from "./outbox-shared.js";

/** Narrows untrusted input to a non-array object. */
function isRecordObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
