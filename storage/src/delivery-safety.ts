/**
 * Stable delivery outcomes understood by SDK outboxes and hosted ingest. A
 * pause is intentionally distinct from retry: retry may be scheduled later,
 * while pause requires an explicit operator-controlled recovery action.
 */
export type DeliveryDisposition = "retry" | "pause" | "reject";

/**
 * Recommended thresholds warn before hard enforcement; hard thresholds are
 * finite transport ceilings and never accept zero as an unlimited sentinel.
 */
export interface DeliverySafetyPolicy {
  recommended: {
    queuedBytes: number;
    rollingSendBytes: number;
  };
  hard: {
    batchBytes: number;
    queuedBytes: number;
    rollingSendBytes: number;
    rollingRequests: number;
    windowMs: number;
    automaticReplayBatches: 0 | 1;
  };
}

/**
 * Conservative SDK defaults. These bound one automatic recovery probe and its
 * transfer volume; a host may configure stricter finite limits.
 */
export const DEFAULT_DELIVERY_SAFETY_POLICY: Readonly<DeliverySafetyPolicy> = deepFreeze({
  recommended: {
    queuedBytes: 5 * 1024 * 1024,
    rollingSendBytes: 1024 * 1024,
  },
  hard: {
    batchBytes: 1024 * 1024,
    queuedBytes: 64 * 1024 * 1024,
    rollingSendBytes: 2 * 1024 * 1024,
    rollingRequests: 30,
    windowMs: 60_000,
    automaticReplayBatches: 1,
  },
});

/**
 * Validates a complete delivery policy at the host configuration boundary.
 * Missing input resolves to immutable safe defaults; partial or unlimited
 * policies fail closed so an omitted ceiling cannot create unbounded replay.
 */
export function parseDeliverySafetyPolicy(input: unknown): Readonly<DeliverySafetyPolicy> {
  if (input === undefined) {
    return DEFAULT_DELIVERY_SAFETY_POLICY;
  }
  const root = requireObject(input, "deliverySafety");
  const recommended = requireObject(root.recommended, "recommended");
  const hard = requireObject(root.hard, "hard");
  const parsed: DeliverySafetyPolicy = {
    recommended: {
      queuedBytes: requirePositiveInteger(recommended.queuedBytes, "recommended.queuedBytes"),
      rollingSendBytes: requirePositiveInteger(recommended.rollingSendBytes, "recommended.rollingSendBytes"),
    },
    hard: {
      batchBytes: requirePositiveInteger(hard.batchBytes, "hard.batchBytes"),
      queuedBytes: requirePositiveInteger(hard.queuedBytes, "hard.queuedBytes"),
      rollingSendBytes: requirePositiveInteger(hard.rollingSendBytes, "hard.rollingSendBytes"),
      rollingRequests: requirePositiveInteger(hard.rollingRequests, "hard.rollingRequests"),
      windowMs: requirePositiveInteger(hard.windowMs, "hard.windowMs"),
      automaticReplayBatches: requireAutomaticReplayBatches(hard.automaticReplayBatches),
    },
  };
  if (parsed.recommended.queuedBytes > parsed.hard.queuedBytes) {
    throw new TypeError("recommended.queuedBytes must not exceed hard.queuedBytes");
  }
  if (parsed.recommended.rollingSendBytes > parsed.hard.rollingSendBytes) {
    throw new TypeError("recommended.rollingSendBytes must not exceed hard.rollingSendBytes");
  }
  if (parsed.hard.batchBytes > parsed.hard.rollingSendBytes) {
    throw new TypeError("hard.batchBytes must not exceed hard.rollingSendBytes");
  }
  return deepFreeze(parsed);
}

/** Narrows an untrusted policy branch to an object without accepting arrays. */
function requireObject(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

/** Requires a finite positive integer so zero can never mean unlimited. */
function requirePositiveInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${field} must be a positive safe integer`);
  }
  return value;
}

/** Restricts unattended recovery to either disabled or one bounded canary. */
function requireAutomaticReplayBatches(value: unknown): 0 | 1 {
  if (value !== 0 && value !== 1) {
    throw new TypeError("hard.automaticReplayBatches must be 0 or 1");
  }
  return value;
}

/** Freezes the policy and its two nested threshold groups. */
function deepFreeze(policy: DeliverySafetyPolicy): Readonly<DeliverySafetyPolicy> {
  Object.freeze(policy.recommended);
  Object.freeze(policy.hard);
  return Object.freeze(policy);
}
