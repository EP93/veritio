import type { AuditEvent, EvidenceEdge } from "@veritio/core";

import type { DeliveryDisposition } from "./ingest.js";

/** The exact redacted batch that was prepared for remote ingest. */
export interface SpoolPayload {
  events: AuditEvent[];
  edges: EvidenceEdge[];
}

/** A durable queue envelope that preserves payload and replay accounting. */
export interface SpoolEntry {
  version: 1;
  sequence: number;
  capturedAt: string;
  payload: SpoolPayload;
  encodedBytes: number;
  recordCount: number;
  attempts: number;
  disposition?: DeliveryDisposition;
  code?: string;
  retryAt?: string;
  circuitId?: string;
  reason?: string;
}

/** A sticky circuit prevents ordinary hook invocations from attempting delivery. */
export interface SpoolCircuit {
  code: string;
  reason: string;
  openedAt: string;
  circuitId?: string;
  retryAt?: string;
}

/** Hard local queue limits retain old evidence and refuse the newest remote copy. */
export interface SpoolLimits {
  hardBatches: number;
  hardBytes: number;
}

/** An operator-issued replay epoch with aggregate, finite cost bounds. */
export interface ReplayPermit {
  id: string;
  kind: "canary" | "drain";
  maxBatches: number;
  maxRecords: number;
  maxBytes: number;
  maxElapsedMs: number;
}

/** Aggregate outcome from one explicit replay epoch. */
export interface ReplayResult {
  attemptedBatches: number;
  attemptedRecords: number;
  attemptedBytes: number;
  dispatchedBatches: number;
  quarantinedBatches: number;
  paused: boolean;
}

/** Queue counts and bytes are safe to expose without revealing event payloads. */
export interface SpoolStatus {
  pending: number;
  held: number;
  quarantined: number;
  total: number;
  pendingBytes: number;
  heldBytes: number;
  quarantinedBytes: number;
  totalBytes: number;
  queueFull: boolean;
  circuit: SpoolCircuit | null;
}

/** Default queue ceilings bound disk growth without deleting older evidence. */
export const DEFAULT_SPOOL_LIMITS: Readonly<SpoolLimits> = Object.freeze({
  hardBatches: 250,
  hardBytes: 50_000_000,
});

/** Compatibility alias for callers that previously displayed the batch ceiling. */
export const MAX_SPOOL_BATCHES = DEFAULT_SPOOL_LIMITS.hardBatches;

/** Compatibility constant; ordinary hooks no longer invoke automatic replay. */
export const FLUSH_BATCHES_PER_HOOK = 1;

/** One request may never consume more than this share of a replay epoch. */
export const FLUSH_TIMEOUT_MS = 5_000;

/** Absolute permit ceilings prevent an explicit command from becoming unbounded. */
export const MAX_REPLAY_PERMIT = Object.freeze({
  maxBatches: DEFAULT_SPOOL_LIMITS.hardBatches,
  maxRecords: DEFAULT_SPOOL_LIMITS.hardBatches * 500,
  maxBytes: DEFAULT_SPOOL_LIMITS.hardBytes,
  maxElapsedMs: 15_000,
});
