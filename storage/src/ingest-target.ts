import type { AuditEventInput, EvidenceEdgeInput } from "@veritio/core";
import { type DeliveryDisposition, type DeliverySafetyPolicy, parseDeliverySafetyPolicy } from "./delivery-safety.js";
import {
  dispatchLeaseId,
  emptyDispatchResult,
  type OutboxAdapter,
  type OutboxDispatcher,
  type OutboxPayload,
  outboxPayloadByteLength,
  validateDispatchOptions,
} from "./outbox.js";

/**
 * HTTP delivery of governed-change evidence to a Veritio ingest endpoint.
 *
 * This is the bridge between the local transactional outbox (`./outbox`) and the
 * hosted ingest API. The host resolves `baseUrl` + the scoped `key` at its
 * process boundary and injects them here; this module NEVER reads environment
 * variables and never embeds a key (rules 03/04). The cloud re-normalizes and
 * re-redacts every record server-side, so the draft's raw `AuditEventInput` /
 * `EvidenceEdgeInput` records are posted as-is — no local hashing.
 *
 * Delivery is idempotent: governed-change record ids are deterministic, the
 * cloud is idempotent on those ids, and a retryable failure leaves the outbox
 * row pending so the next dispatch retries safely.
 */

const DEFAULT_INGEST_PATH = "/api/ingest";

/** Finite default for every SDK-owned HTTP ingest attempt. */
export const DEFAULT_HTTP_INGEST_TIMEOUT_MS = 10_000;

export interface IngestBatch {
  events: readonly AuditEventInput[];
  edges: readonly EvidenceEdgeInput[];
}

export interface IngestResult {
  appended: { events: number; edges: number };
  tips: { event: string | null; edge: string | null };
}

const EMPTY_RESULT: IngestResult = {
  appended: { events: 0, edges: 0 },
  tips: { event: null, edge: null },
};

/**
 * Base class for ingest delivery failures. Carries the HTTP status, an explicit
 * `retryable` flag (so a dispatcher can decide whether to keep the outbox row
 * pending), and any partial `appended` counts the server reported. Messages are
 * sanitized: raw server error text is never echoed (rule 09).
 */
export class IngestError extends Error {
  readonly status: number;
  readonly disposition: DeliveryDisposition;
  readonly retryable: boolean;
  readonly appended?: { events: number; edges: number } | undefined;
  readonly circuitId?: string | undefined;
  readonly retryAfterSeconds?: number | undefined;

  /** Stores only typed control metadata and a sanitized caller-authored message. */
  constructor(
    message: string,
    options: {
      status: number;
      disposition: DeliveryDisposition;
      appended?: { events: number; edges: number } | undefined;
      circuitId?: string | undefined;
      retryAfterSeconds?: number | undefined;
    },
  ) {
    super(message);
    this.name = "IngestError";
    this.status = options.status;
    this.disposition = options.disposition;
    this.retryable = options.disposition === "retry";
    this.appended = options.appended;
    this.circuitId = options.circuitId;
    this.retryAfterSeconds = options.retryAfterSeconds;
  }
}

/** A `5xx` ingest failure: transient, the outbox should retry. */
export class IngestRetryableError extends IngestError {
  /** Classifies a transient server failure without retaining its response text. */
  constructor(status: number, appended?: { events: number; edges: number } | undefined) {
    super(`ingest is temporarily unavailable (status ${status})`, { status, disposition: "retry", appended });
    this.name = "IngestRetryableError";
  }
}

/** A `409` append/idempotency conflict: not retryable without changing inputs. */
export class IngestConflictError extends IngestError {
  /** Classifies an append conflict as a terminal rejection. */
  constructor(appended?: { events: number; edges: number } | undefined) {
    super("ingest rejected the batch as an append conflict (status 409)", {
      status: 409,
      disposition: "reject",
      appended,
    });
    this.name = "IngestConflictError";
  }
}

/** A `4xx` client rejection (auth, scope, validation, too-many-records). */
export class IngestClientError extends IngestError {
  /** Classifies a client-side request rejection as terminal. */
  constructor(status: number, appended?: { events: number; edges: number } | undefined) {
    super(`ingest rejected the batch (status ${status})`, { status, disposition: "reject", appended });
    this.name = "IngestClientError";
  }
}

/** An explicit terminal server disposition for work that must not be replayed. */
export class IngestRejectedError extends IngestError {
  /** Retains only the status and committed counts from a validated reject verdict. */
  constructor(status: number, appended?: { events: number; edges: number } | undefined) {
    super(`ingest permanently rejected the batch (status ${status})`, {
      status,
      disposition: "reject",
      appended,
    });
    this.name = "IngestRejectedError";
  }
}

/**
 * A hosted economic-safety circuit hold. It is not retryable: dispatchers must
 * persist a tenant barrier and await explicit recovery authorization.
 */
export class IngestPausedError extends IngestError {
  /** Preserves only bounded circuit controls from a verified economic hold. */
  constructor(
    status: number,
    options: {
      appended?: { events: number; edges: number } | undefined;
      circuitId?: string | undefined;
      retryAfterSeconds?: number | undefined;
    } = {},
  ) {
    super(`ingest delivery is paused by an economic safety circuit (status ${status})`, {
      status,
      disposition: "pause",
      ...options,
    });
    this.name = "IngestPausedError";
  }
}

/**
 * A server-side HTTP evidence sink. `dispatchEntry` is the real entrypoint: one
 * outbox entry becomes ONE batched POST. `postBatch` exposes the same delivery
 * for callers that already hold a `{events, edges}` batch.
 */
export interface HttpIngestTarget {
  /** Sends one already-minimized batch within the configured byte and time bounds. */
  postBatch(batch: IngestBatch): Promise<IngestResult>;
  /** Sends one durable outbox payload as exactly one HTTP request. */
  dispatchEntry(payload: OutboxPayload): Promise<IngestResult>;
}

export interface HttpIngestTargetOptions {
  /** Cloud base URL, e.g. `https://console.getveritio.com` (host-injected). */
  baseUrl: string;
  /** `vrt_…` ingest-authority scoped key (host-injected; never logged). */
  key: string;
  /** Ingest path; defaults to `/api/ingest`. */
  path?: string;
  /** Finite abort bound in milliseconds; defaults to ten seconds. */
  timeoutMs?: number;
  /** Optional stricter finite SDK transport policy. */
  deliverySafety?: DeliverySafetyPolicy;
  /** Injectable fetch for testing. Defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
}

/**
 * Builds an HTTP ingest target. A single governed-change draft is ~3 events plus
 * a handful of edges, so one outbox entry is always one POST. The ingest
 * endpoint owns the per-request record cap and rejects an oversized batch with a
 * typed `413` (mapped to `IngestClientError`); the client deliberately does not
 * duplicate that hosted operational limit, so the server stays the single
 * authority and the two can never silently drift.
 */
export function createHttpIngestTarget(options: HttpIngestTargetOptions): HttpIngestTarget {
  const baseUrl = requireNonEmpty(options.baseUrl, "baseUrl").replace(/\/+$/, "");
  const key = requireNonEmpty(options.key, "key");
  const path = options.path ?? DEFAULT_INGEST_PATH;
  const url = `${baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const timeoutMs = requirePositiveInteger(options.timeoutMs ?? DEFAULT_HTTP_INGEST_TIMEOUT_MS, "timeoutMs");
  const deliverySafety = parseDeliverySafetyPolicy(options.deliverySafety);
  if (typeof fetchImpl !== "function") {
    throw new TypeError("a fetch implementation is required (pass fetchImpl)");
  }

  /**
   * POSTs one `{events, edges}` batch and maps the response into a result or a
   * typed, sanitized error. Returns early without a network call for an empty
   * batch so dispatching an edge-only or empty entry is cheap.
   */
  async function postBatchWithMode(batch: IngestBatch, delivery: "live-v1" | "replay-v1"): Promise<IngestResult> {
    if (batch.events.length === 0 && batch.edges.length === 0) {
      return EMPTY_RESULT;
    }

    const requestBody = JSON.stringify({ events: batch.events, edges: batch.edges });
    if (new TextEncoder().encode(requestBody).byteLength > deliverySafety.hard.batchBytes) {
      throw new IngestClientError(413);
    }
    const response = await fetchImpl(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${key}`,
        "content-type": "application/json",
        "x-veritio-delivery": delivery,
      },
      body: requestBody,
      signal: AbortSignal.timeout(timeoutMs),
    });

    const body = await safeJson(response);
    if (response.ok) {
      return parseResult(body);
    }

    const appended = extractAppended(body);
    const pause = extractEconomicSafetyPause(body);
    if (pause !== null) {
      throw new IngestPausedError(response.status, { appended, ...pause });
    }
    if (extractExplicitRejection(body)) {
      throw new IngestRejectedError(response.status, appended);
    }
    if (response.status === 409) {
      throw new IngestConflictError(appended);
    }
    if (response.status >= 500) {
      throw new IngestRetryableError(response.status, appended);
    }
    throw new IngestClientError(response.status, appended);
  }

  return {
    postBatch(batch): Promise<IngestResult> {
      return postBatchWithMode(batch, "live-v1");
    },
    /**
     * Delivers one outbox payload as a single POST of its records + edges.
     */
    dispatchEntry(payload: OutboxPayload): Promise<IngestResult> {
      if (!payload || !Array.isArray(payload.records) || !Array.isArray(payload.edges)) {
        throw new TypeError("outbox payload must contain records and edges arrays");
      }
      return postBatchWithMode({ events: payload.records, edges: payload.edges }, "replay-v1");
    },
  };
}

/**
 * Drains a transactional outbox to an HTTP ingest target with ONE POST per
 * entry (rather than the per-record loop used for local sinks). On success the
 * row is marked dispatched; on any failure it is marked failed so a retryable
 * error leaves it pending for the next pass. Mirrors `createOutboxDispatcher`'s
 * batch contract but is batch-aware for the HTTP endpoint.
 */
export function createHttpOutboxDispatcher(options: {
  adapter: OutboxAdapter;
  target: Pick<HttpIngestTarget, "dispatchEntry">;
  deliverySafety?: DeliverySafetyPolicy;
}): OutboxDispatcher {
  const deliverySafety = parseDeliverySafetyPolicy(options.deliverySafety);
  return {
    async dispatchBatch(dispatchOptions) {
      validateDispatchOptions(dispatchOptions, deliverySafety);
      const result = emptyDispatchResult();
      const startedAt = Date.now();
      for (let index = 0; index < dispatchOptions.permit.maxEntries; index += 1) {
        if (Date.now() - startedAt >= dispatchOptions.permit.maxElapsedMs) break;
        const remainingBytes = dispatchOptions.permit.maxBytes - result.bytes;
        if (remainingBytes <= 0) break;
        const leaseId = dispatchLeaseId(dispatchOptions.permit, index);
        const [entry] = await options.adapter.claimDispatchable({
          tenantId: dispatchOptions.tenantId,
          ...(dispatchOptions.now === undefined ? {} : { now: dispatchOptions.now }),
          leaseId,
          leaseMs: dispatchOptions.permit.leaseMs,
          limit: 1,
          maxPayloadBytes: Math.min(remainingBytes, deliverySafety.hard.batchBytes),
        });
        if (!entry) break;
        result.bytes += outboxPayloadByteLength(entry.payload);
        try {
          await options.target.dispatchEntry(entry.payload);
          await options.adapter.markDispatched(
            entry.id,
            dispatchOptions.now === undefined
              ? { leaseId: entry.leaseId }
              : { leaseId: entry.leaseId, dispatchedAt: dispatchOptions.now },
          );
          result.dispatched += 1;
        } catch (error) {
          // Honor the typed verdict: a non-retryable rejection (4xx/409) is
          // dead-lettered so it is never re-dispatched; a transient 5xx (or any
          // unexpected non-typed throw) stays retryable rather than being
          // silently parked.
          const disposition = error instanceof IngestError ? error.disposition : "retry";
          await options.adapter.markFailed(entry.id, error, {
            leaseId: entry.leaseId,
            ...(dispatchOptions.now === undefined ? {} : { now: dispatchOptions.now }),
            disposition,
            ...(error instanceof IngestError && error.circuitId !== undefined ? { circuitId: error.circuitId } : {}),
          });
          result[disposition === "retry" ? "retried" : disposition === "pause" ? "paused" : "rejected"] += 1;
          if (disposition !== "reject") break;
        }
      }
      return result;
    },
  };
}

/**
 * Reads a JSON body defensively; a non-JSON or empty body becomes `null` rather
 * than throwing, so error mapping still depends only on the HTTP status.
 */
async function safeJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

/**
 * Coerces an ingest 200 body into the result shape, defaulting missing fields so
 * a lenient server response never crashes the dispatcher.
 */
function parseResult(body: unknown): IngestResult {
  const appended = extractAppended(body) ?? { events: 0, edges: 0 };
  const tips = isRecord(body) && isRecord(body.tips) ? body.tips : {};
  return {
    appended,
    tips: {
      event: typeof tips.event === "string" ? tips.event : null,
      edge: typeof tips.edge === "string" ? tips.edge : null,
    },
  };
}

/**
 * Extracts partial `appended` counts from an ingest response body when present,
 * so a conflict/error carries how many records the server committed.
 */
function extractAppended(body: unknown): { events: number; edges: number } | undefined {
  if (!isRecord(body) || !isRecord(body.appended)) {
    return undefined;
  }
  const { events, edges } = body.appended;
  if (typeof events === "number" && typeof edges === "number") {
    return { events, edges };
  }
  return undefined;
}

/**
 * Trusts a terminal response only when both portable control fields agree.
 * This lets a server report post-commit derived-processing failure without a
 * 5xx status fallback teaching clients to replay already-committed evidence.
 */
function extractExplicitRejection(body: unknown): boolean {
  return isRecord(body) && body.deliveryDisposition === "reject" && body.retryable === false;
}

/**
 * Accepts pause metadata only for the exact hosted economic-safety code and
 * validated bounded fields, preventing arbitrary server text from entering SDK
 * state or changing generic 5xx retry semantics.
 */
function extractEconomicSafetyPause(
  body: unknown,
): { circuitId?: string | undefined; retryAfterSeconds?: number | undefined } | null {
  if (!isRecord(body) || body.code !== "economic_safety_hold" || body.deliveryDisposition !== "pause") {
    return null;
  }
  const result: { circuitId?: string; retryAfterSeconds?: number } = {};
  if (typeof body.circuitId === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(body.circuitId)) {
    result.circuitId = body.circuitId;
  }
  if (
    typeof body.retryAfterSeconds === "number" &&
    Number.isSafeInteger(body.retryAfterSeconds) &&
    body.retryAfterSeconds > 0
  ) {
    result.retryAfterSeconds = body.retryAfterSeconds;
  }
  return result;
}

/** Narrows an untrusted response body to a non-array object. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Requires a non-empty host-provided endpoint or credential string. */
function requireNonEmpty(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${field} is required`);
  }
  return value;
}

/** Requires a finite positive integer for network bounds. */
function requirePositiveInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${field} must be a positive safe integer`);
  }
  return value;
}
