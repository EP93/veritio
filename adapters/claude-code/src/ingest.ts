import type { AuditEvent, EvidenceEdge } from "@veritio/core";

/**
 * Default bound on one ingest ship-out attempt. An UNBOUNDED await here once
 * froze Claude Code for minutes when the hosted endpoint stalled (SessionStart
 * blocked on Bun's 5-minute fetch default), so every ship-out must abort in
 * bounded time. Aborting is safe server-side: veritio-cloud enforces fail-closed
 * connection/statement timeouts on every tenant DB connection (issue #32 /
 * PR #33), so a client abort can no longer wedge a tenant.
 */
export const DEFAULT_INGEST_TIMEOUT_MS = 10_000;

/**
 * Absolute hook ship-out ceiling. Adapter hosts may choose a lower timeout, but
 * a process-boundary override cannot turn an observability hook back into a
 * minutes-long blocking operation.
 */
export const MAX_INGEST_TIMEOUT_MS = 30_000;

/** Portable delivery outcomes shared by HTTP ingest clients and durable queues. */
export type DeliveryDisposition = "retry" | "pause" | "reject";

/** Bounded, non-sensitive fields accepted from an ingest error response. */
export interface IngestFailureDetails {
  deliveryDisposition: DeliveryDisposition;
  code?: string;
  retryAt?: string;
  circuitId?: string;
}

const LEGACY_PAUSE_CODES = new Set([
  "economic_safety_hold",
  "monthly_event_quota_exceeded",
  "operator_pause",
  "provider_block",
  "tenant_db_quota_blocked",
]);

/**
 * Typed failure for a non-2xx ingest response, carrying the HTTP status so the
 * spool can separate outages worth retrying (5xx/429 — e.g. the hosted tenant
 * DB quota-blocked, July 2026) from rejections that will never succeed (other
 * 4xx: bad key, tenant mismatch, malformed batch). Never carries response
 * bodies or headers — the status code is the whole contract.
 */
export class IngestHttpError extends Error {
  readonly status: number;
  readonly deliveryDisposition: DeliveryDisposition;
  readonly code: string | undefined;
  readonly retryAt: string | undefined;
  readonly circuitId: string | undefined;

  constructor(status: number, details?: Partial<IngestFailureDetails>) {
    super(`ingest POST failed with status ${status}`);
    this.name = "IngestHttpError";
    this.status = status;
    this.deliveryDisposition = details?.deliveryDisposition ?? legacyDisposition(status);
    this.code = details?.code;
    this.retryAt = details?.retryAt;
    this.circuitId = details?.circuitId;
  }
}

/**
 * Resolves a thrown ship-out failure into the three-way durable queue outcome.
 * Transport exceptions are retryable; typed HTTP failures preserve an explicit
 * server disposition or the backwards-compatible status/code fallback.
 */
export function deliveryDispositionOf(error: unknown): DeliveryDisposition {
  return error instanceof IngestHttpError ? error.deliveryDisposition : "retry";
}

/**
 * Classifies a ship-out failure as worth retrying later via the offline spool.
 * HTTP 5xx (server/storage down, incl. the 503 a quota-blocked tenant DB now
 * returns) and 429 (rate limit) are retryable; every other HTTP status is a
 * permanent rejection. Non-HTTP failures (DNS, refused connection, abort on
 * the timeout bound) are transport outages and always retryable.
 */
export function isRetryableIngestFailure(error: unknown): boolean {
  return deliveryDispositionOf(error) === "retry";
}

/**
 * Best-effort POST of an invocation's redacted events + edges to a Veritio ingest
 * endpoint, aborted after `timeoutMs` (default {@link DEFAULT_INGEST_TIMEOUT_MS})
 * so a stalled endpoint can never block the agent past the bound. The server
 * re-redacts and re-chains, and ingest is idempotent (deterministic record ids),
 * so a retry or a re-posted session-start is safe. The scoped key is supplied by
 * the caller (resolved at the process boundary); it is never embedded here.
 * Non-2xx responses throw {@link IngestHttpError} so callers can classify.
 */
export async function postToIngest(
  ingest: { url: string; key: string; timeoutMs?: number },
  payload: { events: AuditEvent[]; edges: EvidenceEdge[] },
): Promise<void> {
  if (payload.events.length === 0 && payload.edges.length === 0) {
    return;
  }
  const timeoutMs = ingest.timeoutMs ?? DEFAULT_INGEST_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_INGEST_TIMEOUT_MS) {
    throw new TypeError(`ingest timeout must be an integer between 1 and ${MAX_INGEST_TIMEOUT_MS} milliseconds`);
  }
  const response = await fetch(ingest.url, {
    method: "POST",
    headers: { authorization: `Bearer ${ingest.key}`, "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) {
    throw new IngestHttpError(response.status, await failureDetails(response));
  }
}

/** Maps a legacy response without a portable body disposition by HTTP status. */
function legacyDisposition(status: number): DeliveryDisposition {
  return status >= 500 || status === 429 ? "retry" : "reject";
}

/**
 * Parses only the small portable control fields from a non-2xx response. Raw
 * error prose and unknown metadata are deliberately discarded so credentials,
 * evidence payloads, and provider details can never enter the local queue.
 */
async function failureDetails(response: Response): Promise<IngestFailureDetails> {
  let body: Record<string, unknown> = {};
  try {
    const parsed: unknown = await response.json();
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      body = parsed as Record<string, unknown>;
    }
  } catch {
    // A non-JSON legacy response falls back to status-only classification.
  }

  const explicit = body.deliveryDisposition;
  const code = boundedString(body.code, 128);
  const deliveryDisposition: DeliveryDisposition =
    explicit === "retry" || explicit === "pause" || explicit === "reject"
      ? explicit
      : code && LEGACY_PAUSE_CODES.has(code)
        ? "pause"
        : legacyDisposition(response.status);
  const retryAt = boundedString(body.retryAt, 64);
  const circuitId = boundedString(body.circuitId, 128);
  return {
    deliveryDisposition,
    ...(code ? { code } : {}),
    ...(retryAt && Number.isFinite(Date.parse(retryAt)) ? { retryAt } : {}),
    ...(circuitId ? { circuitId } : {}),
  };
}

/** Keeps response-derived control strings small before they reach durable state. */
function boundedString(value: unknown, maxLength: number): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength ? value : undefined;
}
