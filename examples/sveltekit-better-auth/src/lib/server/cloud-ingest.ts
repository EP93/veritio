import {
  createHttpIngestTarget,
  createHttpOutboxDispatcher,
  DEFAULT_DELIVERY_SAFETY_POLICY,
  type OutboxAdapter,
} from "@veritio/storage";
import type { AuditEventInput, EvidenceEdgeInput } from "@veritio/core";

/**
 * Server-only boundary between this example and hosted Veritio Cloud.
 *
 * The hosted ingest API has no CORS, so delivery is server-to-server: a UI
 * action hits this example's OWN SvelteKit endpoint, which dispatches the outbox
 * to the Cloud. Per the repo rules, the scoped ingest key and base URL are read
 * from environment ONLY here (a process-boundary module under `$lib/server`,
 * which SvelteKit never bundles to the client), never in SDK core and never
 * shipped to the browser. The browser only ever sees `cloudPublicConfig()` (no
 * token).
 *
 * Configure (e.g. in `.env` / the dev shell):
 *   VERITIO_CLOUD_BASE_URL   = http://localhost:3010
 *   VERITIO_CLOUD_PROJECT_ID = <the Cloud project id (this becomes scope.tenantId)>
 *   VERITIO_CLOUD_INGEST_TOKEN = vrt_… (an "ingest"-authority scoped key)
 * When unset, the example runs in local-only mode and skips dispatch.
 */

interface InternalCloudConfig {
  baseUrl: string | null;
  projectId: string | null;
  token: string | null;
}

/** Public, token-free view of the cloud configuration for the browser. */
export interface CloudPublicConfig {
  configured: boolean;
  baseUrl: string | null;
  projectId: string | null;
  /** Deep link to the project's Changes surface, when a base URL is set. */
  changesUrl: string | null;
}

/** Reads the cloud config from the process environment at the server boundary. */
function readConfig(): InternalCloudConfig {
  return {
    baseUrl: trimmed(process.env.VERITIO_CLOUD_BASE_URL),
    projectId: trimmed(process.env.VERITIO_CLOUD_PROJECT_ID),
    token: trimmed(process.env.VERITIO_CLOUD_INGEST_TOKEN),
  };
}

function trimmed(value: string | undefined): string | null {
  const next = value?.trim();
  return next && next.length > 0 ? next : null;
}

/** True when base URL, project id, and an ingest token are all configured. */
export function isCloudConfigured(): boolean {
  const config = readConfig();
  return Boolean(config.baseUrl && config.projectId && config.token);
}

/**
 * The tenant id every governed-change record must carry. The hosted ingest
 * rejects the whole batch unless `scope.tenantId` equals the key's project, so
 * the tenant IS the configured project id. A local placeholder is used when the
 * example runs without cloud configuration.
 */
export function cloudTenantId(): string {
  return readConfig().projectId ?? "tenant_local_demo";
}

/** Returns the browser-safe configuration (never includes the token). */
export function cloudPublicConfig(): CloudPublicConfig {
  const config = readConfig();
  const configured = Boolean(config.baseUrl && config.projectId && config.token);
  return {
    configured,
    baseUrl: config.baseUrl,
    projectId: config.projectId,
    changesUrl: config.baseUrl ? `${config.baseUrl.replace(/\/+$/, "")}/evidence/changes` : null,
  };
}

/** The result of attempting to deliver pending outbox entries to the Cloud. */
export interface DispatchResult {
  status: "dispatched" | "failed" | "local_only";
  dispatched?: number;
  failed?: number;
  /** Sanitized failure reason from the outbox (status + retryability), if any. */
  error?: string;
}

const AUTOMATIC_DISPATCH_PERMIT = {
  kind: "automatic" as const,
  maxEntries: 1,
  maxBytes: DEFAULT_DELIVERY_SAFETY_POLICY.hard.batchBytes,
  maxElapsedMs: 5_000,
  leaseMs: 30_000,
};

/**
 * Drains the transactional outbox to hosted ingest using the OSS HTTP dispatcher
 * (`@veritio/storage`). Every automatic pass is one finite canary: retries stay
 * pending, pauses stay held, and rejected entries are not replayed. Returns
 * `local_only` (no network) when the cloud is not configured.
 */
export async function dispatchOutboxToCloud(adapter: OutboxAdapter, tenantId: string): Promise<DispatchResult> {
  const config = readConfig();
  if (!(config.baseUrl && config.projectId && config.token)) {
    return { status: "local_only" };
  }

  const target = createHttpIngestTarget({ baseUrl: config.baseUrl, key: config.token });
  const dispatcher = createHttpOutboxDispatcher({ adapter, target });
  const result = await dispatcher.dispatchBatch({ tenantId, permit: AUTOMATIC_DISPATCH_PERMIT });
  const { dispatched } = result;
  const failed = result.retried + result.paused + result.rejected;

  if (failed > 0) {
    const pending = await adapter.list({ tenantId });
    const lastError = pending.find((entry) => entry.status === "pending" && entry.lastError)?.lastError;
    return { status: "failed", dispatched, failed, ...(lastError ? { error: lastError } : {}) };
  }
  return { status: "dispatched", dispatched, failed };
}

/**
 * Posts a ready-made evidence batch (the provenance-recorder events + edges of an
 * agent session) to hosted ingest in ONE request, outside the per-mutation
 * outbox. The session/prompt/tool/proposal/review records are pure evidence — not
 * tied to a local business mutation that needs transactional staging — so a
 * direct batch post is the right boundary. Returns `local_only` when the cloud is
 * not configured, and a sanitized `failed` (never raw server text, rule 09) on a
 * delivery error.
 */
export async function dispatchBatchToCloud(
  records: readonly AuditEventInput[],
  edges: readonly EvidenceEdgeInput[],
): Promise<DispatchResult> {
  if (records.length === 0 && edges.length === 0) {
    return { status: "local_only" };
  }
  const config = readConfig();
  if (!(config.baseUrl && config.projectId && config.token)) {
    return { status: "local_only" };
  }

  const target = createHttpIngestTarget({ baseUrl: config.baseUrl, key: config.token });
  try {
    const result = await target.postBatch({ events: records, edges });
    return { status: "dispatched", dispatched: result.appended.events + result.appended.edges };
  } catch (error) {
    const message =
      error instanceof Error && error.name.startsWith("Ingest") ? error.message : "ingest delivery failed";
    return { status: "failed", failed: records.length + edges.length, error: message };
  }
}
