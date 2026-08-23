import type {
  AuditEventInput,
  AuditRecord,
  EvidenceEdgeInput,
  EvidenceEdgeRecord,
  GovernedChangeDraft,
} from "@veritio/core";
import type { DeliveryDisposition } from "./delivery-safety.js";

export type OutboxPayload = GovernedChangeDraft["outboxEntry"];

/** Durable queue lifecycle, including crash-recoverable leases and hard holds. */
export type OutboxStatus = "pending" | "leased" | "paused" | "dispatched" | "dead";

export interface OutboxEnqueueInput {
  id: string;
  tenantId: string;
  payload: OutboxPayload;
  availableAt?: string | Date;
}

export interface OutboxStoredEntry extends OutboxEnqueueInput {
  availableAt: string;
  status: OutboxStatus;
  attempts: number;
  createdAt: string;
  updatedAt: string;
  dispatchedAt?: string;
  lastError?: string;
  leaseId?: string;
  leaseExpiresAt?: string;
  circuitId?: string;
}

export interface OutboxListOptions {
  tenantId?: string;
  limit?: number;
  now?: string | Date;
}

export interface OutboxTransaction {
  /** Stages one tenant-validated payload inside the host transaction. */
  enqueue(input: OutboxEnqueueInput): Promise<OutboxStoredEntry>;
}

/** Finite controls used while atomically acquiring delivery work. */
export interface OutboxClaimOptions extends Omit<OutboxListOptions, "tenantId"> {
  tenantId: string;
  leaseId: string;
  leaseMs: number;
  limit: number;
  maxPayloadBytes: number;
}

/** A stored row owned by one time-bounded dispatcher lease. */
export interface OutboxClaim extends OutboxStoredEntry {
  status: "leased";
  leaseId: string;
  leaseExpiresAt: string;
}

export interface OutboxAdapter {
  /** Commits enqueues only when the host callback succeeds. */
  transaction<T>(run: (tx: OutboxTransaction) => Promise<T>): Promise<T>;
  /** Lists durable rows for bounded diagnostics and operator workflows. */
  list(options?: OutboxListOptions): Promise<OutboxStoredEntry[]>;
  /** Lists due rows without acquiring ownership or bypassing tenant barriers. */
  listDispatchable(options?: OutboxListOptions): Promise<OutboxStoredEntry[]>;
  /** Atomically acquires at most one active delivery lease per tenant. */
  claimDispatchable(options: OutboxClaimOptions): Promise<OutboxClaim[]>;
  /** Settles success only when the caller still owns the active lease. */
  markDispatched(id: string, options?: { leaseId?: string; dispatchedAt?: string | Date }): Promise<OutboxStoredEntry>;
  /** Persists an explicit retry, pause, or rejection disposition. */
  markFailed(
    id: string,
    error: unknown,
    options?: {
      leaseId?: string;
      now?: string | Date;
      availableAt?: string | Date;
      retryable?: boolean;
      disposition?: DeliveryDisposition;
      circuitId?: string;
    },
  ): Promise<OutboxStoredEntry>;
  /** Re-arms held rows only after exact circuit acknowledgement. */
  resumePaused(options: {
    tenantId: string;
    expectedCircuitId: string;
    limit: number;
    now?: string | Date;
  }): Promise<number>;
}

export interface OutboxEvidenceTarget {
  /** Records one event through the target's idempotent append contract. */
  recordEvent(input: AuditEventInput): Promise<AuditRecord>;
  /** Records one edge through the target's idempotent append contract. */
  recordEdge(input: EvidenceEdgeInput): Promise<EvidenceEdgeRecord>;
}

/** Explicit finite authorization for one dispatch pass. */
export interface DispatchPermit {
  kind: "automatic" | "canary" | "operator";
  approvalId?: string;
  maxEntries: number;
  maxBytes: number;
  maxElapsedMs: number;
  leaseMs: number;
}

/** Detailed accounting by terminal delivery disposition. */
export interface OutboxDispatchResult {
  dispatched: number;
  retried: number;
  paused: number;
  rejected: number;
  bytes: number;
}

export interface OutboxDispatchOptions extends Omit<OutboxListOptions, "tenantId"> {
  tenantId: string;
  permit: DispatchPermit;
}

export interface OutboxDispatcher {
  /** Runs one tenant-scoped pass bounded by its mandatory finite permit. */
  dispatchBatch(options: OutboxDispatchOptions): Promise<OutboxDispatchResult>;
}

export interface SqlOutboxRow {
  id: string;
  tenant_id: string;
  payload_canonical: string;
  entry_json: string;
  status: string;
  attempts: number;
  available_at: string;
  created_at: string;
  updated_at: string;
  dispatched_at: string | null;
  last_error: string | null;
}

export type SqlOutboxQueryResult =
  | readonly Record<string, unknown>[]
  | { rows: readonly Record<string, unknown>[] }
  | [readonly Record<string, unknown>[], unknown];

export interface SqlOutboxSession {
  /** Executes one parameterized statement on the current host session. */
  execute(statement: string, params: readonly unknown[]): Promise<SqlOutboxQueryResult>;
}

export interface SqlOutboxExecutor extends SqlOutboxSession {
  /** Runs all lease decisions and writes on one real database transaction. */
  transaction<T>(run: (session: SqlOutboxSession) => Promise<T>): Promise<T>;
}

export interface SqlOutboxAdapterOptions {
  client: SqlOutboxExecutor;
  tableName?: string;
}

export type SqlOutboxDialect = "postgres" | "mysql";

/** Postgres schema used by host-managed outbox migrations. */
export const POSTGRES_OUTBOX_SCHEMA_SQL = `CREATE TABLE IF NOT EXISTS veritio_outbox_entries (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  payload_canonical text NOT NULL,
  entry_json text NOT NULL,
  status text NOT NULL,
  attempts integer NOT NULL,
  available_at text NOT NULL,
  created_at text NOT NULL,
  updated_at text NOT NULL,
  dispatched_at text,
  last_error text
);

CREATE INDEX IF NOT EXISTS veritio_outbox_dispatch_idx
  ON veritio_outbox_entries (status, available_at, tenant_id, created_at, id);

CREATE INDEX IF NOT EXISTS veritio_outbox_tenant_claim_idx
  ON veritio_outbox_entries (tenant_id, status, available_at, created_at, id);

CREATE INDEX IF NOT EXISTS veritio_outbox_tenant_guard_idx
  ON veritio_outbox_entries (tenant_id, id);`;

/** MySQL/MariaDB schema used by host-managed outbox migrations. */
export const MYSQL_OUTBOX_SCHEMA_SQL = `CREATE TABLE IF NOT EXISTS \`veritio_outbox_entries\` (
  \`id\` varchar(255) PRIMARY KEY,
  \`tenant_id\` varchar(255) NOT NULL,
  \`payload_canonical\` longtext NOT NULL,
  \`entry_json\` longtext NOT NULL,
  \`status\` varchar(32) NOT NULL,
  \`attempts\` integer NOT NULL,
  \`available_at\` varchar(40) NOT NULL,
  \`created_at\` varchar(40) NOT NULL,
  \`updated_at\` varchar(40) NOT NULL,
  \`dispatched_at\` varchar(40),
  \`last_error\` longtext,
  KEY \`veritio_outbox_dispatch_idx\` (\`status\`, \`available_at\`, \`tenant_id\`, \`created_at\`, \`id\`),
  KEY \`veritio_outbox_tenant_claim_idx\` (\`tenant_id\`, \`status\`, \`available_at\`, \`created_at\`, \`id\`),
  KEY \`veritio_outbox_tenant_guard_idx\` (\`tenant_id\`, \`id\`)
);`;
