import { canonicalJson } from "@veritio/core";
import type { DeliveryDisposition } from "./delivery-safety.js";
import type {
  OutboxClaimOptions,
  OutboxEnqueueInput,
  OutboxListOptions,
  OutboxPayload,
  OutboxStoredEntry,
  SqlOutboxDialect,
  SqlOutboxQueryResult,
} from "./outbox-types.js";

const OUTBOX_SCHEMA_VERSION = "2026-06-23";
const MAX_LAST_ERROR_LENGTH = 256;

/** Builds and validates the initial pending row without mutating caller input. */
export function createPendingEntry(input: OutboxEnqueueInput): OutboxStoredEntry {
  const tenantId = assertNonEmpty(input.tenantId, "tenantId");
  const id = assertNonEmpty(input.id, "id");
  validatePayload(input.payload, tenantId);
  const now = normalizeDate(new Date());
  return {
    id,
    tenantId,
    payload: clonePayload(input.payload),
    availableAt: normalizeDate(input.availableAt ?? now),
    status: "pending",
    attempts: 0,
    createdAt: now,
    updatedAt: now,
  };
}

/** Validates a governed-change outbox payload and its tenant scope. */
export function validatePayload(payload: OutboxPayload, expectedTenantId?: string): void {
  if (!isRecordObject(payload)) throw new TypeError("outbox payload must be an object");
  if (payload.schemaVersion !== OUTBOX_SCHEMA_VERSION) {
    throw new TypeError("outbox payload schemaVersion is unsupported");
  }
  if (
    payload.mutationBinding !== "same_transaction" &&
    payload.mutationBinding !== "not_transaction_bound" &&
    payload.mutationBinding !== "best_effort"
  ) {
    throw new TypeError("outbox payload mutationBinding is unsupported");
  }
  if (!Array.isArray(payload.records) || !Array.isArray(payload.edges)) {
    throw new TypeError("outbox payload records and edges are required");
  }
  let tenantId = expectedTenantId;
  for (const record of payload.records) tenantId = assertPayloadTenant(record.scope?.tenantId, tenantId);
  for (const edge of payload.edges) tenantId = assertPayloadTenant(edge.scope?.tenantId, tenantId);
}

/** Computes the exact UTF-8 JSON body bytes used for one HTTP ingest request. */
export function outboxPayloadByteLength(payload: OutboxPayload): number {
  validatePayload(payload);
  return new TextEncoder().encode(JSON.stringify({ events: payload.records, edges: payload.edges })).byteLength;
}

/** Parses and integrity-checks one SQL row's serialized entry. */
export function entryFromSqlRow(row: Record<string, unknown>): OutboxStoredEntry {
  const parsed = JSON.parse(readString(row, "entry_json")) as unknown;
  validateStoredEntry(parsed);
  const entry = parsed as OutboxStoredEntry;
  if (canonicalJson(entry.payload) !== readString(row, "payload_canonical")) {
    throw new TypeError("stored outbox entry integrity check failed");
  }
  return cloneEntry(entry);
}

/** Validates a durable entry before it drives retry or settlement state. */
export function validateStoredEntry(entry: unknown): void {
  if (!isRecordObject(entry)) throw new TypeError("stored outbox entry is invalid");
  assertNonEmpty(entry.id, "id");
  assertNonEmpty(entry.tenantId, "tenantId");
  validatePayload(entry.payload as OutboxPayload, String(entry.tenantId));
  if (!["pending", "leased", "paused", "dispatched", "dead"].includes(String(entry.status))) {
    throw new TypeError("stored outbox status is invalid");
  }
  if (typeof entry.attempts !== "number" || !Number.isInteger(entry.attempts) || entry.attempts < 0) {
    throw new TypeError("stored outbox attempts is invalid");
  }
  normalizeDate(entry.availableAt);
  normalizeDate(entry.createdAt);
  normalizeDate(entry.updatedAt);
  if (entry.dispatchedAt !== undefined) normalizeDate(entry.dispatchedAt);
  if (entry.status === "leased") {
    assertNonEmpty(entry.leaseId, "leaseId");
    normalizeDate(entry.leaseExpiresAt);
  } else if (entry.leaseId !== undefined || entry.leaseExpiresAt !== undefined) {
    throw new TypeError("stored outbox lease metadata is invalid");
  }
  if (
    entry.status === "paused" &&
    (typeof entry.circuitId !== "string" || sanitizeCircuitId(entry.circuitId) === undefined)
  ) {
    throw new TypeError("stored paused outbox circuit id is invalid");
  }
  if (entry.status !== "paused" && entry.circuitId !== undefined) {
    throw new TypeError("stored outbox circuit id is invalid");
  }
}

/** Validates tenant, limit, and clock controls for read operations. */
export function validateListOptions(options: OutboxListOptions): void {
  if (options.tenantId !== undefined) assertNonEmpty(options.tenantId, "tenantId");
  if (options.limit !== undefined && (!Number.isInteger(options.limit) || options.limit < 0)) {
    throw new TypeError("limit must be a non-negative integer");
  }
  if (options.now !== undefined) normalizeDate(options.now);
}

/** Validates finite claim bounds and its opaque owner id. */
export function validateClaimOptions(options: OutboxClaimOptions): void {
  validateListOptions(options);
  assertNonEmpty(options.leaseId, "leaseId");
  for (const field of ["leaseMs", "limit", "maxPayloadBytes"] as const) {
    if (!Number.isSafeInteger(options[field]) || options[field] <= 0) {
      throw new TypeError(`${field} must be a positive safe integer`);
    }
  }
}

/** Filters rows by tenant and stable queue order, then applies a finite limit. */
export function filterEntries(entries: OutboxStoredEntry[], options: OutboxListOptions): OutboxStoredEntry[] {
  const scoped =
    options.tenantId === undefined ? entries : entries.filter((entry) => entry.tenantId === options.tenantId);
  scoped.sort(compareEntries);
  return options.limit === undefined ? scoped : scoped.slice(0, options.limit);
}

/** Finds one mutable entry or fails closed for an unknown settlement id. */
export function findEntry(entries: OutboxStoredEntry[], id: string): OutboxStoredEntry {
  const entry = entries.find((candidate) => candidate.id === id);
  if (!entry) throw new TypeError("outbox entry not found");
  return entry;
}

/** Resolves the new disposition contract while retaining the old retryable flag. */
export function resolveDisposition(options: {
  retryable?: boolean;
  disposition?: DeliveryDisposition;
}): DeliveryDisposition {
  const legacy = options.retryable === undefined ? undefined : options.retryable ? "retry" : "reject";
  if (legacy !== undefined && options.disposition !== undefined && legacy !== options.disposition) {
    throw new TypeError("retryable and disposition disagree");
  }
  return options.disposition ?? legacy ?? "retry";
}

/** Requires the current worker lease and rejects stale settlement. */
export function assertLease(entry: OutboxStoredEntry, leaseId: string | undefined): void {
  if (entry.status === "leased") {
    if (leaseId === undefined || leaseId !== entry.leaseId) throw new TypeError("outbox lease does not match");
    return;
  }
  if (leaseId !== undefined) throw new TypeError("outbox lease is no longer active");
}

/** Removes lease metadata before a terminal or retry transition. */
export function clearLease(entry: OutboxStoredEntry): void {
  delete entry.leaseId;
  delete entry.leaseExpiresAt;
}

/** Stores only bounded opaque circuit ids, never server error text. */
export function sanitizeCircuitId(value: string | undefined): string | undefined {
  return value !== undefined && /^[A-Za-z0-9_-]{1,128}$/.test(value) ? value : undefined;
}

/** Returns a resumable unique hold id when the upstream pause omitted one. */
export function resolveCircuitId(value: string | undefined): string {
  return sanitizeCircuitId(value) ?? `local_${crypto.randomUUID()}`;
}

/** Normalizes common SQL driver result envelopes to rows. */
export function rowsFromResult(result: SqlOutboxQueryResult): readonly Record<string, unknown>[] {
  if (Array.isArray(result)) {
    if (result.length === 2 && Array.isArray(result[0])) return result[0] as readonly Record<string, unknown>[];
    return result as readonly Record<string, unknown>[];
  }
  return (result as { rows: readonly Record<string, unknown>[] }).rows;
}

/** Returns the first normalized SQL row. */
export function firstRow(result: SqlOutboxQueryResult): Record<string, unknown> | undefined {
  return rowsFromResult(result)[0];
}

/** Reads a required string field from an untrusted SQL result. */
export function readString(row: Record<string, unknown>, field: string): string {
  const value = row[field];
  if (typeof value !== "string") throw new TypeError("stored outbox entry integrity check failed");
  return value;
}

/** Compares enqueue identity without retry metadata or timestamps. */
export function sameEnqueueInput(left: OutboxStoredEntry, right: OutboxStoredEntry): boolean {
  return left.tenantId === right.tenantId && canonicalJson(left.payload) === canonicalJson(right.payload);
}

/** Keeps queue processing stable across process restarts. */
export function compareEntries(left: OutboxStoredEntry, right: OutboxStoredEntry): number {
  return left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id);
}

/** Normalizes a date-like value or rejects it before ordering decisions. */
export function normalizeDate(value: string | Date | unknown): string {
  const date = value instanceof Date ? value : new Date(String(value));
  if (Number.isNaN(date.getTime())) throw new TypeError("timestamp is invalid");
  return date.toISOString();
}

/** Builds a bounded, single-line failure summary without stack traces. */
export function errorMessage(error: unknown): string {
  if (!(error instanceof Error)) return "outbox dispatch failed";
  const message = error.message.replace(/\s+/g, " ").trim();
  const name = error.name && error.name.trim().length > 0 ? error.name : "Error";
  const summary = message.length > 0 ? `${name}: ${message}` : name;
  return summary.length > MAX_LAST_ERROR_LENGTH ? `${summary.slice(0, MAX_LAST_ERROR_LENGTH - 1)}…` : summary;
}

/** Requires a non-empty string identifier. */
export function assertNonEmpty(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) throw new TypeError(`${field} is required`);
  return value;
}

/** Quotes a validated one- or two-part SQL identifier. */
export function quoteTableName(tableName: string, dialect: SqlOutboxDialect): string {
  const parts = tableName.split(".");
  if (parts.length === 0 || parts.length > 2 || parts.some((part) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(part))) {
    throw new TypeError("tableName must be an identifier or schema-qualified identifier");
  }
  return parts.map((part) => (dialect === "postgres" ? `"${part}"` : `\`${part}\``)).join(".");
}

/** Clones a row so caller mutation cannot alter durable state by reference. */
export function cloneEntry(entry: OutboxStoredEntry): OutboxStoredEntry {
  return JSON.parse(JSON.stringify(entry)) as OutboxStoredEntry;
}

/** Clones minimized payloads before durable persistence. */
export function clonePayload(payload: OutboxPayload): OutboxPayload {
  return JSON.parse(JSON.stringify(payload)) as OutboxPayload;
}

/** Returns a canonical payload string for SQL idempotency checks. */
export function canonicalPayload(payload: OutboxPayload): string {
  return canonicalJson(payload);
}

/** Validates one payload member against its queue tenant. */
function assertPayloadTenant(tenantId: unknown, expected: string | undefined): string {
  const actual = assertNonEmpty(tenantId, "scope.tenantId");
  if (expected !== undefined && actual !== expected) throw new TypeError("outbox payload tenant mismatch");
  return actual;
}

/** Narrows untrusted input to a non-array object. */
function isRecordObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
