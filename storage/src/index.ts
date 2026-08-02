import {
  type AuditEvent,
  type AuditRecord,
  type AuditStore,
  type AuditStoreAppendOptions,
  type AuditStoreListOptions,
  canonicalJson,
  type EvidenceScope,
  HASH_ALGORITHM,
  hashAuditRecord,
  hashIdempotencyKey,
} from "@veritio/core";

export const POSTGRES_AUDIT_RECORDS_SCHEMA_SQL = `CREATE TABLE IF NOT EXISTS veritio_audit_records (
  tenant_id text NOT NULL,
  sequence bigint NOT NULL,
  idempotency_key_hash char(64) NOT NULL,
  event_canonical text NOT NULL,
  record_json text NOT NULL,
  hash char(64) NOT NULL,
  previous_hash char(64),
  appended_at text NOT NULL,
  PRIMARY KEY (tenant_id, sequence),
  UNIQUE (tenant_id, idempotency_key_hash)
);

CREATE INDEX IF NOT EXISTS veritio_audit_records_tenant_sequence_idx
  ON veritio_audit_records (tenant_id, sequence);`;

export const MYSQL_AUDIT_RECORDS_SCHEMA_SQL = `CREATE TABLE IF NOT EXISTS \`veritio_audit_records\` (
  \`tenant_id\` varchar(255) NOT NULL,
  \`sequence\` bigint NOT NULL,
  \`idempotency_key_hash\` char(64) NOT NULL,
  \`event_canonical\` longtext NOT NULL,
  \`record_json\` longtext NOT NULL,
  \`hash\` char(64) NOT NULL,
  \`previous_hash\` char(64),
  \`appended_at\` varchar(40) NOT NULL,
  PRIMARY KEY (\`tenant_id\`, \`sequence\`),
  UNIQUE KEY \`veritio_audit_records_idempotency_unique\` (\`tenant_id\`, \`idempotency_key_hash\`),
  KEY \`veritio_audit_records_tenant_sequence_idx\` (\`tenant_id\`, \`sequence\`)
);`;

export const MONGO_AUDIT_RECORD_INDEXES = [
  {
    keys: { tenantId: 1, sequence: 1 },
    options: { unique: true, name: "veritio_audit_records_tenant_sequence_unique" },
  },
  {
    keys: { tenantId: 1, idempotencyKeyHash: 1 },
    options: { unique: true, name: "veritio_audit_records_idempotency_unique" },
  },
] as const;

export interface SqlAuditRow {
  tenant_id: string;
  sequence: number;
  idempotency_key_hash: string;
  event_canonical: string;
  record_json: string;
  hash: string;
  previous_hash: string | null;
  appended_at: string;
}

export type SqlAuditQueryResult =
  | readonly Record<string, unknown>[]
  | { rows: readonly Record<string, unknown>[] }
  | [readonly Record<string, unknown>[], unknown];

export interface SqlAuditSession {
  execute(statement: string, params: readonly unknown[]): Promise<SqlAuditQueryResult>;
}

export interface SqlAuditExecutor extends SqlAuditSession {
  transaction<T>(run: (session: SqlAuditSession) => Promise<T>): Promise<T>;
}

export interface SqlAuditStoreOptions {
  client: SqlAuditExecutor;
  tableName?: string;
}

export interface MongoAuditDocument {
  tenantId: string;
  sequence: number;
  idempotencyKeyHash: string;
  eventCanonical: string;
  recordJson: string;
  hash: string;
  previousHash: string | null;
  appendedAt: string;
}

export interface MongoAuditFindOptions extends Record<string, unknown> {
  sort?: { sequence?: 1 | -1 };
  limit?: number;
}

export interface MongoAuditCursor {
  toArray(): Promise<readonly MongoAuditDocument[]>;
}

export interface MongoAuditCollection {
  findOne(filter: Record<string, unknown>, options?: MongoAuditFindOptions): Promise<MongoAuditDocument | null>;
  find(filter: Record<string, unknown>, options?: MongoAuditFindOptions): MongoAuditCursor;
  insertOne(document: MongoAuditDocument, options?: Record<string, unknown>): Promise<unknown>;
}

export interface MongoAuditTransactionContext {
  collection?: MongoAuditCollection;
  options?: Record<string, unknown>;
}

export interface MongoAuditStoreOptions {
  collection: MongoAuditCollection;
  transaction<T>(run: (context: MongoAuditTransactionContext) => Promise<T>): Promise<T>;
}

export interface RedisAuditTipClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options?: { ttlSeconds?: number }): Promise<unknown>;
}

export interface RedisAuditTipCache {
  getTenantTip(tenantId: string): Promise<AuditRecord | null>;
  setTenantTip(record: AuditRecord, options?: { ttlSeconds?: number }): Promise<void>;
}

type SqlDialect = "postgres" | "mysql";

const DEFAULT_SQL_TABLE = "veritio_audit_records";
const DEFAULT_REDIS_TIP_PREFIX = "veritio:audit-tip";
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;

/**
 * Creates a Postgres-backed AuditStore using an injected executor. The adapter
 * stays host-neutral and assumes the host owns connection pooling and migrations.
 */
export function createPostgresAuditStore(options: SqlAuditStoreOptions): AuditStore {
  return new SqlAuditStore("postgres", options);
}

/**
 * Creates a Neon-compatible AuditStore through the Postgres dialect because
 * Neon preserves the same SQL semantics needed for tenant chain ordering.
 */
export function createNeonAuditStore(options: SqlAuditStoreOptions): AuditStore {
  return createPostgresAuditStore(options);
}

/**
 * Creates a MySQL-backed AuditStore using host-injected transaction execution.
 */
export function createMysqlAuditStore(options: SqlAuditStoreOptions): AuditStore {
  return new SqlAuditStore("mysql", options);
}

/**
 * Compatibility alias for callers that spell MySQL with a capital S.
 */
export function createMySqlAuditStore(options: SqlAuditStoreOptions): AuditStore {
  return createMysqlAuditStore(options);
}

/**
 * Creates a MariaDB-compatible AuditStore through the MySQL dialect.
 */
export function createMariaDbAuditStore(options: SqlAuditStoreOptions): AuditStore {
  return createMysqlAuditStore(options);
}

/**
 * Compatibility alias for callers that spell MariaDB with an all-caps DB.
 */
export function createMariaDBAuditStore(options: SqlAuditStoreOptions): AuditStore {
  return createMysqlAuditStore(options);
}

/**
 * Creates a Mongo-backed AuditStore using an injected collection and transaction
 * boundary. The host owns session setup so the OSS adapter avoids driver lock-in.
 */
export function createMongoAuditStore(options: MongoAuditStoreOptions): AuditStore {
  return new MongoAuditStore(options);
}

/**
 * Creates a Redis tenant-tip cache, not a source-of-truth AuditStore. Values are
 * validated before read/write so Redis can accelerate chain-tip lookup without
 * weakening record integrity.
 */
export function createRedisAuditTipCache(options: {
  client: RedisAuditTipClient;
  keyPrefix?: string;
}): RedisAuditTipCache {
  const keyPrefix = normalizeRedisPrefix(options.keyPrefix ?? DEFAULT_REDIS_TIP_PREFIX);

  return {
    /**
     * Reads a cached tenant chain tip and validates the stored record envelope
     * before returning it.
     */
    async getTenantTip(tenantId) {
      const normalizedTenantId = requireNonEmptyString(tenantId, "tenantId");
      const value = await options.client.get(redisTipKey(keyPrefix, normalizedTenantId));
      if (value === null) {
        return null;
      }
      return cloneRecord(parseStoredRecordJson(value, normalizedTenantId));
    },

    /**
     * Writes a validated audit record as the latest cached tenant tip.
     */
    async setTenantTip(record, setOptions) {
      const tenantId = validateStoredAuditRecord(record);
      await options.client.set(redisTipKey(keyPrefix, tenantId), JSON.stringify(record), setOptions);
    },
  };
}

/**
 * SQL AuditStore implementation shared by Postgres, Neon, MySQL, and MariaDB.
 * It keeps tenant chains isolated by primary key and uses transactions to avoid
 * racing sequence and idempotency decisions.
 */
class SqlAuditStore implements AuditStore {
  readonly #client: SqlAuditExecutor;
  readonly #dialect: SqlDialect;
  readonly #table: string;

  /**
   * Stores the host-provided SQL executor and validates the table identifier at
   * construction time.
   */
  constructor(dialect: SqlDialect, options: SqlAuditStoreOptions) {
    this.#dialect = dialect;
    this.#client = options.client;
    this.#table = quoteTableName(options.tableName ?? DEFAULT_SQL_TABLE, dialect);
  }

  /**
   * Appends one audit event inside a host transaction. Existing idempotency keys
   * return their original record, while payload conflicts and stale expected tips
   * fail closed.
   */
  async append(event: AuditEvent, options: AuditStoreAppendOptions = {}): Promise<AuditRecord> {
    const tenantId = requireTenantIdFromEvent(event);
    const idempotencyKeyHash = hashIdempotencyKey(tenantId, options.idempotencyKey ?? event.id);
    const eventCanonical = canonicalJson(event);

    return this.#client.transaction(async (session) => {
      const existing = firstRow(
        await session.execute(this.#selectByIdempotencySql(), this.#params(tenantId, idempotencyKeyHash)),
      );
      if (existing) {
        const record = recordFromSqlRow(existing, tenantId);
        if (readString(existing, "event_canonical") !== eventCanonical) {
          throw new TypeError("idempotency conflict");
        }
        return cloneRecord(record);
      }

      const tipRow = firstRow(await session.execute(this.#selectTenantTipSql(), this.#params(tenantId)));
      const tip = tipRow ? recordFromSqlRow(tipRow, tenantId) : null;
      const previousHash = tip?.hash ?? null;
      if (options.expectedPreviousHash !== undefined && options.expectedPreviousHash !== previousHash) {
        throw new TypeError("expectedPreviousHash does not match tenant chain tip");
      }

      const record = buildAuditRecord({
        event,
        previousHash,
        sequence: (tip?.sequence ?? 0) + 1,
        idempotencyKeyHash,
      });

      await session.execute(
        this.#insertSql(),
        this.#params(
          tenantId,
          record.sequence,
          idempotencyKeyHash,
          eventCanonical,
          JSON.stringify(record),
          record.hash,
          record.previousHash,
          record.appendedAt,
        ),
      );

      return cloneRecord(record);
    });
  }

  /**
   * Lists records for exactly one tenant in ascending sequence order, validating
   * the stored envelopes before returning cloned records.
   */
  async list(scope: EvidenceScope & { tenantId: string }, options: AuditStoreListOptions = {}): Promise<AuditRecord[]> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    validateListOptions(options);

    const afterSequence = options.afterSequence ?? 0;
    const rows = rowsFromResult(
      await this.#client.execute(
        this.#selectTenantRecordsSql(options.limit),
        options.limit === undefined
          ? this.#params(tenantId, afterSequence)
          : this.#tenantRecordsParams(tenantId, afterSequence, options.limit),
      ),
    );
    const records = rows.map((row) => recordFromSqlRow(row, tenantId));
    assertStrictlyIncreasing(records);
    return records.map(cloneRecord);
  }

  /**
   * Selects an existing record by tenant-scoped idempotency hash.
   */
  #selectByIdempotencySql(): string {
    return `SELECT event_canonical, record_json FROM ${this.#table} WHERE tenant_id = ${this.#placeholder(1)} AND idempotency_key_hash = ${this.#placeholder(2)} LIMIT 1`;
  }

  /**
   * Locks and returns the current tenant chain tip before appending the next
   * sequence number.
   */
  #selectTenantTipSql(): string {
    return `SELECT record_json FROM ${this.#table} WHERE tenant_id = ${this.#placeholder(1)} ORDER BY sequence DESC LIMIT 1 FOR UPDATE`;
  }

  /**
   * Builds the dialect-specific tenant listing query. MySQL receives a validated
   * inline limit because mysql2 prepared statements do not support LIMIT params.
   */
  #selectTenantRecordsSql(limitValue: number | undefined): string {
    const limit =
      limitValue === undefined ? "" : ` LIMIT ${this.#dialect === "mysql" ? limitValue : this.#placeholder(3)}`;
    return `SELECT record_json FROM ${this.#table} WHERE tenant_id = ${this.#placeholder(1)} AND sequence > ${this.#placeholder(2)} ORDER BY sequence ASC${limit}`;
  }

  /**
   * Builds the SQL insert statement for the canonical audit-record envelope.
   */
  #insertSql(): string {
    return `INSERT INTO ${this.#table} (tenant_id, sequence, idempotency_key_hash, event_canonical, record_json, hash, previous_hash, appended_at) VALUES (${this.#placeholder(1)}, ${this.#placeholder(2)}, ${this.#placeholder(3)}, ${this.#placeholder(4)}, ${this.#placeholder(5)}, ${this.#placeholder(6)}, ${this.#placeholder(7)}, ${this.#placeholder(8)})`;
  }

  /**
   * Returns the placeholder syntax expected by the active SQL dialect.
   */
  #placeholder(index: number): string {
    return this.#dialect === "postgres" ? `$${index}` : "?";
  }

  /**
   * Keeps SQL parameter arrays immutable at call sites.
   */
  #params(...params: unknown[]): readonly unknown[] {
    return params;
  }

  /**
   * Omits the LIMIT parameter for MySQL because its limit value is already
   * validated and inlined in the generated statement.
   */
  #tenantRecordsParams(tenantId: string, afterSequence: number, limit: number): readonly unknown[] {
    return this.#dialect === "mysql"
      ? this.#params(tenantId, afterSequence)
      : this.#params(tenantId, afterSequence, limit);
  }
}

/**
 * Mongo AuditStore implementation that preserves the same tenant chain and
 * idempotency semantics as SQL stores through host-injected transactions.
 */
class MongoAuditStore implements AuditStore {
  readonly #collection: MongoAuditCollection;
  readonly #transaction: MongoAuditStoreOptions["transaction"];

  /**
   * Stores the host-provided Mongo collection and transaction callback.
   */
  constructor(options: MongoAuditStoreOptions) {
    this.#collection = options.collection;
    this.#transaction = options.transaction;
  }

  /**
   * Appends one event to the Mongo tenant chain, validating idempotency conflicts
   * and expectedPreviousHash before inserting the canonical document.
   */
  async append(event: AuditEvent, options: AuditStoreAppendOptions = {}): Promise<AuditRecord> {
    const tenantId = requireTenantIdFromEvent(event);
    const idempotencyKeyHash = hashIdempotencyKey(tenantId, options.idempotencyKey ?? event.id);
    const eventCanonical = canonicalJson(event);

    return this.#transaction(async (context) => {
      const collection = context.collection ?? this.#collection;
      const operationOptions = context.options ?? {};
      const existing = await collection.findOne({ tenantId, idempotencyKeyHash }, withMongoOptions(operationOptions));
      if (existing) {
        const record = recordFromMongoDocument(existing, tenantId);
        if (existing.eventCanonical !== eventCanonical) {
          throw new TypeError("idempotency conflict");
        }
        return cloneRecord(record);
      }

      const tipDocument = await collection.findOne(
        { tenantId },
        withMongoOptions(operationOptions, { sort: { sequence: -1 } }),
      );
      const tip = tipDocument ? recordFromMongoDocument(tipDocument, tenantId) : null;
      const previousHash = tip?.hash ?? null;
      if (options.expectedPreviousHash !== undefined && options.expectedPreviousHash !== previousHash) {
        throw new TypeError("expectedPreviousHash does not match tenant chain tip");
      }

      const record = buildAuditRecord({
        event,
        previousHash,
        sequence: (tip?.sequence ?? 0) + 1,
        idempotencyKeyHash,
      });
      await collection.insertOne(documentFromRecord(tenantId, eventCanonical, record), operationOptions);
      return cloneRecord(record);
    });
  }

  /**
   * Lists tenant-scoped Mongo documents in sequence order and verifies every
   * stored record envelope before returning clones.
   */
  async list(scope: EvidenceScope & { tenantId: string }, options: AuditStoreListOptions = {}): Promise<AuditRecord[]> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    validateListOptions(options);
    const findOptions: MongoAuditFindOptions =
      options.limit === undefined ? { sort: { sequence: 1 } } : { sort: { sequence: 1 }, limit: options.limit };

    const cursor = this.#collection.find(
      { tenantId, sequence: { $gt: options.afterSequence ?? 0 } },
      withMongoOptions({}, findOptions),
    );
    const documents = await cursor.toArray();
    const records = documents.map((document) => recordFromMongoDocument(document, tenantId));
    assertStrictlyIncreasing(records);
    return records.map(cloneRecord);
  }
}

/**
 * Builds the canonical AuditRecord envelope around an already-normalized event
 * and validates the hash before any storage adapter persists it.
 */
function buildAuditRecord(input: {
  event: AuditEvent;
  previousHash: string | null;
  sequence: number;
  idempotencyKeyHash: string;
}): AuditRecord {
  const recordWithoutHash: Omit<AuditRecord, "hash"> = {
    event: cloneEvent(input.event),
    sequence: input.sequence,
    previousHash: input.previousHash,
    hashAlgorithm: HASH_ALGORITHM,
    canonicalization: "veritio-json-v1",
    appendedAt: new Date().toISOString(),
    idempotencyKeyHash: input.idempotencyKeyHash,
  };
  const record: AuditRecord = {
    ...recordWithoutHash,
    hash: hashAuditRecord(recordWithoutHash),
  };

  validateStoredAuditRecord(record);
  return record;
}

/**
 * Converts a validated AuditRecord into the Mongo document shape while keeping
 * the canonical event string available for idempotency conflict checks.
 */
function documentFromRecord(tenantId: string, eventCanonical: string, record: AuditRecord): MongoAuditDocument {
  return {
    tenantId,
    sequence: record.sequence,
    idempotencyKeyHash: record.idempotencyKeyHash,
    eventCanonical,
    recordJson: JSON.stringify(record),
    hash: record.hash,
    previousHash: record.previousHash,
    appendedAt: record.appendedAt,
  };
}

/**
 * Reads and validates a SQL row's serialized record envelope for the expected
 * tenant.
 */
function recordFromSqlRow(row: Record<string, unknown>, expectedTenantId: string): AuditRecord {
  return parseStoredRecordJson(readString(row, "record_json"), expectedTenantId);
}

/**
 * Reads and validates a Mongo document's serialized record envelope for the
 * expected tenant.
 */
function recordFromMongoDocument(document: MongoAuditDocument, expectedTenantId: string): AuditRecord {
  if (document.tenantId !== expectedTenantId) {
    throw new TypeError("stored audit record tenant mismatch");
  }
  return parseStoredRecordJson(document.recordJson, expectedTenantId);
}

/**
 * Parses stored JSON and immediately verifies tenant scope, envelope metadata,
 * and hash integrity before returning a record.
 */
function parseStoredRecordJson(value: string, expectedTenantId: string): AuditRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new TypeError("stored audit record is not valid JSON");
  }
  validateStoredAuditRecord(parsed, expectedTenantId);
  return parsed as AuditRecord;
}

/**
 * Performs the fail-closed integrity check for records loaded from external
 * stores. Any mismatch means the adapter must refuse the record.
 */
function validateStoredAuditRecord(record: unknown, expectedTenantId?: string): string {
  if (!isRecordObject(record)) {
    throw new TypeError("stored audit record integrity check failed");
  }
  const tenantId = requireTenantIdFromRecord(record);
  if (expectedTenantId !== undefined && tenantId !== expectedTenantId) {
    throw new TypeError("stored audit record tenant mismatch");
  }
  const sequence = record.sequence;
  if (typeof sequence !== "number" || !Number.isInteger(sequence) || sequence < 1) {
    throw new TypeError("stored audit record integrity check failed");
  }
  if (record.hashAlgorithm !== HASH_ALGORITHM || record.canonicalization !== "veritio-json-v1") {
    throw new TypeError("stored audit record integrity check failed");
  }
  if (record.previousHash !== null && !isSha256Hex(record.previousHash)) {
    throw new TypeError("stored audit record integrity check failed");
  }
  if (!isSha256Hex(record.hash) || !isSha256Hex(record.idempotencyKeyHash)) {
    throw new TypeError("stored audit record integrity check failed");
  }
  if (typeof record.appendedAt !== "string" || Number.isNaN(new Date(record.appendedAt).getTime())) {
    throw new TypeError("stored audit record integrity check failed");
  }
  if (hashAuditRecord(record as unknown as AuditRecord) !== record.hash) {
    throw new TypeError("stored audit record integrity check failed");
  }
  return tenantId;
}

/**
 * Extracts the tenant id from an event before storage append.
 */
function requireTenantIdFromEvent(event: AuditEvent): string {
  return requireNonEmptyString(event.scope?.tenantId, "scope.tenantId");
}

/**
 * Extracts the tenant id from an untrusted stored record envelope.
 */
function requireTenantIdFromRecord(record: Record<string, unknown>): string {
  const event = record.event;
  if (!isRecordObject(event)) {
    throw new TypeError("scope.tenantId is required");
  }
  const scope = event.scope;
  if (!isRecordObject(scope)) {
    throw new TypeError("scope.tenantId is required");
  }
  return requireNonEmptyString(scope.tenantId, "scope.tenantId");
}

/**
 * Validates list pagination controls before they are used in SQL or Mongo
 * queries.
 */
function validateListOptions(options: AuditStoreListOptions): void {
  if (options.limit !== undefined && (!Number.isInteger(options.limit) || options.limit < 0)) {
    throw new TypeError("limit must be a non-negative integer");
  }
  if (options.afterSequence !== undefined && (!Number.isInteger(options.afterSequence) || options.afterSequence < 0)) {
    throw new TypeError("afterSequence must be a non-negative integer");
  }
}

/**
 * Confirms a storage backend returned records in strictly ascending sequence
 * order for a single tenant chain.
 */
function assertStrictlyIncreasing(records: readonly AuditRecord[]): void {
  let previousSequence = 0;
  for (const record of records) {
    if (record.sequence <= previousSequence) {
      throw new TypeError("stored audit record ordering check failed");
    }
    previousSequence = record.sequence;
  }
}

/**
 * Normalizes common SQL driver result shapes into a row array.
 */
function rowsFromResult(result: SqlAuditQueryResult): readonly Record<string, unknown>[] {
  if (Array.isArray(result)) {
    if (result.length === 2 && Array.isArray(result[0])) {
      return result[0] as readonly Record<string, unknown>[];
    }
    return result as readonly Record<string, unknown>[];
  }
  return (result as { rows: readonly Record<string, unknown>[] }).rows;
}

/**
 * Returns the first SQL row from a normalized query result.
 */
function firstRow(result: SqlAuditQueryResult): Record<string, unknown> | undefined {
  return rowsFromResult(result)[0];
}

/**
 * Reads a string column from an untrusted SQL row and fails if the shape differs
 * from the schema contract.
 */
function readString(row: Record<string, unknown>, field: string): string {
  const value = row[field];
  if (typeof value !== "string") {
    throw new TypeError("stored audit record integrity check failed");
  }
  return value;
}

/**
 * Quotes an identifier or schema-qualified identifier after validating that no
 * caller-controlled SQL syntax can be injected.
 */
function quoteTableName(tableName: string, dialect: SqlDialect): string {
  const parts = tableName.split(".");
  if (parts.length === 0 || parts.length > 2 || parts.some((part) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(part))) {
    throw new TypeError("tableName must be an identifier or schema-qualified identifier");
  }

  return parts
    .map((part) => {
      return dialect === "postgres" ? `"${part}"` : `\`${part}\``;
    })
    .join(".");
}

/**
 * Merges Mongo find options without dropping transaction/session options passed
 * by the host.
 */
function withMongoOptions(base: Record<string, unknown>, options: MongoAuditFindOptions = {}): MongoAuditFindOptions {
  const merged: MongoAuditFindOptions = { ...base };
  if (options.sort) {
    merged.sort = options.sort;
  }
  if (options.limit !== undefined) {
    merged.limit = options.limit;
  }
  return merged;
}

/**
 * Normalizes Redis key prefixes to a non-empty value without trailing separators.
 */
function normalizeRedisPrefix(prefix: string): string {
  const normalized = requireNonEmptyString(prefix, "keyPrefix").replace(/:+$/g, "");
  if (normalized.length === 0) {
    throw new TypeError("keyPrefix is required");
  }
  return normalized;
}

/**
 * Builds the namespaced Redis key for a tenant chain tip.
 */
function redisTipKey(prefix: string, tenantId: string): string {
  return `${prefix}:${encodeURIComponent(tenantId)}`;
}

/**
 * Enforces required string fields in storage adapter boundaries.
 */
function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${field} is required`);
  }
  return value;
}

/**
 * Checks whether an untrusted value is a lowercase SHA-256 hex digest.
 */
function isSha256Hex(value: unknown): value is string {
  return typeof value === "string" && SHA256_HEX_PATTERN.test(value);
}

/**
 * Narrows an untrusted value to a plain record object.
 */
function isRecordObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Clones events before storage so external callers cannot mutate persisted
 * evidence by reference.
 */
function cloneEvent(event: AuditEvent): AuditEvent {
  return JSON.parse(JSON.stringify(event)) as AuditEvent;
}

/**
 * Clones records before returning them to callers.
 */
function cloneRecord(record: AuditRecord): AuditRecord {
  return JSON.parse(JSON.stringify(record)) as AuditRecord;
}

export * from "./clickhouse-read-model.js";
export * from "./delivery-safety.js";
export * from "./file-store.js";
export * from "./ingest-target.js";
export * from "./object-archive.js";
export * from "./outbox.js";
