import { createHash } from "node:crypto";
import {
  type AuditChainState,
  type AuditEvent,
  type AuditRecord,
  type AuditStore,
  type AuditStoreAppendOptions,
  type AuditStoreListOptions,
  type CheckpointingAuditStore,
  canonicalJson,
  type DispositionAttempt,
  type EvidenceScope,
  HASH_ALGORITHM,
  hashAuditRecord,
  hashIdempotencyKey,
  type RetentionCheckpoint,
  type RetentionDisposition,
  type RetentionPolicyFence,
  verifyRetentionCheckpoint,
  verifyRetentionDisposition,
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
  ON veritio_audit_records (tenant_id, sequence);

CREATE TABLE IF NOT EXISTS veritio_audit_records_state (
  tenant_id text PRIMARY KEY,
  authoritative_tip_sequence bigint NOT NULL,
  authoritative_tip_hash char(64),
  minimum_retained_sequence bigint NOT NULL,
  latest_checkpoint_hash char(64),
  retention_policy_fence bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS veritio_audit_records_idem (
  tenant_id text NOT NULL,
  idempotency_key_hash char(64) NOT NULL,
  event_canonical_hash char(64) NOT NULL,
  original_sequence bigint NOT NULL,
  original_record_hash char(64) NOT NULL,
  record_json text,
  PRIMARY KEY (tenant_id, idempotency_key_hash)
);

CREATE TABLE IF NOT EXISTS veritio_audit_records_checkpoints (
  tenant_id text NOT NULL,
  epoch bigint NOT NULL,
  checkpoint_hash char(64) NOT NULL,
  checkpoint_canonical text NOT NULL,
  PRIMARY KEY (tenant_id, epoch),
  UNIQUE (tenant_id, checkpoint_hash)
);

CREATE TABLE IF NOT EXISTS veritio_audit_records_attempts (
  tenant_id text NOT NULL,
  checkpoint_hash char(64) NOT NULL,
  attempt_id varchar(128) NOT NULL,
  policy_fence bigint NOT NULL,
  status varchar(16) NOT NULL,
  attempt_canonical text NOT NULL,
  PRIMARY KEY (tenant_id, checkpoint_hash)
);

CREATE TABLE IF NOT EXISTS veritio_audit_records_receipts (
  tenant_id text NOT NULL,
  checkpoint_hash char(64) NOT NULL,
  disposition_canonical text NOT NULL,
  PRIMARY KEY (tenant_id, checkpoint_hash)
);

INSERT INTO veritio_audit_records_state (
  tenant_id, authoritative_tip_sequence, authoritative_tip_hash,
  minimum_retained_sequence, latest_checkpoint_hash, retention_policy_fence
)
SELECT records.tenant_id, records.sequence, records.hash, 1, NULL, 0
FROM veritio_audit_records AS records
WHERE NOT EXISTS (
  SELECT 1 FROM veritio_audit_records AS newer
  WHERE newer.tenant_id = records.tenant_id AND newer.sequence > records.sequence
)
ON CONFLICT (tenant_id) DO NOTHING;`;

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
);

CREATE TABLE IF NOT EXISTS \`veritio_audit_records_state\` (
  \`tenant_id\` varchar(255) NOT NULL,
  \`authoritative_tip_sequence\` bigint NOT NULL,
  \`authoritative_tip_hash\` char(64),
  \`minimum_retained_sequence\` bigint NOT NULL,
  \`latest_checkpoint_hash\` char(64),
  \`retention_policy_fence\` bigint NOT NULL,
  PRIMARY KEY (\`tenant_id\`)
);

CREATE TABLE IF NOT EXISTS \`veritio_audit_records_idem\` (
  \`tenant_id\` varchar(255) NOT NULL,
  \`idempotency_key_hash\` char(64) NOT NULL,
  \`event_canonical_hash\` char(64) NOT NULL,
  \`original_sequence\` bigint NOT NULL,
  \`original_record_hash\` char(64) NOT NULL,
  \`record_json\` longtext,
  PRIMARY KEY (\`tenant_id\`, \`idempotency_key_hash\`)
);

CREATE TABLE IF NOT EXISTS \`veritio_audit_records_checkpoints\` (
  \`tenant_id\` varchar(255) NOT NULL,
  \`epoch\` bigint NOT NULL,
  \`checkpoint_hash\` char(64) NOT NULL,
  \`checkpoint_canonical\` longtext NOT NULL,
  PRIMARY KEY (\`tenant_id\`, \`epoch\`),
  UNIQUE KEY \`veritio_checkpoint_hash_unique\` (\`tenant_id\`, \`checkpoint_hash\`)
);

CREATE TABLE IF NOT EXISTS \`veritio_audit_records_attempts\` (
  \`tenant_id\` varchar(255) NOT NULL,
  \`checkpoint_hash\` char(64) NOT NULL,
  \`attempt_id\` varchar(128) NOT NULL,
  \`policy_fence\` bigint NOT NULL,
  \`status\` varchar(16) NOT NULL,
  \`attempt_canonical\` longtext NOT NULL,
  PRIMARY KEY (\`tenant_id\`, \`checkpoint_hash\`)
);

CREATE TABLE IF NOT EXISTS \`veritio_audit_records_receipts\` (
  \`tenant_id\` varchar(255) NOT NULL,
  \`checkpoint_hash\` char(64) NOT NULL,
  \`disposition_canonical\` longtext NOT NULL,
  PRIMARY KEY (\`tenant_id\`, \`checkpoint_hash\`)
);

INSERT IGNORE INTO \`veritio_audit_records_state\` (
  \`tenant_id\`, \`authoritative_tip_sequence\`, \`authoritative_tip_hash\`,
  \`minimum_retained_sequence\`, \`latest_checkpoint_hash\`, \`retention_policy_fence\`
)
SELECT records.tenant_id, records.sequence, records.hash, 1, NULL, 0
FROM \`veritio_audit_records\` AS records
WHERE NOT EXISTS (
  SELECT 1 FROM \`veritio_audit_records\` AS newer
  WHERE newer.tenant_id = records.tenant_id AND newer.sequence > records.sequence
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

export const MONGO_RETENTION_INDEXES = {
  chainStates: [{ keys: { tenantId: 1 }, options: { unique: true, name: "veritio_chain_state_tenant_unique" } }],
  idempotencyLedger: [
    {
      keys: { tenantId: 1, idempotencyKeyHash: 1 },
      options: { unique: true, name: "veritio_retention_idempotency_unique" },
    },
  ],
  checkpoints: [
    {
      keys: { tenantId: 1, epoch: 1 },
      options: { unique: true, name: "veritio_retention_checkpoint_epoch_unique" },
    },
    {
      keys: { tenantId: 1, checkpointHash: 1 },
      options: { unique: true, name: "veritio_retention_checkpoint_hash_unique" },
    },
  ],
  dispositionAttempts: [
    {
      keys: { tenantId: 1, checkpointHash: 1 },
      options: { unique: true, name: "veritio_retention_attempt_checkpoint_unique" },
    },
  ],
  dispositions: [
    {
      keys: { tenantId: 1, checkpointHash: 1 },
      options: { unique: true, name: "veritio_retention_disposition_checkpoint_unique" },
    },
  ],
} as const;

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

export interface SqlAuditRetentionTableNames {
  records: string;
  chainState: string;
  idempotencyLedger: string;
  checkpoints: string;
  dispositionAttempts: string;
  dispositions: string;
}

/**
 * Derives deterministic additive companion names while keeping each identifier
 * within PostgreSQL's 63-byte and MySQL/MariaDB's 64-byte ASCII ceilings.
 */
export function getSqlAuditRetentionTableNames(
  tableName: string,
  dialect: SqlDialect = "postgres",
): SqlAuditRetentionTableNames {
  const limit = sqlIdentifierByteLimit(dialect);
  const records = splitSqlTableName(tableName)
    .map((part) => boundSqlIdentifier(part, limit))
    .join(".");
  return {
    records,
    chainState: appendTableSuffix(records, "_state", limit),
    idempotencyLedger: appendTableSuffix(records, "_idem", limit),
    checkpoints: appendTableSuffix(records, "_checkpoints", limit),
    dispositionAttempts: appendTableSuffix(records, "_attempts", limit),
    dispositions: appendTableSuffix(records, "_receipts", limit),
  };
}

export interface SqlAuditChainStateRow {
  tenant_id: string;
  authoritative_tip_sequence: number | string;
  authoritative_tip_hash: string | null;
  minimum_retained_sequence: number | string;
  latest_checkpoint_hash: string | null;
  retention_policy_fence: number | string;
}

export interface SqlIdempotencyLedgerRow {
  event_canonical_hash: string;
  original_sequence: number | string;
  original_record_hash: string;
  record_json: string | null;
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
  sort?: Record<string, 1 | -1>;
  limit?: number;
}

export interface MongoAuditCursor<TDocument = MongoAuditDocument> {
  toArray(): Promise<readonly TDocument[]>;
}

export interface MongoAuditCollection {
  findOne(filter: Record<string, unknown>, options?: MongoAuditFindOptions): Promise<MongoAuditDocument | null>;
  find(filter: Record<string, unknown>, options?: MongoAuditFindOptions): MongoAuditCursor;
  insertOne(document: MongoAuditDocument, options?: Record<string, unknown>): Promise<unknown>;
  deleteMany(filter: Record<string, unknown>, options?: Record<string, unknown>): Promise<unknown>;
}

export interface MongoRetentionCollection<TDocument extends Record<string, unknown>> {
  findOne(filter: Record<string, unknown>, options?: MongoAuditFindOptions): Promise<TDocument | null>;
  find(filter: Record<string, unknown>, options?: MongoAuditFindOptions): MongoAuditCursor<TDocument>;
  insertOne(document: TDocument, options?: Record<string, unknown>): Promise<unknown>;
  updateOne(
    filter: Record<string, unknown>,
    update: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  deleteMany(filter: Record<string, unknown>, options?: Record<string, unknown>): Promise<unknown>;
}

export interface MongoAuditChainStateDocument extends Record<string, unknown> {
  tenantId: string;
  authoritativeTipSequence: number;
  authoritativeTipHash: string | null;
  minimumRetainedSequence: number;
  latestCheckpointHash: string | null;
  retentionPolicyFence: number;
}

export interface MongoIdempotencyLedgerDocument extends Record<string, unknown> {
  tenantId: string;
  idempotencyKeyHash: string;
  eventCanonicalHash: string;
  originalSequence: number;
  originalRecordHash: string;
  recordJson?: string;
}

export interface MongoCheckpointDocument extends Record<string, unknown> {
  tenantId: string;
  epoch: number;
  checkpointHash: string;
  checkpointCanonical: string;
}

export interface MongoDispositionAttemptDocument extends Record<string, unknown> {
  tenantId: string;
  checkpointHash: string;
  attemptId: string;
  policyFence: number;
  status: "pending" | "disposed";
  attemptCanonical: string;
}

export interface MongoDispositionDocument extends Record<string, unknown> {
  tenantId: string;
  checkpointHash: string;
  dispositionCanonical: string;
}

export interface MongoRetentionCollections {
  chainStates: MongoRetentionCollection<MongoAuditChainStateDocument>;
  idempotencyLedger: MongoRetentionCollection<MongoIdempotencyLedgerDocument>;
  checkpoints: MongoRetentionCollection<MongoCheckpointDocument>;
  dispositionAttempts: MongoRetentionCollection<MongoDispositionAttemptDocument>;
  dispositions: MongoRetentionCollection<MongoDispositionDocument>;
}

export interface MongoAuditTransactionContext {
  collection?: MongoAuditCollection;
  options?: Record<string, unknown>;
}

export interface MongoAuditStoreOptions {
  collection: MongoAuditCollection;
  retention?: MongoRetentionCollections;
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

export type SqlDialect = "postgres" | "mysql";

const DEFAULT_SQL_TABLE = "veritio_audit_records";
const DEFAULT_REDIS_TIP_PREFIX = "veritio:audit-tip";
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;

/**
 * Creates a Postgres-backed AuditStore using an injected executor. The adapter
 * stays host-neutral and assumes the host owns connection pooling and migrations.
 */
export function createPostgresAuditStore(options: SqlAuditStoreOptions): CheckpointingAuditStore {
  return new SqlAuditStore("postgres", options);
}

/**
 * Creates a Neon-compatible AuditStore through the Postgres dialect because
 * Neon preserves the same SQL semantics needed for tenant chain ordering.
 */
export function createNeonAuditStore(options: SqlAuditStoreOptions): CheckpointingAuditStore {
  return createPostgresAuditStore(options);
}

/**
 * Creates a MySQL-backed AuditStore using host-injected transaction execution.
 */
export function createMysqlAuditStore(options: SqlAuditStoreOptions): CheckpointingAuditStore {
  return new SqlAuditStore("mysql", options);
}

/**
 * Compatibility alias for callers that spell MySQL with a capital S.
 */
export function createMySqlAuditStore(options: SqlAuditStoreOptions): CheckpointingAuditStore {
  return createMysqlAuditStore(options);
}

/**
 * Creates a MariaDB-compatible AuditStore through the MySQL dialect.
 */
export function createMariaDbAuditStore(options: SqlAuditStoreOptions): CheckpointingAuditStore {
  return createMysqlAuditStore(options);
}

/**
 * Compatibility alias for callers that spell MariaDB with an all-caps DB.
 */
export function createMariaDBAuditStore(options: SqlAuditStoreOptions): CheckpointingAuditStore {
  return createMysqlAuditStore(options);
}

/**
 * Creates a Mongo-backed AuditStore using an injected collection and transaction
 * boundary. The host owns session setup so the OSS adapter avoids driver lock-in.
 */
export function createMongoAuditStore(options: MongoAuditStoreOptions): CheckpointingAuditStore {
  return new MongoAuditStore(options);
}

/**
 * Explicitly activates retention for one legacy Mongo tenant by validating the
 * complete hot chain and atomically backfilling authoritative state and ledger.
 */
export async function backfillMongoAuditRetentionState(
  options: MongoAuditStoreOptions,
  scope: EvidenceScope & { tenantId: string },
): Promise<AuditChainState> {
  const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
  const retention = options.retention;
  if (!retention) throw new TypeError("Mongo retention collections are required");
  return options.transaction(async (context) => {
    const operationOptions = context.options ?? {};
    const existing = await retention.chainStates.findOne({ tenantId }, withMongoOptions(operationOptions));
    if (existing) return chainStateFromMongoDocument(existing, tenantId);
    const collection = context.collection ?? options.collection;
    const documents = await collection
      .find({ tenantId }, withMongoOptions(operationOptions, { sort: { sequence: 1 } }))
      .toArray();
    const records = documents.map((document) => verifiedMongoAuditDocumentRecord(document, tenantId));
    assertLegacyMongoAuditChain(records);
    for (const record of records) {
      await retention.idempotencyLedger.insertOne(
        mongoLedgerDocument(tenantId, record.idempotencyKeyHash, sha256Hex(canonicalJson(record.event)), record),
        operationOptions,
      );
    }
    const tip = records.at(-1);
    const state: AuditChainState = {
      authoritativeTipSequence: tip?.sequence ?? 0,
      authoritativeTipHash: tip?.hash ?? null,
      minimumRetainedSequence: 1,
      latestCheckpointHash: null,
      retentionPolicyFence: 0,
    };
    await retention.chainStates.insertOne(mongoChainStateDocument(tenantId, state), operationOptions);
    return { ...state };
  });
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
class SqlAuditStore implements CheckpointingAuditStore {
  readonly #client: SqlAuditExecutor;
  readonly #dialect: SqlDialect;
  readonly #table: string;
  readonly #chainStateTable: string;
  readonly #idempotencyTable: string;
  readonly #checkpointsTable: string;
  readonly #attemptsTable: string;
  readonly #dispositionsTable: string;

  /**
   * Stores the host-provided SQL executor and validates the table identifier at
   * construction time.
   */
  constructor(dialect: SqlDialect, options: SqlAuditStoreOptions) {
    this.#dialect = dialect;
    this.#client = options.client;
    const tableName = options.tableName ?? DEFAULT_SQL_TABLE;
    const names = getSqlAuditRetentionTableNames(tableName, dialect);
    this.#table = quoteTableName(names.records, dialect);
    this.#chainStateTable = quoteTableName(names.chainState, dialect);
    this.#idempotencyTable = quoteTableName(names.idempotencyLedger, dialect);
    this.#checkpointsTable = quoteTableName(names.checkpoints, dialect);
    this.#attemptsTable = quoteTableName(names.dispositionAttempts, dialect);
    this.#dispositionsTable = quoteTableName(names.dispositions, dialect);
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
    const eventCanonicalHash = sha256Hex(eventCanonical);

    return this.#client.transaction(async (session) => {
      const chainState = await this.#lockChainState(session, tenantId);
      const ledgerEntry = firstRow(
        await session.execute(this.#selectLedgerSql(), this.#params(tenantId, idempotencyKeyHash)),
      );
      if (ledgerEntry) {
        if (readString(ledgerEntry, "event_canonical_hash") !== eventCanonicalHash) {
          throw new TypeError("idempotency conflict");
        }
        const recordJson = readNullableString(ledgerEntry, "record_json");
        if (recordJson === null) {
          throw new TypeError("idempotency_history_disposed");
        }
        const record = parseStoredRecordJson(recordJson, tenantId);
        return cloneRecord(record);
      }

      const legacyExisting = firstRow(
        await session.execute(this.#selectByIdempotencySql(), this.#params(tenantId, idempotencyKeyHash)),
      );
      if (legacyExisting) {
        const record = recordFromSqlRow(legacyExisting, tenantId);
        if (readString(legacyExisting, "event_canonical") !== eventCanonical) {
          throw new TypeError("idempotency conflict");
        }
        await session.execute(
          this.#insertLedgerSql(),
          this.#params(
            tenantId,
            idempotencyKeyHash,
            eventCanonicalHash,
            record.sequence,
            record.hash,
            canonicalJson(record),
          ),
        );
        return cloneRecord(record);
      }

      const previousHash = chainState.authoritativeTipHash;
      if (options.expectedPreviousHash !== undefined && options.expectedPreviousHash !== previousHash) {
        throw new TypeError("expectedPreviousHash does not match tenant chain tip");
      }

      const record = buildAuditRecord({
        event,
        previousHash,
        sequence: chainState.authoritativeTipSequence + 1,
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
      await session.execute(
        this.#insertLedgerSql(),
        this.#params(
          tenantId,
          idempotencyKeyHash,
          eventCanonicalHash,
          record.sequence,
          record.hash,
          canonicalJson(record),
        ),
      );
      await this.#writeChainState(session, tenantId, {
        ...chainState,
        authoritativeTipSequence: record.sequence,
        authoritativeTipHash: record.hash,
      });

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
   * Reads the separately persisted authoritative state, returning genesis only
   * when the tenant has never appended or advanced a retention fence.
   */
  async getChainState(scope: EvidenceScope & { tenantId: string }): Promise<AuditChainState> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    const row = firstRow(await this.#client.execute(this.#selectChainStateSql(false), this.#params(tenantId)));
    return row ? chainStateFromSqlRow(row, tenantId) : genesisChainState();
  }

  /**
   * Locks the tenant chain row and advances the opaque retention-policy fence
   * only for an exact compare-and-swap match.
   */
  async advanceRetentionPolicyFence(
    scope: EvidenceScope & { tenantId: string },
    expectedVersion: RetentionPolicyFence,
  ): Promise<RetentionPolicyFence> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    assertRetentionPolicyFence(expectedVersion);
    return this.#client.transaction(async (session) => {
      const current = await this.#lockChainState(session, tenantId);
      if (current.retentionPolicyFence !== expectedVersion) {
        throw new TypeError("retention policy fence mismatch");
      }
      const next = current.retentionPolicyFence + 1;
      if (!Number.isSafeInteger(next)) {
        throw new TypeError("retention policy fence exhausted");
      }
      await this.#writeChainState(session, tenantId, { ...current, retentionPolicyFence: next });
      return next;
    });
  }

  /**
   * Locks authoritative chain state, verifies the exact hot prefix and checkpoint
   * boundary, then atomically tombstones idempotency, persists the anchor, crops
   * rows, and advances the retained-range state.
   */
  async compactRange(
    scope: EvidenceScope & { tenantId: string },
    checkpoint: RetentionCheckpoint,
    expected: AuditChainState,
    policyFence: RetentionPolicyFence,
  ): Promise<void> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    assertAuditChainState(expected);
    assertRetentionPolicyFence(policyFence);
    await this.#client.transaction(async (session) => {
      const current = await this.#lockChainState(session, tenantId);
      assertCompactionEnvelope(tenantId, checkpoint, expected, policyFence, current);
      const previousCheckpoints = rowsFromResult(
        await session.execute(this.#selectLatestCheckpointSql(true), this.#params(tenantId)),
      )
        .map((row) => checkpointFromSqlRow(row, tenantId))
        .sort((left, right) => left.epoch - right.epoch);
      const previousCheckpoint = previousCheckpoints.at(-1);
      assertCheckpointPrefix(checkpoint, current, previousCheckpoint);

      const rows = rowsFromResult(
        await session.execute(
          this.#selectRangeForUpdateSql(),
          this.#params(tenantId, checkpoint.fromSequence, checkpoint.throughSequence),
        ),
      );
      const records = rows.map((row) => recordFromSqlRow(row, tenantId));
      assertCheckpointRecords(checkpoint, records);

      for (const [index, record] of records.entries()) {
        const eventCanonical = verifiedStoredEventCanonical(record, readString(rows[index]!, "event_canonical"));
        await session.execute(
          this.#upsertTombstoneSql(),
          this.#params(tenantId, record.idempotencyKeyHash, sha256Hex(eventCanonical), record.sequence, record.hash),
        );
      }
      await session.execute(
        this.#insertCheckpointSql(),
        this.#params(tenantId, checkpoint.epoch, checkpoint.hash, canonicalJson(checkpoint)),
      );
      await session.execute(
        this.#deleteRangeSql(),
        this.#params(tenantId, checkpoint.fromSequence, checkpoint.throughSequence),
      );
      await this.#writeChainState(session, tenantId, {
        ...current,
        minimumRetainedSequence: checkpoint.throughSequence + 1,
        latestCheckpointHash: checkpoint.hash,
      });
    });
  }

  /**
   * Lists hash-verified cloned checkpoints in epoch order.
   */
  async listCheckpoints(scope: EvidenceScope & { tenantId: string }): Promise<RetentionCheckpoint[]> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    const rows = rowsFromResult(await this.#client.execute(this.#listCheckpointsSql(), this.#params(tenantId)));
    return rows
      .map((row) => checkpointFromSqlRow(row, tenantId))
      .sort((left, right) => left.epoch - right.epoch)
      .map(cloneRetentionCheckpoint);
  }

  /**
   * Creates or replays the exact minimal pending attempt under a locked policy
   * fence, permitting crash rebinding only at a newer current fence.
   */
  async prepareDisposition(
    scope: EvidenceScope & { tenantId: string },
    checkpointHash: string,
    attempt: DispositionAttempt,
    expectedPolicyFence: RetentionPolicyFence,
  ): Promise<DispositionAttempt> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    assertDispositionAttempt(attempt);
    assertRetentionPolicyFence(expectedPolicyFence);
    return this.#client.transaction(async (session) => {
      const current = await this.#lockChainState(session, tenantId);
      assertAttemptFence(checkpointHash, attempt, expectedPolicyFence, current);
      const checkpointRow = firstRow(
        await session.execute(this.#selectCheckpointByHashSql(), this.#params(tenantId, checkpointHash)),
      );
      if (!checkpointRow) throw new TypeError("disposition checkpoint not found");
      checkpointFromSqlRow(checkpointRow, tenantId);
      const dispositionRow = firstRow(
        await session.execute(this.#selectDispositionSql(), this.#params(tenantId, checkpointHash)),
      );
      if (dispositionRow) throw new TypeError("checkpoint disposition already confirmed");
      const existingRow = firstRow(
        await session.execute(this.#selectAttemptSql(true), this.#params(tenantId, checkpointHash)),
      );
      const existing = existingRow ? attemptFromSqlRow(existingRow, checkpointHash) : undefined;
      if (existing) {
        if (canonicalJson(existing) === canonicalJson(attempt)) return cloneDispositionAttempt(existing);
        if (existing.status !== "pending" || attempt.policyFence <= existing.policyFence) {
          throw new TypeError("disposition attempt conflict");
        }
        await session.execute(
          this.#updateAttemptSql(),
          this.#params(
            attempt.attemptId,
            attempt.policyFence,
            attempt.status,
            canonicalJson(attempt),
            tenantId,
            checkpointHash,
          ),
        );
      } else {
        await session.execute(
          this.#insertAttemptSql(),
          this.#params(
            tenantId,
            checkpointHash,
            attempt.attemptId,
            attempt.policyFence,
            attempt.status,
            canonicalJson(attempt),
          ),
        );
      }
      return cloneDispositionAttempt(attempt);
    });
  }

  /**
   * Verifies one receipt against its checkpoint and atomically CASes the exact
   * current attempt plus fence before persisting a unique accepted receipt.
   */
  async confirmDisposition(
    scope: EvidenceScope & { tenantId: string },
    receipt: RetentionDisposition,
    expectedAttemptId: string,
    expectedPolicyFence: RetentionPolicyFence,
  ): Promise<void> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    requireNonEmptyString(expectedAttemptId, "expectedAttemptId");
    assertRetentionPolicyFence(expectedPolicyFence);
    await this.#client.transaction(async (session) => {
      const current = await this.#lockChainState(session, tenantId);
      if (current.retentionPolicyFence !== expectedPolicyFence) {
        throw new TypeError("retention policy fence mismatch");
      }
      const checkpointHash = receipt.checkpointHash;
      const attemptRow = firstRow(
        await session.execute(this.#selectAttemptSql(true), this.#params(tenantId, checkpointHash)),
      );
      if (!attemptRow) throw new TypeError("disposition attempt mismatch");
      const attempt = attemptFromSqlRow(attemptRow, checkpointHash);
      if (attempt.attemptId !== expectedAttemptId || attempt.policyFence !== expectedPolicyFence) {
        throw new TypeError("disposition attempt mismatch");
      }
      const checkpointRow = firstRow(
        await session.execute(this.#selectCheckpointByHashSql(), this.#params(tenantId, checkpointHash)),
      );
      if (!checkpointRow) throw new TypeError("disposition checkpoint not found");
      const checkpoint = checkpointFromSqlRow(checkpointRow, tenantId);
      const existingRow = firstRow(
        await session.execute(this.#selectDispositionSql(), this.#params(tenantId, checkpointHash)),
      );
      if (existingRow) {
        const existing = dispositionFromSqlRow(existingRow, checkpoint, tenantId);
        if (attempt.status === "disposed" && canonicalJson(existing) === canonicalJson(receipt)) return;
        throw new TypeError("conflicting disposition receipt");
      }
      if (attempt.status !== "pending") throw new TypeError("disposition attempt is not pending");
      assertValidDisposition(receipt, checkpoint);
      await session.execute(
        this.#insertDispositionSql(),
        this.#params(tenantId, checkpointHash, canonicalJson(receipt)),
      );
      const disposedAttempt: DispositionAttempt = { ...attempt, status: "disposed" };
      await session.execute(
        this.#updateAttemptSql(),
        this.#params(
          disposedAttempt.attemptId,
          disposedAttempt.policyFence,
          disposedAttempt.status,
          canonicalJson(disposedAttempt),
          tenantId,
          checkpointHash,
        ),
      );
    });
  }

  /**
   * Lists accepted receipts in checkpoint epoch order and returns defensive
   * clones of their exact canonical protocol fields.
   */
  async listDispositions(scope: EvidenceScope & { tenantId: string }): Promise<RetentionDisposition[]> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    const checkpoints = await this.listCheckpoints(scope);
    const checkpointsByHash = new Map(checkpoints.map((checkpoint) => [checkpoint.hash, checkpoint]));
    const rows = rowsFromResult(await this.#client.execute(this.#listDispositionsSql(), this.#params(tenantId)));
    return rows
      .map((row) => {
        const checkpoint = checkpointsByHash.get(dispositionCheckpointHash(readString(row, "disposition_canonical")));
        if (!checkpoint) throw new TypeError("stored retention disposition checkpoint not found");
        return { checkpoint, disposition: dispositionFromSqlRow(row, checkpoint, tenantId) };
      })
      .sort((left, right) => left.checkpoint.epoch - right.checkpoint.epoch)
      .map(({ disposition }) => cloneRetentionDisposition(disposition));
  }

  /**
   * Selects an existing record by tenant-scoped idempotency hash.
   */
  #selectByIdempotencySql(): string {
    return `SELECT event_canonical, record_json FROM ${this.#table} WHERE tenant_id = ${this.#placeholder(1)} AND idempotency_key_hash = ${this.#placeholder(2)} LIMIT 1`;
  }

  /**
   * Selects the separate idempotency ledger, including permanent tombstones.
   */
  #selectLedgerSql(): string {
    return `SELECT event_canonical_hash, original_sequence, original_record_hash, record_json FROM ${this.#idempotencyTable} WHERE tenant_id = ${this.#placeholder(1)} AND idempotency_key_hash = ${this.#placeholder(2)} LIMIT 1`;
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

  /** Builds the ledger insert used by new append and legacy replay migration. */
  #insertLedgerSql(): string {
    return `INSERT INTO ${this.#idempotencyTable} (tenant_id, idempotency_key_hash, event_canonical_hash, original_sequence, original_record_hash, record_json) VALUES (${this.#placeholder(1)}, ${this.#placeholder(2)}, ${this.#placeholder(3)}, ${this.#placeholder(4)}, ${this.#placeholder(5)}, ${this.#placeholder(6)})`;
  }

  /** Builds the dialect-specific tombstone upsert that removes record bytes. */
  #upsertTombstoneSql(): string {
    const values = `(${this.#placeholder(1)}, ${this.#placeholder(2)}, ${this.#placeholder(3)}, ${this.#placeholder(4)}, ${this.#placeholder(5)}, NULL)`;
    if (this.#dialect === "postgres") {
      return `INSERT INTO ${this.#idempotencyTable} (tenant_id, idempotency_key_hash, event_canonical_hash, original_sequence, original_record_hash, record_json) VALUES ${values} ON CONFLICT (tenant_id, idempotency_key_hash) DO UPDATE SET event_canonical_hash = EXCLUDED.event_canonical_hash, original_sequence = EXCLUDED.original_sequence, original_record_hash = EXCLUDED.original_record_hash, record_json = NULL`;
    }
    return `INSERT INTO ${this.#idempotencyTable} (tenant_id, idempotency_key_hash, event_canonical_hash, original_sequence, original_record_hash, record_json) VALUES ${values} ON DUPLICATE KEY UPDATE event_canonical_hash = VALUES(event_canonical_hash), original_sequence = VALUES(original_sequence), original_record_hash = VALUES(original_record_hash), record_json = NULL`;
  }

  /** Selects authoritative chain state with an optional transactional row lock. */
  #selectChainStateSql(lock: boolean): string {
    return `SELECT tenant_id, authoritative_tip_sequence, authoritative_tip_hash, minimum_retained_sequence, latest_checkpoint_hash, retention_policy_fence FROM ${this.#chainStateTable} WHERE tenant_id = ${this.#placeholder(1)}${lock ? " FOR UPDATE" : ""}`;
  }

  /** Inserts an untouched tenant chain row without racing another initializer. */
  #insertGenesisSql(): string {
    const values = `(${this.#placeholder(1)}, 0, NULL, 1, NULL, 0)`;
    return this.#dialect === "postgres"
      ? `INSERT INTO ${this.#chainStateTable} (tenant_id, authoritative_tip_sequence, authoritative_tip_hash, minimum_retained_sequence, latest_checkpoint_hash, retention_policy_fence) VALUES ${values} ON CONFLICT (tenant_id) DO NOTHING`
      : `INSERT IGNORE INTO ${this.#chainStateTable} (tenant_id, authoritative_tip_sequence, authoritative_tip_hash, minimum_retained_sequence, latest_checkpoint_hash, retention_policy_fence) VALUES ${values}`;
  }

  /** Writes every authoritative chain-state field while the tenant row is locked. */
  #updateChainStateSql(): string {
    return `UPDATE ${this.#chainStateTable} SET authoritative_tip_sequence = ${this.#placeholder(1)}, authoritative_tip_hash = ${this.#placeholder(2)}, minimum_retained_sequence = ${this.#placeholder(3)}, latest_checkpoint_hash = ${this.#placeholder(4)}, retention_policy_fence = ${this.#placeholder(5)} WHERE tenant_id = ${this.#placeholder(6)}`;
  }

  /** Locks the exact candidate prefix rows before validation and crop. */
  #selectRangeForUpdateSql(): string {
    return `SELECT event_canonical, record_json FROM ${this.#table} WHERE tenant_id = ${this.#placeholder(1)} AND sequence >= ${this.#placeholder(2)} AND sequence <= ${this.#placeholder(3)} ORDER BY sequence ASC FOR UPDATE`;
  }

  /** Deletes only the already locked and verified checkpoint range. */
  #deleteRangeSql(): string {
    return `DELETE FROM ${this.#table} WHERE tenant_id = ${this.#placeholder(1)} AND sequence >= ${this.#placeholder(2)} AND sequence <= ${this.#placeholder(3)}`;
  }

  /** Persists exact canonical checkpoint bytes under tenant epoch/hash uniqueness. */
  #insertCheckpointSql(): string {
    return `INSERT INTO ${this.#checkpointsTable} (tenant_id, epoch, checkpoint_hash, checkpoint_canonical) VALUES (${this.#placeholder(1)}, ${this.#placeholder(2)}, ${this.#placeholder(3)}, ${this.#placeholder(4)})`;
  }

  /** Selects the current checkpoint anchor, optionally locking it for crop. */
  #selectLatestCheckpointSql(lock: boolean): string {
    return `SELECT tenant_id, epoch, checkpoint_hash, checkpoint_canonical FROM ${this.#checkpointsTable} WHERE tenant_id = ${this.#placeholder(1)}${lock ? " FOR UPDATE" : ""}`;
  }

  /** Lists canonical checkpoints by authoritative epoch order. */
  #listCheckpointsSql(): string {
    return `SELECT tenant_id, epoch, checkpoint_hash, checkpoint_canonical FROM ${this.#checkpointsTable} WHERE tenant_id = ${this.#placeholder(1)}`;
  }

  /** Selects one tenant-scoped checkpoint by its protocol hash. */
  #selectCheckpointByHashSql(): string {
    return `SELECT tenant_id, epoch, checkpoint_hash, checkpoint_canonical FROM ${this.#checkpointsTable} WHERE tenant_id = ${this.#placeholder(1)} AND checkpoint_hash = ${this.#placeholder(2)} LIMIT 1`;
  }

  /** Selects one disposition attempt with optional transactional locking. */
  #selectAttemptSql(lock: boolean): string {
    return `SELECT attempt_canonical FROM ${this.#attemptsTable} WHERE tenant_id = ${this.#placeholder(1)} AND checkpoint_hash = ${this.#placeholder(2)}${lock ? " FOR UPDATE" : ""}`;
  }

  /** Inserts a new pending minimal disposition attempt. */
  #insertAttemptSql(): string {
    return `INSERT INTO ${this.#attemptsTable} (tenant_id, checkpoint_hash, attempt_id, policy_fence, status, attempt_canonical) VALUES (${this.#placeholder(1)}, ${this.#placeholder(2)}, ${this.#placeholder(3)}, ${this.#placeholder(4)}, ${this.#placeholder(5)}, ${this.#placeholder(6)})`;
  }

  /** Rebinds or disposes the exact checkpoint attempt row. */
  #updateAttemptSql(): string {
    return `UPDATE ${this.#attemptsTable} SET attempt_id = ${this.#placeholder(1)}, policy_fence = ${this.#placeholder(2)}, status = ${this.#placeholder(3)}, attempt_canonical = ${this.#placeholder(4)} WHERE tenant_id = ${this.#placeholder(5)} AND checkpoint_hash = ${this.#placeholder(6)}`;
  }

  /** Selects the unique accepted disposition for one checkpoint. */
  #selectDispositionSql(): string {
    return `SELECT tenant_id, checkpoint_hash, disposition_canonical FROM ${this.#dispositionsTable} WHERE tenant_id = ${this.#placeholder(1)} AND checkpoint_hash = ${this.#placeholder(2)} LIMIT 1`;
  }

  /** Lists every tenant receipt so canonical checkpoint epochs control ordering. */
  #listDispositionsSql(): string {
    return `SELECT tenant_id, checkpoint_hash, disposition_canonical FROM ${this.#dispositionsTable} WHERE tenant_id = ${this.#placeholder(1)}`;
  }

  /** Persists one accepted canonical receipt under checkpoint uniqueness. */
  #insertDispositionSql(): string {
    return `INSERT INTO ${this.#dispositionsTable} (tenant_id, checkpoint_hash, disposition_canonical) VALUES (${this.#placeholder(1)}, ${this.#placeholder(2)}, ${this.#placeholder(3)})`;
  }

  /** Initializes then locks the tenant chain state before append/crop/fence CAS. */
  async #lockChainState(session: SqlAuditSession, tenantId: string): Promise<AuditChainState> {
    let row = firstRow(await session.execute(this.#selectChainStateSql(true), this.#params(tenantId)));
    if (!row) {
      await session.execute(this.#insertGenesisSql(), this.#params(tenantId));
      row = firstRow(await session.execute(this.#selectChainStateSql(true), this.#params(tenantId)));
    }
    if (!row) throw new TypeError("failed to initialize audit chain state");
    return chainStateFromSqlRow(row, tenantId);
  }

  /** Updates separately persisted chain authority inside the caller transaction. */
  async #writeChainState(session: SqlAuditSession, tenantId: string, state: AuditChainState): Promise<void> {
    assertAuditChainState(state);
    await session.execute(
      this.#updateChainStateSql(),
      this.#params(
        state.authoritativeTipSequence,
        state.authoritativeTipHash,
        state.minimumRetainedSequence,
        state.latestCheckpointHash,
        state.retentionPolicyFence,
        tenantId,
      ),
    );
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
class MongoAuditStore implements CheckpointingAuditStore {
  readonly #collection: MongoAuditCollection;
  readonly #retention: MongoRetentionCollections | undefined;
  readonly #transaction: MongoAuditStoreOptions["transaction"];

  /**
   * Stores the host-provided Mongo collection and transaction callback.
   */
  constructor(options: MongoAuditStoreOptions) {
    this.#collection = options.collection;
    this.#retention = options.retention;
    this.#transaction = options.transaction;
  }

  /**
   * Appends one event to the Mongo tenant chain, validating idempotency conflicts
   * and expectedPreviousHash before inserting the canonical document.
   */
  async append(event: AuditEvent, options: AuditStoreAppendOptions = {}): Promise<AuditRecord> {
    if (!this.#retention) {
      return this.#appendLegacy(event, options);
    }
    const tenantId = requireTenantIdFromEvent(event);
    const idempotencyKeyHash = hashIdempotencyKey(tenantId, options.idempotencyKey ?? event.id);
    const eventCanonical = canonicalJson(event);
    const eventCanonicalHash = sha256Hex(eventCanonical);

    return this.#transaction(async (context) => {
      const collection = context.collection ?? this.#collection;
      const operationOptions = context.options ?? {};
      const retention = this.#requireRetention();
      const chainState = await this.#mongoChainState(retention, tenantId, operationOptions);
      const ledgerEntry = await retention.idempotencyLedger.findOne(
        { tenantId, idempotencyKeyHash },
        withMongoOptions(operationOptions),
      );
      if (ledgerEntry) {
        if (ledgerEntry.eventCanonicalHash !== eventCanonicalHash) {
          throw new TypeError("idempotency conflict");
        }
        if (ledgerEntry.recordJson === undefined) {
          throw new TypeError("idempotency_history_disposed");
        }
        const record = parseStoredRecordJson(ledgerEntry.recordJson, tenantId);
        return cloneRecord(record);
      }

      const legacyExisting = await collection.findOne(
        { tenantId, idempotencyKeyHash },
        withMongoOptions(operationOptions),
      );
      if (legacyExisting) {
        const record = recordFromMongoDocument(legacyExisting, tenantId);
        if (legacyExisting.eventCanonical !== eventCanonical) throw new TypeError("idempotency conflict");
        await retention.idempotencyLedger.insertOne(
          mongoLedgerDocument(tenantId, idempotencyKeyHash, eventCanonicalHash, record),
          operationOptions,
        );
        return cloneRecord(record);
      }

      const previousHash = chainState.authoritativeTipHash;
      if (options.expectedPreviousHash !== undefined && options.expectedPreviousHash !== previousHash) {
        throw new TypeError("expectedPreviousHash does not match tenant chain tip");
      }

      const record = buildAuditRecord({
        event,
        previousHash,
        sequence: chainState.authoritativeTipSequence + 1,
        idempotencyKeyHash,
      });
      await collection.insertOne(documentFromRecord(tenantId, eventCanonical, record), operationOptions);
      await retention.idempotencyLedger.insertOne(
        mongoLedgerDocument(tenantId, idempotencyKeyHash, eventCanonicalHash, record),
        operationOptions,
      );
      await retention.chainStates.updateOne(
        { tenantId },
        {
          $set: mongoChainStateDocument(tenantId, {
            ...chainState,
            authoritativeTipSequence: record.sequence,
            authoritativeTipHash: record.hash,
          }),
        },
        operationOptions,
      );
      return cloneRecord(record);
    });
  }

  /**
   * Preserves the source-compatible pre-retention append path when hosts have
   * not yet injected the additive Mongo companion collections.
   */
  async #appendLegacy(event: AuditEvent, options: AuditStoreAppendOptions): Promise<AuditRecord> {
    const tenantId = requireTenantIdFromEvent(event);
    const idempotencyKeyHash = hashIdempotencyKey(tenantId, options.idempotencyKey ?? event.id);
    const eventCanonical = canonicalJson(event);
    return this.#transaction(async (context) => {
      const collection = context.collection ?? this.#collection;
      const operationOptions = context.options ?? {};
      const existing = await collection.findOne({ tenantId, idempotencyKeyHash }, withMongoOptions(operationOptions));
      if (existing) {
        const record = recordFromMongoDocument(existing, tenantId);
        if (existing.eventCanonical !== eventCanonical) throw new TypeError("idempotency conflict");
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
      const record = buildAuditRecord({ event, previousHash, sequence: (tip?.sequence ?? 0) + 1, idempotencyKeyHash });
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

  /** Returns separately persisted authoritative chain state for one tenant. */
  async getChainState(scope: EvidenceScope & { tenantId: string }): Promise<AuditChainState> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    const retention = this.#requireRetention();
    const document = await retention.chainStates.findOne({ tenantId });
    if (document) return chainStateFromMongoDocument(document, tenantId);
    if (await this.#collection.findOne({ tenantId })) {
      throw new TypeError("Mongo retention state migration required");
    }
    return genesisChainState();
  }

  /** Locks Mongo chain state through the host replica-set transaction and CASes the policy fence. */
  async advanceRetentionPolicyFence(
    scope: EvidenceScope & { tenantId: string },
    expectedVersion: RetentionPolicyFence,
  ): Promise<RetentionPolicyFence> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    assertRetentionPolicyFence(expectedVersion);
    return this.#transaction(async (context) => {
      const retention = this.#requireRetention();
      const operationOptions = context.options ?? {};
      const current = await this.#mongoChainState(retention, tenantId, operationOptions);
      if (current.retentionPolicyFence !== expectedVersion) throw new TypeError("retention policy fence mismatch");
      const next = current.retentionPolicyFence + 1;
      if (!Number.isSafeInteger(next)) throw new TypeError("retention policy fence exhausted");
      await retention.chainStates.updateOne(
        { tenantId, retentionPolicyFence: expectedVersion },
        { $set: { retentionPolicyFence: next } },
        operationOptions,
      );
      return next;
    });
  }

  /**
   * Verifies and crops one Mongo hot prefix atomically with idempotency
   * tombstones, checkpoint bytes, and authoritative state in a replica-set transaction.
   */
  async compactRange(
    scope: EvidenceScope & { tenantId: string },
    checkpoint: RetentionCheckpoint,
    expected: AuditChainState,
    policyFence: RetentionPolicyFence,
  ): Promise<void> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    assertAuditChainState(expected);
    assertRetentionPolicyFence(policyFence);
    await this.#transaction(async (context) => {
      const retention = this.#requireRetention();
      const collection = context.collection ?? this.#collection;
      const operationOptions = context.options ?? {};
      const current = await this.#mongoChainState(retention, tenantId, operationOptions);
      assertCompactionEnvelope(tenantId, checkpoint, expected, policyFence, current);
      const previousCheckpoints = (
        await retention.checkpoints.find({ tenantId }, withMongoOptions(operationOptions)).toArray()
      )
        .map((document) => checkpointFromMongoDocument(document, tenantId))
        .sort((left, right) => left.epoch - right.epoch);
      const previousCheckpoint = previousCheckpoints.at(-1);
      assertCheckpointPrefix(checkpoint, current, previousCheckpoint);
      const documents = await collection
        .find(
          { tenantId, sequence: { $gte: checkpoint.fromSequence, $lte: checkpoint.throughSequence } },
          withMongoOptions(operationOptions, { sort: { sequence: 1 } }),
        )
        .toArray();
      const records = documents.map((document) => recordFromMongoDocument(document, tenantId));
      assertCheckpointRecords(checkpoint, records);
      for (const [index, record] of records.entries()) {
        const eventCanonical = verifiedStoredEventCanonical(record, documents[index]!.eventCanonical);
        await retention.idempotencyLedger.updateOne(
          { tenantId, idempotencyKeyHash: record.idempotencyKeyHash },
          {
            $set: {
              tenantId,
              idempotencyKeyHash: record.idempotencyKeyHash,
              eventCanonicalHash: sha256Hex(eventCanonical),
              originalSequence: record.sequence,
              originalRecordHash: record.hash,
            },
            $unset: { recordJson: "" },
          },
          { ...operationOptions, upsert: true },
        );
      }
      await retention.checkpoints.insertOne(
        {
          tenantId,
          epoch: checkpoint.epoch,
          checkpointHash: checkpoint.hash,
          checkpointCanonical: canonicalJson(checkpoint),
        },
        operationOptions,
      );
      await collection.deleteMany(
        { tenantId, sequence: { $gte: checkpoint.fromSequence, $lte: checkpoint.throughSequence } },
        operationOptions,
      );
      await retention.chainStates.updateOne(
        { tenantId },
        { $set: { minimumRetainedSequence: checkpoint.throughSequence + 1, latestCheckpointHash: checkpoint.hash } },
        operationOptions,
      );
    });
  }

  /** Lists cloned hash-verified Mongo checkpoint records in epoch order. */
  async listCheckpoints(scope: EvidenceScope & { tenantId: string }): Promise<RetentionCheckpoint[]> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    const documents = await this.#requireRetention().checkpoints.find({ tenantId }).toArray();
    return documents
      .map((document) => checkpointFromMongoDocument(document, tenantId))
      .sort((left, right) => left.epoch - right.epoch)
      .map(cloneRetentionCheckpoint);
  }

  /** Creates, replays, or fresh-fence rebinds one Mongo disposition attempt transactionally. */
  async prepareDisposition(
    scope: EvidenceScope & { tenantId: string },
    checkpointHash: string,
    attempt: DispositionAttempt,
    expectedPolicyFence: RetentionPolicyFence,
  ): Promise<DispositionAttempt> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    assertDispositionAttempt(attempt);
    assertRetentionPolicyFence(expectedPolicyFence);
    return this.#transaction(async (context) => {
      const retention = this.#requireRetention();
      const operationOptions = context.options ?? {};
      const current = await this.#mongoChainState(retention, tenantId, operationOptions);
      assertAttemptFence(checkpointHash, attempt, expectedPolicyFence, current);
      await this.#casMongoChainState(retention, tenantId, current, operationOptions);
      const checkpointDocument = await retention.checkpoints.findOne(
        { tenantId, checkpointHash },
        withMongoOptions(operationOptions),
      );
      if (!checkpointDocument) throw new TypeError("disposition checkpoint not found");
      checkpointFromMongoDocument(checkpointDocument, tenantId);
      if (await retention.dispositions.findOne({ tenantId, checkpointHash }, withMongoOptions(operationOptions))) {
        throw new TypeError("checkpoint disposition already confirmed");
      }
      const existingDocument = await retention.dispositionAttempts.findOne(
        { tenantId, checkpointHash },
        withMongoOptions(operationOptions),
      );
      const existing = existingDocument ? attemptFromMongoDocument(existingDocument, checkpointHash) : undefined;
      if (existing) {
        if (canonicalJson(existing) === canonicalJson(attempt)) return cloneDispositionAttempt(existing);
        if (existing.status !== "pending" || attempt.policyFence <= existing.policyFence) {
          throw new TypeError("disposition attempt conflict");
        }
        await retention.dispositionAttempts.updateOne(
          { tenantId, checkpointHash },
          { $set: mongoAttemptDocument(tenantId, attempt) },
          operationOptions,
        );
      } else {
        await retention.dispositionAttempts.insertOne(mongoAttemptDocument(tenantId, attempt), operationOptions);
      }
      return cloneDispositionAttempt(attempt);
    });
  }

  /** Verifies and accepts one Mongo disposition receipt under exact attempt/fence CAS. */
  async confirmDisposition(
    scope: EvidenceScope & { tenantId: string },
    receipt: RetentionDisposition,
    expectedAttemptId: string,
    expectedPolicyFence: RetentionPolicyFence,
  ): Promise<void> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    requireNonEmptyString(expectedAttemptId, "expectedAttemptId");
    assertRetentionPolicyFence(expectedPolicyFence);
    await this.#transaction(async (context) => {
      const retention = this.#requireRetention();
      const operationOptions = context.options ?? {};
      const current = await this.#mongoChainState(retention, tenantId, operationOptions);
      if (current.retentionPolicyFence !== expectedPolicyFence) throw new TypeError("retention policy fence mismatch");
      await this.#casMongoChainState(retention, tenantId, current, operationOptions);
      const checkpointHash = receipt.checkpointHash;
      const attemptDocument = await retention.dispositionAttempts.findOne(
        { tenantId, checkpointHash },
        withMongoOptions(operationOptions),
      );
      if (!attemptDocument) throw new TypeError("disposition attempt mismatch");
      const attempt = attemptFromMongoDocument(attemptDocument, checkpointHash);
      if (attempt.attemptId !== expectedAttemptId || attempt.policyFence !== expectedPolicyFence) {
        throw new TypeError("disposition attempt mismatch");
      }
      const checkpointDocument = await retention.checkpoints.findOne(
        { tenantId, checkpointHash },
        withMongoOptions(operationOptions),
      );
      if (!checkpointDocument) throw new TypeError("disposition checkpoint not found");
      const checkpoint = checkpointFromMongoDocument(checkpointDocument, tenantId);
      const existingDocument = await retention.dispositions.findOne(
        { tenantId, checkpointHash },
        withMongoOptions(operationOptions),
      );
      if (existingDocument) {
        const existing = dispositionFromMongoDocument(existingDocument, checkpoint, tenantId);
        if (attempt.status === "disposed" && canonicalJson(existing) === canonicalJson(receipt)) return;
        throw new TypeError("conflicting disposition receipt");
      }
      if (attempt.status !== "pending") throw new TypeError("disposition attempt is not pending");
      assertValidDisposition(receipt, checkpoint);
      await retention.dispositions.insertOne(
        { tenantId, checkpointHash, dispositionCanonical: canonicalJson(receipt) },
        operationOptions,
      );
      const disposedAttempt: DispositionAttempt = { ...attempt, status: "disposed" };
      await retention.dispositionAttempts.updateOne(
        { tenantId, checkpointHash },
        { $set: mongoAttemptDocument(tenantId, disposedAttempt) },
        operationOptions,
      );
    });
  }

  /** Lists cloned accepted Mongo receipts in checkpoint epoch order. */
  async listDispositions(scope: EvidenceScope & { tenantId: string }): Promise<RetentionDisposition[]> {
    const tenantId = requireNonEmptyString(scope.tenantId, "scope.tenantId");
    const retention = this.#requireRetention();
    const checkpoints = await this.listCheckpoints(scope);
    const checkpointsByHash = new Map(checkpoints.map((checkpoint) => [checkpoint.hash, checkpoint]));
    const documents = await retention.dispositions.find({ tenantId }).toArray();
    return documents
      .map((document) => {
        const checkpoint = checkpointsByHash.get(dispositionCheckpointHash(document.dispositionCanonical));
        if (!checkpoint) throw new TypeError("stored retention disposition checkpoint not found");
        return { checkpoint, disposition: dispositionFromMongoDocument(document, checkpoint, tenantId) };
      })
      .sort((left, right) => left.checkpoint.epoch - right.checkpoint.epoch)
      .map(({ disposition }) => cloneRetentionDisposition(disposition));
  }

  /** Fails closed when a host invokes destructive retention before injecting all companion collections. */
  #requireRetention(): MongoRetentionCollections {
    const retention = this.#retention;
    if (!retention) throw new TypeError("Mongo retention collections are required");
    return retention;
  }

  /** Initializes and returns one transaction-scoped Mongo chain-state document. */
  async #mongoChainState(
    retention: MongoRetentionCollections,
    tenantId: string,
    operationOptions: Record<string, unknown>,
  ): Promise<AuditChainState> {
    let document = await retention.chainStates.findOne({ tenantId }, withMongoOptions(operationOptions));
    if (!document) {
      if (await this.#collection.findOne({ tenantId }, withMongoOptions(operationOptions))) {
        throw new TypeError("Mongo retention state migration required");
      }
      const genesis = genesisChainState();
      await retention.chainStates.insertOne(mongoChainStateDocument(tenantId, genesis), operationOptions);
      document = await retention.chainStates.findOne({ tenantId }, withMongoOptions(operationOptions));
    }
    if (!document) throw new TypeError("failed to initialize audit chain state");
    return chainStateFromMongoDocument(document, tenantId);
  }

  /**
   * Conditionally writes the complete state document so Mongo snapshot
   * transactions conflict with any concurrent append, crop, or fence advance.
   */
  async #casMongoChainState(
    retention: MongoRetentionCollections,
    tenantId: string,
    expected: AuditChainState,
    operationOptions: Record<string, unknown>,
  ): Promise<void> {
    const result = await retention.chainStates.updateOne(
      { tenantId, ...expected },
      { $inc: { retentionCasRevision: 1 } },
      operationOptions,
    );
    assertMongoUpdateMatched(result, "retention policy fence mismatch");
  }
}

/** Returns the untouched authoritative state for a tenant with no persisted operations. */
function genesisChainState(): AuditChainState {
  return {
    authoritativeTipSequence: 0,
    authoritativeTipHash: null,
    minimumRetainedSequence: 1,
    latestCheckpointHash: null,
    retentionPolicyFence: 0,
  };
}

/** Appends a distinct companion suffix without exceeding the active dialect's byte ceiling. */
function appendTableSuffix(tableName: string, suffix: string, limit: number): string {
  const parts = tableName.split(".");
  const finalPart = parts.pop();
  if (!finalPart) throw new TypeError("tableName must be an identifier or schema-qualified identifier");
  const candidate = `${finalPart}${suffix}`;
  if (Buffer.byteLength(candidate) <= limit) return [...parts, candidate].join(".");
  const digest = sha256Hex(`${finalPart}\u0000${suffix}`).slice(0, 8);
  const prefixLength = limit - suffix.length - digest.length - 1;
  return [...parts, `${finalPart.slice(0, prefixLength)}_${digest}${suffix}`].join(".");
}

/** Returns the server-enforced byte ceiling for one SQL identifier component. */
function sqlIdentifierByteLimit(dialect: SqlDialect): number {
  return dialect === "postgres" ? 63 : 64;
}

/** Deterministically maps one valid overlong identifier into its dialect ceiling. */
function boundSqlIdentifier(identifier: string, limit: number): string {
  if (Buffer.byteLength(identifier) <= limit) return identifier;
  const digest = sha256Hex(identifier).slice(0, 8);
  return `${identifier.slice(0, limit - digest.length - 1)}_${digest}`;
}

/** Parses one SQL chain-state row and validates all numeric/hash boundaries. */
function chainStateFromSqlRow(row: Record<string, unknown>, expectedTenantId: string): AuditChainState {
  if (readString(row, "tenant_id") !== expectedTenantId)
    throw new TypeError("stored audit chain state tenant mismatch");
  const state: AuditChainState = {
    authoritativeTipSequence: readSafeInteger(row, "authoritative_tip_sequence"),
    authoritativeTipHash: readNullableString(row, "authoritative_tip_hash"),
    minimumRetainedSequence: readSafeInteger(row, "minimum_retained_sequence"),
    latestCheckpointHash: readNullableString(row, "latest_checkpoint_hash"),
    retentionPolicyFence: readSafeInteger(row, "retention_policy_fence"),
  };
  assertAuditChainState(state);
  return state;
}

/** Parses one Mongo chain-state document without trusting driver coercions. */
function chainStateFromMongoDocument(
  document: MongoAuditChainStateDocument,
  expectedTenantId: string,
): AuditChainState {
  if (document.tenantId !== expectedTenantId) throw new TypeError("stored audit chain state tenant mismatch");
  const state: AuditChainState = {
    authoritativeTipSequence: document.authoritativeTipSequence,
    authoritativeTipHash: document.authoritativeTipHash,
    minimumRetainedSequence: document.minimumRetainedSequence,
    latestCheckpointHash: document.latestCheckpointHash,
    retentionPolicyFence: document.retentionPolicyFence,
  };
  assertAuditChainState(state);
  return state;
}

/** Creates the explicit minimized Mongo chain-state document persisted separately from event rows. */
function mongoChainStateDocument(tenantId: string, state: AuditChainState): MongoAuditChainStateDocument {
  assertAuditChainState(state);
  return { tenantId, ...state };
}

/** Creates a live idempotency ledger entry containing only canonical digest, origin, and optional hot record bytes. */
function mongoLedgerDocument(
  tenantId: string,
  idempotencyKeyHash: string,
  eventCanonicalHash: string,
  record: AuditRecord,
): MongoIdempotencyLedgerDocument {
  return {
    tenantId,
    idempotencyKeyHash,
    eventCanonicalHash,
    originalSequence: record.sequence,
    originalRecordHash: record.hash,
    recordJson: canonicalJson(record),
  };
}

/** Validates exact state, fence, tenant, checkpoint shape, and range ceiling before destructive work. */
function assertCompactionEnvelope(
  tenantId: string,
  checkpoint: RetentionCheckpoint,
  expected: AuditChainState,
  policyFence: RetentionPolicyFence,
  current: AuditChainState,
): void {
  if (!auditChainStatesEqual(current, expected)) throw new TypeError("audit chain state mismatch");
  if (policyFence !== current.retentionPolicyFence || expected.retentionPolicyFence !== policyFence) {
    throw new TypeError("retention policy fence mismatch");
  }
  const verification = verifyRetentionCheckpoint(checkpoint);
  if (!verification.ok) throw new TypeError(`invalid retention checkpoint: ${verification.reason}`);
  if (checkpoint.tenantId !== tenantId || checkpoint.chainKind !== "audit") {
    throw new TypeError("checkpoint tenant or chain kind mismatch");
  }
  if (checkpoint.throughSequence > current.authoritativeTipSequence) {
    throw new TypeError("checkpoint range exceeds authoritative tip");
  }
}

/** Enforces the next epoch, prior-checkpoint linkage, and exact retained-prefix start. */
function assertCheckpointPrefix(
  checkpoint: RetentionCheckpoint,
  current: AuditChainState,
  previousCheckpoint?: RetentionCheckpoint,
): void {
  const expectedEpoch = previousCheckpoint ? previousCheckpoint.epoch + 1 : 1;
  if (
    checkpoint.epoch !== expectedEpoch ||
    checkpoint.previousCheckpointHash !== (previousCheckpoint?.hash ?? null) ||
    checkpoint.fromSequence !== current.minimumRetainedSequence ||
    checkpoint.fromPreviousHash !== (previousCheckpoint?.throughHash ?? null) ||
    current.latestCheckpointHash !== (previousCheckpoint?.hash ?? null)
  ) {
    throw new TypeError("checkpoint prefix or prior checkpoint mismatch");
  }
}

/** Revalidates every hot record and its exact contiguous checkpoint boundary before crop. */
function assertCheckpointRecords(checkpoint: RetentionCheckpoint, records: readonly AuditRecord[]): void {
  if (records.length !== checkpoint.recordCount) throw new TypeError("checkpoint range is not an intact hot prefix");
  let expectedPreviousHash = checkpoint.fromPreviousHash;
  for (const [index, record] of records.entries()) {
    if (
      record.sequence !== checkpoint.fromSequence + index ||
      record.previousHash !== expectedPreviousHash ||
      hashAuditRecord(record) !== record.hash
    ) {
      throw new TypeError("checkpoint range failed authoritative integrity validation");
    }
    expectedPreviousHash = record.hash;
  }
  if (expectedPreviousHash !== checkpoint.throughHash) {
    throw new TypeError("checkpoint throughHash does not match authoritative boundary");
  }
}

/**
 * Derives canonical event bytes from a hash-verified record and rejects any
 * redundant storage column that disagrees before creating a permanent digest.
 */
function verifiedStoredEventCanonical(record: AuditRecord, redundantCanonical: unknown): string {
  const canonical = canonicalJson(record.event);
  if (redundantCanonical !== canonical) {
    throw new TypeError("stored audit event canonical integrity check failed");
  }
  return canonical;
}

/** Parses and hash-verifies canonical checkpoint bytes stored by SQL. */
function checkpointFromSqlRow(row: Record<string, unknown>, expectedTenantId: string): RetentionCheckpoint {
  const checkpoint = parseStoredCheckpoint(readString(row, "checkpoint_canonical"), expectedTenantId);
  if (
    readString(row, "tenant_id") !== checkpoint.tenantId ||
    readSafeInteger(row, "epoch") !== checkpoint.epoch ||
    readString(row, "checkpoint_hash") !== checkpoint.hash
  ) {
    throw new TypeError("stored retention checkpoint redundant column mismatch");
  }
  return checkpoint;
}

/** Parses and hash-verifies canonical checkpoint bytes stored by Mongo. */
function checkpointFromMongoDocument(document: MongoCheckpointDocument, expectedTenantId: string): RetentionCheckpoint {
  const checkpoint = parseStoredCheckpoint(document.checkpointCanonical, expectedTenantId);
  if (
    document.tenantId !== checkpoint.tenantId ||
    document.epoch !== checkpoint.epoch ||
    document.checkpointHash !== checkpoint.hash
  ) {
    throw new TypeError("stored retention checkpoint redundant column mismatch");
  }
  return checkpoint;
}

/** Parses exact checkpoint JSON and fails closed on shape, hash, tenant, or non-canonical bytes. */
function parseStoredCheckpoint(value: string, expectedTenantId: string): RetentionCheckpoint {
  const checkpoint = parseJsonObject(value, "stored retention checkpoint") as unknown as RetentionCheckpoint;
  const verification = verifyRetentionCheckpoint(checkpoint);
  if (!verification.ok || checkpoint.tenantId !== expectedTenantId || canonicalJson(checkpoint) !== value) {
    throw new TypeError("stored retention checkpoint integrity check failed");
  }
  return checkpoint;
}

/** Parses and validates one exact minimal SQL disposition-attempt envelope. */
function attemptFromSqlRow(row: Record<string, unknown>, expectedCheckpointHash: string): DispositionAttempt {
  return parseStoredAttempt(readString(row, "attempt_canonical"), expectedCheckpointHash);
}

/** Parses and validates one exact minimal Mongo disposition-attempt envelope. */
function attemptFromMongoDocument(
  document: MongoDispositionAttemptDocument,
  expectedCheckpointHash: string,
): DispositionAttempt {
  return parseStoredAttempt(document.attemptCanonical, expectedCheckpointHash);
}

/** Parses exact attempt bytes, rejects extra fields, and verifies checkpoint binding. */
function parseStoredAttempt(value: string, expectedCheckpointHash: string): DispositionAttempt {
  const attempt = parseJsonObject(value, "stored disposition attempt") as unknown as DispositionAttempt;
  assertDispositionAttempt(attempt);
  if (attempt.checkpointHash !== expectedCheckpointHash || canonicalJson(attempt) !== value) {
    throw new TypeError("stored disposition attempt integrity check failed");
  }
  return attempt;
}

/** Builds the minimized Mongo attempt document with exact canonical attempt bytes. */
function mongoAttemptDocument(tenantId: string, attempt: DispositionAttempt): MongoDispositionAttemptDocument {
  assertDispositionAttempt(attempt);
  return {
    tenantId,
    checkpointHash: attempt.checkpointHash,
    attemptId: attempt.attemptId,
    policyFence: attempt.policyFence,
    status: attempt.status,
    attemptCanonical: canonicalJson(attempt),
  };
}

/** Enforces the current fence and exact pending-attempt checkpoint binding before persistence. */
function assertAttemptFence(
  checkpointHash: string,
  attempt: DispositionAttempt,
  expectedPolicyFence: RetentionPolicyFence,
  current: AuditChainState,
): void {
  if (current.retentionPolicyFence !== expectedPolicyFence || attempt.policyFence !== expectedPolicyFence) {
    throw new TypeError("retention policy fence mismatch");
  }
  if (attempt.status !== "pending" || attempt.checkpointHash !== checkpointHash) {
    throw new TypeError("disposition attempt binding mismatch");
  }
}

/** Parses and checkpoint-verifies a canonical SQL disposition receipt. */
function dispositionFromSqlRow(
  row: Record<string, unknown>,
  checkpoint: RetentionCheckpoint,
  expectedTenantId: string,
): RetentionDisposition {
  const disposition = parseStoredDisposition(readString(row, "disposition_canonical"), checkpoint);
  if (
    readString(row, "tenant_id") !== expectedTenantId ||
    readString(row, "checkpoint_hash") !== disposition.checkpointHash
  ) {
    throw new TypeError("stored retention disposition redundant column mismatch");
  }
  return disposition;
}

/** Parses and checkpoint-verifies a canonical Mongo disposition receipt. */
function dispositionFromMongoDocument(
  document: MongoDispositionDocument,
  checkpoint: RetentionCheckpoint,
  expectedTenantId: string,
): RetentionDisposition {
  const disposition = parseStoredDisposition(document.dispositionCanonical, checkpoint);
  if (document.tenantId !== expectedTenantId || document.checkpointHash !== disposition.checkpointHash) {
    throw new TypeError("stored retention disposition redundant column mismatch");
  }
  return disposition;
}

/** Reads only the canonical receipt checkpoint hash needed to join against verified anchors. */
function dispositionCheckpointHash(value: string): string {
  const parsed = parseJsonObject(value, "stored retention disposition");
  return requireNonEmptyString(parsed.checkpointHash, "stored retention disposition checkpointHash");
}

/** Parses exact receipt bytes and verifies their checkpoint binding and hash. */
function parseStoredDisposition(value: string, checkpoint: RetentionCheckpoint): RetentionDisposition {
  const receipt = parseJsonObject(value, "stored retention disposition") as unknown as RetentionDisposition;
  assertValidDisposition(receipt, checkpoint);
  if (canonicalJson(receipt) !== value) throw new TypeError("stored retention disposition integrity check failed");
  return receipt;
}

/** Requires a disposition receipt to pass the protocol verifier against its persisted checkpoint. */
function assertValidDisposition(receipt: RetentionDisposition, checkpoint: RetentionCheckpoint): void {
  const verification = verifyRetentionDisposition(receipt, checkpoint);
  if (!verification.ok) throw new TypeError(`invalid retention disposition: ${verification.reason}`);
}

/** Parses an untrusted JSON object with a stable fail-closed storage error. */
function parseJsonObject(value: string, label: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new TypeError(`${label} is not valid JSON`);
  }
  if (!isRecordObject(parsed)) throw new TypeError(`${label} is not an object`);
  return parsed;
}

/** Validates the complete authoritative chain-state CAS shape. */
function assertAuditChainState(state: AuditChainState): void {
  if (
    !isRecordObject(state) ||
    !Number.isSafeInteger(state.authoritativeTipSequence) ||
    state.authoritativeTipSequence < 0 ||
    !Number.isSafeInteger(state.minimumRetainedSequence) ||
    state.minimumRetainedSequence < 1 ||
    state.minimumRetainedSequence > state.authoritativeTipSequence + 1 ||
    (state.authoritativeTipHash !== null && !isSha256Hex(state.authoritativeTipHash)) ||
    (state.latestCheckpointHash !== null && !isSha256Hex(state.latestCheckpointHash))
  ) {
    throw new TypeError("invalid audit chain state");
  }
  assertRetentionPolicyFence(state.retentionPolicyFence);
}

/** Compares every persisted crop boundary so partial caller state never satisfies CAS. */
function auditChainStatesEqual(left: AuditChainState, right: AuditChainState): boolean {
  return (
    left.authoritativeTipSequence === right.authoritativeTipSequence &&
    left.authoritativeTipHash === right.authoritativeTipHash &&
    left.minimumRetainedSequence === right.minimumRetainedSequence &&
    left.latestCheckpointHash === right.latestCheckpointHash &&
    left.retentionPolicyFence === right.retentionPolicyFence
  );
}

/** Validates the non-negative safe-integer opaque policy fence. */
function assertRetentionPolicyFence(value: unknown): asserts value is RetentionPolicyFence {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("retention policy fence must be a non-negative safe integer");
  }
}

const RETENTION_ATTEMPT_KEYS = new Set(["attemptId", "checkpointHash", "policyFence", "status"]);
const RETENTION_ATTEMPT_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

/** Rejects personal/malformed ids and every extra enumerable attempt field, including symbols. */
function assertDispositionAttempt(attempt: DispositionAttempt): void {
  if (!isRecordObject(attempt)) throw new TypeError("invalid disposition attempt");
  const keys = Reflect.ownKeys(attempt).filter((key) => Object.prototype.propertyIsEnumerable.call(attempt, key));
  if (
    keys.length !== RETENTION_ATTEMPT_KEYS.size ||
    keys.some((key) => typeof key !== "string" || !RETENTION_ATTEMPT_KEYS.has(key))
  ) {
    throw new TypeError("invalid disposition attempt fields");
  }
  if (typeof attempt.attemptId !== "string" || !RETENTION_ATTEMPT_ID_PATTERN.test(attempt.attemptId)) {
    throw new TypeError("attempt.attemptId is invalid");
  }
  if (!isSha256Hex(attempt.checkpointHash)) throw new TypeError("attempt.checkpointHash must be lowercase sha256");
  assertRetentionPolicyFence(attempt.policyFence);
  if (attempt.status !== "pending" && attempt.status !== "disposed") throw new TypeError("attempt.status is invalid");
}

/** Returns a defensive checkpoint clone without changing byte-significant fields. */
function cloneRetentionCheckpoint(checkpoint: RetentionCheckpoint): RetentionCheckpoint {
  return JSON.parse(JSON.stringify(checkpoint)) as RetentionCheckpoint;
}

/** Returns only the four allowed disposition-attempt fields. */
function cloneDispositionAttempt(attempt: DispositionAttempt): DispositionAttempt {
  return {
    attemptId: attempt.attemptId,
    checkpointHash: attempt.checkpointHash,
    policyFence: attempt.policyFence,
    status: attempt.status,
  };
}

/** Returns a defensive disposition clone without mutable shared references. */
function cloneRetentionDisposition(receipt: RetentionDisposition): RetentionDisposition {
  return JSON.parse(JSON.stringify(receipt)) as RetentionDisposition;
}

/** Computes the deterministic canonical-event digest retained in idempotency tombstones. */
function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
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
 * Validates every redundant Mongo audit-document field against its hash-verified
 * record envelope before legacy state migration can make the chain authoritative.
 */
function verifiedMongoAuditDocumentRecord(document: MongoAuditDocument, expectedTenantId: string): AuditRecord {
  const record = recordFromMongoDocument(document, expectedTenantId);
  verifiedStoredEventCanonical(record, document.eventCanonical);
  if (
    document.sequence !== record.sequence ||
    document.idempotencyKeyHash !== record.idempotencyKeyHash ||
    document.hash !== record.hash ||
    document.previousHash !== record.previousHash ||
    document.appendedAt !== record.appendedAt
  ) {
    throw new TypeError("stored audit record integrity check failed");
  }
  return record;
}

/** Ensures a legacy hot Mongo chain is complete from genesis through its tip. */
function assertLegacyMongoAuditChain(records: readonly AuditRecord[]): void {
  let previousHash: string | null = null;
  for (const [index, record] of records.entries()) {
    if (record.sequence !== index + 1 || record.previousHash !== previousHash) {
      throw new TypeError("stored audit record integrity check failed");
    }
    previousHash = record.hash;
  }
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

/** Reads a nullable string column while rejecting every other driver value. */
function readNullableString(row: Record<string, unknown>, field: string): string | null {
  const value = row[field];
  if (value !== null && typeof value !== "string") {
    throw new TypeError("stored audit retention integrity check failed");
  }
  return value;
}

/** Normalizes SQL bigint number/string results without accepting unsafe integer coercion. */
function readSafeInteger(row: Record<string, unknown>, field: string): number {
  const value = row[field];
  const number = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  if (typeof number !== "number" || !Number.isSafeInteger(number) || number < 0) {
    throw new TypeError("stored audit retention integrity check failed");
  }
  return number;
}

/** Requires a conditional Mongo update to match exactly one authoritative document. */
function assertMongoUpdateMatched(result: unknown, message: string): void {
  if (!isRecordObject(result) || result.matchedCount !== 1) throw new TypeError(message);
}

/**
 * Quotes an identifier or schema-qualified identifier after validating that no
 * caller-controlled SQL syntax can be injected.
 */
function quoteTableName(tableName: string, dialect: SqlDialect): string {
  const parts = splitSqlTableName(tableName);
  const limit = sqlIdentifierByteLimit(dialect);
  if (parts.some((part) => Buffer.byteLength(part) > limit)) {
    throw new TypeError(`tableName identifier exceeds ${limit} bytes`);
  }

  return parts
    .map((part) => {
      return dialect === "postgres" ? `"${part}"` : `\`${part}\``;
    })
    .join(".");
}

/** Splits and syntax-validates a base or schema-qualified SQL table name. */
function splitSqlTableName(tableName: string): string[] {
  const parts = tableName.split(".");
  if (parts.length === 0 || parts.length > 2 || parts.some((part) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(part))) {
    throw new TypeError("tableName must be an identifier or schema-qualified identifier");
  }
  return parts;
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
export * from "./retention-coordinator.js";
export * from "./retention-staging-archive.js";
