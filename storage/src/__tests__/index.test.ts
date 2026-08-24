import { describe, expect, test } from "bun:test";
import {
  type AuditChainState,
  type AuditRecord,
  canonicalJson,
  createAuditEvent,
  createRetentionCheckpoint,
  createRetentionDisposition,
  type DispositionAttempt,
  MemoryAuditStore,
} from "@veritio/core";
import { type AuditStoreConformanceCorruption, createAuditStoreConformanceTests } from "../conformance";
import * as storageModule from "../index";
import {
  createMariaDbAuditStore,
  createMongoAuditStore,
  createMysqlAuditStore,
  createNeonAuditStore,
  createPostgresAuditStore,
  createRedisAuditTipCache,
  getSqlAuditRetentionTableNames,
  MONGO_RETENTION_INDEXES,
  type MongoAuditChainStateDocument,
  type MongoAuditCollection,
  type MongoAuditDocument,
  type MongoAuditStoreOptions,
  type MongoCheckpointDocument,
  type MongoDispositionAttemptDocument,
  type MongoDispositionDocument,
  type MongoIdempotencyLedgerDocument,
  type MongoRetentionCollection,
  type MongoRetentionCollections,
  MYSQL_AUDIT_RECORDS_SCHEMA_SQL,
  POSTGRES_AUDIT_RECORDS_SCHEMA_SQL,
  type RedisAuditTipClient,
  type SqlAuditChainStateRow,
  type SqlAuditExecutor,
  type SqlAuditRow,
} from "../index";
import { createRetentionStoreConformanceTests } from "../retention-conformance";

describe("SQL AuditStore adapters", () => {
  for (const [label, createStore] of [
    ["postgres", createPostgresAuditStore],
    ["neon", createNeonAuditStore],
    ["mysql", createMysqlAuditStore],
    ["mariadb", createMariaDbAuditStore],
  ] as const) {
    describe(`${label} AuditStore conformance`, () => {
      for (const conformanceTest of createAuditStoreConformanceTests({
        name: label,
        createTarget() {
          const client = createSqlClient();
          return {
            store: createStore({ client }),
            mutateStoredRecord(corruption) {
              mutateSqlStoredRecord(client, corruption);
            },
          };
        },
      })) {
        test(conformanceTest.name, conformanceTest.run);
      }

      for (const conformanceTest of createRetentionStoreConformanceTests({
        name: label,
        createTarget() {
          const client = createSqlClient();
          return { store: createStore({ client }) };
        },
      })) {
        test(conformanceTest.name, conformanceTest.run);
      }
    });
  }

  test("SQL schema helpers declare tenant and idempotency constraints", () => {
    expect(POSTGRES_AUDIT_RECORDS_SCHEMA_SQL).toContain("CREATE TABLE IF NOT EXISTS veritio_audit_records");
    expect(POSTGRES_AUDIT_RECORDS_SCHEMA_SQL).toContain("UNIQUE (tenant_id, idempotency_key_hash)");
    expect(MYSQL_AUDIT_RECORDS_SCHEMA_SQL).toContain("CREATE TABLE IF NOT EXISTS `veritio_audit_records`");
    expect(MYSQL_AUDIT_RECORDS_SCHEMA_SQL).toContain("UNIQUE KEY");
    expect(POSTGRES_AUDIT_RECORDS_SCHEMA_SQL).toContain("tenant_id text PRIMARY KEY");
    expect(POSTGRES_AUDIT_RECORDS_SCHEMA_SQL).toContain("PRIMARY KEY (tenant_id, epoch)");
    expect(POSTGRES_AUDIT_RECORDS_SCHEMA_SQL).toContain("UNIQUE (tenant_id, checkpoint_hash)");
    expect(POSTGRES_AUDIT_RECORDS_SCHEMA_SQL).toContain("PRIMARY KEY (tenant_id, idempotency_key_hash)");
    expect(MYSQL_AUDIT_RECORDS_SCHEMA_SQL).toContain("PRIMARY KEY (`tenant_id`, `epoch`)");
    expect(MONGO_RETENTION_INDEXES.chainStates[0].options.unique).toBe(true);
    expect(MONGO_RETENTION_INDEXES.checkpoints).toHaveLength(2);
  });

  test("MySQL list queries inline validated limits for mysql2 prepared statements", async () => {
    const client = createSqlClient();
    const store = createMysqlAuditStore({ client });
    await store.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
    await store.append(makeEvent("evt_02", "org_123", { role: "admin" }));

    const records = await store.list({ tenantId: "org_123" }, { limit: 1 });

    expect(records).toHaveLength(1);
    expect(client.statements.some((statement) => statement.includes("LIMIT ?"))).toBe(false);
    expect(client.statements.some((statement) => statement.includes("LIMIT 1"))).toBe(true);
  });

  test("SQL maps every schema and table identifier component within its dialect byte ceiling", async () => {
    const longSchema = `schema_${"s".repeat(80)}`;
    const longTable = `records_${"r".repeat(80)}`;
    const postgresClient = createSqlClient();
    const postgresStore = createPostgresAuditStore({
      client: postgresClient,
      tableName: `${longSchema}.${longTable}`,
    });
    await postgresStore.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
    await postgresStore.listCheckpoints({ tenantId: "org_123" });
    const postgresIdentifiers = postgresClient.statements.flatMap((statement) =>
      [...statement.matchAll(/"([^"]+)"/g)].map((match) => match[1]!),
    );

    const mysqlClient = createSqlClient();
    const mysqlStore = createMariaDbAuditStore({ client: mysqlClient, tableName: `${longSchema}.${longTable}` });
    await mysqlStore.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
    await mysqlStore.listCheckpoints({ tenantId: "org_123" });
    const mysqlIdentifiers = mysqlClient.statements.flatMap((statement) =>
      [...statement.matchAll(/`([^`]+)`/g)].map((match) => match[1]!),
    );

    expect(postgresIdentifiers.length).toBeGreaterThan(0);
    expect(postgresIdentifiers.every((identifier) => Buffer.byteLength(identifier) <= 63)).toBe(true);
    expect(mysqlIdentifiers.length).toBeGreaterThan(0);
    expect(mysqlIdentifiers.every((identifier) => Buffer.byteLength(identifier) <= 64)).toBe(true);
    expect(new Set(postgresIdentifiers).size).toBeGreaterThanOrEqual(5);
    expect(new Set(mysqlIdentifiers).size).toBeGreaterThanOrEqual(5);
  });

  test("SQL identifier mapping is deterministic and honors the MySQL-only sixty-fourth byte", () => {
    const identifier = `t${"x".repeat(63)}`;
    const postgres = getSqlAuditRetentionTableNames(identifier, "postgres");
    const postgresReplay = getSqlAuditRetentionTableNames(identifier, "postgres");
    const mysql = getSqlAuditRetentionTableNames(identifier, "mysql");

    expect(postgres).toEqual(postgresReplay);
    expect(postgres.records).not.toBe(identifier);
    expect(Buffer.byteLength(postgres.records)).toBeLessThanOrEqual(63);
    expect(mysql.records).toBe(identifier);
    expect(Buffer.byteLength(mysql.records)).toBe(64);
  });

  test("SQL compaction rejects redundant event canonical bytes that disagree with the verified record", async () => {
    const client = createSqlClient();
    const store = createPostgresAuditStore({ client });
    const record = await store.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
    client.rows[0]!.event_canonical = canonicalJson({ ...record.event, metadata: { role: "tampered" } });
    const state = await store.getChainState({ tenantId: "org_123" });

    await expect(
      store.compactRange({ tenantId: "org_123" }, checkpointForRecord(record), state, state.retentionPolicyFence),
    ).rejects.toThrow("stored audit event canonical integrity check failed");

    expect(await store.list({ tenantId: "org_123" })).toEqual([record]);
    expect(await store.listCheckpoints({ tenantId: "org_123" })).toEqual([]);
  });

  test("SQL append and crop reject relationally corrupt persisted chain state before mutation", async () => {
    for (const operation of ["append", "crop"] as const) {
      for (const invalid of relationallyInvalidChainStates) {
        const client = createSqlClient();
        const store = createPostgresAuditStore({ client });
        const record = await store.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
        const state = invalid(record.hash);
        overwriteSqlChainState(client, state);
        const before = sqlMutationSnapshot(client);

        const attempted = operation === "append"
          ? store.append(makeEvent("evt_02", "org_123", { role: "admin" }))
          : store.compactRange({ tenantId: "org_123" }, checkpointForRecord(record), state, 0);
        await expect(attempted).rejects.toThrow("invalid audit chain state");

        expect(sqlMutationSnapshot(client)).toBe(before);
      }
    }
  });

  test("SQL checkpoint reads reject redundant epoch and hash column corruption", async () => {
    const client = createSqlClient();
    const store = createPostgresAuditStore({ client });
    const record = await store.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
    const checkpoint = checkpointForRecord(record);
    const state = await store.getChainState({ tenantId: "org_123" });
    await store.compactRange({ tenantId: "org_123" }, checkpoint, state, state.retentionPolicyFence);
    const rows = (
      client as typeof client & {
        checkpoints: Array<{ epoch: number; checkpoint_hash: string }>;
      }
    ).checkpoints;
    rows[0]!.epoch = 99;
    rows[0]!.checkpoint_hash = "f".repeat(64);

    await expect(store.listCheckpoints({ tenantId: "org_123" })).rejects.toThrow(
      "stored retention checkpoint redundant column mismatch",
    );
  });

  test("SQL disposition reads reject redundant checkpoint hash column corruption", async () => {
    const client = createSqlClient();
    const store = createPostgresAuditStore({ client });
    const record = await store.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
    const checkpoint = checkpointForRecord(record);
    const state = await store.getChainState({ tenantId: "org_123" });
    await store.compactRange({ tenantId: "org_123" }, checkpoint, state, state.retentionPolicyFence);
    const attempt = attemptForCheckpoint(checkpoint.hash);
    await store.prepareDisposition({ tenantId: "org_123" }, checkpoint.hash, attempt, 0);
    const receipt = dispositionForCheckpoint(checkpoint);
    await store.confirmDisposition({ tenantId: "org_123" }, receipt, attempt.attemptId, 0);
    const rows = (
      client as typeof client & {
        dispositions: Array<{ checkpoint_hash: string }>;
      }
    ).dispositions;
    rows[0]!.checkpoint_hash = "f".repeat(64);

    await expect(store.listDispositions({ tenantId: "org_123" })).rejects.toThrow(
      "stored retention disposition redundant column mismatch",
    );
  });
});

describe("Mongo AuditStore adapter", () => {
  describe("mongo AuditStore conformance", () => {
    for (const conformanceTest of createAuditStoreConformanceTests({
      name: "mongo",
      createTarget() {
        const collection = createMongoCollection();
        const retention = createMongoRetentionCollections();
        return {
          store: createMongoAuditStore({
            collection,
            retention,
            transaction: async (run) => run({ collection }),
          }),
          mutateStoredRecord(corruption) {
            mutateMongoStoredRecord(collection, corruption);
          },
        };
      },
    })) {
      test(conformanceTest.name, conformanceTest.run);
    }

    for (const conformanceTest of createRetentionStoreConformanceTests({
      name: "mongo",
      createTarget() {
        const collection = createMongoCollection();
        const retention = createMongoRetentionCollections();
        return {
          store: createMongoAuditStore({
            collection,
            retention,
            transaction: async (run) => run({ collection }),
          }),
        };
      },
    })) {
      test(conformanceTest.name, conformanceTest.run);
    }
  });

  test("Mongo compaction rejects redundant event canonical bytes that disagree with the verified record", async () => {
    const collection = createMongoCollection();
    const retention = createMongoRetentionCollections();
    const store = createMongoAuditStore({
      collection,
      retention,
      transaction: async (run) => run({ collection }),
    });
    const record = await store.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
    collection.documents[0]!.eventCanonical = canonicalJson({ ...record.event, metadata: { role: "tampered" } });
    const state = await store.getChainState({ tenantId: "org_123" });

    await expect(
      store.compactRange({ tenantId: "org_123" }, checkpointForRecord(record), state, state.retentionPolicyFence),
    ).rejects.toThrow("stored audit event canonical integrity check failed");

    expect(await store.list({ tenantId: "org_123" })).toEqual([record]);
    expect(await store.listCheckpoints({ tenantId: "org_123" })).toEqual([]);
  });

  test("Mongo append and crop reject relationally corrupt persisted chain state before mutation", async () => {
    for (const operation of ["append", "crop"] as const) {
      for (const invalid of relationallyInvalidChainStates) {
        const collection = createMongoCollection();
        const retention = createMongoRetentionCollections();
        const store = createMongoAuditStore({
          collection,
          retention,
          transaction: async (run) => run({ collection }),
        });
        const record = await store.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
        const state = invalid(record.hash);
        Object.assign(retentionDocuments(retention.chainStates)[0]!, state);
        const before = mongoMutationSnapshot(collection, retention);

        const attempted = operation === "append"
          ? store.append(makeEvent("evt_02", "org_123", { role: "admin" }))
          : store.compactRange({ tenantId: "org_123" }, checkpointForRecord(record), state, 0);
        await expect(attempted).rejects.toThrow("invalid audit chain state");

        expect(mongoMutationSnapshot(collection, retention)).toBe(before);
      }
    }
  });

  test("Mongo checkpoint reads reject redundant epoch and hash field corruption", async () => {
    const collection = createMongoCollection();
    const retention = createMongoRetentionCollections();
    const store = createMongoAuditStore({
      collection,
      retention,
      transaction: async (run) => run({ collection }),
    });
    const record = await store.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
    const checkpoint = checkpointForRecord(record);
    const state = await store.getChainState({ tenantId: "org_123" });
    await store.compactRange({ tenantId: "org_123" }, checkpoint, state, state.retentionPolicyFence);
    const documents = retentionDocuments(retention.checkpoints);
    documents[0]!.epoch = 99;
    documents[0]!.checkpointHash = "f".repeat(64);

    await expect(store.listCheckpoints({ tenantId: "org_123" })).rejects.toThrow(
      "stored retention checkpoint redundant column mismatch",
    );
  });

  test("Mongo disposition reads reject redundant checkpoint hash field corruption", async () => {
    const collection = createMongoCollection();
    const retention = createMongoRetentionCollections();
    const store = createMongoAuditStore({
      collection,
      retention,
      transaction: async (run) => run({ collection }),
    });
    const record = await store.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
    const checkpoint = checkpointForRecord(record);
    const state = await store.getChainState({ tenantId: "org_123" });
    await store.compactRange({ tenantId: "org_123" }, checkpoint, state, state.retentionPolicyFence);
    const attempt = attemptForCheckpoint(checkpoint.hash);
    await store.prepareDisposition({ tenantId: "org_123" }, checkpoint.hash, attempt, 0);
    const receipt = dispositionForCheckpoint(checkpoint);
    await store.confirmDisposition({ tenantId: "org_123" }, receipt, attempt.attemptId, 0);
    retentionDocuments(retention.dispositions)[0]!.checkpointHash = "f".repeat(64);

    await expect(store.listDispositions({ tenantId: "org_123" })).rejects.toThrow(
      "stored retention disposition redundant column mismatch",
    );
  });

  test("Mongo retention activation requires an explicit integrity-validating legacy backfill", async () => {
    const collection = createMongoCollection();
    const transaction: MongoAuditStoreOptions["transaction"] = async (run) => run({ collection });
    const legacyStore = createMongoAuditStore({ collection, transaction });
    const firstEvent = makeEvent("evt_01", "org_123", { role: "viewer" });
    const first = await legacyStore.append(firstEvent);
    const second = await legacyStore.append(makeEvent("evt_02", "org_123", { role: "admin" }));
    const retention = createMongoRetentionCollections();
    const store = createMongoAuditStore({ collection, retention, transaction });

    await expect(store.getChainState({ tenantId: "org_123" })).rejects.toThrow(
      "Mongo retention state migration required",
    );
    await expect(store.append(makeEvent("evt_03", "org_123", { role: "owner" }))).rejects.toThrow(
      "Mongo retention state migration required",
    );

    const backfill = (
      storageModule as typeof storageModule & {
        backfillMongoAuditRetentionState(
          options: MongoAuditStoreOptions,
          scope: { tenantId: string },
        ): Promise<unknown>;
      }
    ).backfillMongoAuditRetentionState;
    expect(backfill).toBeFunction();
    await backfill({ collection, retention, transaction }, { tenantId: "org_123" });

    expect(await store.getChainState({ tenantId: "org_123" })).toEqual({
      authoritativeTipSequence: 2,
      authoritativeTipHash: second.hash,
      minimumRetainedSequence: 1,
      latestCheckpointHash: null,
      retentionPolicyFence: 0,
    });
    expect(await store.append(firstEvent)).toEqual(first);
    const third = await store.append(makeEvent("evt_03", "org_123", { role: "owner" }));
    expect(third.sequence).toBe(3);
    expect(third.previousHash).toBe(second.hash);
  });

  test("Mongo legacy backfill rejects a corrupt chain without partial activation", async () => {
    const collection = createMongoCollection();
    const transaction: MongoAuditStoreOptions["transaction"] = async (run) => run({ collection });
    const legacyStore = createMongoAuditStore({ collection, transaction });
    await legacyStore.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
    await legacyStore.append(makeEvent("evt_02", "org_123", { role: "admin" }));
    const second = JSON.parse(collection.documents[1]!.recordJson) as AuditRecord;
    collection.documents[1]!.recordJson = JSON.stringify({ ...second, previousHash: "f".repeat(64) });
    const retention = createMongoRetentionCollections();
    const store = createMongoAuditStore({ collection, retention, transaction });
    const backfill = (
      storageModule as typeof storageModule & {
        backfillMongoAuditRetentionState(
          options: MongoAuditStoreOptions,
          scope: { tenantId: string },
        ): Promise<unknown>;
      }
    ).backfillMongoAuditRetentionState;

    expect(backfill).toBeFunction();
    await expect(backfill({ collection, retention, transaction }, { tenantId: "org_123" })).rejects.toThrow(
      "stored audit record integrity check failed",
    );
    await expect(store.getChainState({ tenantId: "org_123" })).rejects.toThrow(
      "Mongo retention state migration required",
    );
  });
});

describe("Redis audit tip cache", () => {
  test("stores validated chain tips without pretending to be an AuditStore", async () => {
    const redis = createRedisClient();
    const cache = createRedisAuditTipCache({ client: redis, keyPrefix: "test:veritio:tips" });
    const durableStore = new MemoryAuditStore();
    const record = await durableStore.append(makeEvent("evt_01", "org_123", { role: "viewer" }));

    expect("append" in cache).toBe(false);
    expect("list" in cache).toBe(false);

    await cache.setTenantTip(record);

    expect(await cache.getTenantTip("org_123")).toEqual(record);
    expect(redis.values.get("test:veritio:tips:org_123")).toBe(JSON.stringify(record));
  });

  test("Redis tip cache fails closed for missing tenant scope and corrupted records", async () => {
    const redis = createRedisClient();
    const cache = createRedisAuditTipCache({ client: redis });
    const durableStore = new MemoryAuditStore();
    const record = await durableStore.append(makeEvent("evt_01", "org_123", { role: "viewer" }));

    await expect(cache.setTenantTip({ ...record, event: { ...record.event, scope: undefined } })).rejects.toThrow(
      "scope.tenantId is required",
    );

    redis.values.set("veritio:audit-tip:org_123", JSON.stringify({ ...record, hash: "0".repeat(64) }));

    await expect(cache.getTenantTip("org_123")).rejects.toThrow("stored audit record integrity check failed");
  });
});

function makeEvent(id: string, tenantId: string, metadata: Record<string, unknown>) {
  return createAuditEvent({
    id,
    occurredAt: `2026-06-10T00:00:0${id.endsWith("1") ? "0" : "1"}.000Z`,
    actor: { type: "user", id: `usr_${tenantId}` },
    action: "org.member.invited",
    target: { type: "organization", id: tenantId },
    scope: { tenantId, environment: "test" },
    metadata,
  });
}

/** Covers both sequence/hash null equivalence and retained-minimum/checkpoint equivalence. */
const relationallyInvalidChainStates = [
  (hash: string): AuditChainState => ({
    authoritativeTipSequence: 0,
    authoritativeTipHash: hash,
    minimumRetainedSequence: 1,
    latestCheckpointHash: null,
    retentionPolicyFence: 0,
  }),
  (_hash: string): AuditChainState => ({
    authoritativeTipSequence: 1,
    authoritativeTipHash: null,
    minimumRetainedSequence: 1,
    latestCheckpointHash: null,
    retentionPolicyFence: 0,
  }),
  (hash: string): AuditChainState => ({
    authoritativeTipSequence: 1,
    authoritativeTipHash: hash,
    minimumRetainedSequence: 1,
    latestCheckpointHash: hash,
    retentionPolicyFence: 0,
  }),
  (hash: string): AuditChainState => ({
    authoritativeTipSequence: 1,
    authoritativeTipHash: hash,
    minimumRetainedSequence: 2,
    latestCheckpointHash: null,
    retentionPolicyFence: 0,
  }),
] as const;

/** Overwrites the SQL fake's persisted row without using adapter validation. */
function overwriteSqlChainState(client: SqlAuditExecutor, state: AuditChainState): void {
  const row = (
    client as SqlAuditExecutor & { chainStates: SqlAuditChainStateRow[] }
  ).chainStates[0];
  if (!row) throw new TypeError("SQL chain state fixture is missing");
  Object.assign(row, {
    authoritative_tip_sequence: state.authoritativeTipSequence,
    authoritative_tip_hash: state.authoritativeTipHash,
    minimum_retained_sequence: state.minimumRetainedSequence,
    latest_checkpoint_hash: state.latestCheckpointHash,
    retention_policy_fence: state.retentionPolicyFence,
  });
}

/** Captures all SQL authoritative mutation surfaces while excluding statement telemetry. */
function sqlMutationSnapshot(client: SqlAuditExecutor): string {
  const mutable = client as SqlAuditExecutor & {
    rows: SqlAuditRow[];
    chainStates: SqlAuditChainStateRow[];
    ledger: unknown[];
    checkpoints: unknown[];
  };
  return canonicalJson({
    rows: mutable.rows,
    chainStates: mutable.chainStates,
    ledger: mutable.ledger,
    checkpoints: mutable.checkpoints,
  });
}

/** Captures Mongo rows plus every retention collection touched by append or crop. */
function mongoMutationSnapshot(
  collection: MongoAuditCollection & { documents: MongoAuditDocument[] },
  retention: MongoRetentionCollections,
): string {
  return canonicalJson({
    rows: collection.documents,
    chainStates: retentionDocuments(retention.chainStates),
    ledger: retentionDocuments(retention.idempotencyLedger),
    checkpoints: retentionDocuments(retention.checkpoints),
  });
}

/** Builds one deterministic single-record checkpoint for focused adapter regressions. */
function checkpointForRecord(record: AuditRecord) {
  return createRetentionCheckpoint({
    checkpointId: `rcp_${record.event.id}`,
    tenantId: record.event.scope!.tenantId!,
    chainKind: "audit",
    epoch: 1,
    fromSequence: record.sequence,
    fromPreviousHash: record.previousHash,
    throughSequence: record.sequence,
    throughHash: record.hash,
    recordCount: 1,
    archiveRootHash: "a".repeat(64),
    previousCheckpointHash: null,
    createdAt: "2026-08-24T01:00:00.000Z",
  });
}

/** Builds the minimal pending attempt used by redundant receipt-column regressions. */
function attemptForCheckpoint(checkpointHash: string): DispositionAttempt {
  return { attemptId: "attempt_integrity", checkpointHash, policyFence: 0, status: "pending" };
}

/** Builds one deterministic receipt matching a focused single-record checkpoint. */
function dispositionForCheckpoint(checkpoint: ReturnType<typeof checkpointForRecord>) {
  return createRetentionDisposition({
    dispositionId: "disposition_integrity",
    tenantId: checkpoint.tenantId,
    chainKind: "audit",
    checkpointHash: checkpoint.hash,
    fromSequence: checkpoint.fromSequence,
    throughSequence: checkpoint.throughSequence,
    archiveRootHash: checkpoint.archiveRootHash,
    policyReference: "policy.integrity",
    disposedAt: "2026-08-24T02:00:00.000Z",
  });
}

function mutateSqlStoredRecord(
  client: SqlAuditExecutor & { rows: SqlAuditRow[] },
  corruption: AuditStoreConformanceCorruption,
): void {
  const index = client.rows.findIndex(
    (row) => row.tenant_id === corruption.tenantId && row.sequence === corruption.sequence,
  );
  if (index === -1) {
    throw new TypeError("stored audit record not found");
  }
  const row = client.rows[index]!;
  const record = JSON.parse(row.record_json) as AuditRecord;
  const nextRecord = corruption.mutate(record) ?? record;
  client.rows[index] = { ...row, record_json: JSON.stringify(nextRecord) };
}

function mutateMongoStoredRecord(
  collection: MongoAuditCollection & { documents: MongoAuditDocument[] },
  corruption: AuditStoreConformanceCorruption,
): void {
  const index = collection.documents.findIndex(
    (document) => document.tenantId === corruption.tenantId && document.sequence === corruption.sequence,
  );
  if (index === -1) {
    throw new TypeError("stored audit record not found");
  }
  const document = collection.documents[index]!;
  const record = JSON.parse(document.recordJson) as AuditRecord;
  const nextRecord = corruption.mutate(record) ?? record;
  collection.documents[index] = { ...document, recordJson: JSON.stringify(nextRecord) };
}

function createSqlClient(): SqlAuditExecutor & { rows: SqlAuditRow[]; statements: string[] } {
  type LedgerRow = {
    tenant_id: string;
    idempotency_key_hash: string;
    event_canonical_hash: string;
    original_sequence: number;
    original_record_hash: string;
    record_json: string | null;
  };
  type CheckpointRow = { tenant_id: string; epoch: number; checkpoint_hash: string; checkpoint_canonical: string };
  type AttemptRow = {
    tenant_id: string;
    checkpoint_hash: string;
    attempt_id: string;
    policy_fence: number;
    status: string;
    attempt_canonical: string;
  };
  type DispositionRow = { tenant_id: string; checkpoint_hash: string; disposition_canonical: string };
  const client: SqlAuditExecutor & {
    rows: SqlAuditRow[];
    statements: string[];
    chainStates: SqlAuditChainStateRow[];
    ledger: LedgerRow[];
    checkpoints: CheckpointRow[];
    attempts: AttemptRow[];
    dispositions: DispositionRow[];
  } = {
    rows: [],
    statements: [],
    chainStates: [],
    ledger: [],
    checkpoints: [],
    attempts: [],
    dispositions: [],
    async transaction(run) {
      return run(client);
    },
    async execute(statement, params) {
      client.statements.push(statement);
      const sql = statement.toLowerCase();
      if (sql.startsWith("select tenant_id") && sql.includes("_state")) {
        const [tenantId] = params;
        return client.chainStates.filter((row) => row.tenant_id === tenantId);
      }
      if (sql.startsWith("insert") && sql.includes("_state")) {
        const [tenantId] = params;
        if (!client.chainStates.some((row) => row.tenant_id === tenantId)) {
          client.chainStates.push({
            tenant_id: String(tenantId),
            authoritative_tip_sequence: 0,
            authoritative_tip_hash: null,
            minimum_retained_sequence: 1,
            latest_checkpoint_hash: null,
            retention_policy_fence: 0,
          });
        }
        return [];
      }
      if (sql.startsWith("update") && sql.includes("_state")) {
        const [tipSequence, tipHash, minimumSequence, latestCheckpointHash, fence, tenantId] = params;
        const row = client.chainStates.find((candidate) => candidate.tenant_id === tenantId);
        if (!row) throw new TypeError("chain state not found");
        Object.assign(row, {
          authoritative_tip_sequence: Number(tipSequence),
          authoritative_tip_hash: tipHash === null ? null : String(tipHash),
          minimum_retained_sequence: Number(minimumSequence),
          latest_checkpoint_hash: latestCheckpointHash === null ? null : String(latestCheckpointHash),
          retention_policy_fence: Number(fence),
        });
        return [];
      }
      if (sql.startsWith("select event_canonical_hash") && sql.includes("_idem")) {
        const [tenantId, idempotencyKeyHash] = params;
        return client.ledger.filter(
          (row) => row.tenant_id === tenantId && row.idempotency_key_hash === idempotencyKeyHash,
        );
      }
      if (sql.startsWith("insert") && sql.includes("_idem")) {
        const [tenantId, idempotencyKeyHash, eventCanonicalHash, originalSequence, originalRecordHash, recordJson] =
          params;
        const existing = client.ledger.find(
          (row) => row.tenant_id === tenantId && row.idempotency_key_hash === idempotencyKeyHash,
        );
        const next: LedgerRow = {
          tenant_id: String(tenantId),
          idempotency_key_hash: String(idempotencyKeyHash),
          event_canonical_hash: String(eventCanonicalHash),
          original_sequence: Number(originalSequence),
          original_record_hash: String(originalRecordHash),
          record_json: recordJson === undefined || recordJson === null ? null : String(recordJson),
        };
        if (existing && (sql.includes("on conflict") || sql.includes("on duplicate key")))
          Object.assign(existing, next);
        else if (existing) throw new TypeError("duplicate idempotency key");
        else client.ledger.push(next);
        return [];
      }
      if (sql.startsWith("select") && sql.includes("checkpoint_canonical") && sql.includes("_checkpoints")) {
        const [tenantId, checkpointHash] = params;
        let rows = client.checkpoints.filter(
          (row) =>
            row.tenant_id === tenantId && (checkpointHash === undefined || row.checkpoint_hash === checkpointHash),
        );
        rows = rows.sort((left, right) => (sql.includes("desc") ? right.epoch - left.epoch : left.epoch - right.epoch));
        return sql.includes("limit 1") ? rows.slice(0, 1) : rows;
      }
      if (sql.startsWith("insert") && sql.includes("_checkpoints")) {
        const [tenantId, epoch, checkpointHash, checkpointCanonical] = params;
        if (
          client.checkpoints.some(
            (row) => row.tenant_id === tenantId && (row.epoch === epoch || row.checkpoint_hash === checkpointHash),
          )
        ) {
          throw new TypeError("duplicate checkpoint");
        }
        client.checkpoints.push({
          tenant_id: String(tenantId),
          epoch: Number(epoch),
          checkpoint_hash: String(checkpointHash),
          checkpoint_canonical: String(checkpointCanonical),
        });
        return [];
      }
      if (sql.startsWith("select attempt_canonical") && sql.includes("_attempts")) {
        const [tenantId, checkpointHash] = params;
        return client.attempts.filter((row) => row.tenant_id === tenantId && row.checkpoint_hash === checkpointHash);
      }
      if (sql.startsWith("insert") && sql.includes("_attempts")) {
        const [tenantId, checkpointHash, attemptId, policyFence, status, attemptCanonical] = params;
        client.attempts.push({
          tenant_id: String(tenantId),
          checkpoint_hash: String(checkpointHash),
          attempt_id: String(attemptId),
          policy_fence: Number(policyFence),
          status: String(status),
          attempt_canonical: String(attemptCanonical),
        });
        return [];
      }
      if (sql.startsWith("update") && sql.includes("_attempts")) {
        const [attemptId, policyFence, status, attemptCanonical, tenantId, checkpointHash] = params;
        const row = client.attempts.find(
          (candidate) => candidate.tenant_id === tenantId && candidate.checkpoint_hash === checkpointHash,
        );
        if (!row) throw new TypeError("attempt not found");
        Object.assign(row, {
          attempt_id: String(attemptId),
          policy_fence: Number(policyFence),
          status: String(status),
          attempt_canonical: String(attemptCanonical),
        });
        return [];
      }
      if (sql.startsWith("select") && sql.includes("disposition_canonical") && sql.includes("_receipts")) {
        const [tenantId, checkpointHash] = params;
        return client.dispositions.filter(
          (row) =>
            row.tenant_id === tenantId && (checkpointHash === undefined || row.checkpoint_hash === checkpointHash),
        );
      }
      if (sql.startsWith("insert") && sql.includes("_receipts")) {
        const [tenantId, checkpointHash, dispositionCanonical] = params;
        if (client.dispositions.some((row) => row.tenant_id === tenantId && row.checkpoint_hash === checkpointHash)) {
          throw new TypeError("duplicate disposition");
        }
        client.dispositions.push({
          tenant_id: String(tenantId),
          checkpoint_hash: String(checkpointHash),
          disposition_canonical: String(dispositionCanonical),
        });
        return [];
      }
      if (sql.startsWith("select event_canonical, record_json") && sql.includes("sequence >=")) {
        const [tenantId, fromSequence, throughSequence] = params;
        return client.rows
          .filter(
            (row) =>
              row.tenant_id === tenantId &&
              row.sequence >= Number(fromSequence) &&
              row.sequence <= Number(throughSequence),
          )
          .sort((left, right) => left.sequence - right.sequence);
      }
      if (sql.startsWith("select event_canonical")) {
        const [tenantId, idempotencyKeyHash] = params;
        return client.rows.filter(
          (row) => row.tenant_id === tenantId && row.idempotency_key_hash === idempotencyKeyHash,
        );
      }
      if (sql.startsWith("select record_json") && sql.includes("order by") && sql.includes("desc")) {
        const [tenantId] = params;
        return client.rows
          .filter((row) => row.tenant_id === tenantId)
          .sort((a, b) => b.sequence - a.sequence)
          .slice(0, 1);
      }
      if (
        sql.startsWith("insert into") &&
        !sql.includes("_idem") &&
        !sql.includes("_checkpoints") &&
        !sql.includes("_attempts") &&
        !sql.includes("_receipts")
      ) {
        const [tenantId, sequence, idempotencyKeyHash, eventCanonical, recordJson, hash, previousHash, appendedAt] =
          params;
        if (client.rows.some((row) => row.tenant_id === tenantId && row.idempotency_key_hash === idempotencyKeyHash)) {
          throw new TypeError("duplicate idempotency key");
        }
        if (client.rows.some((row) => row.tenant_id === tenantId && row.sequence === sequence)) {
          throw new TypeError("duplicate tenant sequence");
        }
        client.rows.push({
          tenant_id: String(tenantId),
          sequence: Number(sequence),
          idempotency_key_hash: String(idempotencyKeyHash),
          event_canonical: String(eventCanonical),
          record_json: String(recordJson),
          hash: String(hash),
          previous_hash: previousHash === null ? null : String(previousHash),
          appended_at: String(appendedAt),
        });
        return [];
      }
      if (sql.startsWith("select record_json") && sql.includes("order by") && sql.includes("asc")) {
        const [tenantId, afterSequence, third] = params;
        if (sql.includes("sequence >=") && sql.includes("sequence <=")) {
          return client.rows
            .filter(
              (row) =>
                row.tenant_id === tenantId && row.sequence >= Number(afterSequence) && row.sequence <= Number(third),
            )
            .sort((a, b) => a.sequence - b.sequence);
        }
        const limit = third;
        const inlineLimit = statement.match(/\blimit\s+(\d+)\s*$/i)?.[1];
        const effectiveLimit = limit ?? inlineLimit;
        const rows = client.rows
          .filter((row) => row.tenant_id === tenantId && row.sequence > Number(afterSequence))
          .sort((a, b) => a.sequence - b.sequence);
        return effectiveLimit === undefined ? rows : rows.slice(0, Number(effectiveLimit));
      }
      if (sql.startsWith("delete from") && !sql.includes("_idem")) {
        const [tenantId, fromSequence, throughSequence] = params;
        client.rows = client.rows.filter(
          (row) =>
            row.tenant_id !== tenantId || row.sequence < Number(fromSequence) || row.sequence > Number(throughSequence),
        );
        return [];
      }
      throw new TypeError(`unexpected SQL: ${statement}`);
    },
  };

  return client;
}

function createMongoCollection(): MongoAuditCollection & { documents: MongoAuditDocument[] } {
  return {
    documents: [],
    async findOne(filter, options = {}) {
      const matches = this.documents.filter((document) => matchesMongoFilter(document, filter));
      if (options.sort?.sequence === -1) {
        matches.sort((a, b) => b.sequence - a.sequence);
      }
      if (options.sort?.sequence === 1) {
        matches.sort((a, b) => a.sequence - b.sequence);
      }
      return matches[0] ?? null;
    },
    async insertOne(document) {
      if (
        this.documents.some(
          (existing) =>
            existing.tenantId === document.tenantId && existing.idempotencyKeyHash === document.idempotencyKeyHash,
        )
      ) {
        throw new TypeError("duplicate idempotency key");
      }
      if (
        this.documents.some(
          (existing) => existing.tenantId === document.tenantId && existing.sequence === document.sequence,
        )
      ) {
        throw new TypeError("duplicate tenant sequence");
      }
      this.documents.push({ ...document });
      return { acknowledged: true };
    },
    async deleteMany(filter) {
      this.documents = this.documents.filter((document) => !matchesMongoFilter(document, filter));
      return { acknowledged: true };
    },
    find(filter, options = {}) {
      let matches = this.documents.filter((document) => matchesMongoFilter(document, filter));
      if (options.sort?.sequence === 1) {
        matches = matches.sort((a, b) => a.sequence - b.sequence);
      }
      if (typeof options.limit === "number") {
        matches = matches.slice(0, options.limit);
      }
      return {
        async toArray() {
          return matches;
        },
      };
    },
  };
}

function createMongoRetentionCollections(): MongoRetentionCollections {
  return {
    chainStates: createMongoRetentionCollection<MongoAuditChainStateDocument>(),
    idempotencyLedger: createMongoRetentionCollection<MongoIdempotencyLedgerDocument>(),
    checkpoints: createMongoRetentionCollection<MongoCheckpointDocument>(),
    dispositionAttempts: createMongoRetentionCollection<MongoDispositionAttemptDocument>(),
    dispositions: createMongoRetentionCollection<MongoDispositionDocument>(),
  };
}

function createMongoRetentionCollection<
  TDocument extends Record<string, unknown>,
>(): MongoRetentionCollection<TDocument> & { documents: TDocument[] } {
  const documents: TDocument[] = [];
  return {
    documents,
    async findOne(filter, options = {}) {
      const matches = documents.filter((document) => matchesGenericMongoFilter(document, filter));
      sortGenericMongoDocuments(matches, options.sort);
      return matches[0] ?? null;
    },
    find(filter, options = {}) {
      let matches = documents.filter((document) => matchesGenericMongoFilter(document, filter));
      sortGenericMongoDocuments(matches, options.sort);
      if (typeof options.limit === "number") matches = matches.slice(0, options.limit);
      return {
        async toArray() {
          return matches.map((document) => ({ ...document }));
        },
      };
    },
    async insertOne(document) {
      documents.push({ ...document });
      return { acknowledged: true };
    },
    async updateOne(filter, update, options = {}) {
      let document = documents.find((candidate) => matchesGenericMongoFilter(candidate, filter));
      if (!document && options.upsert === true) {
        document = { ...filter } as TDocument;
        documents.push(document);
      }
      if (!document) return { acknowledged: true, matchedCount: 0 };
      const set = update.$set as Record<string, unknown> | undefined;
      if (set) Object.assign(document, set);
      const unset = update.$unset as Record<string, unknown> | undefined;
      if (unset) for (const key of Object.keys(unset)) delete document[key];
      const increment = update.$inc as Record<string, unknown> | undefined;
      if (increment) {
        for (const [key, value] of Object.entries(increment)) {
          if (typeof value !== "number") throw new TypeError("fake Mongo increment must be numeric");
          const current = document[key];
          if (current !== undefined && typeof current !== "number") {
            throw new TypeError("fake Mongo increment target must be numeric");
          }
          document[key] = (current ?? 0) + value;
        }
      }
      return { acknowledged: true, matchedCount: 1 };
    },
    async deleteMany(filter) {
      for (let index = documents.length - 1; index >= 0; index -= 1) {
        if (matchesGenericMongoFilter(documents[index]!, filter)) documents.splice(index, 1);
      }
      return { acknowledged: true };
    },
  };
}

/** Exposes the unit fake's backing documents for deliberate integrity corruption. */
function retentionDocuments<TDocument extends Record<string, unknown>>(
  collection: MongoRetentionCollection<TDocument>,
): TDocument[] {
  return (collection as MongoRetentionCollection<TDocument> & { documents: TDocument[] }).documents;
}

function matchesGenericMongoFilter(document: Record<string, unknown>, filter: Record<string, unknown>): boolean {
  return Object.entries(filter).every(([key, expected]) => {
    const actual = document[key];
    if (typeof expected === "object" && expected !== null && !Array.isArray(expected)) {
      const range = expected as { $gt?: number; $gte?: number; $lte?: number };
      if (range.$gt !== undefined && (!(typeof actual === "number") || actual <= range.$gt)) return false;
      if (range.$gte !== undefined && (!(typeof actual === "number") || actual < range.$gte)) return false;
      if (range.$lte !== undefined && (!(typeof actual === "number") || actual > range.$lte)) return false;
      return true;
    }
    return actual === expected;
  });
}

function sortGenericMongoDocuments(documents: Record<string, unknown>[], sort?: Record<string, 1 | -1>): void {
  const entry = sort ? Object.entries(sort)[0] : undefined;
  if (!entry) return;
  const [field, direction] = entry;
  documents.sort((left, right) => (Number(left[field]) - Number(right[field])) * direction);
}

function matchesMongoFilter(document: MongoAuditDocument, filter: Record<string, unknown>): boolean {
  if (filter.tenantId !== undefined && document.tenantId !== filter.tenantId) {
    return false;
  }
  if (filter.idempotencyKeyHash !== undefined && document.idempotencyKeyHash !== filter.idempotencyKeyHash) {
    return false;
  }
  const sequence = filter.sequence as { $gt?: number; $gte?: number; $lte?: number } | undefined;
  if (sequence?.$gt !== undefined && document.sequence <= sequence.$gt) {
    return false;
  }
  if (sequence?.$gte !== undefined && document.sequence < sequence.$gte) {
    return false;
  }
  if (sequence?.$lte !== undefined && document.sequence > sequence.$lte) {
    return false;
  }
  return true;
}

function createRedisClient(): RedisAuditTipClient & { values: Map<string, string> } {
  return {
    values: new Map<string, string>(),
    async get(key) {
      return this.values.get(key) ?? null;
    },
    async set(key, value) {
      this.values.set(key, value);
    },
  };
}
