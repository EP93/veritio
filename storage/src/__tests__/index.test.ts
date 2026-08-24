import { describe, expect, test } from "bun:test";
import { type AuditRecord, createAuditEvent, MemoryAuditStore } from "@veritio/core";
import { type AuditStoreConformanceCorruption, createAuditStoreConformanceTests } from "../conformance";
import {
  createMariaDbAuditStore,
  createMongoAuditStore,
  createMysqlAuditStore,
  createNeonAuditStore,
  createPostgresAuditStore,
  createRedisAuditTipCache,
  MONGO_RETENTION_INDEXES,
  type MongoAuditChainStateDocument,
  type MongoAuditCollection,
  type MongoAuditDocument,
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

  test("SQL companion identifiers remain within the PostgreSQL and MariaDB identifier ceiling", async () => {
    const client = createSqlClient();
    const store = createMariaDbAuditStore({
      client,
      tableName: "veritio_mariadb_retention_records_1787565429246_185537",
    });
    await store.append(makeEvent("evt_01", "org_123", { role: "viewer" }));
    await store.listCheckpoints({ tenantId: "org_123" });

    const identifiers = client.statements.flatMap((statement) =>
      [...statement.matchAll(/`([^`]+)`/g)].map((match) => match[1]!),
    );
    expect(identifiers.length).toBeGreaterThan(0);
    expect(identifiers.every((identifier) => identifier.length <= 63)).toBe(true);
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
      if (sql.startsWith("select checkpoint_canonical") && sql.includes("_checkpoints")) {
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
      if (sql.startsWith("select disposition_canonical") && sql.includes("_receipts")) {
        const [tenantId, checkpointHash] = params;
        return client.dispositions.filter(
          (row) => row.tenant_id === tenantId && row.checkpoint_hash === checkpointHash,
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
>(): MongoRetentionCollection<TDocument> {
  const documents: TDocument[] = [];
  return {
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
  const sequence = filter.sequence as { $gt?: number } | undefined;
  if (sequence?.$gt !== undefined && document.sequence <= sequence.$gt) {
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
