import { describe, test } from "bun:test";
import { type AuditRecord } from "@veritio/core";
import type { Collection, Db } from "mongodb";
import mysql, { type Pool as MySqlPool } from "mysql2/promise";
import pg, { type Pool as PgPool } from "pg";
import {
  createMariaDbAuditStore,
  createMongoAuditStore,
  createMysqlAuditStore,
  createNeonAuditStore,
  createPostgresAuditStore,
  getSqlAuditRetentionTableNames,
  MONGO_AUDIT_RECORD_INDEXES,
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
  type SqlAuditExecutor,
  type SqlAuditQueryResult,
} from "../src";
import { type AuditStoreConformanceCorruption, createAuditStoreConformanceTests } from "../src/conformance";
import { createRetentionStoreConformanceTests } from "../src/retention-conformance";

const { Pool } = pg;

type SqlDialect = "postgres" | "mysql";
type SqlStoreFactory = typeof createPostgresAuditStore;

const postgresUrl = process.env.VERITIO_POSTGRES_TEST_URL;
const neonUrl = process.env.VERITIO_NEON_TEST_URL;
const mysqlUrl = process.env.VERITIO_MYSQL_TEST_URL;
const mariaDbUrl = process.env.VERITIO_MARIADB_TEST_URL;
const mongoUrl = process.env.VERITIO_MONGODB_TEST_URL;

if (postgresUrl) {
  defineSqlLiveSuite("postgres", "postgres", postgresUrl, createPostgresAuditStore);
}

if (neonUrl) {
  defineSqlLiveSuite("neon", "postgres", neonUrl, createNeonAuditStore);
}

if (mysqlUrl) {
  defineSqlLiveSuite("mysql", "mysql", mysqlUrl, createMysqlAuditStore);
}

if (mariaDbUrl) {
  defineSqlLiveSuite("mariadb", "mysql", mariaDbUrl, createMariaDbAuditStore);
}

if (mongoUrl) {
  defineMongoLiveSuite(mongoUrl);
}

/**
 * Registers live SQL conformance tests against one ephemeral tenant-chain table.
 */
function defineSqlLiveSuite(label: string, dialect: SqlDialect, url: string, createStore: SqlStoreFactory): void {
  describe(`${label} live AuditStore conformance`, () => {
    for (const conformanceTest of createAuditStoreConformanceTests({
      name: `${label} live`,
      async createTarget() {
        const tableName = uniqueIdentifier(`veritio_${label}_audit_records`);
        const target =
          dialect === "postgres" ? await createPostgresTarget(url, tableName) : await createMySqlTarget(url, tableName);
        return {
          store: createStore({ client: target.executor, tableName }),
          /**
           * Delegates deliberate record corruption to the live database target.
           */
          mutateStoredRecord(corruption) {
            return target.mutateStoredRecord(corruption);
          },
          close: target.close,
        };
      },
    })) {
      test(conformanceTest.name, conformanceTest.run);
    }

    for (const conformanceTest of createRetentionStoreConformanceTests({
      name: `${label} live`,
      async createTarget() {
        const tableName = uniqueIdentifier(`veritio_${label}_retention_records`);
        const target =
          dialect === "postgres" ? await createPostgresTarget(url, tableName) : await createMySqlTarget(url, tableName);
        return {
          store: createStore({ client: target.executor, tableName }),
          close: target.close,
        };
      },
    })) {
      test(conformanceTest.name, conformanceTest.run);
    }
  });
}

/**
 * Creates a Postgres live target with schema setup, corruption hooks, and cleanup
 * scoped to one generated table.
 */
async function createPostgresTarget(url: string, tableName: string) {
  const pool = new Pool({ connectionString: url });
  await waitForConnection(() => pool.query("SELECT 1"));
  for (const statement of createPostgresSchemaStatements(tableName)) {
    await pool.query(statement);
  }
  const executor = createPostgresExecutor(pool);

  return {
    executor,
    async mutateStoredRecord(corruption: AuditStoreConformanceCorruption) {
      const { rows } = await pool.query(
        `SELECT record_json FROM ${quotePostgresIdentifier(tableName)} WHERE tenant_id = $1 AND sequence = $2`,
        [corruption.tenantId, corruption.sequence],
      );
      const record = JSON.parse(String(rows[0]?.record_json ?? "{}")) as AuditRecord;
      const nextRecord = corruption.mutate(record) ?? record;
      await pool.query(
        `UPDATE ${quotePostgresIdentifier(tableName)} SET record_json = $1 WHERE tenant_id = $2 AND sequence = $3`,
        [JSON.stringify(nextRecord), corruption.tenantId, corruption.sequence],
      );
    },
    async close() {
      for (const name of retentionTableNames(tableName).reverse()) {
        await pool.query(`DROP TABLE IF EXISTS ${quotePostgresIdentifier(name)}`);
      }
      await pool.end();
    },
  };
}

/**
 * Creates a MySQL or MariaDB live target with schema setup, corruption hooks, and
 * cleanup scoped to one generated table.
 */
async function createMySqlTarget(url: string, tableName: string) {
  const pool = mysql.createPool(url);
  await waitForConnection(() => pool.query("SELECT 1"));
  for (const statement of createMySqlSchemaStatements(tableName)) {
    await pool.query(statement);
  }
  const executor = createMySqlExecutor(pool);

  return {
    executor,
    async mutateStoredRecord(corruption: AuditStoreConformanceCorruption) {
      const [rows] = await pool.execute(
        `SELECT record_json FROM ${quoteMySqlIdentifier(tableName)} WHERE tenant_id = ? AND sequence = ?`,
        [corruption.tenantId, corruption.sequence],
      );
      const [row] = rows as Array<{ record_json: string }>;
      const record = JSON.parse(row?.record_json ?? "{}") as AuditRecord;
      const nextRecord = corruption.mutate(record) ?? record;
      await pool.execute(
        `UPDATE ${quoteMySqlIdentifier(tableName)} SET record_json = ? WHERE tenant_id = ? AND sequence = ?`,
        [JSON.stringify(nextRecord), corruption.tenantId, corruption.sequence],
      );
    },
    async close() {
      for (const name of retentionTableNames(tableName).reverse()) {
        await pool.query(`DROP TABLE IF EXISTS ${quoteMySqlIdentifier(name)}`);
      }
      await pool.end();
    },
  };
}

/**
 * Adapts a pg pool to the SqlAuditExecutor contract with explicit transactions.
 */
function createPostgresExecutor(pool: PgPool): SqlAuditExecutor {
  return {
    /**
     * Executes a single Postgres statement through the shared pool.
     */
    execute(statement, params) {
      return pool.query(statement, [...params]);
    },
    async transaction(run) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await run({
          /**
           * Executes a Postgres statement inside the open transaction.
           */
          execute(statement, params) {
            return client.query(statement, [...params]);
          },
        });
        await client.query("COMMIT");
        return result;
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    },
  };
}

/**
 * Adapts a mysql2 pool to the SqlAuditExecutor contract with explicit
 * connection-scoped transactions.
 */
function createMySqlExecutor(pool: MySqlPool): SqlAuditExecutor {
  return {
    async execute(statement, params) {
      const [rows] = await pool.execute(statement, [...params]);
      return normalizeMySqlRows(rows);
    },
    async transaction(run) {
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        const result = await run({
          async execute(statement, params) {
            const [rows] = await connection.execute(statement, [...params]);
            return normalizeMySqlRows(rows);
          },
        });
        await connection.commit();
        return result;
      } catch (error) {
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
    },
  };
}

/**
 * Registers live Mongo conformance tests against one ephemeral collection.
 */
function defineMongoLiveSuite(url: string): void {
  describe("mongodb live AuditStore conformance", () => {
    for (const conformanceTest of createAuditStoreConformanceTests({
      name: "mongodb live",
      async createTarget() {
        // Import the driver lazily so this suite (and the whole file) does not
        // load `mongodb`/`bson` unless a live Mongo URL is configured. Some
        // bson builds call `node:v8` APIs that are unimplemented under Bun, so
        // an eager top-level import would crash the file on Bun even when the
        // Mongo conformance suite is not selected.
        const { MongoClient } = await import("mongodb");
        const collectionName = uniqueIdentifier("veritio_mongo_audit_records");
        const client = new MongoClient(url);
        await client.connect();
        const collection = client.db().collection<MongoAuditDocument>(collectionName);
        const retention = await createMongoRetentionCollections(client.db(), collectionName);
        for (const index of MONGO_AUDIT_RECORD_INDEXES) {
          await collection.createIndex(index.keys, index.options);
        }

        return {
          store: createMongoAuditStore({
            collection: collection as unknown as MongoAuditCollection,
            retention,
            transaction: async (run) =>
              client.withSession((session) =>
                session.withTransaction(async () =>
                  run({
                    collection: collection as unknown as MongoAuditCollection,
                    options: { session },
                  }),
                ),
              ),
          }),
          async mutateStoredRecord(corruption) {
            await mutateMongoStoredRecord(collection, corruption);
          },
          async close() {
            await collection.drop().catch(ignoreNamespaceMissing);
            await dropMongoRetentionCollections(retention);
            await client.close();
          },
        };
      },
    })) {
      test(conformanceTest.name, conformanceTest.run);
    }

    for (const conformanceTest of createRetentionStoreConformanceTests({
      name: "mongodb live",
      async createTarget() {
        const { MongoClient } = await import("mongodb");
        const collectionName = uniqueIdentifier("veritio_mongo_retention_records");
        const client = new MongoClient(url);
        await client.connect();
        const collection = client.db().collection<MongoAuditDocument>(collectionName);
        const retention = await createMongoRetentionCollections(client.db(), collectionName);
        for (const index of MONGO_AUDIT_RECORD_INDEXES) {
          await collection.createIndex(index.keys, index.options);
        }
        return {
          store: createMongoAuditStore({
            collection: collection as unknown as MongoAuditCollection,
            retention,
            transaction: async (run) =>
              client.withSession((session) =>
                session.withTransaction(async () =>
                  run({ collection: collection as unknown as MongoAuditCollection, options: { session } }),
                ),
              ),
          }),
          async close() {
            await collection.drop().catch(ignoreNamespaceMissing);
            await dropMongoRetentionCollections(retention);
            await client.close();
          },
        };
      },
    })) {
      test(conformanceTest.name, conformanceTest.run);
    }
  });
}

/**
 * Mutates stored Mongo record JSON to prove the adapter fails closed on
 * integrity corruption.
 */
async function mutateMongoStoredRecord(
  collection: Collection<MongoAuditDocument>,
  corruption: AuditStoreConformanceCorruption,
): Promise<void> {
  const document = await collection.findOne({
    tenantId: corruption.tenantId,
    sequence: corruption.sequence,
  });
  const record = JSON.parse(document?.recordJson ?? "{}") as AuditRecord;
  const nextRecord = corruption.mutate(record) ?? record;
  await collection.updateOne(
    { tenantId: corruption.tenantId, sequence: corruption.sequence },
    { $set: { recordJson: JSON.stringify(nextRecord) } },
  );
}

/**
 * Builds the Postgres schema used only by live conformance tests.
 */
function createPostgresSchemaStatements(tableName: string): string[] {
  const table = quotePostgresIdentifier(tableName);
  const [, chainState, idempotency, checkpoints, attempts, dispositions] =
    retentionTableNames(tableName).map(quotePostgresIdentifier);
  return [
    `CREATE TABLE IF NOT EXISTS ${table} (
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
  )`,
    `CREATE TABLE IF NOT EXISTS ${chainState} (
    tenant_id text PRIMARY KEY,
    authoritative_tip_sequence bigint NOT NULL,
    authoritative_tip_hash char(64),
    minimum_retained_sequence bigint NOT NULL,
    latest_checkpoint_hash char(64),
    retention_policy_fence bigint NOT NULL
  )`,
    `CREATE TABLE IF NOT EXISTS ${idempotency} (
    tenant_id text NOT NULL,
    idempotency_key_hash char(64) NOT NULL,
    event_canonical_hash char(64) NOT NULL,
    original_sequence bigint NOT NULL,
    original_record_hash char(64) NOT NULL,
    record_json text,
    PRIMARY KEY (tenant_id, idempotency_key_hash)
  )`,
    `CREATE TABLE IF NOT EXISTS ${checkpoints} (
    tenant_id text NOT NULL,
    epoch bigint NOT NULL,
    checkpoint_hash char(64) NOT NULL,
    checkpoint_canonical text NOT NULL,
    PRIMARY KEY (tenant_id, epoch),
    UNIQUE (tenant_id, checkpoint_hash)
  )`,
    `CREATE TABLE IF NOT EXISTS ${attempts} (
    tenant_id text NOT NULL,
    checkpoint_hash char(64) NOT NULL,
    attempt_id varchar(128) NOT NULL,
    policy_fence bigint NOT NULL,
    status varchar(16) NOT NULL,
    attempt_canonical text NOT NULL,
    PRIMARY KEY (tenant_id, checkpoint_hash)
  )`,
    `CREATE TABLE IF NOT EXISTS ${dispositions} (
    tenant_id text NOT NULL,
    checkpoint_hash char(64) NOT NULL,
    disposition_canonical text NOT NULL,
    PRIMARY KEY (tenant_id, checkpoint_hash)
  )`,
  ];
}

/**
 * Builds the MySQL/MariaDB schema used only by live conformance tests.
 */
function createMySqlSchemaStatements(tableName: string): string[] {
  const table = quoteMySqlIdentifier(tableName);
  const [, chainState, idempotency, checkpoints, attempts, dispositions] =
    retentionTableNames(tableName).map(quoteMySqlIdentifier);
  return [
    `CREATE TABLE IF NOT EXISTS ${table} (
    tenant_id varchar(255) NOT NULL,
    sequence bigint NOT NULL,
    idempotency_key_hash char(64) NOT NULL,
    event_canonical longtext NOT NULL,
    record_json longtext NOT NULL,
    hash char(64) NOT NULL,
    previous_hash char(64),
    appended_at varchar(40) NOT NULL,
    PRIMARY KEY (tenant_id, sequence),
    UNIQUE KEY veritio_idempotency_unique (tenant_id, idempotency_key_hash),
    KEY veritio_tenant_sequence_idx (tenant_id, sequence)
  )`,
    `CREATE TABLE IF NOT EXISTS ${chainState} (
    tenant_id varchar(255) NOT NULL,
    authoritative_tip_sequence bigint NOT NULL,
    authoritative_tip_hash char(64),
    minimum_retained_sequence bigint NOT NULL,
    latest_checkpoint_hash char(64),
    retention_policy_fence bigint NOT NULL,
    PRIMARY KEY (tenant_id)
  )`,
    `CREATE TABLE IF NOT EXISTS ${idempotency} (
    tenant_id varchar(255) NOT NULL,
    idempotency_key_hash char(64) NOT NULL,
    event_canonical_hash char(64) NOT NULL,
    original_sequence bigint NOT NULL,
    original_record_hash char(64) NOT NULL,
    record_json longtext,
    PRIMARY KEY (tenant_id, idempotency_key_hash)
  )`,
    `CREATE TABLE IF NOT EXISTS ${checkpoints} (
    tenant_id varchar(255) NOT NULL,
    epoch bigint NOT NULL,
    checkpoint_hash char(64) NOT NULL,
    checkpoint_canonical longtext NOT NULL,
    PRIMARY KEY (tenant_id, epoch),
    UNIQUE KEY veritio_checkpoint_hash_unique (tenant_id, checkpoint_hash)
  )`,
    `CREATE TABLE IF NOT EXISTS ${attempts} (
    tenant_id varchar(255) NOT NULL,
    checkpoint_hash char(64) NOT NULL,
    attempt_id varchar(128) NOT NULL,
    policy_fence bigint NOT NULL,
    status varchar(16) NOT NULL,
    attempt_canonical longtext NOT NULL,
    PRIMARY KEY (tenant_id, checkpoint_hash)
  )`,
    `CREATE TABLE IF NOT EXISTS ${dispositions} (
    tenant_id varchar(255) NOT NULL,
    checkpoint_hash char(64) NOT NULL,
    disposition_canonical longtext NOT NULL,
    PRIMARY KEY (tenant_id, checkpoint_hash)
  )`,
  ];
}

/** Derives the records table plus every additive retention companion table. */
function retentionTableNames(tableName: string): string[] {
  const names = getSqlAuditRetentionTableNames(tableName);
  return [
    names.records,
    names.chainState,
    names.idempotencyLedger,
    names.checkpoints,
    names.dispositionAttempts,
    names.dispositions,
  ];
}

/** Creates and indexes the five explicit Mongo companion collections for one live target. */
async function createMongoRetentionCollections(db: Db, prefix: string): Promise<MongoRetentionCollections> {
  const chainStates = db.collection<MongoAuditChainStateDocument>(`${prefix}_chain_state`);
  const idempotencyLedger = db.collection<MongoIdempotencyLedgerDocument>(`${prefix}_idempotency`);
  const checkpoints = db.collection<MongoCheckpointDocument>(`${prefix}_checkpoints`);
  const dispositionAttempts = db.collection<MongoDispositionAttemptDocument>(`${prefix}_disposition_attempts`);
  const dispositions = db.collection<MongoDispositionDocument>(`${prefix}_dispositions`);
  const collections = { chainStates, idempotencyLedger, checkpoints, dispositionAttempts, dispositions };
  for (const [key, indexes] of Object.entries(MONGO_RETENTION_INDEXES)) {
    const collection = collections[key as keyof typeof collections];
    for (const index of indexes) await collection.createIndex(index.keys, index.options);
  }
  return collections as unknown as MongoRetentionCollections;
}

/** Drops only the live suite's generated Mongo companion collections. */
async function dropMongoRetentionCollections(collections: MongoRetentionCollections): Promise<void> {
  for (const collection of Object.values(collections)) {
    await (collection as unknown as Collection).drop().catch(ignoreNamespaceMissing);
  }
}

/**
 * Normalizes mysql2 result tuples into the row shape expected by storage tests.
 */
function normalizeMySqlRows(rows: unknown): SqlAuditQueryResult {
  return Array.isArray(rows) ? (rows as readonly Record<string, unknown>[]) : [];
}

/**
 * Retries initial database connectivity so container startup delay does not make
 * live tests flaky.
 */
async function waitForConnection(run: () => Promise<unknown>): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      await run();
      return;
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
  }
  throw lastError;
}

/**
 * Generates an isolated SQL table or Mongo collection name for one test target.
 */
function uniqueIdentifier(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.floor(Math.random() * 1_000_000)}`;
}

/**
 * Quotes a validated Postgres identifier for live-test SQL.
 */
function quotePostgresIdentifier(identifier: string): string {
  assertIdentifier(identifier);
  return `"${identifier}"`;
}

/**
 * Quotes a validated MySQL identifier for live-test SQL.
 */
function quoteMySqlIdentifier(identifier: string): string {
  assertIdentifier(identifier);
  return `\`${identifier}\``;
}

/**
 * Rejects unsafe SQL identifier text before quote helpers interpolate it.
 */
function assertIdentifier(identifier: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(identifier)) {
    throw new TypeError("identifier must be a SQL identifier");
  }
}

/**
 * Ignores Mongo cleanup races where the ephemeral collection was already absent.
 */
function ignoreNamespaceMissing(error: unknown): void {
  if (typeof error === "object" && error !== null && "codeName" in error && error.codeName === "NamespaceNotFound") {
    return;
  }
  throw error;
}
