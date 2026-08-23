import { expect, test } from "bun:test";
import mysql, { type Pool as MySqlPool } from "mysql2/promise";
import pg, { type Pool as PgPool } from "pg";
import {
  createHttpIngestTarget,
  createHttpOutboxDispatcher,
  createMysqlOutboxAdapter,
  createPostgresOutboxAdapter,
  MYSQL_OUTBOX_SCHEMA_SQL,
  type OutboxAdapter,
  type OutboxDispatchResult,
  POSTGRES_OUTBOX_SCHEMA_SQL,
  type SqlOutboxExecutor,
  type SqlOutboxQueryResult,
} from "../src";

const { Pool } = pg;
const ROWS = 100;
const WORKERS = 20;

if (process.env.VERITIO_POSTGRES_TEST_URL) {
  test("postgres live outbox leases deliver 100 rows exactly once across 20 workers", async () => {
    const table = identifier("veritio_outbox_pg_stress");
    const pool = new Pool({ connectionString: process.env.VERITIO_POSTGRES_TEST_URL });
    try {
      await pool.query(POSTGRES_OUTBOX_SCHEMA_SQL.replaceAll("veritio_outbox_entries", table));
      await runLeaseStress(createPostgresOutboxAdapter({ client: postgresExecutor(pool), tableName: table }));
    } finally {
      await pool.query(`DROP TABLE IF EXISTS "${table}"`);
      await pool.end();
    }
  }, 60_000);
}

if (process.env.VERITIO_MYSQL_TEST_URL) {
  test("mysql live outbox leases deliver 100 rows exactly once across 20 workers", async () => {
    const table = identifier("veritio_outbox_mysql_stress");
    const pool = mysql.createPool(process.env.VERITIO_MYSQL_TEST_URL);
    try {
      for (const statement of MYSQL_OUTBOX_SCHEMA_SQL.replaceAll("veritio_outbox_entries", table).split(";")) {
        if (statement.trim()) await pool.query(statement);
      }
      await runLeaseStress(createMysqlOutboxAdapter({ client: mysqlExecutor(pool), tableName: table }));
    } finally {
      await pool.query(`DROP TABLE IF EXISTS \`${table}\``);
      await pool.end();
    }
  }, 60_000);
}

/** Exercises real row-lock semantics through independent dispatcher passes. */
async function runLeaseStress(adapter: OutboxAdapter): Promise<void> {
  await adapter.transaction(async (tx) => {
    for (let index = 0; index < ROWS; index += 1) {
      await tx.enqueue({ id: `entry_${index}`, tenantId: "tenant_live_stress", payload: payload(index) });
    }
  });
  const received = new Map<string, number>();
  let inFlight = 0;
  let maxInFlight = 0;
  const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { events: Array<{ id: string }> };
    const id = body.events[0]!.id;
    received.set(id, (received.get(id) ?? 0) + 1);
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    try {
      await Bun.sleep(1);
      return Response.json({ appended: { events: 1, edges: 0 } });
    } finally {
      inFlight -= 1;
    }
  }) as typeof fetch;
  const target = createHttpIngestTarget({ baseUrl: "http://127.0.0.1", key: "vrt_live", fetchImpl });
  const results: OutboxDispatchResult[] = [];
  for (let round = 0; round < 20 && results.reduce((sum, result) => sum + result.dispatched, 0) < ROWS; round += 1) {
    const roundResults = await Promise.all(
      Array.from({ length: WORKERS }, (_, worker) =>
        createHttpOutboxDispatcher({ adapter, target }).dispatchBatch({
          tenantId: "tenant_live_stress",
          permit: {
            kind: "operator",
            approvalId: `live_${round}_${worker}`,
            maxEntries: 10,
            maxBytes: 1024 * 1024,
            maxElapsedMs: 30_000,
            leaseMs: 60_000,
          },
        }),
      ),
    );
    results.push(...roundResults);
  }
  expect(results.reduce((sum, result) => sum + result.dispatched, 0)).toBe(ROWS);
  expect(received.size).toBe(ROWS);
  expect([...received.values()].every((count) => count === 1)).toBe(true);
  expect(maxInFlight).toBe(1);
}

/** Adapts pg pool calls to the injected SQL outbox contract. */
function postgresExecutor(pool: PgPool): SqlOutboxExecutor {
  return {
    execute: (statement, params) => pool.query(statement, [...params]),
    async transaction(run) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await run({ execute: (statement, params) => client.query(statement, [...params]) });
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

/** Adapts mysql2 pool calls to the injected SQL outbox contract. */
function mysqlExecutor(pool: MySqlPool): SqlOutboxExecutor {
  const execute = async (statement: string, params: readonly unknown[]): Promise<SqlOutboxQueryResult> => {
    const [rows] = await pool.execute(statement, [...params]);
    return Array.isArray(rows) ? (rows as Record<string, unknown>[]) : [];
  };
  return {
    execute,
    async transaction(run) {
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        const result = await run({
          async execute(statement, params) {
            const [rows] = await connection.execute(statement, [...params]);
            return Array.isArray(rows) ? (rows as Record<string, unknown>[]) : [];
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

/** Produces a collision-free validated SQL identifier for one test run. */
function identifier(prefix: string): string {
  return `${prefix}_${process.pid}_${Date.now()}`;
}

/** Builds one minimal tenant-scoped outbox payload. */
function payload(index: number) {
  return {
    schemaVersion: "2026-06-23" as const,
    mutationBinding: "best_effort" as const,
    records: [
      {
        id: `evt_${index}`,
        actor: { type: "service", id: "live-stress" },
        action: "stress.delivery",
        target: { type: "entry", id: `target_${index}` },
        scope: { tenantId: "tenant_live_stress" },
        metadata: {},
      },
    ],
    edges: [],
  };
}
