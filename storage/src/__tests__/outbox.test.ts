import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { type AuditEventInput, createGovernedChangeDraft, defineEntity, type EvidenceEdgeInput } from "@veritio/core";
import { createFileEvidenceStore, type FileEvidenceStore } from "../file-store";
import { DEFAULT_DELIVERY_SAFETY_POLICY } from "../delivery-safety";
import {
  createFileOutboxAdapter,
  createOutboxDispatcher,
  createPostgresOutboxAdapter,
  createRollingWindowLedger,
  dispatchOutboxEntry,
  MYSQL_OUTBOX_SCHEMA_SQL,
  type OutboxEvidenceTarget,
  outboxPayloadByteLength,
  OutboxQueueFullError,
  type OutboxStoredEntry,
  POSTGRES_OUTBOX_SCHEMA_SQL,
  type SqlOutboxExecutor,
  type SqlOutboxRow,
} from "../outbox";

const TENANT = "tenant_outbox";
const PERMIT = {
  kind: "operator" as const,
  approvalId: "outbox-tests",
  maxEntries: 10,
  maxBytes: 1024 * 1024,
  maxElapsedMs: 5_000,
  leaseMs: 30_000,
};

describe("transactional evidence outbox", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "veritio-outbox-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  test("rolled-back host transactions emit no outbox rows or evidence records", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    const evidence = createFileEvidenceStore(join(dir, "evidence"));
    const draft = makeDraft("rollback");

    await expect(
      adapter.transaction(async (tx) => {
        await tx.enqueue({
          id: "outbox_rollback",
          tenantId: TENANT,
          payload: draft.outboxEntry,
        });
        throw new Error("host mutation rolled back");
      }),
    ).rejects.toThrow("host mutation rolled back");

    const dispatcher = createOutboxDispatcher({ adapter, target: evidence });
    expect(await adapter.list({ tenantId: TENANT })).toEqual([]);
    expect(await dispatcher.dispatchBatch({ tenantId: TENANT, permit: PERMIT })).toEqual({
      dispatched: 0,
      retried: 0,
      paused: 0,
      rejected: 0,
      bytes: 0,
    });
    expect(await evidence.listEvents()).toEqual([]);
    expect(await evidence.listEdges()).toEqual([]);
  });

  test("retrying a partially delivered outbox entry is idempotent", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    const evidence = createFileEvidenceStore(join(dir, "evidence"));
    const draft = makeDraft("retry");
    const flakyTarget = failOnceAfterSecondEvent(evidence);

    await adapter.transaction(async (tx) => {
      await tx.enqueue({
        id: "outbox_retry",
        tenantId: TENANT,
        payload: draft.outboxEntry,
      });
    });

    const firstAttempt = createOutboxDispatcher({ adapter, target: flakyTarget });
    expect((await firstAttempt.dispatchBatch({ tenantId: TENANT, permit: PERMIT })).retried).toBe(1);
    expect(await evidence.listEvents()).toHaveLength(2);
    expect(await evidence.listEdges()).toHaveLength(0);

    const retry = createOutboxDispatcher({ adapter, target: evidence });
    expect((await retry.dispatchBatch({ tenantId: TENANT, permit: PERMIT })).dispatched).toBe(1);
    expect((await retry.dispatchBatch({ tenantId: TENANT, permit: PERMIT })).dispatched).toBe(0);

    expect(await evidence.listEvents()).toHaveLength(draft.events.length);
    expect(await evidence.listEdges()).toHaveLength(draft.edges.length);
    expect((await adapter.list({ tenantId: TENANT }))[0]).toMatchObject({
      id: "outbox_retry",
      tenantId: TENANT,
      status: "dispatched",
      attempts: 1,
    });
  });

  test("direct duplicate delivery does not create duplicate revisions or changes", async () => {
    const evidence = createFileEvidenceStore(join(dir, "evidence"));
    const draft = makeDraft("duplicate");

    await dispatchOutboxEntry(draft.outboxEntry, evidence);
    await dispatchOutboxEntry(draft.outboxEntry, evidence);

    const events = await evidence.listEvents();
    const edges = await evidence.listEdges();
    expect(events).toHaveLength(draft.events.length);
    expect(edges).toHaveLength(draft.edges.length);
    expect(events.map((record) => record.event.action).sort()).toEqual([
      "activity.recorded",
      "change.declared",
      "entity.revision.created",
    ]);
  });

  test("rejects payloads that do not match the outbox tenant scope", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    const draft = makeDraft("tenant-mismatch");
    draft.outboxEntry.records[0]!.scope = { tenantId: "other_tenant" };

    await expect(
      adapter.transaction(async (tx) => {
        await tx.enqueue({
          id: "outbox_bad_tenant",
          tenantId: TENANT,
          payload: draft.outboxEntry,
        });
      }),
    ).rejects.toThrow("outbox payload tenant mismatch");
  });

  test("markFailed dead-letters a non-retryable failure, bounds lastError, and survives reload", async () => {
    const path = join(dir, "outbox");
    const adapter = createFileOutboxAdapter(path);
    await adapter.transaction(async (tx) => {
      await tx.enqueue({ id: "outbox_dead", tenantId: TENANT, payload: makeDraft(TENANT).outboxEntry });
    });
    const [before] = await adapter.list({ tenantId: TENANT });

    const longError = new Error(`boom ${"x".repeat(400)}\n\twith   verbose   detail`);
    const dead = await adapter.markFailed("outbox_dead", longError, { retryable: false });

    expect(dead.status).toBe("dead");
    expect(dead.attempts).toBe(1);
    expect(dead.availableAt).toBe(before!.availableAt); // non-retryable does NOT re-arm availableAt
    expect(dead.lastError!.length).toBeLessThanOrEqual(256); // F: bounded
    expect(dead.lastError).toContain("Error:"); // name-prefixed summary
    expect(dead.lastError).not.toContain("\n"); // whitespace collapsed, no raw multi-line text
    expect(await adapter.listDispatchable({ tenantId: TENANT })).toHaveLength(0); // dead is not dispatchable

    // The dead row round-trips through a reload (validateStoredEntry accepts it).
    const reopened = createFileOutboxAdapter(path);
    expect((await reopened.list({ tenantId: TENANT }))[0]).toMatchObject({ status: "dead", attempts: 1 });

    // A retryable failure (default/explicit) still lands on pending and re-arms.
    await adapter.transaction(async (tx) => {
      await tx.enqueue({ id: "outbox_retry", tenantId: TENANT, payload: makeDraft(TENANT).outboxEntry });
    });
    const pending = await adapter.markFailed("outbox_retry", new Error("transient"), { retryable: true });
    expect(pending.status).toBe("pending");
  });

  test("SQL outbox adapter commits, rolls back, and dispatches through host transactions", async () => {
    const client = createSqlOutboxClient();
    const adapter = createPostgresOutboxAdapter({ client });
    const evidence = createFileEvidenceStore(join(dir, "evidence"));
    const draft = makeDraft("sql");

    await adapter
      .transaction(async (tx) => {
        await tx.enqueue({
          id: "outbox_sql_rollback",
          tenantId: TENANT,
          payload: draft.outboxEntry,
        });
        throw new Error("rollback sql outbox");
      })
      .catch(() => {});

    expect(await adapter.list({ tenantId: TENANT })).toEqual([]);

    await adapter.transaction(async (tx) => {
      await tx.enqueue({
        id: "outbox_sql_commit",
        tenantId: TENANT,
        payload: draft.outboxEntry,
      });
    });

    const dispatcher = createOutboxDispatcher({ adapter, target: evidence });
    const dispatchStatementIndex = client.statements.length;
    expect((await dispatcher.dispatchBatch({ tenantId: TENANT, permit: PERMIT })).dispatched).toBe(1);
    const dispatchStatements = client.statements.slice(dispatchStatementIndex).map(({ statement }) => statement);
    expect(dispatchStatements.find((statement) => statement.includes("SKIP LOCKED"))).toContain("NOT EXISTS");
    expect(
      dispatchStatements.find((statement) => statement.startsWith("SELECT") && statement.includes("WHERE id")),
    ).toContain("FOR UPDATE");
    expect(
      dispatchStatements.some(
        (statement) =>
          statement.startsWith("SELECT payload_canonical") &&
          statement.includes("WHERE tenant_id") &&
          !statement.includes("status") &&
          !statement.includes("WHERE id"),
      ),
    ).toBe(false);
    expect(await evidence.listEvents()).toHaveLength(draft.events.length);
    expect(await evidence.listEdges()).toHaveLength(draft.edges.length);
    expect((await adapter.list({ tenantId: TENANT }))[0]).toMatchObject({
      id: "outbox_sql_commit",
      status: "dispatched",
    });
  });

  test("SQL schemas index tenant claims and the stable lease guard", () => {
    for (const schema of [POSTGRES_OUTBOX_SCHEMA_SQL, MYSQL_OUTBOX_SCHEMA_SQL]) {
      expect(schema).toContain("veritio_outbox_tenant_claim_idx");
      expect(schema).toContain("veritio_outbox_tenant_guard_idx");
    }
  });

  test("file and SQL claims leave future pending work unavailable", async () => {
    const adapters = [
      createFileOutboxAdapter(join(dir, "future-outbox")),
      createPostgresOutboxAdapter({ client: createSqlOutboxClient() }),
    ];
    for (const adapter of adapters) {
      await adapter.transaction(async (tx) => {
        await tx.enqueue({
          id: "outbox_due",
          tenantId: TENANT,
          payload: makeDraft("due").outboxEntry,
          availableAt: "2026-08-01T00:00:00.000Z",
        });
        await tx.enqueue({
          id: "outbox_future",
          tenantId: TENANT,
          payload: makeDraft("future").outboxEntry,
          availableAt: "2026-08-03T00:00:00.000Z",
        });
      });
      const claimed = await adapter.claimDispatchable({
        tenantId: TENANT,
        now: "2026-08-02T00:00:00.000Z",
        leaseId: "lease_due_only",
        leaseMs: 1_000,
        limit: 10,
        maxPayloadBytes: 10 * 1024 * 1024,
      });
      expect(claimed.map((entry) => entry.id)).toEqual(["outbox_due"]);
    }
  });

  test("file and SQL pause barriers require exact circuit acknowledgement", async () => {
    const adapters = [
      createFileOutboxAdapter(join(dir, "paused-outbox")),
      createPostgresOutboxAdapter({ client: createSqlOutboxClient() }),
    ];
    for (const adapter of adapters) {
      await adapter.transaction(async (tx) => {
        await tx.enqueue({ id: "outbox_hold", tenantId: TENANT, payload: makeDraft("hold").outboxEntry });
        await tx.enqueue({ id: "outbox_waiting", tenantId: TENANT, payload: makeDraft("waiting").outboxEntry });
      });
      const [held] = await adapter.claimDispatchable({
        tenantId: TENANT,
        leaseId: "lease_hold",
        leaseMs: 60_000,
        limit: 1,
        maxPayloadBytes: 10 * 1024 * 1024,
      });
      await adapter.markFailed(held!.id, new Error("economic hold"), {
        leaseId: held!.leaseId,
        disposition: "pause",
        circuitId: "circuit_current",
      });
      expect(
        await adapter.claimDispatchable({
          tenantId: TENANT,
          leaseId: "lease_blocked",
          leaseMs: 60_000,
          limit: 1,
          maxPayloadBytes: 10 * 1024 * 1024,
        }),
      ).toHaveLength(0);
      await expect(
        adapter.resumePaused({ tenantId: TENANT, expectedCircuitId: "circuit_stale", limit: 1 }),
      ).rejects.toThrow("circuit");
      expect(await adapter.resumePaused({ tenantId: TENANT, expectedCircuitId: "circuit_current", limit: 1 })).toBe(1);
      const [heldAgain] = await adapter.claimDispatchable({
        tenantId: TENANT,
        leaseId: "lease_generated_circuit",
        leaseMs: 60_000,
        limit: 1,
        maxPayloadBytes: 10 * 1024 * 1024,
      });
      await adapter.markFailed(heldAgain!.id, new Error("economic hold without upstream id"), {
        leaseId: heldAgain!.leaseId,
        disposition: "pause",
      });
      const generatedCircuit = (await adapter.list({ tenantId: TENANT })).find(
        (entry) => entry.status === "paused",
      )!.circuitId;
      expect(generatedCircuit).toMatch(/^local_[A-Za-z0-9-]+$/);
      expect(await adapter.resumePaused({ tenantId: TENANT, expectedCircuitId: generatedCircuit!, limit: 1 })).toBe(1);
    }
  });

  test("expired leases recover and stale workers cannot settle the reclaimed row", async () => {
    const adapter = createFileOutboxAdapter(join(dir, "outbox"));
    await adapter.transaction((tx) =>
      tx.enqueue({
        id: "outbox_lease",
        tenantId: TENANT,
        payload: makeDraft("lease").outboxEntry,
        availableAt: "2026-08-01T00:00:00.000Z",
      }),
    );
    const first = await adapter.claimDispatchable({
      tenantId: TENANT,
      now: "2026-08-02T00:00:00.000Z",
      leaseId: "lease_old",
      leaseMs: 1_000,
      limit: 1,
      maxPayloadBytes: 10 * 1024 * 1024,
    });
    expect(first).toHaveLength(1);
    expect(first[0]).toMatchObject({ status: "leased", leaseId: "lease_old" });
    expect(
      await adapter.claimDispatchable({
        tenantId: TENANT,
        now: "2026-08-02T00:00:00.500Z",
        leaseId: "lease_early",
        leaseMs: 1_000,
        limit: 1,
        maxPayloadBytes: 10 * 1024 * 1024,
      }),
    ).toHaveLength(0);
    const reclaimed = await adapter.claimDispatchable({
      tenantId: TENANT,
      now: "2026-08-02T00:00:01.001Z",
      leaseId: "lease_new",
      leaseMs: 1_000,
      limit: 1,
      maxPayloadBytes: 10 * 1024 * 1024,
    });
    expect(reclaimed[0]).toMatchObject({ leaseId: "lease_new" });
    await expect(adapter.markDispatched("outbox_lease", { leaseId: "lease_old" })).rejects.toThrow("lease");
    expect((await adapter.markDispatched("outbox_lease", { leaseId: "lease_new" })).status).toBe("dispatched");
  });
});

/**
 * Creates a governed-change draft whose minimized outbox payload contains no raw
 * customer email, giving the outbox tests a realistic revision payload.
 */
function makeDraft(suffix: string) {
  const entity = defineEntity<{
    id: string;
    amount: number;
    customerEmail: string;
  }>({
    authority: "example.billing",
    type: "invoice",
    schemaRef: "example.billing.invoice.v1",
    fieldSetRef: "example.billing.invoice.public.v1",
    identity: (row) => row.id,
    fields: {
      amount: { capture: "content_digest" },
      customerEmail: { capture: "keyed_digest" },
    },
  });

  return createGovernedChangeDraft({
    scope: { tenantId: TENANT, environment: "test" },
    entity,
    before: { id: `inv_${suffix}`, amount: 1200, customerEmail: "buyer@example.com" },
    after: { id: `inv_${suffix}`, amount: 1480, customerEmail: "buyer@example.com" },
    changedPaths: ["/amount"],
    change: {
      id: `change_${suffix}`,
      type: "invoice.adjusted",
      initiatedBy: { authority: "example.auth", kind: "principal", type: "user", id: "usr_123" },
    },
    activity: {
      id: `activity_${suffix}`,
      type: "invoice.adjustment",
      performedBy: { authority: "example.auth", kind: "principal", type: "user", id: "usr_123" },
    },
    producer: { authority: "example.billing", kind: "principal", type: "service", id: "billing-api" },
    occurredAt: "2026-06-23T10:00:00.000Z",
    idempotencyKeyHash: `sha256:${suffix}`,
    mutationBinding: "same_transaction",
    digestKeys: {
      keyedDigest: {
        keyVersion: "tenant-key-1",
        secret: "test-secret",
      },
    },
  });
}

/**
 * Simulates a dispatcher crash after the second event append. Retrying the same
 * outbox entry must rely on event IDs to replay safely without duplicate changes.
 */
function failOnceAfterSecondEvent(store: FileEvidenceStore): OutboxEvidenceTarget {
  let events = 0;
  let failed = false;
  return {
    async recordEvent(input: AuditEventInput) {
      const record = await store.recordEvent(input);
      events += 1;
      if (!failed && events === 2) {
        failed = true;
        throw new Error("dispatcher crashed after partial append");
      }
      return record;
    },
    async recordEdge(input: EvidenceEdgeInput) {
      return store.recordEdge(input);
    },
  };
}

/**
 * Provides an in-memory SQL executor that exercises the public SQL outbox
 * contract without requiring credentials in unit tests.
 */
function createSqlOutboxClient(): SqlOutboxExecutor & {
  rows: SqlOutboxRow[];
  statements: Array<{ statement: string; params: readonly unknown[] }>;
} {
  const client: SqlOutboxExecutor & {
    rows: SqlOutboxRow[];
    statements: Array<{ statement: string; params: readonly unknown[] }>;
  } = {
    rows: [],
    statements: [],
    async transaction(run) {
      const snapshot = client.rows.map((row) => ({ ...row }));
      try {
        return await run(client);
      } catch (error) {
        client.rows = snapshot;
        throw error;
      }
    },
    async execute(statement, params) {
      const sql = statement.toLowerCase();
      client.statements.push({ statement, params });
      if (sql.startsWith("select id") && sql.includes("where tenant_id") && sql.endsWith("for update")) {
        const [tenantId] = params;
        return client.rows
          .filter((row) => row.tenant_id === tenantId)
          .sort((left, right) => left.id.localeCompare(right.id))
          .slice(0, 1);
      }
      if (sql.startsWith("select payload_canonical") && sql.includes("where id")) {
        const [id] = params;
        return client.rows.filter((row) => row.id === id);
      }
      if (sql.includes("where tenant_id") && sql.includes("status") && sql.endsWith("for update")) {
        const [tenantId, status] = params;
        return client.rows.filter((row) => row.tenant_id === tenantId && row.status === status);
      }
      if (sql.includes("for update skip locked")) {
        const tenantScoped = sql.includes("candidate.tenant_id =");
        const [pendingStatus, leasedStatus, now] = params;
        const tenantId = tenantScoped ? params[6] : undefined;
        const limit = params[tenantScoped ? 7 : 6];
        return limitRows(
          client.rows.filter(
            (row) =>
              (row.status === pendingStatus || row.status === leasedStatus) &&
              row.available_at <= String(now) &&
              (!tenantScoped || row.tenant_id === tenantId) &&
              !client.rows.some(
                (candidate) =>
                  candidate.tenant_id === row.tenant_id &&
                  (candidate.status === "paused" ||
                    (candidate.status === "leased" && candidate.available_at > String(now))),
              ),
          ),
          limit,
        );
      }
      if (sql.startsWith("insert into")) {
        const [
          id,
          tenantId,
          payloadCanonical,
          entryJson,
          status,
          attempts,
          availableAt,
          createdAt,
          updatedAt,
          dispatchedAt,
          lastError,
        ] = params;
        if (client.rows.some((row) => row.id === id)) {
          throw new TypeError("duplicate outbox id");
        }
        client.rows.push({
          id: String(id),
          tenant_id: String(tenantId),
          payload_canonical: String(payloadCanonical),
          entry_json: String(entryJson),
          status: String(status),
          attempts: Number(attempts),
          available_at: String(availableAt),
          created_at: String(createdAt),
          updated_at: String(updatedAt),
          dispatched_at: dispatchedAt === null ? null : String(dispatchedAt),
          last_error: lastError === null ? null : String(lastError),
        });
        return [];
      }
      if (sql.includes("not exists") && sql.includes("available_at")) {
        const tenantScoped = sql.includes("candidate.tenant_id =");
        const [status, availableAt] = params;
        const tenantId = tenantScoped ? params[5] : undefined;
        const limit = params[tenantScoped ? 6 : 5];
        return limitRows(
          client.rows.filter(
            (row) =>
              row.status === status &&
              row.available_at <= String(availableAt) &&
              (!tenantScoped || row.tenant_id === tenantId) &&
              !client.rows.some(
                (candidate) =>
                  candidate.tenant_id === row.tenant_id &&
                  (candidate.status === "paused" ||
                    (candidate.status === "leased" && candidate.available_at > String(availableAt))),
              ),
          ),
          limit,
        );
      }
      if (sql.startsWith("select payload_canonical, entry_json")) {
        const tenantScoped = sql.includes("tenant_id =");
        const tenantId = tenantScoped ? params[0] : undefined;
        const limit = params[tenantScoped ? 1 : 0];
        return limitRows(
          client.rows.filter((row) => !tenantScoped || row.tenant_id === tenantId),
          limit,
        );
      }
      if (sql.startsWith("update")) {
        const [entryJson, status, attempts, availableAt, updatedAt, dispatchedAt, lastError, id] = params;
        const row = client.rows.find((candidate) => candidate.id === id);
        if (!row) {
          throw new TypeError("outbox entry not found");
        }
        Object.assign(row, {
          entry_json: String(entryJson),
          status: String(status),
          attempts: Number(attempts),
          available_at: String(availableAt),
          updated_at: String(updatedAt),
          dispatched_at: dispatchedAt === null ? null : String(dispatchedAt),
          last_error: lastError === null ? null : String(lastError),
        });
        return [];
      }
      throw new TypeError(`unexpected SQL: ${statement}`);
    },
  };
  return client;
}

/**
 * Sorts and limits SQL mock rows in the same order the real outbox queries use.
 */
function limitRows(rows: SqlOutboxRow[], limit: unknown): SqlOutboxRow[] {
  const sorted = rows.sort(
    (left, right) => left.created_at.localeCompare(right.created_at) || left.id.localeCompare(right.id),
  );
  return limit === null || limit === undefined ? sorted : sorted.slice(0, Number(limit));
}

describe("file outbox queued-bytes ceiling", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "veritio-outbox-cap-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  test("enqueue fails closed once the undelivered backlog would exceed the cap", async () => {
    const payload = makeDraft("cap").outboxEntry;
    const entryBytes = outboxPayloadByteLength(payload);
    const adapter = createFileOutboxAdapter(join(dir, "outbox"), { maxQueuedBytes: entryBytes + 10 });

    await adapter.transaction((tx) => tx.enqueue({ id: "cap_1", tenantId: TENANT, payload }));
    await expect(
      adapter.transaction((tx) =>
        tx.enqueue({ id: "cap_2", tenantId: TENANT, payload: makeDraft("cap2").outboxEntry }),
      ),
    ).rejects.toThrow(OutboxQueueFullError);
    // The refused enqueue rolled back: only the first durable copy exists.
    expect(await adapter.list({ tenantId: TENANT })).toHaveLength(1);

    // Idempotent re-enqueue of the SAME entry stays accepted at the ceiling.
    await adapter.transaction((tx) => tx.enqueue({ id: "cap_1", tenantId: TENANT, payload }));
    expect(await adapter.list({ tenantId: TENANT })).toHaveLength(1);
  });

  test("dispatched rows leave the backlog so delivery restores capacity", async () => {
    const payload = makeDraft("drain").outboxEntry;
    const entryBytes = outboxPayloadByteLength(payload);
    const path = join(dir, "outbox");
    const adapter = createFileOutboxAdapter(path, { maxQueuedBytes: entryBytes + 10 });
    await adapter.transaction((tx) => tx.enqueue({ id: "drain_1", tenantId: TENANT, payload }));

    const evidence = createFileEvidenceStore(join(dir, "evidence"));
    const dispatcher = createOutboxDispatcher({ adapter, target: evidence });
    expect((await dispatcher.dispatchBatch({ tenantId: TENANT, permit: PERMIT })).dispatched).toBe(1);

    await adapter.transaction((tx) =>
      tx.enqueue({ id: "drain_2", tenantId: TENANT, payload: makeDraft("d2").outboxEntry }),
    );
    expect(await adapter.list({ tenantId: TENANT })).toHaveLength(2);
  });

  test("rejects a non-positive ceiling at construction", () => {
    expect(() => createFileOutboxAdapter(join(dir, "outbox"), { maxQueuedBytes: 0 })).toThrow("maxQueuedBytes");
  });
});

describe("rolling window ledger", () => {
  const policy = {
    ...DEFAULT_DELIVERY_SAFETY_POLICY,
    hard: { ...DEFAULT_DELIVERY_SAFETY_POLICY.hard, rollingRequests: 2, rollingSendBytes: 300, windowMs: 1_000 },
  };

  test("caps requests and bytes across recorded sends", () => {
    const ledger = createRollingWindowLedger(policy);
    expect(ledger.remainingRequests(0)).toBe(2);
    expect(ledger.remainingBytes(0)).toBe(300);
    ledger.record(0, 100);
    ledger.record(10, 150);
    expect(ledger.remainingRequests(20)).toBe(0);
    expect(ledger.remainingBytes(20)).toBe(50);
  });

  test("restores capacity only after sends age out of the window", () => {
    const ledger = createRollingWindowLedger(policy);
    ledger.record(0, 200);
    ledger.record(500, 100);
    expect(ledger.remainingRequests(999)).toBe(0);
    // The first send ages out exactly at windowMs; the second remains.
    expect(ledger.remainingRequests(1_000)).toBe(1);
    expect(ledger.remainingBytes(1_000)).toBe(200);
    expect(ledger.remainingRequests(1_500)).toBe(2);
    expect(ledger.remainingBytes(1_500)).toBe(300);
  });
});
