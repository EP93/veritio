import assert from "node:assert/strict";
import {
  createAuditEvent,
  verifyAuditRecords,
  type AuditEventInput,
  type AuditRecord,
  type AuditStore,
} from "@veritio/core";

export * from "./retention-conformance.js";

type MaybePromise<T> = T | Promise<T>;

export interface AuditStoreConformanceCorruption {
  tenantId: string;
  sequence: number;
  mutate(record: AuditRecord): AuditRecord | void;
}

export interface AuditStoreConformanceTarget {
  store: AuditStore;
  mutateStoredRecord(corruption: AuditStoreConformanceCorruption): MaybePromise<void>;
  close?(): MaybePromise<void>;
}

export interface AuditStoreConformanceOptions {
  name: string;
  createTarget(): MaybePromise<AuditStoreConformanceTarget>;
}

export interface AuditStoreConformanceTest {
  name: string;
  run(): Promise<void>;
}

const TENANT_A = "org_conformance_a";
const TENANT_B = "org_conformance_b";
const BAD_HASH = "0".repeat(64);

/**
 * Returns reusable conformance tests that every storage adapter must satisfy.
 * The suite protects tenant-local ordering, idempotent append behavior, cloning,
 * and fail-closed integrity checks across SQL, Mongo, and future stores.
 */
export function createAuditStoreConformanceTests(options: AuditStoreConformanceOptions): AuditStoreConformanceTest[] {
  return [
    {
      name: "appends tenant-scoped chains and lists records deterministically",
      async run() {
      await withTarget(options, async ({ store }) => {
        const first = await store.append(makeConformanceEvent("evt_conformance_01", TENANT_A, { role: "viewer" }));
        const second = await store.append(
          makeConformanceEvent("evt_conformance_02", TENANT_A, { policy: "security_1y" }),
          { expectedPreviousHash: first.hash },
        );
        const otherTenant = await store.append(
          makeConformanceEvent("evt_conformance_03", TENANT_B, { role: "admin" }),
        );

        assert.equal(first.sequence, 1);
        assert.equal(first.previousHash, null);
        assert.equal(second.sequence, 2);
        assert.equal(second.previousHash, first.hash);
        assert.equal(otherTenant.sequence, 1);
        assert.equal(otherTenant.previousHash, null);

        const tenantRecords = await store.list({ tenantId: TENANT_A });
        assert.deepEqual(tenantRecords, [first, second]);
        assert.deepEqual(verifyAuditRecords(tenantRecords), { ok: true });
        assert.deepEqual(await store.list({ tenantId: TENANT_A }, { afterSequence: 1, limit: 1 }), [second]);
        assert.deepEqual(await store.list({ tenantId: TENANT_B }), [otherTenant]);
      });
      },
    },
    {
      name: "returns idempotent records and rejects conflicting idempotency keys",
      async run() {
      await withTarget(options, async ({ store }) => {
        const event = makeConformanceEvent("evt_conformance_01", TENANT_A, { role: "viewer" });

        const first = await store.append(event, { idempotencyKey: "invite:user-456" });
        const repeated = await store.append(event, { idempotencyKey: "invite:user-456" });

        assert.deepEqual(repeated, first);
        assert.deepEqual(await store.list({ tenantId: TENANT_A }), [first]);
        await assert.rejects(
          store.append(makeConformanceEvent("evt_conformance_02", TENANT_A, { role: "admin" }), {
            idempotencyKey: "invite:user-456",
          }),
          /idempotency conflict/,
        );
      });
      },
    },
    {
      name: "fails closed for missing tenant scope and expected tip mismatches",
      async run() {
      await withTarget(options, async ({ store }) => {
        await assert.rejects(
          store.append(makeConformanceEventWithoutTenant("evt_conformance_missing_scope")),
          /scope\.tenantId is required/,
        );

        await store.append(makeConformanceEvent("evt_conformance_01", TENANT_A, { role: "viewer" }));
        await assert.rejects(
          store.append(makeConformanceEvent("evt_conformance_02", TENANT_A, { role: "admin" }), {
            expectedPreviousHash: BAD_HASH,
          }),
          /expectedPreviousHash does not match tenant chain tip/,
        );
      });
      },
    },
    {
      name: "returns cloned records so callers cannot mutate stored evidence",
      async run() {
      await withTarget(options, async ({ store }) => {
        const first = await store.append(makeConformanceEvent("evt_conformance_01", TENANT_A, { role: "viewer" }));
        first.event.metadata.role = "owner";
        first.hash = BAD_HASH;

        const [listed] = await store.list({ tenantId: TENANT_A });

        assert.deepEqual(listed?.event.metadata, { role: "viewer" });
        assert.notEqual(listed?.hash, BAD_HASH);
        assert.deepEqual(verifyAuditRecords(listed ? [listed] : []), { ok: true });
      });
      },
    },
    {
      name: "fails closed when stored record integrity is corrupted",
      async run() {
      await withTarget(options, async (target) => {
        const first = await target.store.append(
          makeConformanceEvent("evt_conformance_01", TENANT_A, { role: "viewer" }),
        );
        await target.mutateStoredRecord({
          tenantId: TENANT_A,
          sequence: first.sequence,
          /**
           * Corrupts the stored hash to prove adapters reject tampered records.
           */
          mutate(record) {
            record.hash = BAD_HASH;
          },
        });

        await assert.rejects(
          target.store.list({ tenantId: TENANT_A }),
          /stored audit record integrity check failed/,
        );
      });
      },
    },
  ];
}

/**
 * Creates and closes a conformance target around one test case so adapter
 * resources cannot leak between tenant-chain checks.
 */
async function withTarget<T>(
  options: AuditStoreConformanceOptions,
  run: (target: AuditStoreConformanceTarget) => Promise<T>,
): Promise<T> {
  const target = await options.createTarget();
  try {
    return await run(target);
  } finally {
    await target.close?.();
  }
}

/**
 * Builds a valid tenant-scoped conformance event with deterministic timestamps.
 */
function makeConformanceEvent(id: string, tenantId: string, metadata: Record<string, unknown>) {
  return createAuditEvent({
    id,
    occurredAt: "2026-06-10T00:00:00.000Z",
    actor: { type: "user", id: `usr_${tenantId}` },
    action: "org.member.invited",
    target: { type: "organization", id: tenantId },
    scope: { tenantId, environment: "test" },
    metadata,
  });
}

/**
 * Builds an event that intentionally lacks tenant scope for fail-closed tests.
 */
function makeConformanceEventWithoutTenant(id: string) {
  const input: AuditEventInput = {
    id,
    occurredAt: "2026-06-10T00:00:00.000Z",
    actor: { type: "user", id: "usr_missing_scope" },
    action: "org.member.invited",
    target: { type: "organization", id: TENANT_A },
    metadata: {},
  };
  return createAuditEvent(input);
}
