import assert from "node:assert/strict";
import {
  type AuditEvent,
  type AuditRecord,
  type CheckpointingAuditStore,
  createAuditEvent,
  createRetentionCheckpoint,
  createRetentionDisposition,
  type DispositionAttempt,
  type RetentionCheckpoint,
} from "@veritio/core";

type MaybePromise<T> = T | Promise<T>;

export interface RetentionStoreConformanceTarget {
  store: CheckpointingAuditStore;
  close?(): MaybePromise<void>;
}

export interface RetentionStoreConformanceOptions {
  name: string;
  createTarget(): MaybePromise<RetentionStoreConformanceTarget>;
}

export interface RetentionStoreConformanceTest {
  name: string;
  run(): Promise<void>;
}

const TENANT_ID = "org_retention_conformance";
const SCOPE = { tenantId: TENANT_ID };
const ARCHIVE_ROOT_HASH = "a".repeat(64);

/**
 * Returns the shared destructive-retention contract for every authoritative
 * database adapter that opts into CheckpointingAuditStore. Each case owns an
 * isolated target so a failed crop or disposition cannot contaminate another
 * adapter assertion.
 */
export function createRetentionStoreConformanceTests(
  options: RetentionStoreConformanceOptions,
): RetentionStoreConformanceTest[] {
  return [
    {
      name: "preserves the authoritative tip after a full crop and appends from the original hash",
      async run() {
        await withTarget(options, async ({ store }) => {
          const first = await store.append(makeEvent("evt_retention_01", 1));
          const second = await store.append(makeEvent("evt_retention_02", 2));
          const checkpoint = checkpointFor([first, second]);
          const expected = await store.getChainState(SCOPE);

          await store.compactRange(SCOPE, checkpoint, expected, expected.retentionPolicyFence);

          assert.deepEqual(await store.list(SCOPE), []);
          assert.deepEqual(await store.getChainState(SCOPE), {
            authoritativeTipSequence: 2,
            authoritativeTipHash: second.hash,
            minimumRetainedSequence: 3,
            latestCheckpointHash: checkpoint.hash,
            retentionPolicyFence: 0,
          });
          const third = await store.append(makeEvent("evt_retention_03", 3));
          assert.equal(third.sequence, 3);
          assert.equal(third.previousHash, second.hash);

          const listed = await store.listCheckpoints(SCOPE);
          assert.deepEqual(listed, [checkpoint]);
          listed[0]!.checkpointId = "mutated_by_caller";
          assert.deepEqual(await store.listCheckpoints(SCOPE), [checkpoint]);
        });
      },
    },
    {
      name: "supports partial crops through a second ordered epoch",
      async run() {
        await withTarget(options, async ({ store }) => {
          const first = await store.append(makeEvent("evt_retention_01", 1));
          const second = await store.append(makeEvent("evt_retention_02", 2));
          const third = await store.append(makeEvent("evt_retention_03", 3));
          const fourth = await store.append(makeEvent("evt_retention_04", 4));
          const firstCheckpoint = checkpointFor([first, second]);
          const initial = await store.getChainState(SCOPE);

          await store.compactRange(SCOPE, firstCheckpoint, initial, initial.retentionPolicyFence);

          assert.deepEqual(await store.list(SCOPE), [third, fourth]);
          const secondCheckpoint = checkpointFor([third], {
            checkpointId: "rcp_retention_conformance_2",
            epoch: 2,
            previousCheckpointHash: firstCheckpoint.hash,
            createdAt: "2026-08-24T01:01:00.000Z",
          });
          const afterFirstCrop = await store.getChainState(SCOPE);
          await store.compactRange(SCOPE, secondCheckpoint, afterFirstCrop, afterFirstCrop.retentionPolicyFence);

          assert.deepEqual(await store.list(SCOPE), [fourth]);
          const secondAttempt = dispositionAttempt(secondCheckpoint, "attempt_epoch_2", 0);
          await store.prepareDisposition(SCOPE, secondCheckpoint.hash, secondAttempt, 0);
          const secondReceipt = dispositionFor(secondCheckpoint, "disposition_epoch_2", "policy.v2");
          await store.confirmDisposition(SCOPE, secondReceipt, secondAttempt.attemptId, 0);
          const firstAttempt = dispositionAttempt(firstCheckpoint, "attempt_epoch_1", 0);
          await store.prepareDisposition(SCOPE, firstCheckpoint.hash, firstAttempt, 0);
          const firstReceipt = dispositionFor(firstCheckpoint, "disposition_epoch_1", "policy.v1");
          await store.confirmDisposition(SCOPE, firstReceipt, firstAttempt.attemptId, 0);

          assert.deepEqual(await store.listCheckpoints(SCOPE), [firstCheckpoint, secondCheckpoint]);
          assert.deepEqual(await store.listDispositions(SCOPE), [firstReceipt, secondReceipt]);
        });
      },
    },
    {
      name: "rejects stale state and wrong crop boundaries without partial mutation",
      async run() {
        await withTarget(options, async ({ store }) => {
          const first = await store.append(makeEvent("evt_retention_01", 1));
          const second = await store.append(makeEvent("evt_retention_02", 2));
          const stale = await store.getChainState(SCOPE);
          const third = await store.append(makeEvent("evt_retention_03", 3));

          await assert.rejects(store.compactRange(SCOPE, checkpointFor([first, second]), stale, 0));
          assert.deepEqual(await store.list(SCOPE), [first, second, third]);
          assert.deepEqual(await store.listCheckpoints(SCOPE), []);

          const current = await store.getChainState(SCOPE);
          const wrongBoundary = createRetentionCheckpoint({
            ...checkpointFor([first, second]),
            throughHash: "f".repeat(64),
          });
          await assert.rejects(store.compactRange(SCOPE, wrongBoundary, current, current.retentionPolicyFence));
          assert.deepEqual(await store.list(SCOPE), [first, second, third]);
          assert.deepEqual(await store.listCheckpoints(SCOPE), []);
        });
      },
    },
    {
      name: "rejects a stale policy fence and leaves the hot prefix intact",
      async run() {
        await withTarget(options, async ({ store }) => {
          const first = await store.append(makeEvent("evt_retention_01", 1));
          const stale = await store.getChainState(SCOPE);

          assert.equal(await store.advanceRetentionPolicyFence(SCOPE, 0), 1);
          await assert.rejects(store.advanceRetentionPolicyFence(SCOPE, 0));
          await assert.rejects(store.compactRange(SCOPE, checkpointFor([first]), stale, 0));

          assert.deepEqual(await store.list(SCOPE), [first]);
          assert.deepEqual(await store.listCheckpoints(SCOPE), []);
          assert.equal((await store.getChainState(SCOPE)).retentionPolicyFence, 1);
        });
      },
    },
    {
      name: "keeps permanent minimal idempotency tombstones after crop",
      async run() {
        await withTarget(options, async ({ store }) => {
          const event = makeEvent("evt_retention_01", 1);
          const first = await store.append(event, { idempotencyKey: "stable-retention-key" });
          const expected = await store.getChainState(SCOPE);
          await store.compactRange(SCOPE, checkpointFor([first]), expected, expected.retentionPolicyFence);

          await assert.rejects(
            store.append(event, { idempotencyKey: "stable-retention-key" }),
            /idempotency_history_disposed/,
          );
          await assert.rejects(
            store.append(makeEvent("evt_retention_changed", 2, "admin"), {
              idempotencyKey: "stable-retention-key",
            }),
            /idempotency conflict/,
          );
          assert.deepEqual(await store.list(SCOPE), []);
          assert.equal((await store.getChainState(SCOPE)).authoritativeTipSequence, 1);
        });
      },
    },
    {
      name: "accepts one exact disposition replay and rejects a conflicting duplicate",
      async run() {
        await withTarget(options, async ({ store }) => {
          const checkpoint = await compactOne(store);
          const attempt = dispositionAttempt(checkpoint, "attempt_1", 0);
          assert.deepEqual(await store.prepareDisposition(SCOPE, checkpoint.hash, attempt, 0), attempt);
          assert.deepEqual(await store.prepareDisposition(SCOPE, checkpoint.hash, attempt, 0), attempt);

          const receipt = dispositionFor(checkpoint, "disposition_1", "policy.v1");
          await store.confirmDisposition(SCOPE, receipt, attempt.attemptId, 0);
          await store.confirmDisposition(SCOPE, receipt, attempt.attemptId, 0);

          const listed = await store.listDispositions(SCOPE);
          assert.deepEqual(listed, [receipt]);
          listed[0]!.policyReference = "mutated.by.caller";
          assert.deepEqual(await store.listDispositions(SCOPE), [receipt]);

          const conflictingReceipt = createRetentionDisposition({
            ...receipt,
            dispositionId: "disposition_conflict",
          });
          await assert.rejects(store.confirmDisposition(SCOPE, conflictingReceipt, attempt.attemptId, 0));
          await assert.rejects(store.prepareDisposition(SCOPE, checkpoint.hash, attempt, 0));
          assert.deepEqual(await store.listDispositions(SCOPE), [receipt]);
        });
      },
    },
    {
      name: "rebinds a crashed pending disposition only at a newer current fence",
      async run() {
        await withTarget(options, async ({ store }) => {
          const checkpoint = await compactOne(store);
          const staleAttempt = dispositionAttempt(checkpoint, "attempt_stale", 0);
          await store.prepareDisposition(SCOPE, checkpoint.hash, staleAttempt, 0);
          await assert.rejects(
            store.prepareDisposition(SCOPE, checkpoint.hash, dispositionAttempt(checkpoint, "attempt_conflict", 0), 0),
          );

          assert.equal(await store.advanceRetentionPolicyFence(SCOPE, 0), 1);
          const rebound = dispositionAttempt(checkpoint, "attempt_rebound", 1);
          assert.deepEqual(await store.prepareDisposition(SCOPE, checkpoint.hash, rebound, 1), rebound);
          const receipt = dispositionFor(checkpoint, "disposition_rebound", "policy.v2");

          await assert.rejects(store.confirmDisposition(SCOPE, receipt, staleAttempt.attemptId, 0));
          await store.confirmDisposition(SCOPE, receipt, rebound.attemptId, 1);
          assert.deepEqual(await store.listDispositions(SCOPE), [receipt]);
        });
      },
    },
    {
      name: "fails closed for non-minimal disposition attempts before persistence",
      async run() {
        await withTarget(options, async ({ store }) => {
          const checkpoint = await compactOne(store);
          const attemptWithSecret = {
            ...dispositionAttempt(checkpoint, "attempt_secret", 0),
            authorization: "Bearer must-not-persist",
          } as DispositionAttempt;
          await assert.rejects(store.prepareDisposition(SCOPE, checkpoint.hash, attemptWithSecret, 0));

          const valid = dispositionAttempt(checkpoint, "attempt_minimal", 0);
          assert.deepEqual(await store.prepareDisposition(SCOPE, checkpoint.hash, valid, 0), valid);
        });
      },
    },
  ];
}

/**
 * Creates and reliably closes one adapter target around a conformance case.
 */
async function withTarget<T>(
  options: RetentionStoreConformanceOptions,
  run: (target: RetentionStoreConformanceTarget) => Promise<T>,
): Promise<T> {
  const target = await options.createTarget();
  try {
    return await run(target);
  } finally {
    await target.close?.();
  }
}

/**
 * Builds deterministic audit events whose canonical bytes differ only through
 * explicit fixture inputs.
 */
function makeEvent(id: string, minute: number, role = "viewer"): AuditEvent {
  return createAuditEvent({
    id,
    occurredAt: `2026-08-24T00:${String(minute).padStart(2, "0")}:00.000Z`,
    actor: { type: "system", id: "sys_retention_conformance" },
    action: "retention.record.observed",
    target: { type: "organization", id: TENANT_ID },
    scope: SCOPE,
    metadata: { role },
  });
}

/**
 * Builds one canonical checkpoint over an exact contiguous record prefix.
 */
function checkpointFor(
  records: readonly AuditRecord[],
  options: {
    checkpointId?: string;
    epoch?: number;
    previousCheckpointHash?: string | null;
    createdAt?: string;
  } = {},
): RetentionCheckpoint {
  const first = records[0];
  const last = records.at(-1);
  if (!first || !last) {
    throw new TypeError("retention conformance checkpoint requires records");
  }
  return createRetentionCheckpoint({
    checkpointId: options.checkpointId ?? "rcp_retention_conformance_1",
    tenantId: TENANT_ID,
    chainKind: "audit",
    epoch: options.epoch ?? 1,
    fromSequence: first.sequence,
    fromPreviousHash: first.previousHash,
    throughSequence: last.sequence,
    throughHash: last.hash,
    recordCount: records.length,
    archiveRootHash: ARCHIVE_ROOT_HASH,
    previousCheckpointHash: options.previousCheckpointHash ?? null,
    createdAt: options.createdAt ?? "2026-08-24T01:00:00.000Z",
  });
}

/**
 * Persists and crops one record so disposition cases start from the required
 * durable checkpoint state.
 */
async function compactOne(store: CheckpointingAuditStore): Promise<RetentionCheckpoint> {
  const first = await store.append(makeEvent("evt_retention_01", 1), { idempotencyKey: "retention:event:1" });
  const checkpoint = checkpointFor([first]);
  const state = await store.getChainState(SCOPE);
  await store.compactRange(SCOPE, checkpoint, state, state.retentionPolicyFence);
  return checkpoint;
}

/**
 * Creates the exact four-field non-personal attempt envelope accepted by the
 * checkpointing store contract.
 */
function dispositionAttempt(
  checkpoint: RetentionCheckpoint,
  attemptId: string,
  policyFence: number,
): DispositionAttempt {
  return { attemptId, checkpointHash: checkpoint.hash, policyFence, status: "pending" };
}

/**
 * Builds a deterministic disposition receipt bound to a checkpoint fixture.
 */
function dispositionFor(checkpoint: RetentionCheckpoint, dispositionId: string, policyReference: string) {
  return createRetentionDisposition({
    dispositionId,
    tenantId: TENANT_ID,
    chainKind: "audit",
    checkpointHash: checkpoint.hash,
    fromSequence: checkpoint.fromSequence,
    throughSequence: checkpoint.throughSequence,
    archiveRootHash: checkpoint.archiveRootHash,
    policyReference,
    disposedAt: "2026-08-24T02:00:00.000Z",
  });
}
