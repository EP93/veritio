import { describe, expect, test } from "bun:test";
import {
  createAuditEvent,
  createRetentionCheckpoint,
  createRetentionDisposition,
  MemoryAuditStore,
  type AuditEvent,
  type AuditRecord,
  type DispositionAttempt,
  type RetentionCheckpoint,
} from "../index";

const TENANT_ID = "org_retention";
const SCOPE = { tenantId: TENANT_ID };
const ARCHIVE_ROOT_HASH = "a".repeat(64);

/**
 * Builds deterministic tenant audit input so retention assertions depend only
 * on the store transition under test, not generated ids or event timestamps.
 */
function auditEvent(id: string, minute: number, role = "viewer"): AuditEvent {
  return createAuditEvent({
    id,
    occurredAt: `2026-08-24T00:${String(minute).padStart(2, "0")}:00.000Z`,
    actor: { type: "system", id: "sys_retention" },
    action: "retention.record.observed",
    target: { type: "organization", id: TENANT_ID },
    scope: SCOPE,
    metadata: { role },
  });
}

/**
 * Creates a valid checkpoint over an exact ordered record prefix while keeping
 * archive provider details outside the authoritative-store contract.
 */
function checkpointFor(
  records: readonly AuditRecord[],
  options: { epoch?: number; previousCheckpoint?: RetentionCheckpoint } = {},
): RetentionCheckpoint {
  const first = records[0];
  const last = records.at(-1);
  if (!first || !last) throw new TypeError("checkpoint fixture requires records");
  const epoch = options.epoch ?? 1;
  return createRetentionCheckpoint({
    checkpointId: `rcp_${epoch}`,
    tenantId: TENANT_ID,
    chainKind: "audit",
    epoch,
    fromSequence: first.sequence,
    fromPreviousHash: first.previousHash,
    throughSequence: last.sequence,
    throughHash: last.hash,
    recordCount: records.length,
    archiveRootHash: ARCHIVE_ROOT_HASH,
    previousCheckpointHash: options.previousCheckpoint?.hash ?? null,
    createdAt: `2026-08-24T01:0${epoch}:00.000Z`,
  });
}

/**
 * Crops one complete checkpoint so disposition tests start from the durable
 * checkpoint state required by the public store contract.
 */
async function compactFixture(store: MemoryAuditStore): Promise<RetentionCheckpoint> {
  const first = await store.append(auditEvent("evt_1", 1), { idempotencyKey: "event:1" });
  const checkpoint = checkpointFor([first]);
  const expected = await store.getChainState(SCOPE);
  await store.compactRange(SCOPE, checkpoint, expected, expected.retentionPolicyFence);
  return checkpoint;
}

describe("MemoryAuditStore retention checkpoints", () => {
  test("continues the authoritative sequence and original hash link after a full-prefix crop", async () => {
    const store = new MemoryAuditStore();
    const first = await store.append(auditEvent("evt_1", 1));
    const second = await store.append(auditEvent("evt_2", 2));
    const beforeCrop = await store.getChainState(SCOPE);
    const checkpoint = checkpointFor([first, second]);

    expect(beforeCrop).toEqual({
      authoritativeTipSequence: 2,
      authoritativeTipHash: second.hash,
      minimumRetainedSequence: 1,
      latestCheckpointHash: null,
      retentionPolicyFence: 0,
    });

    await store.compactRange(SCOPE, checkpoint, beforeCrop, beforeCrop.retentionPolicyFence);

    expect(await store.list(SCOPE)).toEqual([]);
    expect(await store.listCheckpoints(SCOPE)).toEqual([checkpoint]);
    expect(await store.getChainState(SCOPE)).toEqual({
      authoritativeTipSequence: 2,
      authoritativeTipHash: second.hash,
      minimumRetainedSequence: 3,
      latestCheckpointHash: checkpoint.hash,
      retentionPolicyFence: 0,
    });

    const third = await store.append(auditEvent("evt_3", 3));
    expect(third.sequence).toBe(3);
    expect(third.previousHash).toBe(second.hash);
  });

  test("rejects a stale chain-state CAS without deleting rows or storing a checkpoint", async () => {
    const store = new MemoryAuditStore();
    const first = await store.append(auditEvent("evt_1", 1));
    const second = await store.append(auditEvent("evt_2", 2));
    const staleState = await store.getChainState(SCOPE);
    const checkpoint = checkpointFor([first, second]);
    const third = await store.append(auditEvent("evt_3", 3));

    await expect(store.compactRange(SCOPE, checkpoint, staleState, staleState.retentionPolicyFence)).rejects.toThrow();

    expect(await store.list(SCOPE)).toEqual([first, second, third]);
    expect(await store.listCheckpoints(SCOPE)).toEqual([]);
  });

  test("rejects a wrong checkpoint boundary atomically and leaves retained rows byte-identical", async () => {
    const store = new MemoryAuditStore();
    const first = await store.append(auditEvent("evt_1", 1));
    const second = await store.append(auditEvent("evt_2", 2));
    const third = await store.append(auditEvent("evt_3", 3));
    const expected = await store.getChainState(SCOPE);
    const wrongBoundary = createRetentionCheckpoint({
      ...checkpointFor([first, second]),
      throughHash: "f".repeat(64),
    });

    await expect(
      store.compactRange(SCOPE, wrongBoundary, expected, expected.retentionPolicyFence),
    ).rejects.toThrow();
    expect(await store.list(SCOPE)).toEqual([first, second, third]);

    await store.compactRange(SCOPE, checkpointFor([first, second]), expected, expected.retentionPolicyFence);
    expect(await store.list(SCOPE)).toEqual([third]);
  });

  test("requires a contiguous next checkpoint prefix and preserves the first checkpoint on failure", async () => {
    const store = new MemoryAuditStore();
    const first = await store.append(auditEvent("evt_1", 1));
    const second = await store.append(auditEvent("evt_2", 2));
    const third = await store.append(auditEvent("evt_3", 3));
    const firstCheckpoint = checkpointFor([first]);
    const initial = await store.getChainState(SCOPE);
    await store.compactRange(SCOPE, firstCheckpoint, initial, initial.retentionPolicyFence);
    const afterFirstCrop = await store.getChainState(SCOPE);
    const gapCheckpoint = createRetentionCheckpoint({
      ...checkpointFor([third], { epoch: 2, previousCheckpoint: firstCheckpoint }),
      fromPreviousHash: second.hash,
    });

    await expect(
      store.compactRange(SCOPE, gapCheckpoint, afterFirstCrop, afterFirstCrop.retentionPolicyFence),
    ).rejects.toThrow();

    expect(await store.list(SCOPE)).toEqual([second, third]);
    expect(await store.listCheckpoints(SCOPE)).toEqual([firstCheckpoint]);
  });

  test("CASes the policy fence and rejects compaction with a stale fence without mutation", async () => {
    const store = new MemoryAuditStore();
    const first = await store.append(auditEvent("evt_1", 1));
    const staleState = await store.getChainState(SCOPE);

    expect(await store.advanceRetentionPolicyFence(SCOPE, 0)).toBe(1);
    await expect(store.advanceRetentionPolicyFence(SCOPE, 0)).rejects.toThrow();
    await expect(store.compactRange(SCOPE, checkpointFor([first]), staleState, 0)).rejects.toThrow();

    expect(await store.list(SCOPE)).toEqual([first]);
    expect(await store.listCheckpoints(SCOPE)).toEqual([]);
    expect((await store.getChainState(SCOPE)).retentionPolicyFence).toBe(1);
  });

  test("keeps permanent idempotency tombstones after disposed history leaves hot storage", async () => {
    const store = new MemoryAuditStore();
    const originalEvent = auditEvent("evt_1", 1);
    const original = await store.append(originalEvent, { idempotencyKey: "stable-key" });
    const state = await store.getChainState(SCOPE);
    await store.compactRange(SCOPE, checkpointFor([original]), state, state.retentionPolicyFence);

    await expect(store.append(originalEvent, { idempotencyKey: "stable-key" })).rejects.toThrow(
      "idempotency_history_disposed",
    );
    await expect(store.append(auditEvent("evt_changed", 2, "admin"), { idempotencyKey: "stable-key" })).rejects.toThrow(
      "idempotency conflict",
    );
    expect(await store.list(SCOPE)).toEqual([]);
    expect((await store.getChainState(SCOPE)).authoritativeTipSequence).toBe(1);
  });
});

describe("MemoryAuditStore retention disposition", () => {
  test("replays one exact pending attempt and one exact disposed receipt idempotently", async () => {
    const store = new MemoryAuditStore();
    const checkpoint = await compactFixture(store);
    const attempt: DispositionAttempt = {
      attemptId: "attempt_1",
      checkpointHash: checkpoint.hash,
      policyFence: 0,
      status: "pending",
    };

    expect(await store.prepareDisposition(SCOPE, checkpoint.hash, attempt, 0)).toEqual(attempt);
    expect(await store.prepareDisposition(SCOPE, checkpoint.hash, attempt, 0)).toEqual(attempt);

    const receipt = createRetentionDisposition({
      dispositionId: "disposition_1",
      tenantId: TENANT_ID,
      chainKind: "audit",
      checkpointHash: checkpoint.hash,
      fromSequence: checkpoint.fromSequence,
      throughSequence: checkpoint.throughSequence,
      archiveRootHash: checkpoint.archiveRootHash,
      policyReference: "policy.v1",
      disposedAt: "2026-08-24T02:00:00.000Z",
    });

    await store.confirmDisposition(SCOPE, receipt, attempt.attemptId, 0);
    await store.confirmDisposition(SCOPE, receipt, attempt.attemptId, 0);
    expect(await store.listDispositions(SCOPE)).toEqual([receipt]);

    const conflictingReceipt = createRetentionDisposition({
      ...receipt,
      dispositionId: "disposition_conflict",
    });
    await expect(store.confirmDisposition(SCOPE, conflictingReceipt, attempt.attemptId, 0)).rejects.toThrow();
    await expect(store.prepareDisposition(SCOPE, checkpoint.hash, attempt, 0)).rejects.toThrow();
    expect(await store.listDispositions(SCOPE)).toEqual([receipt]);
  });

  test("rebinds a crashed pending attempt only to a newer current policy fence", async () => {
    const store = new MemoryAuditStore();
    const checkpoint = await compactFixture(store);
    const staleAttempt: DispositionAttempt = {
      attemptId: "attempt_stale",
      checkpointHash: checkpoint.hash,
      policyFence: 0,
      status: "pending",
    };
    await store.prepareDisposition(SCOPE, checkpoint.hash, staleAttempt, 0);

    const sameFenceAttempt: DispositionAttempt = { ...staleAttempt, attemptId: "attempt_conflict" };
    await expect(store.prepareDisposition(SCOPE, checkpoint.hash, sameFenceAttempt, 0)).rejects.toThrow();

    expect(await store.advanceRetentionPolicyFence(SCOPE, 0)).toBe(1);
    const reboundAttempt: DispositionAttempt = {
      attemptId: "attempt_rebound",
      checkpointHash: checkpoint.hash,
      policyFence: 1,
      status: "pending",
    };
    expect(await store.prepareDisposition(SCOPE, checkpoint.hash, reboundAttempt, 1)).toEqual(reboundAttempt);

    const receipt = createRetentionDisposition({
      dispositionId: "disposition_rebound",
      tenantId: TENANT_ID,
      chainKind: "audit",
      checkpointHash: checkpoint.hash,
      fromSequence: checkpoint.fromSequence,
      throughSequence: checkpoint.throughSequence,
      archiveRootHash: checkpoint.archiveRootHash,
      policyReference: "policy.v2",
      disposedAt: "2026-08-24T03:00:00.000Z",
    });

    await expect(store.confirmDisposition(SCOPE, receipt, staleAttempt.attemptId, 0)).rejects.toThrow();
    await store.confirmDisposition(SCOPE, receipt, reboundAttempt.attemptId, 1);
    expect(await store.listDispositions(SCOPE)).toEqual([receipt]);
  });

  test("rejects attempts and receipts that are not exactly bound to the checkpoint and fence", async () => {
    const store = new MemoryAuditStore();
    const checkpoint = await compactFixture(store);
    const wrongCheckpointAttempt: DispositionAttempt = {
      attemptId: "attempt_wrong_checkpoint",
      checkpointHash: "b".repeat(64),
      policyFence: 0,
      status: "pending",
    };
    await expect(
      store.prepareDisposition(SCOPE, checkpoint.hash, wrongCheckpointAttempt, 0),
    ).rejects.toThrow();

    const wrongFenceAttempt: DispositionAttempt = {
      attemptId: "attempt_wrong_fence",
      checkpointHash: checkpoint.hash,
      policyFence: 1,
      status: "pending",
    };
    await expect(store.prepareDisposition(SCOPE, checkpoint.hash, wrongFenceAttempt, 0)).rejects.toThrow();

    const attempt: DispositionAttempt = {
      attemptId: "attempt_valid",
      checkpointHash: checkpoint.hash,
      policyFence: 0,
      status: "pending",
    };
    await store.prepareDisposition(SCOPE, checkpoint.hash, attempt, 0);
    const mismatchedReceipt = createRetentionDisposition({
      dispositionId: "disposition_mismatch",
      tenantId: TENANT_ID,
      chainKind: "audit",
      checkpointHash: "c".repeat(64),
      fromSequence: checkpoint.fromSequence,
      throughSequence: checkpoint.throughSequence,
      archiveRootHash: checkpoint.archiveRootHash,
      policyReference: "policy.v1",
      disposedAt: "2026-08-24T04:00:00.000Z",
    });

    await expect(store.confirmDisposition(SCOPE, mismatchedReceipt, attempt.attemptId, 0)).rejects.toThrow();
    expect(await store.listDispositions(SCOPE)).toEqual([]);
  });
});
