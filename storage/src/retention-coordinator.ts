import {
  canonicalJson,
  type AuditChainState,
  type AuditRecord,
  type CheckpointingAuditStore,
  type RetentionCheckpoint,
  type RetentionCheckpointInput,
  type RetentionDisposition,
  type RetentionDispositionInput,
  type RetentionVerificationOptions,
  verifyRetentionCheckpoint,
  verifyRetentionDisposition,
} from "@veritio/core";
import type {
  RetentionStagingArchive,
  RetentionStagingManifest,
} from "./retention-staging-archive.js";

const ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const POLICY_REFERENCE_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/;

/**
 * Current host authorization for exactly one retention policy version. The
 * opaque policy reference is non-personal; legal interpretation remains host-owned.
 */
export interface RetentionEligibilityDecision {
  eligible: boolean;
  policyReference: string;
  version: number;
}

/**
 * Host-owned per-tenant serialization boundary. Implementations must acquire
 * the tenant fence, revalidate `expectedVersion`, keep it held until operation
 * resolves/rejects, and never invoke operation for a stale or held decision.
 * The OSS coordinator can enforce callback scope but cannot prove the host's
 * callback actually locks or serializes external hold mutations.
 */
export type RetentionPolicyFenceRunner = <T>(
  expectedVersion: number,
  operation: () => Promise<T>,
) => Promise<T>;

/**
 * Host-owned tenant/chain serialization boundary for a complete retention
 * epoch. Hosted implementations may use a durable distributed lease; the host
 * must not invoke `operation` until it exclusively owns that tenant audit chain
 * and must retain ownership until the promise settles. OSS cannot implement or
 * prove a cross-process lease on the host's behalf.
 */
export type RetentionEpochLeaseRunner = <T>(operation: () => Promise<T>) => Promise<T>;

/** Caller-owned protocol identifiers and exact UTC-millisecond checkpoint time. */
export interface RetentionCheckpointFactoryInput {
  checkpointId: string;
  createdAt: string;
}

/** Caller-owned attempt/receipt identifiers and exact UTC-millisecond disposal time. */
export interface RetentionDispositionFactoryInput {
  attemptId: string;
  dispositionId: string;
  disposedAt: string;
}

/**
 * Complete injected inputs for one audit-retention epoch. Core receives no
 * environment, clock, randomness, provider credential, or legal-hold details.
 */
export interface RunRetentionEpochOptions {
  store: CheckpointingAuditStore;
  archive: RetentionStagingArchive;
  tenantId: string;
  records: readonly AuditRecord[];
  previousCheckpoint: RetentionCheckpoint | null;
  expectedState: AuditChainState;
  eligibility: RetentionEligibilityDecision;
  checkpoint: RetentionCheckpointFactoryInput;
  disposition: RetentionDispositionFactoryInput;
  segmentRecordCount?: number;
  createCheckpoint(input: RetentionCheckpointInput): RetentionCheckpoint;
  createDisposition(input: RetentionDispositionInput): RetentionDisposition;
  verification?: RetentionVerificationOptions;
  withEpochLease: RetentionEpochLeaseRunner;
  withPolicyFence: RetentionPolicyFenceRunner;
}

/** Detached coordinator result; authoritative records remain owned by the injected store. */
export interface RunRetentionEpochResult {
  manifest: RetentionStagingManifest;
  checkpoint: RetentionCheckpoint;
  disposition: RetentionDisposition;
}

/**
 * Acquires the required host tenant/chain epoch lease before any validation,
 * preflight, store call, or provider call. This outer serialization boundary
 * spans the complete run and is distinct from the two short policy fences.
 */
export async function runRetentionEpoch(options: RunRetentionEpochOptions): Promise<RunRetentionEpochResult> {
  if (typeof options.withEpochLease !== "function") {
    throw new TypeError("withEpochLease is required");
  }
  return options.withEpochLease(() => runRetentionEpochUnderLease(options));
}

/**
 * Executes the leased two-stage state machine in the fixed order seal, verify,
 * crop, prepare, delete, dual absence confirmation, receipt verification, and
 * confirmation. Fence one surrounds final checkpoint validation and crop;
 * fence two is freshly acquired at the same injected policy version and stays
 * held across every disposal operation. Byte-identical completed stages replay
 * idempotently while the outer lease prevents concurrent restaging races.
 */
async function runRetentionEpochUnderLease(
  options: RunRetentionEpochOptions,
): Promise<RunRetentionEpochResult> {
  validateCoordinatorInputs(options);
  const epoch = (options.previousCheckpoint?.epoch ?? 0) + 1;
  const epochInput = {
    tenantId: options.tenantId,
    epoch,
    previousCheckpoint: options.previousCheckpoint,
    records: options.records,
    ...(options.segmentRecordCount === undefined ? {} : { segmentRecordCount: options.segmentRecordCount }),
  };
  const manifest = options.archive.deriveEpoch(epochInput);

  const checkpointInput: RetentionCheckpointInput = {
    checkpointId: options.checkpoint.checkpointId,
    tenantId: options.tenantId,
    chainKind: "audit",
    epoch,
    fromSequence: manifest.fromSequence,
    fromPreviousHash: manifest.fromPreviousHash,
    throughSequence: manifest.throughSequence,
    throughHash: manifest.throughHash,
    recordCount: manifest.recordCount,
    archiveRootHash: manifest.archiveRootHash,
    previousCheckpointHash: options.previousCheckpoint?.hash ?? null,
    createdAt: options.checkpoint.createdAt,
  };
  const checkpoint = options.createCheckpoint(checkpointInput);
  assertCheckpointFactoryBinding(checkpoint, checkpointInput);
  assertVerifiedCheckpoint(checkpoint, options.verification);

  const preflightCheckpoints = await options.store.listCheckpoints({ tenantId: options.tenantId });
  const preflightCheckpoint = preflightCheckpoints.find((candidate) => candidate.epoch === checkpoint.epoch);
  if (preflightCheckpoint && canonicalJson(preflightCheckpoint) !== canonicalJson(checkpoint)) {
    throw new TypeError("retention checkpoint replay conflict");
  }
  const preflightDisposition = (await options.store.listDispositions({ tenantId: options.tenantId })).find(
    (candidate) => candidate.checkpointHash === checkpoint.hash,
  );
  if (preflightDisposition) {
    if (!preflightCheckpoint) throw new TypeError("retention disposition checkpoint is missing");
    const expectedReceipt = createAndVerifyDisposition(options, checkpoint);
    if (canonicalJson(preflightDisposition) !== canonicalJson(expectedReceipt)) {
      throw new TypeError("retention disposition replay conflict");
    }
    if (!(await options.archive.confirmEpochAbsent(manifest))) {
      throw new TypeError("staged retention epoch is present after confirmed disposition");
    }
    return {
      manifest: cloneManifest(manifest),
      checkpoint: cloneCheckpoint(checkpoint),
      disposition: cloneDisposition(preflightDisposition),
    };
  }

  if (!preflightCheckpoint) {
    const sealedManifest = await options.archive.sealEpoch(epochInput);
    if (canonicalJson(sealedManifest) !== canonicalJson(manifest)) {
      throw new TypeError("staged retention manifest derivation mismatch");
    }
    const archiveVerification = await options.archive.verifyEpoch(manifest);
    if (!archiveVerification.ok) {
      throw new TypeError("staged retention epoch verification failed");
    }
    if (archiveVerification.archiveRootHash !== manifest.archiveRootHash) {
      throw new TypeError("staged retention archive root mismatch");
    }
  }

  await options.withPolicyFence(options.eligibility.version, async () => {
    assertVerifiedCheckpoint(checkpoint, options.verification);
    const checkpoints = await options.store.listCheckpoints({ tenantId: options.tenantId });
    const storedAtEpoch = checkpoints.find((candidate) => candidate.epoch === checkpoint.epoch);
    if (storedAtEpoch) {
      if (canonicalJson(storedAtEpoch) !== canonicalJson(checkpoint)) {
        throw new TypeError("retention checkpoint replay conflict");
      }
      return;
    }
    if (options.expectedState.retentionPolicyFence !== options.eligibility.version) {
      throw new TypeError("retention policy fence mismatch");
    }
    await options.store.compactRange(
      { tenantId: options.tenantId },
      checkpoint,
      cloneChainState(options.expectedState),
      options.eligibility.version,
    );
  });

  const disposition = await options.withPolicyFence(options.eligibility.version, async () => {
    const currentState = await options.store.getChainState({ tenantId: options.tenantId });
    if (currentState.retentionPolicyFence !== options.eligibility.version) {
      throw new TypeError("retention policy fence mismatch");
    }
    const storedCheckpoint = (await options.store.listCheckpoints({ tenantId: options.tenantId })).find(
      (candidate) => candidate.hash === checkpoint.hash,
    );
    if (!storedCheckpoint || canonicalJson(storedCheckpoint) !== canonicalJson(checkpoint)) {
      throw new TypeError("retention checkpoint was not durably compacted");
    }

    const accepted = (await options.store.listDispositions({ tenantId: options.tenantId })).find(
      (candidate) => candidate.checkpointHash === checkpoint.hash,
    );
    if (accepted) {
      const expectedReceipt = createAndVerifyDisposition(options, checkpoint);
      if (canonicalJson(accepted) !== canonicalJson(expectedReceipt)) {
        throw new TypeError("retention disposition replay conflict");
      }
      if (!(await options.archive.confirmEpochAbsent(manifest))) {
        throw new TypeError("staged retention epoch is present after confirmed disposition");
      }
      return accepted;
    }

    const attempt = await options.store.prepareDisposition(
      { tenantId: options.tenantId },
      checkpoint.hash,
      {
        attemptId: options.disposition.attemptId,
        checkpointHash: checkpoint.hash,
        policyFence: options.eligibility.version,
        status: "pending",
      },
      options.eligibility.version,
    );
    if (
      attempt.attemptId !== options.disposition.attemptId ||
      attempt.checkpointHash !== checkpoint.hash ||
      attempt.policyFence !== options.eligibility.version ||
      attempt.status !== "pending"
    ) {
      throw new TypeError("prepared disposition attempt binding mismatch");
    }

    await options.archive.deleteEpoch(manifest);
    if (!(await options.archive.confirmEpochAbsent(manifest))) {
      throw new TypeError("staged retention epoch deletion is unconfirmed");
    }
    const receipt = createAndVerifyDisposition(options, checkpoint);
    await options.store.confirmDisposition(
      { tenantId: options.tenantId },
      receipt,
      attempt.attemptId,
      options.eligibility.version,
    );
    return receipt;
  });

  return {
    manifest: cloneManifest(manifest),
    checkpoint: cloneCheckpoint(checkpoint),
    disposition: cloneDisposition(disposition),
  };
}

/** Creates only protocol-minimal receipt fields and verifies host signing policy before persistence. */
function createAndVerifyDisposition(
  options: RunRetentionEpochOptions,
  checkpoint: RetentionCheckpoint,
): RetentionDisposition {
  const input: RetentionDispositionInput = {
    dispositionId: options.disposition.dispositionId,
    tenantId: options.tenantId,
    chainKind: "audit",
    checkpointHash: checkpoint.hash,
    fromSequence: checkpoint.fromSequence,
    throughSequence: checkpoint.throughSequence,
    archiveRootHash: checkpoint.archiveRootHash,
    policyReference: options.eligibility.policyReference,
    disposedAt: options.disposition.disposedAt,
  };
  const receipt = options.createDisposition(input);
  assertDispositionFactoryBinding(receipt, input);
  const verification = verifyRetentionDisposition(receipt, checkpoint, options.verification ?? {});
  if (!verification.ok) throw new TypeError(`invalid retention disposition: ${verification.reason}`);
  return receipt;
}

/** Rejects ineligible, malformed, or stale caller authority before any provider write occurs. */
function validateCoordinatorInputs(options: RunRetentionEpochOptions): void {
  assertId(options.tenantId, "tenantId");
  if (options.eligibility.eligible !== true) throw new TypeError("retention epoch is not eligible");
  assertPolicyReference(options.eligibility.policyReference);
  assertFence(options.eligibility.version);
  assertId(options.checkpoint.checkpointId, "checkpointId");
  assertId(options.disposition.attemptId, "attemptId");
  assertId(options.disposition.dispositionId, "dispositionId");
  if (options.records.length === 0) throw new TypeError("retention epoch requires at least one record");
  if (options.previousCheckpoint !== null && options.previousCheckpoint.tenantId !== options.tenantId) {
    throw new TypeError("previous checkpoint tenant mismatch");
  }
}

/** Re-verifies checkpoint shape, hash, and injected signature requirement inside crop fence one. */
function assertVerifiedCheckpoint(
  checkpoint: RetentionCheckpoint,
  verificationOptions: RetentionVerificationOptions | undefined,
): void {
  const verification = verifyRetentionCheckpoint(checkpoint, verificationOptions ?? {});
  if (!verification.ok) throw new TypeError(`invalid retention checkpoint: ${verification.reason}`);
}

/** Ensures a host signing callback changes only optional signature fields, never coordinator-owned binding fields. */
function assertCheckpointFactoryBinding(
  checkpoint: RetentionCheckpoint,
  input: RetentionCheckpointInput,
): void {
  const bound =
    checkpoint.checkpointId === input.checkpointId &&
    checkpoint.tenantId === input.tenantId &&
    checkpoint.chainKind === input.chainKind &&
    checkpoint.epoch === input.epoch &&
    checkpoint.fromSequence === input.fromSequence &&
    checkpoint.fromPreviousHash === input.fromPreviousHash &&
    checkpoint.throughSequence === input.throughSequence &&
    checkpoint.throughHash === input.throughHash &&
    checkpoint.recordCount === input.recordCount &&
    checkpoint.archiveRootHash === input.archiveRootHash &&
    checkpoint.previousCheckpointHash === input.previousCheckpointHash &&
    checkpoint.createdAt === input.createdAt;
  if (!bound) throw new TypeError("checkpoint factory changed coordinator-owned fields");
}

/** Ensures receipt creation cannot add or alter range, tenant, policy, provider method, or time bindings. */
function assertDispositionFactoryBinding(
  receipt: RetentionDisposition,
  input: RetentionDispositionInput,
): void {
  const bound =
    receipt.dispositionId === input.dispositionId &&
    receipt.tenantId === input.tenantId &&
    receipt.chainKind === input.chainKind &&
    receipt.checkpointHash === input.checkpointHash &&
    receipt.fromSequence === input.fromSequence &&
    receipt.throughSequence === input.throughSequence &&
    receipt.archiveRootHash === input.archiveRootHash &&
    receipt.policyReference === input.policyReference &&
    receipt.disposedAt === input.disposedAt &&
    receipt.method === "provider-delete";
  if (!bound) throw new TypeError("disposition factory changed coordinator-owned fields");
}

/** Clones the crop CAS snapshot so a store cannot mutate caller-owned expected state. */
function cloneChainState(state: AuditChainState): AuditChainState {
  return { ...state };
}

/** Clones physical segment lookups before returning a derived manifest to the host. */
function cloneManifest(manifest: RetentionStagingManifest): RetentionStagingManifest {
  return { ...manifest, segments: manifest.segments.map((segment) => ({ ...segment })) };
}

/** Clones optional detached checkpoint signature fields without retaining mutable references. */
function cloneCheckpoint(checkpoint: RetentionCheckpoint): RetentionCheckpoint {
  return {
    ...checkpoint,
    ...(checkpoint.signature ? { signature: { ...checkpoint.signature } } : {}),
  };
}

/** Clones optional detached receipt signature fields without exposing authoritative store state. */
function cloneDisposition(disposition: RetentionDisposition): RetentionDisposition {
  return {
    ...disposition,
    ...(disposition.signature ? { signature: { ...disposition.signature } } : {}),
  };
}

/** Requires the retention protocol's bounded portable identifier alphabet. */
function assertId(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw new TypeError(`${field} is invalid`);
}

/** Requires a non-personal bounded policy reference without raw legal or user narratives. */
function assertPolicyReference(value: unknown): asserts value is string {
  if (typeof value !== "string" || !POLICY_REFERENCE_PATTERN.test(value)) {
    throw new TypeError("policyReference is invalid");
  }
}

/** Requires the store-compatible non-negative exact monotonic fence version. */
function assertFence(value: unknown): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("retention policy fence is invalid");
  }
}
