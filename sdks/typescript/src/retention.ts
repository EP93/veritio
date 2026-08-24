import { createHash } from "node:crypto";
import type { AuditRecord } from "./index.js";
import { canonicalJson, hashAuditRecord } from "./index.js";

export const RETENTION_SCHEMA_VERSION = "1.0" as const;
export const RETENTION_CANONICALIZATION = "veritio-json-v1" as const;
export const RETENTION_HASH_ALGORITHM = "sha256" as const;

const ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const POLICY_REFERENCE_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const TIMESTAMP_PATTERN = /^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/;
const BASE64_SIGNATURE_PATTERN = /^[A-Za-z0-9+/]{86}==$/;

export interface RetentionSignature {
  algorithm: "ed25519";
  publicKeyFingerprint: string;
  signature: string;
}

export interface RetentionCheckpointInput {
  checkpointId: string;
  tenantId: string;
  chainKind: "audit";
  epoch: number;
  fromSequence: number;
  fromPreviousHash: string | null;
  throughSequence: number;
  throughHash: string;
  recordCount: number;
  archiveRootHash: string;
  previousCheckpointHash: string | null;
  createdAt: string;
  signaturePublicKeyFingerprint?: string;
}

export interface RetentionCheckpoint extends RetentionCheckpointInput {
  recordType: "retention.checkpoint";
  schemaVersion: typeof RETENTION_SCHEMA_VERSION;
  canonicalization: typeof RETENTION_CANONICALIZATION;
  hashAlgorithm: typeof RETENTION_HASH_ALGORITHM;
  hash: string;
  signature?: RetentionSignature;
}

export interface RetentionDispositionInput {
  dispositionId: string;
  tenantId: string;
  chainKind: "audit";
  checkpointHash: string;
  fromSequence: number;
  throughSequence: number;
  archiveRootHash: string;
  policyReference: string;
  disposedAt: string;
  signaturePublicKeyFingerprint?: string;
}

export interface RetentionDisposition extends RetentionDispositionInput {
  recordType: "retention.disposition";
  schemaVersion: typeof RETENTION_SCHEMA_VERSION;
  method: "provider-delete";
  canonicalization: typeof RETENTION_CANONICALIZATION;
  hashAlgorithm: typeof RETENTION_HASH_ALGORITHM;
  hash: string;
  signature?: RetentionSignature;
}

export type RetentionSignatureStatus = "valid" | "invalid" | "skipped" | "absent";

export interface RetentionVerificationOptions {
  trustedPublicKey?: Uint8Array;
  requireSignature?: boolean;
  signatureVerifier?: (publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array) => boolean;
}

export type RetentionVerificationReason =
  | "invalid_checkpoint"
  | "invalid_disposition"
  | "unsupported_protocol"
  | "hash_mismatch"
  | "signature_fingerprint_mismatch"
  | "signature_invalid"
  | "signature_required"
  | "tenant_mismatch"
  | "chain_kind_mismatch"
  | "epoch_mismatch"
  | "range_mismatch"
  | "previous_checkpoint_hash_mismatch"
  | "missing_tenant_scope"
  | "unsupported_hash_algorithm"
  | "unsupported_canonicalization"
  | "sequence_mismatch"
  | "previous_hash_mismatch"
  | "record_hash_mismatch"
  | "checkpoint_mismatch";

export type RetentionVerificationResult =
  | { ok: true; signature: RetentionSignatureStatus }
  | { ok: false; index: number; reason: RetentionVerificationReason; signature: RetentionSignatureStatus };

/**
 * Constructs an immutable audit-retention anchor from caller-owned identifiers
 * and time. The helper never reads a clock, generates randomness, or signs on
 * behalf of a host; an optional detached signature is attached only after its
 * fingerprint has been bound into the canonical unsigned payload hash.
 */
export function createRetentionCheckpoint(
  input: RetentionCheckpointInput,
  signature?: RetentionSignature,
): RetentionCheckpoint {
  assertCheckpointInput(input);
  assertSignaturePair(input.signaturePublicKeyFingerprint, signature);
  const unsigned = checkpointUnsigned(input);
  return {
    ...unsigned,
    hash: hashRetentionCheckpoint(unsigned),
    ...(signature ? { signature: normalizeSignature(signature) } : {}),
  };
}

/**
 * Hashes exactly the canonical unsigned checkpoint payload, excluding both the
 * stored hash and detached signature while retaining an optional key fingerprint.
 */
export function hashRetentionCheckpoint(
  checkpoint: RetentionCheckpoint | Omit<RetentionCheckpoint, "hash" | "signature">,
): string {
  return sha256(canonicalJson(checkpointHashPayload(checkpoint)));
}

/**
 * Verifies one checkpoint's protocol metadata, deterministic hash, and optional
 * detached signature through a caller-injected trust boundary.
 */
export function verifyRetentionCheckpoint(
  checkpoint: RetentionCheckpoint,
  options: RetentionVerificationOptions = {},
): RetentionVerificationResult {
  return verifyCheckpointAt(checkpoint, options, 0);
}

/**
 * Verifies a complete checkpoint chain from epoch one, including tenant scope,
 * exact range continuity, prior-tip linkage, and checkpoint-hash linkage.
 */
export function verifyRetentionCheckpointChain(
  checkpoints: readonly RetentionCheckpoint[],
  options: RetentionVerificationOptions = {},
): RetentionVerificationResult {
  let signature: RetentionSignatureStatus = checkpoints.length === 0 ? "absent" : "valid";
  for (const [index, checkpoint] of checkpoints.entries()) {
    const verified = verifyCheckpointAt(checkpoint, options, index);
    signature = combineSignatureStatus(signature, verified.signature);
    if (!verified.ok) return { ...verified, signature };

    const previous = checkpoints[index - 1]!;
    if (checkpoint.epoch !== index + 1) return failure(index, "epoch_mismatch", signature);
    if (index === 0) continue;
    if (checkpoint.tenantId !== previous.tenantId) return failure(index, "tenant_mismatch", signature);
    if (checkpoint.chainKind !== previous.chainKind) return failure(index, "chain_kind_mismatch", signature);
    if (
      checkpoint.fromSequence !== previous.throughSequence + 1 ||
      checkpoint.fromPreviousHash !== previous.throughHash
    ) {
      return failure(index, "range_mismatch", signature);
    }
    if (checkpoint.previousCheckpointHash !== previous.hash) {
      return failure(index, "previous_checkpoint_hash_mismatch", signature);
    }
  }
  return { ok: true, signature };
}

/**
 * Verifies retained tenant audit rows from a validated checkpoint anchor without
 * weakening the existing genesis-only verifier or re-hashing retained records.
 */
export function verifyAuditRecordsFromCheckpoint(
  checkpoint: RetentionCheckpoint,
  records: readonly AuditRecord[],
  options: RetentionVerificationOptions = {},
): RetentionVerificationResult {
  const checkpointResult = verifyRetentionCheckpoint(checkpoint, options);
  if (!checkpointResult.ok) return checkpointResult;
  let sequence = checkpoint.throughSequence;
  let previousHash = checkpoint.throughHash;
  for (const [index, record] of records.entries()) {
    if (!record.event.scope?.tenantId) return failure(index, "missing_tenant_scope", checkpointResult.signature);
    if (record.event.scope.tenantId !== checkpoint.tenantId) return failure(index, "tenant_mismatch", checkpointResult.signature);
    if (record.hashAlgorithm !== RETENTION_HASH_ALGORITHM) {
      return failure(index, "unsupported_hash_algorithm", checkpointResult.signature);
    }
    if (record.canonicalization !== RETENTION_CANONICALIZATION) {
      return failure(index, "unsupported_canonicalization", checkpointResult.signature);
    }
    if (record.sequence !== sequence + 1) return failure(index, "sequence_mismatch", checkpointResult.signature);
    if (record.previousHash !== previousHash) return failure(index, "previous_hash_mismatch", checkpointResult.signature);
    if (record.hash !== hashAuditRecord(record)) return failure(index, "record_hash_mismatch", checkpointResult.signature);
    sequence = record.sequence;
    previousHash = record.hash;
  }
  return checkpointResult;
}

/**
 * Constructs the minimal non-personal receipt retained after provider deletion.
 * The caller supplies all authority and timing inputs; core fixes the v1 method
 * and hashes the canonical unsigned payload without collecting provider details.
 */
export function createRetentionDisposition(
  input: RetentionDispositionInput,
  signature?: RetentionSignature,
): RetentionDisposition {
  assertDispositionInput(input);
  assertSignaturePair(input.signaturePublicKeyFingerprint, signature);
  const unsigned = dispositionUnsigned(input);
  return {
    ...unsigned,
    hash: hashRetentionDisposition(unsigned),
    ...(signature ? { signature: normalizeSignature(signature) } : {}),
  };
}

/**
 * Hashes the canonical unsigned disposition receipt so signatures bind the
 * checkpoint, range, archive digest, method, policy reference, and disposal time.
 */
export function hashRetentionDisposition(
  disposition: RetentionDisposition | Omit<RetentionDisposition, "hash" | "signature">,
): string {
  return sha256(canonicalJson(dispositionHashPayload(disposition)));
}

/**
 * Verifies a disposition's own integrity and signature, then requires exact
 * equality with the referenced checkpoint before accepting the disposal claim.
 */
export function verifyRetentionDisposition(
  disposition: RetentionDisposition,
  checkpoint: RetentionCheckpoint,
  options: RetentionVerificationOptions = {},
): RetentionVerificationResult {
  const checkpointResult = verifyRetentionCheckpoint(checkpoint, {
    ...(options.trustedPublicKey ? { trustedPublicKey: options.trustedPublicKey } : {}),
    ...(options.signatureVerifier ? { signatureVerifier: options.signatureVerifier } : {}),
  });
  if (!checkpointResult.ok) return checkpointResult;
  if (
    disposition.recordType !== "retention.disposition" ||
    disposition.schemaVersion !== RETENTION_SCHEMA_VERSION ||
    disposition.method !== "provider-delete" ||
    disposition.canonicalization !== RETENTION_CANONICALIZATION ||
    disposition.hashAlgorithm !== RETENTION_HASH_ALGORITHM
  ) {
    return failure(0, "unsupported_protocol", "absent");
  }
  try {
    assertDispositionInput(disposition);
  } catch {
    return failure(0, "invalid_disposition", "absent");
  }
  if (!HASH_PATTERN.test(disposition.hash) || disposition.hash !== hashRetentionDisposition(disposition)) {
    return failure(0, "hash_mismatch", "absent");
  }
  const signature = verifyDetachedSignature(disposition, options);
  if (signature.reason) return failure(0, signature.reason, signature.status);
  if (
    disposition.tenantId !== checkpoint.tenantId ||
    disposition.chainKind !== checkpoint.chainKind ||
    disposition.checkpointHash !== checkpoint.hash ||
    disposition.fromSequence !== checkpoint.fromSequence ||
    disposition.throughSequence !== checkpoint.throughSequence ||
    disposition.archiveRootHash !== checkpoint.archiveRootHash
  ) {
    return failure(0, "checkpoint_mismatch", signature.status);
  }
  return { ok: true, signature: signature.status };
}

/** Applies shape, hash, and injected-signature gates at a stable result index. */
function verifyCheckpointAt(
  checkpoint: RetentionCheckpoint,
  options: RetentionVerificationOptions,
  index: number,
): RetentionVerificationResult {
  if (
    checkpoint.recordType !== "retention.checkpoint" ||
    checkpoint.schemaVersion !== RETENTION_SCHEMA_VERSION ||
    checkpoint.canonicalization !== RETENTION_CANONICALIZATION ||
    checkpoint.hashAlgorithm !== RETENTION_HASH_ALGORITHM
  ) {
    return failure(index, "unsupported_protocol", "absent");
  }
  try {
    assertCheckpointInput(checkpoint);
  } catch {
    return failure(index, "invalid_checkpoint", "absent");
  }
  if (!HASH_PATTERN.test(checkpoint.hash) || checkpoint.hash !== hashRetentionCheckpoint(checkpoint)) {
    return failure(index, "hash_mismatch", "absent");
  }
  const signature = verifyDetachedSignature(checkpoint, options);
  if (signature.reason) return failure(index, signature.reason, signature.status);
  return { ok: true, signature: signature.status };
}

/** Validates detached signature metadata and invokes only the caller's verifier. */
function verifyDetachedSignature(
  record: RetentionCheckpoint | RetentionDisposition,
  options: RetentionVerificationOptions,
): { status: RetentionSignatureStatus; reason?: RetentionVerificationReason } {
  const fingerprint = record.signaturePublicKeyFingerprint;
  const signature = record.signature;
  if (!fingerprint && !signature) {
    return options.requireSignature ? { status: "absent", reason: "signature_required" } : { status: "absent" };
  }
  if (!fingerprint || !signature || signature.publicKeyFingerprint !== fingerprint) {
    return { status: "invalid", reason: "signature_fingerprint_mismatch" };
  }
  if (signature.algorithm !== "ed25519" || !BASE64_SIGNATURE_PATTERN.test(signature.signature)) {
    return { status: "invalid", reason: "signature_invalid" };
  }
  if (!options.trustedPublicKey || !options.signatureVerifier) {
    return options.requireSignature
      ? { status: "skipped", reason: "signature_required" }
      : { status: "skipped" };
  }
  if (sha256Bytes(options.trustedPublicKey) !== fingerprint) {
    return { status: "invalid", reason: "signature_fingerprint_mismatch" };
  }
  try {
    const signatureBytes = Uint8Array.from(Buffer.from(signature.signature, "base64"));
    const message = new TextEncoder().encode(record.hash);
    return options.signatureVerifier(options.trustedPublicKey, signatureBytes, message)
      ? { status: "valid" }
      : { status: "invalid", reason: "signature_invalid" };
  } catch {
    return { status: "invalid", reason: "signature_invalid" };
  }
}

/** Copies only normative checkpoint fields and fixes supported protocol metadata. */
function checkpointUnsigned(input: RetentionCheckpointInput): Omit<RetentionCheckpoint, "hash" | "signature"> {
  return {
    recordType: "retention.checkpoint",
    schemaVersion: RETENTION_SCHEMA_VERSION,
    checkpointId: input.checkpointId,
    tenantId: input.tenantId,
    chainKind: input.chainKind,
    epoch: input.epoch,
    fromSequence: input.fromSequence,
    fromPreviousHash: input.fromPreviousHash,
    throughSequence: input.throughSequence,
    throughHash: input.throughHash,
    recordCount: input.recordCount,
    archiveRootHash: input.archiveRootHash,
    previousCheckpointHash: input.previousCheckpointHash,
    createdAt: input.createdAt,
    canonicalization: RETENTION_CANONICALIZATION,
    hashAlgorithm: RETENTION_HASH_ALGORITHM,
    ...(input.signaturePublicKeyFingerprint
      ? { signaturePublicKeyFingerprint: input.signaturePublicKeyFingerprint }
      : {}),
  };
}

/** Copies the minimal receipt fields and fixes the v1 provider-delete method. */
function dispositionUnsigned(input: RetentionDispositionInput): Omit<RetentionDisposition, "hash" | "signature"> {
  return {
    recordType: "retention.disposition",
    schemaVersion: RETENTION_SCHEMA_VERSION,
    dispositionId: input.dispositionId,
    tenantId: input.tenantId,
    chainKind: input.chainKind,
    checkpointHash: input.checkpointHash,
    fromSequence: input.fromSequence,
    throughSequence: input.throughSequence,
    archiveRootHash: input.archiveRootHash,
    method: "provider-delete",
    policyReference: input.policyReference,
    disposedAt: input.disposedAt,
    canonicalization: RETENTION_CANONICALIZATION,
    hashAlgorithm: RETENTION_HASH_ALGORITHM,
    ...(input.signaturePublicKeyFingerprint
      ? { signaturePublicKeyFingerprint: input.signaturePublicKeyFingerprint }
      : {}),
  };
}

/** Selects actual unsigned checkpoint fields while excluding hash, signature, and host extras. */
function checkpointHashPayload(
  checkpoint: RetentionCheckpoint | Omit<RetentionCheckpoint, "hash" | "signature">,
): Record<string, unknown> {
  return {
    recordType: checkpoint.recordType,
    schemaVersion: checkpoint.schemaVersion,
    checkpointId: checkpoint.checkpointId,
    tenantId: checkpoint.tenantId,
    chainKind: checkpoint.chainKind,
    epoch: checkpoint.epoch,
    fromSequence: checkpoint.fromSequence,
    fromPreviousHash: checkpoint.fromPreviousHash,
    throughSequence: checkpoint.throughSequence,
    throughHash: checkpoint.throughHash,
    recordCount: checkpoint.recordCount,
    archiveRootHash: checkpoint.archiveRootHash,
    previousCheckpointHash: checkpoint.previousCheckpointHash,
    createdAt: checkpoint.createdAt,
    canonicalization: checkpoint.canonicalization,
    hashAlgorithm: checkpoint.hashAlgorithm,
    ...(checkpoint.signaturePublicKeyFingerprint
      ? { signaturePublicKeyFingerprint: checkpoint.signaturePublicKeyFingerprint }
      : {}),
  };
}

/** Selects actual unsigned receipt fields while excluding hash, signature, and host extras. */
function dispositionHashPayload(
  disposition: RetentionDisposition | Omit<RetentionDisposition, "hash" | "signature">,
): Record<string, unknown> {
  return {
    recordType: disposition.recordType,
    schemaVersion: disposition.schemaVersion,
    dispositionId: disposition.dispositionId,
    tenantId: disposition.tenantId,
    chainKind: disposition.chainKind,
    checkpointHash: disposition.checkpointHash,
    fromSequence: disposition.fromSequence,
    throughSequence: disposition.throughSequence,
    archiveRootHash: disposition.archiveRootHash,
    method: disposition.method,
    policyReference: disposition.policyReference,
    disposedAt: disposition.disposedAt,
    canonicalization: disposition.canonicalization,
    hashAlgorithm: disposition.hashAlgorithm,
    ...(disposition.signaturePublicKeyFingerprint
      ? { signaturePublicKeyFingerprint: disposition.signaturePublicKeyFingerprint }
      : {}),
  };
}

/** Copies only protocol signature fields so host extras never enter stored records. */
function normalizeSignature(signature: RetentionSignature): RetentionSignature {
  return {
    algorithm: signature.algorithm,
    publicKeyFingerprint: signature.publicKeyFingerprint,
    signature: signature.signature,
  };
}

/** Enforces portable ids, exact numbers/time, genesis rules, and range consistency. */
function assertCheckpointInput(input: RetentionCheckpointInput): void {
  assertId(input.checkpointId, "checkpointId");
  assertId(input.tenantId, "tenantId");
  if (input.chainKind !== "audit") throw new TypeError("chainKind must be audit");
  assertSafeInteger(input.epoch, "epoch");
  assertSafeInteger(input.fromSequence, "fromSequence");
  assertSafeInteger(input.throughSequence, "throughSequence");
  assertSafeInteger(input.recordCount, "recordCount");
  assertHash(input.throughHash, "throughHash");
  assertHash(input.archiveRootHash, "archiveRootHash");
  assertNullableHash(input.fromPreviousHash, "fromPreviousHash");
  assertNullableHash(input.previousCheckpointHash, "previousCheckpointHash");
  assertTimestamp(input.createdAt, "createdAt");
  if (input.signaturePublicKeyFingerprint !== undefined) {
    assertHash(input.signaturePublicKeyFingerprint, "signaturePublicKeyFingerprint");
  }
  if (input.throughSequence < input.fromSequence || input.recordCount !== input.throughSequence - input.fromSequence + 1) {
    throw new TypeError("recordCount must equal the inclusive checkpoint range");
  }
  if (input.epoch === 1) {
    if (input.fromSequence !== 1 || input.fromPreviousHash !== null || input.previousCheckpointHash !== null) {
      throw new TypeError("epoch one must begin at genesis");
    }
  } else if (input.fromPreviousHash === null || input.previousCheckpointHash === null) {
    throw new TypeError("later epochs must link prior record and checkpoint hashes");
  }
}

/** Enforces the minimal non-personal receipt vocabulary and ordered range. */
function assertDispositionInput(input: RetentionDispositionInput): void {
  assertId(input.dispositionId, "dispositionId");
  assertId(input.tenantId, "tenantId");
  if (input.chainKind !== "audit") throw new TypeError("chainKind must be audit");
  assertHash(input.checkpointHash, "checkpointHash");
  assertSafeInteger(input.fromSequence, "fromSequence");
  assertSafeInteger(input.throughSequence, "throughSequence");
  if (input.throughSequence < input.fromSequence) throw new TypeError("disposition range must be ordered");
  assertHash(input.archiveRootHash, "archiveRootHash");
  if (!POLICY_REFERENCE_PATTERN.test(input.policyReference)) throw new TypeError("policyReference is invalid");
  assertTimestamp(input.disposedAt, "disposedAt");
  if (input.signaturePublicKeyFingerprint !== undefined) {
    assertHash(input.signaturePublicKeyFingerprint, "signaturePublicKeyFingerprint");
  }
}

/** Requires fingerprints and detached signatures to be present or absent together. */
function assertSignaturePair(fingerprint: string | undefined, signature: RetentionSignature | undefined): void {
  if (Boolean(fingerprint) !== Boolean(signature)) throw new TypeError("signature and fingerprint must appear together");
  if (!signature) return;
  if (signature.algorithm !== "ed25519") throw new TypeError("signature algorithm must be ed25519");
  assertHash(signature.publicKeyFingerprint, "signature.publicKeyFingerprint");
  if (!BASE64_SIGNATURE_PATTERN.test(signature.signature)) throw new TypeError("signature must be padded base64");
}

/** Requires the bounded language-neutral identifier alphabet. */
function assertId(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw new TypeError(`${field} is invalid`);
}

/** Requires positive integers that remain exact in JavaScript, Python, and Go. */
function assertSafeInteger(value: unknown, field: string): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${field} must be a positive safe integer`);
  }
}

/** Requires the retention protocol's bare lowercase SHA-256 representation. */
function assertHash(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) throw new TypeError(`${field} must be lowercase sha256`);
}

/** Validates nullable prior-link hashes without accepting empty-string sentinels. */
function assertNullableHash(value: unknown, field: string): void {
  if (value !== null) assertHash(value, field);
}

/** Requires a real UTC instant rendered with exactly millisecond precision. */
function assertTimestamp(value: unknown, field: string): asserts value is string {
  if (
    typeof value !== "string" ||
    !TIMESTAMP_PATTERN.test(value) ||
    Number.isNaN(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new TypeError(`${field} must be exact UTC milliseconds`);
  }
}

/** Computes the bare lowercase SHA-256 digest used by portable retention records. */
function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Fingerprints raw trusted public-key bytes without changing their representation. */
function sha256Bytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Builds the shared fail-closed verifier result without leaking raw exceptions. */
function failure(
  index: number,
  reason: RetentionVerificationReason,
  signature: RetentionSignatureStatus,
): RetentionVerificationResult {
  return { ok: false, index, reason, signature };
}

/** Aggregates chain status with invalid and skipped states taking precedence. */
function combineSignatureStatus(
  current: RetentionSignatureStatus,
  next: RetentionSignatureStatus,
): RetentionSignatureStatus {
  if (current === "invalid" || next === "invalid") return "invalid";
  if (current === "skipped" || next === "skipped") return "skipped";
  if (current === "absent" || next === "absent") return "absent";
  return "valid";
}
