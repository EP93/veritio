import { createHash, randomUUID } from "node:crypto";
import {
  verifyRetentionCheckpoint,
  verifyRetentionDisposition,
  type RetentionCheckpoint,
  type RetentionDisposition,
} from "./retention.js";

export const SCHEMA_VERSION = "2026-06-10";
export const EDGE_SCHEMA_VERSION = "2026-06-13";
export const EVIDENCE_COMMIT_SCHEMA_VERSION = "2026-06-23";
export const HASH_ALGORITHM = "sha256";
export const EVIDENCE_COMMIT_TREE_ALGORITHM = "veritio-merkle-v1";
const ACTION_PATTERN = /^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$/;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;

export const EVIDENCE_ENTITY_TYPES = [
  "tenant",
  "principal",
  "actor",
  "activity",
  "change",
  "revision",
  "assertion",
  "record",
  "evidence_commit",
  "data_subject",
  "resource",
  "data_category",
  "purpose",
  "policy",
  "consent",
  "processor",
  "system",
  "repository",
  "branch",
  "commit",
  "pull_request",
  "file",
  "diff_hunk",
  "agent_session",
  "activity_episode",
  "tool_call",
  "ci_run",
  "artifact",
  "deployment",
  "runtime_event",
  "subject_request",
  "export_bundle",
] as const;

export const EVIDENCE_EDGE_RELATIONS = [
  "caused_by",
  "part_of",
  "read",
  "modified",
  "created",
  "deleted",
  "derived_from",
  "reviewed_by",
  "approved_by",
  "waived_by",
  "built_by",
  "deployed_as",
  "observed_in",
  "attests_to",
  "exports",
  "satisfies_policy",
  "violates_policy",
  "subject_of",
  "processed_for",
  "retained_under",
  "sent_to",
  "has_activity",
  "has_input",
  "has_output",
  "has_assertion",
  "resulted_in",
  "performed_by",
  "used",
  "generated",
  "based_on",
  "asserts_about",
  "retracts",
  "corrects",
  "supersedes",
  "disputes",
  "confirms",
  "compensates",
] as const;

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export type ActorType = "user" | "system" | "service" | "ai_agent" | "anonymous";

export interface Principal {
  type: ActorType;
  id: string;
  display?: string;
}

export interface Resource {
  type: string;
  id: string;
  display?: string;
}

export interface EvidenceScope {
  tenantId?: string;
  workspaceId?: string;
  environment?: string;
}

export type EvidenceEntityType = (typeof EVIDENCE_ENTITY_TYPES)[number];
export type EvidenceEdgeRelation = (typeof EVIDENCE_EDGE_RELATIONS)[number];

export interface EvidenceEntity {
  type: EvidenceEntityType;
  id: string;
  actorType?: "user" | "service" | "system" | "ai_agent";
  resourceType?: string;
  version?: string;
  pathHash?: string;
}

export interface EvidenceEdgeInput {
  id?: string;
  occurredAt?: string | Date;
  scope?: EvidenceScope;
  from: EvidenceEntity;
  relation: EvidenceEdgeRelation;
  to: EvidenceEntity;
  metadata?: Record<string, unknown>;
}

export interface EvidenceEdge {
  id: string;
  schemaVersion: typeof EDGE_SCHEMA_VERSION;
  occurredAt: string;
  scope?: EvidenceScope;
  from: EvidenceEntity;
  relation: EvidenceEdgeRelation;
  to: EvidenceEntity;
  metadata: JsonObject;
}

export type LawfulBasis =
  | "consent"
  | "contract"
  | "legal_obligation"
  | "vital_interests"
  | "public_task"
  | "legitimate_interests"
  | "not_applicable";

export interface AuditEventInput {
  id?: string;
  occurredAt?: string | Date;
  actor: Principal;
  action: string;
  target: Resource;
  scope?: EvidenceScope;
  requestId?: string;
  purpose?: string;
  lawfulBasis?: LawfulBasis;
  dataCategories?: string[];
  retention?: string;
  metadata?: Record<string, unknown>;
}

export interface AuditEvent {
  id: string;
  schemaVersion: typeof SCHEMA_VERSION;
  occurredAt: string;
  actor: Principal;
  action: string;
  target: Resource;
  scope?: EvidenceScope;
  requestId?: string;
  purpose?: string;
  lawfulBasis?: LawfulBasis;
  dataCategories?: string[];
  retention?: string;
  metadata: JsonObject;
}

export interface AuditRecord {
  event: AuditEvent;
  sequence: number;
  previousHash: string | null;
  hash: string;
  hashAlgorithm: typeof HASH_ALGORITHM;
  canonicalization: "veritio-json-v1";
  appendedAt: string;
  idempotencyKeyHash: string;
}

export interface EvidenceEdgeRecord {
  edge: EvidenceEdge;
  sequence: number;
  previousHash: string | null;
  hash: string;
  hashAlgorithm: typeof HASH_ALGORITHM;
  canonicalization: "veritio-json-v1";
  appendedAt: string;
  idempotencyKeyHash: string;
}

export type EvidenceCommitMemberRecordType =
  | "audit.record"
  | "evidence.edge.record"
  | "entity.revision.record"
  | "activity.record"
  | "assertion.record"
  | "change.record";

export interface EvidenceCommitMember {
  index: number;
  recordType: EvidenceCommitMemberRecordType;
  recordId: string;
  recordHash: string;
}

export interface EvidenceCommitInput {
  commitId: string;
  streamId: string;
  sequence: number;
  previousCommitHash: string | null;
  members: EvidenceCommitMember[];
  committedAt?: string | Date;
}

export interface EvidenceCommit {
  recordType: "evidence.commit";
  schemaVersion: typeof EVIDENCE_COMMIT_SCHEMA_VERSION;
  commitId: string;
  streamId: string;
  sequence: number;
  previousCommitHash: string | null;
  members: EvidenceCommitMember[];
  recordCount: number;
  recordsRoot: string;
  canonicalization: "veritio-json-v1";
  hashAlgorithm: typeof HASH_ALGORITHM;
  treeAlgorithm: typeof EVIDENCE_COMMIT_TREE_ALGORITHM;
  committedAt: string;
  hash: string;
}

export interface AuditStoreAppendOptions {
  idempotencyKey?: string;
  expectedPreviousHash?: string | null;
}

export interface AuditStoreListOptions {
  afterSequence?: number;
  limit?: number;
}

export interface AuditStore {
  append(event: AuditEvent, options?: AuditStoreAppendOptions): Promise<AuditRecord>;
  list(scope: EvidenceScope & { tenantId: string }, options?: AuditStoreListOptions): Promise<AuditRecord[]>;
}

/**
 * Captures the authoritative tenant audit-chain tip and retention CAS boundary
 * independently from hot record rows so a fully cropped chain can still append.
 */
export interface AuditChainState {
  authoritativeTipSequence: number;
  authoritativeTipHash: string | null;
  minimumRetainedSequence: number;
  latestCheckpointHash: string | null;
  retentionPolicyFence: number;
}

/**
 * Names the opaque monotonic host-policy version used to fence destructive
 * retention operations without putting legal-hold details into OSS records.
 */
export type RetentionPolicyFence = number;

/**
 * Binds one provider-disposal attempt to a checkpoint and exact policy fence;
 * only the store may transition a pending attempt to disposed.
 */
export interface DispositionAttempt {
  attemptId: string;
  checkpointHash: string;
  policyFence: RetentionPolicyFence;
  status: "pending" | "disposed";
}

/**
 * Extends the source-compatible AuditStore with audit-only checkpoint crop and
 * disposition CAS operations; derived archives never implement this authority.
 */
export interface CheckpointingAuditStore extends AuditStore {
  getChainState(scope: EvidenceScope & { tenantId: string }): Promise<AuditChainState>;
  advanceRetentionPolicyFence(
    scope: EvidenceScope & { tenantId: string },
    expectedVersion: RetentionPolicyFence,
  ): Promise<RetentionPolicyFence>;
  compactRange(
    scope: EvidenceScope & { tenantId: string },
    checkpoint: RetentionCheckpoint,
    expected: AuditChainState,
    policyFence: RetentionPolicyFence,
  ): Promise<void>;
  listCheckpoints(scope: EvidenceScope & { tenantId: string }): Promise<RetentionCheckpoint[]>;
  prepareDisposition(
    scope: EvidenceScope & { tenantId: string },
    checkpointHash: string,
    attempt: DispositionAttempt,
    expectedPolicyFence: RetentionPolicyFence,
  ): Promise<DispositionAttempt>;
  confirmDisposition(
    scope: EvidenceScope & { tenantId: string },
    receipt: RetentionDisposition,
    expectedAttemptId: string,
    expectedPolicyFence: RetentionPolicyFence,
  ): Promise<void>;
  listDispositions(scope: EvidenceScope & { tenantId: string }): Promise<RetentionDisposition[]>;
}

export interface AuditRecorder {
  record(input: AuditEventInput, options?: AuditStoreAppendOptions): Promise<AuditRecord>;
}

export type VerificationResult =
  | { ok: true }
  | {
      ok: false;
      index: number;
      reason:
        | "missing_tenant_scope"
        | "unsupported_hash_algorithm"
        | "unsupported_canonicalization"
        | "sequence_mismatch"
        | "previous_hash_mismatch"
        | "hash_mismatch";
    };

export type EvidenceCommitVerificationResult =
  | { ok: true }
  | {
      ok: false;
      index: number;
      reason:
        | "unsupported_hash_algorithm"
        | "unsupported_canonicalization"
        | "unsupported_tree_algorithm"
        | "sequence_mismatch"
        | "previous_hash_mismatch"
        | "record_count_mismatch"
        | "records_root_mismatch"
        | "hash_mismatch"
        | "invalid_member_manifest";
    };

const SENSITIVE_KEY_PATTERN = /(password|secret|token|api[_-]?key|authorization|email|phone|ssn)/i;

/**
 * Produces the protocol canonical JSON string used by hashing and fixtures.
 * Object keys are sorted, undefined object fields are omitted, array holes become
 * null, and unsupported numeric/object values fail before they can affect hashes.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalizeForJson(value));
}

/**
 * Normalizes host-provided audit input into the language-neutral audit event
 * contract while enforcing action format, required actor/target fields, sorted
 * data categories, and deterministic metadata redaction.
 */
export function createAuditEvent(input: AuditEventInput): AuditEvent {
  assertNonEmpty(input.actor?.id, "actor.id");
  assertNonEmpty(input.actor?.type, "actor.type");
  assertNonEmpty(input.action, "action");
  assertNonEmpty(input.target?.id, "target.id");
  assertNonEmpty(input.target?.type, "target.type");
  if (!ACTION_PATTERN.test(input.action)) {
    throw new TypeError("action must use dotted lowercase protocol form");
  }

  const event: AuditEvent = {
    id: input.id ?? `evt_${randomUUID()}`,
    schemaVersion: SCHEMA_VERSION,
    occurredAt: normalizeDate(input.occurredAt ?? new Date()),
    actor: cleanPrincipal(input.actor),
    action: input.action,
    target: cleanResource(input.target),
    metadata: redactMetadata(input.metadata ?? {}),
  };

  const scope = input.scope ? cleanScope(input.scope) : undefined;
  if (scope) {
    event.scope = scope;
  }
  if (input.requestId) {
    event.requestId = input.requestId;
  }
  if (input.purpose) {
    event.purpose = input.purpose;
  }
  if (input.lawfulBasis) {
    event.lawfulBasis = input.lawfulBasis;
  }
  if (input.dataCategories?.length) {
    event.dataCategories = [...new Set(input.dataCategories)].sort();
  }
  if (input.retention) {
    event.retention = input.retention;
  }

  return event;
}

/**
 * Creates a portable evidence-graph edge without changing audit-event
 * semantics. Entity and relation validation stays here so hosted products cannot
 * invent framework-specific graph vocabulary.
 */
export function createEvidenceEdge(input: EvidenceEdgeInput): EvidenceEdge {
  const from = cleanEvidenceEntity(input.from, "from");
  const to = cleanEvidenceEntity(input.to, "to");
  if (!isEvidenceEdgeRelation(input.relation)) {
    throw new TypeError("relation must be a supported evidence graph relation");
  }

  const edge: EvidenceEdge = {
    id: input.id ?? `edge_${randomUUID()}`,
    schemaVersion: EDGE_SCHEMA_VERSION,
    occurredAt: normalizeDate(input.occurredAt ?? new Date()),
    from,
    relation: input.relation,
    to,
    metadata: redactMetadata(input.metadata ?? {}),
  };

  const scope = input.scope ? cleanScope(input.scope) : undefined;
  if (scope) {
    edge.scope = scope;
  }

  return edge;
}

/**
 * Hashes an audit event together with the previous chain hash. This is the
 * event-level link used by conformance fixtures and must remain stable across
 * the TypeScript, Python, and Go SDKs.
 */
export function hashAuditEvent(event: AuditEvent, previousHash: string | null = null): string {
  return sha256Hex(
    canonicalJson({
      event,
      previousHash,
    }),
  );
}

/**
 * Hashes an evidence edge together with the previous edge-chain hash. It mirrors
 * audit-event hashing so graph records can be verified independently.
 */
export function hashEvidenceEdge(edge: EvidenceEdge, previousHash: string | null = null): string {
  return sha256Hex(
    canonicalJson({
      edge,
      previousHash,
    }),
  );
}

/**
 * Recomputes the envelope hash for an audit record while excluding the stored
 * hash field itself. Storage adapters use this to detect tampering after read.
 */
export function hashAuditRecord(record: AuditRecord | Omit<AuditRecord, "hash">): string {
  const { hash: _hash, ...hashInput } = record as AuditRecord;
  return sha256Hex(canonicalJson(hashInput));
}

/**
 * Recomputes the envelope hash for an evidence-edge record while excluding the
 * stored hash field itself. Verifiers rely on this to prove graph-chain integrity.
 */
export function hashEvidenceEdgeRecord(record: EvidenceEdgeRecord | Omit<EvidenceEdgeRecord, "hash">): string {
  const { hash: _hash, ...hashInput } = record as EvidenceEdgeRecord;
  return sha256Hex(canonicalJson(hashInput));
}

/**
 * Creates an EvidenceCommit that binds an ordered manifest of already-persisted
 * evidence records. The commit hash is algorithm-qualified and does not rewrite
 * existing v1 audit or edge record hashes.
 */
export function createEvidenceCommit(input: EvidenceCommitInput): EvidenceCommit {
  assertNonEmpty(input.commitId, "commitId");
  assertNonEmpty(input.streamId, "streamId");
  assertPositiveInteger(input.sequence, "sequence");
  if (input.previousCommitHash !== null && !isSha256Digest(input.previousCommitHash)) {
    throw new TypeError("previousCommitHash must be null or sha256 digest");
  }

  const members = normalizeCommitMembers(input.members);
  const recordsRoot = computeRecordsRoot(members);
  const commitWithoutHash: Omit<EvidenceCommit, "hash"> = {
    recordType: "evidence.commit",
    schemaVersion: EVIDENCE_COMMIT_SCHEMA_VERSION,
    commitId: input.commitId,
    streamId: input.streamId,
    sequence: input.sequence,
    previousCommitHash: input.previousCommitHash,
    members,
    recordCount: members.length,
    recordsRoot,
    canonicalization: "veritio-json-v1",
    hashAlgorithm: HASH_ALGORITHM,
    treeAlgorithm: EVIDENCE_COMMIT_TREE_ALGORITHM,
    committedAt: normalizeDate(input.committedAt ?? new Date()),
  };

  return {
    ...commitWithoutHash,
    hash: hashEvidenceCommit(commitWithoutHash),
  };
}

/**
 * Recomputes the EvidenceCommit hash from canonical fields excluding `hash`.
 * The domain marker keeps commit hashes separate from v1 record envelope hashes.
 */
export function hashEvidenceCommit(commit: EvidenceCommit | Omit<EvidenceCommit, "hash">): string {
  const { hash: _hash, ...commitWithoutHash } = commit as EvidenceCommit;
  return prefixedSha256(
    canonicalJson({
      domain: "veritio-commit-v1",
      commit: commitWithoutHash,
    }),
  );
}

/**
 * Verifies EvidenceCommit chains per stream. A valid chain starts at sequence 1
 * with `previousCommitHash: null`, then increments by one and points to the
 * previous commit hash for that stream.
 *
 * Verification scope (v1): this proves the commit LEDGER's internal
 * consistency only — sequence/previous-hash linkage, member-manifest shape,
 * Merkle root, and commit hash. It deliberately does NOT reconcile
 * `member.recordHash` against independently verified records, so a fabricated
 * commit chain over fabricated hashes verifies `ok` in isolation. Per-record
 * integrity comes from `verifyAuditRecords`/`verifyEvidenceEdgeRecords`;
 * compose both (as the reference server's `verify()` does) for end-to-end
 * evidence verification. See spec/evidence-commit-hashing.md.
 */
export function verifyEvidenceCommits(commits: readonly EvidenceCommit[]): EvidenceCommitVerificationResult {
  const streamState = new Map<string, { previousHash: string | null; sequence: number }>();

  for (const [index, commit] of commits.entries()) {
    if (commit.hashAlgorithm !== HASH_ALGORITHM) {
      return { ok: false, index, reason: "unsupported_hash_algorithm" };
    }
    if (commit.canonicalization !== "veritio-json-v1") {
      return { ok: false, index, reason: "unsupported_canonicalization" };
    }
    if (commit.treeAlgorithm !== EVIDENCE_COMMIT_TREE_ALGORITHM) {
      return { ok: false, index, reason: "unsupported_tree_algorithm" };
    }
    // Defensive parity with the Python verifier: commits arriving from
    // untrusted JSON may not honor the compile-time type, so a missing/empty
    // streamId or a non-string hash fails closed instead of keying a stream
    // on undefined or comparing against a non-string.
    if (typeof commit.streamId !== "string" || commit.streamId.length === 0) {
      return { ok: false, index, reason: "invalid_member_manifest" };
    }
    if (typeof commit.hash !== "string") {
      return { ok: false, index, reason: "hash_mismatch" };
    }

    const state = streamState.get(commit.streamId) ?? { previousHash: null, sequence: 0 };
    if (commit.previousCommitHash !== state.previousHash) {
      return { ok: false, index, reason: "previous_hash_mismatch" };
    }
    if (commit.sequence !== state.sequence + 1) {
      return { ok: false, index, reason: "sequence_mismatch" };
    }

    let members: EvidenceCommitMember[];
    try {
      members = normalizeCommitMembers(commit.members);
    } catch {
      return { ok: false, index, reason: "invalid_member_manifest" };
    }
    if (commit.recordCount !== members.length) {
      return { ok: false, index, reason: "record_count_mismatch" };
    }
    if (commit.recordsRoot !== computeRecordsRoot(members)) {
      return { ok: false, index, reason: "records_root_mismatch" };
    }
    if (commit.hash !== hashEvidenceCommit(commit)) {
      return { ok: false, index, reason: "hash_mismatch" };
    }

    streamState.set(commit.streamId, {
      previousHash: commit.hash,
      sequence: commit.sequence,
    });
  }

  return { ok: true };
}

/**
 * Verifies tenant-scoped audit records as independent hash chains. The verifier
 * fails closed on missing tenant scope, unsupported envelope metadata, sequence
 * gaps, previous-hash mismatches, and record-hash tampering.
 */
export function verifyAuditRecords(records: readonly AuditRecord[]): VerificationResult {
  const tenantState = new Map<string, { previousHash: string | null; sequence: number }>();

  for (const [index, record] of records.entries()) {
    if (!record.event.scope?.tenantId) {
      return { ok: false, index, reason: "missing_tenant_scope" };
    }
    if (record.hashAlgorithm !== HASH_ALGORITHM) {
      return { ok: false, index, reason: "unsupported_hash_algorithm" };
    }
    if (record.canonicalization !== "veritio-json-v1") {
      return { ok: false, index, reason: "unsupported_canonicalization" };
    }

    const state = tenantState.get(record.event.scope.tenantId) ?? { previousHash: null, sequence: 0 };
    if (record.sequence !== state.sequence + 1) {
      return { ok: false, index, reason: "sequence_mismatch" };
    }
    if (record.previousHash !== state.previousHash) {
      return { ok: false, index, reason: "previous_hash_mismatch" };
    }

    const expectedHash = hashAuditRecord(record);
    if (record.hash !== expectedHash) {
      return { ok: false, index, reason: "hash_mismatch" };
    }

    tenantState.set(record.event.scope.tenantId, {
      previousHash: record.hash,
      sequence: record.sequence,
    });
  }

  return { ok: true };
}

/**
 * Verifies tenant-scoped evidence-edge records using the same envelope rules as
 * audit records while keeping graph chains separate from audit-event chains.
 */
export function verifyEvidenceEdgeRecords(records: readonly EvidenceEdgeRecord[]): VerificationResult {
  const tenantState = new Map<string, { previousHash: string | null; sequence: number }>();

  for (const [index, record] of records.entries()) {
    if (!record.edge.scope?.tenantId) {
      return { ok: false, index, reason: "missing_tenant_scope" };
    }
    if (record.hashAlgorithm !== HASH_ALGORITHM) {
      return { ok: false, index, reason: "unsupported_hash_algorithm" };
    }
    if (record.canonicalization !== "veritio-json-v1") {
      return { ok: false, index, reason: "unsupported_canonicalization" };
    }

    const state = tenantState.get(record.edge.scope.tenantId) ?? { previousHash: null, sequence: 0 };
    if (record.sequence !== state.sequence + 1) {
      return { ok: false, index, reason: "sequence_mismatch" };
    }
    if (record.previousHash !== state.previousHash) {
      return { ok: false, index, reason: "previous_hash_mismatch" };
    }

    const expectedHash = hashEvidenceEdgeRecord(record);
    if (record.hash !== expectedHash) {
      return { ok: false, index, reason: "hash_mismatch" };
    }

    tenantState.set(record.edge.scope.tenantId, {
      previousHash: record.hash,
      sequence: record.sequence,
    });
  }

  return { ok: true };
}

/**
 * Wraps an injected AuditStore with the minimal recorder API used by adapters.
 * The SDK never reads host environment state directly; callers inject storage at
 * the application boundary.
 */
export function createAuditRecorder(options: { store: AuditStore }): AuditRecorder {
  return {
    async record(input, appendOptions) {
      return options.store.append(createAuditEvent(input), appendOptions);
    },
  };
}

/**
 * Local-only AuditStore implementation for tests, examples, and Workbench
 * scenarios. It preserves tenant isolation, idempotency replay, and hash-chain
 * semantics without implying production durability.
 */
export class MemoryAuditStore implements CheckpointingAuditStore {
  #records: AuditRecord[] = [];
  #idempotencyRecords = new Map<
    string,
    { eventCanonicalHash: string; originalSequence: number; originalRecordHash: string; record?: AuditRecord }
  >();
  #tenantChainStates = new Map<string, AuditChainState>();
  #tenantCheckpoints = new Map<string, RetentionCheckpoint[]>();
  #tenantDispositionAttempts = new Map<string, Map<string, DispositionAttempt>>();
  #tenantDispositions = new Map<string, Map<string, RetentionDisposition>>();

  /**
   * Appends one audit event to the tenant-local in-memory hash chain. Idempotent
   * replays return the original record, while conflicting payloads or stale chain
   * tips fail closed.
   */
  async append(event: AuditEvent, options: AuditStoreAppendOptions = {}): Promise<AuditRecord> {
    const tenantId = requireTenantId(event);
    const idempotencyKeyHash = hashIdempotencyKey(tenantId, options.idempotencyKey ?? event.id);
    const eventCanonical = canonicalJson(event);
    const eventCanonicalHash = sha256Hex(eventCanonical);
    const storedEvent = cloneEvent(event);
    const existing = this.#idempotencyRecords.get(idempotencyKeyHash);
    if (existing) {
      if (existing.eventCanonicalHash !== eventCanonicalHash) {
        throw new TypeError("idempotency conflict");
      }
      if (!existing.record) {
        throw new TypeError("idempotency_history_disposed");
      }
      return cloneRecord(existing.record);
    }

    const chainState = this.#chainState(tenantId);
    const previousHash = chainState.authoritativeTipHash;
    if (options.expectedPreviousHash !== undefined && options.expectedPreviousHash !== previousHash) {
      throw new TypeError("expectedPreviousHash does not match tenant chain tip");
    }

    const recordWithoutHash: Omit<AuditRecord, "hash"> = {
      event: storedEvent,
      sequence: chainState.authoritativeTipSequence + 1,
      previousHash,
      hashAlgorithm: HASH_ALGORITHM,
      canonicalization: "veritio-json-v1",
      appendedAt: new Date().toISOString(),
      idempotencyKeyHash,
    };
    const record: AuditRecord = {
      ...recordWithoutHash,
      hash: hashAuditRecord(recordWithoutHash),
    };

    this.#records.push(record);
    this.#tenantChainStates.set(tenantId, {
      ...chainState,
      authoritativeTipSequence: record.sequence,
      authoritativeTipHash: record.hash,
    });
    this.#idempotencyRecords.set(idempotencyKeyHash, {
      eventCanonicalHash,
      originalSequence: record.sequence,
      originalRecordHash: record.hash,
      record,
    });
    return cloneRecord(record);
  }

  /**
   * Lists cloned tenant records after an optional sequence boundary. Callers must
   * provide tenant scope so one tenant cannot observe another tenant's chain.
   */
  async list(scope: EvidenceScope & { tenantId: string }, options: AuditStoreListOptions = {}): Promise<AuditRecord[]> {
    assertNonEmpty(scope.tenantId, "scope.tenantId");
    if (options.limit !== undefined && (!Number.isInteger(options.limit) || options.limit < 0)) {
      throw new TypeError("limit must be a non-negative integer");
    }
    if (
      options.afterSequence !== undefined &&
      (!Number.isInteger(options.afterSequence) || options.afterSequence < 0)
    ) {
      throw new TypeError("afterSequence must be a non-negative integer");
    }

    const afterSequence = options.afterSequence ?? 0;
    const records = this.#records.filter((record) => {
      return record.event.scope?.tenantId === scope.tenantId && record.sequence > afterSequence;
    });
    const limited = options.limit === undefined ? records : records.slice(0, options.limit);
    return limited.map(cloneRecord);
  }

  /**
   * Returns the minimal authoritative tenant state even when compaction removed
   * every hot row, keeping append sequence and hash authority intact.
   */
  async getChainState(scope: EvidenceScope & { tenantId: string }): Promise<AuditChainState> {
    assertNonEmpty(scope.tenantId, "scope.tenantId");
    return cloneAuditChainState(this.#chainState(scope.tenantId));
  }

  /**
   * Atomically increments the opaque retention-policy fence only when the host
   * presents the exact current version, allowing queued hold changes to win.
   */
  async advanceRetentionPolicyFence(
    scope: EvidenceScope & { tenantId: string },
    expectedVersion: RetentionPolicyFence,
  ): Promise<RetentionPolicyFence> {
    assertNonEmpty(scope.tenantId, "scope.tenantId");
    assertRetentionPolicyFence(expectedVersion);
    const current = this.#chainState(scope.tenantId);
    if (current.retentionPolicyFence !== expectedVersion) {
      throw new TypeError("retention policy fence mismatch");
    }
    if (!Number.isSafeInteger(current.retentionPolicyFence + 1)) {
      throw new TypeError("retention policy fence exhausted");
    }
    const next = current.retentionPolicyFence + 1;
    this.#tenantChainStates.set(scope.tenantId, { ...current, retentionPolicyFence: next });
    return next;
  }

  /**
   * Validates an exact audit-prefix checkpoint and all CAS boundaries before one
   * in-memory commit crops hot rows, tombstones idempotency, and advances state.
   */
  async compactRange(
    scope: EvidenceScope & { tenantId: string },
    checkpoint: RetentionCheckpoint,
    expected: AuditChainState,
    policyFence: RetentionPolicyFence,
  ): Promise<void> {
    assertNonEmpty(scope.tenantId, "scope.tenantId");
    assertRetentionPolicyFence(policyFence);
    assertAuditChainState(expected);
    const current = this.#chainState(scope.tenantId);
    if (!auditChainStatesEqual(current, expected)) {
      throw new TypeError("audit chain state mismatch");
    }
    if (policyFence !== current.retentionPolicyFence || expected.retentionPolicyFence !== policyFence) {
      throw new TypeError("retention policy fence mismatch");
    }
    const checkpointVerification = verifyRetentionCheckpoint(checkpoint);
    if (!checkpointVerification.ok) {
      throw new TypeError(`invalid retention checkpoint: ${checkpointVerification.reason}`);
    }
    if (checkpoint.tenantId !== scope.tenantId || checkpoint.chainKind !== "audit") {
      throw new TypeError("checkpoint tenant or chain kind mismatch");
    }

    const checkpoints = this.#tenantCheckpoints.get(scope.tenantId) ?? [];
    const previousCheckpoint = checkpoints.at(-1);
    if (
      checkpoint.epoch !== checkpoints.length + 1 ||
      checkpoint.previousCheckpointHash !== (previousCheckpoint?.hash ?? null) ||
      checkpoint.fromSequence !== current.minimumRetainedSequence ||
      checkpoint.fromPreviousHash !== (previousCheckpoint?.throughHash ?? null)
    ) {
      throw new TypeError("checkpoint prefix or prior checkpoint mismatch");
    }
    if (checkpoint.throughSequence > current.authoritativeTipSequence) {
      throw new TypeError("checkpoint range exceeds authoritative tip");
    }

    const coveredRecords = this.#records
      .filter(
        (record) =>
          record.event.scope?.tenantId === scope.tenantId &&
          record.sequence >= checkpoint.fromSequence &&
          record.sequence <= checkpoint.throughSequence,
      )
      .sort((left, right) => left.sequence - right.sequence);
    if (coveredRecords.length !== checkpoint.recordCount) {
      throw new TypeError("checkpoint range is not an intact hot prefix");
    }
    let expectedPreviousHash = checkpoint.fromPreviousHash;
    for (const [index, record] of coveredRecords.entries()) {
      if (
        record.sequence !== checkpoint.fromSequence + index ||
        record.previousHash !== expectedPreviousHash ||
        hashAuditRecord(record) !== record.hash
      ) {
        throw new TypeError("checkpoint range failed authoritative integrity validation");
      }
      expectedPreviousHash = record.hash;
    }
    if (expectedPreviousHash !== checkpoint.throughHash) {
      throw new TypeError("checkpoint throughHash does not match authoritative boundary");
    }

    const coveredIdempotencyHashes = new Set(coveredRecords.map((record) => record.idempotencyKeyHash));
    const retainedRecords = this.#records.filter(
      (record) =>
        record.event.scope?.tenantId !== scope.tenantId ||
        record.sequence < checkpoint.fromSequence ||
        record.sequence > checkpoint.throughSequence,
    );
    const storedCheckpoints = [...checkpoints, cloneRetentionCheckpoint(checkpoint)];
    const nextState: AuditChainState = {
      ...current,
      minimumRetainedSequence: checkpoint.throughSequence + 1,
      latestCheckpointHash: checkpoint.hash,
    };

    this.#records = retainedRecords;
    for (const idempotencyKeyHash of coveredIdempotencyHashes) {
      const entry = this.#idempotencyRecords.get(idempotencyKeyHash);
      if (entry) {
        this.#idempotencyRecords.set(idempotencyKeyHash, {
          eventCanonicalHash: entry.eventCanonicalHash,
          originalSequence: entry.originalSequence,
          originalRecordHash: entry.originalRecordHash,
        });
      }
    }
    this.#tenantCheckpoints.set(scope.tenantId, storedCheckpoints);
    this.#tenantChainStates.set(scope.tenantId, nextState);
  }

  /**
   * Lists cloned tenant checkpoints in epoch order so callers cannot mutate the
   * authoritative anchors used by later crops and disposal receipt validation.
   */
  async listCheckpoints(scope: EvidenceScope & { tenantId: string }): Promise<RetentionCheckpoint[]> {
    assertNonEmpty(scope.tenantId, "scope.tenantId");
    return (this.#tenantCheckpoints.get(scope.tenantId) ?? []).map(cloneRetentionCheckpoint);
  }

  /**
   * Creates or idempotently replays a pending disposition attempt, allowing a
   * crashed attempt to be rebound only to the same checkpoint at a newer fence.
   */
  async prepareDisposition(
    scope: EvidenceScope & { tenantId: string },
    checkpointHash: string,
    attempt: DispositionAttempt,
    expectedPolicyFence: RetentionPolicyFence,
  ): Promise<DispositionAttempt> {
    assertNonEmpty(scope.tenantId, "scope.tenantId");
    assertNonEmpty(checkpointHash, "checkpointHash");
    assertDispositionAttempt(attempt);
    assertRetentionPolicyFence(expectedPolicyFence);
    const current = this.#chainState(scope.tenantId);
    if (current.retentionPolicyFence !== expectedPolicyFence || attempt.policyFence !== expectedPolicyFence) {
      throw new TypeError("retention policy fence mismatch");
    }
    if (attempt.status !== "pending" || attempt.checkpointHash !== checkpointHash) {
      throw new TypeError("disposition attempt binding mismatch");
    }
    const checkpoint = (this.#tenantCheckpoints.get(scope.tenantId) ?? []).find(
      (candidate) => candidate.hash === checkpointHash,
    );
    if (!checkpoint) {
      throw new TypeError("disposition checkpoint not found");
    }
    if (this.#tenantDispositions.get(scope.tenantId)?.has(checkpointHash)) {
      throw new TypeError("checkpoint disposition already confirmed");
    }

    const attempts = this.#tenantDispositionAttempts.get(scope.tenantId) ?? new Map<string, DispositionAttempt>();
    const existing = attempts.get(checkpointHash);
    if (existing) {
      if (canonicalJson(existing) === canonicalJson(attempt)) {
        return cloneDispositionAttempt(existing);
      }
      if (existing.status !== "pending" || attempt.policyFence <= existing.policyFence) {
        throw new TypeError("disposition attempt conflict");
      }
    }

    const storedAttempt = cloneDispositionAttempt(attempt);
    attempts.set(checkpointHash, storedAttempt);
    this.#tenantDispositionAttempts.set(scope.tenantId, attempts);
    return cloneDispositionAttempt(storedAttempt);
  }

  /**
   * Verifies a receipt against its checkpoint and atomically CASes the current
   * pending attempt plus policy fence before accepting one unique disposition.
   */
  async confirmDisposition(
    scope: EvidenceScope & { tenantId: string },
    receipt: RetentionDisposition,
    expectedAttemptId: string,
    expectedPolicyFence: RetentionPolicyFence,
  ): Promise<void> {
    assertNonEmpty(scope.tenantId, "scope.tenantId");
    assertNonEmpty(expectedAttemptId, "expectedAttemptId");
    assertRetentionPolicyFence(expectedPolicyFence);
    const current = this.#chainState(scope.tenantId);
    if (current.retentionPolicyFence !== expectedPolicyFence) {
      throw new TypeError("retention policy fence mismatch");
    }
    const attempts = this.#tenantDispositionAttempts.get(scope.tenantId);
    const attemptEntry = [...(attempts?.entries() ?? [])].find(([, attempt]) => attempt.attemptId === expectedAttemptId);
    if (!attemptEntry) {
      throw new TypeError("disposition attempt mismatch");
    }
    const [checkpointHash, attempt] = attemptEntry;
    if (attempt.policyFence !== expectedPolicyFence || attempt.checkpointHash !== checkpointHash) {
      throw new TypeError("disposition attempt fence mismatch");
    }
    const checkpoint = (this.#tenantCheckpoints.get(scope.tenantId) ?? []).find(
      (candidate) => candidate.hash === checkpointHash,
    );
    if (!checkpoint) {
      throw new TypeError("disposition checkpoint not found");
    }
    const dispositions = this.#tenantDispositions.get(scope.tenantId) ?? new Map<string, RetentionDisposition>();
    const existing = dispositions.get(checkpointHash);
    if (existing) {
      if (attempt.status === "disposed" && canonicalJson(existing) === canonicalJson(receipt)) {
        return;
      }
      throw new TypeError("conflicting disposition receipt");
    }
    if (attempt.status !== "pending") {
      throw new TypeError("disposition attempt is not pending");
    }
    const receiptVerification = verifyRetentionDisposition(receipt, checkpoint);
    if (!receiptVerification.ok) {
      throw new TypeError(`invalid retention disposition: ${receiptVerification.reason}`);
    }

    dispositions.set(checkpointHash, cloneRetentionDisposition(receipt));
    attempts?.set(checkpointHash, { ...attempt, status: "disposed" });
    this.#tenantDispositions.set(scope.tenantId, dispositions);
  }

  /**
   * Lists cloned accepted receipts in checkpoint epoch order, never exposing
   * pending attempts or mutable authoritative disposition state.
   */
  async listDispositions(scope: EvidenceScope & { tenantId: string }): Promise<RetentionDisposition[]> {
    assertNonEmpty(scope.tenantId, "scope.tenantId");
    const dispositions = this.#tenantDispositions.get(scope.tenantId);
    return (this.#tenantCheckpoints.get(scope.tenantId) ?? [])
      .map((checkpoint) => dispositions?.get(checkpoint.hash))
      .filter((receipt): receipt is RetentionDisposition => receipt !== undefined)
      .map(cloneRetentionDisposition);
  }

  /**
   * Returns a cloned snapshot for local verification and tests without exposing
   * mutable references to the store's internal record array.
   */
  records(): AuditRecord[] {
    return this.#records.map(cloneRecord);
  }

  /**
   * Reads an existing authoritative chain-state row or supplies the untouched
   * tenant genesis state without persisting unnecessary empty tenant entries.
   */
  #chainState(tenantId: string): AuditChainState {
    return this.#tenantChainStates.get(tenantId) ?? {
      authoritativeTipSequence: 0,
      authoritativeTipHash: null,
      minimumRetainedSequence: 1,
      latestCheckpointHash: null,
      retentionPolicyFence: 0,
    };
  }
}

/**
 * Applies deterministic metadata redaction before metadata enters canonical JSON
 * or hashes. Sensitive key names are redacted recursively rather than persisted.
 */
function redactMetadata(value: Record<string, unknown>): JsonObject {
  return redactAny(value, "") as JsonObject;
}

/**
 * Recursively converts arbitrary metadata into protocol JSON while replacing
 * sensitive-key values with the stable redaction marker.
 */
function redactAny(value: unknown, key: string): JsonValue {
  if (SENSITIVE_KEY_PATTERN.test(key)) {
    const digestEnvelope = sanitizeDigestEnvelope(value);
    if (digestEnvelope) {
      return digestEnvelope;
    }
    return "[redacted]";
  }

  if (value === undefined) {
    return null;
  }

  if (value == null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("metadata numbers must be finite");
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactAny(item, key));
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value === "object") {
    const digestEnvelope = sanitizeDigestEnvelope(value);
    if (digestEnvelope) {
      return digestEnvelope;
    }
    const result: JsonObject = {};
    for (const objectKey of Object.keys(value as Record<string, unknown>).sort()) {
      const objectValue = (value as Record<string, unknown>)[objectKey];
      if (objectValue !== undefined) {
        result[objectKey] = redactAny(objectValue, objectKey);
      }
    }
    return result;
  }

  return String(value);
}

/**
 * Allows only the minimized digest envelope fields to survive key-name
 * redaction. This keeps governed revision commitments useful for fields such as
 * `customerEmail` without letting sibling raw values or key material ride along.
 */
function sanitizeDigestEnvelope(value: unknown): JsonObject | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return undefined;
  }
  const envelope = value as Record<string, unknown>;
  const digest = envelope.digest;
  if (typeof digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(digest)) {
    return undefined;
  }
  if (
    Object.hasOwn(envelope, "canonicalization") ||
    Object.hasOwn(envelope, "schemaRef") ||
    Object.hasOwn(envelope, "fieldSetRef") ||
    Object.hasOwn(envelope, "fields")
  ) {
    return undefined;
  }

  if (envelope.algorithm === "hmac-sha256") {
    return typeof envelope.keyVersion === "string" && envelope.keyVersion.trim().length > 0
      ? { algorithm: "hmac-sha256", digest, keyVersion: envelope.keyVersion }
      : undefined;
  }

  if (envelope.algorithm === "sha256") {
    return { algorithm: "sha256", digest };
  }

  if (
    envelope.captureMode === "content_digest" ||
    envelope.captureMode === "randomized_digest" ||
    envelope.captureMode === "reference" ||
    envelope.captureMode === "redact" ||
    envelope.captureMode === "encrypt"
  ) {
    return { captureMode: envelope.captureMode, digest };
  }

  return undefined;
}

/**
 * Converts arbitrary values into the canonical JSON domain used by hashing.
 * Sorting and undefined handling live here so every hash entrypoint shares one
 * deterministic representation.
 */
function normalizeForJson(value: unknown): JsonValue | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (value == null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("JSON numbers must be finite");
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => normalizeForJson(item) ?? null);
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value === "object") {
    const result: JsonObject = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const normalized = normalizeForJson((value as Record<string, unknown>)[key]);
      if (normalized !== undefined) {
        result[key] = normalized;
      }
    }
    return result;
  }

  throw new TypeError(`unsupported JSON value type: ${typeof value}`);
}

/**
 * Accepts Date objects or date strings and emits an ISO timestamp. Invalid dates
 * fail before they become part of an auditable record.
 */
function normalizeDate(value: string | Date): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new TypeError("occurredAt must be a valid date");
  }
  return date.toISOString();
}

/**
 * Enforces required string fields at the SDK boundary with consistent errors.
 */
function assertNonEmpty(value: unknown, field: string): void {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${field} is required`);
  }
}

/**
 * Requires positive integer sequence values before they enter hash inputs.
 */
function assertPositiveInteger(value: unknown, field: string): void {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new TypeError(`${field} must be a positive integer`);
  }
}

/**
 * Normalizes and validates the ordered EvidenceCommit member manifest. Duplicate
 * indices or duplicate physical record identities fail rather than being
 * silently de-duplicated.
 */
function normalizeCommitMembers(members: readonly EvidenceCommitMember[]): EvidenceCommitMember[] {
  if (!Array.isArray(members) || members.length === 0) {
    throw new TypeError("members must not be empty");
  }
  const sorted = members.map(cleanCommitMember).sort((left, right) => left.index - right.index);
  const identities = new Set<string>();
  for (const [expectedIndex, member] of sorted.entries()) {
    if (member.index !== expectedIndex) {
      throw new TypeError("member indices must be contiguous from zero");
    }
    const identity = `${member.recordType}\u0000${member.recordId}`;
    if (identities.has(identity)) {
      throw new TypeError("duplicate commit member");
    }
    identities.add(identity);
  }
  return sorted;
}

/**
 * Validates one EvidenceCommit member and strips unknown fields before hashing.
 */
function cleanCommitMember(member: EvidenceCommitMember): EvidenceCommitMember {
  if (typeof member.index !== "number" || !Number.isInteger(member.index) || member.index < 0) {
    throw new TypeError("member index must be a non-negative integer");
  }
  if (!isEvidenceCommitMemberRecordType(member.recordType)) {
    throw new TypeError("recordType must be a supported commit member record type");
  }
  assertNonEmpty(member.recordId, "recordId");
  if (!isSha256Digest(member.recordHash)) {
    throw new TypeError("recordHash must be a sha256 digest");
  }
  return {
    index: member.index,
    recordType: member.recordType,
    recordId: member.recordId,
    recordHash: member.recordHash,
  };
}

/**
 * Computes the Merkle root for sorted commit members. Odd levels duplicate the
 * final hash at that level, matching the PR5 conformance fixture.
 */
function computeRecordsRoot(members: readonly EvidenceCommitMember[]): string {
  let level = members.map((member) => commitLeafHash(member));
  while (level.length > 1) {
    const nextLevel: string[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index]!;
      const right = level[index + 1] ?? left;
      nextLevel.push(
        prefixedSha256(
          canonicalJson({
            domain: "veritio-merkle-node-v1",
            left,
            right,
          }),
        ),
      );
    }
    level = nextLevel;
  }
  return level[0]!;
}

/**
 * Hashes one ordered commit member leaf with an explicit domain separator.
 */
function commitLeafHash(member: EvidenceCommitMember): string {
  return prefixedSha256(
    canonicalJson({
      domain: "veritio-record-leaf-v1",
      index: member.index,
      recordType: member.recordType,
      recordId: member.recordId,
      recordHash: member.recordHash,
    }),
  );
}

/**
 * Narrows commit member record types to the initial physical record vocabulary.
 */
function isEvidenceCommitMemberRecordType(value: unknown): value is EvidenceCommitMemberRecordType {
  return (
    value === "audit.record" ||
    value === "evidence.edge.record" ||
    value === "entity.revision.record" ||
    value === "activity.record" ||
    value === "assertion.record" ||
    value === "change.record"
  );
}

/**
 * Checks algorithm-qualified SHA-256 digests used by EvidenceCommit v2 fields.
 */
function isSha256Digest(value: unknown): value is string {
  return typeof value === "string" && SHA256_DIGEST_PATTERN.test(value);
}

/**
 * Returns a protocol principal without carrying undefined or extra host fields.
 */
function cleanPrincipal(value: Principal): Principal {
  return value.display
    ? { type: value.type, id: value.id, display: value.display }
    : { type: value.type, id: value.id };
}

/**
 * Returns a protocol resource without carrying undefined or extra host fields.
 */
function cleanResource(value: Resource): Resource {
  return value.display
    ? { type: value.type, id: value.id, display: value.display }
    : { type: value.type, id: value.id };
}

/**
 * Validates evidence graph entities against the public vocabulary and strips any
 * non-protocol fields before the edge is hashed or exported.
 */
function cleanEvidenceEntity(value: EvidenceEntity, field: string): EvidenceEntity {
  assertNonEmpty(value?.type, `${field}.type`);
  assertNonEmpty(value?.id, `${field}.id`);
  if (!isEvidenceEntityType(value.type)) {
    throw new TypeError(`${field}.type must be a supported evidence graph entity type`);
  }

  const entity: EvidenceEntity = { type: value.type, id: value.id };
  if (value.actorType) {
    entity.actorType = value.actorType;
  }
  if (value.resourceType) {
    entity.resourceType = value.resourceType;
  }
  if (value.version) {
    entity.version = value.version;
  }
  if (value.pathHash) {
    entity.pathHash = value.pathHash;
  }
  return entity;
}

/**
 * Narrows a string to the supported evidence entity vocabulary.
 */
function isEvidenceEntityType(value: string): value is EvidenceEntityType {
  return (EVIDENCE_ENTITY_TYPES as readonly string[]).includes(value);
}

/**
 * Narrows a string to the supported evidence-edge relation vocabulary.
 */
function isEvidenceEdgeRelation(value: string): value is EvidenceEdgeRelation {
  return (EVIDENCE_EDGE_RELATIONS as readonly string[]).includes(value);
}

/**
 * Normalizes optional scope fields while preserving tenant/workspace/environment
 * names exactly as supplied by the host boundary.
 */
function cleanScope(value: EvidenceScope): EvidenceScope | undefined {
  const scope: EvidenceScope = {};
  if (value.tenantId) {
    scope.tenantId = value.tenantId;
  }
  if (value.workspaceId) {
    scope.workspaceId = value.workspaceId;
  }
  if (value.environment) {
    scope.environment = value.environment;
  }
  return Object.keys(scope).length > 0 ? scope : undefined;
}

/**
 * Requires tenant scope before appending to any audit chain. Tenantless records
 * are rejected because they cannot be isolated or verified safely.
 */
function requireTenantId(event: AuditEvent): string {
  const tenantId = event.scope?.tenantId;
  if (typeof tenantId !== "string" || tenantId.trim().length === 0) {
    throw new TypeError("scope.tenantId is required");
  }
  return tenantId;
}

/**
 * Hashes idempotency keys with the tenant id so the same host key cannot collide
 * across tenant chains.
 */
export function hashIdempotencyKey(tenantId: string, idempotencyKey: string): string {
  assertNonEmpty(tenantId, "tenantId");
  assertNonEmpty(idempotencyKey, "idempotencyKey");
  return sha256Hex(`${tenantId}\u0000${idempotencyKey}`);
}

/**
 * Deep-clones audit events before storage returns them so callers cannot mutate
 * stored evidence after append.
 */
function cloneEvent(event: AuditEvent): AuditEvent {
  return JSON.parse(JSON.stringify(event)) as AuditEvent;
}

/**
 * Deep-clones audit records before exposing them to callers or test fixtures.
 */
function cloneRecord(record: AuditRecord): AuditRecord {
  return JSON.parse(JSON.stringify(record)) as AuditRecord;
}

/**
 * Clones authoritative chain CAS state before returning it across the store
 * boundary so callers cannot mutate a later expected-state comparison.
 */
function cloneAuditChainState(state: AuditChainState): AuditChainState {
  return { ...state };
}

/**
 * Clones checkpoint protocol records, including optional detached signatures,
 * before storing or returning an authoritative retention anchor.
 */
function cloneRetentionCheckpoint(checkpoint: RetentionCheckpoint): RetentionCheckpoint {
  return JSON.parse(JSON.stringify(checkpoint)) as RetentionCheckpoint;
}

/**
 * Clones disposition attempts so caller mutation cannot alter a pending or
 * disposed compare-and-swap binding after preparation.
 */
function cloneDispositionAttempt(attempt: DispositionAttempt): DispositionAttempt {
  return { ...attempt };
}

/**
 * Clones accepted disposition receipts before persistence or return, preserving
 * the byte-significant protocol fields while isolating mutable references.
 */
function cloneRetentionDisposition(disposition: RetentionDisposition): RetentionDisposition {
  return JSON.parse(JSON.stringify(disposition)) as RetentionDisposition;
}

/**
 * Validates the non-negative safe-integer policy version used by store CAS
 * operations; zero is the untouched tenant fence and remains a valid token.
 */
function assertRetentionPolicyFence(value: unknown): asserts value is RetentionPolicyFence {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("retention policy fence must be a non-negative safe integer");
  }
}

/**
 * Validates caller-supplied expected chain state before comparing it with the
 * authoritative snapshot, rejecting malformed state rather than coercing it.
 */
function assertAuditChainState(value: AuditChainState): void {
  if (
    typeof value !== "object" ||
    value === null ||
    !Number.isSafeInteger(value.authoritativeTipSequence) ||
    value.authoritativeTipSequence < 0 ||
    !Number.isSafeInteger(value.minimumRetainedSequence) ||
    value.minimumRetainedSequence < 1 ||
    value.minimumRetainedSequence > value.authoritativeTipSequence + 1 ||
    (value.authoritativeTipHash !== null && !/^[a-f0-9]{64}$/.test(value.authoritativeTipHash)) ||
    (value.latestCheckpointHash !== null && !/^[a-f0-9]{64}$/.test(value.latestCheckpointHash))
  ) {
    throw new TypeError("invalid audit chain state");
  }
  assertRetentionPolicyFence(value.retentionPolicyFence);
}

/**
 * Compares every authoritative crop boundary explicitly so omitted or stale
 * fields cannot accidentally satisfy a partial expected-state check.
 */
function auditChainStatesEqual(left: AuditChainState, right: AuditChainState): boolean {
  return (
    left.authoritativeTipSequence === right.authoritativeTipSequence &&
    left.authoritativeTipHash === right.authoritativeTipHash &&
    left.minimumRetainedSequence === right.minimumRetainedSequence &&
    left.latestCheckpointHash === right.latestCheckpointHash &&
    left.retentionPolicyFence === right.retentionPolicyFence
  );
}

/**
 * Validates the minimal non-personal attempt envelope before it can replace a
 * durable pending attempt or participate in disposition confirmation.
 */
function assertDispositionAttempt(attempt: DispositionAttempt): void {
  if (typeof attempt !== "object" || attempt === null) {
    throw new TypeError("invalid disposition attempt");
  }
  assertNonEmpty(attempt.attemptId, "attempt.attemptId");
  if (!/^[a-f0-9]{64}$/.test(attempt.checkpointHash)) {
    throw new TypeError("attempt.checkpointHash must be lowercase sha256");
  }
  assertRetentionPolicyFence(attempt.policyFence);
  if (attempt.status !== "pending" && attempt.status !== "disposed") {
    throw new TypeError("attempt.status is invalid");
  }
}

/**
 * Computes a lowercase SHA-256 hex digest, the only hash algorithm currently
 * accepted by the protocol envelope.
 */
function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * Computes an algorithm-qualified SHA-256 digest for EvidenceCommit fields while
 * leaving v1 audit/edge record hashes in their existing bare-hex shape.
 */
function prefixedSha256(value: string): string {
  return `sha256:${sha256Hex(value)}`;
}

export * from "./governed-change.js";
export * from "./provenance.js";
export * from "./risk.js";
export * from "./templates.js";
export {
  buildExportBundle,
  computeRootHash,
  parseExportBundle,
  serializeExportBundle,
  signExportBundle,
  verifyExportBundle,
} from "./export-bundle.js";
export type {
  ExportBundle,
  ExportBundleFileEntry,
  ExportBundleInput,
  ExportBundleManifest,
  ExportBundleSignature,
  ExportBundleVerificationReport,
} from "./export-bundle.js";
export { verifyAuditChainScoped, verifyEdgeChainScoped } from "./export-bundle-chain-modes.js";
export type { ExportBundleChainScope } from "./export-bundle-chain-modes.js";
export * from "./retention.js";
