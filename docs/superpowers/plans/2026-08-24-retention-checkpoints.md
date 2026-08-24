# Retention Checkpoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the public audit-retention checkpoint protocol, authoritative compaction, staged disposal, and checkpoint-aware exports across Veritio libraries.

**Architecture:** Add immutable audit-only checkpoint/disposition records and anchored verification to core, then make retention-capable authoritative stores preserve chain state independently from hot rows. A separate derived staging archive verifies each epoch before atomic crop; `vevb-2` exports the retained tail and checkpoint chain without changing `vevb-1` bytes.

**Tech Stack:** JSON Schema 2020-12, TypeScript/Bun, Python 3.11, Go, PostgreSQL/MySQL/MongoDB adapters, Ed25519, NDJSON, Vitest/Bun test.

**Spec:** `docs/superpowers/specs/2026-08-24-retention-checkpoints-design.md`

## Global Constraints

- V1 retention compacts audit records only; evidence-edge, EvidenceCommit, `FileEvidenceStore`, ClickHouse, and `ObjectAuditArchive` remain non-capable.
- Sequences never reset; retained records are never rehashed; R2/S3 never becomes authoritative.
- IDs match `^[A-Za-z0-9._:-]{1,128}$`; policy references use the same alphabet up to 256 characters.
- Integers are `1..9007199254740991`; timestamps are exact UTC milliseconds.
- Existing `vevb-1` fixtures and bytes remain unchanged; checkpoint-aware exports are `vevb-2`.
- TypeScript, Python, and Go hashes and verification semantics must match shared fixtures.
- Every production function receives the documentation comment required by `AGENTS.md`.

---

### Task 1: Protocol Records and Cross-Language Core

**Files:**
- Create: `spec/retention-checkpoint.schema.json`, `spec/retention-disposition.schema.json`, `spec/retention-checkpoints.md`
- Create: `spec/conformance/retention-checkpoints.json`, `spec/conformance/retention-dispositions.json`
- Create: `sdks/typescript/src/retention.ts`, `sdks/typescript/src/__tests__/retention.test.ts`
- Create: `sdks/python/src/veritio/retention.py`, `sdks/python/tests/test_retention.py`
- Create: `sdks/go/retention.go`, `sdks/go/retention_test.go`
- Modify: `sdks/typescript/src/index.ts`, `sdks/python/src/veritio/__init__.py`

**Interfaces:**
- Produces: `createRetentionCheckpoint`, `hashRetentionCheckpoint`, `verifyRetentionCheckpointChain`, `verifyAuditRecordsFromCheckpoint`, `createRetentionDisposition`, and `verifyRetentionDisposition`, with snake_case and Go equivalents.

```ts
export interface RetentionCheckpointInput {
  checkpointId: string; tenantId: string; chainKind: "audit"; epoch: number;
  fromSequence: number; fromPreviousHash: string | null; throughSequence: number;
  throughHash: string; recordCount: number; archiveRootHash: string;
  previousCheckpointHash: string | null; createdAt: string;
  signaturePublicKeyFingerprint?: string;
}
```

- [ ] **Step 1: Add shared fixtures and failing TS/Python/Go tests.** Use literal expected hashes and rejection vectors for invalid IDs, unsafe integers, timestamp precision, range continuity, signature fingerprint, and disposition/checkpoint mismatch.
- [ ] **Step 2: Run the three focused suites and confirm they fail because retention APIs are absent.**

```sh
bun test sdks/typescript/src/__tests__/retention.test.ts
PYTHONPATH=sdks/python/src python3 -m unittest sdks.python.tests.test_retention
(cd sdks/go && go test ./... -run Retention)
```

- [ ] **Step 3: Implement the strict schemas and normative prose.** Hash the canonical unsigned payload, bind an optional key fingerprint before hashing, and sign the 64-character lowercase hash bytes.
- [ ] **Step 4: Implement TypeScript, Python, and Go from the same fixture semantics.** Python signature verification is injected through a callable so OSS core adds no mandatory crypto package; constructors and hash verification remain dependency-free.
- [ ] **Step 5: Run focused tests, typechecks, and commit.**

```sh
bun test sdks/typescript/src/__tests__/retention.test.ts
bun run --cwd sdks/typescript typecheck
PYTHONPATH=sdks/python/src python3 -m unittest sdks.python.tests.test_retention
(cd sdks/go && go test ./... -run Retention)
git add spec sdks/typescript sdks/python sdks/go
git commit -m "feat(core): add retention checkpoint protocol"
```

### Task 2: Retention-Capable Memory Store

**Files:**
- Modify: `sdks/typescript/src/index.ts`
- Create: `sdks/typescript/src/__tests__/retention-store.test.ts`

**Interfaces:**
- Produces: `CheckpointingAuditStore`, `AuditChainState`, `RetentionPolicyFence`, `DispositionAttempt`, and memory-store implementations of `advanceRetentionPolicyFence`, `compactRange`, `prepareDisposition`, `confirmDisposition`, `listCheckpoints`, and `listDispositions`.

```ts
export interface CheckpointingAuditStore extends AuditStore {
  getChainState(scope: EvidenceScope & { tenantId: string }): Promise<AuditChainState>;
  compactRange(scope: EvidenceScope & { tenantId: string }, checkpoint: RetentionCheckpoint, expected: AuditChainState, policyFence: number): Promise<void>;
  prepareDisposition(scope: EvidenceScope & { tenantId: string }, checkpointHash: string, attempt: DispositionAttempt, expectedPolicyFence: number): Promise<DispositionAttempt>;
  confirmDisposition(scope: EvidenceScope & { tenantId: string }, receipt: RetentionDisposition, expectedAttemptId: string, expectedPolicyFence: number): Promise<void>;
}
```

- [ ] **Step 1: Write failing behavioral tests.** Cover full-prefix crop followed by append, exact boundary CAS, stale fence, permanent minimal idempotency tombstones, byte-identical disposition replay, conflicting receipt, and crash retry that rebinds a stale attempt.
- [ ] **Step 2: Run the focused test and verify the missing interface/behavior failures.**

```sh
bun test sdks/typescript/src/__tests__/retention-store.test.ts
```

- [ ] **Step 3: Implement separate tenant chain state and idempotency ledger in `MemoryAuditStore`.** A disposed matching replay throws `idempotency_history_disposed`; a changed payload remains `idempotency conflict`.
- [ ] **Step 4: Implement atomic-in-memory crop and disposition CAS semantics without changing `AuditStore.append/list`.**
- [ ] **Step 5: Run all TS tests and commit.**

```sh
bun test sdks/typescript/src
git add sdks/typescript/src
git commit -m "feat(core): add checkpointing audit store contract"
```

### Task 3: SQL and Mongo Retention Adapters

**Files:**
- Modify: `storage/src/index.ts`, `storage/src/conformance.ts`, `storage/src/__tests__/index.test.ts`, `storage/integration/live-databases.test.ts`
- Create: `storage/src/retention-conformance.ts`

**Interfaces:**
- Consumes: `CheckpointingAuditStore` from Task 2.
- Produces: retention-capable PostgreSQL/Neon/MySQL/MariaDB/Mongo adapters and additive schema constants for chain state, idempotency ledger, checkpoints, disposition attempts, and receipts.

```sql
PRIMARY KEY (tenant_id);
UNIQUE (tenant_id, epoch);
UNIQUE (tenant_id, checkpoint_hash);
UNIQUE (tenant_id, idempotency_key_hash);
```

- [ ] **Step 1: Add failing shared conformance tests to every capable adapter.** The mutation each test catches is a wrong crop boundary, stale policy acceptance, reopened idempotency key, lost tip after full crop, or duplicate disposition.
- [ ] **Step 2: Run storage tests and confirm the new conformance suite fails.**

```sh
bun run --cwd storage test
```

- [ ] **Step 3: Add additive SQL/Mongo persistence and transactional adapter methods.** Lock chain state before append/crop; never derive the tip from remaining hot rows.
- [ ] **Step 4: Run unit and live database suites.**

```sh
bun run --cwd storage test
bun run --cwd storage db:up
bun run --cwd storage test:live
```

- [ ] **Step 5: Commit the adapter change.**

```sh
git add storage
git commit -m "feat(storage): add retention-capable audit stores"
```

### Task 4: Staging Archive and Coordinator

**Files:**
- Create: `storage/src/retention-staging-archive.ts`, `storage/src/retention-coordinator.ts`
- Create: `storage/src/__tests__/retention-staging-archive.test.ts`, `storage/src/__tests__/retention-coordinator.test.ts`
- Create: `storage/integration/retention-staging-minio.test.ts`
- Modify: `storage/src/index.ts`

**Interfaces:**
- Produces: `RetentionStagingClient`, `createRetentionStagingArchive`, and `runRetentionEpoch` with injected policy/fence inputs and no environment reads.

```ts
export interface RetentionStagingClient extends ObjectArchiveClient {
  delete(key: string): Promise<void>;
}
```

- [ ] **Step 1: Write failing tests for anchored epoch seal/verify, corrupted bytes, provider-neutral roots, deletion confirmed by get plus list, crop ordering, and hold-fence retry races.**
- [ ] **Step 2: Run focused tests and verify failure.**

```sh
bun test storage/src/__tests__/retention-staging-archive.test.ts storage/src/__tests__/retention-coordinator.test.ts
```

- [ ] **Step 3: Implement the separate staging archive; do not widen `ObjectAuditArchive`.**
- [ ] **Step 4: Implement the two-stage coordinator in the order `seal -> verify -> compact -> prepare -> delete -> confirm`.**
- [ ] **Step 5: Run focused, storage, and MinIO tests; commit.**

```sh
bun run --cwd storage test
bun test storage/integration/retention-staging-minio.test.ts
git add storage
git commit -m "feat(storage): add staged retention disposal"
```

### Task 5: VEVB-2 and CLI/Server Verification

**Files:**
- Create: `spec/export-bundle-v2.schema.json`, `spec/export-bundle-v2.md`, `spec/conformance/export-bundle-v2-golden.json`, `spec/conformance/export-bundle-v2-tampered.json`
- Create: `sdks/typescript/src/export-bundle-v2.ts`, `sdks/typescript/src/__tests__/export-bundle-v2.test.ts`
- Modify: `sdks/typescript/src/export-bundle.ts`, `sdks/typescript/src/index.ts`, `cli/src/index.ts`, `cli/src/__tests__/verify-bundle.test.ts`, `server/node/src/index.ts`, `server/node/src/__tests__/index.test.ts`

**Interfaces:**
- Produces: discriminated `vevb-1 | vevb-2` parsing/verification and complete-retained-tail exports with per-chain origin claims.

```ts
export type ExportBundle = ExportBundleV1 | ExportBundleV2;
export type AuditOriginClaim =
  | { kind: "genesis" }
  | { kind: "checkpoint"; checkpointHash: string };
```

- [ ] **Step 1: Add failing v2 fixture, core, CLI, and server tests while retaining literal v1 golden assertions.**
- [ ] **Step 2: Run focused tests and verify v2 is rejected as unsupported.**

```sh
bun test sdks/typescript/src/__tests__/export-bundle-v2.test.ts cli/src/__tests__/verify-bundle.test.ts server/node/src/__tests__/index.test.ts
```

- [ ] **Step 3: Implement v2 builder/parser/verifier.** Require the full checkpoint chain, zero-or-one bound disposition per epoch, checkpoint-origin audit complete tail, genesis-only edges, and empty commits.
- [ ] **Step 4: Update CLI output and server selection without changing v1 APIs or bytes.**
- [ ] **Step 5: Run focused tests and commit.**

```sh
bun run --cwd cli test
bun run --cwd server/node test
bun test sdks/typescript/src
git add spec sdks/typescript cli server/node
git commit -m "feat(export): add checkpoint-aware vevb-2"
```

### Task 6: Documentation and Full OSS Gate

**Files:**
- Modify: `storage/README.md`, `sdks/typescript/README.md`, `sdks/python/README.md`, `sdks/go/README.md`, `docs/review-backlog.md`

- [ ] **Step 1: Document audit-only retention capability, weaker post-disposal proof, non-capable adapters, migration order, and no automatic compliance claim.**
- [ ] **Step 2: Run placeholder and diff checks.**

```sh
rg -n "TODO|TBD|FIXME" spec sdks storage cli server/node
git diff --check
```

- [ ] **Step 3: Run the full gate and commit documentation.**

```sh
bun run verify
git add storage/README.md sdks docs/review-backlog.md
git commit -m "docs: document retention checkpoint operations"
```
