# Retention Checkpoints and Two-Stage Disposal Design

Status: approved architecture; written specification awaiting review

Date: 2026-08-24

Scope: public retention checkpoint protocol, authoritative-store compaction,
derived archive verification, export/verifier behavior, and cross-language
conformance

## Decision

Veritio will preserve a tenant chain across retention by introducing a portable,
hashed retention checkpoint. A checkpoint binds the verified prefix that has
left the authoritative hot store to the first record that remains. It does not
rewrite an existing record, reset sequence numbers, or promote object storage to
an authoritative `AuditStore`.

Retention runs in two independently auditable stages:

1. **Checkpoint and crop.** Once a prefix has reached its total-retention
   deadline, exact canonical record bytes are sealed to the derived object
   archive as a short-lived safety copy, the range is replay-verified from the
   prior checkpoint (or chain origin for epoch 1), a checkpoint is persisted
   atomically with authoritative chain state, and only then may the covered
   prefix be removed from the authoritative store.
2. **Dispose staged payload.** After the crop is confirmed, and only while the
   host's hold and policy decision is still current, the short-lived archive
   payload is deleted. A signed disposition receipt keeps the checkpoint and
   archive digest auditable without retaining event bodies. The receipt is an
   attestation of an attempted disposal operation, not cryptographic proof that
   every physical copy was erased.

The derived archive is never a cheaper long-term authoritative tier. Normal
reads, verification, exports, and DSAR responses do not fall back to it after a
crop. A host that wants long-term cold retention must use a conforming
authoritative `AuditStore` migration; object storage alone cannot take that role.

The protocol and storage contract live in this OSS repository. Hosted plan
selection, scheduling, legal-hold authority, customer notices, and provider
operations remain private to `veritio-cloud`.

## Existing Invariants

- Audit and evidence-edge records are independent tenant-scoped chains. The v1
  compaction contract covers audit records only; evidence-edge and
  EvidenceCommit retention remain fail-closed until their authoritative store
  interfaces gain equivalent checkpoint support.
- Sequences remain global and monotonic within a tenant chain. They never reset
  at a checkpoint.
- A record hash continues to cover its original `previousHash`. Retention never
  re-hashes a retained record.
- A conforming `AuditStore` remains the sequence and idempotency authority.
- R2/S3 archives remain derived, eventually consistent tiers containing exact
  `canonicalJson` NDJSON bytes. They never append records or choose a sequence.
- Existing full-chain verification and every `vevb-1`
  full/windowed/filtered byte remain unchanged. Checkpoint-aware exports use a
  new `vevb-2` format.
- Unknown versions, algorithms, checkpoint shapes, or signatures fail closed.

## Portable Records

### Retention checkpoint

The language-neutral checkpoint schema is `retention-checkpoint.schema.json`.
Its canonical unsigned payload is:

```json
{
  "recordType": "retention.checkpoint",
  "schemaVersion": "1.0",
  "checkpointId": "rcp_...",
  "tenantId": "org_...",
  "chainKind": "audit",
  "epoch": 1,
  "fromSequence": 1,
  "fromPreviousHash": null,
  "throughSequence": 1000,
  "throughHash": "<64 lowercase hex>",
  "recordCount": 1000,
  "archiveRootHash": "<64 lowercase hex>",
  "previousCheckpointHash": null,
  "createdAt": "2026-08-24T00:00:00.000Z",
  "canonicalization": "veritio-json-v1",
  "hashAlgorithm": "sha256",
  "signaturePublicKeyFingerprint": "<64 lowercase hex>"
}
```

The stored record adds `hash`, computed as SHA-256 over the canonical unsigned
payload. `checkpointId` and `createdAt` are caller inputs; core helpers never
read a clock or generate randomness. `chainKind` is `audit` in v1. `epoch`
starts at 1 and increments by exactly one.

`fromSequence` through `throughSequence` is the newly retired contiguous range.
For epoch 1, `fromSequence` is 1 and `fromPreviousHash` is null. For later
epochs, `fromSequence` is the prior checkpoint's `throughSequence + 1` and
`fromPreviousHash` is its `throughHash`. `recordCount` equals
`throughSequence - fromSequence + 1`. `previousCheckpointHash` is null for epoch
1 and equals the prior checkpoint's hash thereafter. Each checkpoint therefore
binds only bytes staged for its own epoch and remains verifiable after earlier
epoch payloads are disposed.

`archiveRootHash` is provider-neutral. It is the SHA-256 of canonical JSON for
the ordered array of covered segment descriptors:

```json
[
  {
    "fromSequence": 1,
    "toSequence": 1000,
    "recordCount": 1000,
    "firstPreviousHash": null,
    "lastHash": "<64 lowercase hex>",
    "contentSha256": "<64 lowercase hex>"
  }
]
```

Descriptors are strictly contiguous, cover exactly the checkpoint's
`fromSequence` through `throughSequence`, and are sorted by `fromSequence`.
The first descriptor carries `fromPreviousHash`, and the last carries
`throughHash`. Provider
bucket names and object keys are excluded so migrating an intact segment does
not change the protocol digest. A dedicated retention-staging manifest owns the
physical lookup key; the existing cumulative `ObjectAuditArchive` remains
unchanged and continues to require origin-complete segments.

All numeric fields are integers from 1 through JavaScript's maximum safe integer
(`9007199254740991`). Timestamps use the exact UTC millisecond form
`YYYY-MM-DDTHH:mm:ss.sssZ`; offsets, missing milliseconds, leap seconds, and
extra precision fail closed. `checkpointId`, `dispositionId`, and `tenantId`
match `^[A-Za-z0-9._:-]{1,128}$`; `policyReference` uses the same alphabet with
a 256-character maximum.

The protocol supports an optional detached Ed25519 signature. A signed payload
includes `signaturePublicKeyFingerprint` before its checkpoint hash is computed,
then adds `{ algorithm: "ed25519", publicKeyFingerprint, signature }` where the
signature is standard padded base64 over the UTF-8 bytes of the 64-character
checkpoint hash. Both fingerprints must equal SHA-256 of the raw public key.
Verification reports `valid`, `invalid`, `skipped`, or `absent` against a
caller-supplied trusted key, and a caller-requested signature fails when absent
or skipped. Unsigned records omit both fingerprint and signature. Hosts decide
through injected policy whether a signature is required.

### Disposition receipt

`retention-disposition.schema.json` defines the record retained after archived
payload disposal:

- `recordType: "retention.disposition"` and `schemaVersion: "1.0"`;
- caller-supplied `dispositionId`, `tenantId`, `chainKind`, and `disposedAt`;
- `checkpointHash`, `fromSequence`, `throughSequence`, and `archiveRootHash`
  copied from the checkpoint;
- `method`, fixed to `provider-delete` in v1;
- a non-personal `policyReference` string supplied by the host;
- `canonicalization`, `hashAlgorithm`, and the record `hash`;
- optional fingerprint/signature fields with the exact checkpoint rules.

The receipt never contains a legal-hold reason, user identity, raw provider
response, bucket key, or event metadata. Hosts keep operational authorization
and provider evidence in their own access-controlled audit log.

## Checkpoint Verification

Core exposes equivalent TypeScript, Python, and Go operations:

- construct and hash a checkpoint;
- verify one checkpoint's shape and hash;
- verify a checkpoint chain;
- verify audit records from a checkpoint anchor;
- construct, hash, and verify a disposition receipt.

Checkpoint-chain verification requires:

- one tenant and one `chainKind` throughout;
- epochs increasing by one;
- exact range continuity from the prior `throughSequence`/`throughHash`;
- `previousCheckpointHash` linkage;
- a valid hash and supported protocol metadata on every checkpoint.

Anchored record verification starts its state at the checkpoint's
`throughSequence` and `throughHash`. The first retained record must have
`sequence === throughSequence + 1` and
`previousHash === throughHash`; all later records follow the existing strict
rules. An empty retained tail is valid when the checkpoint itself is valid.
Existing `verifyAuditRecords` and `verifyEvidenceEdgeRecords` keep their
start-at-one behavior; callers must opt into the new anchored verifier.

Epoch verification starts with the prior checkpoint's sequence/hash, or the
null/zero genesis state for epoch 1. It replays only the epoch's staged
segments, recomputes every record hash and `archiveRootHash`, requires the range
tip to equal the new checkpoint, and then verifies the retained hot tail from
the new checkpoint. A checkpoint chain therefore preserves continuity without
requiring disposed event bodies. It proves only that each claimed anchor is
tamper-evident; it cannot prove the content of an already disposed epoch.

Disposition verification always receives the referenced checkpoint. It requires
exact tenant, chain kind, checkpoint hash, range, and archive-root equality in
addition to the receipt's own hash/signature. At most one accepted disposition
exists per checkpoint hash; a byte-identical replay is idempotent and a
conflicting second receipt fails closed.

## Authoritative Store Contract

The existing `AuditStore` surface stays source-compatible. Retention-capable
audit adapters additionally implement `CheckpointingAuditStore`, whose
operations are tenant-scoped and compare-and-swap guarded:

- `getChainState(scope)` returns the authoritative sequence/hash tip and latest
  checkpoint plus the retention-policy fence version even when no hot records
  remain;
- `advanceRetentionPolicyFence(scope, expectedVersion)` atomically increments
  that opaque version when a host changes eligibility or hold state;
- `compactRange(scope, checkpoint, expectedState, policyFence)` atomically
  persists the verified checkpoint, converts covered idempotency entries to
  tombstones, advances the minimum retained sequence, and deletes only the exact
  checkpoint range;
- `listCheckpoints(scope)` returns cloned checkpoints in epoch order;
- `prepareDisposition(scope, checkpointHash, attempt, expectedPolicyFence)`
  atomically creates or retrieves the matching pending attempt; after a crash,
  a fresh-fence retry atomically supersedes an older pending attempt while no
  receipt exists and returns the newly bound attempt id;
- `confirmDisposition(scope, receipt, expectedAttemptId,
  expectedPolicyFence)` validates the receipt against that checkpoint and CASes
  both the current attempt and still-current fence before storing the unique
  accepted receipt and advancing the attempt to disposed;
- `listDispositions(scope)` returns accepted receipts in checkpoint-epoch order.

`compactRange` accepts no archive client and performs no network work. The
caller must finish archive sealing and verification first. The store validates
the checkpoint hash, tenant, audit chain kind, next epoch, prior checkpoint
linkage, and exact current state in the same transaction as the crop. The
expected state includes current authoritative tip sequence/hash, minimum
retained sequence, latest checkpoint hash, and retention-policy fence version.
The checkpoint must begin at the minimum retained sequence, advance it without
overlap or gap, and its
`throughHash` must equal the integrity-checked authoritative row at
`throughSequence`. A range cannot extend past the current tip. A race, stale
policy fence, gap, overlap, boundary mismatch, signature-policy failure at the
host boundary, or stale state deletes nothing.

Every retention-capable adapter keeps chain state separately from hot records.
Append allocates `sequence = authoritativeTipSequence + 1` and uses
`authoritativeTipHash` even when the cropped prefix included every physical
record row. Idempotency state is a separate minimal ledger. Before crop it can
return the original record as today. During crop it becomes a permanent
tenant-lifetime tombstone containing only idempotency-key hash,
event-canonical hash, original sequence, and original record hash; it retains no
event body. A matching retry returns the stable
`idempotency_history_disposed` error, a changed payload remains an idempotency
conflict, and neither path can append a duplicate. Tenant deletion removes the
ledger with the tenant.

Postgres/Neon, MySQL/MariaDB, MongoDB, and the memory test store
receive equivalent state/checkpoint behavior and conformance tests. MongoDB
continues to require replica-set transactions. Object archive and ClickHouse do
not implement this interface. Evidence-edge stores do not implement v1
compaction and their rows are never cropped by this contract. The existing
`FileEvidenceStore` also remains non-compacting in v1; a future file adapter must
specify a crash-safe journal/snapshot transaction before it can implement this
interface.

## Two-Stage State Machine

One serialized worker owns a tenant audit chain at a time. Its durable states
are:

`eligible -> sealing -> archive_verified -> compacted -> disposal_confirmed -> disposed`

Eligibility means the records have already reached the host's total-retention
boundary; staging is not an additional retention tier. Failures before
`compacted` leave authoritative rows untouched.
Retries re-use byte-identical archive segments and the same checkpoint inputs.
A crash after `compacted` is safe because the atomic database transaction
already records both the anchor and crop boundary; there is no intermediate
checkpoint-committed-but-not-cropped state. A crash during provider
deletion leaves the state uncertain; the host reconciles provider existence and
does not issue a disposition receipt until every covered object is confirmed
absent.

Legal holds are intentionally host-injected. The OSS coordinator accepts an
eligibility decision with an opaque, non-personal reference and monotonic
version, but never claims that a hold check satisfies any law. The host
serializes hold mutations and compaction, revalidates the version immediately
inside its destructive-operation fence, and passes that version to
`compactRange`; a stale token fails. Stage 2 acquires the same per-tenant fence,
calls `prepareDisposition`, and keeps the fence held across provider deletion and
absence confirmation before `confirmDisposition`. A concurrent hold mutation
waits for that bounded critical section. If deletion or confirmation fails, the
fence is released without a receipt and every retry must acquire it and validate
a fresh policy version, supersede/rebind any stale pending attempt, and CAS that
version again at confirmation; a queued hold therefore wins before retry. A hold blocks
both crop and final archive disposal for the covered data. Releasing a hold
triggers a fresh eligibility calculation; it never resumes a stale deletion
blindly.

The existing `ObjectAuditArchive` is not changed to tolerate missing origin
segments. A new `RetentionStagingArchive` seals and verifies exactly one epoch
from an explicit prior checkpoint/genesis anchor. Its client extends the
read/write/list surface with delete; v1 disposal is complete only when every epoch
key is absent by both direct read and prefix listing. Provider-specific
authorization and reconciliation remain host-owned.

## Export Bundles

Existing `vevb-1` bundle bytes and claims remain valid. Checkpoint-aware exports
use `vevb-2`, with `records/retention-checkpoints.jsonl` and
`records/retention-dispositions.jsonl` added to the mandatory file map. Its
manifest carries per-chain claims instead of one scalar `chainScope`:

```json
{
  "audit": {
    "origin": { "kind": "checkpoint", "checkpointHash": "<64 lowercase hex>" },
    "selection": "complete-retained-tail"
  },
  "edges": { "origin": { "kind": "genesis" }, "selection": "full" },
  "commits": { "origin": { "kind": "genesis" }, "selection": "empty" }
}
```

The initial v2 checkpoint mode supports only the complete retained audit tail
from the latest included checkpoint. It does not compose checkpoint origin with
windowed or filtered selection; such a manifest fails closed. Evidence-edge
records retain the existing genesis full/windowed/filtered rules and cannot use
a checkpoint origin in v1 of this feature. Commits must be empty whenever the
audit origin is checkpointed. Every included disposition must bind exactly to
an included checkpoint, and `verification.json` reports separate checkpoint,
disposition, audit, edge, and commit verdicts.

The checkpoint file contains the complete checkpoint chain from epoch 1 through
the manifest-selected latest checkpoint, even though disposed event bodies are
absent. The disposition file contains zero or one receipt for each included
checkpoint, in epoch order; an absent receipt is never synthesized.

Before crop, the archive replay is an internal verification gate and the
authoritative store can still produce an ordinary full bundle. After crop,
normal product exports use the authoritative retained audit tail and the v2
checkpoint claim; they never serve expired content from the derived safety
copy. Their UI/CLI language says that historical content is no longer
available.

## Irreversibility

Compaction has no public restore operation. The authoritative crop is committed
only after archive and boundary verification, and rollback must occur before
that transaction. Afterward, the staged copy exists solely so provider deletion
can be confirmed; it is not imported below an advanced chain tip. The public API
reports the range as `disposed` after its receipt, never fabricates placeholder
events, and cannot reconstruct deleted content.

## Delivery Order

1. Add schemas, normative prose, and deterministic conformance fixtures.
2. Land TypeScript, Python, and Go checkpoint/disposition parity.
3. Add the separately versioned `vevb-2` schema, builder, verifier, and fixtures
   without changing existing `vevb-1` fixtures.
4. Add the retention-capable store interface and memory adapter, including
   durable disposition attempts/receipts.
5. Add SQL and Mongo migrations plus live conformance coverage.
6. Add the separate retention-staging archive with provider-neutral root
   computation, anchored exact-range verification, and deletion confirmation.
7. Only then let `veritio-cloud` enforce plan retention.

## Verification Matrix

Tests must cover deterministic hashes in all three SDKs; wrong tenant, epoch,
prior hash, sequence, archive root, and signature failures; a fully cropped hot
store followed by a correct append; stale concurrent crop attempts; idempotent
retry before and after crop; archive corruption; crash points at every state;
legal-hold version races; bound disposition receipts; v2 checkpointed bundle
verification; integer/timestamp/signature rejection boundaries;
and unchanged golden bytes for existing exports.

Storage live suites run through `storage/docker-compose.yml` for PostgreSQL,
MySQL, and transactional MongoDB. The final OSS gate is `bun run verify` plus
the environment-gated live storage suite.

## Non-Goals and Claims Boundary

- This protocol does not decide a lawful retention period or interpret a legal
  hold.
- A disposition receipt does not prove deletion from backups, replicas, or a
  provider's internal media.
- Checkpoints do not make R2, S3, ClickHouse, or a bundle the append authority.
- No hosted account, hosted project id, billing plan, or provider credential is
  required by the OSS APIs.
- Retention support is evidence support and operational control, not automatic
  GDPR, HIPAA, SOC 2, DORA, NIS2, or other compliance.

## Acceptance Criteria

- A tenant can append after its entire authoritative audit-record prefix is cropped without
  resetting sequence or breaking the original hash link.
- No hot row is deleted unless the exact archived prefix and checkpoint have
  verified and the checkpoint/crop transaction commits.
- Each staged epoch verifies from genesis or the prior checkpoint, while
  checkpoint-only verification makes its weaker post-disposal claim explicit.
- Final disposal retains no event bodies in checkpoint or disposition records.
- TypeScript, Python, and Go produce identical checkpoint and disposition
  hashes for the conformance fixtures.
- Every adapter that opts into `CheckpointingAuditStore` passes the same
  retention conformance suite; non-capable adapters reject compaction.
- Existing non-retention APIs, hashes, fixtures, and `vevb-1` bundles remain
  byte-compatible; checkpoint-aware exports identify themselves as `vevb-2`.
