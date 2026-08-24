# Evidence-provenance review backlog

Verified follow-ups from the multi-lens adversarial review of the
evidence-provenance-fabric work (PRs #10/#11) and the cloud surfaces (#23).
Each item was confirmed against `main` by a verification agent; the **fixed**
items below already landed (see `fix/review-backlog`). The remaining items are
deferred deliberately — they are protocol-coupled, cross-repo, or design
decisions that deserve a coordinated `veritio-protocol-change` /
`split-orchestrator` cycle rather than a post-deploy drive-by.

> Reviewer output is critique, not truth. Re-verify each item against current
> code before patching (repo policy).

## Landed (this pass)

- **Retention checkpoints and staged disposal (OSS) — LANDED 2026-08-24.**
  Audit-only v1 checkpoint/disposition records and parity helpers now exist in
  TypeScript, Python, and Go. Postgres/Neon, MySQL/MariaDB, MongoDB, and the
  in-memory test store implement the authoritative checkpoint contract with
  real-database conformance; the separate staging archive/coordinator uses a
  host-injected epoch lease and policy fences. `vevb-2` verifies the complete
  checkpoint chain plus retained audit tail without changing `vevb-1` bytes or
  defaults. This is evidence support/audit-trail functionality, not an
  automatic legal-compliance claim.

- **K — scoped-key revoke TOCTOU** (`veritio-cloud`): the revoke `UPDATE` now
  carries an `isNull(revoked_at)` guard and returns the existing row on a
  0-row race, so a concurrent double-revoke can no longer overwrite the original
  timestamp or write a duplicate `scoped_key.revoked` audit row.
- **J — outbox poison-pill** (`storage`): a non-retryable ingest verdict
  (`4xx`/`409`, `IngestError.retryable === false`) now dead-letters the row to a
  terminal `dead` status instead of looping forever; transient `5xx` and
  unexpected throws stay `pending`.
- **F — unbounded `lastError`** (`storage`): `errorMessage()` now persists a
  bounded (≤256-char), whitespace-collapsed `name: message` summary, never the
  raw unbounded `error.message`.
- **B — fabricated synthetic parent** (`sdks/{ts,py,go}`): the governed-change
  builder no longer invents `rev_<type>_<id>_previous`. A parent revision, the
  `derived_from` edge, and `outboxEntry.expectedParentRevisionRef` are emitted
  **only** when the caller supplies a real `expectedParentRevisionRef`; an update
  without one leaves lineage open for the host store. This changes the hashed
  `entity.revision.created` metadata (`veritio.revision.parents` is now `[]`
  instead of `[synthetic]`) byte-identically across all three SDKs — a deliberate,
  correct hash change since the placeholder was never valid.
- **riskScore ad-hoc field replaced** (`sdks/{ts,py,go}`, `adapters/better-auth`,
  examples): the numeric `riskScore` on the session security context was removed
  (breaking) and replaced by the deterministic `riskSignals` model — normalized,
  scored byte-identically across languages by the SDK risk module
  (`veritio.reference.v1`) — plus the `security.risk` assertion path
  (`recordType: assertion.recorded`, linked by `based_on` edges). The local
  server stores assertions as a sink and never scores. Remaining cross-language
  parity TODO: the `activityEpisodeId` recorder stamp and any Python/Go
  agent-capture adapter are tracked under `.claude/rules/02-sdk-parity.md`.

## Deferred — protocol-change / cross-repo cycle

### Retention follow-ups deliberately outside v1

- **Evidence-edge and EvidenceCommit checkpoints — DEFERRED.** Their chains
  remain genesis/full-chain in v1; do not crop them through the audit-store
  contract.
- **Crash-safe `FileEvidenceStore` retention — DEFERRED.** A file adapter needs
  a specified journal/snapshot transaction before it can become authoritative
  and checkpoint-capable.
- **Derived-tier authority — REJECTED.** ClickHouse and R2/S3/ObjectAuditArchive
  remain derived and cannot own sequence, idempotency, verify/DSAR answers, or
  long-term replay. A host needing cold retention must migrate to a conforming
  authoritative store rather than promote an archive.

### C — revision id collides on rollback to an identical earlier state
- **Decision (2026-07-17): DEFERRED PAST CLOUD LAUNCH.** The change-scoped
  stopgap is fixture-pinned, replay-stable, and consumed opaquely by the cloud
  read models, so it is sound to ship on. Adopting the host-assigned ordinal
  scheme changes every revision-id string plus the cloud Explain/timeline/diff
  keys — revisit only alongside a deliberate protocol rev, not as launch work.
- **Status:** STOPGAP LANDED (`fix/review-backlog-deferred`): the revision id
  is now `rev_<type>_<id>_<digest12>_<sha256(changeId)8>` byte-identically
  across TS/Python/Go, pinned by `spec/conformance/governed-revision-id.json`
  (+ rollback-distinctness tests in all three SDKs). Verified that the cloud
  read models consume `revision.ref.id` as an opaque map key (never parsed),
  so the format change is transparent to Explain/timeline/diff. REMAINING
  OPEN: the spec's host-assigned ordinal design (`rev_..._18` + `ordinal`)
  is still the target; the id changes again when hosts assign ordinals.
- **Original finding (for context):** confirmed across TS/Python/Go.
- **Where:** `sdks/typescript/src/governed-change.ts` (`rev_<type>_<id>_<digest12>`),
  Python `governed_change.py`, Go `governed_change.go` (same scheme); consumers
  `veritio-cloud/src/cloud/governed-changes.server.ts` + `src/evidence/governed-changes.ts`
  key Explain/timeline/diff nodes on `revision.ref.id`.
- **Problem:** the revision id is content-addressed by the state-commitment
  digest only. A rollback `A → B → A'` that restores `A`'s exact governed state
  yields `A' == A`'s id, merging two distinct revisions into one Explain node
  (and a `B ↔ A` self-cycle). The design spec's intended shape is an **ordinal**
  suffix (`rev_..._18` + a separate `ordinal`), not the digest.
- **Why deferred:** the fix changes **every** revision id string and the cloud
  read models that key on it; the "right" scheme (host-assigned ordinals) is a
  design decision the SDK draft-builder can't make alone. Needs a conformance
  vector (`spec/conformance/governed-revision-id.json`) + coordinated cloud
  read-model/test updates.
- **Options:** (a) spec-aligned ordinal suffix (host-assigned — architectural);
  (b) stopgap: append `sha256(change.id)[:8]` to the id (replay-stable, but still
  diverges from the spec's ordinal target). Decide deliberately.

### lineagePolicy is a declared-but-unenforced knob
- **Status:** RESOLVED as documented-reserved (`fix/review-backlog-deferred`):
  the field is now explicitly documented as RESERVED / not-yet-enforced in all
  three SDKs, with enforcement tied to the host-assigned ordinal design (C).
  Kept (not removed) so hosts can record intent without a schema change later.
- **Original finding (for context):** `GovernedEntityDefinition.lineagePolicy`
  ('linear' | 'dag') is declared in all SDKs + the design spec but never read.
- **Action:** either honor it (host-side OCC enforcement, tied to C) or document
  it as reserved/not-yet-enforced. Removal touches public API in 3 languages +
  the spec example — do it as a deliberate decision, not a silent drop.

## Deferred — documentation / low-risk parity

### E — EvidenceCommit hash construction has no prose spec
- **Status:** LANDED (`fix/review-backlog-deferred`): normative
  `spec/evidence-commit-hashing.md` (manifest normalization, leaf/node/commit
  domain separators, odd-leaf rule, chain linkage), transcribed from the SDK
  sources; the conformance fixture stays the tie-breaker.
- **Original finding (for context):** confirmed. The algorithm (leaf separator `veritio-record-leaf-v1`,
  node separator `veritio-merkle-node-v1`, commit separator `veritio-commit-v1`,
  Merkle odd-leaf rule, canonical input) lives ONLY in SDK source
  (`sdks/typescript/src/index.ts:953/971/473`, Python `event.py:379/389/209`,
  Go `event.go:694/713/522`) + the `spec/conformance/evidence-commit.json`
  fixture. No committed prose lets an independent implementer reproduce the bytes.
- **Action:** add a normative `EvidenceCommit hash construction` section in
  `spec/` (next to `evidence-commit.schema.json`). Doc-only, but transcribe the
  algorithm carefully from the SDK source + verify against the fixture.

### A — EvidenceCommit verification is scoped to ledger atomicity (document the boundary)
- **Status:** LANDED (`fix/review-backlog-deferred`): "Verification scope
  (v1)" section in `spec/evidence-commit-hashing.md` + tightened
  `verifyEvidenceCommits` doc-comments in all three SDKs. The optional
  membership reconciliation in the composed `verify()` remains a future nicety.
- **Original finding (for context):** confirmed-as-intended, not a bug. `verifyEvidenceCommits`
  (`index.ts:484`, `event.py:212`, `event.go:550`) checks only the commit chain's
  internal consistency and never reconciles `member.recordHash` against the
  actually-verified records, so a fabricated chain verifies `ok` in isolation.
  Per-record integrity is covered by `verifyAuditRecords` /
  `verifyEvidenceEdgeRecords` in the composed `server/node` `verify()` path, and
  the design spec scopes commits to ledger atomicity.
- **Action:** add a "Verification scope (v1)" note in the spec + tighten the
  `verifyEvidenceCommits` doc-comments in all 3 SDKs so the boundary is explicit.
  Optionally add a cheap membership reconciliation in the composed `verify()`.

### I — CaptureMode advertises 8 modes, only 4 implemented (fails closed)
- **Status:** LANDED (`fix/review-backlog-deferred`): implemented-vs-reserved
  modes documented on `CaptureMode` (TS), `EntityFieldPolicy.Capture` (Go),
  and the `define_entity` docstring (Python). Type kept wide deliberately.
- **Original finding (for context):** partly-confirmed. `CaptureMode` advertises 8 modes; the
  state-commitment builder implements 4 (`omit`, `full`, `keyed_digest`,
  `content_digest`) and the other 4 (`randomized_digest`, `reference`, `redact`,
  `encrypt`) `throw`/error (fail closed — no silent weak commitment).
- **Action:** document which modes are implemented vs fail-closed in the
  `CaptureMode` doc-comment (3 SDKs), or narrow the public type to the supported
  set. No data-leak risk today.

### H — `verifyEvidenceCommits` defensive validation is uneven across SDKs
- **Status:** LANDED (`fix/review-backlog-deferred`): TS gained the
  streamId/hash type guards (Python parity, with tests); Go gained the empty
  streamId guard (its type system already rules out a non-string hash).
- **Original finding (for context):** partly-confirmed, cosmetic. Python has two extra type guards
  (`streamId`/`hash` are strings → `invalid_member_manifest`/`hash_mismatch`)
  that TS/Go lack; every other branch matches.
- **Action:** add the two guards to TS + Go for parity (low priority).

### G — Go `redactAny` default stringifies unsupported types (pre-existing)
- **Status:** the concerning sub-claims are refuted. `event.go:811` mirrors the
  TS `String(value)` / Python `str(value)` fallbacks, and no new
  digest-envelope/governed-change path reaches it.
- **Action:** none required; keep the parity note here for the record.

## Refuted (no action)

- **D — captureMethod hardcoded:** refuted. The reviewer's claim that
  `captureMethod` mis-asserts a guarantee did not hold against the actual code.

## Cross-repo follow-ups

- **veritio-website — risk-scoring explainer:** the temperature knob
  (`riskPolicy`) and per-action frequency rules landed in OSS
  (docs/risk-scoring.md + spec/risk-scoring.md are the source of truth); the
  public education page for them belongs in `veritio-website`, not here.

## Review 2026-07-18 — post-0.4.3-train pass (PRs #35–#45)

Six-lens adversarial review of everything merged since 2026-07-13 (capture
correctness, protocol compat, SDK parity, privacy/redaction, boundary). The
strongest claims were re-verified locally; the capture bug below was reproduced
against the real hook binary. Items are OPEN unless marked otherwise.

### Open — needs a fix branch

- **Capture heals wedge on same-tenant scope drift (MEDIUM, reproduced) —
  FIXED 2026-07-19.** `refreshContextScope` now re-scopes ONLY on a tenant-id
  change (same-tenant environment/workspace drift stays frozen at the
  SessionStart values — re-scoping kept the idempotency key, tenant + event id
  only, while drifting the canonical bytes, so the deterministic session-start
  replay conflicted and capture died silently for the session).
  `findPriorSessionStart` returns the prior append's full `event.scope` and
  `rebuildSessionContext` mirrors it verbatim instead of re-deriving from
  config. Doc comments corrected; regression tests pin both heals
  (`map.test.ts`: same-tenant drift no-op, tenant-change re-scope, prior-scope
  mirror).
- **`bun.lock` drift from the 0.4.3 release train (MEDIUM, confirmed) —
  FIXED 2026-07-19.** The adapter's workspace manifest snapshot in `bun.lock`
  now records the `0.4.3` pins (note: `bun install`/`--force` do NOT refresh
  the version spec of workspace-resolved deps — the snapshot had to be
  corrected in the lockfile text, then validated with plain and
  `--frozen-lockfile` installs, both clean). Still open from this finding:
  add `--frozen-lockfile` to CI installs so the next drift fails loudly.
- **Destructive-classifier long-form gaps (LOW, runtime-verified) —
  FIXED 2026-07-30.** `rm … --recursive`, `rimraf` (incl. `npx`/`bunx`), and
  `find … -delete` now classify as `destructive`/`irreversible`; the patterns
  stay scoped to one shell word group so pipeline segments cannot smear flags
  onto an unrelated leading command. DESIGN.md classification table updated in
  the same change (mapping is hash-affecting capture contract); regression
  tests in `map.test.ts` pin all three plus the piped-command non-match.
- **`provenance-ids.json` under-pins two derivations (LOW, confirmed) —
  FIXED 2026-07-30.** The fixture now pins the tool-event id
  (`evt_tool__<toolCallId>`) and the absent-resultVersion file-change sentinel
  (`…__x`); the TS conformance test executes both through the public recorder
  surface (`recordToolCall`, `recordFileChange` without `resultVersion`).

### Landed (this pass)

- **Risk-signal mapping documented as capture contract.** cc70340's commit
  message claimed the classification mapping was in DESIGN.md; it never was.
  Now landed: DESIGN.md "Risk-signal classification" table (patterns,
  precedence, env mapping, known gaps) + parity obligation in
  `.claude/rules/02-sdk-parity.md`.

### Verified sound (no action)

- Tenant isolation of both heal paths: candidates filtered by
  `event.scope.tenantId`; a real tenant change emits a second session-start
  under a distinct key by design. No wrong-tenant writes, no session-start
  double-emit (byte-identical replay returns `appended:false`).
- Frozen risk vocabulary: `RiskSignals` carries enums + numbers only — no
  free-text field exists to leak into; raw command text never leaves the
  classifier (hash only).
- Release-script skip logic (1f6ea3a): npm versions are immutable and
  `npm view` failure fails OPEN to a publish attempt, so neither stuck
  partial-publish states nor registry blips can cause a false skip.
- Provenance-id spec pin (794c3b4) matches the TS implementation
  byte-for-byte; the 2026-07-15 "edge-id turn conflict" open decision is
  RESOLVED by occurrence-scoped edge ids, not contradicted.
- Shared TS/Python/Go behavior untouched: no shared conformance fixture
  modified by any commit in the window; all three languages green.

## Release decisions (2026-07-17)

- **`@veritio/codex` stays unpublished-experimental for the Cloud launch.** It
  is deliberately outside `scripts/release-npm.sh`'s publish loop; its capture
  contract should soak against real Codex sessions before the package name is
  claimed publicly. Revisit when a user needs `bunx @veritio/codex` resolution.
- **Provenance edge-id scheme is now normative** — pinned by
  `spec/provenance-identity.md` + `spec/conformance/provenance-ids.json`
  (PR #40); no longer an open decision.
