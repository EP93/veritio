# Changelog

All notable changes to Veritio will be documented in this file.

Veritio is a pre-1.0 Apache-2.0 project. Early releases may change APIs while the protocol, SDKs, adapters, and storage contracts settle. Release notes should be explicit about migration steps and should avoid legal-compliance guarantees.

## [0.4.8] - 2026-08-25

### Added

- The first published retention protocol surface defines audit-only
  `retention.checkpoint` and `retention.disposition` schemas, canonical hashes,
  optional Ed25519 signatures, conformance fixtures, and matching constructor
  and verification APIs across TypeScript, Python, and Go.
- Authoritative memory, PostgreSQL/Neon, MySQL/MariaDB, and transactional MongoDB
  stores implement checkpointed prefix crop, durable chain state, permanent
  idempotency tombstones, monotonic policy fences, and disposition-attempt CAS.
- The derived object-staging archive preserves exact NDJSON bytes and the
  host-injected retention coordinator enforces epoch leases, two policy fences,
  staged verification, provider deletion, and independent direct-plus-prefix
  absence confirmation before a receipt can be persisted.
- Checkpoint-aware `vevb-2` export bundles carry closed checkpoint/disposition
  records and explicit retention-signature trust results. The CLI verifies and
  reports both bundle versions, and the self-hosted server/MCP can build v2 only
  from explicit host-injected checkpoint inputs.
- `@veritio/core/version` and `@veritio/storage/version` expose immutable exact
  package identity tokens for server hosts that cannot read package metadata.
- `@veritio/storage/retention` exposes a frozen retention-coordinator
  capability token with explicit API/protocol/schema identity and fail-closed
  feature flags for confirmed-disposal-time and accepted cold replay behavior.

### Changed

- The first public retention coordinator contract resolves `disposedAt` through
  an asynchronous host callback only after staged deletion and direct-plus-prefix
  absence confirmation. The host must durably return the same time for the same
  attempt context because receipt-persistence retries may re-invoke it. Existing
  accepted receipts replay byte-for-byte without consulting the callback;
  deletion, absence, callback, and timestamp failures persist no receipt.
- Released `@veritio/core`, `@veritio/storage`, and `@veritio/claude-code`
  0.4.8 as one train. Claude Code pins core and storage exactly at 0.4.8, and
  all seven plugin hooks pin the exact Claude Code package version. Independent
  framework adapters remain on their own release cadence. The Claude plugin
  manifest/cache advances to 0.1.3 and the marketplace catalog to 0.1.2.

### Safety

- Disposal-time callback context is limited to tenant id, a detached checkpoint,
  attempt id, disposition id, and opaque policy fence. The OSS packages do not
  read host environment or clock state and make no claim about provider backups
  or legal compliance.

## [0.4.7] - 2026-08-23

### Added

- Claude Code remote delivery now has a finite durable queue, sticky pause,
  quarantine, one-request canary, and explicitly budgeted manual drains. Normal
  hooks never auto-replay backlog after an outage or quota upgrade.
- CI now verifies the Claude plugin package pin, the core/storage/Claude release
  train, disabled-by-default hosted plugin state, and the Codex remote-attempt
  ceiling before the main suite.
- Capture delivery modes are tagged on the wire: the Claude Code adapter sends
  `x-veritio-delivery` (`live-v1` for hooks, `replay-v1` for spool drains) so
  server-side replay budgets can meter drains separately from live capture.
- `spec/conformance/provenance-ids.json` pins the tool-event id and the
  absent-`resultVersion` sentinel, both exercised through the public recorder
  surface in the TypeScript conformance test.

### Changed

- Released `@veritio/core`, `@veritio/storage`, and `@veritio/claude-code`
  0.4.7 as one train. Only `@veritio/claude-code` pins the other two EXACTLY
  (`@veritio/core` and `@veritio/storage` at `0.4.7`); `@veritio/storage` and
  the framework adapters continue to declare `@veritio/core` as a peer at
  `>=0.0.0`. Publishing still requires the guarded release script and a
  short-lived npm token.
- The Claude plugin now pins `@veritio/claude-code@0.4.7` exactly on all seven
  hooks instead of resolving npm latest, and
  `verify:agent-integrations` fails the build unless all seven hooks, the
  Claude Code dependency pins, and `bun.lock` agree with the release version.
  An unavailable exact version fails closed rather than falling back.
- Published framework adapters (`better-auth`, `next`, `tanstack-start`,
  `sveltekit`, `react`, `vue`, `svelte`) move to 0.0.4. They declare
  `@veritio/core` as a peer at `>=0.0.0`, so this is a republish, not a
  compatibility change.
- The experimental, still-unpublished `@veritio/codex` workspace package is at
  0.0.3 and rejects both env and direct-call ingest timeouts above 30 seconds.
  The ceiling landed earlier in this release cycle at 0.0.2; 0.0.3 is a
  version-only bump. Neither version reached a registry.
- Internal, unpublished packages moved with the train and are listed here only
  so the version fields are accounted for: `@veritio/express`, `@veritio/hono`,
  `@veritio/trpc`, and `@veritio/server` to 0.0.2, `@veritio/gateway` to 0.0.2,
  and the `veritio` CLI to 0.1.1. None are on npm. The Claude Code plugin
  manifest moves to 0.1.2 and the marketplace catalog to 0.1.1.
- `@veritio/claude-code` now ships a `veritio-claude-code-spool` operator CLI
  for inspecting and controlling the durable delivery queue (`status`, `pause`,
  `quarantine`).
- `rm --recursive`, `rimraf` (including `npx`/`bunx` invocations), and
  `find … -delete` now classify as destructive/irreversible. Matching is scoped
  to one shell word group so pipeline segments cannot smear flags onto an
  unrelated leading command. This mapping is hash-affecting capture contract;
  the adapter `DESIGN.md` table changed in the same commit.

### Fixed

- The Claude Code spool reconciles its sequence from durable filenames before
  legacy migration, so an interrupted upgrade can never overwrite an
  already-migrated entry.
- The storage HTTP ingest client honors the portable three-way
  `deliveryDisposition` first; pause no longer requires the hosted hold code,
  and legacy pause codes remain a fallback only.
- Rolling request and byte ceilings are accounted across dispatch passes via a
  per-dispatcher rolling window ledger, and each in-flight ingest request is
  clamped to the permit time remaining so a dispatch pass cannot outlive its
  permit or lease.
- The gateway ship-out outbox enforces a hard queued-bytes ceiling; a full
  queue drops only the remote copy and surfaces a typed hold.
- `veritio login` bounds its HTTP requests and skips rewriting an
  already-managed Codex wrapper.

### Safety

- Local and GitHub-hosted guidance now separates agent model/API budgets from
  Veritio delivery budgets. Veritio capture is local-first; production stress
  and automatic backlog drains are explicitly excluded.

## [0.4.4] - 2026-08-02

### Changed

- Docs-only republish so npm shows the reworked package READMEs and the new
  `homepage` link to getveritio.com. No runtime or protocol changes.
  `@veritio/core` 0.4.4, `@veritio/storage` 0.4.4, `@veritio/claude-code`
  0.4.5 (pins bumped to 0.4.4), and framework adapters
  (`@veritio/better-auth`, `@veritio/next`, `@veritio/tanstack-start`,
  `@veritio/sveltekit`, `@veritio/react`, `@veritio/vue`, `@veritio/svelte`)
  0.0.3.
- `scripts/release-npm.sh` now also publishes the framework adapters after the
  core/storage/claude-code trio, keeping the skip-if-published behavior for
  partial releases.

## [0.4.3] - 2026-07-15

### Added

- `@veritio/claude-code`: captured activity now carries frozen-vocabulary risk
  signals (spec/risk-signals.schema.json) — destructive/delete/permission/
  config Bash command classes (recursive removals required for destructive;
  unmatched commands attach nothing), effect-side create/update/delete signals
  with `dataVolume` on file changes, and `envCriticality` derived from
  `VERITIO_ENVIRONMENT`. Lights up per-step scoring, episode risk rollups, and
  the hosted in-band risk detector for Claude Code capture. Adapter-only
  release: `@veritio/core` and `@veritio/storage` are unchanged and stay
  pinned at 0.4.2.

## [0.4.2] - 2026-07-15

### Fixed

- `@veritio/claude-code` + `@veritio/codex`: ingest ship-out now aborts after a
  bounded timeout (`VERITIO_INGEST_TIMEOUT_MS`, default 10s) instead of hanging
  on a stalled endpoint (previously a stalled hosted ingest froze the capturing
  agent for minutes). Capture stays fail-open; the local store already holds the
  records.
- `@veritio/claude-code`: file-change events now carry unique, replay-stable ids
  (`evt_filechange__<toolCallId>` / `evt_filechange__<sessionId>__turn<n>`)
  instead of the recorder default that collided on the ingest idempotency key
  after a tenant's first file change and dropped every later batch.
- `@veritio/core` provenance recorder: record-method edge ids are scoped by
  their owning event (`edge_<eventId>__<from>__<relation>__<to>`) so a
  recurring logical link (a session re-modifying the same file in a later turn)
  no longer collides and drops the batch; `link()` keeps its endpoint-derived
  singleton id. Default prompt event ids include `occurredAt` when supplied so
  the same prompt text recorded twice is two occurrences, not a conflict.

### Added

- `@veritio/codex` (experimental): Codex CLI capture via the `notify` hook — hash-only `agent.session.started` + `agent.prompt.recorded` per turn, local file sink + optional ingest; wrapper-safe (never replaces an existing notify).
- `veritio login`: browser device-authorization flow that mints a scoped ingest key on console approval and writes Codex/Claude Code capture config — no key pasted by hand.
- `plugins/veritio` + `.claude-plugin/marketplace.json`: Claude Code plugin bundling the capture hooks and the hosted Veritio MCP server (install via `/plugin marketplace add getveritio/veritio`).
- `@veritio/gateway`: optional `ingest` config block ships recorded gateway evidence to a Veritio ingest endpoint (Veritio Cloud or self-hosted) through a durable file outbox — local store stays authoritative, delivery is async and idempotent, cloud outages never block traffic.
- `@veritio/gateway` (experimental, unpublished): self-hosted AI governance gateway — transparent Anthropic/OpenAI passthrough proxy (streaming included) with virtual keys, enforced provider/model/endpoint allowlists, provider-reported token metering costed in integer micro-USD, and one hash-chained `ai.request.*` audit event per request outcome (metadata + sha256 content hashes only, never bodies or key material). Fail-closed evidence semantics: in the default `block` mode the gateway refuses traffic it cannot evidence. Vocabulary frozen in `spec/ai-gateway-capture.md`.
- `scripts/release-npm.sh`: the guarded npm publish path for the release trio
  (verify gate, dependency-ordered `bun publish` with workspace-pin rewriting,
  post-publish registry check; token supplied at run time, never stored).

## [0.4.1] - 2026-07-09

### Fixed

- Published Node-compatible ESM specifiers for `@veritio/core` export-bundle
  helpers. `@veritio/core`, `@veritio/storage`, and `@veritio/claude-code`
  were released together; `@veritio/claude-code` now pins the `0.4.1` core and
  storage packages.

## [0.3.0] - 2026-07-07

### Added

- Evidence export bundles (`vevb-1`): a portable, offline-verifiable container
  that indexes tamper-evident record files under a signed manifest.
  `@veritio/core` gains `buildExportBundle` (deterministic, clock-free assembly
  of audit/edge/commit records into fixed `records/*.jsonl` files plus an
  embedded `verification.json`), `computeRootHash`, `serializeExportBundle` /
  `parseExportBundle` (canonical single-file container), `signExportBundle`
  (Ed25519 detached signature over the manifest digest), and
  `verifyExportBundle` (fail-closed structure/integrity/chains/signature gates).
- `veritio verify-bundle <file> [--public-key <path>] [--require-signature]
  [--json]` CLI command: reads a container, runs the offline verifier, prints
  per-gate results and a `VALID`/`INVALID` verdict, and exits non-zero on
  failure. Public keys are accepted as raw 32-byte, hex, or base64.
- MCP `create_export_bundle` now emits a `vevb-1` bundle.
- Normative format spec `spec/export-bundle.md`, container/manifest/signature
  JSON Schema `spec/export-bundle.schema.json`, and pinned conformance fixtures
  `spec/conformance/export-bundle-golden.json` (a complete signed bundle over
  real record envelopes) and `spec/conformance/export-bundle-tampered.json` (the
  same bytes with one record byte flipped). Both carry the raw verifying public
  key as hex so any implementation can reproduce the verdict offline.

## [0.2.0] - 2026-07-05

`@veritio/core` 0.2.0, `@veritio/storage` 0.2.0, `@veritio/claude-code` 0.2.0
(released together; claude-code pins the others exactly). No breaking protocol
changes in this release: default-policy scoring output is byte-identical to
0.1.x, and all pre-existing conformance fixtures and frozen hash anchors are
unchanged.

### Added

- Temperature-derived risk policies: `riskPolicy({ temperature, overrides })`
  (`risk_policy` in Python, `RiskPolicy` in Go) derives a full
  `RiskScoringPolicy` from `veritio.reference.v1`. Temperature is a multiple of
  0.01 in `[0,1]`; `0.5` reproduces the reference policy byte-for-byte; derived
  versions look like `veritio.reference.v1+temp0.70`. Overrides merge after
  derivation and require an explicit `policyVersion` (fail closed). Pinned by
  `spec/conformance/risk-policy-temperature.json`.
- Per-action frequency rules in the episode rollup:
  `policy.rollup.frequencyRules` (`{ actions, windowSeconds, threshold, boost }`)
  detects bursts such as repeated failed logins; rules fire once per episode and
  the rollup score becomes `max(peak, velocityScore, frequencyScore)`. Rollup
  steps accept an optional `action`; policies without rules emit byte-identical
  pre-0.2.0 output. Pinned by `spec/conformance/risk-episode-frequency.json`.
- Better Auth adapter security mappers: `recordLoginFailed`
  (`auth.login.failed`) and `recordAccessDenied` (`authz.access.denied`) —
  translation-only, PII-safe (the attempted email is never recorded).
- Normative prose spec `spec/risk-scoring.md`; full policy field reference and
  temperature/frequency documentation in `docs/risk-scoring.md`; risk-scoring
  README sections for the Python and Go SDKs.
- `examples/risk-scoring-walkthrough`: tested walkthrough driving the real
  Better Auth adapter (burst escalates to `critical`, the same actions spread
  out stay `low`).
- Agent Skills for coding agents (`skills/veritio-audit-trail`,
  `skills/veritio-risk-scoring`), installable via
  `npx skills add getveritio/veritio`.

### Accumulated earlier items (shipped across the 0.1.x releases; the changelog was not cut at 0.1.0/0.1.1)

- OSS hygiene scaffold for contribution workflow, security disclosure, GitHub issue templates, pull request review, and release checks.
- Shared protocol conformance fixtures for canonical JSON, event creation, redaction, event hashing, audit record hashing, and idempotency-key hashing across TypeScript, Python, and Go tests.
- Runner-neutral storage conformance tests for durable `AuditStore` adapters.
- Env-gated live storage conformance tests for Postgres-compatible stores, the Neon factory, MySQL, MariaDB, and MongoDB.
- Runnable Next.js App Router plus Better Auth reference example with server-owned tenant and actor context.
- Deterministic cross-language risk-signal scoring (`risk.ts` / `risk.py` / `risk.go`) with the `DEFAULT_RISK_POLICY` reference policy (`veritio.reference.v1`), pinned by `spec/conformance` fixtures. See `docs/risk-scoring.md`.
- `security.risk` assertion builders (`createSecurityRiskAssertion`, `buildSecurityRiskAssessedEvent`, `hashAssertionRecord`) and the `activity_episode` evidence entity type plus the `activity.episode.started` lifecycle event/template.
- `activityEpisodeId` threading: stamped on every session event by the recorder (parity with `metadata.sessionId`), captured per session by `@veritio/claude-code`, and surfaced on the Better Auth example agent-session UIs.
- Local server `recordAssertion` / `listAssertions`: stores a precomputed `security.risk` assertion verbatim and links it to its subject by a `based_on` edge (the server is a sink and never scores).

### Changed

- Storage package exports `@veritio/storage/conformance` for external database adapter checks.
- Postgres/Neon and MySQL/MariaDB example schemas now match the storage adapter column contract.
- **BREAKING:** removed `riskScore` from the session security context (Better Auth adapter `BetterAuthSessionSecurityContext`, and the TypeScript/Python/Go `SessionSecurityContext` templates). Hosts now record a structured `riskSignals` envelope that the SDK scores deterministically. Migration: replace the numeric `riskScore` on the security context with a `riskSignals` envelope on event metadata via `withRiskSignals` (`with_risk_signals` in Python, `WithRiskSignals` in Go).

### Fixed

- Nothing yet.

### Security

- Nothing yet.

## Release Note Guidelines

For each release, include:

- protocol, schema, canonical JSON, hash, idempotency, redaction, retention, or storage-ordering changes
- TypeScript, Python, and Go SDK compatibility notes
- adapter and storage helper changes
- package publishing notes for public packages
- migration steps for breaking or behavior-affecting changes
- security fixes or disclosure references when public

Use evidence-support language. Do not claim that a Veritio release provides legal advice or automatic compliance with any regulation or framework.
