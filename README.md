# Veritio

**English** | [한국어](README.ko.md) | [简体中文](README.zh-CN.md)

[getveritio.com](https://getveritio.com) · [Docs](https://getveritio.com/docs/) · [Veritio Cloud](https://getveritio.com/cloud/)

Veritio is a protocol-first open-source evidence layer for application audit
trails, consent history events, data subject workflow evidence, retention
events, records of processing support, evidence graphs, and exportable records.

It provides language-neutral schemas, TypeScript/Python/Go SDKs, thin framework
adapters, host-injected storage helpers, local Workbench/MCP tooling, and
conformance fixtures. Veritio supports evidence collection and verification; it
is not legal advice and does not make an application automatically compliant
with GDPR, EAA, SOC 2, HIPAA, DORA, NIS2, or any other framework.

## What Is Implemented

- Language-neutral audit event and evidence-edge schemas in `spec/`.
- Append-only audit and edge record envelopes with canonical JSON, SHA-256
  hashes, previous-hash links, and tenant-scoped idempotency.
- TypeScript, Python, and Go SDKs for event/edge creation, canonicalization,
  hashing, redaction, shared audit templates, and governed-action drafts for
  server-side create/update/delete flows.
- TypeScript-only audit storage and provenance helpers, including the
  `createProvenanceRecorder` agent/change recorder.
- Public JavaScript packages for Better Auth, Next.js, TanStack Start,
  SvelteKit, React, Vue, Svelte, storage helpers, Claude Code capture, and the
  local CLI.
- In-repo private server and adapter shells for self-hosted/server-side surfaces
  that are not yet public npm packages.
- Local Workbench and MCP development loop through `veritio dev --mcp`.
- Runnable examples for Better Auth across frameworks, Python FastAPI, Go Gin,
  storage adapters, and optional hosted-ingest delivery.

## Install

Public package names are stable, but this repository is still pre-1.0. Use local
workspace links while developing inside this repo.

```sh
npm install @veritio/core
npm install @veritio/storage
npm install @veritio/better-auth
npm install -D veritio
```

```sh
pip install veritio
go get github.com/getveritio/veritio/sdks/go
```

Inside this monorepo:

```sh
bun install
bun run verify
```

### Agent Skills

Teach Claude Code, Codex, Cursor, opencode, and other coding agents the Veritio
SDK — installable from [skills.sh](https://www.skills.sh):

```sh
npx skills add getveritio/veritio
```

This installs `veritio-audit-trail` (events, storage, adapters, verification)
and `veritio-risk-scoring` (signals, temperature policies, frequency rules,
assertions) from [`skills/`](skills/). Both follow the
[Agent Skills](https://agentskills.io) `SKILL.md` format.

## TypeScript Quick Start

Use `@veritio/core` when you want normalized event and edge payloads plus
deterministic hashes. The in-memory `MemoryAuditStore` persists audit events
only; use the local Workbench/server or file-backed store when you need event
and edge chains.

```ts
import {
  MemoryAuditStore,
  createAuditEvent,
  createEvidenceEdge,
  hashEvidenceEdge,
} from "@veritio/core";

const store = new MemoryAuditStore();

const event = createAuditEvent({
  id: "evt_01",
  occurredAt: "2026-06-10T00:00:00.000Z",
  actor: { type: "user", id: "usr_123" },
  action: "org.member.invited",
  target: { type: "organization", id: "org_123" },
  scope: { tenantId: "org_123", environment: "production" },
  purpose: "access_management",
  lawfulBasis: "contract",
  retention: "security_1y",
  metadata: { inviteId: "inv_123", role: "viewer" },
});

const record = await store.append(event);

const edge = createEvidenceEdge({
  id: "edge_01",
  occurredAt: "2026-06-10T00:00:01.000Z",
  scope: { tenantId: "org_123", environment: "production" },
  from: { type: "actor", id: "usr_123", actorType: "user" },
  relation: "created",
  to: { type: "runtime_event", id: event.id },
  metadata: { reason: "member_invite" },
});

const edgeHash = hashEvidenceEdge(edge, record.hash);
```

## Governed Action Quick Start

Use `createGovernedActionDraft` when a server action or API route mutates a
governed entity. The helper derives tenant-scoped idempotency hashes,
change/activity ids, changed paths, revision evidence, and outbox-ready event
and edge inputs. It is available as `createGovernedActionDraft` in TypeScript,
`create_governed_action_draft` in Python, and `CreateGovernedActionDraft` in
Go.

```ts
import { createGovernedActionDraft, defineEntity } from "@veritio/core";

const ProjectEntry = defineEntity({
  authority: "app.example",
  type: "project_entry",
  schemaRef: "app.example/project-entry@1",
  fieldSetRef: "project-entry-governed-fields@1",
  identity: (row: { id: string }) => row.id,
  fields: {
    status: { capture: "full" },
    customerEmail: { capture: "keyed_digest" },
    privateNotes: { capture: "omit" },
  },
});

const draft = createGovernedActionDraft({
  scope: { tenantId: "org_123", environment: "production" },
  entity: ProjectEntry,
  before,
  after,
  actionType: "project_entry.updated",
  activityType: "project_entry.updated",
  initiatedBy: { authority: "app.example.auth", kind: "principal", type: "user", id: "usr_123" },
  performedBy: { authority: "app.example.auth", kind: "principal", type: "user", id: "usr_123" },
  producer: { authority: "app.example", kind: "principal", type: "service", id: "api" },
  idempotencyKey: `project_entry:${after.id}:v${after.version}`,
  mutationBinding: "same_transaction",
  digestKeys: { keyedDigest: { keyVersion: "email-v1", secret: tenantDigestSecret } },
});
```

Record governed actions at the server-side business mutation boundary, not
inside browser form state. See [`docs/integrations.md`](docs/integrations.md)
for TypeScript, FastAPI, Gin, framework, hosted-ingest, and transactional
outbox recipes.

## Local Workbench

Run the OSS local Workbench and MCP endpoint without a hosted account:

```sh
veritio dev --mcp --scenario
```

The default server binds `http://127.0.0.1:4983` and exposes:

- event and edge ingest/list endpoints
- evidence graph query
- chain verification
- export bundle preview
- browser Workbench UI
- MCP JSON-RPC endpoint at `/mcp`

MCP read tools are available by default. Write tools such as
`veritio.record_event`, `veritio.record_edge`, and `veritio.reset_dev_store`
are hidden unless the CLI is started with `--allow-write-tools`.

## Export bundles

A Veritio Evidence Export Bundle (`vevb-1`) is a portable, offline-verifiable
container: a signed manifest indexing tamper-evident record files. Build one from
raw records, optionally sign it with Ed25519, and verify it anywhere without a
network or authority call. The format is normative in
[`spec/export-bundle.md`](spec/export-bundle.md), pinned by
`spec/export-bundle.schema.json` and the golden/tampered conformance fixtures.

```ts
import { buildExportBundle, signExportBundle, serializeExportBundle } from "@veritio/core";

const bundle = await buildExportBundle({
  scope: { tenantId: "org_123" },
  range: { from: "2026-07-01T00:00:00Z", to: "2026-07-02T00:00:00Z" },
  producer: { authority: "veritio", kind: "principal", type: "service", id: "svc_export" },
  createdAt: "2026-07-05T00:00:00Z", // caller-supplied: the build reads no clock
  events: auditRecords,
  edges: edgeRecords,
});

const keyPair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
const signed = await signExportBundle(bundle, keyPair.privateKey, keyPair.publicKey);
await Bun.write("bundle.json", serializeExportBundle(signed));
```

Verify offline with the CLI, passing the raw Ed25519 public key (raw 32-byte,
hex, or base64):

```sh
veritio verify-bundle bundle.json --public-key key.hex --require-signature
```

It prints per-gate `structure` / `integrity` / `chains` / `signature` results and
a final `VALID` / `INVALID`, and exits non-zero when the bundle does not verify.
An unsigned bundle proves internal consistency only; require signatures (a signed
bundle plus `--public-key` and `--require-signature`) to prove its origin.

## Protocol Invariants

The public protocol lives in `spec/` and conformance fixtures live in
`spec/conformance/`.

| File | Purpose |
| --- | --- |
| `spec/event.schema.json` | Audit event payload, schema version `2026-06-10`. |
| `spec/edge.schema.json` | Evidence graph edge payload, schema version `2026-06-13`. |
| `spec/audit-record.schema.json` | Append-only record envelope for events. |
| `spec/edge-record.schema.json` | Append-only record envelope for edges. |
| `spec/conformance/*.json` | Cross-language vectors for canonical JSON, hashing, redaction, event creation, edge creation, and governed-action drafts. |

Protocol-sensitive behavior:

- Canonical JSON version is `veritio-json-v1`.
- Hash algorithm is `sha256`.
- Persisted record hashes use `sha256(veritio-json-v1(record without hash))`.
- Event hashes use `sha256(veritio-json-v1({ event, previousHash }))`.
- Edge hashes use `sha256(veritio-json-v1({ edge, previousHash }))`.
- Idempotency key hashes use `sha256(tenantId + NUL + idempotencyKey)`.
- Stored audit and edge records require tenant scope and fail closed when
  required integrity data is missing.
- Metadata redaction is deterministic and based on sensitive key names such as
  password, secret, token, API key, authorization, email, phone, and SSN.

Consent, data subject request, retention, organization, auth, agent, code, CI,
deployment, and export flows are currently represented through templates,
actions, graph entities, and graph relations. They are not separate workflow
schemas in `spec/` yet.

## Package Map

| Package or path | Status | Role |
| --- | --- | --- |
| `@veritio/core` | Public | TypeScript SDK, core event/edge helpers, memory audit store, templates, TS provenance recorder, deterministic risk-signal scoring, and `security.risk` assertion builders. |
| `veritio` Python package | Public | Python SDK for event/edge helpers, hashing, redaction, and templates. |
| `github.com/getveritio/veritio/sdks/go` | Public | Go SDK for event/edge helpers, hashing, redaction, and templates. |
| `@veritio/storage` | Public | Host-injected SQL, MongoDB, Redis tip cache, conformance helpers, and local file-backed evidence store. |
| `@veritio/better-auth` | Public | Better Auth server-side lifecycle adapter. |
| `@veritio/next` | Public | Next.js server actions and route handler adapter. |
| `@veritio/tanstack-start` | Public | TanStack Start server function and route adapter. |
| `@veritio/sveltekit` | Public | SvelteKit server action and endpoint adapter. |
| `@veritio/react`, `@veritio/vue`, `@veritio/svelte` | Public | Browser-safe UI intent helpers; they do not record audit events client-side. |
| `@veritio/codex` | Public (experimental) | Codex CLI notify-hook capture with local redacted file sink and optional ingest POST. Hash-only session/prompt evidence. |
| `@veritio/claude-code` | Public | Claude Code hook capture with local redacted file sink, optional ingest POST, and read-only MCP query/export. Threads a stable `activityEpisodeId` per session. |
| `veritio` CLI | Public | Local Workbench and MCP CLI. |
| `@veritio/gateway` | Public (experimental, unpublished) | Self-hosted AI governance gateway: transparent Anthropic/OpenAI passthrough proxy with virtual keys, enforced allowlist policy, provider-reported metering, and hash-chained `ai.*` evidence (`spec/ai-gateway-capture.md`). |
| `@veritio/server` | Private workspace package | Local/self-hosted Node server module for Workbench, MCP, graph query, verification, and export preview. |
| `@veritio/express`, `@veritio/hono`, `@veritio/trpc` | Private package shells | In-repo adapter surfaces that are not public packages yet. |
| `veritio-fastapi` | Package shell/example surface | Python FastAPI adapter direction plus runnable FastAPI example. |

## Language Parity

TypeScript, Python, and Go share the same protocol semantics for:

- audit event creation
- evidence edge creation
- canonical JSON normalization
- event, edge, audit-record, and edge-record hashing
- sensitive metadata redaction
- UTC millisecond timestamp normalization
- optional-field omission
- auth, organization, data, agent, and code audit templates
- deterministic `riskSignals` scoring (`DEFAULT_RISK_POLICY`,
  `veritio.reference.v1`), temperature-derived policies (`riskPolicy`),
  per-action frequency rules, and `security.risk` assertion builders — see
  [docs/risk-scoring.md](docs/risk-scoring.md) and
  [spec/risk-scoring.md](spec/risk-scoring.md)

The TypeScript SDK currently has extra runtime helpers: `MemoryAuditStore`,
audit/edge chain verification helpers, and the TS-only `createProvenanceRecorder`
for agent and change provenance. Python and Go must preserve the same event and
edge semantics when those higher-level recorders are added.

## Storage

`@veritio/storage` is host-injected. It does not open database connections, read
environment variables, or own credentials.

Durable store helpers:

- `createPostgresAuditStore`
- `createNeonAuditStore`
- `createMysqlAuditStore`
- `createMariaDbAuditStore`
- `createMongoAuditStore`

Local and cache helpers:

- `createFileEvidenceStore` writes tenant-scoped event and edge JSONL chains for
  local hooks, agent provenance, and reference MCP workflows.
- `createRedisAuditTipCache` stores validated tenant chain tips only; Redis is
  not a durable audit store by itself.
- `@veritio/storage/conformance` exports
  `createAuditStoreConformanceTests` for durable adapter tests.

## Examples

Start with `examples/README.md`.

- `nextjs-better-auth`, `tanstack-start-better-auth`,
  `react-better-auth`, `vue-better-auth`, and `sveltekit-better-auth` show
  server-side Better Auth lifecycle events, governed CRUD, graph edges, and
  scenario routes.
- `fastapi-governed-crud` and `gin-governed-crud` show the same ideas in Python
  FastAPI and Go Gin.
- `storage-postgres-neon`, `storage-mysql-mariadb`, `storage-mongodb`, and
  `storage-redis` show host-injected storage setup.
- `cloud-full-governance-poc` can post the same SDK-created evidence to a
  hosted ingest endpoint when a host supplies scoped credentials.

Examples are verified separately from the root workspace:

```sh
bun run verify:examples
```

## Repository Boundary

This repository owns the public OSS foundation:

- language-neutral specs
- TypeScript, Python, and Go SDKs
- framework adapters
- host-injected storage helpers
- local/self-hosted server modules
- local Workbench and MCP tooling
- verifier and export bundle format
- conformance fixtures and public examples

Sibling repositories own other surfaces:

- `veritio-website`: public Astro website, docs pages, SEO metadata, marketing
  copy, public examples, and static assets.
- `veritio-cloud`: private hosted SaaS/PaaS implementation, hosted ingest,
  hosted MCP, managed storage, billing, regions, customer portals, admin, and
  operational jobs.

Hosted Veritio must consume this repo through public package boundaries or
explicit local development links. Hosted-only fields, billing concepts, region
behavior, private admin operations, and customer portal details must not become
protocol semantics.

## Repository Layout

```txt
spec/                 Language-neutral event, edge, and record schemas
sdks/typescript/      TypeScript SDK
sdks/python/          Python SDK
sdks/go/              Go SDK
storage/              Host-injected storage adapters and local file store
adapters/             Framework, auth, UI-intent, and agent adapters
server/node/          Private local/self-hosted Node server module
gateway/              Self-hosted AI governance gateway (experimental)
cli/                  Local Workbench and MCP CLI
docs/                 OSS architecture, routing, AI integration, and release docs
examples/             Runnable public examples
scripts/              Verification and split-repo orchestration scripts
.agents/              Local Codex-style skills
.codex/               Codex agent and hook configuration
.claude/              Claude Code rules, agents, skills, and hooks
.github/              GitHub workflow configuration
```

Local private execution specs belong under ignored `.codex/private/` paths and
must not be committed or copied into public docs.

## Verification

Primary OSS gate:

```sh
bun run verify
```

Focused gates:

```sh
bun run test:ts
bun run test:python
bun run test:go
bun run test:storage
bun run test:adapters
bun run typecheck
bun run verify:examples
git diff --check
```

Split-repo coordination from this control repo:

```sh
bun run status:split
bun run verify:siblings
bun run verify:split
```

Use `bun run verify:split` for changes that span the OSS repo, the website
sibling, and the hosted cloud sibling.

## More Documentation

- `docs/README.md`: documentation index.
- `docs/architecture.md`: protocol, SDK, storage, server, Workbench, and export
  architecture.
- `docs/ai-integration.md`: guidance for AI coding agents and agent evidence
  capture.
- `docs/repo-map.md`: split-repo ownership map.
- `docs/repository-spec.md`: OSS repository ownership and handoff rules.
- `docs/split-orchestration.md`: control-repo commands and multi-repo workflow.
- `docs/release-checklist.md`: pre-release verification and publishing checks.

## License

Apache-2.0.
