# Veritio

**English** | [Deutsch](README.de.md) | [한국어](README.ko.md) | [简体中文](README.zh-CN.md)

[getveritio.com](https://getveritio.com) · [Docs](https://getveritio.com/docs/) · [Veritio Cloud](https://getveritio.com/cloud/)

[![Verify](https://github.com/getveritio/veritio/actions/workflows/verify.yml/badge.svg)](https://github.com/getveritio/veritio/actions/workflows/verify.yml)
[![npm](https://img.shields.io/npm/v/%40veritio%2Fcore?label=%40veritio%2Fcore)](https://www.npmjs.com/package/@veritio/core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Veritio is a protocol-first open-source **evidence layer**: tamper-evident
audit trails, AI-agent provenance, consent and DSAR workflow evidence,
retention events, and compliance exports that anyone can verify offline.

Veritio supports compliance evidence collection and verification; it is not
legal advice and does not make an application automatically compliant with
GDPR, EAA, SOC 2, HIPAA, DORA, NIS2, or any other framework.

## Why Veritio

- **Tamper-evident by construction.** Append-only records with canonical JSON,
  SHA-256 hash chains, and tenant-scoped idempotency. Verification detects
  mutation, deletion, and reordering.
- **Verifiable offline.** Export a signed evidence bundle (`vevb-1`) and verify
  it anywhere — no network, no vendor, no account.
- **A protocol, not a lock-in.** Language-neutral schemas in
  [`spec/`](spec/), with TypeScript, Python, and Go SDKs that produce
  byte-identical hashes and scores, pinned by cross-language conformance
  fixtures.
- **AI-agent provenance.** Capture Claude Code sessions as hash-chained,
  redacted evidence — prompts, tool calls, and file changes as hashes and
  stable IDs, never raw content.
- **Deterministic risk scoring.** Structured risk signals score into identical
  bytes across all three SDKs; no model calls, no heuristics at query time.
- **Privacy by default.** Deterministic metadata redaction, stable IDs over
  personal data, and fail-closed integrity when required fields are missing.
- **Thin edges.** Framework adapters translate context only; storage is
  host-injected — your database clients, your credentials, never ours.

## Quickstart

```sh
npm install @veritio/core
```

```ts
import { MemoryAuditStore, createAuditEvent } from "@veritio/core";

const store = new MemoryAuditStore();

const record = await store.append(
  createAuditEvent({
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
  }),
);
// record.hash chains to the previous record for this tenant.
```

For durable storage, inject your own database client through
[`@veritio/storage`](storage/README.md) (Postgres, Neon, MySQL, MariaDB,
MongoDB, plus a local file store and a Redis tip cache). Python and Go SDKs
expose the same event, hashing, and redaction semantics — see
[`sdks/python`](sdks/python/) and [`sdks/go`](sdks/go/).

**Prove it later.** Build a portable export bundle and verify it offline —
per-gate `structure` / `integrity` / `chains` / `signature` results and a final
`VALID` / `INVALID`:

```sh
veritio verify-bundle bundle.json --public-key key.hex --require-signature
```

The bundle format is normative in [`spec/export-bundle.md`](spec/export-bundle.md);
the `veritio` CLI currently runs from this repo and is not yet on npm.

## Capture AI Agent Activity

[`@veritio/claude-code`](adapters/claude-code/README.md) records Claude Code
sessions as a hash-chained provenance trail — out-of-band via hooks, so the
evidence does not depend on the agent choosing to report:

- Prompts, tool inputs, and file contents are captured as **hashes and stable
  IDs only** — raw content never enters the trail.
- Every event carries the session's `sessionId` and a durable
  `activityEpisodeId`, so a whole agent session rolls up into one reviewable
  episode.
- Bash commands and file changes are classified into structured
  `metadata.riskSignals`, scored deterministically by the SDK risk module
  (`veritio.reference.v1` policy) — same bytes in TypeScript, Python, and Go.
  See [docs/risk-scoring.md](docs/risk-scoring.md).
- A read-only MCP server lets a human or another agent list sessions, inspect
  the provenance graph, and export a verifiable bundle.

Teach coding agents the SDK itself via [skills.sh](https://www.skills.sh):

```sh
npx skills add getveritio/veritio
```

## Governed Actions

When a server action or API route mutates a governed entity, one helper derives
the change/activity IDs, tenant-scoped idempotency hash, changed paths,
revision evidence, and outbox-ready event and edge inputs — available as
`createGovernedActionDraft` (TS), `create_governed_action_draft` (Python), and
`CreateGovernedActionDraft` (Go):

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
```

Record governed actions at the server-side business mutation boundary, not in
browser form state. Full recipes — TypeScript, FastAPI, Gin, framework
adapters, hosted ingest, and transactional outbox — live in
[`docs/integrations.md`](docs/integrations.md).

## Local Workbench

Run the local Workbench and MCP endpoint without any account:

```sh
veritio dev --mcp --scenario
```

It serves event/edge ingest, evidence graph query, chain verification, export
preview, a browser UI, and an MCP JSON-RPC endpoint at `/mcp` on
`http://127.0.0.1:4983`. Write tools stay hidden unless started with
`--allow-write-tools`.

## Ecosystem

| Package | Status | Role |
| --- | --- | --- |
| [`@veritio/core`](sdks/typescript/) | npm | TypeScript SDK: events, edges, hashing, redaction, templates, provenance recorder, risk scoring, assertions. |
| [`@veritio/storage`](storage/) | npm | Host-injected Postgres/Neon/MySQL/MariaDB/MongoDB stores, Redis tip cache, file store, conformance tests. |
| [`@veritio/claude-code`](adapters/claude-code/) | npm | Claude Code capture hooks + read-only MCP query/export. |
| [`@veritio/better-auth`](adapters/better-auth/) | npm | Better Auth server-side lifecycle adapter. |
| [`@veritio/next`](adapters/next/), [`@veritio/tanstack-start`](adapters/tanstack-start/), [`@veritio/sveltekit`](adapters/sveltekit/) | npm | Server-side framework adapters. |
| [`@veritio/react`](adapters/react/), [`@veritio/vue`](adapters/vue/), [`@veritio/svelte`](adapters/svelte/) | npm | Browser-safe UI intent helpers; no client-side recording. |
| [`sdks/python`](sdks/python/) | in-repo | Python SDK (`pip install -e sdks/python`; not yet on PyPI). |
| [`sdks/go`](sdks/go/) | Go module | `go get github.com/getveritio/veritio/sdks/go`. |
| `veritio` CLI, `@veritio/server`, `@veritio/gateway`, `@veritio/codex`, express/hono/trpc shells | in-repo | Local Workbench/MCP CLI, self-hosted server module, experimental AI gateway, and adapter surfaces not yet published. |

## Veritio Cloud

[Veritio Cloud](https://getveritio.com/cloud/) is the hosted option: managed
ingest, dashboards, risk timelines, and region-aware exports on top of the same
protocol. Everything in this repository works fully self-hosted without an
account — hosted delivery is always optional.

## Learn More

- [`spec/`](spec/) — language-neutral schemas, hash rules, and conformance
  fixtures; the protocol source of truth.
- [`docs/architecture.md`](docs/architecture.md) — layers, integrity model,
  redaction, risk, and the hosted boundary.
- [`docs/integrations.md`](docs/integrations.md) — integration recipes.
- [`docs/ai-integration.md`](docs/ai-integration.md) — AI agent capture and MCP
  guidance.
- [`examples/`](examples/) — runnable Better Auth, FastAPI, Gin, storage, and
  hosted-ingest examples.
- Contributing: `bun install && bun run verify` runs the full cross-language
  gate; see [`docs/release-checklist.md`](docs/release-checklist.md).

## License

Apache-2.0.
