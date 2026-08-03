# AI Integration Guide

This repository is designed so AI coding agents can inspect, emit, query, and
verify application evidence without inventing protocol details or leaking
private host data.

## Stable Starting Points

- `spec/event.schema.json`: language-neutral audit event contract.
- `spec/edge.schema.json`: language-neutral evidence graph edge contract.
- `spec/audit-record.schema.json`: append-only audit record envelope.
- `spec/edge-record.schema.json`: append-only edge record envelope.
- `spec/conformance/`: canonical JSON, hashing, redaction, creation vectors,
  and governed-action draft parity fixtures.
- `sdks/typescript/src/index.ts`: TypeScript SDK entrypoint.
- `sdks/typescript/src/provenance.ts`: TS-only agent/change provenance recorder.
- `sdks/python/src/veritio/__init__.py`: Python SDK entrypoint.
- `sdks/go/event.go`: Go SDK entrypoint.
- `server/node/src/index.ts`: local Workbench, MCP, graph, verification, and
  export preview implementation.
- `adapters/claude-code/`: Claude Code hook capture and reference MCP query
  adapter.

## Agent Rules

- Keep protocol semantics in `spec/` and SDKs, not in a framework adapter.
- For form/API mutations, use `createGovernedActionDraft`,
  `create_governed_action_draft`, or `CreateGovernedActionDraft` at the
  server-side business mutation boundary. Do not record governed changes from
  browser form state.
- Do not send secrets, raw tokens, passwords, API keys, cookies, authorization
  headers, raw prompts, raw tool inputs, command output, file contents, or diffs
  into event metadata.
- Prefer stable IDs, content hashes, path hashes, counts, coarse locations, and
  bounded status fields.
- Always include tenant scope before appending durable records in a multi-tenant
  host.
- Treat `metadata` as potentially sensitive and pass it through SDK redaction.
- Link related evidence with edges that reference stable entity IDs or hashes.
- Do not claim Veritio guarantees compliance; use evidence support wording.
- Do not copy private execution specs, roadmap details, or operational prompts
  into public docs or examples.

## Common Event Shape

```json
{
  "id": "evt_01",
  "schemaVersion": "2026-06-10",
  "occurredAt": "2026-06-10T00:00:00.000Z",
  "actor": { "type": "user", "id": "usr_123" },
  "action": "org.member.invited",
  "target": { "type": "organization", "id": "org_123" },
  "scope": { "tenantId": "org_123", "environment": "production" },
  "purpose": "access_management",
  "lawfulBasis": "contract",
  "retention": "security_1y",
  "metadata": { "role": "viewer" }
}
```

## Common Edge Shape

```json
{
  "id": "edge_01",
  "schemaVersion": "2026-06-13",
  "occurredAt": "2026-06-13T00:00:00.000Z",
  "scope": { "tenantId": "org_123", "environment": "production" },
  "from": { "type": "agent_session", "id": "agt_sess_123" },
  "relation": "created",
  "to": { "type": "file", "id": "file_billing_plan", "pathHash": "sha256:..." },
  "metadata": { "reason": "ai_agent" }
}
```

## Agent Provenance

The TypeScript SDK exports `createProvenanceRecorder`. It emits agent, change,
review, CI, deployment, and runtime observation events and connects them through
evidence edges.

Recorder conventions:

- Every session-related event gets `metadata.sessionId`.
- Every session-related event also gets `metadata.activityEpisodeId`, the stable
  activity-episode id that groups one session's events. It is stamped after
  caller metadata (so a caller cannot shadow it), the same mechanism as
  `metadata.sessionId`.
- Structured risk signals ride on `metadata.riskSignals` (via `withRiskSignals`)
  and are scored deterministically by the SDK risk module, never by
  `createAuditEvent`. See [risk-scoring.md](./risk-scoring.md).
- Event IDs are deterministic from stable caller IDs unless overridden.
- Edges derive from stable entity references.
- The enforcing human is linked through a `caused_by` edge rather than a new
  event field.
- The host injects `recordEvent` and `recordEdge` sinks; the recorder owns no
  storage transaction.

Python and Go do not yet expose the same high-level recorder. They should keep
event and edge semantics aligned so a later recorder can emit equivalent
payloads.

## Risk Assertions

A `security.risk` assertion records a precomputed risk conclusion as append-only
evidence. It uses `recordType: assertion.recorded` (not the audit-event shape),
carries `producer.authority: veritio.detectors`, and links to its subject through
a `based_on` edge — never an inline `evidence[]` array. Detectors (in Veritio
Cloud) append a `security.risk.assessed` event and the assertion record on
band-crossing; the OSS SDK ships only the builders (`buildSecurityRiskAssessedEvent`,
`createSecurityRiskAssertion`, `hashAssertionRecord`). The local server stores
assertions verbatim and never recomputes the score. See
[risk-scoring.md](./risk-scoring.md).

## Claude Code Capture

`@veritio/claude-code` captures Claude Code activity passively through hooks.
The hook writes redacted local evidence to `createFileEvidenceStore` and can
optionally POST the same records to an ingest endpoint when the host supplies
both an ingest URL and key.

Captured evidence keeps raw content out of storage:

- prompts are represented by hashes
- file changes use before/after content hashes and path hashes
- tool inputs and command output are not persisted
- MCP query/export reads the local file-backed store

The adapter includes a read-only MCP server with tools to list sessions, inspect
a session graph, and export a verifiable bundle.

Remote delivery is bounded independently from capture: local evidence remains
authoritative, normal hooks never replay queued batches, the queue has compiled
hard batch/byte ceilings, and recovery requires a one-request canary followed by
an explicitly budgeted drain. Package hooks must name an exact published
version; `npm latest` is not a review boundary.

## Codex CLI Capture

The in-repo experimental `@veritio/codex` adapter maps the local Codex CLI
`notify` callback to hash-only session and prompt records. One turn creates at
most one ingest POST, and its timeout is constrained to 1-30 seconds. It has no
automatic retry or backlog drain. The package and `veritio` CLI are not yet
published, so setup is supported from a repository checkout only.

Codex cloud tasks and GitHub code reviews do not expose the local CLI notify
contract to this adapter. Do not claim they are captured. GitHub CI proves the
adapter with synthetic notifications and no paid agent or ingest credentials.

## GitHub-hosted agents

Agent cost controls and Veritio delivery controls solve different problems.
For Claude Code GitHub Actions, set a narrow trigger, workflow concurrency,
`timeout-minutes`, and `--max-turns`; install an exact reviewed capture package
and keep credentials in GitHub Secrets. For Codex cloud/GitHub, use the native
product's usage limits; Veritio's local notify adapter is not an agent-spend
limit and does not run there today.

Repository verification must stay deterministic and free of paid calls:

```sh
bun run verify:agent-integrations
bun run --cwd adapters/claude-code test
bun run --cwd adapters/codex test
```

Never run delivery stress, a production canary, or a spool drain from an
untrusted pull-request workflow.

## Local Agent Check

Start the local Workbench and MCP endpoint:

```sh
veritio dev --mcp --scenario
```

Then use MCP JSON-RPC `tools/list` and `tools/call` requests against `/mcp`.
Read tools include event listing, edge listing, graph query, chain verification,
export preview, and integration scenarios. Write tools are hidden unless the
server starts with `--allow-write-tools`.

## Repository Routing

Agents should route work by source of truth:

- Protocol fields, schemas, hashes, redaction, SDK behavior, adapters, storage,
  local server, verifier, export format, and examples: `veritio`.
- Public site pages, SEO metadata, marketing copy, website docs pages, and
  static assets: `veritio-website`.
- Hosted ingest, hosted MCP, managed storage, billing, regions, admin,
  customer portals, and operational jobs: `veritio-cloud`.

For cross-repo work, update public protocol and SDK behavior in this repo first,
then hosted behavior, then website claims after backing behavior exists.
