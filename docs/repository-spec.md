# Veritio OSS Repository Spec

This repository is the portable evidence foundation for Veritio. It defines the
public protocol, SDK behavior, storage contracts, adapters, local/self-hosted
server modules, local Workbench/MCP loop, verifier, export format, conformance
fixtures, and public examples.

It must remain useful without a Veritio Cloud account.

## Owns

- `spec/`: language-neutral event, edge, audit-record, and edge-record schemas.
- `spec/conformance/`: cross-language canonical JSON, hashing, redaction, event
  creation, edge creation, and record hashing fixtures.
- `sdks/typescript/`, `sdks/python/`, `sdks/go/`: public SDKs with equivalent
  field names and shared semantics.
- `storage/`: host-injected storage helpers, conformance behavior, schema
  helpers, Redis tenant-tip cache, and local file-backed evidence store.
- `adapters/`: thin framework, auth, UI-intent, and agent adapters.
- `server/`: local/self-hosted server modules.
- `cli/`: local Workbench and MCP command-line tooling.
- `examples/`: public examples that work without proprietary hosted state.
- `docs/`: public OSS architecture, protocol, routing, AI integration, release,
  and split-repo coordination docs.
- `scripts/verify-split.sh`: split-repo verification orchestration from this
  repo.
- `.agents/`, `.codex/agents/`, `.claude/`: local agent configuration and
  project-scoped review helpers.

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

## Does Not Own

- Public website implementation, SEO pages, marketing assets, or website docs
  page rendering.
- Hosted SaaS/PaaS implementation, billing, hosted regions, hosted customer
  portals, hosted admin, private operations, operational jobs, or managed
  service commitments.
- Hosted-only fields that are not part of the public protocol.
- Private roadmap, execution prompts, unpublished product specs, or private
  orchestration notes.
- Website or hosted implementation code under the guise of coordination.

## Edit Routing

| Change | Owning repository |
| --- | --- |
| New event field, edge relation, hash input, canonical JSON rule, redaction rule, idempotency rule, export manifest field | `veritio` first |
| SDK API, adapter behavior, storage helper, local verifier, local server, Workbench, MCP, or conformance fixture | `veritio` |
| Hosted ingest, hosted MCP, billing, admin, regions, customer portal, managed storage, or private operational job | `veritio-cloud` |
| Public landing page, website docs page, SEO metadata, marketing copy, or website asset | `veritio-website` |

## Handoff Contract

If a task begins here but needs hosted behavior, first define or confirm the
public contract in this repo. Then implement hosted behavior in `veritio-cloud`.

If a task begins here but is only public website copy or website docs rendering,
hand it to `veritio-website`.

For feasible multi-repo work, coordinate sibling edits from this repo using
explicit paths and split verification commands instead of asking the user to
open separate chats.

## Product Wording

Prefer:

- evidence support
- audit trail
- records of processing
- data subject workflow
- exportable evidence
- tamper-evident records

Avoid:

- guaranteed compliance
- automatic compliance
- legal advice
- certified by Veritio
- claims that installing the SDK satisfies GDPR, EAA, SOC 2, HIPAA, DORA, NIS2,
  or other frameworks by itself

## Verification

Run `bun run verify` before claiming done for non-doc OSS changes.

For docs-only changes, inspect changed docs, run `git diff --check`, and run
targeted checks when examples, commands, package names, or links changed.

Run `bun run verify:split` before claiming done for changes that touch multiple
Veritio split repositories.
