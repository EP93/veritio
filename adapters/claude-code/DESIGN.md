# Veritio × Claude Code — Agent Provenance Capture (sub-project B)

**Status:** Implemented (grounded in the verified Claude Code hooks contract, CC 2.1.178 / docs 2026-06-16).
**Owner repo:** `veritio` (OSS adapter + reference MCP). Hosted MCP ingest is `veritio-cloud` (deferred).
**Depends on:** `@veritio/core` `createProvenanceRecorder` (which now stamps `metadata.sessionId`).

**As-built deltas from this design:**
- The reference query+export MCP lives **in the adapter package** (`src/query.ts` +
  `src/mcp.ts`, bin `veritio-claude-code-mcp`), not a separate `server/mcp-provenance`
  package — the adapter is the natural reader of the store it writes, and this avoids a
  4th workspace package. The file-backed store is in `@veritio/storage` as designed.
- Sink is selected by **presence** of `VERITIO_INGEST_URL` + `VERITIO_INGEST_KEY`
  (local file store always on; ingest POST added when both are set) rather than a
  `VERITIO_SINK` enum.
- Both bins run under **Bun** (the SDK `dist/` uses bundler-resolved imports).

## Goal

Capture a developer's Claude Code agent activity **passively** (via hooks) and turn
it into Veritio evidence — the same `AuditEvent` + `EvidenceEdge` graph the Sessions/
Audit/per-session-canvas surfaces (sub-project A) render. Then **expose** the recorded
provenance to a human or another agent via an MCP server (query + export).

Capture is out-of-band (hooks fire deterministically), so the audit trail does not
depend on the agent choosing to report — MCP is the *read* side, not the capture side.

## Decisions

- **First target:** Claude Code hooks (best-documented, passive, stable `session_id`).
- **Sink:** configurable — a **local file-backed evidence store by default** (zero-infra,
  self-contained), with an **optional POST to a Veritio ingest endpoint** (closing the
  loop into the cloud Sessions UI). Selected by config/env at the process boundary.
- **MCP surface:** **query + export** — list sessions, fetch a session's provenance
  graph, export a verifiable evidence bundle. A dedicated reference server (not the
  Workbench).
- **Capture depth:** hashes + stable ids only (protocol-aligned); raw prompts/diffs/
  commands are never persisted (full-capture is a separate, later mode).

## Package layout

```
adapters/claude-code/
  package.json            @veritio/claude-code
  src/
    index.ts              public exports (handleHookEvent, config types)
    hook.ts               CLI entry: read stdin JSON → handleHookEvent → exit 0
    map.ts                pure: hook payload → recorder calls (the heart)
    redact.ts             pure: prompt/command/diff → hashes + redacted metadata
    state.ts              per-session state across process invocations (pre-image cache, tool counter)
    sink.ts               configurable ProvenanceSinks: local file store | ingest POST
    config.ts             resolve config from env at the process boundary only
  src/__tests__/          map/redact/state unit tests (pure, no Claude Code needed)
  README.md               install (settings.json snippet) + usage

storage/src/file-store.ts (new)   file-backed AuditStore + edge store (durable across processes)

server/mcp-provenance/ (new)      reference MCP server: query + export over the local store
```

A hook runs as a **fresh process per event** (stdin JSON), so the sink must be durable
across invocations and per-session state (pre-image hashes, the tool-call counter)
lives in a state dir keyed by `session_id` (e.g. under `$XDG_STATE_HOME`/tmp).

## Hook event → recorder mapping (`map.ts`)

| Hook event | Recorder call | Notes |
|---|---|---|
| `SessionStart` | `startSession({ sessionId: session_id, agentActor: {ai_agent, "claude-code"}, agent: {name:"claude-code", version}, model, initiatedBy: <configured human>, branch/repo from git })` | `session_id` becomes `metadata.sessionId` on every event → groups in the Sessions UI. `model` from payload when present. |
| `UserPromptSubmit` | `recordPrompt({ promptHash: sha256(prompt) })` | Never store raw `prompt`. |
| `PreToolUse` (Edit/Write/MultiEdit) | — (state only) | Read `tool_input.file_path` from disk, cache `beforeHash` in session state for the matching PostToolUse. |
| `PostToolUse` | `recordToolCall({ toolCallId, tool: tool_name, status:"succeeded", reads, modifies })`; for Edit/Write/MultiEdit also `recordFileChange({ files:[{pathHash, beforeHash(from state), afterHash(disk)}], changedBy: tool_call })` | `toolCallId` synthesized deterministically (see below). |
| `PostToolUseFailure` | `recordToolCall({ status:"failed" })` | The contract splits success/failure; both subscribed. |
| `Stop` | `git status --porcelain` → `recordFileChange` for changed files not already captured this turn | Catches **Bash-driven** writes the edit hooks miss (the contract's documented gap). |
| `SessionEnd` | finalize state (flush, clear pre-image cache) | Protocol has no session-end event; no spurious event emitted. |

**State-loss self-heal (part of the contract).** Hook state can vanish while a
session keeps running — Claude Code fires `SessionEnd` at a continuation/compaction
boundary (which clears state) without a follow-up `SessionStart`, or the state file
is lost to a crash/cleanup. Any non-SessionStart hook that loads `context: null`
must REBUILD the session context instead of no-oping, or capture dies silently for
the rest of the session. The rebuild must mirror the bytes of this session's prior
`agent.session.started` append under the current tenant from the local store
(`occurredAt`, model, branch, repository, episode id) so the deterministic
session-start replay stays an idempotent no-op — a fresh `occurredAt` would be an
idempotency conflict that rejects whole batches. Only when no prior append exists
is a fresh context safe. A Python/Go capture adapter must reproduce this behavior.

**Deterministic ids.** Claude Code hook payloads do **not** include a `tool_use_id`,
so `toolCallId` is synthesized as `tc_<session_id>_<n>` where `n` is a monotonic
per-session counter in state (stable on replay of the same ledger). File ids are
`f_<sha256(file_path)[:16]>` (path itself is hashed into `pathHash`, never stored raw).
File-change **event** ids must be supplied by the adapter — the recorder's default
(`evt_filechange__<sourceTreeId>__x`) is constant per source tree, and a constant id
collides on the ingest idempotency key (same key, different bytes → the whole batch
409s) after a tenant's first file change. The contract: `evt_filechange__<toolCallId>`
for the PostToolUse path, `evt_filechange__<session_id>__turn<n>` for the Stop
turn-scan — unique per capture, stable on replay of the same hook delivery.

## Risk-signal classification (`map.ts`) — language-neutral capture contract

Captured activity is classified into `metadata.riskSignals` **before hashing**,
so the command→class mapping below is hash-affecting: a Python/Go capture
adapter must reproduce it byte-for-byte or recorded events diverge. Values are
ONLY enums from `spec/risk-signals.schema.json`; raw command text never leaves
the classifier (only its `inputHash` is stored).

**Bash commands** (`bashRiskSignals`) — first match wins, in this order; an
unmatched command attaches NO signals (conservative by design so ordinary
reads/builds never inflate episode risk):

| Precedence | Pattern class (case-insensitive) | `operationType` | `reversibility` |
|---|---|---|---|
| 1 | `rm` with a short-flag recursive group (`-r`/`-rf`/`-fr`/`-R`…), `rm … --recursive` (long flag, same shell word group — no `|`/`;`/`&` between `rm` and the flag), `rimraf` (incl. `npx`/`bunx rimraf`), `find … -delete` (same word group), `git reset --hard`, `git clean -f*`, `git push --force`/`-f`, `drop table|database|schema`, `truncate table`, `terraform destroy`, `kubectl delete`, `mkfs`, `dd if=` | `destructive` | `irreversible` |
| 2 | `rm`, `rmdir`, `unlink`, `git branch -D` | `delete` | `recoverable` |
| 3 | `chmod`, `chown`, `sudo` | `permission` | `reversible` |
| 4 | `git config`, `npm config`, `wrangler secret`, `export VAR=` | `config` | `reversible` |

**File-change batches** (`fileChangeRiskSignals`): any delete in the batch →
`delete`/`recoverable`; else all-create → `create` and mixed/update →
`update`, both `reversible`. Always carries `dataVolume` = files in the batch.
Signals ride the file-change EVENT (the effect), never doubled onto the edit
tool call that produced it.

**`envCriticality`** (`envCriticalityOf`, applied to every signal): configured
environment label containing `prod` → `production`, `stag` → `staging`,
`sandbox` → `sandbox`, anything else → `development`.

The long-form gaps flagged in the 2026-07-18 review (`rm --recursive`,
`npx rimraf`, `find … -delete`) are now matched by precedence 1; the
patterns stay scoped to one shell word group so a pipeline segment after
`|`/`;`/`&` cannot smear a flag onto an unrelated leading command.

## Redaction (`redact.ts`) — non-negotiable (`.claude/rules/03-privacy-security.md`)

- `prompt` → `promptHash` only.
- `tool_input.command` (Bash) and MCP tool inputs → never stored; record `tool` +
  `status` + an `inputHash` only.
- Edit/Write content (`old_string`/`new_string`/`content`) → `beforeHash`/`afterHash`
  (sha256 of disk content), never the strings.
- `file_path` → `pathHash` (+ a short non-PII basename only if a flag opts in).
- Actor ids are stable configured ids, not emails/usernames.
- Redaction runs in the hook **before** anything reaches the sink, and is deterministic.

## Sink (`sink.ts`) + config (`config.ts`)

`ProvenanceSinks` built from config:
- **local** (default): a file-backed `AuditStore` + edge store (`storage/file-store.ts`)
  appending hash-chained records to `~/.veritio/<scope>/{events,edges}.jsonl`. Durable
  across hook processes; the reference MCP reads it.
- **ingest** (optional): `recordEvent`/`recordEdge` POST batches to a Veritio ingest URL
  with a scoped **ingest** key. The key + URL are read from env **only in `config.ts`**
  (process boundary), never embedded in the hook script. Server re-redacts (the ingest
  handler already does). This is what surfaces captured sessions in the cloud Sessions UI.
- Config resolution (env, process boundary only): `VERITIO_SINK=local|ingest|both`,
  `VERITIO_INGEST_URL`, `VERITIO_INGEST_KEY`, `VERITIO_ACTOR_ID` (the enforcing human),
  `VERITIO_LOCAL_DIR`.

## Reference MCP (`server/mcp-provenance/`) — query + export

Reads the local file store; exposes tools:
- `veritio.list_sessions(day?)` → session summaries (reuses the same summarize logic
  shape as the cloud read model; the OSS summarizer is the source of truth).
- `veritio.get_session(sessionId)` → the session's events + projected graph.
- `veritio.export_session(sessionId)` → a verifiable evidence bundle (records + chain
  tips + a `verify()` result), suitable for archival/compliance hand-off.

Mirrors the existing Workbench MCP server shape (hand-rolled MCP over HTTP/stdio).

## Verified-contract caveats designed around

- **Failures bypass `PostToolUse`** → also subscribe `PostToolUseFailure`.
- **Bash mutates files invisibly** to edit hooks → `Stop` hook runs a `git status`
  tree scan per turn.
- **No before/after content in payload** → pre-image captured in `PreToolUse`, post-image
  from disk in `PostToolUse`; never trust `tool_response` for diffs.
- **No `tool_use_id`** → synthesized deterministic id.
- Newer events (`PostToolUseFailure`, etc.) are version-dependent → feature-detect by
  `hook_event_name`; ignore unknown events gracefully.

## Privacy / security / boundary invariants

- Redaction before persistence; deterministic; hashes + stable ids only.
- The hook script is thin: read stdin → redact → hand a configured sink the event. No
  storage credentials or provider tokens embedded; ingest key read at the process
  boundary only (`04-adapters-and-server.md`).
- Local file store has no credentials; ingest POST carries only a scoped key + redacted
  records (server re-redacts).

## SDK parity

TypeScript-only adapter (matches the TS-only recorder). Document a Python/Go parity
TODO in `.claude/rules/02-sdk-parity.md` alongside the `metadata.sessionId` note when
the other recorders land. The hook→recorder mapping table here is the language-neutral
contract.

## Test plan

- `map.test.ts`: each hook payload → expected recorder calls (pure; fixtures from the
  verified contract incl. Edit/Write/Bash/failure/Stop).
- `redact.test.ts`: prompts/commands/content never appear; only hashes/ids; deterministic.
- `state.test.ts`: pre-image cache + monotonic tool counter survive simulated multi-process
  invocations (same state dir); deterministic ids on replay.
- `file-store.test.ts`: durable hash-chained append across reopen; `verify()` passes.
- End-to-end (manual, documented): wire the hook in a throwaway project's
  `.claude/settings.json`, run an agent turn, confirm the local store + (optionally) the
  cloud Sessions UI show the session.

## Out of scope (this iteration)

- Codex / OpenCode adapters (same mapping contract, later).
- Hosted MCP ingest in `veritio-cloud` (the reference MCP is OSS; hosted is separate).
- Full-capture mode (raw diffs as encrypted payload refs).
- Real-time streaming / a daemon (per-invocation file append is sufficient for v1).
