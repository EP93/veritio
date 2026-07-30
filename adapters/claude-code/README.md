# @veritio/claude-code

Part of [Veritio](https://getveritio.com), the open-source evidence layer — see the [docs](https://getveritio.com/docs/) and [Veritio Cloud](https://getveritio.com/cloud/).

Capture [Claude Code](https://code.claude.com) agent activity as Veritio evidence —
passively, via hooks — and query it back through an MCP server.

The hook maps each Claude Code event to the `@veritio/core` provenance recorder and
appends a hash-chained, **redacted** evidence trail to a durable local store (and,
optionally, to a Veritio ingest endpoint). Capture is out-of-band, so the trail does
not depend on the agent choosing to report. A companion MCP server lets a human or
another agent list sessions, inspect a session's provenance graph, and export a
verifiable bundle.

> **Privacy:** raw prompts, tool inputs (Bash commands, MCP arguments — which can
> carry secrets), and file contents/diffs are **never** persisted. Only stable ids
> and content hashes travel. Redaction runs in the hook before anything reaches a sink.

## What is captured

| Claude Code event | Veritio record |
|---|---|
| `SessionStart` | `agent.session.started` (+ `caused_by` edge to the enforcing human) |
| `UserPromptSubmit` | `agent.prompt.recorded` (prompt **hash** only) |
| `PreToolUse` (Edit/Write/MultiEdit) | pre-image content hash cached for the matching PostToolUse |
| `PostToolUse` / `PostToolUseFailure` | `agent.tool.called` (succeeded/failed) + a code change with before/after **hashes** |
| `Stop` | a `git status` turn-scan records Bash-driven file changes the edit hooks miss |
| `SessionEnd` | finalizes per-session state |

## Configure the hook

The hook runs under **Bun** (the published `dist/` consumes the Veritio SDK, which is
bundler/Bun-resolved). Add to your project's `.claude/settings.json`
(`${CLAUDE_PROJECT_DIR}` is provided by Claude Code):

```jsonc
{
  "hooks": {
    "SessionStart":       [{ "hooks": [{ "type": "command", "command": "bun ${CLAUDE_PROJECT_DIR}/node_modules/@veritio/claude-code/dist/hook.js" }] }],
    "UserPromptSubmit":   [{ "hooks": [{ "type": "command", "command": "bun ${CLAUDE_PROJECT_DIR}/node_modules/@veritio/claude-code/dist/hook.js" }] }],
    "PreToolUse":         [{ "matcher": "Edit|Write|MultiEdit", "hooks": [{ "type": "command", "command": "bun ${CLAUDE_PROJECT_DIR}/node_modules/@veritio/claude-code/dist/hook.js" }] }],
    "PostToolUse":        [{ "hooks": [{ "type": "command", "command": "bun ${CLAUDE_PROJECT_DIR}/node_modules/@veritio/claude-code/dist/hook.js" }] }],
    "PostToolUseFailure": [{ "hooks": [{ "type": "command", "command": "bun ${CLAUDE_PROJECT_DIR}/node_modules/@veritio/claude-code/dist/hook.js" }] }],
    "Stop":               [{ "hooks": [{ "type": "command", "command": "bun ${CLAUDE_PROJECT_DIR}/node_modules/@veritio/claude-code/dist/hook.js" }] }],
    "SessionEnd":         [{ "hooks": [{ "type": "command", "command": "bun ${CLAUDE_PROJECT_DIR}/node_modules/@veritio/claude-code/dist/hook.js" }] }]
  }
}
```

The hook always exits `0` — a logging hook never blocks the agent.

## Configuration (environment)

Read only at the process boundary; no credential is embedded in the hook.

| Variable | Default | Purpose |
|---|---|---|
| `VERITIO_LOCAL_DIR` | `~/.veritio/claude-code` | Local evidence store directory (always written) |
| `VERITIO_TENANT_ID` | `local` | Tenant scope on every record |
| `VERITIO_ACTOR_ID` | `local_developer` | Stable id of the enforcing human (never an email) |
| `VERITIO_AGENT_ACTOR_ID` | `agent_claude_code` | Stable id of the agent actor |
| `VERITIO_ENVIRONMENT` | `development` | Scope environment |
| `VERITIO_WORKSPACE_ID` | — | Optional workspace scope |
| `VERITIO_INGEST_URL` + `VERITIO_INGEST_KEY` | — | If **both** set, also POST records to a Veritio ingest endpoint (e.g. Veritio Cloud), so captured sessions surface in the hosted Sessions UI. The server re-redacts. |
| `VERITIO_INGEST_TIMEOUT_MS` | `10000` | Abort bound (ms) for one ingest POST. A stalled endpoint can never block the agent past this bound; the hook still exits 0 (capture is fail-open, the local store already has the records). |

### Offline spool (ingest outages)

When a ship-out fails for a **retryable** reason (endpoint unreachable, timeout,
HTTP 5xx/429 — e.g. the hosted tenant database being temporarily unavailable),
the batch is queued under `<localDir>/spool/` and replayed by later hook
invocations once the endpoint recovers, oldest first, a few batches per hook so
the hook time bound holds. Replay is safe because record ids are deterministic
and server ingest is idempotent. Permanent rejections (other 4xx: bad key,
tenant mismatch, malformed batch) are never queued. The queue is capped at
1,000 batches (oldest dropped first, with a stderr note); spooled files contain
exactly the redacted, hash-only payload the wire would have carried. The spool
is currently TypeScript-only — a Python/Go capture adapter must reproduce this
ship-out behavior (see `.claude/rules/02-sdk-parity.md`).

## Query + export (MCP)

The package also ships a read-only MCP server (`veritio-claude-code-mcp`, `dist/mcp.js`)
over stdio with three tools:

- `veritio.list_sessions(day?)` — summarized sessions (enforcing human, agent/model, branch, change count, outcome).
- `veritio.get_session(sessionId)` — a session's events + projected provenance graph.
- `veritio.export_session(sessionId)` — a verifiable evidence bundle (records + hash-chain verdict).

Register it with your MCP client (reads the same `VERITIO_LOCAL_DIR`):

```jsonc
{ "mcpServers": { "veritio-provenance": { "command": "bun", "args": ["/abs/path/node_modules/@veritio/claude-code/dist/mcp.js"] } } }
```

## Cross-language parity

This adapter is TypeScript-only today (it matches the TS-only provenance recorder). The
hook→recorder mapping table above is the language-neutral contract; a Python/Go capture
adapter must reproduce it, including the `metadata.sessionId` stamp
(see `.claude/rules/02-sdk-parity.md`).
