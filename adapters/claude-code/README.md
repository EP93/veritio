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

> **Privacy:** raw prompts, tool argument payloads (Bash commands, MCP arguments —
> which can carry secrets), and file contents/diffs are **never** persisted.
> Stable ids and content hashes travel. Raw file paths can be retained temporarily
> in local per-session state to pair a pre-image with its post-image; they are not
> sent as evidence metadata. Redaction runs before anything reaches a sink.

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

Install an exact reviewed version in repositories and hosted runners; do not
use an unversioned `bunx` command. The bundled plugin pins
`@veritio/claude-code@0.4.6`. Treat it as unavailable until exact registry
readback succeeds; the plugin must fail closed rather than fall back to 0.4.5.

The `veritio` CLI device-login helper is not published yet. From a repository
checkout, build it with `bun run --cwd cli build` and invoke
`bun cli/dist/index.js login claude`; do not assume a global `veritio` binary.

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
| `VERITIO_INGEST_TIMEOUT_MS` | `10000` | Abort bound (ms) for one ingest POST, constrained to `1..30000`. The hook still exits 0 because the local store is authoritative for capture. |
| `VERITIO_SPOOL_HARD_BATCHES` | `250` | Optional lower queue batch ceiling. It cannot raise the compiled-in hard ceiling. |
| `VERITIO_SPOOL_HARD_BYTES` | `50000000` | Optional lower queue byte ceiling. It cannot raise the compiled-in hard ceiling. |

### Durable delivery queue

Remote delivery has three durable outcomes:

- `retry`: transport failures, HTTP 429, and legacy 5xx responses remain in the
  pending queue.
- `pause`: an explicit server pause (including recognized legacy quota codes)
  opens a sticky circuit and moves the entire queue to held. Later hooks append
  locally and make **zero** remote attempts.
- `reject`: permanent failures are moved to quarantine with the redacted payload
  intact; they are never silently deleted.

Ordinary hook invocations never replay a backlog. Recovery requires a separate
operator command and every replay epoch is bounded by batches, records, encoded
bytes, and elapsed time. This prevents an endpoint recovery, quota upgrade, or
misclassified provider failure from turning many routine hooks into an
uncontrolled egress drain.

The queue lives under `<localDir>/spool/` with `pending`, `held`, and
`quarantine` states. The hard ceiling is 250 batches or 50 MB. At the ceiling,
existing entries are retained, pending entries move to held, and the newest
remote-delivery copy is refused with a visible stderr signal. Older flat spool
files upgrade into a manual hold; they do not auto-replay.

Use the operator CLI to inspect and control delivery:

```sh
veritio-claude-code-spool status
veritio-claude-code-spool pause --reason "provider transfer alarm"
veritio-claude-code-spool quarantine

# At most one request, 500 records / 1 MB / 5 seconds.
veritio-claude-code-spool canary

# Every drain budget is mandatory and is checked before each request.
veritio-claude-code-spool drain \
  --max-batches 10 \
  --max-records 5000 \
  --max-bytes 10000000 \
  --max-elapsed-ms 15000

# Resume only moves held entries back to pending; it performs no network I/O.
veritio-claude-code-spool resume --acknowledge "provider headroom reviewed"
```

`status`, `pause`, `resume`, and `quarantine` work without ingest credentials.
`canary` and `drain` require both ingest variables. CLI output contains queue
metadata, never event payloads or credentials. Spool payload files contain the
same redacted, hash-only batch prepared for the wire. The queue is currently
TypeScript-only; another capture adapter must reproduce the same disposition
and replay-permit semantics (see `.claude/rules/02-sdk-parity.md`).

### GitHub-hosted Claude Code

Anthropic's GitHub Action has its own paid model/API and runner exposure. Bound
that workflow separately with a narrow event trigger, GitHub `concurrency`, a
job `timeout-minutes`, and Claude's `--max-turns`. Veritio's hook and spool do
not cap Claude tokens or GitHub runner minutes.

If the action is configured to load repository Claude hooks, install the exact
reviewed `@veritio/claude-code` version before it runs and pass Veritio ingest
credentials only through GitHub Secrets. Omit those credentials for local-only
artifact capture. Never run the stress suite or a spool drain from a pull-request
workflow; CI uses synthetic hooks and no paid provider credentials.

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
