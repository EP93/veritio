# Veritio plugin for Claude Code

Give your Claude Code sessions a **tamper-evident audit trail** — who did what,
when — recorded to Veritio Cloud, plus a hosted MCP server so you (or Claude)
can query that evidence back.

- **Passive capture** — session start/end, prompts, tool calls, and file changes
  are recorded via Claude Code hooks. Raw prompts, tool argument payloads, and
  file contents are not stored; stable ids, content hashes, and temporary local
  file-path keys used to pair pre/post edit hashes are retained.
- **Hosted MCP** — `list_sessions` / `get_session` / `export_session` against
  your own evidence, over `https://console.getveritio.com/api/mcp`.

## Install

```
/plugin marketplace add getveritio/veritio
/plugin install veritio@veritio
```

The plugin ships **disabled by default** (it connects to a hosted service).
Enable it with `/plugin`. Local capture needs no hosted credentials. To connect
the hosted sink using the still-unpublished CLI, build and run it from a Veritio
repository checkout:

```
bun run --cwd cli build
bun cli/dist/index.js login claude
```

`veritio login` runs a browser device-authorization
flow: you approve in the console, it mints a scoped ingest key and writes the
capture credentials — **no key is ever pasted**. The hosted MCP uses Claude
Code's built-in OAuth (approve it once in `/mcp`).

## What gets recorded

| Claude Code event | Veritio record |
|---|---|
| `SessionStart` | `agent.session.started` |
| `UserPromptSubmit` | `agent.prompt.recorded` (prompt **hash** only) |
| `PreToolUse` (Edit/Write/MultiEdit) | pre-image content hash |
| `PostToolUse` / `PostToolUseFailure` | `agent.tool.called` + code change (before/after **hashes**) |
| `Stop` | `git status` turn-scan for Bash-driven file changes |
| `SessionEnd` | finalizes session state |

Capture is pinned to the reviewed `@veritio/claude-code@0.4.6` via `bunx`; it
does not resolve npm latest for every hook. The credentials come from the env
written by a repository-checkout `veritio login` (the CLI is not published;
only after this exact package is published and verified from the registry; an
unavailable exact version fails closed instead of falling back to an older or
latest runtime.

Hosted delivery is local-first and bounded: one hook never drains old work, the
durable remote queue has hard batch/byte ceilings, and recovery requires a
one-request canary plus an explicitly budgeted operator drain. The plugin does
not cap Claude model/API spend or GitHub Actions minutes; configure those limits
on the agent workflow separately. Veritio produces compliance *evidence*; it
does not make you compliant and is not legal advice.

## Requirements

- [Bun](https://bun.sh) on PATH (the capture hook runs under Bun).
- A Veritio Cloud account for the hosted sink and MCP (the OSS SDK works
  fully offline without one; this plugin is the hosted-connected path).
