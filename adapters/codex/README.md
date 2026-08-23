# @veritio/codex

Capture [Codex CLI](https://github.com/openai/codex) agent activity as Veritio
evidence — passively, via the `notify` hook — with a local file sink and an
optional ingest POST to Veritio Cloud.

Codex fires a `notify` program once per turn. This adapter maps each
`agent-turn-complete` notification to a hash-chained, **redacted** evidence
trail: a session-started record and a prompt record carrying only the prompt's
**hash**. Capture is out-of-band and never blocks or disturbs the agent.

> **Privacy:** raw prompts and message contents are **never** persisted — only
> stable ids and a prompt hash travel. Redaction runs in the hook before
> anything reaches a sink.

## What is captured

| Codex notification | Veritio record |
|---|---|
| `agent-turn-complete` | `agent.session.started` + `agent.prompt.recorded` (prompt **hash** only) |

Codex notify does not report tool calls or file edits, so this adapter is
session/prompt-grained. For per-edit and per-tool provenance, run the Veritio
`Stop`-style git scan in your own tooling; a first-class Codex adapter that
reads Codex session transcripts is future work.

## Configure the notify hook

Codex has a **single** `notify` slot. If you already use one (e.g. a desktop
notifier), you MUST wrap it — never replace it. In `~/.codex/config.toml`:

```toml
notify = ["/absolute/path/to/veritio-codex-notify-wrapper.sh"]
```

with a wrapper that forwards to your existing notifier, then runs capture in
the background so it never blocks the turn:

```bash
#!/bin/bash
# your existing notifier (if any):
# "/path/to/existing/notifier" "$@" || true
nohup veritio-codex-notify "$@" >/dev/null 2>&1 &
```

If you have no existing notifier, point `notify` directly at a wrapper that
just backgrounds `veritio-codex-notify "$@"`.

From a repository checkout, the in-repo `veritio login codex` command can write
this configuration and mint the ingest key, so no key is pasted by hand. The
CLI and `@veritio/codex` are still unpublished; do not document `npm install`,
`bunx @veritio/codex`, or a globally available `veritio` command yet.

## Configuration (environment)

Read only at the process boundary; no credential is embedded in the hook.

| Variable | Default | Purpose |
|---|---|---|
| `VERITIO_LOCAL_DIR` | `~/.veritio/codex` | Local evidence store directory (always written) |
| `VERITIO_TENANT_ID` | `local` | Tenant scope on every record |
| `VERITIO_ACTOR_ID` | `local_developer` | Stable id of the enforcing human (never an email) |
| `VERITIO_AGENT_ACTOR_ID` | `agent_codex` | Stable id of the agent actor |
| `VERITIO_ENVIRONMENT` | `development` | Scope environment |
| `VERITIO_WORKSPACE_ID` | — | Optional workspace scope |
| `VERITIO_INGEST_URL` + `VERITIO_INGEST_KEY` | — | If **both** set, also POST records to a Veritio ingest endpoint. The server re-redacts. |
| `VERITIO_INGEST_TIMEOUT_MS` | `10000` | Abort bound (ms) for one ingest POST, constrained to `1..30000`. A stalled endpoint can never block the notify hook past this bound; capture stays fail-open (local store already has the records). |

## Local and GitHub-hosted Codex

This adapter covers Codex CLI processes that invoke the configured `notify`
program. It does not claim capture of Codex cloud tasks or GitHub code reviews:
those environments do not expose this local notify contract to Veritio. Keep
the local store as the default sink and add hosted credentials only when the
target tenant's sticky economic circuit is deployed.

For GitHub-hosted verification, CI builds and tests the adapter with synthetic
notifications and no provider credentials. It never launches paid Codex work,
never stress-tests a remote ingest endpoint, and never replays a backlog. Model
or Codex usage limits are separate from Veritio's one-request delivery bound.

## Cross-language parity

TypeScript-only today (matches the TS-only provenance recorder). The
notification→record mapping table above is the language-neutral contract a
future Python/Go capture adapter must reproduce, including the hash-only rule.

## Status

Experimental notify-based capture. Ingest ship-out aborts after a bounded
timeout (`VERITIO_INGEST_TIMEOUT_MS`, default 10s, maximum 30s) so a stalled endpoint can
never block the agent; client aborts are safe now that the hosted side
enforces fail-closed DB connection/statement timeouts (the old "never abort"
rule predated that hardening). Capture stays fail-open either way.
