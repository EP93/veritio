import type { FileChangeInput, FileModification, RiskSignals, ToolCallInput } from "@veritio/core";
import type { AdapterConfig } from "./config.js";
import { hashJson, pathEntityId, sha256 } from "./redact.js";
import type { HookPayload, SessionContext } from "./types.js";

/** Claude Code tools whose `tool_input.file_path` yields a recordable file change. */
const EDIT_TOOLS = new Set(["Edit", "Write", "MultiEdit"]);

function sanitize(value: string): string {
  return value.replace(/[^A-Za-z0-9_-]/g, "_");
}

/**
 * Derives the stable activity-episode id that groups one Claude Code session's
 * events. Deterministic from the session id so every separate hook process
 * resolves the same episode without shared memory.
 */
export function episodeIdOf(sessionId: string): string {
  return `ep_${sanitize(sessionId)}`;
}

/**
 * Builds the StartSessionInput captured at SessionStart. `now` and git facts are
 * passed in (the hook does the I/O) so this stays pure and deterministic; the
 * result is persisted and replayed verbatim on later events.
 */
export function buildSessionContext(
  payload: HookPayload,
  config: AdapterConfig,
  opts: { now: string; activityEpisodeId: string; branch?: string; repository?: { provider: string; id: string } },
): SessionContext {
  const context: SessionContext = {
    scope: {
      tenantId: config.tenantId,
      environment: config.environment,
      ...(config.workspaceId ? { workspaceId: config.workspaceId } : {}),
    },
    sessionId: payload.session_id,
    initiatedBy: { type: "user", id: config.actorId },
    agentActor: { type: "ai_agent", id: config.agentActorId },
    agent: { name: "claude-code" },
    model: { provider: "anthropic", name: payload.model ?? "claude" },
    occurredAt: opts.now,
    purpose: "agent_provenance",
  };
  context.activityEpisodeId = opts.activityEpisodeId;
  if (opts.branch) {
    context.branch = opts.branch;
  }
  if (opts.repository) {
    context.repository = opts.repository;
  }
  return context;
}

/**
 * Refreshes a persisted session context's tenant scope from the CURRENT
 * config — but ONLY when the tenant id itself changed. The context freezes
 * identity (sessionId, activityEpisodeId) at SessionStart; a session started
 * before the ingest env existed carries the "local" fallback tenant forever,
 * so every ship-out is rejected 403 and dropped silently — re-tenanting heals
 * that, and is safe end-to-end because idempotency keys hash the tenant id:
 * records replayed under the new tenant are NEW records everywhere, never
 * byte conflicts. Same-tenant drift (environment / workspaceId changed
 * mid-session) must NOT re-scope: the idempotency key hashes only
 * tenant + event id, so the deterministic session-start replay would keep its
 * key while its canonical bytes drift — an idempotency CONFLICT that rejects
 * every batch and silently kills capture for the rest of the session (the
 * exact wedge this heal exists to prevent). Those fields stay frozen at their
 * SessionStart values; a new environment takes effect from the next session.
 * Returns the same reference when unchanged so state writes stay stable.
 */
export function refreshContextScope(context: SessionContext, config: AdapterConfig): SessionContext {
  if (context.scope.tenantId === config.tenantId) {
    return context;
  }
  return {
    ...context,
    scope: {
      tenantId: config.tenantId,
      environment: config.environment,
      ...(config.workspaceId ? { workspaceId: config.workspaceId } : {}),
    },
  };
}

/** The promptHash for a UserPromptSubmit event — the raw prompt is never stored. */
export function promptHashOf(payload: HookPayload): string {
  return sha256(payload.prompt ?? "");
}

/**
 * Rebuilds a session context after state loss. Hook state can vanish while a
 * session keeps running (SessionEnd fires at a continuation/compaction
 * boundary and clears state, a crash, manual cleanup); later hooks then load
 * `context: null` and every capture silently no-ops FOREVER for that session.
 * The heal must not simply build a fresh context: `startSession` replays the
 * deterministic `evt_session__<id>` event, so any byte drift from the
 * original append (a fresh `occurredAt`) is an idempotency CONFLICT, which
 * rejects the whole batch. When a prior `agent.session.started` append for
 * this session+tenant exists (the caller reads it from the local store), its
 * bytes are mirrored — scope, occurredAt, model, branch, repository, episode
 * id — so the replay stays byte-identical. Scope is mirrored from the PRIOR
 * APPEND, never re-derived from current config: the idempotency key hashes
 * only tenant + event id, so a same-tenant environment/workspace drift would
 * keep the key while changing the bytes — a conflict that kills capture for
 * the session. Without a prior append there is nothing to conflict with and a
 * fresh context is safe.
 */
export function rebuildSessionContext(
  payload: HookPayload,
  config: AdapterConfig,
  opts: { now: string; activityEpisodeId: string; branch?: string; repository?: { provider: string; id: string } },
  prior: {
    occurredAt: string;
    metadata: Record<string, unknown>;
    scope?: SessionContext["scope"] | undefined;
  } | null,
): SessionContext {
  const context = buildSessionContext(payload, config, opts);
  if (!prior) {
    return context;
  }
  if (prior.scope) {
    context.scope = prior.scope;
  }
  context.occurredAt = prior.occurredAt;
  const meta = prior.metadata;
  const model = meta.model as { provider?: unknown; name?: unknown } | undefined;
  if (typeof model?.name === "string") {
    context.model = { provider: "anthropic", name: model.name };
  }
  if (typeof meta.branch === "string") {
    context.branch = meta.branch;
  } else {
    delete context.branch;
  }
  const repository = meta.repository as { provider?: unknown; id?: unknown } | undefined;
  if (typeof repository?.provider === "string" && typeof repository?.id === "string") {
    context.repository = { provider: repository.provider, id: repository.id };
  } else {
    delete context.repository;
  }
  if (typeof meta.activityEpisodeId === "string") {
    context.activityEpisodeId = meta.activityEpisodeId;
  }
  return context;
}

/**
 * Builds the tool-call record (and, for edit tools, the file-change record) for a
 * PostToolUse / PostToolUseFailure event. The file edges live ONLY on the
 * fileChange (changedBy = the tool call) — never also on `toolCall.modifies` —
 * so the `tool_call --modified--> file` edge is emitted exactly once.
 */
export function buildToolCall(
  payload: HookPayload,
  config: AdapterConfig,
  opts: {
    seq: number;
    now: string;
    status: "succeeded" | "failed";
    preImages: Record<string, string>;
    afterHashes: Record<string, string>;
  },
): { toolCall: ToolCallInput; fileChange?: FileChangeInput } {
  const toolCallId = `tc_${sanitize(payload.session_id)}_${opts.seq}`;
  const tool = payload.tool_name ?? "unknown";
  const toolCall: ToolCallInput = {
    toolCallId,
    tool,
    status: opts.status,
    occurredAt: opts.now,
    inputHash: hashJson(payload.tool_input ?? {}),
  };
  if (tool === "Bash" && typeof payload.tool_input?.command === "string") {
    const signals = bashRiskSignals(payload.tool_input.command, config.environment);
    if (signals) {
      toolCall.riskSignals = signals;
    }
  }

  const filePath =
    EDIT_TOOLS.has(tool) && typeof payload.tool_input?.file_path === "string"
      ? (payload.tool_input.file_path as string)
      : undefined;
  const afterHash = filePath ? opts.afterHashes[filePath] : undefined;
  if (!filePath || !afterHash) {
    return { toolCall };
  }

  const beforeHash = opts.preImages[filePath];
  const pathHash = sha256(filePath);
  const file: FileModification = {
    id: pathEntityId(pathHash),
    pathHash,
    afterHash,
    action: tool === "Write" && !beforeHash ? "create" : "upsert",
  };
  if (beforeHash) {
    file.beforeHash = beforeHash;
  }
  const fileChange: FileChangeInput = {
    // The recorder's default filechange id is constant per source tree, so two
    // different changes in one tenant would collide on the ingest idempotency
    // key (same key, different bytes -> the whole batch 409s). Scope the id to
    // this tool call instead: deterministic for a replay of the same hook
    // delivery, unique across calls/sessions.
    id: `evt_filechange__${toolCallId}`,
    sourceTreeId: `tree_${sanitize(config.tenantId)}`,
    occurredAt: opts.now,
    changedBy: { type: "tool_call", id: toolCallId },
    files: [file],
    riskSignals: fileChangeRiskSignals([file], config.environment),
  };
  return { toolCall, fileChange };
}

/**
 * Frozen-vocabulary risk classification for captured activity. Classification
 * runs BEFORE hashing and stores ONLY spec enums (spec/risk-signals.schema.json)
 * — never raw command text. Patterns are deliberately conservative: an
 * unmatched command attaches NO signals, so ordinary reads and builds never
 * inflate episode risk, while destructive/permission/config classes light up
 * the per-step scoring and the episode risk rollup.
 */
const DESTRUCTIVE_COMMAND =
  /\brm\s+(-[a-z]*r[a-z]*\s+)+|\brm\s[^|;&]*--recursive\b|\brimraf\b|\bfind\s[^|;&]*\s-delete\b|git\s+reset\s+--hard|git\s+clean\s+-[a-z]*f|git\s+push\s+.*(--force|\s-f\b)|drop\s+(table|database|schema)|truncate\s+table|terraform\s+destroy|kubectl\s+delete|mkfs|\bdd\s+if=/i;
const DELETE_COMMAND = /\brm\b|\brmdir\b|\bunlink\b|git\s+branch\s+-D/i;
const PERMISSION_COMMAND = /\bchmod\b|\bchown\b|\bsudo\b/i;
const CONFIG_COMMAND = /git\s+config|npm\s+config|wrangler\s+secret|\bexport\s+\w+=/i;

/** Maps the adapter's environment label onto the frozen envCriticality enum. */
export function envCriticalityOf(environment: string): "sandbox" | "development" | "staging" | "production" {
  const env = environment.toLowerCase();
  if (env.includes("prod")) return "production";
  if (env.includes("stag")) return "staging";
  if (env.includes("sandbox")) return "sandbox";
  return "development";
}

/**
 * Risk signals for a Bash command, or undefined when nothing risk-relevant
 * matches. The command text itself never leaves this function.
 */
export function bashRiskSignals(command: string, environment: string): RiskSignals | undefined {
  const envCriticality = envCriticalityOf(environment);
  if (DESTRUCTIVE_COMMAND.test(command)) {
    return { operationType: "destructive", reversibility: "irreversible", envCriticality };
  }
  if (DELETE_COMMAND.test(command)) {
    return { operationType: "delete", reversibility: "recoverable", envCriticality };
  }
  if (PERMISSION_COMMAND.test(command)) {
    return { operationType: "permission", reversibility: "reversible", envCriticality };
  }
  if (CONFIG_COMMAND.test(command)) {
    return { operationType: "config", reversibility: "reversible", envCriticality };
  }
  return undefined;
}

/**
 * Risk signals for a batch of file modifications: deletes dominate (delete/
 * recoverable), otherwise create vs update, always with dataVolume = files in
 * the batch. Signals ride the file-change EVENT (the effect), never doubled
 * onto the edit tool call that produced it.
 */
export function fileChangeRiskSignals(
  files: readonly { action?: "create" | "upsert" | "delete" }[],
  environment: string,
): RiskSignals {
  const envCriticality = envCriticalityOf(environment);
  const hasDelete = files.some((file) => file.action === "delete");
  if (hasDelete) {
    return { operationType: "delete", reversibility: "recoverable", envCriticality, dataVolume: files.length };
  }
  const allCreate = files.length > 0 && files.every((file) => file.action === "create");
  return {
    operationType: allCreate ? "create" : "update",
    reversibility: "reversible",
    envCriticality,
    dataVolume: files.length,
  };
}

/** A changed file discovered by the Stop-turn git scan (catches Bash-driven writes). */
export interface ChangedFile {
  pathHash: string;
  afterHash: string;
  action: "create" | "upsert" | "delete";
}

/**
 * Builds the file-change record for files a turn changed on disk that no edit
 * tool reported (Bash writes). `changedBy` is omitted so the recorder attributes
 * them to the session entity. Returns null when nothing changed. The event id is
 * scoped to (session, turn) — the recorder's default filechange id is constant
 * per source tree, and a constant id collides on the ingest idempotency key
 * (same key, different bytes -> the whole batch 409s) after the tenant's first
 * ever turn-scan. Deterministic per turn so a re-delivered Stop replays cleanly.
 */
export function buildBashFileChange(
  files: ChangedFile[],
  config: AdapterConfig,
  opts: { now: string; turn: number; sessionId: string },
): FileChangeInput | null {
  if (files.length === 0) {
    return null;
  }
  return {
    id: `evt_filechange__${sanitize(opts.sessionId)}__turn${opts.turn}`,
    sourceTreeId: `tree_${sanitize(config.tenantId)}`,
    occurredAt: opts.now,
    files: files.map((file) => ({
      id: pathEntityId(file.pathHash),
      pathHash: file.pathHash,
      afterHash: file.afterHash,
      action: file.action,
    })),
    riskSignals: fileChangeRiskSignals(files, config.environment),
  };
}
