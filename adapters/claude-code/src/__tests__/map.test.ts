import { describe, expect, test } from "bun:test";

import type { AdapterConfig } from "../config";
import {
  buildBashFileChange,
  buildSessionContext,
  buildToolCall,
  episodeIdOf,
  promptHashOf,
  rebuildSessionContext,
  refreshContextScope,
} from "../map";
import type { HookPayload } from "../types";

const config: AdapterConfig = {
  localDir: "/tmp/veritio",
  tenantId: "local",
  actorId: "usr_dev",
  agentActorId: "agent_cc",
  environment: "development",
};

const NOW = "2026-06-18T12:00:00.000Z";

function payload(extra: Partial<HookPayload>): HookPayload {
  return { hook_event_name: "PostToolUse", session_id: "sess_a", ...extra };
}

describe("buildSessionContext", () => {
  test("maps a SessionStart payload to a StartSessionInput", () => {
    const ctx = buildSessionContext(payload({ hook_event_name: "SessionStart", model: "claude-opus-4-8" }), config, {
      now: NOW,
      activityEpisodeId: episodeIdOf("sess_a"),
      branch: "feat/x",
      repository: { provider: "github", id: "acme/app" },
    });
    expect(ctx.sessionId).toBe("sess_a");
    expect(ctx.initiatedBy).toEqual({ type: "user", id: "usr_dev" });
    expect(ctx.agentActor).toEqual({ type: "ai_agent", id: "agent_cc" });
    expect(ctx.agent).toEqual({ name: "claude-code" });
    expect(ctx.model).toEqual({ provider: "anthropic", name: "claude-opus-4-8" });
    expect(ctx.occurredAt).toBe(NOW);
    expect(ctx.branch).toBe("feat/x");
    expect(ctx.repository).toEqual({ provider: "github", id: "acme/app" });
    expect(ctx.scope.tenantId).toBe("local");
    expect(ctx.activityEpisodeId).toBe("ep_sess_a");
  });
});

describe("episodeIdOf", () => {
  test("derives a stable, sanitized activity-episode id from the session id", () => {
    expect(episodeIdOf("sess_a")).toBe("ep_sess_a");
    expect(episodeIdOf("a/b:c")).toBe("ep_a_b_c");
  });
});

describe("promptHashOf", () => {
  test("hashes the prompt and never carries the raw text", () => {
    const hash = promptHashOf(payload({ hook_event_name: "UserPromptSubmit", prompt: "delete prod database" }));
    expect(hash.startsWith("sha256:")).toBe(true);
    expect(hash).not.toContain("delete prod database");
  });
});

describe("buildToolCall", () => {
  test("non-edit tool: tool call only, input hashed, no file change", () => {
    const { toolCall, fileChange } = buildToolCall(
      payload({ tool_name: "Bash", tool_input: { command: "rm -rf build" } }),
      config,
      { seq: 0, now: NOW, status: "succeeded", preImages: {}, afterHashes: {} },
    );
    expect(toolCall.toolCallId).toBe("tc_sess_a_0");
    expect(toolCall.tool).toBe("Bash");
    expect(toolCall.status).toBe("succeeded");
    expect(toolCall.inputHash?.startsWith("sha256:")).toBe(true);
    expect(toolCall.modifies).toBeUndefined();
    expect(fileChange).toBeUndefined();
  });

  test("edit tool emits a file change with before/after on the change, NOT on the tool call", () => {
    const fp = "/repo/src/app.ts";
    const { toolCall, fileChange } = buildToolCall(
      payload({ tool_name: "Edit", tool_input: { file_path: fp, old_string: "a", new_string: "b" } }),
      config,
      {
        seq: 2,
        now: NOW,
        status: "succeeded",
        preImages: { [fp]: "sha256:before" },
        afterHashes: { [fp]: "sha256:after" },
      },
    );
    // The tool_call --modified--> file edge must be emitted exactly once (via the
    // file change), so the tool call itself carries no modifies.
    expect(toolCall.modifies).toBeUndefined();
    expect(fileChange).toBeDefined();
    expect(fileChange?.changedBy).toEqual({ type: "tool_call", id: "tc_sess_a_2" });
    expect(fileChange?.files).toHaveLength(1);
    expect(fileChange?.files[0]).toMatchObject({
      beforeHash: "sha256:before",
      afterHash: "sha256:after",
      action: "upsert",
    });
  });

  test("Write with no pre-image is recorded as a create", () => {
    const fp = "/repo/new.ts";
    const { fileChange } = buildToolCall(
      payload({ tool_name: "Write", tool_input: { file_path: fp, content: "x" } }),
      config,
      { seq: 1, now: NOW, status: "succeeded", preImages: {}, afterHashes: { [fp]: "sha256:after" } },
    );
    expect(fileChange?.files[0]?.action).toBe("create");
    expect(fileChange?.files[0]?.beforeHash).toBeUndefined();
  });

  test("a failed tool call carries failed status", () => {
    const { toolCall } = buildToolCall(payload({ tool_name: "Bash", tool_input: {} }), config, {
      seq: 0,
      now: NOW,
      status: "failed",
      preImages: {},
      afterHashes: {},
    });
    expect(toolCall.status).toBe("failed");
  });
});

describe("buildBashFileChange", () => {
  test("builds a change for git-detected files, null when none", () => {
    expect(buildBashFileChange([], config, { now: NOW, turn: 1, sessionId: "sess_a" })).toBeNull();
    const fc = buildBashFileChange([{ pathHash: "sha256:p1", afterHash: "sha256:a1", action: "upsert" }], config, {
      now: NOW,
      turn: 1,
      sessionId: "sess_a",
    });
    expect(fc?.files).toHaveLength(1);
    expect(fc?.files[0]?.pathHash).toBe("sha256:p1");
    expect(fc?.changedBy).toBeUndefined(); // attributed to the session entity
  });

  // Regression: the recorder's DEFAULT filechange id is constant per source
  // tree, so relying on it collided every later turn-scan in a tenant onto one
  // ingest idempotency key (same key, different bytes -> whole batch 409s).
  // The id must be unique per (session, turn) yet stable for a replayed Stop.
  test("filechange id is unique per session and turn, stable on replay", () => {
    const files = [{ pathHash: "sha256:p1", afterHash: "sha256:a1", action: "upsert" as const }];
    const a1 = buildBashFileChange(files, config, { now: NOW, turn: 1, sessionId: "sess_a" });
    const a1Replay = buildBashFileChange(files, config, { now: NOW, turn: 1, sessionId: "sess_a" });
    const a2 = buildBashFileChange(files, config, { now: NOW, turn: 2, sessionId: "sess_a" });
    const b1 = buildBashFileChange(files, config, { now: NOW, turn: 1, sessionId: "sess_b" });
    expect(a1?.id).toBeDefined();
    expect(a1?.id).toStartWith("evt_");
    expect(a1?.id).toBe(a1Replay?.id as string);
    expect(a1?.id).not.toBe(a2?.id as string);
    expect(a1?.id).not.toBe(b1?.id as string);
  });
});

describe("buildToolCall filechange id", () => {
  const fp = "/tmp/e.txt";
  const edit = (sessionId: string, seq: number) =>
    buildToolCall(payload({ session_id: sessionId, tool_name: "Edit", tool_input: { file_path: fp } }), config, {
      seq,
      now: NOW,
      status: "succeeded",
      preImages: { [fp]: "sha256:before" },
      afterHashes: { [fp]: "sha256:after" },
    });

  // Same collision regression as the turn-scan: each edit's filechange must own
  // a distinct id (scoped to its tool call), not the recorder's constant default.
  test("filechange id is unique per tool call, stable on replay", () => {
    const a0 = edit("sess_a", 0);
    const a0Replay = edit("sess_a", 0);
    const a1 = edit("sess_a", 1);
    const b0 = edit("sess_b", 0);
    expect(a0.fileChange?.id).toBeDefined();
    expect(a0.fileChange?.id).toStartWith("evt_");
    expect(a0.fileChange?.id).toBe(a0Replay.fileChange?.id as string);
    expect(a0.fileChange?.id).not.toBe(a1.fileChange?.id as string);
    expect(a0.fileChange?.id).not.toBe(b0.fileChange?.id as string);
  });
});

describe("risk signal derivation", () => {
  // Classification happens BEFORE hashing and stores only frozen-vocabulary
  // enums — never raw command text. Unmatched commands attach NOTHING so
  // ordinary reads never inflate episode risk.
  test("destructive Bash commands carry destructive/irreversible signals", () => {
    const { toolCall } = buildToolCall(
      payload({ tool_name: "Bash", tool_input: { command: "rm -rf /tmp/scratch" } }),
      config,
      { seq: 0, now: NOW, status: "succeeded", preImages: {}, afterHashes: {} },
    );
    expect(toolCall.riskSignals).toMatchObject({
      operationType: "destructive",
      reversibility: "irreversible",
      envCriticality: "development",
    });
  });

  test("plain delete and permission commands classify without overstating", () => {
    const del = buildToolCall(payload({ tool_name: "Bash", tool_input: { command: "rm notes.txt" } }), config, {
      seq: 0,
      now: NOW,
      status: "succeeded",
      preImages: {},
      afterHashes: {},
    });
    expect(del.toolCall.riskSignals).toMatchObject({ operationType: "delete", reversibility: "recoverable" });
    const perm = buildToolCall(payload({ tool_name: "Bash", tool_input: { command: "chmod +x deploy.sh" } }), config, {
      seq: 1,
      now: NOW,
      status: "succeeded",
      preImages: {},
      afterHashes: {},
    });
    expect(perm.toolCall.riskSignals).toMatchObject({ operationType: "permission" });
  });

  test("benign commands attach no risk signals at all", () => {
    const { toolCall } = buildToolCall(
      payload({ tool_name: "Bash", tool_input: { command: "ls -la && git status" } }),
      config,
      { seq: 0, now: NOW, status: "succeeded", preImages: {}, afterHashes: {} },
    );
    expect(toolCall.riskSignals).toBeUndefined();
  });

  test("file changes carry create/update signals with dataVolume; deletes score as deletes", () => {
    const fp = "/tmp/new.ts";
    const { fileChange } = buildToolCall(payload({ tool_name: "Write", tool_input: { file_path: fp } }), config, {
      seq: 0,
      now: NOW,
      status: "succeeded",
      preImages: {},
      afterHashes: { [fp]: "sha256:a" },
    });
    expect(fileChange?.riskSignals).toMatchObject({
      operationType: "create",
      reversibility: "reversible",
      dataVolume: 1,
    });

    const scan = buildBashFileChange(
      [
        { pathHash: "sha256:p1", afterHash: "sha256:a1", action: "delete" },
        { pathHash: "sha256:p2", afterHash: "sha256:a2", action: "upsert" },
      ],
      config,
      { now: NOW, turn: 1, sessionId: "sess_a" },
    );
    expect(scan?.riskSignals).toMatchObject({
      operationType: "delete",
      reversibility: "recoverable",
      dataVolume: 2,
    });
  });

  test("environment maps onto the frozen envCriticality vocabulary", () => {
    const prod = buildToolCall(
      payload({ tool_name: "Bash", tool_input: { command: "rm -rf build" } }),
      { ...config, environment: "prod-eu-1" },
      { seq: 0, now: NOW, status: "succeeded", preImages: {}, afterHashes: {} },
    );
    expect(prod.toolCall.riskSignals).toMatchObject({ envCriticality: "production" });
  });

  // Codex review regression: a force-only single-file removal is an ordinary
  // delete — only RECURSIVE removals classify as destructive/irreversible.
  test("rm -f single file is a plain delete, not destructive", () => {
    const { toolCall } = buildToolCall(
      payload({ tool_name: "Bash", tool_input: { command: "rm -f build.log" } }),
      config,
      { seq: 0, now: NOW, status: "succeeded", preImages: {}, afterHashes: {} },
    );
    expect(toolCall.riskSignals).toMatchObject({ operationType: "delete", reversibility: "recoverable" });
    const recursive = buildToolCall(payload({ tool_name: "Bash", tool_input: { command: "rm -fr old-dir" } }), config, {
      seq: 1,
      now: NOW,
      status: "succeeded",
      preImages: {},
      afterHashes: {},
    });
    expect(recursive.toolCall.riskSignals).toMatchObject({ operationType: "destructive" });
  });

  // 2026-07-18 review: long-form/aliased recursive deletes evaded the
  // destructive class (rm --recursive fell through to delete; rimraf and
  // find -delete attached no signal at all).
  test("long-form and aliased recursive deletes classify as destructive", () => {
    const commands = [
      "rm --recursive old-dir",
      "rm --force --recursive old-dir",
      "npx rimraf dist",
      "find . -name '*.tmp' -delete",
    ];
    for (const [seq, command] of commands.entries()) {
      const { toolCall } = buildToolCall(payload({ tool_name: "Bash", tool_input: { command } }), config, {
        seq,
        now: NOW,
        status: "succeeded",
        preImages: {},
        afterHashes: {},
      });
      expect(toolCall.riskSignals).toMatchObject({ operationType: "destructive", reversibility: "irreversible" });
    }
    // A pipeline segment must not smear flags onto an unrelated leading command.
    const piped = buildToolCall(
      payload({ tool_name: "Bash", tool_input: { command: "ls | grep --recursive foo" } }),
      config,
      { seq: 9, now: NOW, status: "succeeded", preImages: {}, afterHashes: {} },
    );
    expect(piped.toolCall.riskSignals).toBeUndefined();
  });
});

describe("refreshContextScope", () => {
  const startedLocal = buildSessionContext(payload({ hook_event_name: "SessionStart" }), config, {
    now: NOW,
    activityEpisodeId: "ep_sess_a",
  });

  test("heals a context frozen with the fallback tenant once config carries a real one", () => {
    // Regression: a session started BEFORE the ingest env existed persisted
    // scope.tenantId "local"; every later ship-out 403'd silently forever.
    const configured: AdapterConfig = {
      ...config,
      tenantId: "proj_real",
      environment: "production",
      ingest: { url: "https://example.test/api/ingest", key: "vrt_x" },
    };
    const healed = refreshContextScope(startedLocal, configured);
    expect(healed.scope.tenantId).toBe("proj_real");
    expect(healed.scope.environment).toBe("production");
    // Identity stays frozen — only scope follows config.
    expect(healed.sessionId).toBe(startedLocal.sessionId);
    expect(healed.activityEpisodeId).toBe(startedLocal.activityEpisodeId);
    expect(healed.occurredAt).toBe(startedLocal.occurredAt);
  });

  test("returns the same reference when scope already matches (stable state writes)", () => {
    expect(refreshContextScope(startedLocal, config)).toBe(startedLocal);
  });

  test("same-tenant environment drift stays frozen (idempotency-conflict wedge)", () => {
    // Regression (review 2026-07-18, reproduced): the idempotency key hashes
    // only tenant + event id, so re-scoping environment/workspaceId
    // mid-session keeps the key while drifting the canonical bytes — the
    // deterministic session-start replay then CONFLICTS and capture dies
    // silently for the rest of the session. Same-tenant drift must be a no-op.
    const driftedEnv = refreshContextScope(startedLocal, { ...config, environment: "production" });
    expect(driftedEnv).toBe(startedLocal);
    const driftedWorkspace = refreshContextScope(startedLocal, { ...config, workspaceId: "ws_1" });
    expect(driftedWorkspace).toBe(startedLocal);
  });

  test("tenant change still re-scopes fully, including environment and workspace", () => {
    const rescoped = refreshContextScope(startedLocal, {
      ...config,
      tenantId: "proj_other",
      environment: "production",
      workspaceId: "ws_1",
    });
    expect(rescoped.scope).toEqual({
      tenantId: "proj_other",
      environment: "production",
      workspaceId: "ws_1",
    });
  });
});

describe("rebuildSessionContext", () => {
  const opts = {
    now: "2026-07-18T09:00:00.000Z",
    activityEpisodeId: episodeIdOf("sess_a"),
    branch: "feat/current",
    repository: { provider: "github", id: "acme/app" },
  };

  test("mirrors the prior session-start bytes so the replay stays idempotent", () => {
    const prior = {
      occurredAt: "2026-07-14T07:50:39.286Z",
      metadata: {
        activityEpisodeId: "ep_custom_thread",
        branch: "main",
        model: { provider: "anthropic", name: "claude-fable-5" },
        repository: { provider: "github", id: "acme/original" },
        sessionId: "sess_a",
      },
    };
    const ctx = rebuildSessionContext(payload({ model: "claude-opus-4-8" }), config, opts, prior);
    // Byte-critical fields come from the prior append, NOT from current facts.
    expect(ctx.occurredAt).toBe("2026-07-14T07:50:39.286Z");
    expect(ctx.model).toEqual({ provider: "anthropic", name: "claude-fable-5" });
    expect(ctx.branch).toBe("main");
    expect(ctx.repository).toEqual({ provider: "github", id: "acme/original" });
    expect(ctx.activityEpisodeId).toBe("ep_custom_thread");
    expect(ctx.sessionId).toBe("sess_a");
  });

  test("drops branch/repository when the prior append had none (byte parity)", () => {
    const prior = {
      occurredAt: "2026-07-14T07:50:39.286Z",
      metadata: { sessionId: "sess_a", model: { provider: "anthropic", name: "claude" } },
    };
    const ctx = rebuildSessionContext(payload({}), config, opts, prior);
    expect(ctx.branch).toBeUndefined();
    expect(ctx.repository).toBeUndefined();
    expect(ctx.occurredAt).toBe("2026-07-14T07:50:39.286Z");
  });

  test("builds a fresh context when there is no prior append (nothing to conflict with)", () => {
    const ctx = rebuildSessionContext(payload({ model: "claude-opus-4-8" }), config, opts, null);
    expect(ctx).toEqual(buildSessionContext(payload({ model: "claude-opus-4-8" }), config, opts));
    expect(ctx.occurredAt).toBe(opts.now);
  });

  test("mirrors the prior append's scope, not current config (same-tenant drift wedge)", () => {
    // Regression (review 2026-07-18, reproduced): rebuilding with the CURRENT
    // config's environment/workspace while the prior append recorded different
    // ones keeps the idempotency key (tenant + event id) but drifts the bytes —
    // conflict, dead capture. The prior scope must win verbatim.
    const prior = {
      occurredAt: "2026-07-14T07:50:39.286Z",
      metadata: { sessionId: "sess_a", model: { provider: "anthropic", name: "claude" } },
      scope: { tenantId: config.tenantId, environment: "development", workspaceId: "ws_orig" },
    };
    const driftedConfig: AdapterConfig = { ...config, environment: "production", workspaceId: "ws_new" };
    const ctx = rebuildSessionContext(payload({}), driftedConfig, opts, prior);
    expect(ctx.scope).toEqual({
      tenantId: config.tenantId,
      environment: "development",
      workspaceId: "ws_orig",
    });
  });
});
