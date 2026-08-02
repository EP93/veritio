#!/usr/bin/env bun
import { execFileSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { type AuditEvent, createProvenanceRecorder, type EvidenceEdge, type RecordResult } from "@veritio/core";
import { createFileEvidenceStore } from "@veritio/storage";

import { resolveConfig } from "./config.js";
import {
  buildBashFileChange,
  buildSessionContext,
  buildToolCall,
  type ChangedFile,
  episodeIdOf,
  promptHashOf,
  rebuildSessionContext,
  refreshContextScope,
} from "./map.js";
import { sha256 } from "./redact.js";
import { shipWithSpool } from "./spool.js";
import { clearState, loadState, saveState } from "./state.js";
import type { HookPayload, SessionContext } from "./types.js";

/** Largest file the turn-scan will hash, to keep a Stop hook bounded. */
const MAX_HASH_BYTES = 2_000_000;
const MAX_TURN_FILES = 500;

/**
 * Claude Code hook entrypoint. Reads one hook event from stdin, maps it to
 * Veritio recorder calls against a durable file store (and optionally ships the
 * records to an ingest endpoint), and ALWAYS exits 0 — a logging/observability
 * hook must never block the agent. All raw content is hashed before it leaves.
 */
async function main(): Promise<void> {
  const raw = readStdin();
  if (!raw.trim()) {
    return;
  }
  const payload = JSON.parse(raw) as HookPayload;
  if (!payload.session_id || !payload.hook_event_name) {
    return;
  }

  const config = resolveConfig(process.env);
  if (config.ingest && config.tenantId === "local") {
    // Loud, non-blocking: shipping with the fallback tenant is guaranteed to
    // be rejected by the scoped key's tenant check — silent 403s wedged whole
    // sessions before this warning existed.
    process.stderr.write(
      "veritio-claude-code: ingest is configured but VERITIO_TENANT_ID is missing — ship-out will be rejected\n",
    );
  }
  const state = loadState(config.localDir, payload.session_id);
  const store = createFileEvidenceStore(config.localDir);
  if (state.context) {
    // Heal sessions whose persisted context froze a stale tenant scope (e.g.
    // started before the ingest env existed): scope follows current config.
    state.context = refreshContextScope(state.context, config);
  } else if (payload.hook_event_name !== "SessionStart" && payload.hook_event_name !== "SessionEnd") {
    // Self-heal a session whose state was lost mid-flight (SessionEnd fired at
    // a continuation boundary and cleared it, crash, cleanup): without this,
    // every later hook breaks on the null context and capture dies silently
    // for the rest of the session. Mirrors the prior session-start bytes from
    // the local store so the idempotent replay cannot conflict (see
    // rebuildSessionContext).
    const now = new Date().toISOString();
    const activityEpisodeId = state.activityEpisodeId ?? config.activityEpisodeId ?? episodeIdOf(payload.session_id);
    state.context = rebuildSessionContext(
      payload,
      config,
      { now, activityEpisodeId, ...readGit(payload.cwd) },
      await findPriorSessionStart(store, config.tenantId, payload.session_id),
    );
    state.activityEpisodeId = state.context.activityEpisodeId ?? activityEpisodeId;
  }
  const recorder = createProvenanceRecorder(store);
  const now = new Date().toISOString();
  const events: AuditEvent[] = [];
  const edges: EvidenceEdge[] = [];
  const collect = (result: RecordResult): void => {
    events.push(result.event.event);
    for (const edge of result.edges) {
      edges.push(edge.edge);
    }
  };

  switch (payload.hook_event_name) {
    case "SessionStart": {
      // Precedence: persisted state first (keeps the id stable across this
      // session's many separate hook processes), then the opt-in
      // VERITIO_ACTIVITY_EPISODE_ID override (threads sessions into one episode),
      // then the deterministic ep_<sessionId> default. The override only takes
      // effect on the FIRST SessionStart, before state exists.
      const activityEpisodeId = state.activityEpisodeId ?? config.activityEpisodeId ?? episodeIdOf(payload.session_id);
      state.activityEpisodeId = activityEpisodeId;
      state.context = buildSessionContext(payload, config, { now, activityEpisodeId, ...readGit(payload.cwd) });
      const { result } = await recorder.startSession(state.context);
      collect(result);
      break;
    }
    case "UserPromptSubmit": {
      if (!state.context) break;
      const { session } = await recorder.startSession(state.context); // idempotent replay
      collect(await session.recordPrompt({ promptHash: promptHashOf(payload), occurredAt: now }));
      break;
    }
    case "PreToolUse": {
      const filePath = filePathOf(payload);
      const hash = filePath ? hashFile(filePath) : undefined;
      if (filePath && hash) {
        state.preImages[filePath] = hash;
      }
      break;
    }
    case "PostToolUse":
    case "PostToolUseFailure": {
      if (!state.context) break;
      const { session } = await recorder.startSession(state.context);
      const filePath = filePathOf(payload);
      const after = filePath ? hashFile(filePath) : undefined;
      const { toolCall, fileChange } = buildToolCall(payload, config, {
        seq: state.toolSeq,
        now,
        status: payload.hook_event_name === "PostToolUse" ? "succeeded" : "failed",
        preImages: state.preImages,
        afterHashes: filePath && after ? { [filePath]: after } : {},
      });
      collect(await session.recordToolCall(toolCall));
      if (fileChange) {
        collect(await session.recordFileChange(fileChange));
      }
      state.toolSeq += 1;
      if (filePath) {
        delete state.preImages[filePath];
      }
      break;
    }
    case "Stop": {
      if (!state.context) break;
      state.turn += 1;
      const fileChange = buildBashFileChange(gitChangedFiles(payload.cwd), config, {
        now,
        turn: state.turn,
        sessionId: payload.session_id,
      });
      if (fileChange) {
        const { session } = await recorder.startSession(state.context);
        collect(await session.recordFileChange(fileChange));
      }
      break;
    }
    case "SessionEnd": {
      clearState(config.localDir, payload.session_id);
      return;
    }
    default:
      return; // Unknown / non-provenance events are ignored.
  }

  saveState(config.localDir, payload.session_id, state);
  if (config.ingest) {
    // Ordinary capture may append to the durable queue but never drains it.
    // Replay requires a separate, explicit finite operator permit.
    await shipWithSpool(config.ingest, config.localDir, { events, edges }, config.spoolLimits);
  }
}

/**
 * Finds this session's most recent `agent.session.started` append under the
 * CURRENT tenant in the local store, for the state-loss self-heal: its bytes
 * are what a rebuilt context must mirror so the deterministic session-start
 * replay stays idempotent instead of conflicting. Returns the prior append's
 * full `event.scope` too — the heal must mirror it verbatim (the idempotency
 * key hashes only tenant + event id, so re-deriving environment/workspace
 * from current config would conflict on same-tenant drift). Best-effort (null
 * on any read failure) — a fresh context is then used, which is only safe
 * when no prior append exists.
 */
async function findPriorSessionStart(
  store: { listEvents(): Promise<{ event: AuditEvent }[]> },
  tenantId: string,
  sessionId: string,
): Promise<{
  occurredAt: string;
  metadata: Record<string, unknown>;
  scope?: SessionContext["scope"] | undefined;
} | null> {
  try {
    const records = await store.listEvents();
    for (let i = records.length - 1; i >= 0; i -= 1) {
      const event = records[i]!.event;
      if (
        event.action === "agent.session.started" &&
        event.target.id === sessionId &&
        event.scope?.tenantId === tenantId
      ) {
        // tenantId is proven present by the guard above; spreading keeps the
        // prior append's environment/workspaceId exactly as recorded.
        return {
          occurredAt: event.occurredAt,
          metadata: event.metadata,
          scope: { ...event.scope, tenantId },
        };
      }
    }
  } catch {
    // Unreadable local store — heal with a fresh context below.
  }
  return null;
}

/** Reads all of stdin synchronously; returns "" when there is no piped input. */
function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function filePathOf(payload: HookPayload): string | undefined {
  const value = payload.tool_input?.file_path;
  return typeof value === "string" ? value : undefined;
}

/** Hashes a file's current content, or returns undefined if unreadable/too large. */
function hashFile(path: string): string | undefined {
  try {
    if (statSync(path).size > MAX_HASH_BYTES) {
      return undefined;
    }
    return sha256(readFileSync(path, "utf8"));
  } catch {
    return undefined;
  }
}

/** Reads the current branch + origin remote for the SessionStart context (best-effort). */
function readGit(cwd?: string): { branch?: string; repository?: { provider: string; id: string } } {
  const dir = cwd ?? process.cwd();
  const out: { branch?: string; repository?: { provider: string; id: string } } = {};
  try {
    const branch = git(dir, ["rev-parse", "--abbrev-ref", "HEAD"]).trim();
    if (branch) {
      out.branch = branch;
    }
  } catch {
    // not a git repo
  }
  try {
    const remote = git(dir, ["config", "--get", "remote.origin.url"]).trim();
    if (remote) {
      const match = remote.match(/[/:]([^/]+\/[^/]+?)(?:\.git)?$/);
      out.repository = { provider: remote.includes("github") ? "github" : "git", id: match?.[1] ?? remote };
    }
  } catch {
    // no remote
  }
  return out;
}

/**
 * Lists files the working tree changed this turn (catches Bash-driven writes that
 * the Edit/Write hooks never see), hashing current content. Bounded + best-effort.
 */
function gitChangedFiles(cwd?: string): ChangedFile[] {
  const dir = cwd ?? process.cwd();
  let porcelain: string;
  try {
    porcelain = git(dir, ["status", "--porcelain"]);
  } catch {
    return [];
  }
  const files: ChangedFile[] = [];
  for (const line of porcelain.split("\n")) {
    if (!line.trim() || files.length >= MAX_TURN_FILES) continue;
    const code = line.slice(0, 2);
    const path = line.slice(3).trim();
    if (!path) continue;
    const pathHash = sha256(path);
    if (code.includes("D")) {
      files.push({ pathHash, afterHash: sha256(""), action: "delete" });
      continue;
    }
    const absolute = isAbsolute(path) ? path : join(dir, path);
    const afterHash = hashFile(absolute);
    if (!afterHash) continue;
    files.push({ pathHash, afterHash, action: code.includes("?") || code.includes("A") ? "create" : "upsert" });
  }
  return files;
}

function git(dir: string, args: string[]): string {
  return execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
}

main()
  .then(() => process.exit(0))
  .catch((error: unknown) => {
    // Never block the agent: log a sanitized line and exit successfully.
    const message = error instanceof Error ? error.message : "unknown error";
    process.stderr.write(`veritio-claude-code: ${message}\n`);
    process.exit(0);
  });
