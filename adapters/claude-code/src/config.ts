import { homedir } from "node:os";
import { join } from "node:path";

import { MAX_INGEST_TIMEOUT_MS } from "./ingest.js";
import { DEFAULT_SPOOL_LIMITS, type SpoolLimits } from "./spool.js";

/**
 * Resolved adapter configuration. The local file store is always the working sink
 * (the reference MCP reads it); when both an ingest URL and key are present the
 * hook ALSO ships the invocation's records to a Veritio ingest endpoint.
 */
export interface AdapterConfig {
  localDir: string;
  ingest?: { url: string; key: string; timeoutMs?: number };
  /** Optional on embedded config literals for backwards compatibility; resolveConfig always sets it. */
  spoolLimits?: SpoolLimits;
  tenantId: string;
  /** The enforcing human (stable id, never an email/username). */
  actorId: string;
  /** The agent actor id. */
  agentActorId: string;
  workspaceId?: string;
  environment: string;
  /**
   * Opt-in override for the activity-episode id. When set, it threads multiple
   * Claude Code sessions into ONE durable activity episode (cross-session
   * swimlane). Falls back to the deterministic `ep_<sessionId>` derivation when
   * unset. Non-PII grouping id only (never an email/username); it travels
   * verbatim as `metadata.activityEpisodeId` on every emitted event.
   */
  activityEpisodeId?: string;
}

/**
 * Reads configuration from the environment. This is the ONLY place env is read
 * (the process boundary), so map/redact/state stay pure and no credential is
 * embedded in the hook logic. Fails closed if ingest is half-configured.
 */
export function resolveConfig(env: NodeJS.ProcessEnv): AdapterConfig {
  const url = env.VERITIO_INGEST_URL?.trim();
  const key = env.VERITIO_INGEST_KEY?.trim();
  if ((url && !key) || (key && !url)) {
    throw new Error("ingest requires both VERITIO_INGEST_URL and VERITIO_INGEST_KEY");
  }

  const config: AdapterConfig = {
    localDir: resolveLocalDir(env),
    spoolLimits: {
      hardBatches: parseSpoolLimit(
        env.VERITIO_SPOOL_HARD_BATCHES,
        "VERITIO_SPOOL_HARD_BATCHES",
        DEFAULT_SPOOL_LIMITS.hardBatches,
      ),
      hardBytes: parseSpoolLimit(
        env.VERITIO_SPOOL_HARD_BYTES,
        "VERITIO_SPOOL_HARD_BYTES",
        DEFAULT_SPOOL_LIMITS.hardBytes,
      ),
    },
    tenantId: env.VERITIO_TENANT_ID?.trim() || "local",
    actorId: env.VERITIO_ACTOR_ID?.trim() || "local_developer",
    agentActorId: env.VERITIO_AGENT_ACTOR_ID?.trim() || "agent_claude_code",
    environment: env.VERITIO_ENVIRONMENT?.trim() || "development",
  };
  if (url && key) {
    config.ingest = { url, key };
    const timeoutMs = parseIngestTimeout(env.VERITIO_INGEST_TIMEOUT_MS);
    if (timeoutMs !== undefined) {
      config.ingest.timeoutMs = timeoutMs;
    }
  }
  const workspaceId = env.VERITIO_WORKSPACE_ID?.trim();
  if (workspaceId) {
    config.workspaceId = workspaceId;
  }
  const activityEpisodeId = env.VERITIO_ACTIVITY_EPISODE_ID?.trim();
  if (activityEpisodeId) {
    config.activityEpisodeId = activityEpisodeId;
  }
  return config;
}

/** Resolves only the local queue path so offline operator commands need no ingest credentials. */
export function resolveLocalDir(env: NodeJS.ProcessEnv): string {
  return env.VERITIO_LOCAL_DIR?.trim() || join(homedir(), ".veritio", "claude-code");
}

/**
 * Parses the opt-in VERITIO_INGEST_TIMEOUT_MS override for the ship-out abort
 * bound. Fails closed on non-positive or non-numeric values instead of silently
 * capturing with an unintended (or unbounded) timeout.
 */
function parseIngestTimeout(raw: string | undefined): number | undefined {
  const trimmed = raw?.trim();
  if (!trimmed) {
    return undefined;
  }
  const value = Number(trimmed);
  if (!Number.isInteger(value) || value <= 0 || value > MAX_INGEST_TIMEOUT_MS) {
    throw new Error(`VERITIO_INGEST_TIMEOUT_MS must be an integer between 1 and ${MAX_INGEST_TIMEOUT_MS} milliseconds`);
  }
  return value;
}

/**
 * Parses a local queue limit. Environment overrides may lower the compiled-in
 * ceiling but cannot enlarge the adapter's economic exposure.
 */
function parseSpoolLimit(raw: string | undefined, name: string, hardMaximum: number): number {
  const trimmed = raw?.trim();
  if (!trimmed) {
    return hardMaximum;
  }
  const value = Number(trimmed);
  if (!Number.isSafeInteger(value) || value < 1 || value > hardMaximum) {
    throw new Error(`${name} must be a positive integer within the hard safety ceiling of ${hardMaximum}`);
  }
  return value;
}
