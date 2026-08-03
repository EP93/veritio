import { homedir } from "node:os";
import { join } from "node:path";

import { MAX_INGEST_TIMEOUT_MS } from "./ingest.js";

/**
 * Resolved Codex adapter configuration. Mirrors `@veritio/claude-code`: the
 * local file store is always the working sink; when both an ingest URL and key
 * are present the notify hook ALSO ships the turn's records to a Veritio ingest
 * endpoint (the server re-redacts).
 */
export interface CodexAdapterConfig {
  localDir: string;
  ingest?: { url: string; key: string; timeoutMs?: number };
  tenantId: string;
  /** The enforcing human (stable id, never an email/username). */
  actorId: string;
  /** The agent actor id. */
  agentActorId: string;
  workspaceId?: string;
  environment: string;
}

/**
 * Reads configuration from the environment. This is the ONLY place env is read
 * (the process boundary), so the map stays pure and no credential is embedded in
 * the hook logic. Fails closed if ingest is half-configured.
 */
export function resolveConfig(env: NodeJS.ProcessEnv): CodexAdapterConfig {
  const url = env.VERITIO_INGEST_URL?.trim();
  const key = env.VERITIO_INGEST_KEY?.trim();
  if ((url && !key) || (key && !url)) {
    throw new Error("ingest requires both VERITIO_INGEST_URL and VERITIO_INGEST_KEY");
  }

  const config: CodexAdapterConfig = {
    localDir: env.VERITIO_LOCAL_DIR?.trim() || join(homedir(), ".veritio", "codex"),
    tenantId: env.VERITIO_TENANT_ID?.trim() || "local",
    actorId: env.VERITIO_ACTOR_ID?.trim() || "local_developer",
    agentActorId: env.VERITIO_AGENT_ACTOR_ID?.trim() || "agent_codex",
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
  return config;
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
