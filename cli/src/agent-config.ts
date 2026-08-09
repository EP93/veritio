import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Pure builders for the per-agent capture configuration `veritio login` writes.
 * Kept side-effect-free (path/string construction only) so they are unit-tested
 * directly; the login command does the file I/O at the process boundary.
 */

/** The minted credentials a successful device login yields. */
export interface VeritioCredentials {
  ingestUrl: string;
  ingestKey: string;
  tenantId: string;
}

/** Canonical local paths login writes to (all under $HOME, mode 600). */
export const CREDENTIALS_PATH = join(homedir(), ".veritio", "credentials.json");
export const CODEX_CAPTURE_DIR = join(homedir(), ".veritio", "codex-capture");
export const CODEX_ENV_PATH = join(CODEX_CAPTURE_DIR, "capture.env");
export const CODEX_WRAPPER_PATH = join(CODEX_CAPTURE_DIR, "notify-wrapper.sh");

/** Serializes credentials as the `capture.env` KEY=VALUE file the notify wrapper sources. */
export function buildCaptureEnv(creds: VeritioCredentials): string {
  return [
    `VERITIO_INGEST_URL=${creds.ingestUrl}`,
    `VERITIO_INGEST_KEY=${creds.ingestKey}`,
    `VERITIO_TENANT_ID=${creds.tenantId}`,
    "",
  ].join("\n");
}

/**
 * Builds the Codex `notify` wrapper. Codex has ONE notify slot, so the wrapper
 * forwards to any pre-existing notifier first (never replacing it), then runs
 * Veritio capture in the background so it can never block or fail the turn.
 * `existingNotify` is the command array Codex had configured before login.
 */
export function buildCodexWrapper(
  notifyBinPath: string,
  existingNotify: readonly string[] | null,
  captureEnvPath: string = CODEX_ENV_PATH,
): string {
  const forward =
    existingNotify && existingNotify.length > 0
      ? `${existingNotify.map((part) => `'${part.replace(/'/g, "'\\''")}'`).join(" ")} "$@" || true\n`
      : "";
  return [
    "#!/bin/bash",
    "# Managed by `veritio login codex`. Forwards to your existing notifier (if any),",
    "# then runs Veritio capture in the background — capture never blocks the turn.",
    `set -a; . '${captureEnvPath}'; set +a`,
    forward.trimEnd(),
    `nohup '${notifyBinPath}' "$@" >/dev/null 2>&1 &`,
    "",
  ]
    .filter((line) => line !== "")
    .join("\n")
    .concat("\n");
}

/** The `notify = [...]` line Codex's config.toml should carry after login. */
export function codexNotifyLine(wrapperPath: string): string {
  return `notify = ["${wrapperPath}"]`;
}

/**
 * Produces the `.claude/settings.json` fragment login merges into a project (or
 * user) settings file: the ingest env for the capture hooks. The hook wiring
 * itself is the plugin's job (WS3); login only supplies credentials.
 */
export function buildClaudeEnv(creds: VeritioCredentials): Record<string, string> {
  return {
    VERITIO_INGEST_URL: creds.ingestUrl,
    VERITIO_INGEST_KEY: creds.ingestKey,
    VERITIO_TENANT_ID: creds.tenantId,
  };
}

/** Derives the ingest URL from a console base URL (`…/api/ingest`). */
export function ingestUrlFor(consoleUrl: string): string {
  return `${consoleUrl.replace(/\/+$/, "")}/api/ingest`;
}
