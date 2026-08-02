import { createCaptureEnvironment, simulateSession } from "./capture";

/**
 * Replays the simulated Claude Code session against a Veritio Cloud project so
 * a dev/demo tenant gains realistic agent-session and code-change evidence —
 * the same families the local capture test proves, delivered through the real
 * hook binary and the hosted ingest API. Mirrors the env contract of
 * `cloud-full-governance-poc/src/post-cloud.ts`; secrets stay in env and are
 * never logged.
 *
 * ```sh
 * VERITIO_CLOUD_BASE_URL=http://localhost:3010 \
 * VERITIO_CLOUD_PROJECT_ID=<project id> \
 * VERITIO_CLOUD_INGEST_TOKEN=<vrt_… ingest key> \
 * bun src/post-cloud.ts
 * ```
 */
async function main() {
  const baseUrl = readEnv("VERITIO_CLOUD_BASE_URL", "http://localhost:3010");
  const projectId = readEnv("VERITIO_CLOUD_PROJECT_ID");
  const ingestToken = readEnv("VERITIO_CLOUD_INGEST_TOKEN");
  const sessionId = process.env.VERITIO_CLOUD_SESSION_ID ?? `sess_cloud_demo_${Date.now().toString(36)}`;

  const env = createCaptureEnvironment();
  simulateSession(
    env,
    {
      sessionId,
      prompt: "Refactor billing and rotate the key TOP-SECRET-ROTATE-ME-9000",
    },
    {
      tenantId: projectId,
      ingestUrl: `${baseUrl.replace(/\/$/, "")}/api/ingest`,
      ingestKey: ingestToken,
    },
  );

  console.log(
    JSON.stringify(
      {
        baseUrl,
        projectId,
        sessionId,
        posted: "agent session (start, prompt hash, Edit tool pre/post, turn scan, end)",
        note: "raw prompt text never leaves the machine — only sha256 hashes travel",
      },
      null,
      2,
    ),
  );
}

/** Reads a required env var, with an optional default for the base URL. */
function readEnv(name: string, fallback?: string): string {
  const value = process.env[name]?.trim() || fallback;
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
