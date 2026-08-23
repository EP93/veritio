import { describe, expect, test } from "bun:test";

import { resolveConfig } from "../config";
import { buildSessionContext, episodeIdOf } from "../map";
import type { HookPayload } from "../types";

const NOW = "2026-06-18T12:00:00.000Z";

function sessionStart(sessionId: string): HookPayload {
  return { hook_event_name: "SessionStart", session_id: sessionId };
}

describe("resolveConfig — VERITIO_ACTIVITY_EPISODE_ID", () => {
  test("set: config.activityEpisodeId equals the override (opt-in)", () => {
    const config = resolveConfig({ VERITIO_ACTIVITY_EPISODE_ID: "ep_shared_swimlane" } as NodeJS.ProcessEnv);
    expect(config.activityEpisodeId).toBe("ep_shared_swimlane");
  });

  test("unset: config.activityEpisodeId is undefined (deterministic fallback path)", () => {
    const config = resolveConfig({} as NodeJS.ProcessEnv);
    expect(config.activityEpisodeId).toBeUndefined();
  });

  test("empty/whitespace: treated as unset so the deterministic default still fires", () => {
    expect(resolveConfig({ VERITIO_ACTIVITY_EPISODE_ID: "" } as NodeJS.ProcessEnv).activityEpisodeId).toBeUndefined();
    expect(
      resolveConfig({ VERITIO_ACTIVITY_EPISODE_ID: "   " } as NodeJS.ProcessEnv).activityEpisodeId,
    ).toBeUndefined();
  });

  test("is independent of the ingest fail-closed coupling (no throw when standalone)", () => {
    expect(() => resolveConfig({ VERITIO_ACTIVITY_EPISODE_ID: "ep_shared" } as NodeJS.ProcessEnv)).not.toThrow();
  });
});

describe("resolveConfig — bounded delivery spool", () => {
  test("uses conservative hard bounds unless the host explicitly lowers them", () => {
    expect(resolveConfig({} as NodeJS.ProcessEnv).spoolLimits).toEqual({
      hardBatches: 250,
      hardBytes: 50_000_000,
    });
    expect(
      resolveConfig({
        VERITIO_SPOOL_HARD_BATCHES: "25",
        VERITIO_SPOOL_HARD_BYTES: "1000000",
      } as NodeJS.ProcessEnv).spoolLimits,
    ).toEqual({ hardBatches: 25, hardBytes: 1_000_000 });
  });

  test("rejects non-finite, non-integer, and expanded hard bounds", () => {
    const invalidCases: Array<[string, string]> = [
      ["VERITIO_SPOOL_HARD_BATCHES", "0"],
      ["VERITIO_SPOOL_HARD_BATCHES", "251"],
      ["VERITIO_SPOOL_HARD_BATCHES", "Infinity"],
      ["VERITIO_SPOOL_HARD_BYTES", "1.5"],
      ["VERITIO_SPOOL_HARD_BYTES", "50000001"],
    ];
    for (const [name, value] of invalidCases) {
      expect(() => resolveConfig({ [name]: value } as NodeJS.ProcessEnv)).toThrow("hard safety ceiling");
    }
  });
});

describe("SessionStart activity-episode resolution (override wins; default otherwise)", () => {
  // Mirrors the hook's first-SessionStart precedence (state is empty):
  //   state.activityEpisodeId ?? config.activityEpisodeId ?? episodeIdOf(sessionId)
  test("override set: the session-start context's activityEpisodeId equals the override, not ep_<sessionId>", () => {
    const config = resolveConfig({ VERITIO_ACTIVITY_EPISODE_ID: "ep_shared_swimlane" } as NodeJS.ProcessEnv);
    const payload = sessionStart("sess_a");
    const activityEpisodeId = config.activityEpisodeId ?? episodeIdOf(payload.session_id);
    const ctx = buildSessionContext(payload, config, { now: NOW, activityEpisodeId });
    expect(ctx.activityEpisodeId).toBe("ep_shared_swimlane");
    expect(ctx.activityEpisodeId).not.toBe(episodeIdOf("sess_a"));
  });

  test("override unset: the session-start context falls back to ep_<sessionId>", () => {
    const config = resolveConfig({} as NodeJS.ProcessEnv);
    const payload = sessionStart("sess_a");
    const activityEpisodeId = config.activityEpisodeId ?? episodeIdOf(payload.session_id);
    const ctx = buildSessionContext(payload, config, { now: NOW, activityEpisodeId });
    expect(ctx.activityEpisodeId).toBe("ep_sess_a");
  });
});
