/**
 * @veritio/claude-code — capture Claude Code agent activity as Veritio evidence.
 *
 * The hook CLI (`veritio-claude-code-hook`, dist/hook.js) is the runtime entry,
 * wired into Claude Code's settings.json. This module re-exports the pure,
 * reusable building blocks (config resolution, redaction, per-session state, the
 * hook→recorder mapping, and the ingest poster) for embedding or testing.
 */
export * from "./config.js";
export * from "./ingest.js";
export * from "./map.js";
export * from "./query.js";
export * from "./redact.js";
export * from "./spool.js";
export * from "./state.js";
export type { HookPayload, SessionContext } from "./types.js";
