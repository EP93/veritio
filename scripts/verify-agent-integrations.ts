import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { MAX_INGEST_TIMEOUT_MS } from "../adapters/codex/src/ingest.js";

const root = resolve(import.meta.dir, "..");
const core = readJson("sdks/typescript/package.json");
const storage = readJson("storage/package.json");
const claude = readJson("adapters/claude-code/package.json");
const plugin = readJson("plugins/veritio/.claude-plugin/plugin.json");
const hooks = readJson("plugins/veritio/hooks/hooks.json");
const lockfile = readFileSync(resolve(root, "bun.lock"), "utf8");

const releaseVersion = stringAt(core, "version");
assertEqual(stringAt(storage, "version"), releaseVersion, "storage must share the core release version");
assertEqual(stringAt(claude, "version"), releaseVersion, "Claude Code must share the core release version");
assertEqual(stringAt(claude, "dependencies", "@veritio/core"), releaseVersion, "Claude Code must pin core exactly");
assertEqual(
  stringAt(claude, "dependencies", "@veritio/storage"),
  releaseVersion,
  "Claude Code must pin storage exactly",
);
const claudeWorkspace = lockfile.match(/"adapters\/claude-code": \{[\s\S]*?\n    \},/)?.[0] ?? "";
if (
  !claudeWorkspace.includes(`"@veritio/core": "${releaseVersion}"`) ||
  !claudeWorkspace.includes(`"@veritio/storage": "${releaseVersion}"`)
) {
  throw new Error("bun.lock must record the exact Claude core/storage release pins");
}

const expectedHook = `bunx --package @veritio/claude-code@${releaseVersion} veritio-claude-code-hook`;
const commands = collectHookCommands(hooks);
if (commands.length !== 7 || commands.some((command) => command !== expectedHook)) {
  throw new Error("every Claude plugin hook must use the exact reviewed, published package version");
}
if (commands.some((command) => /@latest|bunx\s+-y|@veritio\/claude-code\s/.test(command))) {
  throw new Error("Claude plugin hooks must never auto-select an unreviewed package version");
}
assertEqual(plugin.defaultEnabled, false, "hosted-connected plugin must remain disabled by default");
assertEqual(MAX_INGEST_TIMEOUT_MS, 30_000, "Codex remote attempt maximum must stay finite");

console.log(
  JSON.stringify({
    outcome: "ok",
    releaseVersion,
    pluginVersion: stringAt(plugin, "version"),
    pinnedClaudeVersion: releaseVersion,
    codexMaximumRemoteAttemptMs: MAX_INGEST_TIMEOUT_MS,
  }),
);

/** Reads one repository JSON document without accepting comments or coercion. */
function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(root, path), "utf8")) as Record<string, unknown>;
}

/** Reads one required string through a sequence of object keys. */
function stringAt(value: unknown, ...keys: string[]): string {
  let current = value;
  for (const key of keys) {
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      throw new Error(`missing ${keys.join(".")}`);
    }
    current = (current as Record<string, unknown>)[key];
  }
  if (typeof current !== "string" || !current) {
    throw new Error(`missing ${keys.join(".")}`);
  }
  return current;
}

/** Flattens the seven Claude event hook commands for exact pin verification. */
function collectHookCommands(document: Record<string, unknown>): string[] {
  const groups = document.hooks;
  if (!groups || typeof groups !== "object" || Array.isArray(groups)) return [];
  const commands: string[] = [];
  for (const entries of Object.values(groups as Record<string, unknown>)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
      const hooks = (entry as Record<string, unknown>).hooks;
      if (!Array.isArray(hooks)) continue;
      for (const hook of hooks) {
        if (!hook || typeof hook !== "object" || Array.isArray(hook)) continue;
        const command = (hook as Record<string, unknown>).command;
        if (typeof command === "string") commands.push(command);
      }
    }
  }
  return commands;
}

/** Throws a stable contract error when two integration values drift. */
function assertEqual(actual: unknown, expected: unknown, message: string): void {
  if (actual !== expected) throw new Error(`${message}: expected ${String(expected)}`);
}
