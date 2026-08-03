#!/usr/bin/env node
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseExportBundle, verifyExportBundle } from "@veritio/core";
import {
  LocalEvidenceStore,
  runIntegrationScenario,
  type StartedWorkbenchServer,
  type StartWorkbenchServerOptions,
  startWorkbenchServer,
} from "@veritio/server";
import { type LoginDeps, parseLoginArgs, runLogin } from "./login.js";

export interface DevCommandOptions {
  command: "dev";
  mcp: boolean;
  host: string;
  port: number;
  allowWriteTools: boolean;
  scenario: boolean;
}

export interface CliDependencies {
  start(options: StartWorkbenchServerOptions): Promise<Pick<StartedWorkbenchServer, "url" | "close">>;
  write(message: string): void;
}

export interface CliRunResult {
  code: number;
  server?: Pick<StartedWorkbenchServer, "url" | "close">;
}

const USAGE = "Usage: veritio dev --mcp [--host 127.0.0.1] [--port 4983] [--allow-write-tools] [--scenario]";

/**
 * Parses the local Workbench CLI contract and rejects unsupported commands before
 * any server or MCP write-tool state can be started.
 */
export function parseCliArgs(args: readonly string[]): DevCommandOptions {
  if (args[0] !== "dev") {
    throw new TypeError(USAGE);
  }

  const options: DevCommandOptions = {
    command: "dev",
    mcp: false,
    host: "127.0.0.1",
    port: 4983,
    allowWriteTools: false,
    scenario: false,
  };

  for (let index = 1; index < args.length; index++) {
    const arg = args[index];
    switch (arg) {
      case "--mcp":
        options.mcp = true;
        break;
      case "--host":
        options.host = requireNext(args, ++index, "--host");
        break;
      case "--port":
        options.port = parsePort(requireNext(args, ++index, "--port"));
        break;
      case "--allow-write-tools":
        options.allowWriteTools = true;
        break;
      case "--scenario":
        options.scenario = true;
        break;
      default:
        throw new TypeError(`Unknown option: ${arg}\n${USAGE}`);
    }
  }

  if (!options.mcp) {
    throw new TypeError(USAGE);
  }
  return options;
}

/**
 * Starts the local Workbench/MCP server with injected dependencies for tests.
 * Scenario seeding and write tools stay explicit CLI choices.
 */
export async function runCli(
  args: readonly string[] = process.argv.slice(2),
  dependencies: Partial<CliDependencies> = {},
): Promise<CliRunResult> {
  if (args[0] === "verify-bundle") {
    return runVerifyBundle(args, dependencies);
  }
  if (args[0] === "login") {
    return runLoginCommand(args, dependencies);
  }
  const write = dependencies.write ?? ((message: string) => process.stdout.write(`${message}\n`));
  try {
    const options = parseCliArgs(args);
    const store = new LocalEvidenceStore();
    if (options.scenario) {
      await runIntegrationScenario(store);
    }
    const start = dependencies.start ?? startWorkbenchServer;
    const server = await start({
      store,
      host: options.host,
      port: options.port,
      allowWriteTools: options.allowWriteTools,
    });
    write(`Veritio Workbench: ${server.url}`);
    write(`MCP endpoint: ${server.url}/mcp`);
    write(`MCP write tools: ${options.allowWriteTools ? "enabled" : "disabled"}`);
    return { code: 0, server };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    write(message);
    return { code: 1 };
  }
}

/**
 * Wires the login command to real side effects: fetch, mode-600 credential and
 * config writes (creating parent dirs), Codex config read/write under $HOME, and
 * an OS `open` for the approval URL. All I/O lives here at the process boundary.
 */
async function runLoginCommand(args: readonly string[], dependencies: Partial<CliDependencies>): Promise<CliRunResult> {
  const write = dependencies.write ?? ((message: string) => process.stdout.write(`${message}\n`));
  const codexConfigPath = join(homedir(), ".codex", "config.toml");
  const deps: LoginDeps = {
    codexNotifyBin: resolveCodexNotifyBin(),
    fetch,
    write,
    async writeFile(path, contents, mode) {
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, contents, { mode });
    },
    async readCodexConfig() {
      try {
        return await readFile(codexConfigPath, "utf8");
      } catch {
        return null;
      }
    },
    async writeCodexConfig(contents) {
      await mkdir(dirname(codexConfigPath), { recursive: true });
      await writeFile(codexConfigPath, contents);
    },
    openBrowser(url) {
      const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
      execFile(opener, [url], () => {});
    },
    sleep: (ms) => new Promise((done) => setTimeout(done, ms)),
    now: () => Date.now(),
  };
  try {
    return { code: await runLogin(parseLoginArgs(args), deps) };
  } catch (error) {
    write(error instanceof Error ? error.message : String(error));
    return { code: 1 };
  }
}

/**
 * Resolves the declared workspace/package dependency to an absolute notify
 * entrypoint so login never installs a wrapper around a missing global bin.
 */
function resolveCodexNotifyBin(): string {
  const require = createRequire(import.meta.url);
  return join(dirname(require.resolve("@veritio/codex")), "notify.js");
}

export interface VerifyBundleOptions {
  command: "verify-bundle";
  file: string;
  publicKeyPath?: string;
  requireSignature: boolean;
  json: boolean;
}

export interface VerifyBundleDependencies {
  write(message: string): void;
  writeError(message: string): void;
}

const VERIFY_BUNDLE_USAGE = "Usage: veritio verify-bundle <file> [--public-key <path>] [--require-signature] [--json]";

/**
 * Parses the `verify-bundle` contract: one positional bundle file plus the
 * optional `--public-key`, `--require-signature`, and `--json` flags. A missing
 * file, a second positional, or an unknown option fails closed with the usage
 * string so a malformed invocation never reaches the offline verifier.
 */
export function parseVerifyBundleArgs(args: readonly string[]): VerifyBundleOptions {
  const options: VerifyBundleOptions = {
    command: "verify-bundle",
    file: "",
    requireSignature: false,
    json: false,
  };
  let file: string | undefined;

  for (let index = 1; index < args.length; index++) {
    const arg = args[index];
    if (arg === undefined) {
      continue;
    }
    switch (arg) {
      case "--public-key":
        options.publicKeyPath = requireNext(args, ++index, "--public-key");
        break;
      case "--require-signature":
        options.requireSignature = true;
        break;
      case "--json":
        options.json = true;
        break;
      default:
        if (arg.startsWith("--")) {
          throw new TypeError(`Unknown option: ${arg}\n${VERIFY_BUNDLE_USAGE}`);
        }
        if (file !== undefined) {
          throw new TypeError(`Unexpected argument: ${arg}\n${VERIFY_BUNDLE_USAGE}`);
        }
        file = arg;
        break;
    }
  }

  if (!file) {
    throw new TypeError(VERIFY_BUNDLE_USAGE);
  }
  options.file = file;
  return options;
}

/**
 * Runs `veritio verify-bundle`: reads the container file, parses it, runs the
 * fail-closed offline verifier, and prints either a human summary or the raw
 * `--json` report. Exit code is 0 iff the report is valid. Every failure path —
 * unreadable file, malformed container, or bad key file — prints a sanitized
 * message to stderr and returns 1; stack traces and raw error text never reach
 * the user.
 */
export async function runVerifyBundle(
  args: readonly string[],
  dependencies: Partial<VerifyBundleDependencies> = {},
): Promise<CliRunResult> {
  const write = dependencies.write ?? ((message: string) => process.stdout.write(`${message}\n`));
  const writeError = dependencies.writeError ?? ((message: string) => process.stderr.write(`${message}\n`));

  let options: VerifyBundleOptions;
  try {
    options = parseVerifyBundleArgs(args);
  } catch (error) {
    writeError(error instanceof Error ? error.message : String(error));
    return { code: 1 };
  }

  let text: string;
  try {
    text = await readFile(options.file, "utf8");
  } catch {
    writeError(`verify-bundle: unable to read ${options.file}`);
    return { code: 1 };
  }

  let publicKey: CryptoKey | undefined;
  if (options.publicKeyPath) {
    try {
      publicKey = await readEd25519PublicKey(options.publicKeyPath);
    } catch {
      writeError(`verify-bundle: unable to read public key ${options.publicKeyPath}`);
      return { code: 1 };
    }
  }

  let report: Awaited<ReturnType<typeof verifyExportBundle>>;
  try {
    const bundle = parseExportBundle(text);
    report = await verifyExportBundle(bundle, {
      requireSignature: options.requireSignature,
      ...(publicKey ? { publicKey } : {}),
    });
  } catch (error) {
    writeError(error instanceof Error ? error.message : String(error));
    return { code: 1 };
  }

  if (options.json) {
    write(JSON.stringify(report, null, 2));
  } else {
    write(`structure: ${report.checks.structure ? "pass" : "fail"}`);
    write(`integrity: ${report.checks.integrity ? "pass" : "fail"}`);
    write(`chains: ${report.checks.chains ? "pass" : "fail"}`);
    write(`signature: ${report.checks.signature}`);
    if (report.issues.length > 0) {
      write("issues:");
      for (const issue of report.issues) {
        write(`  - ${issue}`);
      }
    }
    write(report.valid ? "VALID" : "INVALID");
    if (report.valid) {
      if (report.checks.signature === "absent") {
        write(
          "unsigned — integrity verified, authenticity NOT verified; pass --public-key and --require-signature to verify origin",
        );
      } else if (report.checks.signature === "skipped") {
        write("signature present but not checked — pass --public-key to verify origin");
      }
    }
  }

  return { code: report.valid ? 0 : 1 };
}

/**
 * Reads an Ed25519 public key file and imports it as a verifying `CryptoKey`.
 * Three encodings are accepted: a raw 32-byte binary file, one line of 64-char
 * hex, or one line of standard base64 over those 32 bytes. The 32-byte length is
 * the unambiguous discriminator — hex is 64 chars and base64 is 44, so only a raw
 * key file has exactly 32 bytes. Any other decoded length fails closed before the
 * key reaches WebCrypto.
 */
async function readEd25519PublicKey(path: string): Promise<CryptoKey> {
  const raw = await readFile(path);
  const keyBytes = raw.length === 32 ? raw : decodeKeyText(raw.toString("utf8").trim());
  if (keyBytes.length !== 32) {
    throw new Error("public key must be 32 raw Ed25519 bytes");
  }
  // Copy into a fresh ArrayBuffer so importKey gets a plain-ArrayBuffer BufferSource
  // (a Buffer/Uint8Array can be backed by SharedArrayBuffer, which WebCrypto rejects).
  const buffer = new ArrayBuffer(32);
  new Uint8Array(buffer).set(keyBytes);
  return crypto.subtle.importKey("raw", buffer, "Ed25519", true, ["verify"]);
}

/**
 * Decodes the text form of an Ed25519 public key: 64 hex characters, otherwise
 * standard base64. Malformed base64 throws, which the caller reports as an
 * unreadable key file.
 */
function decodeKeyText(text: string): Uint8Array {
  if (/^[0-9a-fA-F]{64}$/.test(text)) {
    return Uint8Array.from(Buffer.from(text, "hex"));
  }
  return Uint8Array.from(Buffer.from(text, "base64"));
}

/**
 * Reads the value after a CLI option and fails if the option is missing input.
 */
function requireNext(args: readonly string[], index: number, option: string): string {
  const value = args[index];
  if (!value || value.startsWith("--")) {
    throw new TypeError(`${option} requires a value`);
  }
  return value;
}

/**
 * Parses and bounds a TCP port before it reaches Node server startup.
 */
function parsePort(value: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new TypeError("port must be between 0 and 65535");
  }
  return port;
}

/**
 * Detects direct CLI execution across ESM file URLs and relative argv paths.
 */
export function isCliEntrypoint(metaUrl: string, argvPath: string | undefined, cwd = process.cwd()): boolean {
  if (!argvPath) {
    return false;
  }
  return fileURLToPath(metaUrl) === resolve(cwd, argvPath);
}

if (isCliEntrypoint(import.meta.url, process.argv[1])) {
  const result = await runCli();
  if (result.code !== 0) {
    process.exitCode = result.code;
  }
}
