import {
  buildCaptureEnv,
  buildClaudeEnv,
  buildCodexWrapper,
  CODEX_ENV_PATH,
  CODEX_WRAPPER_PATH,
  CREDENTIALS_PATH,
  codexNotifyLine,
  ingestUrlFor,
  type VeritioCredentials,
} from "./agent-config.js";

/**
 * `veritio login` — RFC 8628 device flow against Veritio Cloud that mints a
 * scoped ingest key on browser approval, so no key is ever pasted. On success
 * it writes local credentials and, for the chosen agent, the capture config
 * (Codex notify wrapper, or a printed Claude Code settings env block).
 */

export type LoginAgent = "codex" | "claude" | "both";

export interface LoginOptions {
  command: "login";
  consoleUrl: string;
  agent: LoginAgent;
  clientName: string;
  openBrowser: boolean;
}

const DEFAULT_CONSOLE_URL = "https://console.getveritio.com";
const LOGIN_REQUEST_TIMEOUT_MS = 15_000;
const LOGIN_USAGE =
  "Usage: veritio login [codex|claude|both] [--console-url <url>] [--client-name <name>] [--no-browser]";

/** Parses the login contract; unknown flags/agents fail closed with usage. */
export function parseLoginArgs(args: readonly string[]): LoginOptions {
  const options: LoginOptions = {
    command: "login",
    consoleUrl: DEFAULT_CONSOLE_URL,
    agent: "both",
    clientName: "veritio-cli",
    openBrowser: true,
  };
  for (let index = 1; index < args.length; index++) {
    const arg = args[index];
    if (arg === "codex" || arg === "claude" || arg === "both") {
      options.agent = arg;
    } else if (arg === "--console-url") {
      options.consoleUrl = requireNext(args, ++index, "--console-url");
    } else if (arg === "--client-name") {
      options.clientName = requireNext(args, ++index, "--client-name");
    } else if (arg === "--no-browser") {
      options.openBrowser = false;
    } else {
      throw new TypeError(LOGIN_USAGE);
    }
  }
  return options;
}

function requireNext(args: readonly string[], index: number, option: string): string {
  const value = args[index];
  if (!value || value.startsWith("--")) {
    throw new TypeError(`${option} requires a value`);
  }
  return value;
}

interface DeviceStart {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  intervalSeconds: number;
  expiresInSeconds: number;
}

type DevicePoll =
  | { status: "pending" }
  | { status: "denied" }
  | { status: "expired" }
  | { status: "approved"; token: string; projectId: string };

/** Injectable side effects so the flow is fully testable without real I/O. */
export interface LoginDeps {
  /** Absolute reviewed adapter entrypoint; never relies on an ambient global bin. */
  codexNotifyBin: string;
  fetch: typeof fetch;
  write(message: string): void;
  writeFile(path: string, contents: string, mode: number): Promise<void>;
  readCodexConfig(): Promise<string | null>;
  writeCodexConfig(contents: string): Promise<void>;
  openBrowser(url: string): void;
  sleep(ms: number): Promise<void>;
  now(): number;
}

/**
 * Runs the device flow to completion and writes capture config for the chosen
 * agent. Returns an exit code. Polling stops on approval, denial, expiry, or the
 * grant deadline — it never loops unbounded.
 */
export async function runLogin(options: LoginOptions, deps: LoginDeps): Promise<number> {
  const base = options.consoleUrl.replace(/\/+$/, "");
  const start = (await postJson(deps.fetch, `${base}/api/device/code`, {
    clientName: options.clientName,
    authority: "ingest",
  })) as DeviceStart;

  const approveUrl = `${start.verificationUri}?code=${encodeURIComponent(start.userCode)}`;
  deps.write(`\nTo connect, approve this device in your browser:\n  ${approveUrl}\n`);
  deps.write(`If it doesn't open automatically, go to ${start.verificationUri} and enter code: ${start.userCode}\n`);
  if (options.openBrowser) deps.openBrowser(approveUrl);

  const deadline = deps.now() + start.expiresInSeconds * 1000;
  let poll: DevicePoll = { status: "pending" };
  while (deps.now() < deadline) {
    await deps.sleep(start.intervalSeconds * 1000);
    poll = (await postJson(deps.fetch, `${base}/api/device/token`, { deviceCode: start.deviceCode })) as DevicePoll;
    if (poll.status !== "pending") break;
  }

  if (poll.status !== "approved") {
    deps.write(poll.status === "expired" ? "Login timed out — run `veritio login` again." : "Login was not approved.");
    return 1;
  }

  const creds: VeritioCredentials = {
    ingestUrl: ingestUrlFor(base),
    ingestKey: poll.token,
    tenantId: poll.projectId,
  };
  await deps.writeFile(CREDENTIALS_PATH, `${JSON.stringify(creds, null, 2)}\n`, 0o600);
  deps.write(`\n✓ Connected. Credentials stored at ${CREDENTIALS_PATH}\n`);

  if (options.agent === "codex" || options.agent === "both") {
    await configureCodex(creds, deps);
  }
  if (options.agent === "claude" || options.agent === "both") {
    deps.write('Claude Code: add this to your project\'s .claude/settings.json "env":');
    deps.write(JSON.stringify(buildClaudeEnv(creds), null, 2));
    deps.write("(the Veritio Claude Code plugin wires the capture hooks themselves.)\n");
  }
  return 0;
}

/**
 * Writes the Codex capture env + notify wrapper and rewrites config.toml's
 * single `notify` slot to the wrapper — preserving any existing notifier by
 * threading it into the wrapper (never dropping it).
 */
async function configureCodex(creds: VeritioCredentials, deps: LoginDeps): Promise<void> {
  await deps.writeFile(CODEX_ENV_PATH, buildCaptureEnv(creds), 0o600);
  const notifyBin = deps.codexNotifyBin;
  const existing = await deps.readCodexConfig();
  const existingNotify = existing ? extractNotify(existing) : null;
  const alreadyManaged = existingNotify?.length === 1 && existingNotify[0] === CODEX_WRAPPER_PATH;
  if (!alreadyManaged) {
    await deps.writeFile(CODEX_WRAPPER_PATH, buildCodexWrapper(notifyBin, existingNotify), 0o755);
  }
  const nextConfig = upsertNotify(existing ?? "", codexNotifyLine(CODEX_WRAPPER_PATH));
  await deps.writeCodexConfig(nextConfig);
  deps.write(`Codex: notify hook installed (wrapper at ${CODEX_WRAPPER_PATH}).\n`);
}

/** Extracts the existing `notify = [...]` array from config.toml, or null. */
export function extractNotify(configToml: string): string[] | null {
  const match = /^\s*notify\s*=\s*\[(.*?)\]/ms.exec(configToml);
  if (!match) return null;
  const items = match[1]?.match(/"([^"]*)"/g);
  if (!items) return null;
  return items.map((item) => item.slice(1, -1));
}

/** Replaces the `notify = ...` line in config.toml (or appends one). */
export function upsertNotify(configToml: string, notifyLine: string): string {
  if (/^\s*notify\s*=/m.test(configToml)) {
    return configToml.replace(/^\s*notify\s*=.*$/m, notifyLine);
  }
  const trimmed = configToml.replace(/\s*$/, "");
  return trimmed.length > 0 ? `${trimmed}\n${notifyLine}\n` : `${notifyLine}\n`;
}

/** POSTs JSON and parses the JSON response, throwing a clean error on failure. */
async function postJson(fetchImpl: typeof fetch, url: string, body: unknown): Promise<unknown> {
  const response = await fetchImpl(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(LOGIN_REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`request to ${url} failed with status ${response.status}`);
  }
  return response.json();
}
