#!/usr/bin/env bun
import { resolveConfig, resolveLocalDir } from "./config.js";
import {
  flushSpool,
  inspectSpool,
  pauseSpool,
  quarantinedSpoolEntries,
  type ReplayPermit,
  resumeSpool,
} from "./spool.js";

/** Injectable output boundary keeps queue commands testable and payload-safe. */
export interface SpoolCliIo {
  stdout(text: string): void;
  stderr(text: string): void;
}

const DEFAULT_IO: SpoolCliIo = {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
};

const USAGE = `Usage: veritio-claude-code-spool <command> [options]

Commands:
  status
  pause --reason <text>
  resume --acknowledge <text>
  canary
  drain --max-batches <n> --max-records <n> --max-bytes <n> --max-elapsed-ms <n>
  quarantine
`;

/** Parses strict flag/value pairs and rejects ambiguous or duplicated options. */
function parseOptions(args: string[], allowed: ReadonlySet<string>): Map<string, string> {
  const options = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flag || !allowed.has(flag) || value === undefined || value.startsWith("--") || options.has(flag)) {
      throw new Error("invalid or duplicate command option");
    }
    options.set(flag, value);
  }
  return options;
}

/** Parses a finite positive integer before it can become a replay permit field. */
function finitePositiveInteger(value: string | undefined, name: string): number {
  const parsed = Number(value);
  if (!value || !Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a finite positive integer`);
  }
  return parsed;
}

/** Writes stable JSON output without echoing credentials or queued payloads. */
function writeJson(io: SpoolCliIo, value: unknown): void {
  io.stdout(`${JSON.stringify(value, null, 2)}\n`);
}

/** Resolves the configured ingest boundary only for commands that perform network I/O. */
function requireIngest(env: NodeJS.ProcessEnv): ReturnType<typeof resolveConfig> & {
  ingest: NonNullable<ReturnType<typeof resolveConfig>["ingest"]>;
} {
  const config = resolveConfig(env);
  if (!config.ingest) {
    throw new Error("canary and drain require VERITIO_INGEST_URL plus VERITIO_INGEST_KEY");
  }
  return config as ReturnType<typeof resolveConfig> & {
    ingest: NonNullable<ReturnType<typeof resolveConfig>["ingest"]>;
  };
}

/**
 * Runs one operator command. Offline inspection and hold controls intentionally
 * bypass ingest config so a missing or broken remote cannot hide the queue.
 */
export async function runSpoolCli(
  args: string[],
  env: NodeJS.ProcessEnv = process.env,
  io: SpoolCliIo = DEFAULT_IO,
): Promise<number> {
  const [command, ...rest] = args;
  try {
    if (!command || command === "help" || command === "--help" || command === "-h") {
      io.stdout(USAGE);
      return 0;
    }
    const localDir = resolveLocalDir(env);
    switch (command) {
      case "status": {
        if (rest.length > 0) throw new Error("status accepts no options");
        writeJson(io, inspectSpool(localDir));
        return 0;
      }
      case "pause": {
        const options = parseOptions(rest, new Set(["--reason"]));
        const reason = options.get("--reason")?.trim();
        if (!reason) throw new Error("pause requires --reason");
        pauseSpool(localDir, { code: "operator_pause", reason });
        writeJson(io, inspectSpool(localDir));
        return 0;
      }
      case "resume": {
        const options = parseOptions(rest, new Set(["--acknowledge"]));
        const acknowledgement = options.get("--acknowledge")?.trim();
        if (!acknowledgement) throw new Error("resume requires --acknowledge");
        resumeSpool(localDir, acknowledgement);
        writeJson(io, inspectSpool(localDir));
        return 0;
      }
      case "quarantine": {
        if (rest.length > 0) throw new Error("quarantine accepts no options");
        writeJson(
          io,
          quarantinedSpoolEntries(localDir).map((entry) => ({
            sequence: entry.sequence,
            capturedAt: entry.capturedAt,
            encodedBytes: entry.encodedBytes,
            recordCount: entry.recordCount,
            attempts: entry.attempts,
            disposition: entry.disposition,
            code: entry.code,
          })),
        );
        return 0;
      }
      case "canary": {
        if (rest.length > 0) throw new Error("canary accepts no options");
        const config = requireIngest(env);
        const replay = await flushSpool(config.ingest, localDir, {
          id: `canary_${Date.now()}`,
          kind: "canary",
          maxBatches: 1,
          maxRecords: 500,
          maxBytes: 1_000_000,
          maxElapsedMs: 5_000,
        });
        writeJson(io, replay);
        return 0;
      }
      case "drain": {
        const options = parseOptions(
          rest,
          new Set(["--max-batches", "--max-records", "--max-bytes", "--max-elapsed-ms"]),
        );
        if (options.size !== 4) {
          throw new Error("drain requires all four finite replay budgets");
        }
        const permit: ReplayPermit = {
          id: `drain_${Date.now()}`,
          kind: "drain",
          maxBatches: finitePositiveInteger(options.get("--max-batches"), "--max-batches"),
          maxRecords: finitePositiveInteger(options.get("--max-records"), "--max-records"),
          maxBytes: finitePositiveInteger(options.get("--max-bytes"), "--max-bytes"),
          maxElapsedMs: finitePositiveInteger(options.get("--max-elapsed-ms"), "--max-elapsed-ms"),
        };
        const config = requireIngest(env);
        writeJson(io, await flushSpool(config.ingest, localDir, permit));
        return 0;
      }
      default:
        throw new Error(`unknown command: ${command}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    io.stderr(`veritio-claude-code-spool: ${message}\n`);
    return 2;
  }
}

if (import.meta.main) {
  process.exit(await runSpoolCli(process.argv.slice(2)));
}
