/**
 * Process-boundary entry: the ONLY module that reads files, environment
 * variables, or process signals. It wires config → file evidence store →
 * health state → proxy handler into a Bun HTTP server, runs the pending-
 * evidence retry loop, and reloads config on SIGHUP without dropping
 * in-flight traffic. Log lines are single, sanitized, and value-free —
 * config contents include real provider keys and must never be echoed.
 *
 * Env: VERITIO_GATEWAY_CONFIG (default ./veritio-gateway.json),
 *      VERITIO_GATEWAY_PORT   (default 8790).
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  createFileEvidenceStore,
  createFileOutboxAdapter,
  createHttpIngestTarget,
  createHttpOutboxDispatcher,
  DEFAULT_DELIVERY_SAFETY_POLICY,
  type OutboxAdapter,
  type OutboxDispatcher,
} from "@veritio/storage";
import { type GatewayConfig, parseGatewayConfig } from "./config";
import { buildGapMarkerEvent, createGatewayEvidence, type GatewayEvidence, type GatewayEvidenceSink } from "./evidence";
import { createHealthState, type HealthState } from "./health";
import { type PricingCatalog, parsePricingCatalog } from "./pricing";
import { createGatewayHandler } from "./proxy";
import { createShipOutSink } from "./shipout";
import { createShipOutRuntime, type ShipOutDeliveryGeneration, type ShipOutRuntime } from "./shipout-runtime";

/** Handle returned by `startGateway`; hosts and tests drive lifecycle through it. */
export interface StartedGateway {
  port: number;
  /** Re-reads the config file; on parse failure the previous config stays active. */
  reload(): Promise<void>;
  stop(): void;
}

/** Start options; test hooks (fetchImpl, retry cadence, signal opt-out) are injectable. */
export interface StartGatewayOptions {
  configPath?: string;
  port?: number;
  fetchImpl?: typeof fetch;
  /** Test/embedding hook; production defaults to a conservative 60-second maintenance interval. */
  retryIntervalMs?: number;
  /** Set false in tests so the suite's own process signals stay untouched. */
  installSignalHandlers?: boolean;
}

interface Wiring {
  handler: (req: Request) => Promise<Response>;
  health: HealthState;
  evidence: GatewayEvidence;
  store: GatewayEvidenceSink;
  config: GatewayConfig;
  /** Present only when `config.ingest` is set: drains the ship-out outbox to the cloud. */
  ingestDispatcher?: OutboxDispatcher;
  /** Same durable adapter used by the dispatcher and sanitized health inspection. */
  ingestOutbox?: OutboxAdapter;
}

/** Loads and validates config + pricing catalog from disk (fail closed on both). */
async function loadWiringInputs(configPath: string): Promise<{ config: GatewayConfig; catalog: PricingCatalog }> {
  const config = parseGatewayConfig(JSON.parse(await readFile(configPath, "utf8")));
  const catalogPath = config.pricingCatalogPath ?? join(import.meta.dir, "..", "pricing", "catalog.json");
  const catalog = parsePricingCatalog(JSON.parse(await readFile(catalogPath, "utf8")));
  return { config, catalog };
}

/**
 * Boots the gateway: one call wires storage, health, proxy, retry loop, and
 * the HTTP listener. Evidence storage is the packaged file store rooted at
 * `config.evidenceDir`; hosts needing a DB-backed store embed
 * `createGatewayHandler` directly instead of using this entry.
 */
export async function startGateway(options: StartGatewayOptions = {}): Promise<StartedGateway> {
  const configPath = options.configPath ?? process.env.VERITIO_GATEWAY_CONFIG ?? "./veritio-gateway.json";
  const port = options.port ?? Number(process.env.VERITIO_GATEWAY_PORT ?? 8790);

  // ONE health state outlives config reloads: pending evidence captured
  // before a reload must survive it, and a reload must never lift the
  // fail-closed 503 gate while outcomes are still unrecorded. The failure
  // mode is read through this box so reloads still apply mode changes.
  let failureMode: "block" | "degrade" = "block";
  const health = createHealthState({ mode: () => failureMode });

  /** Builds one immutable wiring generation; reload swaps the whole generation atomically. */
  async function buildWiring(): Promise<Wiring> {
    const { config, catalog } = await loadWiringInputs(configPath);
    const localStore = createFileEvidenceStore(config.evidenceDir);
    // With `ingest` configured, every locally committed event (including gap
    // markers, which record through the same sink) is mirrored into a file
    // outbox and drained asynchronously — local store stays authoritative,
    // cloud outages only grow the outbox, traffic is never blocked.
    let store: GatewayEvidenceSink = localStore;
    let ingestDispatcher: OutboxDispatcher | undefined;
    let ingestOutbox: OutboxAdapter | undefined;
    if (config.ingest !== undefined) {
      // The ship-out outbox is hard-bounded: in the default `held` startup
      // mode nothing drains it, so without this ceiling a long-lived gateway
      // would grow entries.json until the evidence volume fills. Once full,
      // new remote-delivery copies are refused (sink logs the hold) while the
      // authoritative local store keeps recording.
      const outbox = createFileOutboxAdapter(join(config.evidenceDir, "outbox"), {
        maxQueuedBytes: DEFAULT_DELIVERY_SAFETY_POLICY.hard.queuedBytes,
      });
      ingestOutbox = outbox;
      store = createShipOutSink(localStore, { outbox, tenantId: config.tenantId });
      ingestDispatcher = createHttpOutboxDispatcher({
        adapter: outbox,
        target: createHttpIngestTarget({
          baseUrl: config.ingest.url,
          key: config.ingest.key,
          timeoutMs: config.ingest.canary.maxElapsedMs,
        }),
      });
    }
    const evidence = createGatewayEvidence(store, { tenantId: config.tenantId, gatewayId: config.gatewayId });
    const handler = createGatewayHandler({
      config,
      catalog,
      evidence,
      health,
      ...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
    });
    return {
      handler,
      health,
      evidence,
      store,
      config,
      ...(ingestDispatcher === undefined ? {} : { ingestDispatcher }),
      ...(ingestOutbox === undefined ? {} : { ingestOutbox }),
    };
  }

  let current = await buildWiring();
  failureMode = current.config.evidenceFailureMode;

  /** Retries local evidence and records gap markers before a remote canary is considered. */
  async function runMaintenance(): Promise<void> {
    const generation = current;
    await health.retryPending((outcome) => generation.evidence.record(outcome));
    // Emit the gap marker only once the sink demonstrably works again
    // (pending drained), and consume the count only after the marker
    // actually recorded — consuming on read would zero it while the sink
    // is still down and the marker cannot be written.
    const dropped = health.droppedCount();
    if (dropped > 0 && health.pendingCount() === 0) {
      try {
        await generation.store.recordEvent(
          buildGapMarkerEvent(
            { tenantId: generation.config.tenantId, gatewayId: generation.config.gatewayId },
            dropped,
          ),
        );
        health.consumeDropped(dropped);
      } catch {
        console.error("veritio-gateway: failed to record evidence gap marker; will retry");
      }
    }
  }

  /** Resolves the current reload-safe one-canary delivery generation. */
  function currentDelivery(): ShipOutDeliveryGeneration | undefined {
    const generation = current;
    const ingest = generation.config.ingest;
    if (!ingest || !generation.ingestDispatcher || !generation.ingestOutbox) return undefined;
    return {
      tenantId: generation.config.tenantId,
      startupMode: ingest.startupMode,
      permit: {
        kind: "automatic",
        maxEntries: 1,
        maxBytes: ingest.canary.maxBytes,
        maxElapsedMs: ingest.canary.maxElapsedMs,
        leaseMs: ingest.canary.leaseMs,
      },
      outbox: generation.ingestOutbox,
      dispatcher: generation.ingestDispatcher,
    };
  }

  const shipOutRuntime: ShipOutRuntime = createShipOutRuntime({
    intervalMs: options.retryIntervalMs ?? 60_000,
    maintenance: runMaintenance,
    delivery: currentDelivery,
    onError(stage) {
      console.error(`veritio-gateway: ${stage} maintenance stage failed; delivery remains held`);
    },
  });
  shipOutRuntime.start();

  const server = Bun.serve({
    port,
    idleTimeout: 0,
    fetch(req: Request): Promise<Response> | Response {
      const url = new URL(req.url);
      if (req.method === "GET" && url.pathname === "/healthz") {
        const healthy = current.health.ok();
        return new Response(
          JSON.stringify({
            status: healthy ? "ok" : "evidence_unavailable",
            pendingEvidence: current.health.pendingCount(),
            shipOut: shipOutRuntime.snapshot(),
          }),
          { status: healthy ? 200 : 503, headers: { "content-type": "application/json" } },
        );
      }
      return current.handler(req);
    },
  });

  async function reload(): Promise<void> {
    try {
      current = await buildWiring();
      failureMode = current.config.evidenceFailureMode;
      console.error("veritio-gateway: config reloaded");
    } catch (error) {
      const field =
        error instanceof Error && "field" in error ? String((error as { field: unknown }).field) : "unknown";
      console.error(`veritio-gateway: config reload failed (field: ${field}); keeping previous config`);
    }
  }

  const onSighup = (): void => {
    void reload();
  };
  if (options.installSignalHandlers !== false) process.on("SIGHUP", onSighup);

  return {
    port: server.port ?? port,
    reload,
    stop() {
      shipOutRuntime.stop();
      if (options.installSignalHandlers !== false) process.off("SIGHUP", onSighup);
      server.stop(true);
    },
  };
}

// Direct execution (container entrypoint): boot and log the port only.
if (import.meta.main) {
  startGateway()
    .then((gateway) => {
      console.error(`veritio-gateway: listening on :${gateway.port}`);
    })
    .catch((error) => {
      const field =
        error instanceof Error && "field" in error ? ` (config field: ${(error as { field: unknown }).field})` : "";
      console.error(`veritio-gateway: failed to start${field}`);
      process.exit(1);
    });
}
