import type { DispatchPermit, OutboxAdapter, OutboxDispatcher, OutboxStoredEntry } from "@veritio/storage";

/** Delivery state safe for unauthenticated health output; it never carries errors, keys, or circuit ids. */
export type ShipOutRuntimeState =
  | "disabled"
  | "held"
  | "canary_armed"
  | "canary_running"
  | "canary_complete"
  | "paused"
  | "error";

/** Sanitized queue state exposed by the gateway health endpoint. */
export interface ShipOutRuntimeSnapshot {
  state: ShipOutRuntimeState;
  pending: number;
  paused: number;
  quarantined: number;
  canaryAttempted: boolean;
}

/** One immutable gateway wiring generation used by the runtime on a maintenance tick. */
export interface ShipOutDeliveryGeneration {
  tenantId: string;
  startupMode: "held" | "canary";
  permit: DispatchPermit;
  outbox: Pick<OutboxAdapter, "list">;
  dispatcher: OutboxDispatcher;
}

/** Runtime lifecycle returned to the process boundary. */
export interface ShipOutRuntime {
  start(): void;
  stop(): void;
  snapshot(): ShipOutRuntimeSnapshot;
}

export interface ShipOutRuntimeOptions {
  intervalMs: number;
  /** Retries local evidence and gap markers before remote delivery is considered. */
  maintenance(): Promise<void>;
  /** Resolves the current reload-safe generation; undefined means ship-out disabled. */
  delivery(): ShipOutDeliveryGeneration | undefined;
  /** Receives only a bounded stage identifier, never the underlying error. */
  onError?: (stage: "maintenance" | "inspect" | "dispatch") => void;
}

/** Counts queue lifecycle states without exposing entry payloads or circuit metadata. */
function queueCounts(
  entries: readonly OutboxStoredEntry[],
): Pick<ShipOutRuntimeSnapshot, "pending" | "paused" | "quarantined"> {
  return {
    pending: entries.filter((entry) => entry.status === "pending" || entry.status === "leased").length,
    paused: entries.filter((entry) => entry.status === "paused").length,
    quarantined: entries.filter((entry) => entry.status === "dead").length,
  };
}

/**
 * Creates an awaited self-scheduling maintenance loop. A new timer is armed
 * only after the prior tick settles, preventing overlapping async intervals.
 * Remote delivery starts held and an opted-in canary is consumed at most once.
 */
export function createShipOutRuntime(options: ShipOutRuntimeOptions): ShipOutRuntime {
  if (!Number.isSafeInteger(options.intervalMs) || options.intervalMs <= 0) {
    throw new TypeError("ship-out interval must be a positive safe integer");
  }
  let timer: ReturnType<typeof setTimeout> | null = null;
  let started = false;
  let stopped = false;
  let canaryAttempted = false;
  let canaryTerminal: "complete" | "error" | null = null;
  let snapshot: ShipOutRuntimeSnapshot = {
    state: "disabled",
    pending: 0,
    paused: 0,
    quarantined: 0,
    canaryAttempted: false,
  };

  /** Reports a bounded stage identifier while containing failures in host logging hooks. */
  function reportError(stage: "maintenance" | "inspect" | "dispatch"): void {
    try {
      options.onError?.(stage);
    } catch {
      // A diagnostic hook must not stop or overlap the delivery runtime.
    }
  }

  /** Replaces health state atomically with counts derived from durable rows. */
  function update(state: ShipOutRuntimeState, entries: readonly OutboxStoredEntry[]): void {
    snapshot = { state, ...queueCounts(entries), canaryAttempted };
  }

  /** Lists the current tenant queue and converts inspection failures to value-free state. */
  async function inspect(generation: ShipOutDeliveryGeneration): Promise<OutboxStoredEntry[] | null> {
    try {
      return await generation.outbox.list({ tenantId: generation.tenantId });
    } catch {
      canaryTerminal = "error";
      snapshot = { ...snapshot, state: "error", canaryAttempted };
      reportError("inspect");
      return null;
    }
  }

  /** Runs one serial local-maintenance and optional one-shot canary epoch. */
  async function runTick(): Promise<void> {
    try {
      await options.maintenance();
    } catch {
      reportError("maintenance");
    }
    let generation: ShipOutDeliveryGeneration | undefined;
    try {
      generation = options.delivery();
    } catch {
      canaryTerminal = "error";
      snapshot = { ...snapshot, state: "error", canaryAttempted };
      reportError("inspect");
      return;
    }
    if (!generation) {
      snapshot = { state: "disabled", pending: 0, paused: 0, quarantined: 0, canaryAttempted };
      return;
    }
    const before = await inspect(generation);
    if (!before) return;
    const beforeCounts = queueCounts(before);
    if (beforeCounts.paused > 0) {
      update("paused", before);
      return;
    }
    if (generation.startupMode === "held") {
      update("held", before);
      return;
    }
    if (canaryAttempted) {
      update(canaryTerminal === "error" ? "error" : "canary_complete", before);
      return;
    }
    if (beforeCounts.pending === 0) {
      update("canary_armed", before);
      return;
    }

    canaryAttempted = true;
    update("canary_running", before);
    try {
      const result = await generation.dispatcher.dispatchBatch({
        tenantId: generation.tenantId,
        permit: generation.permit,
      });
      canaryTerminal = "complete";
      const after = (await inspect(generation)) ?? before;
      update(result.paused > 0 || queueCounts(after).paused > 0 ? "paused" : "canary_complete", after);
    } catch {
      canaryTerminal = "error";
      snapshot = { ...snapshot, state: "error", canaryAttempted };
      reportError("dispatch");
    }
  }

  /** Arms the next tick only after the current awaited tick has settled. */
  function schedule(delayMs: number): void {
    if (stopped) return;
    timer = setTimeout(() => {
      timer = null;
      void runTick()
        .catch(() => {
          canaryTerminal = "error";
          snapshot = { ...snapshot, state: "error", canaryAttempted };
          reportError("inspect");
        })
        .finally(() => schedule(options.intervalMs));
    }, delayMs);
  }

  return {
    /** Starts one idempotent self-scheduling loop with an immediate maintenance tick. */
    start(): void {
      if (started) return;
      started = true;
      stopped = false;
      schedule(0);
    },
    /** Prevents new ticks; any already-awaited tick may settle but cannot reschedule. */
    stop(): void {
      stopped = true;
      started = false;
      if (timer !== null) clearTimeout(timer);
      timer = null;
    },
    /** Returns a defensive payload-free snapshot for health reporting. */
    snapshot(): ShipOutRuntimeSnapshot {
      return { ...snapshot };
    },
  };
}
