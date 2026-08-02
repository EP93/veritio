import { mkdir, open, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { DeliveryDisposition } from "./delivery-safety.js";
import {
  assertLease,
  assertNonEmpty,
  clearLease,
  cloneEntry,
  compareEntries,
  createPendingEntry,
  errorMessage,
  filterEntries,
  findEntry,
  normalizeDate,
  outboxPayloadByteLength,
  resolveCircuitId,
  resolveDisposition,
  sameEnqueueInput,
  validateClaimOptions,
  validateListOptions,
  validateStoredEntry,
} from "./outbox-shared.js";
import type {
  OutboxAdapter,
  OutboxClaim,
  OutboxClaimOptions,
  OutboxListOptions,
  OutboxStoredEntry,
  OutboxTransaction,
} from "./outbox-types.js";

/** Creates the process-safe file outbox used by local and self-hosted flows. */
export function createFileOutboxAdapter(dir: string): OutboxAdapter {
  return new FileOutboxAdapter(dir);
}

/** File-backed outbox with atomic snapshots and crash-recoverable claims. */
class FileOutboxAdapter implements OutboxAdapter {
  readonly #dir: string;
  readonly #path: string;

  /** Stores paths without creating files for read-only callers. */
  constructor(dir: string) {
    this.#dir = dir;
    this.#path = join(dir, "entries.json");
  }

  /** Commits staged enqueues only after the host callback succeeds. */
  async transaction<T>(run: (tx: OutboxTransaction) => Promise<T>): Promise<T> {
    return withLock(this.#dir, async () => {
      const entries = await readEntries(this.#path);
      const staged = entries.map(cloneEntry);
      const tx: OutboxTransaction = {
        enqueue: async (input) => {
          const entry = createPendingEntry(input);
          const existing = staged.find((candidate) => candidate.id === entry.id);
          if (existing) {
            if (!sameEnqueueInput(existing, entry)) throw new TypeError("outbox idempotency conflict");
            return cloneEntry(existing);
          }
          staged.push(entry);
          staged.sort(compareEntries);
          return cloneEntry(entry);
        },
      };
      const result = await run(tx);
      await writeEntries(this.#dir, this.#path, staged);
      return result;
    });
  }

  /** Lists validated rows in stable queue order. */
  async list(options: OutboxListOptions = {}): Promise<OutboxStoredEntry[]> {
    validateListOptions(options);
    return filterEntries(await readEntries(this.#path), options).map(cloneEntry);
  }

  /** Lists due pending rows for diagnostics; dispatchers use atomic claims. */
  async listDispatchable(options: OutboxListOptions = {}): Promise<OutboxStoredEntry[]> {
    validateListOptions(options);
    const now = normalizeDate(options.now ?? new Date());
    const entries = await readEntries(this.#path);
    const pausedTenants = new Set(entries.filter((entry) => entry.status === "paused").map((entry) => entry.tenantId));
    return filterEntries(
      entries.filter(
        (entry) => !pausedTenants.has(entry.tenantId) && entry.status === "pending" && entry.availableAt <= now,
      ),
      options,
    ).map(cloneEntry);
  }

  /** Atomically leases a finite byte-bounded slice under the file lock. */
  async claimDispatchable(options: OutboxClaimOptions): Promise<OutboxClaim[]> {
    validateClaimOptions(options);
    return withLock(this.#dir, async () => {
      const entries = await readEntries(this.#path);
      const now = normalizeDate(options.now ?? new Date());
      const pausedTenants = new Set(
        entries.filter((entry) => entry.status === "paused").map((entry) => entry.tenantId),
      );
      const activeLeasedTenants = new Set(
        entries.filter((entry) => entry.status === "leased" && entry.availableAt > now).map((entry) => entry.tenantId),
      );
      const blockedTenants = new Set([...pausedTenants, ...activeLeasedTenants]);
      const candidates = filterEntries(
        entries.filter(
          (entry) =>
            !blockedTenants.has(entry.tenantId) &&
            ((entry.status === "pending" && entry.availableAt <= now) ||
              (entry.status === "leased" && entry.availableAt <= now)),
        ),
        options.tenantId === undefined ? {} : { tenantId: options.tenantId },
      );
      const claims: OutboxClaim[] = [];
      let bytes = 0;
      for (const entry of candidates) {
        if (claims.length >= options.limit) break;
        if (blockedTenants.has(entry.tenantId)) continue;
        const entryBytes = outboxPayloadByteLength(entry.payload);
        if (bytes + entryBytes > options.maxPayloadBytes) break;
        const expiresAt = new Date(new Date(now).getTime() + options.leaseMs).toISOString();
        entry.status = "leased";
        entry.leaseId = options.leaseId;
        entry.leaseExpiresAt = expiresAt;
        entry.availableAt = expiresAt;
        entry.updatedAt = now;
        claims.push(cloneEntry(entry) as OutboxClaim);
        bytes += entryBytes;
        blockedTenants.add(entry.tenantId);
      }
      if (claims.length > 0) await writeEntries(this.#dir, this.#path, entries);
      return claims;
    });
  }

  /** Settles a successfully delivered row only for its active lease owner. */
  async markDispatched(
    id: string,
    options: { leaseId?: string; dispatchedAt?: string | Date } = {},
  ): Promise<OutboxStoredEntry> {
    assertNonEmpty(id, "id");
    return withLock(this.#dir, async () => {
      const entries = await readEntries(this.#path);
      const entry = findEntry(entries, id);
      assertLease(entry, options.leaseId);
      const at = normalizeDate(options.dispatchedAt ?? new Date());
      entry.status = "dispatched";
      entry.dispatchedAt = at;
      entry.updatedAt = at;
      delete entry.lastError;
      delete entry.circuitId;
      clearLease(entry);
      await writeEntries(this.#dir, this.#path, entries);
      return cloneEntry(entry);
    });
  }

  /** Persists retry, pause, or rejection without deleting the evidence payload. */
  async markFailed(
    id: string,
    error: unknown,
    options: {
      leaseId?: string;
      now?: string | Date;
      availableAt?: string | Date;
      retryable?: boolean;
      disposition?: DeliveryDisposition;
      circuitId?: string;
    } = {},
  ): Promise<OutboxStoredEntry> {
    assertNonEmpty(id, "id");
    return withLock(this.#dir, async () => {
      const entries = await readEntries(this.#path);
      const entry = findEntry(entries, id);
      assertLease(entry, options.leaseId);
      const now = normalizeDate(options.now ?? new Date());
      entry.attempts += 1;
      entry.updatedAt = now;
      entry.lastError = errorMessage(error);
      const disposition = resolveDisposition(options);
      delete entry.circuitId;
      if (disposition === "reject") entry.status = "dead";
      else if (disposition === "pause") {
        entry.status = "paused";
        entry.circuitId = resolveCircuitId(options.circuitId);
      } else {
        entry.status = "pending";
        entry.availableAt = normalizeDate(options.availableAt ?? now);
      }
      clearLease(entry);
      await writeEntries(this.#dir, this.#path, entries);
      return cloneEntry(entry);
    });
  }

  /**
   * Explicitly re-arms held rows only when the operator acknowledges the exact
   * persisted circuit, preventing stale UI state from reopening a newer hold.
   */
  async resumePaused(options: {
    tenantId: string;
    expectedCircuitId: string;
    limit: number;
    now?: string | Date;
  }): Promise<number> {
    assertNonEmpty(options.tenantId, "tenantId");
    assertNonEmpty(options.expectedCircuitId, "expectedCircuitId");
    if (!Number.isSafeInteger(options.limit) || options.limit <= 0) throw new TypeError("limit must be positive");
    return withLock(this.#dir, async () => {
      const entries = await readEntries(this.#path);
      const paused = entries.filter((entry) => entry.tenantId === options.tenantId && entry.status === "paused");
      if (paused.some((entry) => entry.circuitId !== options.expectedCircuitId)) {
        throw new TypeError("outbox circuit does not match");
      }
      const now = normalizeDate(options.now ?? new Date());
      const selected = paused.slice(0, options.limit);
      for (const entry of selected) {
        entry.status = "pending";
        entry.availableAt = now;
        entry.updatedAt = now;
        delete entry.circuitId;
      }
      if (selected.length > 0) await writeEntries(this.#dir, this.#path, entries);
      return selected.length;
    });
  }
}

/** Reads and validates the complete snapshot, treating a missing file as empty. */
async function readEntries(path: string): Promise<OutboxStoredEntry[]> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  const parsed = JSON.parse(text) as unknown;
  if (!Array.isArray(parsed)) throw new TypeError("outbox file is not a row array");
  for (const entry of parsed) validateStoredEntry(entry);
  return parsed.map((entry) => cloneEntry(entry as OutboxStoredEntry)).sort(compareEntries);
}

/** Atomically publishes a complete snapshot via same-directory rename. */
async function writeEntries(dir: string, path: string, entries: OutboxStoredEntry[]): Promise<void> {
  await mkdir(dir, { recursive: true });
  const temp = join(dir, `entries.${process.pid}.${Date.now()}.${crypto.randomUUID()}.tmp`);
  await writeFile(temp, `${JSON.stringify(entries.sort(compareEntries), null, 2)}\n`, "utf8");
  await rename(temp, path);
}

/** Serializes snapshot mutations across local processes with an exclusive file. */
async function withLock<T>(dir: string, run: () => Promise<T>): Promise<T> {
  await mkdir(dir, { recursive: true });
  const lockPath = join(dir, ".outbox.lock");
  for (let attempt = 0; ; attempt += 1) {
    try {
      const handle = await open(lockPath, "wx");
      try {
        return await run();
      } finally {
        await handle.close();
        await unlink(lockPath).catch(() => {});
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST" || attempt >= 500) throw error;
      await delay(10);
    }
  }
}

/** Yields between lock attempts without a runtime dependency. */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
