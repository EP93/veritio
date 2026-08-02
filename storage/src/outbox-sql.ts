import type { DeliveryDisposition } from "./delivery-safety.js";
import {
  assertLease,
  assertNonEmpty,
  canonicalPayload,
  clearLease,
  cloneEntry,
  createPendingEntry,
  entryFromSqlRow,
  errorMessage,
  firstRow,
  normalizeDate,
  outboxPayloadByteLength,
  quoteTableName,
  readString,
  resolveCircuitId,
  resolveDisposition,
  rowsFromResult,
  sameEnqueueInput,
  validateClaimOptions,
  validateListOptions,
} from "./outbox-shared.js";
import type {
  OutboxAdapter,
  OutboxClaim,
  OutboxClaimOptions,
  OutboxEnqueueInput,
  OutboxListOptions,
  OutboxStoredEntry,
  OutboxTransaction,
  SqlOutboxAdapterOptions,
  SqlOutboxDialect,
  SqlOutboxSession,
} from "./outbox-types.js";

const DEFAULT_SQL_OUTBOX_TABLE = "veritio_outbox_entries";

/** Creates a Postgres-backed outbox with host-injected transactions. */
export function createPostgresOutboxAdapter(options: SqlOutboxAdapterOptions): OutboxAdapter {
  return new SqlOutboxAdapter("postgres", options);
}

/** Creates a Neon-compatible outbox through the Postgres dialect. */
export function createNeonOutboxAdapter(options: SqlOutboxAdapterOptions): OutboxAdapter {
  return createPostgresOutboxAdapter(options);
}

/** Creates a MySQL-backed outbox with host-injected transactions. */
export function createMysqlOutboxAdapter(options: SqlOutboxAdapterOptions): OutboxAdapter {
  return new SqlOutboxAdapter("mysql", options);
}

/** Creates a MariaDB-compatible outbox through the MySQL dialect. */
export function createMariaDbOutboxAdapter(options: SqlOutboxAdapterOptions): OutboxAdapter {
  return createMysqlOutboxAdapter(options);
}

/** Compatibility alias for the all-caps DB spelling. */
export function createMariaDBOutboxAdapter(options: SqlOutboxAdapterOptions): OutboxAdapter {
  return createMariaDbOutboxAdapter(options);
}

/** SQL implementation shared by Postgres, Neon, MySQL, and MariaDB. */
class SqlOutboxAdapter implements OutboxAdapter {
  readonly #client: SqlOutboxAdapterOptions["client"];
  readonly #dialect: SqlOutboxDialect;
  readonly #table: string;

  /** Validates the table identifier before generating any statement. */
  constructor(dialect: SqlOutboxDialect, options: SqlOutboxAdapterOptions) {
    this.#dialect = dialect;
    this.#client = options.client;
    this.#table = quoteTableName(options.tableName ?? DEFAULT_SQL_OUTBOX_TABLE, dialect);
  }

  /** Runs enqueue operations in the host transaction boundary. */
  async transaction<T>(run: (tx: OutboxTransaction) => Promise<T>): Promise<T> {
    return this.#client.transaction((session) => run({ enqueue: (input) => this.#enqueue(session, input) }));
  }

  /** Lists validated rows in stable order. */
  async list(options: OutboxListOptions = {}): Promise<OutboxStoredEntry[]> {
    validateListOptions(options);
    const tenantScoped = options.tenantId !== undefined;
    const rows = rowsFromResult(
      await this.#client.execute(
        this.#selectEntriesSql(tenantScoped, options.limit),
        this.#selectEntriesParams(options.tenantId, options.limit),
      ),
    );
    return rows.map(entryFromSqlRow).map(cloneEntry);
  }

  /** Lists due pending rows while respecting persisted tenant pause barriers. */
  async listDispatchable(options: OutboxListOptions = {}): Promise<OutboxStoredEntry[]> {
    validateListOptions(options);
    const now = normalizeDate(options.now ?? new Date());
    const tenantScoped = options.tenantId !== undefined;
    const rows = rowsFromResult(
      await this.#client.execute(
        this.#selectDispatchableSql(tenantScoped, options.limit),
        this.#dispatchableParams(now, options),
      ),
    );
    return rows.map(entryFromSqlRow).map(cloneEntry);
  }

  /** Atomically leases rows under `FOR UPDATE SKIP LOCKED`. */
  async claimDispatchable(options: OutboxClaimOptions): Promise<OutboxClaim[]> {
    validateClaimOptions(options);
    return this.#client.transaction(async (session) => {
      await session.execute(this.#lockTenantSql(), [options.tenantId]);
      const now = normalizeDate(options.now ?? new Date());
      const rows = rowsFromResult(
        await session.execute(this.#selectClaimableSql(options.limit), this.#claimableParams(now, options)),
      );
      const claims: OutboxClaim[] = [];
      let bytes = 0;
      for (const row of rows) {
        const entry = entryFromSqlRow(row);
        const entryBytes = outboxPayloadByteLength(entry.payload);
        if (bytes + entryBytes > options.maxPayloadBytes) break;
        const expiresAt = new Date(new Date(now).getTime() + options.leaseMs).toISOString();
        entry.status = "leased";
        entry.leaseId = options.leaseId;
        entry.leaseExpiresAt = expiresAt;
        entry.availableAt = expiresAt;
        entry.updatedAt = now;
        await this.#updateEntry(session, entry);
        claims.push(cloneEntry(entry) as OutboxClaim);
        bytes += entryBytes;
      }
      return claims;
    });
  }

  /** Settles successful work only for the active lease owner. */
  async markDispatched(
    id: string,
    options: { leaseId?: string; dispatchedAt?: string | Date } = {},
  ): Promise<OutboxStoredEntry> {
    assertNonEmpty(id, "id");
    return this.#client.transaction(async (session) => {
      const entry = await this.#loadEntryForUpdate(session, id);
      assertLease(entry, options.leaseId);
      const at = normalizeDate(options.dispatchedAt ?? new Date());
      entry.status = "dispatched";
      entry.dispatchedAt = at;
      entry.updatedAt = at;
      delete entry.lastError;
      delete entry.circuitId;
      clearLease(entry);
      await this.#updateEntry(session, entry);
      return cloneEntry(entry);
    });
  }

  /** Persists retry, pause, or rejection without deleting the payload. */
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
    return this.#client.transaction(async (session) => {
      const entry = await this.#loadEntryForUpdate(session, id);
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
      await this.#updateEntry(session, entry);
      return cloneEntry(entry);
    });
  }

  /** Re-arms paused SQL rows after compare-and-set circuit acknowledgement. */
  async resumePaused(options: {
    tenantId: string;
    expectedCircuitId: string;
    limit: number;
    now?: string | Date;
  }): Promise<number> {
    assertNonEmpty(options.tenantId, "tenantId");
    assertNonEmpty(options.expectedCircuitId, "expectedCircuitId");
    if (!Number.isSafeInteger(options.limit) || options.limit <= 0) throw new TypeError("limit must be positive");
    return this.#client.transaction(async (session) => {
      const entries = rowsFromResult(
        await session.execute(this.#selectPausedForUpdateSql(), [options.tenantId, "paused"]),
      ).map(entryFromSqlRow);
      if (entries.some((entry) => entry.circuitId !== options.expectedCircuitId)) {
        throw new TypeError("outbox circuit does not match");
      }
      const now = normalizeDate(options.now ?? new Date());
      const selected = entries.slice(0, options.limit);
      for (const entry of selected) {
        entry.status = "pending";
        entry.availableAt = now;
        entry.updatedAt = now;
        delete entry.circuitId;
        await this.#updateEntry(session, entry);
      }
      return selected.length;
    });
  }

  /** Inserts or returns an idempotent row within the active SQL transaction. */
  async #enqueue(session: SqlOutboxSession, input: OutboxEnqueueInput): Promise<OutboxStoredEntry> {
    const entry = createPendingEntry(input);
    const canonical = canonicalPayload(entry.payload);
    const existing = firstRow(await session.execute(this.#selectByIdSql(false), [entry.id]));
    if (existing) {
      if (readString(existing, "payload_canonical") !== canonical) throw new TypeError("outbox idempotency conflict");
      const current = entryFromSqlRow(existing);
      if (!sameEnqueueInput(current, entry)) throw new TypeError("outbox idempotency conflict");
      return cloneEntry(current);
    }
    await session.execute(this.#insertSql(), [
      entry.id,
      entry.tenantId,
      canonical,
      JSON.stringify(entry),
      entry.status,
      entry.attempts,
      entry.availableAt,
      entry.createdAt,
      entry.updatedAt,
      null,
      null,
    ]);
    return cloneEntry(entry);
  }

  /** Locks and loads one row so a stale worker cannot race lease settlement. */
  async #loadEntryForUpdate(session: SqlOutboxSession, id: string): Promise<OutboxStoredEntry> {
    const row = firstRow(await session.execute(this.#selectByIdSql(true), [id]));
    if (!row) throw new TypeError("outbox entry not found");
    return entryFromSqlRow(row);
  }

  /** Updates indexed lifecycle fields and the complete validated envelope. */
  async #updateEntry(session: SqlOutboxSession, entry: OutboxStoredEntry): Promise<void> {
    await session.execute(this.#updateSql(), [
      JSON.stringify(entry),
      entry.status,
      entry.attempts,
      entry.availableAt,
      entry.updatedAt,
      entry.dispatchedAt ?? null,
      entry.lastError ?? null,
      entry.id,
    ]);
  }

  /** Selects one row with its canonical payload for integrity validation. */
  #selectByIdSql(forUpdate: boolean): string {
    return `SELECT payload_canonical, entry_json FROM ${this.#table} WHERE id = ${this.#placeholder(1)} LIMIT 1${forUpdate ? " FOR UPDATE" : ""}`;
  }

  /** Selects tenant rows in stable order. */
  #selectEntriesSql(tenantScoped: boolean, limitValue: number | undefined): string {
    const where = tenantScoped ? ` WHERE tenant_id = ${this.#placeholder(1)}` : "";
    const limitIndex = tenantScoped ? 2 : 1;
    const limit =
      limitValue === undefined
        ? ""
        : ` LIMIT ${this.#dialect === "mysql" ? limitValue : this.#placeholder(limitIndex)}`;
    return `SELECT payload_canonical, entry_json FROM ${this.#table}${where} ORDER BY created_at ASC, id ASC${limit}`;
  }

  /** Selects due pending rows without scanning unrelated lifecycle payloads. */
  #selectDispatchableSql(tenantScoped: boolean, limitValue: number | undefined): string {
    const tenant = tenantScoped ? ` AND candidate.tenant_id = ${this.#placeholder(6)}` : "";
    const limitIndex = tenantScoped ? 7 : 6;
    const limit =
      limitValue === undefined
        ? ""
        : ` LIMIT ${this.#dialect === "mysql" ? limitValue : this.#placeholder(limitIndex)}`;
    return `SELECT candidate.payload_canonical, candidate.entry_json FROM ${this.#table} AS candidate WHERE candidate.status = ${this.#placeholder(1)} AND candidate.available_at <= ${this.#placeholder(2)} AND NOT EXISTS (SELECT 1 FROM ${this.#table} AS blocker WHERE blocker.tenant_id = candidate.tenant_id AND (blocker.status = ${this.#placeholder(3)} OR (blocker.status = ${this.#placeholder(4)} AND blocker.available_at > ${this.#placeholder(5)})))${tenant} ORDER BY candidate.created_at ASC, candidate.id ASC${limit}`;
  }

  /** Selects pending or expired leased rows under row locks and pause barriers. */
  #selectClaimableSql(limitValue: number): string {
    const tenant = ` AND candidate.tenant_id = ${this.#placeholder(7)}`;
    const limitIndex = 8;
    const limit = this.#dialect === "mysql" ? limitValue : this.#placeholder(limitIndex);
    return `SELECT candidate.payload_canonical, candidate.entry_json FROM ${this.#table} AS candidate WHERE (candidate.status = ${this.#placeholder(1)} OR candidate.status = ${this.#placeholder(2)}) AND candidate.available_at <= ${this.#placeholder(3)} AND NOT EXISTS (SELECT 1 FROM ${this.#table} AS blocker WHERE blocker.tenant_id = candidate.tenant_id AND (blocker.status = ${this.#placeholder(4)} OR (blocker.status = ${this.#placeholder(5)} AND blocker.available_at > ${this.#placeholder(6)})))${tenant} ORDER BY candidate.created_at ASC, candidate.id ASC LIMIT ${limit} FOR UPDATE SKIP LOCKED`;
  }

  /** Locks one stable tenant row so only one claim can establish an active lease. */
  #lockTenantSql(): string {
    return `SELECT id FROM ${this.#table} WHERE tenant_id = ${this.#placeholder(1)} ORDER BY id ASC LIMIT 1 FOR UPDATE`;
  }

  /** Locks only held rows for compare-and-set operator acknowledgement. */
  #selectPausedForUpdateSql(): string {
    return `SELECT payload_canonical, entry_json FROM ${this.#table} WHERE tenant_id = ${this.#placeholder(1)} AND status = ${this.#placeholder(2)} ORDER BY created_at ASC, id ASC FOR UPDATE`;
  }

  /** Builds the insert statement for one serialized entry. */
  #insertSql(): string {
    return `INSERT INTO ${this.#table} (id, tenant_id, payload_canonical, entry_json, status, attempts, available_at, created_at, updated_at, dispatched_at, last_error) VALUES (${Array.from({ length: 11 }, (_, index) => this.#placeholder(index + 1)).join(", ")})`;
  }

  /** Builds the settlement update statement. */
  #updateSql(): string {
    return `UPDATE ${this.#table} SET entry_json = ${this.#placeholder(1)}, status = ${this.#placeholder(2)}, attempts = ${this.#placeholder(3)}, available_at = ${this.#placeholder(4)}, updated_at = ${this.#placeholder(5)}, dispatched_at = ${this.#placeholder(6)}, last_error = ${this.#placeholder(7)} WHERE id = ${this.#placeholder(8)}`;
  }

  /** Returns the active dialect placeholder. */
  #placeholder(index: number): string {
    return this.#dialect === "postgres" ? `$${index}` : "?";
  }

  /** Builds list parameters without nullable placeholders that real drivers cannot type safely. */
  #selectEntriesParams(tenantId: string | undefined, limit?: number): readonly unknown[] {
    const params: unknown[] = tenantId === undefined ? [] : [tenantId];
    if (limit !== undefined && this.#dialect === "postgres") params.push(limit);
    return params;
  }

  /** Builds due-row diagnostic parameters with an indexed pause exclusion. */
  #dispatchableParams(now: string, options: OutboxListOptions): readonly unknown[] {
    const params: unknown[] = ["pending", now, "paused", "leased", now];
    if (options.tenantId !== undefined) params.push(options.tenantId);
    if (options.limit !== undefined && this.#dialect === "postgres") params.push(options.limit);
    return params;
  }

  /** Builds pending/expired-lease claim parameters. */
  #claimableParams(now: string, options: OutboxClaimOptions): readonly unknown[] {
    const params: unknown[] = ["pending", "leased", now, "paused", "leased", now, options.tenantId];
    if (this.#dialect === "postgres") params.push(options.limit);
    return params;
  }
}
