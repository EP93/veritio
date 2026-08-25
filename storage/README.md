# `@veritio/storage`

Part of [Veritio](https://getveritio.com), the open-source evidence layer — see the [docs](https://getveritio.com/docs/) and [Veritio Cloud](https://getveritio.com/cloud/).

Host-injected storage helpers for Veritio audit trail evidence.

The package provides durable `AuditStore` factories for transaction-capable SQL
and MongoDB boundaries, transactional evidence outbox helpers, plus a Redis
tenant-tip cache helper. It does not read environment variables, open database
connections, or bundle vendor clients.

## Durable Stores

- `createPostgresAuditStore`: PostgreSQL-compatible stores.
- `createNeonAuditStore`: Neon-backed PostgreSQL-compatible stores.
- `createMysqlAuditStore`: MySQL-compatible stores.
- `createMariaDbAuditStore`: MariaDB-compatible stores.
- `createMongoAuditStore`: MongoDB stores with host-provided transaction
  boundaries.

Host applications must provide a transaction-capable client wrapper. The store
uses tenant-scoped append ordering, idempotency-key hashes, expected previous
hash checks, and persisted record integrity validation.

## Audit Retention Checkpoints

Retention checkpointing is an **audit-chain-only** capability in v1. The
Postgres/Neon, MySQL/MariaDB, and Mongo factories return a
`CheckpointingAuditStore`; it preserves the authoritative tenant tip separately
from hot rows, atomically records a checkpoint and crops its exact covered
prefix, and preserves the minimum idempotency ledger needed to reject a
post-crop duplicate. `MemoryAuditStore` in `@veritio/core` implements the same
contract for tests, not as production durability.

`AuditChainState` is relational, not merely a set of typed columns. The tip
sequence is zero exactly when its hash is null; a positive tip requires a valid
hash. `minimumRetainedSequence` is in `1..authoritativeTipSequence + 1` and is
one exactly when `latestCheckpointHash` is null; a later minimum requires a
valid latest-checkpoint hash. `@veritio/core`'s `assertAuditChainState`
validates host expected state, and every capable adapter applies the same
validator to persisted state before append or crop mutation.

Before activating retention on an existing authoritative database, apply the
additive schema constant (`POSTGRES_AUDIT_RECORDS_SCHEMA_SQL` or
`MYSQL_AUDIT_RECORDS_SCHEMA_SQL`) before any checkpoint/crop call. Its SQL
backfill selects the highest legacy sequence/hash for each tenant; it does not
replay or validate the historical chain. Before treating that seeded state as
authoritative, the host must integrity-replay every legacy tenant with
`verifyAuditRecords` and investigate any failure. Then run retention
conformance against a real database before scheduling a worker.

For Mongo, provision the collections passed through `retention`, create
`MONGO_RETENTION_INDEXES` as well as `MONGO_AUDIT_RECORD_INDEXES`, and use a
replica-set transaction boundary. Run `backfillMongoAuditRetentionState` for
each legacy tenant: it verifies the complete hot chain and atomically writes
that tenant's chain state and minimal idempotency ledger. Do not enable crops
until every tenant backfill and real-DB conformance have succeeded.

```ts
import {
  MONGO_AUDIT_RECORD_INDEXES,
  MONGO_RETENTION_INDEXES,
  POSTGRES_AUDIT_RECORDS_SCHEMA_SQL,
  backfillMongoAuditRetentionState,
  createPostgresAuditStore,
} from "@veritio/storage";
import { createRetentionStoreConformanceTests } from "@veritio/storage/conformance";

// Each returned conformance case must receive an empty, isolated real database
// target. `host.createIsolatedPostgresTarget` is application test-harness code.
for (const conformanceTest of createRetentionStoreConformanceTests({
  name: "postgres retention",
  createTarget: async () => {
    const target = await host.createIsolatedPostgresTarget();
    await target.executor.execute(POSTGRES_AUDIT_RECORDS_SCHEMA_SQL, []);
    return {
      store: createPostgresAuditStore({ client: target.executor }),
      close: () => target.close(),
    };
  },
})) {
  test(conformanceTest.name, conformanceTest.run);
}

await host.createIndexes(MONGO_AUDIT_RECORD_INDEXES);
await host.createRetentionIndexes(MONGO_RETENTION_INDEXES);
for (const tenantId of legacyTenantIds) {
  await backfillMongoAuditRetentionState(mongoOptions, { tenantId });
}
```

Only audit records are capable in v1. Evidence-edge chains and
`EvidenceCommit` remain genesis/full-chain records; `FileEvidenceStore`, the
ClickHouse read model, and `ObjectAuditArchive` do not implement
`CheckpointingAuditStore`. A future file adapter needs a crash-safe
journal/snapshot transaction before it can be capable.

### Derived staging and disposal

`createRetentionStagingArchive` is a separate, short-lived derived safety copy
for one explicit epoch. It intentionally does not widen `ObjectAuditArchive`.
`runRetentionEpoch` executes `seal → verify → compact → prepare → delete →
confirm absence → resolve disposal time → confirm receipt`: it requires a
host-injected durable per-tenant epoch lease, a trusted asynchronous
`resolveDisposedAt(context)` callback, and two
host-injected policy-fence callbacks. The first fence guards the crop; the
second remains held through provider deletion, direct-read plus prefix-list
absence confirmation, and receipt confirmation. The helpers read no
environment, credentials, clock, or legal-hold state; hosts supply those
boundaries and must re-evaluate eligibility/version on every retry.

`resolveDisposedAt` runs after deletion and both absence checks succeed,
immediately before each receipt-creation attempt. Its only context fields are
`tenantId`, a detached checkpoint clone, `attemptId`, `dispositionId`, and
`policyFence`. Receipt persistence can fail after resolution, so a retry may
invoke the callback again with the same exact context. The host must durably
return the same exact UTC-millisecond instant for that context; otherwise one
provider disposal could produce conflicting receipts. Rejection or malformed
output fails closed without persisting a receipt. Delete and absence failures
never invoke it. A cold replay with an already accepted disposition verifies
and returns the stored receipt byte-for-byte without invoking the callback.

Hosts can gate the installed public package identities and retention behavior
without reading package files or environment variables:

```ts
import { VERITIO_CORE_VERSION } from "@veritio/core/version";
import {
  RETENTION_COORDINATOR_CAPABILITY,
  type RetentionDisposedAtResolver,
} from "@veritio/storage/retention";
import { VERITIO_STORAGE_VERSION } from "@veritio/storage/version";

if (
  VERITIO_CORE_VERSION !== "0.4.8" ||
  VERITIO_STORAGE_VERSION !== "0.4.8" ||
  !RETENTION_COORDINATOR_CAPABILITY.resolvesDisposedAtAfterConfirmedAbsence ||
  !RETENTION_COORDINATOR_CAPABILITY.requiresAttemptIdempotentDisposedAtResolver ||
  !RETENTION_COORDINATOR_CAPABILITY.mayReinvokeDisposedAtAfterReceiptPersistenceFailure ||
  !RETENTION_COORDINATOR_CAPABILITY.replaysAcceptedDispositionWithoutResolvingDisposedAt
) {
  throw new Error("unsupported Veritio retention coordinator");
}

const resolveDisposedAt: RetentionDisposedAtResolver = async (
  { tenantId, checkpoint, attemptId, dispositionId, policyFence },
) => durableDispositionTimes.resolveOrCreate(
  { tenantId, checkpointHash: checkpoint.hash, attemptId, dispositionId, policyFence },
  () => trustedHostClock.nowUtcMilliseconds(),
);
```

Cold retries inspect authoritative checkpoints and accepted dispositions before
deriving anything from audit records. When a stored checkpoint has no receipt,
the coordinator loads the deterministic epoch manifest and validates its full
checkpoint binding before deleting its exact keys. If deletion already removed
the manifest, confirmation requires both a direct manifest GET miss and an
empty LIST of the complete deterministic epoch prefix; a missing manifest alone
is insufficient. A retry with neither a stored checkpoint nor record bodies
fails closed. `RunRetentionEpochResult.manifest` is `null` only when recovery
confirmed a manifestless post-delete epoch from that checkpoint prefix.

R2/S3 (and MinIO-compatible clients) are never authoritative: they cannot own
sequences, idempotency, verification, DSAR answers, or a restore path. A
checkpoint and its disposition receipt attest to a verified anchor and a
provider-delete attempt. They do **not** prove that every provider replica or
backup has been erased, and, after disposal, Veritio has no epoch event bodies
available for replay. The receipt is deliberately minimal: it omits event
bodies/metadata, legal-hold rationale, user identity, bucket keys, and raw
provider responses; hosts keep operational evidence in their own
access-controlled audit systems.

## Transactional Outbox

The storage package exports the public outbox contract used by governed-change
drafts:

- `OutboxAdapter`
- `createOutboxDispatcher`
- `dispatchOutboxEntry`
- `createPostgresOutboxAdapter`
- `createNeonOutboxAdapter`
- `createMysqlOutboxAdapter`
- `createMariaDbOutboxAdapter`
- `createFileOutboxAdapter`

SQL outbox adapters use the same host-injected transaction pattern as the SQL
`AuditStore` factories. A host should enqueue the minimized governed-change
payload inside the same database transaction as the application mutation when it
wants to claim `mutationBinding: "same_transaction"`.

```ts
await database.transaction(async (tx) => {
  const veritioOutbox = createPostgresOutboxAdapter({
    client: tx.veritioOutboxExecutor,
  });
  const before = await entries.get(tx, id);
  const after = await entries.update(tx, id, patch);
  const draft = createGovernedChangeDraft({
    scope,
    entity: projectEntryEntity,
    before,
    after,
    changedPaths: ["/amount"],
    change,
    activity,
    producer,
    occurredAt: new Date(),
    idempotencyKeyHash,
    mutationBinding: "same_transaction",
  });

  await veritioOutbox.transaction((outboxTx) => outboxTx.enqueue({
    id: idempotencyKeyHash,
    tenantId: scope.tenantId,
    payload: draft.outboxEntry,
  }));
});
```

The exact adapter wiring depends on the host database wrapper. The important
invariant is that `tx.veritioOutboxExecutor.transaction(...)` participates in
the already-active host transaction instead of opening an unrelated commit.

Dispatch is retry-safe. If a worker crashes after appending some events, the
next run replays the same event and edge IDs and the evidence sink rejects
duplicates or conflicts deterministically.

```ts
await createOutboxDispatcher({
  adapter: veritioOutbox,
  target: createFileEvidenceStore("./.veritio/evidence"),
}).dispatchBatch({ tenantId: scope.tenantId });
```

`createFileOutboxAdapter` is useful for local examples and self-hosted file
workflows. It persists outbox rows atomically within its own file lock, but it
does not prove a separate application database mutation committed in the same
transaction. Use `mutationBinding: "not_transaction_bound"` or `"best_effort"`
unless the host can prove the business mutation shares the same transaction
boundary.

## Redis

`createRedisAuditTipCache` stores and reads validated tenant chain tips. It is
not an `AuditStore` and does not claim durable audit evidence on its own. Use it
alongside a durable store when a cache is useful.

## Object-Storage Archive (Cloudflare R2 / AWS S3)

`createObjectAuditArchive` is a derived cold tier for a tenant's evidence
chains on any S3-compatible object store (Cloudflare R2, AWS S3, MinIO). It is
NOT an `AuditStore` and must never own appends: object storage cannot couple
gapless per-tenant sequencing to idempotency-conflict checks atomically, so
sequencing stays in a conforming authoritative store and the archive seals
already-sequenced records into immutable segments. Events and edges are the
protocol's two independently sequenced chains, so they archive under separate
key namespaces (`sealSegment`/`sealEdgeSegment`) and `verifyTenant` replays
both, mirroring `FileEvidenceStore.verify`.

Segments store the exact `canonicalJson` bytes of each record as NDJSON lines,
so hashes recompute byte-for-byte and a full tenant chain verifies from the
archive alone. Sealing fails closed on gaps, overlaps, tampered records, and
mixed tenants; an identical replay of an already-sealed range is idempotent.
`archiveAuditStoreTenant` drains a tenant's un-archived event tail from any
`AuditStore` incrementally, resuming from the archive's own tip (edge batches
are sealed directly — `AuditStore` does not expose edge records).

The host injects an `ObjectArchiveClient` (`put`/`get`/`list` over bytes) built
on its own S3 client — an R2 bucket binding, the AWS SDK, or Bun's built-in
`S3Client` — and owns credentials, bucket provisioning, and retention/WORM
policy. Serialize archiving per tenant; the archive assumes one sealer per
tenant chain.

## ClickHouse Read Model

`createClickHouseAuditReadModel` is a derived, eventually consistent analytical
read model for scan-heavy groupings: activity-episode rollups, session
reconstruction, and subject scans. It is NOT an `AuditStore` and must never be
authoritative — ClickHouse has no synchronous unique constraints or
transactional tip checks, so verify/export and idempotency stay on the
authoritative store.

Projection is at-least-once: duplicates collapse via `ReplacingMergeTree`, and
the read helpers query with `FINAL` so replays never double-count. The full
canonical record travels as a raw `String` column (never ClickHouse's native
JSON type), every projected and returned record is hash-revalidated, and all
value filters bind through ClickHouse query parameters. The host injects a
`ClickHouseExecutor` over the HTTP interface (see
`integration/clickhouse-read-model.test.ts` for a fetch-based reference) and
owns endpoint, credentials, and database selection.

## AuditStore Conformance Suite

`@veritio/storage/conformance` exports `createAuditStoreConformanceTests` for
adapter tests. Use it for in-memory fakes and for live database integration
checks so all durable stores prove the same behavior: tenant-scoped ordering,
idempotency conflicts, expected previous-hash checks, cloned returned records,
and fail-closed integrity validation.

```ts
import { describe, test } from "bun:test";
import { createPostgresAuditStore } from "@veritio/storage";
import { createAuditStoreConformanceTests } from "@veritio/storage/conformance";

describe("postgres live AuditStore conformance", () => {
  for (const conformanceTest of createAuditStoreConformanceTests({
    name: "postgres live",
    async createTarget() {
      const host = await createHostInjectedPostgresHarness();
      await host.resetAuditTable();

      return {
        store: createPostgresAuditStore({ client: host.executor }),
        async mutateStoredRecord({ tenantId, sequence, mutate }) {
          const record = await host.readRecordJson(tenantId, sequence);
          await host.writeRecordJson(tenantId, sequence, mutate(record) ?? record);
        },
        close: () => host.close(),
      };
    },
  })) {
    test(conformanceTest.name, conformanceTest.run);
  }
});
```

The host harness owns database clients, credentials, connection strings, test
containers, and cleanup. Keep environment-variable reads in the test bootstrap
or CI setup, not in `storage/src`.

`createRetentionStoreConformanceTests` adds crop-boundary, retained-tip,
idempotency-tombstone, policy-fence, and unique-disposition coverage for every
authoritative `CheckpointingAuditStore`. Run it against the actual database;
unit-only success cannot validate transactional retention semantics.

## External DB Checks

External database checks run through the same package test command when matching
connection strings are present. Without these environment variables, the live
database suites are skipped and the in-memory conformance tests still run.

```sh
VERITIO_POSTGRES_TEST_URL=postgresql://... \
VERITIO_MYSQL_TEST_URL=mysql://... \
VERITIO_MONGODB_TEST_URL=mongodb://... \
bun run --cwd storage test
```

Supported live-test variables:

- `VERITIO_POSTGRES_TEST_URL`
- `VERITIO_NEON_TEST_URL`
- `VERITIO_MYSQL_TEST_URL`
- `VERITIO_MARIADB_TEST_URL`
- `VERITIO_MONGODB_TEST_URL`

The GitHub Actions verification job runs Postgres, MySQL, MariaDB, and MongoDB
service containers and sets these variables for `bun run verify`. The
`VERITIO_NEON_TEST_URL` job value points at the same Postgres-compatible service
so the Neon factory stays covered without requiring a hosted Neon account.
Projects that need hosted Neon proof can set `VERITIO_NEON_TEST_URL` to a
disposable branch connection string in their own CI.

Derived-tier integration suites gate on their own variables the same way:

- `VERITIO_S3_TEST_ENDPOINT` (+ `VERITIO_S3_TEST_ACCESS_KEY_ID`,
  `VERITIO_S3_TEST_SECRET_ACCESS_KEY`, `VERITIO_S3_TEST_BUCKET`) for the
  object archive against any S3-compatible endpoint.
- `VERITIO_CLICKHOUSE_TEST_ENDPOINT` (+ `VERITIO_CLICKHOUSE_TEST_USER`,
  `VERITIO_CLICKHOUSE_TEST_PASSWORD`, `VERITIO_CLICKHOUSE_TEST_DATABASE`) for
  the ClickHouse read model.

For local runs, `storage/docker-compose.yml` provides disposable targets for
every suite (Postgres, MySQL, MariaDB, MongoDB as a single-node replica set,
MinIO with a pre-provisioned bucket, and ClickHouse) on ports that avoid
common local services:

```sh
bun run --cwd storage db:up     # start containers and wait for health
bun run --cwd storage test:live # run every suite against them
bun run --cwd storage db:down   # discard containers and data
```

To point at databases you manage yourself instead:

1. Start a disposable Postgres, Neon branch, MySQL, MariaDB, or MongoDB test
   database outside this package.
2. For SQL stores, use the schema helpers or example schemas. For MongoDB,
   create indexes from `MONGO_AUDIT_RECORD_INDEXES`.
3. Run `bun run --cwd storage test` with the matching environment variables.

Redis is not a durable `AuditStore` target and should not run this conformance
suite. Test Redis only as a validated tenant-tip cache beside a durable store.

## SQL Schema Helpers

`POSTGRES_AUDIT_RECORDS_SCHEMA_SQL` and `MYSQL_AUDIT_RECORDS_SCHEMA_SQL`
provide starting table definitions. Review them for your database policy,
backup, retention, and migration requirements before applying them.

`POSTGRES_OUTBOX_SCHEMA_SQL` and `MYSQL_OUTBOX_SCHEMA_SQL` provide starting
table definitions for transactional outbox rows. Apply them in the same database
where the host mutation transaction runs when using the SQL outbox adapters.

Veritio supports evidence collection and verification workflows. It is not legal
advice and does not make an application automatically compliant with any
regulation or framework.
