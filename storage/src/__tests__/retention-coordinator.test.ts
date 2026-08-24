import { describe, expect, test } from "bun:test";
import {
  type CheckpointingAuditStore,
  canonicalJson,
  createAuditEvent,
  createRetentionCheckpoint,
  createRetentionDisposition,
  MemoryAuditStore,
  type RetentionCheckpointInput,
  type RetentionDisposition,
  type RetentionDispositionInput,
} from "@veritio/core";
import { type RetentionPolicyFenceRunner, runRetentionEpoch } from "../retention-coordinator";
import { createRetentionStagingArchive, type RetentionStagingClient } from "../retention-staging-archive";

const TENANT_ID = "org_coordinator";

/** Appends deterministic tenant events to a real retention-capable memory store. */
async function seedStore(count = 3): Promise<MemoryAuditStore> {
  const store = new MemoryAuditStore();
  for (let index = 1; index <= count; index += 1) {
    await store.append(
      createAuditEvent({
        id: `evt_${index}`,
        occurredAt: "2026-08-24T01:00:00.000Z",
        actor: { type: "system", id: "coordinator-test" },
        action: "retention.tested",
        target: { type: "organization", id: TENANT_ID },
        scope: { tenantId: TENANT_ID, environment: "test" },
        metadata: { index },
      }),
    );
  }
  return store;
}

/** Provides idempotent in-memory deletion and an operation log for ordering assertions. */
function createClient(log: string[]): RetentionStagingClient & {
  objects: Map<string, Uint8Array>;
  failNextDelete: boolean;
} {
  const objects = new Map<string, Uint8Array>();
  return {
    objects,
    failNextDelete: false,
    async put(key, body) {
      log.push("archive.put");
      objects.set(key, body.slice());
    },
    async get(key) {
      log.push("archive.get");
      const body = objects.get(key);
      return body ? body.slice() : null;
    },
    async list(prefix) {
      log.push("archive.list");
      return [...objects.keys()].filter((key) => key.startsWith(prefix)).sort();
    },
    async delete(key) {
      log.push("archive.delete");
      if (this.failNextDelete) {
        this.failNextDelete = false;
        throw new Error("crash during delete");
      }
      objects.delete(key);
    },
  };
}

/** Delegates to a real store while logging only destructive coordinator boundaries. */
function loggedStore(
  store: CheckpointingAuditStore,
  log: string[],
  isFenceHeld: () => boolean,
): CheckpointingAuditStore {
  return {
    append: store.append.bind(store),
    list: store.list.bind(store),
    getChainState: store.getChainState.bind(store),
    advanceRetentionPolicyFence: store.advanceRetentionPolicyFence.bind(store),
    listCheckpoints: store.listCheckpoints.bind(store),
    listDispositions: store.listDispositions.bind(store),
    async compactRange(...args) {
      expect(isFenceHeld()).toBe(true);
      log.push("store.compact");
      return store.compactRange(...args);
    },
    async prepareDisposition(...args) {
      expect(isFenceHeld()).toBe(true);
      log.push("store.prepare");
      return store.prepareDisposition(...args);
    },
    async confirmDisposition(...args) {
      expect(isFenceHeld()).toBe(true);
      log.push("store.confirm");
      return store.confirmDisposition(...args);
    },
  };
}

/** Builds exact caller-owned IDs, policy, trusted clock, and signing factories for one run. */
async function runOptions(
  store: CheckpointingAuditStore,
  client: RetentionStagingClient,
  overrides: Record<string, unknown> = {},
) {
  const state = await store.getChainState({ tenantId: TENANT_ID });
  const records = await store.list({ tenantId: TENANT_ID });
  return {
    store,
    archive: createRetentionStagingArchive({ client, prefix: "coordinator-staging" }),
    tenantId: TENANT_ID,
    records,
    previousCheckpoint: null,
    expectedState: state,
    eligibility: { eligible: true as const, policyReference: "policy.v1", version: state.retentionPolicyFence },
    checkpoint: { checkpointId: "rcp_run", createdAt: "2026-08-24T01:01:00.000Z" },
    disposition: {
      attemptId: "attempt_run",
      dispositionId: "rdp_run",
    },
    resolveDisposedAt: async () => "2026-08-24T01:02:00.000Z",
    createCheckpoint: (input: RetentionCheckpointInput) => createRetentionCheckpoint(input),
    createDisposition: (input: RetentionDispositionInput) => createRetentionDisposition(input),
    withEpochLease: async <T>(operation: () => Promise<T>) => operation(),
    withPolicyFence: (async (_version, operation) => operation()) as RetentionPolicyFenceRunner,
    ...overrides,
  };
}

/** Serializes callbacks in FIFO order to model one tenant/chain distributed epoch lease. */
function createEpochLeaseRunner() {
  let tail = Promise.resolve();
  return async <T>(operation: () => Promise<T>): Promise<T> => {
    const previous = tail;
    let release!: () => void;
    tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  };
}

describe("retention coordinator", () => {
  test("orders verified staging, crop, prepared deletion, dual absence, receipt creation, and confirmation", async () => {
    const log: string[] = [];
    let fenceHeld = false;
    const realStore = await seedStore();
    const client = createClient(log);
    const store = loggedStore(realStore, log, () => fenceHeld);
    const withPolicyFence: RetentionPolicyFenceRunner = async (version, operation) => {
      expect(version).toBe(0);
      log.push("fence.enter");
      fenceHeld = true;
      try {
        return await operation();
      } finally {
        fenceHeld = false;
        log.push("fence.exit");
      }
    };
    const options = await runOptions(store, client, {
      withPolicyFence,
      createCheckpoint: (input: RetentionCheckpointInput) => {
        log.push("checkpoint.create");
        return createRetentionCheckpoint(input);
      },
      createDisposition: (input: RetentionDispositionInput) => {
        expect(fenceHeld).toBe(true);
        log.push("disposition.create");
        return createRetentionDisposition(input);
      },
      resolveDisposedAt: async (context: unknown) => {
        expect(fenceHeld).toBe(true);
        log.push("disposedAt.resolve");
        expect(context).toEqual({
          tenantId: TENANT_ID,
          checkpoint: expect.any(Object),
          attemptId: "attempt_run",
          dispositionId: "rdp_run",
          policyFence: 0,
        });
        return "2026-08-24T01:02:00.000Z";
      },
    });

    const result = await runRetentionEpoch(options);

    expect(await realStore.list({ tenantId: TENANT_ID })).toEqual([]);
    expect(await realStore.listCheckpoints({ tenantId: TENANT_ID })).toEqual([result.checkpoint]);
    expect(await realStore.listDispositions({ tenantId: TENANT_ID })).toEqual([result.disposition]);
    if (!result.manifest) throw new Error("initial retention run must return its staged manifest");
    expect(result.checkpoint.archiveRootHash).toBe(result.manifest.archiveRootHash);
    expect(result.disposition.archiveRootHash).toBe(result.manifest.archiveRootHash);
    expect(await options.archive.confirmEpochAbsent(result.manifest)).toBe(true);

    const firstFence = log.indexOf("fence.enter");
    const compact = log.indexOf("store.compact");
    const secondFence = log.indexOf("fence.enter", firstFence + 1);
    const prepare = log.indexOf("store.prepare");
    const firstDelete = log.indexOf("archive.delete");
    const receipt = log.indexOf("disposition.create");
    const resolveDisposedAt = log.indexOf("disposedAt.resolve");
    const lastGet = log.slice(0, receipt).lastIndexOf("archive.get");
    const lastList = log.slice(0, receipt).lastIndexOf("archive.list");
    const confirm = log.indexOf("store.confirm");
    expect(log.lastIndexOf("archive.get", firstFence)).toBeGreaterThanOrEqual(0);
    expect(firstFence).toBeLessThan(compact);
    expect(compact).toBeLessThan(secondFence);
    expect(secondFence).toBeLessThan(prepare);
    expect(prepare).toBeLessThan(firstDelete);
    expect(firstDelete).toBeLessThan(lastGet);
    expect(firstDelete).toBeLessThan(lastList);
    expect(lastGet).toBeLessThan(receipt);
    expect(lastList).toBeLessThan(receipt);
    expect(lastGet).toBeLessThan(resolveDisposedAt);
    expect(lastList).toBeLessThan(resolveDisposedAt);
    expect(resolveDisposedAt).toBeLessThan(receipt);
    expect(receipt).toBeLessThan(confirm);
  });

  test("resolves the confirmed disposal time exactly once with a detached privacy-minimal context", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    let calls = 0;
    let callbackCheckpointId = "";
    const options = await runOptions(store, client, {
      resolveDisposedAt: async (context: {
        tenantId: string;
        checkpoint: RetentionCheckpointInput;
        attemptId: string;
        dispositionId: string;
        policyFence: number;
      }) => {
        calls += 1;
        expect(Object.keys(context).sort()).toEqual([
          "attemptId",
          "checkpoint",
          "dispositionId",
          "policyFence",
          "tenantId",
        ]);
        expect(context.tenantId).toBe(TENANT_ID);
        expect(context.attemptId).toBe("attempt_run");
        expect(context.dispositionId).toBe("rdp_run");
        expect(context.policyFence).toBe(0);
        callbackCheckpointId = context.checkpoint.checkpointId;
        context.checkpoint.checkpointId = "callback-mutation";
        return "2026-08-24T01:02:00.000Z";
      },
    });

    const result = await runRetentionEpoch(options);

    expect(calls).toBe(1);
    expect(callbackCheckpointId).toBe("rcp_run");
    expect(result.checkpoint.checkpointId).toBe("rcp_run");
    expect(result.disposition.disposedAt).toBe("2026-08-24T01:02:00.000Z");
  });

  test("does not resolve disposal time when deletion or absence confirmation fails", async () => {
    const deleteLog: string[] = [];
    const deleteStore = await seedStore();
    const deleteClient = createClient(deleteLog);
    deleteClient.failNextDelete = true;
    let deleteResolverCalls = 0;
    const deleteOptions = await runOptions(deleteStore, deleteClient, {
      resolveDisposedAt: async () => {
        deleteResolverCalls += 1;
        return "2026-08-24T01:02:00.000Z";
      },
    });
    await expect(runRetentionEpoch(deleteOptions)).rejects.toThrow("crash during delete");
    expect(deleteResolverCalls).toBe(0);

    const absenceLog: string[] = [];
    const absenceStore = await seedStore();
    const absenceClient = createClient(absenceLog);
    let absenceResolverCalls = 0;
    const absenceOptions = await runOptions(absenceStore, absenceClient, {
      resolveDisposedAt: async () => {
        absenceResolverCalls += 1;
        return "2026-08-24T01:02:00.000Z";
      },
    });
    absenceOptions.archive = {
      ...absenceOptions.archive,
      async confirmEpochAbsent() {
        return false;
      },
    };
    await expect(runRetentionEpoch(absenceOptions)).rejects.toThrow("staged retention epoch deletion is unconfirmed");
    expect(absenceResolverCalls).toBe(0);
  });

  test("fails closed when disposal-time resolution rejects or returns a non-exact UTC-millisecond instant", async () => {
    const failingStore = await seedStore();
    const failingClient = createClient([]);
    const failingOptions = await runOptions(failingStore, failingClient, {
      resolveDisposedAt: async () => {
        throw new Error("trusted clock unavailable");
      },
    });
    await expect(runRetentionEpoch(failingOptions)).rejects.toThrow("trusted clock unavailable");
    expect(await failingStore.listDispositions({ tenantId: TENANT_ID })).toEqual([]);

    for (const invalid of ["2026-08-24T01:02:00Z", "2026-02-30T01:02:00.000Z", "not-a-time", 42]) {
      const store = await seedStore();
      const client = createClient([]);
      const options = await runOptions(store, client, {
        resolveDisposedAt: async () => invalid,
      });
      await expect(runRetentionEpoch(options)).rejects.toThrow("disposedAt must be exact UTC milliseconds");
      expect(await store.listDispositions({ tenantId: TENANT_ID })).toEqual([]);
    }
  });

  test("rejects mismatched prepared attempts and disposition factory bindings", async () => {
    const attemptStore = await seedStore();
    const attemptClient = createClient([]);
    const baseAttemptOptions = await runOptions(attemptStore, attemptClient);
    const mismatchedAttemptStore: CheckpointingAuditStore = {
      ...attemptStore,
      append: attemptStore.append.bind(attemptStore),
      list: attemptStore.list.bind(attemptStore),
      getChainState: attemptStore.getChainState.bind(attemptStore),
      advanceRetentionPolicyFence: attemptStore.advanceRetentionPolicyFence.bind(attemptStore),
      compactRange: attemptStore.compactRange.bind(attemptStore),
      listCheckpoints: attemptStore.listCheckpoints.bind(attemptStore),
      listDispositions: attemptStore.listDispositions.bind(attemptStore),
      confirmDisposition: attemptStore.confirmDisposition.bind(attemptStore),
      async prepareDisposition(...args) {
        const attempt = await attemptStore.prepareDisposition(...args);
        return { ...attempt, attemptId: "attempt_wrong" };
      },
    };
    await expect(runRetentionEpoch({ ...baseAttemptOptions, store: mismatchedAttemptStore })).rejects.toThrow(
      "prepared disposition attempt binding mismatch",
    );

    const mutations: Array<(input: RetentionDispositionInput) => RetentionDispositionInput> = [
      (input) => ({ ...input, dispositionId: "rdp_wrong" }),
      (input) => ({ ...input, policyReference: "policy.wrong" }),
      (input) => ({ ...input, fromSequence: input.fromSequence + 1 }),
      (input) => ({ ...input, checkpointHash: "f".repeat(64) }),
    ];
    for (const mutate of mutations) {
      const store = await seedStore();
      const client = createClient([]);
      const options = await runOptions(store, client, {
        createDisposition: (input: RetentionDispositionInput) => createRetentionDisposition(mutate(input)),
      });
      await expect(runRetentionEpoch(options)).rejects.toThrow();
      expect(await store.listDispositions({ tenantId: TENANT_ID })).toEqual([]);
    }
  });

  test("does not enter the crop fence when archive verification fails", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    let fenceCalls = 0;
    const options = await runOptions(store, client, {
      withPolicyFence: (async (_version, _operation) => {
        fenceCalls += 1;
        throw new Error("must not enter fence");
      }) as RetentionPolicyFenceRunner,
    });
    const archive = options.archive;
    const originalVerify = archive.verifyEpoch.bind(archive);
    options.archive = {
      ...archive,
      async verifyEpoch(manifest) {
        client.objects.set(manifest.segments[0]!.objectKey, new TextEncoder().encode("corrupt"));
        return originalVerify(manifest);
      },
    };

    await expect(runRetentionEpoch(options)).rejects.toThrow("staged retention epoch verification failed");
    expect(fenceCalls).toBe(0);
    expect(await store.list({ tenantId: TENANT_ID })).toHaveLength(3);
    expect(await store.listCheckpoints({ tenantId: TENANT_ID })).toEqual([]);
  });

  test("a policy change between fences crops only after verification but performs no deletion or receipt", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    let calls = 0;
    const options = await runOptions(store, client, {
      withPolicyFence: (async (version, operation) => {
        calls += 1;
        if (calls === 1) {
          const result = await operation();
          await store.advanceRetentionPolicyFence({ tenantId: TENANT_ID }, version);
          return result;
        }
        throw new TypeError("eligibility version changed");
      }) as RetentionPolicyFenceRunner,
    });

    await expect(runRetentionEpoch(options)).rejects.toThrow("eligibility version changed");
    expect(await store.list({ tenantId: TENANT_ID })).toEqual([]);
    expect(await store.listCheckpoints({ tenantId: TENANT_ID })).toHaveLength(1);
    expect(await store.listDispositions({ tenantId: TENANT_ID })).toEqual([]);
    expect(log).not.toContain("archive.delete");
  });

  test("retries a crash after compaction without recropping and reuses the byte-identical staged epoch", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    let fenceCalls = 0;
    const first = await runOptions(store, client, {
      withPolicyFence: (async (_version, operation) => {
        fenceCalls += 1;
        if (fenceCalls === 2) throw new Error("crash before disposal fence");
        return operation();
      }) as RetentionPolicyFenceRunner,
    });
    await expect(runRetentionEpoch(first)).rejects.toThrow("crash before disposal fence");
    const storedCheckpoint = (await store.listCheckpoints({ tenantId: TENANT_ID }))[0]!;

    const retry = await runOptions(store, client, {
      records: first.records,
      previousCheckpoint: null,
      expectedState: first.expectedState,
      eligibility: first.eligibility,
    });
    const result = await runRetentionEpoch(retry);

    expect(result.checkpoint).toEqual(storedCheckpoint);
    expect(log.filter((item) => item === "archive.put")).toHaveLength(2);
    expect(await store.listDispositions({ tenantId: TENANT_ID })).toEqual([result.disposition]);
  });

  test("a genuine cold invocation finishes disposal after crop with zero audit record bodies", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    let fenceCalls = 0;
    const first = await runOptions(store, client, {
      withPolicyFence: (async (_version, operation) => {
        fenceCalls += 1;
        if (fenceCalls === 2) throw new Error("crash before cold disposal");
        return operation();
      }) as RetentionPolicyFenceRunner,
    });
    await expect(runRetentionEpoch(first)).rejects.toThrow("crash before cold disposal");
    expect(await store.list({ tenantId: TENANT_ID })).toEqual([]);
    expect(client.objects.size).toBeGreaterThan(0);
    log.length = 0;

    const cold = await runOptions(store, client, { records: [] });
    const result = await runRetentionEpoch(cold);

    expect(result.manifest).not.toBeNull();
    expect(log).not.toContain("archive.put");
    expect(client.objects.size).toBe(0);
    expect(await store.listDispositions({ tenantId: TENANT_ID })).toEqual([result.disposition]);
  });

  test("a completed disposition rerun proves absence and returns the accepted receipt without provider writes", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    const options = await runOptions(store, client);
    const first = await runRetentionEpoch(options);
    expect(client.objects.size).toBe(0);
    log.length = 0;

    let replayResolverCalls = 0;
    const replayed = await runRetentionEpoch({
      ...options,
      resolveDisposedAt: async () => {
        replayResolverCalls += 1;
        throw new Error("accepted replay must not resolve time");
      },
    });

    expect(replayed.manifest).toBeNull();
    expect(replayResolverCalls).toBe(0);
    expect(replayed.checkpoint).toEqual(first.checkpoint);
    expect(replayed.disposition).toEqual(first.disposition);
    expect(canonicalJson(replayed.disposition)).toBe(canonicalJson(first.disposition));
    expect(log).not.toContain("archive.put");
    expect(client.objects.size).toBe(0);
    expect(await store.listDispositions({ tenantId: TENANT_ID })).toEqual([first.disposition]);
  });

  test("accepted replay rejects disposition, policy, range, or record-hash drift without resolving time", async () => {
    const receiptMutations = [
      (receipt: RetentionDisposition) => ({ ...receipt, dispositionId: "rdp_wrong" }),
      (receipt: RetentionDisposition) => ({ ...receipt, policyReference: "policy.wrong" }),
      (receipt: RetentionDisposition) => ({ ...receipt, fromSequence: receipt.fromSequence + 1 }),
      (receipt: RetentionDisposition) => ({ ...receipt, hash: "f".repeat(64) }),
    ];
    for (const mutate of receiptMutations) {
      const store = await seedStore();
      const client = createClient([]);
      const options = await runOptions(store, client);
      const first = await runRetentionEpoch(options);
      const replayStore: CheckpointingAuditStore = {
        ...store,
        append: store.append.bind(store),
        list: store.list.bind(store),
        getChainState: store.getChainState.bind(store),
        advanceRetentionPolicyFence: store.advanceRetentionPolicyFence.bind(store),
        compactRange: store.compactRange.bind(store),
        listCheckpoints: store.listCheckpoints.bind(store),
        prepareDisposition: store.prepareDisposition.bind(store),
        confirmDisposition: store.confirmDisposition.bind(store),
        async listDispositions() {
          return [mutate(first.disposition)];
        },
      };
      let resolverCalls = 0;
      await expect(
        runRetentionEpoch({
          ...options,
          store: replayStore,
          resolveDisposedAt: async () => {
            resolverCalls += 1;
            return "2026-08-24T01:03:00.000Z";
          },
        }),
      ).rejects.toThrow();
      expect(resolverCalls).toBe(0);
    }
  });

  test("a crash after confirmed provider absence retries receipt confirmation without re-upload", async () => {
    const log: string[] = [];
    const realStore = await seedStore();
    const client = createClient(log);
    let crashBeforeConfirm = true;
    const crashingStore: CheckpointingAuditStore = {
      append: realStore.append.bind(realStore),
      list: realStore.list.bind(realStore),
      getChainState: realStore.getChainState.bind(realStore),
      advanceRetentionPolicyFence: realStore.advanceRetentionPolicyFence.bind(realStore),
      compactRange: realStore.compactRange.bind(realStore),
      listCheckpoints: realStore.listCheckpoints.bind(realStore),
      prepareDisposition: realStore.prepareDisposition.bind(realStore),
      listDispositions: realStore.listDispositions.bind(realStore),
      async confirmDisposition(...args) {
        if (crashBeforeConfirm) {
          crashBeforeConfirm = false;
          throw new Error("crash after delete before confirm");
        }
        return realStore.confirmDisposition(...args);
      },
    };
    const options = await runOptions(crashingStore, client);
    await expect(runRetentionEpoch(options)).rejects.toThrow("crash after delete before confirm");
    expect(client.objects.size).toBe(0);
    expect(await realStore.listDispositions({ tenantId: TENANT_ID })).toEqual([]);
    log.length = 0;

    const replayed = await runRetentionEpoch(options);

    expect(log).not.toContain("archive.put");
    expect(client.objects.size).toBe(0);
    expect(await realStore.listDispositions({ tenantId: TENANT_ID })).toEqual([replayed.disposition]);
  });

  test("a genuine cold invocation confirms delete-before-confirm from checkpoint prefix state", async () => {
    const log: string[] = [];
    const realStore = await seedStore();
    const client = createClient(log);
    const crashingStore: CheckpointingAuditStore = {
      append: realStore.append.bind(realStore),
      list: realStore.list.bind(realStore),
      getChainState: realStore.getChainState.bind(realStore),
      advanceRetentionPolicyFence: realStore.advanceRetentionPolicyFence.bind(realStore),
      compactRange: realStore.compactRange.bind(realStore),
      listCheckpoints: realStore.listCheckpoints.bind(realStore),
      prepareDisposition: realStore.prepareDisposition.bind(realStore),
      listDispositions: realStore.listDispositions.bind(realStore),
      async confirmDisposition() {
        throw new Error("crash after cold delete before confirm");
      },
    };
    const first = await runOptions(crashingStore, client);
    await expect(runRetentionEpoch(first)).rejects.toThrow("crash after cold delete before confirm");
    expect(client.objects.size).toBe(0);
    expect(await realStore.listDispositions({ tenantId: TENANT_ID })).toEqual([]);
    log.length = 0;

    const cold = await runOptions(realStore, client, { records: [] });
    const result = await runRetentionEpoch(cold);

    expect(result.manifest).toBeNull();
    expect(log).not.toContain("archive.put");
    expect(log).not.toContain("archive.delete");
    expect(log).toContain("archive.get");
    expect(log).toContain("archive.list");
    expect(await realStore.listDispositions({ tenantId: TENANT_ID })).toEqual([result.disposition]);
  });

  test("fails closed before provider I/O when neither a checkpoint nor record bodies exist", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    const options = await runOptions(store, client, { records: [] });

    await expect(runRetentionEpoch(options)).rejects.toThrow("retention epoch requires at least one record");

    expect(log).toEqual([]);
    expect(await store.list({ tenantId: TENANT_ID })).toHaveLength(3);
    expect(await store.listCheckpoints({ tenantId: TENANT_ID })).toEqual([]);
  });

  test("serializes concurrent epochs so no stale run can PUT after the winner disposes", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    const base = await runOptions(store, client);
    const withEpochLease = createEpochLeaseRunner();
    let winnerEnteredSeal!: () => void;
    const winnerAtSeal = new Promise<void>((resolve) => {
      winnerEnteredSeal = resolve;
    });
    let releaseWinnerSeal!: () => void;
    const winnerMaySeal = new Promise<void>((resolve) => {
      releaseWinnerSeal = resolve;
    });
    let winnerFinished!: () => void;
    const winnerDone = new Promise<void>((resolve) => {
      winnerFinished = resolve;
    });
    let staleSealCalls = 0;
    const winnerArchive = {
      ...base.archive,
      async sealEpoch(input: Parameters<typeof base.archive.sealEpoch>[0]) {
        winnerEnteredSeal();
        await winnerMaySeal;
        return base.archive.sealEpoch(input);
      },
    };
    const staleArchive = {
      ...base.archive,
      async sealEpoch(input: Parameters<typeof base.archive.sealEpoch>[0]) {
        staleSealCalls += 1;
        await winnerDone;
        return base.archive.sealEpoch(input);
      },
    };

    const winnerPromise = runRetentionEpoch({ ...base, archive: winnerArchive, withEpochLease });
    await winnerAtSeal;
    const stalePromise = runRetentionEpoch({ ...base, archive: staleArchive, withEpochLease });
    await Promise.resolve();
    releaseWinnerSeal();
    const winner = await winnerPromise;
    const logAtWinnerDisposal = log.length;
    winnerFinished();
    const stale = await stalePromise;

    expect(stale.disposition).toEqual(winner.disposition);
    expect(staleSealCalls).toBe(0);
    expect(log.slice(logAtWinnerDisposal)).not.toContain("archive.put");
    expect(client.objects.size).toBe(0);
  });

  test("a rejected epoch lease performs zero store and provider I/O", async () => {
    const providerLog: string[] = [];
    const storeLog: string[] = [];
    const realStore = await seedStore();
    const client = createClient(providerLog);
    const base = await runOptions(realStore, client);
    const observedStore: CheckpointingAuditStore = {
      async append(...args) {
        storeLog.push("append");
        return realStore.append(...args);
      },
      async list(...args) {
        storeLog.push("list");
        return realStore.list(...args);
      },
      async getChainState(...args) {
        storeLog.push("getChainState");
        return realStore.getChainState(...args);
      },
      async advanceRetentionPolicyFence(...args) {
        storeLog.push("advanceRetentionPolicyFence");
        return realStore.advanceRetentionPolicyFence(...args);
      },
      async compactRange(...args) {
        storeLog.push("compactRange");
        return realStore.compactRange(...args);
      },
      async listCheckpoints(...args) {
        storeLog.push("listCheckpoints");
        return realStore.listCheckpoints(...args);
      },
      async prepareDisposition(...args) {
        storeLog.push("prepareDisposition");
        return realStore.prepareDisposition(...args);
      },
      async confirmDisposition(...args) {
        storeLog.push("confirmDisposition");
        return realStore.confirmDisposition(...args);
      },
      async listDispositions(...args) {
        storeLog.push("listDispositions");
        return realStore.listDispositions(...args);
      },
    };
    providerLog.length = 0;

    await expect(
      runRetentionEpoch({
        ...base,
        store: observedStore,
        withEpochLease: async () => {
          throw new Error("epoch lease unavailable");
        },
      }),
    ).rejects.toThrow("epoch lease unavailable");

    expect(storeLog).toEqual([]);
    expect(providerLog).toEqual([]);
    expect(await realStore.listCheckpoints({ tenantId: TENANT_ID })).toEqual([]);
  });

  test("a fresh-fence retry supersedes a pending crashed deletion attempt and accepts no stale receipt", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    client.failNextDelete = true;
    const first = await runOptions(store, client);
    await expect(runRetentionEpoch(first)).rejects.toThrow("crash during delete");
    expect(await store.listDispositions({ tenantId: TENANT_ID })).toEqual([]);

    await store.advanceRetentionPolicyFence({ tenantId: TENANT_ID }, 0);
    const retry = await runOptions(store, client, {
      records: first.records,
      previousCheckpoint: null,
      expectedState: first.expectedState,
      eligibility: { eligible: true, policyReference: "policy.v2", version: 1 },
      disposition: {
        attemptId: "attempt_retry",
        dispositionId: "rdp_retry",
      },
      resolveDisposedAt: async () => "2026-08-24T01:03:00.000Z",
    });
    const result = await runRetentionEpoch(retry);

    expect(result.disposition.policyReference).toBe("policy.v2");
    expect(await store.listDispositions({ tenantId: TENANT_ID })).toEqual([result.disposition]);
  });

  test("a fence change during a faulty unlocked deletion path cannot persist a receipt", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    const archive = createRetentionStagingArchive({ client, prefix: "coordinator-staging" });
    const originalDelete = archive.deleteEpoch.bind(archive);
    let changedFence = false;
    const unsafeArchive = {
      ...archive,
      async deleteEpoch(manifest: Parameters<typeof originalDelete>[0]) {
        await originalDelete(manifest);
        if (!changedFence) {
          changedFence = true;
          await store.advanceRetentionPolicyFence({ tenantId: TENANT_ID }, 0);
        }
      },
    };
    const options = await runOptions(store, client, { archive: unsafeArchive });

    await expect(runRetentionEpoch(options)).rejects.toThrow("retention policy fence mismatch");
    expect(changedFence).toBe(true);
    expect(await store.listDispositions({ tenantId: TENANT_ID })).toEqual([]);
  });

  test("rejects ineligible or malformed host inputs before staging or store mutation", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    const options = await runOptions(store, client, {
      eligibility: { eligible: false, policyReference: "hold.active", version: 0 },
    });

    await expect(runRetentionEpoch(options)).rejects.toThrow("retention epoch is not eligible");
    expect(log).toEqual([]);
    expect(await store.listCheckpoints({ tenantId: TENANT_ID })).toEqual([]);
  });

  test("enforces an injected signature requirement before authoritative crop", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    const options = await runOptions(store, client, {
      verification: { requireSignature: true },
    });

    await expect(runRetentionEpoch(options)).rejects.toThrow("invalid retention checkpoint: signature_required");
    expect(await store.list({ tenantId: TENANT_ID })).toHaveLength(3);
    expect(await store.listCheckpoints({ tenantId: TENANT_ID })).toEqual([]);
  });

  test("returns cloned minimal records and rejects a signing factory that changes the archive binding", async () => {
    const log: string[] = [];
    const store = await seedStore();
    const client = createClient(log);
    const invalid = await runOptions(store, client, {
      createCheckpoint: (input: RetentionCheckpointInput) =>
        createRetentionCheckpoint({
          ...input,
          archiveRootHash: "f".repeat(64),
        }),
    });
    await expect(runRetentionEpoch(invalid)).rejects.toThrow("checkpoint factory changed coordinator-owned fields");
    expect(await store.listCheckpoints({ tenantId: TENANT_ID })).toEqual([]);

    const valid = await runOptions(store, client);
    const result = await runRetentionEpoch(valid);
    const checkpointSnapshot = canonicalJson(result.checkpoint);
    const dispositionSnapshot = canonicalJson(result.disposition);
    if (!result.manifest) throw new Error("initial retention run must return its staged manifest");
    result.manifest.segments[0]!.objectKey = "mutated";
    result.checkpoint.checkpointId = "mutated";
    result.disposition.dispositionId = "mutated";
    expect(canonicalJson((await store.listCheckpoints({ tenantId: TENANT_ID }))[0]!)).toBe(checkpointSnapshot);
    expect(canonicalJson((await store.listDispositions({ tenantId: TENANT_ID }))[0]!)).toBe(dispositionSnapshot);
  });
});
