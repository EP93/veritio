import { describe, expect, test } from "bun:test";
import {
  canonicalJson,
  createAuditEvent,
  createRetentionCheckpoint,
  hashAuditRecord,
  hashIdempotencyKey,
  type AuditRecord,
} from "@veritio/core";
import {
  createRetentionStagingArchive,
  type RetentionStagingClient,
} from "../retention-staging-archive";

const TENANT_ID = "org_retention";

interface MemoryRetentionClient extends RetentionStagingClient {
  objects: Map<string, Uint8Array>;
  hiddenFromList: Set<string>;
  failDeleteKey?: string;
}

/**
 * Provides byte-cloning object storage with independently controllable GET,
 * LIST, and DELETE behavior so each fail-closed boundary is observable.
 */
function createMemoryRetentionClient(): MemoryRetentionClient {
  const objects = new Map<string, Uint8Array>();
  const hiddenFromList = new Set<string>();
  return {
    objects,
    hiddenFromList,
    async put(key, body) {
      objects.set(key, body.slice());
    },
    async get(key) {
      const body = objects.get(key);
      return body ? body.slice() : null;
    },
    async list(prefix) {
      return [...objects.keys()]
        .filter((key) => key.startsWith(prefix) && !hiddenFromList.has(key))
        .sort();
    },
    async delete(key) {
      if (this.failDeleteKey === key) throw new Error("provider delete failed");
      objects.delete(key);
    },
  };
}

/** Builds deterministic hash-valid records without reading a clock. */
function records(count: number): AuditRecord[] {
  const output: AuditRecord[] = [];
  for (let sequence = 1; sequence <= count; sequence += 1) {
    const event = createAuditEvent({
      id: `evt_${sequence}`,
      occurredAt: "2026-08-24T00:00:00.000Z",
      actor: { type: "system", id: "retention-test" },
      action: "retention.tested",
      target: { type: "organization", id: TENANT_ID },
      scope: { tenantId: TENANT_ID, environment: "test" },
      metadata: { sequence },
    });
    const withoutHash = {
      event,
      sequence,
      previousHash: output.at(-1)?.hash ?? null,
      hashAlgorithm: "sha256" as const,
      canonicalization: "veritio-json-v1" as const,
      appendedAt: "2026-08-24T00:00:01.000Z",
      idempotencyKeyHash: hashIdempotencyKey(TENANT_ID, event.id),
    };
    output.push({ ...withoutHash, hash: hashAuditRecord(withoutHash) });
  }
  return output;
}

/** Creates the epoch-one anchor used to prove later staging starts at it. */
function firstCheckpoint(chain: readonly AuditRecord[]) {
  return createRetentionCheckpoint({
    checkpointId: "rcp_epoch_1",
    tenantId: TENANT_ID,
    chainKind: "audit",
    epoch: 1,
    fromSequence: 1,
    fromPreviousHash: null,
    throughSequence: 2,
    throughHash: chain[1]!.hash,
    recordCount: 2,
    archiveRootHash: "a".repeat(64),
    previousCheckpointHash: null,
    createdAt: "2026-08-24T00:01:00.000Z",
  });
}

describe("retention staging archive", () => {
  test("derives the deterministic candidate manifest without any provider write", async () => {
    const chain = records(3);
    const client = createMemoryRetentionClient();
    const archive = createRetentionStagingArchive({ client });
    const input = {
      tenantId: TENANT_ID,
      epoch: 2,
      previousCheckpoint: firstCheckpoint(chain),
      records: chain.slice(2),
    };

    const derived = await archive.deriveEpoch(input);

    expect(client.objects.size).toBe(0);
    expect(await archive.sealEpoch(input)).toEqual(derived);
  });

  test("seals epoch one only from the genesis anchor", async () => {
    const chain = records(2);
    const archive = createRetentionStagingArchive({ client: createMemoryRetentionClient() });
    const manifest = await archive.sealEpoch({
      tenantId: TENANT_ID,
      epoch: 1,
      previousCheckpoint: null,
      records: chain,
    });

    expect(manifest.fromSequence).toBe(1);
    expect(manifest.fromPreviousHash).toBeNull();
    expect(manifest.previousCheckpointHash).toBeNull();
    expect((await archive.verifyEpoch(manifest)).ok).toBe(true);
  });

  test("seals and verifies exactly one epoch from the prior checkpoint anchor", async () => {
    const chain = records(5);
    const client = createMemoryRetentionClient();
    const archive = createRetentionStagingArchive({ client, prefix: "staging-a" });
    const manifest = await archive.sealEpoch({
      tenantId: TENANT_ID,
      epoch: 2,
      previousCheckpoint: firstCheckpoint(chain),
      records: chain.slice(2),
      segmentRecordCount: 2,
    });

    expect(manifest.fromSequence).toBe(3);
    expect(manifest.fromPreviousHash).toBe(chain[1]!.hash);
    expect(manifest.throughSequence).toBe(5);
    expect(manifest.throughHash).toBe(chain[4]!.hash);
    expect(manifest.segments.map((segment) => [segment.fromSequence, segment.toSequence])).toEqual([
      [3, 4],
      [5, 5],
    ]);
    expect(manifest.archiveRootHash).toBe("93a4502628d72e72de1df46b1db3d8ccdfe759c29895fc57befde775ada26f80");
    expect(await archive.verifyEpoch(manifest)).toEqual({
      ok: true,
      archiveRootHash: manifest.archiveRootHash,
      segmentCount: 2,
      recordCount: 3,
    });

    const replayed = await archive.sealEpoch({
      tenantId: TENANT_ID,
      epoch: 2,
      previousCheckpoint: firstCheckpoint(chain),
      records: chain.slice(2),
      segmentRecordCount: 2,
    });
    expect(replayed).toEqual(manifest);
    replayed.segments[0]!.objectKey = "mutated";
    expect((await archive.sealEpoch({
      tenantId: TENANT_ID,
      epoch: 2,
      previousCheckpoint: firstCheckpoint(chain),
      records: chain.slice(2),
      segmentRecordCount: 2,
    })).segments[0]!.objectKey).not.toBe("mutated");
  });

  test("computes a provider-neutral root that excludes prefixes and object keys", async () => {
    const chain = records(3);
    const previousCheckpoint = firstCheckpoint(chain);
    const first = await createRetentionStagingArchive({
      client: createMemoryRetentionClient(),
      prefix: "provider-a/bucket-a",
    }).sealEpoch({ tenantId: TENANT_ID, epoch: 2, previousCheckpoint, records: chain.slice(2) });
    const second = await createRetentionStagingArchive({
      client: createMemoryRetentionClient(),
      prefix: "provider-b/bucket-b",
    }).sealEpoch({ tenantId: TENANT_ID, epoch: 2, previousCheckpoint, records: chain.slice(2) });

    expect(first.segments[0]!.objectKey).not.toBe(second.segments[0]!.objectKey);
    expect(first.manifestKey).not.toBe(second.manifestKey);
    expect(first.archiveRootHash).toBe(second.archiveRootHash);
  });

  test("rejects invalid identifiers, anchors, non-contiguous ranges, and corrupt records before writing", async () => {
    const chain = records(4);
    const client = createMemoryRetentionClient();
    const archive = createRetentionStagingArchive({ client });
    const previousCheckpoint = firstCheckpoint(chain);

    await expect(archive.sealEpoch({
      tenantId: "tenant/escape",
      epoch: 2,
      previousCheckpoint,
      records: chain.slice(2),
    })).rejects.toThrow("tenantId is invalid");
    await expect(archive.sealEpoch({
      tenantId: TENANT_ID,
      epoch: 3,
      previousCheckpoint,
      records: chain.slice(2),
    })).rejects.toThrow("epoch does not extend the prior checkpoint");
    await expect(archive.sealEpoch({
      tenantId: TENANT_ID,
      epoch: 2,
      previousCheckpoint,
      records: [chain[3]!],
    })).rejects.toThrow("records do not begin at the epoch anchor");
    await expect(archive.sealEpoch({
      tenantId: TENANT_ID,
      epoch: 2,
      previousCheckpoint,
      records: [{ ...chain[2]!, hash: "b".repeat(64) }],
    })).rejects.toThrow("record integrity check failed");
    expect(client.objects.size).toBe(0);
  });

  test("fails verification for re-encoded, corrupt, missing, or unlisted exact bytes", async () => {
    const chain = records(4);
    const cases = ["reencoded", "missing", "unlisted"] as const;
    for (const kind of cases) {
      const client = createMemoryRetentionClient();
      const archive = createRetentionStagingArchive({ client, prefix: `staging-${kind}` });
      const manifest = await archive.sealEpoch({
        tenantId: TENANT_ID,
        epoch: 2,
        previousCheckpoint: firstCheckpoint(chain),
        records: chain.slice(2),
      });
      const segmentKey = manifest.segments[0]!.objectKey;
      if (kind === "reencoded") {
        const original = new TextDecoder().decode(client.objects.get(segmentKey)!);
        const firstLine = original.split("\n")[0]!;
        client.objects.set(segmentKey, new TextEncoder().encode(`${JSON.stringify(JSON.parse(firstLine), null, 2)}\n`));
      } else if (kind === "missing") {
        client.objects.delete(segmentKey);
      } else {
        client.hiddenFromList.add(segmentKey);
      }

      const result = await archive.verifyEpoch(manifest);
      expect(result.ok).toBe(false);
    }
  });

  test("requires manifest GET bytes and LIST presence before reporting verification", async () => {
    const chain = records(3);
    const client = createMemoryRetentionClient();
    const archive = createRetentionStagingArchive({ client });
    const manifest = await archive.sealEpoch({
      tenantId: TENANT_ID,
      epoch: 2,
      previousCheckpoint: firstCheckpoint(chain),
      records: chain.slice(2),
    });
    client.hiddenFromList.add(manifest.manifestKey);
    expect((await archive.verifyEpoch(manifest)).ok).toBe(false);
    client.hiddenFromList.delete(manifest.manifestKey);
    client.objects.set(manifest.manifestKey, new TextEncoder().encode(canonicalJson({ corrupted: true })));
    expect((await archive.verifyEpoch(manifest)).ok).toBe(false);
  });

  test("rejects mutated physical keys and non-contiguous descriptors before provider access", async () => {
    const chain = records(4);
    const client = createMemoryRetentionClient();
    const archive = createRetentionStagingArchive({ client });
    const manifest = await archive.sealEpoch({
      tenantId: TENANT_ID,
      epoch: 2,
      previousCheckpoint: firstCheckpoint(chain),
      records: chain.slice(2),
      segmentRecordCount: 1,
    });
    const keyMutation = {
      ...manifest,
      segments: manifest.segments.map((segment) => ({ ...segment })),
    };
    keyMutation.segments[0]!.objectKey = "outside/controlled/prefix";
    await expect(archive.deleteEpoch(keyMutation)).rejects.toThrow("staged epoch segment key is invalid");

    const descriptorMutation = {
      ...manifest,
      segments: manifest.segments.map((segment) => ({ ...segment })),
    };
    descriptorMutation.segments[1]!.fromSequence += 1;
    await expect(archive.deleteEpoch(descriptorMutation)).rejects.toThrow(
      "staged epoch segment descriptors are not contiguous",
    );
    const invalidSegments = { ...manifest, segments: null } as unknown as typeof manifest;
    await expect(archive.deleteEpoch(invalidSegments)).rejects.toThrow("staged epoch manifest range is invalid");
    expect(client.objects.has(manifest.manifestKey)).toBe(true);
  });

  test("deletes idempotently and confirms absence independently through GET and LIST", async () => {
    const chain = records(3);
    const client = createMemoryRetentionClient();
    const archive = createRetentionStagingArchive({ client });
    const manifest = await archive.sealEpoch({
      tenantId: TENANT_ID,
      epoch: 2,
      previousCheckpoint: firstCheckpoint(chain),
      records: chain.slice(2),
    });
    const segmentKey = manifest.segments[0]!.objectKey;

    expect(await archive.confirmEpochAbsent(manifest)).toBe(false);
    await archive.deleteEpoch(manifest);
    await archive.deleteEpoch(manifest);
    expect(await archive.confirmEpochAbsent(manifest)).toBe(true);

    client.objects.set(segmentKey, new TextEncoder().encode("hidden-from-list"));
    client.hiddenFromList.add(segmentKey);
    expect(await archive.confirmEpochAbsent(manifest)).toBe(false);
    client.objects.delete(segmentKey);
    client.hiddenFromList.delete(segmentKey);
    client.objects.set(`${manifest.manifestKey}.ghost`, new TextEncoder().encode("listed-only"));
    expect(await archive.confirmEpochAbsent(manifest)).toBe(false);
  });

  test("propagates provider delete failures without claiming absence", async () => {
    const chain = records(3);
    const client = createMemoryRetentionClient();
    const archive = createRetentionStagingArchive({ client });
    const manifest = await archive.sealEpoch({
      tenantId: TENANT_ID,
      epoch: 2,
      previousCheckpoint: firstCheckpoint(chain),
      records: chain.slice(2),
    });
    client.failDeleteKey = manifest.segments[0]!.objectKey;

    await expect(archive.deleteEpoch(manifest)).rejects.toThrow("provider delete failed");
    expect(await archive.confirmEpochAbsent(manifest)).toBe(false);
  });
});
