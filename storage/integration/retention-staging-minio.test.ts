import { describe, expect, test } from "bun:test";
import { S3Client } from "bun";
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
} from "../src/retention-staging-archive";

const endpoint = process.env.VERITIO_S3_TEST_ENDPOINT;
const accessKeyId = process.env.VERITIO_S3_TEST_ACCESS_KEY_ID ?? "veritio";
const secretAccessKey = process.env.VERITIO_S3_TEST_SECRET_ACCESS_KEY ?? "veritio-local";
const bucket = process.env.VERITIO_S3_TEST_BUCKET ?? "veritio-archive";

if (endpoint) defineRetentionStagingLiveSuite(endpoint);

/**
 * Proves exact anchored epoch sealing, replay verification, idempotent provider
 * deletion, and independent GET/LIST absence through a real MinIO boundary.
 */
function defineRetentionStagingLiveSuite(liveEndpoint: string): void {
  const s3 = new S3Client({ endpoint: liveEndpoint, accessKeyId, secretAccessKey, bucket });
  const runPrefix = `retention-it-${crypto.randomUUID()}`;
  const client = createBunS3RetentionClient(s3);

  describe("retention staging live (MinIO)", () => {
    test("seals, verifies, and disposes an anchored epoch through real GET/LIST/DELETE calls", async () => {
      await waitForBucket(s3, runPrefix);
      const chain = records(4);
      const previousCheckpoint = createRetentionCheckpoint({
        checkpointId: "rcp_live_epoch_1",
        tenantId: "org_live_retention",
        chainKind: "audit",
        epoch: 1,
        fromSequence: 1,
        fromPreviousHash: null,
        throughSequence: 2,
        throughHash: chain[1]!.hash,
        recordCount: 2,
        archiveRootHash: "a".repeat(64),
        previousCheckpointHash: null,
        createdAt: "2026-08-24T02:01:00.000Z",
      });
      const archive = createRetentionStagingArchive({ client, prefix: runPrefix });

      try {
        const manifest = await archive.sealEpoch({
          tenantId: "org_live_retention",
          epoch: 2,
          previousCheckpoint,
          records: chain.slice(2),
          segmentRecordCount: 1,
        });
        expect(await archive.verifyEpoch(manifest)).toEqual({
          ok: true,
          archiveRootHash: manifest.archiveRootHash,
          segmentCount: 2,
          recordCount: 2,
        });

        const firstSegment = await client.get(manifest.segments[0]!.objectKey);
        expect(new TextDecoder().decode(firstSegment!)).toBe(`${canonicalJson(chain[2]!)}\n`);
        expect(await client.list(`${runPrefix}/`)).toHaveLength(3);

        await archive.deleteEpoch(manifest);
        await archive.deleteEpoch(manifest);
        expect(await archive.confirmEpochAbsent(manifest)).toBe(true);
        expect(await client.list(`${runPrefix}/`)).toEqual([]);
      } finally {
        for (const key of await client.list(`${runPrefix}/`)) await client.delete(key);
      }
    }, 60_000);
  });
}

/** Builds a deterministic four-record tenant audit chain for exact byte assertions. */
function records(count: number): AuditRecord[] {
  const output: AuditRecord[] = [];
  for (let sequence = 1; sequence <= count; sequence += 1) {
    const event = createAuditEvent({
      id: `evt_live_${sequence}`,
      occurredAt: "2026-08-24T02:00:00.000Z",
      actor: { type: "system", id: "retention-minio-test" },
      action: "retention.tested",
      target: { type: "organization", id: "org_live_retention" },
      scope: { tenantId: "org_live_retention", environment: "test" },
      metadata: { sequence },
    });
    const withoutHash = {
      event,
      sequence,
      previousHash: output.at(-1)?.hash ?? null,
      hashAlgorithm: "sha256" as const,
      canonicalization: "veritio-json-v1" as const,
      appendedAt: "2026-08-24T02:00:01.000Z",
      idempotencyKeyHash: hashIdempotencyKey("org_live_retention", event.id),
    };
    output.push({ ...withoutHash, hash: hashAuditRecord(withoutHash) });
  }
  return output;
}

/**
 * Adapts Bun's S3 client to exact bytes, complete pagination, and idempotent
 * deletion; non-missing GET/DELETE provider failures remain observable.
 */
function createBunS3RetentionClient(s3: S3Client): RetentionStagingClient {
  return {
    async put(key, body) {
      await s3.write(key, body);
    },
    async get(key) {
      try {
        return new Uint8Array(await s3.file(key).arrayBuffer());
      } catch (error) {
        if ((error as { code?: string }).code === "NoSuchKey") return null;
        throw error;
      }
    },
    async list(prefix) {
      const keys: string[] = [];
      let continuationToken: string | undefined;
      for (;;) {
        const page = await s3.list({ prefix, ...(continuationToken ? { continuationToken } : {}) });
        for (const item of page.contents ?? []) keys.push(item.key);
        if (!page.isTruncated || !page.nextContinuationToken) return keys.sort();
        continuationToken = page.nextContinuationToken;
      }
    },
    async delete(key) {
      await s3.delete(key);
    },
  };
}

/** Retries MinIO bucket discovery without recreating or stopping shared Docker services. */
async function waitForBucket(s3: S3Client, prefix: string): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      await s3.list({ prefix, maxKeys: 1 });
      return;
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
  }
  throw lastError;
}
