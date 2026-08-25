import { createHash } from "node:crypto";
import {
  canonicalJson,
  hashAuditRecord,
  type AuditRecord,
  type RetentionCheckpoint,
  verifyRetentionCheckpoint,
} from "@veritio/core";
import type { ObjectArchiveClient } from "./object-archive-chain.js";

const DEFAULT_PREFIX = "veritio-retention-staging";
const ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const PREFIX_PATTERN = /^[A-Za-z0-9._:/=-]{1,512}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const SEQUENCE_PAD = 16;
const MANIFEST_KEYS = new Set([
  "recordType",
  "schemaVersion",
  "tenantId",
  "epoch",
  "fromSequence",
  "fromPreviousHash",
  "throughSequence",
  "throughHash",
  "recordCount",
  "previousCheckpointHash",
  "archiveRootHash",
  "segments",
  "manifestKey",
]);
const SEGMENT_KEYS = new Set([
  "fromSequence",
  "toSequence",
  "recordCount",
  "firstPreviousHash",
  "lastHash",
  "contentSha256",
  "objectKey",
]);

/**
 * Extends the derived object-archive byte contract with idempotent deletion.
 * A conforming client MUST resolve successfully when a key is already absent;
 * authorization, transport, and other provider failures MUST reject.
 */
export interface RetentionStagingClient extends ObjectArchiveClient {
  delete(key: string): Promise<void>;
}

/** Provider-neutral fields committed by a retention checkpoint archive root. */
export interface RetentionStagingSegmentDescriptor {
  fromSequence: number;
  toSequence: number;
  recordCount: number;
  firstPreviousHash: string | null;
  lastHash: string;
  contentSha256: string;
}

/**
 * Physical staging lookup for one descriptor. `objectKey` is deliberately
 * excluded from the provider-neutral archive-root calculation.
 */
export interface RetentionStagingSegment extends RetentionStagingSegmentDescriptor {
  objectKey: string;
}

/**
 * Derived manifest for one exact audit-retention epoch. It is a short-lived
 * lookup record, never an authoritative chain record or sequence owner.
 */
export interface RetentionStagingManifest {
  recordType: "retention.staging.manifest";
  schemaVersion: "1.0";
  tenantId: string;
  epoch: number;
  fromSequence: number;
  fromPreviousHash: string | null;
  throughSequence: number;
  throughHash: string;
  recordCount: number;
  previousCheckpointHash: string | null;
  archiveRootHash: string;
  segments: RetentionStagingSegment[];
  manifestKey: string;
}

/** Caller-owned exact epoch bytes and explicit genesis/prior-checkpoint anchor. */
export interface SealRetentionEpochInput {
  tenantId: string;
  epoch: number;
  previousCheckpoint: RetentionCheckpoint | null;
  records: readonly AuditRecord[];
  segmentRecordCount?: number;
}

/** Fail-closed replay result used as the coordinator's pre-crop archive gate. */
export type RetentionStagingVerification =
  | { ok: true; archiveRootHash: string; segmentCount: number; recordCount: number }
  | { ok: false; reason: string };

/** Separate derived staging surface for one exact retention epoch. */
export interface RetentionStagingArchive {
  deriveEpoch(input: SealRetentionEpochInput): RetentionStagingManifest;
  sealEpoch(input: SealRetentionEpochInput): Promise<RetentionStagingManifest>;
  recoverEpoch(checkpoint: RetentionCheckpoint): Promise<RetentionStagingManifest | null>;
  verifyEpoch(manifest: RetentionStagingManifest): Promise<RetentionStagingVerification>;
  deleteEpoch(manifest: RetentionStagingManifest): Promise<void>;
  confirmEpochAbsent(manifest: RetentionStagingManifest): Promise<boolean>;
  confirmCheckpointEpochAbsent(checkpoint: RetentionCheckpoint): Promise<boolean>;
}

/** Injected object client and isolated key namespace for derived staging. */
export interface RetentionStagingArchiveOptions {
  client: RetentionStagingClient;
  prefix?: string;
}

/**
 * Creates a separately namespaced derived archive that seals and verifies only
 * one explicit retention epoch. It does not widen `ObjectAuditArchive`, list
 * authoritative records, allocate sequences, or read process configuration.
 */
export function createRetentionStagingArchive(options: RetentionStagingArchiveOptions): RetentionStagingArchive {
  const prefix = validatePrefix(options.prefix ?? DEFAULT_PREFIX);
  const client = options.client;

  /**
   * Deterministically validates and derives one epoch manifest, including exact
   * content digests and provider-neutral root, without reading or writing the
   * provider. Coordinators use this to recognize completed work safely.
   */
  function deriveEpoch(input: SealRetentionEpochInput): RetentionStagingManifest {
    const segmentRecordCount = input.segmentRecordCount ?? 1000;
    assertPositiveSafeInteger(segmentRecordCount, "segmentRecordCount");
    const anchor = validateSealInput(input);
    const epochPrefix = epochKeyPrefix(prefix, input.tenantId, input.epoch);
    const segments: RetentionStagingSegment[] = [];
    for (let offset = 0; offset < input.records.length; offset += segmentRecordCount) {
      const batch = input.records.slice(offset, offset + segmentRecordCount);
      const first = batch[0]!;
      const last = batch.at(-1)!;
      const body = encodeNdjson(batch);
      segments.push({
        fromSequence: first.sequence,
        toSequence: last.sequence,
        recordCount: batch.length,
        firstPreviousHash: first.previousHash,
        lastHash: last.hash,
        contentSha256: sha256Bytes(body),
        objectKey: `${epochPrefix}/${padSequence(first.sequence)}-${padSequence(last.sequence)}.ndjson`,
      });
    }
    const manifest: RetentionStagingManifest = {
      recordType: "retention.staging.manifest",
      schemaVersion: "1.0",
      tenantId: input.tenantId,
      epoch: input.epoch,
      fromSequence: input.records[0]!.sequence,
      fromPreviousHash: anchor.previousHash,
      throughSequence: input.records.at(-1)!.sequence,
      throughHash: input.records.at(-1)!.hash,
      recordCount: input.records.length,
      previousCheckpointHash: anchor.checkpointHash,
      archiveRootHash: sha256Text(canonicalJson(segments.map(providerNeutralDescriptor))),
      segments,
      manifestKey: `${epochPrefix}/manifest.json`,
    };
    validateManifest(manifest, prefix);
    return cloneManifest(manifest);
  }

  /**
   * Seals deterministic exact-byte NDJSON segments and commits their manifest
   * last. Existing byte-identical objects are replayed; conflicting bytes fail
   * closed instead of being overwritten during a crash retry.
   */
  async function sealEpoch(input: SealRetentionEpochInput): Promise<RetentionStagingManifest> {
    const manifest = deriveEpoch(input);
    let offset = 0;
    for (const segment of manifest.segments) {
      const batch = input.records.slice(offset, offset + segment.recordCount);
      const body = encodeNdjson(batch);
      await putExact(client, segment.objectKey, body);
      offset += segment.recordCount;
    }
    await putExact(client, manifest.manifestKey, new TextEncoder().encode(canonicalJson(manifest)));
    return cloneManifest(manifest);
  }

  /**
   * Loads the deterministic manifest key for a durably stored checkpoint and
   * accepts its provider lookups only after the canonical manifest binds every
   * checkpoint field. A missing manifest is returned explicitly because it can
   * mean deletion completed before authoritative receipt confirmation.
   */
  async function recoverEpoch(checkpoint: RetentionCheckpoint): Promise<RetentionStagingManifest | null> {
    assertRecoverableCheckpoint(checkpoint);
    const manifestKey = `${epochKeyPrefix(prefix, checkpoint.tenantId, checkpoint.epoch)}/manifest.json`;
    const manifestBytes = await client.get(manifestKey);
    if (manifestBytes === null) return null;
    const manifest = parseManifest(new TextDecoder().decode(manifestBytes), prefix);
    assertManifestCheckpointBinding(manifest, checkpoint);
    return cloneManifest(manifest);
  }

  /**
   * Re-fetches the exact manifest and segment bytes, requires every expected
   * key to be present in LIST, recomputes byte and record hashes, and replays
   * the epoch from its explicit anchor before permitting authoritative crop.
   */
  async function verifyEpoch(manifest: RetentionStagingManifest): Promise<RetentionStagingVerification> {
    try {
      validateManifest(manifest, prefix);
      const epochPrefix = epochKeyPrefix(prefix, manifest.tenantId, manifest.epoch);
      const expectedKeys = [...manifest.segments.map((segment) => segment.objectKey), manifest.manifestKey].sort();
      const listedKeys = [...(await client.list(`${epochPrefix}/`))].sort();
      if (canonicalJson(listedKeys) !== canonicalJson(expectedKeys)) {
        throw new TypeError("staged epoch objects are not exactly present in listing");
      }

      const manifestBytes = await client.get(manifest.manifestKey);
      if (manifestBytes === null || !bytesEqual(manifestBytes, new TextEncoder().encode(canonicalJson(manifest)))) {
        throw new TypeError("staged epoch manifest integrity check failed");
      }
      const parsedManifest = parseManifest(new TextDecoder().decode(manifestBytes), prefix);
      if (canonicalJson(parsedManifest) !== canonicalJson(manifest)) {
        throw new TypeError("staged epoch manifest integrity check failed");
      }

      let previousSequence = manifest.fromSequence - 1;
      let previousHash = manifest.fromPreviousHash;
      let recordCount = 0;
      for (const segment of manifest.segments) {
        const body = await client.get(segment.objectKey);
        if (body === null) throw new TypeError("staged epoch segment is missing");
        if (sha256Bytes(body) !== segment.contentSha256) {
          throw new TypeError("staged epoch segment integrity check failed");
        }
        const records = parseExactNdjson(body, manifest.tenantId);
        if (
          records.length !== segment.recordCount ||
          records[0]!.sequence !== segment.fromSequence ||
          records.at(-1)!.sequence !== segment.toSequence ||
          records[0]!.previousHash !== segment.firstPreviousHash ||
          records.at(-1)!.hash !== segment.lastHash
        ) {
          throw new TypeError("staged epoch segment descriptor mismatch");
        }
        for (const record of records) {
          if (record.sequence !== previousSequence + 1 || record.previousHash !== previousHash) {
            throw new TypeError("staged epoch records are not contiguous and hash-linked");
          }
          previousSequence = record.sequence;
          previousHash = record.hash;
          recordCount += 1;
        }
      }
      if (
        previousSequence !== manifest.throughSequence ||
        previousHash !== manifest.throughHash ||
        recordCount !== manifest.recordCount
      ) {
        throw new TypeError("staged epoch tip mismatch");
      }
      return {
        ok: true,
        archiveRootHash: manifest.archiveRootHash,
        segmentCount: manifest.segments.length,
        recordCount,
      };
    } catch (error) {
      if (error instanceof TypeError) return { ok: false, reason: error.message };
      throw error;
    }
  }

  /**
   * Deletes all referenced segment objects and then the manifest. Correctness
   * relies on the client's documented already-absent success behavior so a
   * crash after any subset of deletes can retry safely.
   */
  async function deleteEpoch(manifest: RetentionStagingManifest): Promise<void> {
    validateManifest(manifest, prefix);
    for (const segment of manifest.segments) await client.delete(segment.objectKey);
    await client.delete(manifest.manifestKey);
  }

  /**
   * Confirms disposal through independent direct reads of every known key and
   * a complete prefix listing; either surface observing any object returns false.
   */
  async function confirmEpochAbsent(manifest: RetentionStagingManifest): Promise<boolean> {
    validateManifest(manifest, prefix);
    const keys = [...manifest.segments.map((segment) => segment.objectKey), manifest.manifestKey];
    let directReadsAbsent = true;
    for (const key of keys) {
      if ((await client.get(key)) !== null) directReadsAbsent = false;
    }
    const listedKeys = await client.list(`${epochKeyPrefix(prefix, manifest.tenantId, manifest.epoch)}/`);
    return directReadsAbsent && listedKeys.length === 0;
  }

  /**
   * Confirms a post-delete checkpoint epoch without reconstructing segment keys
   * from disposed event bodies. The deterministic manifest key must be absent
   * by direct GET and the complete tenant/epoch prefix must be empty by LIST;
   * a missing manifest alone never establishes provider absence.
   */
  async function confirmCheckpointEpochAbsent(checkpoint: RetentionCheckpoint): Promise<boolean> {
    assertRecoverableCheckpoint(checkpoint);
    const epochPrefix = epochKeyPrefix(prefix, checkpoint.tenantId, checkpoint.epoch);
    const manifestBytes = await client.get(`${epochPrefix}/manifest.json`);
    const listedKeys = await client.list(`${epochPrefix}/`);
    return manifestBytes === null && listedKeys.length === 0;
  }

  return {
    deriveEpoch,
    sealEpoch,
    recoverEpoch,
    verifyEpoch,
    deleteEpoch,
    confirmEpochAbsent,
    confirmCheckpointEpochAbsent,
  };
}

/** Validates the caller's tenant, prior anchor, exact range, and record hashes before any write. */
function validateSealInput(input: SealRetentionEpochInput): {
  previousHash: string | null;
  checkpointHash: string | null;
} {
  assertId(input.tenantId, "tenantId");
  assertPositiveSafeInteger(input.epoch, "epoch");
  if (input.records.length === 0) throw new TypeError("retention epoch requires at least one record");

  let previousHash: string | null;
  let previousSequence: number;
  let checkpointHash: string | null;
  if (input.previousCheckpoint === null) {
    if (input.epoch !== 1) throw new TypeError("epoch one requires the genesis anchor");
    previousSequence = 0;
    previousHash = null;
    checkpointHash = null;
  } else {
    const verification = verifyRetentionCheckpoint(input.previousCheckpoint);
    if (!verification.ok) throw new TypeError("previous checkpoint is invalid");
    if (input.previousCheckpoint.tenantId !== input.tenantId) {
      throw new TypeError("previous checkpoint tenant mismatch");
    }
    if (input.epoch !== input.previousCheckpoint.epoch + 1) {
      throw new TypeError("epoch does not extend the prior checkpoint");
    }
    previousSequence = input.previousCheckpoint.throughSequence;
    previousHash = input.previousCheckpoint.throughHash;
    checkpointHash = input.previousCheckpoint.hash;
  }

  for (const record of input.records) {
    if (record.event.scope?.tenantId !== input.tenantId) throw new TypeError("record tenant mismatch");
    if (hashAuditRecord(record) !== record.hash) throw new TypeError("record integrity check failed");
    if (record.sequence !== previousSequence + 1 || record.previousHash !== previousHash) {
      throw new TypeError("records do not begin at the epoch anchor");
    }
    previousSequence = record.sequence;
    previousHash = record.hash;
  }
  return { previousHash: input.records[0]!.previousHash, checkpointHash };
}

/** Rejects malformed checkpoint identities before they can steer a provider key lookup. */
function assertRecoverableCheckpoint(checkpoint: RetentionCheckpoint): void {
  const verification = verifyRetentionCheckpoint(checkpoint);
  if (!verification.ok) throw new TypeError(`invalid retention checkpoint: ${verification.reason}`);
}

/** Requires recovered derived metadata to bind the complete authoritative checkpoint anchor. */
function assertManifestCheckpointBinding(
  manifest: RetentionStagingManifest,
  checkpoint: RetentionCheckpoint,
): void {
  if (
    manifest.tenantId !== checkpoint.tenantId ||
    manifest.epoch !== checkpoint.epoch ||
    manifest.fromSequence !== checkpoint.fromSequence ||
    manifest.fromPreviousHash !== checkpoint.fromPreviousHash ||
    manifest.throughSequence !== checkpoint.throughSequence ||
    manifest.throughHash !== checkpoint.throughHash ||
    manifest.recordCount !== checkpoint.recordCount ||
    manifest.previousCheckpointHash !== checkpoint.previousCheckpointHash ||
    manifest.archiveRootHash !== checkpoint.archiveRootHash
  ) {
    throw new TypeError("staged epoch manifest checkpoint mismatch");
  }
}

/** Writes bytes only when the deterministic key is absent or already byte-identical. */
async function putExact(client: RetentionStagingClient, key: string, body: Uint8Array): Promise<void> {
  const existing = await client.get(key);
  if (existing !== null) {
    if (!bytesEqual(existing, body)) throw new TypeError("staged epoch object conflict");
    return;
  }
  await client.put(key, body);
}

/** Encodes exact canonical record bytes as newline-terminated opaque NDJSON lines. */
function encodeNdjson(records: readonly AuditRecord[]): Uint8Array {
  return new TextEncoder().encode(`${records.map((record) => canonicalJson(record)).join("\n")}\n`);
}

/** Parses NDJSON only when every line is exact canonical JSON for a tenant-scoped hash-valid record. */
function parseExactNdjson(body: Uint8Array, tenantId: string): AuditRecord[] {
  const text = new TextDecoder().decode(body);
  if (!text.endsWith("\n")) throw new TypeError("staged epoch segment integrity check failed");
  const lines = text.slice(0, -1).split("\n");
  if (lines.length === 0 || lines.some((line) => line.length === 0)) {
    throw new TypeError("staged epoch segment integrity check failed");
  }
  return lines.map((line) => {
    let record: AuditRecord;
    try {
      record = JSON.parse(line) as AuditRecord;
    } catch {
      throw new TypeError("staged epoch record integrity check failed");
    }
    if (
      record.event.scope?.tenantId !== tenantId ||
      canonicalJson(record) !== line ||
      hashAuditRecord(record) !== record.hash
    ) {
      throw new TypeError("staged epoch record integrity check failed");
    }
    return record;
  });
}

/** Selects only portable descriptor fields before hashing the ordered array. */
function providerNeutralDescriptor(segment: RetentionStagingSegment): RetentionStagingSegmentDescriptor {
  return {
    fromSequence: segment.fromSequence,
    toSequence: segment.toSequence,
    recordCount: segment.recordCount,
    firstPreviousHash: segment.firstPreviousHash,
    lastHash: segment.lastHash,
    contentSha256: segment.contentSha256,
  };
}

/** Strictly validates stored manifest shape, continuity, digests, and deterministic physical keys. */
function validateManifest(manifest: RetentionStagingManifest, prefix: string): void {
  if (!isPlainObject(manifest) || !hasOnlyKeys(manifest, MANIFEST_KEYS)) {
    throw new TypeError("staged epoch manifest is invalid");
  }
  assertId(manifest.tenantId, "tenantId");
  assertPositiveSafeInteger(manifest.epoch, "epoch");
  assertPositiveSafeInteger(manifest.fromSequence, "fromSequence");
  assertPositiveSafeInteger(manifest.throughSequence, "throughSequence");
  assertPositiveSafeInteger(manifest.recordCount, "recordCount");
  assertNullableHash(manifest.fromPreviousHash, "fromPreviousHash");
  assertHash(manifest.throughHash, "throughHash");
  assertNullableHash(manifest.previousCheckpointHash, "previousCheckpointHash");
  assertHash(manifest.archiveRootHash, "archiveRootHash");
  if (manifest.recordType !== "retention.staging.manifest" || manifest.schemaVersion !== "1.0") {
    throw new TypeError("staged epoch manifest protocol is unsupported");
  }
  if (
    !Array.isArray(manifest.segments) ||
    manifest.segments.length === 0 ||
    manifest.throughSequence < manifest.fromSequence
  ) {
    throw new TypeError("staged epoch manifest range is invalid");
  }
  const expectedEpochPrefix = epochKeyPrefix(prefix, manifest.tenantId, manifest.epoch);
  if (manifest.manifestKey !== `${expectedEpochPrefix}/manifest.json`) {
    throw new TypeError("staged epoch manifest key is invalid");
  }

  let sequence = manifest.fromSequence;
  let previousHash = manifest.fromPreviousHash;
  let count = 0;
  for (const segment of manifest.segments) {
    if (!isPlainObject(segment) || !hasOnlyKeys(segment, SEGMENT_KEYS)) {
      throw new TypeError("staged epoch segment descriptor is invalid");
    }
    assertPositiveSafeInteger(segment.fromSequence, "segment.fromSequence");
    assertPositiveSafeInteger(segment.toSequence, "segment.toSequence");
    assertPositiveSafeInteger(segment.recordCount, "segment.recordCount");
    assertNullableHash(segment.firstPreviousHash, "segment.firstPreviousHash");
    assertHash(segment.lastHash, "segment.lastHash");
    assertHash(segment.contentSha256, "segment.contentSha256");
    if (
      segment.fromSequence !== sequence ||
      segment.firstPreviousHash !== previousHash ||
      segment.toSequence < segment.fromSequence ||
      segment.recordCount !== segment.toSequence - segment.fromSequence + 1
    ) {
      throw new TypeError("staged epoch segment descriptors are not contiguous");
    }
    const expectedKey = `${expectedEpochPrefix}/${padSequence(segment.fromSequence)}-${padSequence(segment.toSequence)}.ndjson`;
    if (segment.objectKey !== expectedKey) throw new TypeError("staged epoch segment key is invalid");
    sequence = segment.toSequence + 1;
    previousHash = segment.lastHash;
    count += segment.recordCount;
  }
  if (
    sequence - 1 !== manifest.throughSequence ||
    previousHash !== manifest.throughHash ||
    count !== manifest.recordCount ||
    count !== manifest.throughSequence - manifest.fromSequence + 1
  ) {
    throw new TypeError("staged epoch manifest boundary mismatch");
  }
  const root = sha256Text(canonicalJson(manifest.segments.map(providerNeutralDescriptor)));
  if (root !== manifest.archiveRootHash) throw new TypeError("staged epoch archive root mismatch");
}

/** Parses a canonical stored manifest before its keys can steer provider operations. */
function parseManifest(text: string, prefix: string): RetentionStagingManifest {
  let parsed: RetentionStagingManifest;
  try {
    parsed = JSON.parse(text) as RetentionStagingManifest;
  } catch {
    throw new TypeError("staged epoch manifest integrity check failed");
  }
  if (canonicalJson(parsed) !== text) throw new TypeError("staged epoch manifest integrity check failed");
  validateManifest(parsed, prefix);
  return parsed;
}

/** Returns a detached copy so callers cannot mutate internal or replayed manifest state. */
function cloneManifest(manifest: RetentionStagingManifest): RetentionStagingManifest {
  return {
    ...manifest,
    segments: manifest.segments.map((segment) => ({ ...segment })),
  };
}

/** Builds a deterministic key prefix for exactly one tenant audit epoch. */
function epochKeyPrefix(prefix: string, tenantId: string, epoch: number): string {
  return `${prefix}/${encodeURIComponent(tenantId)}/audit/epoch-${padSequence(epoch)}`;
}

/** Rejects prefixes that could blur namespaces or steer storage outside the injected root. */
function validatePrefix(value: string): string {
  if (
    !PREFIX_PATTERN.test(value) ||
    value.startsWith("/") ||
    value.endsWith("/") ||
    value.includes("//") ||
    value.split("/").some((segment) => segment === "..")
  ) {
    throw new TypeError("retention staging prefix is invalid");
  }
  return value;
}

/** Requires the bounded portable identifier alphabet used by retention protocol records. */
function assertId(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw new TypeError(`${field} is invalid`);
}

/** Requires positive exact integers shared by the language-neutral protocol. */
function assertPositiveSafeInteger(value: unknown, field: string): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${field} must be a positive safe integer`);
  }
}

/** Requires the protocol's bare lowercase SHA-256 representation. */
function assertHash(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) throw new TypeError(`${field} must be lowercase sha256`);
}

/** Validates nullable chain anchors without accepting empty sentinels. */
function assertNullableHash(value: unknown, field: string): void {
  if (value !== null) assertHash(value, field);
}

/** Narrows JSON-derived values before strict enumerable-key checks. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Enforces schema-style additionalProperties false at the staging boundary. */
function hasOnlyKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  const keys = Reflect.ownKeys(value).filter((key) => Object.prototype.propertyIsEnumerable.call(value, key));
  return keys.length === allowed.size && keys.every((key) => typeof key === "string" && allowed.has(key));
}

/** Compares provider-returned bytes without decoding or normalizing them. */
function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/** Computes the provider-neutral lowercase SHA-256 digest of canonical descriptor JSON. */
function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Computes the lowercase SHA-256 digest of exact provider bytes. */
function sha256Bytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Left-pads positive sequence and epoch values so key order is numeric order. */
function padSequence(value: number): string {
  return String(value).padStart(SEQUENCE_PAD, "0");
}
