import { describe, expect, test } from "bun:test";
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { join } from "node:path";
import {
  buildExportBundleV2,
  canonicalJson,
  computeRootHash,
  createRetentionCheckpoint,
  createRetentionDisposition,
  type ExportBundleV2,
  hashAuditRecord,
  hashEvidenceEdgeRecord,
  parseExportBundle,
  serializeExportBundle,
  verifyExportBundle,
} from "../index";

const CONFORMANCE_DIR = join(import.meta.dir, "../../../../spec/conformance");
const V2_PATHS = [
  "records/audit-events.jsonl",
  "records/evidence-edges.jsonl",
  "records/commits.jsonl",
  "records/retention-checkpoints.jsonl",
  "records/retention-dispositions.jsonl",
  "verification.json",
] as const;

/** Loads a committed conformance artifact without regenerating its expectations. */
async function fixture(name: string): Promise<any> {
  return Bun.file(join(CONFORMANCE_DIR, name)).json();
}

/** Deep-clones untrusted fixture data before a negative test mutates it. */
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** Verifies Ed25519 retention signatures from the protocol's raw 32-byte public key form. */
function ed25519Verifier(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean {
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const key = createPublicKey({ key: Buffer.concat([spkiPrefix, publicKey]), format: "der", type: "spki" });
  return verify(null, message, key, signature);
}

/** Parses one canonical JSONL file into record objects for builder tests. */
function records(bundle: ExportBundleV2, path: string): unknown[] {
  const payload = bundle.files[path];
  if (!payload) return [];
  return payload
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
}

/** Rebinds one changed file into the manifest so semantic verification is isolated from file integrity. */
async function rebindFile(bundle: ExportBundleV2, path: string): Promise<void> {
  const entry = bundle.manifest.files.find((candidate) => candidate.path === path);
  if (!entry) throw new Error(`missing ${path}`);
  entry.sha256 = createHash("sha256")
    .update(bundle.files[path] ?? "")
    .digest("hex");
  entry.records = bundle.files[path] ? bundle.files[path]!.trimEnd().split("\n").length : 0;
  (entry as any).bytes = new TextEncoder().encode(bundle.files[path] ?? "").byteLength;
  bundle.manifest.rootHash = await computeRootHash(bundle.manifest.files);
}

/** Rebinds a semantically mutated record and all outer file/manifest hashes. */
async function rebindRecord(
  bundle: ExportBundleV2,
  path: "records/audit-events.jsonl" | "records/evidence-edges.jsonl",
  mutate: (record: any) => void,
): Promise<void> {
  const record = JSON.parse(bundle.files[path]!.trim());
  mutate(record);
  delete record.hash;
  record.hash = path === "records/audit-events.jsonl" ? hashAuditRecord(record) : hashEvidenceEdgeRecord(record);
  bundle.files[path] = `${canonicalJson(record)}\n`;
  await rebindFile(bundle, path);
}

describe("vevb-2 checkpoint-aware export", () => {
  test("direct verification rejects an unknown bundle discriminator instead of treating it as vevb-1", async () => {
    const data = await fixture("export-bundle-golden.json");
    const unknown = { ...clone(data.bundle), bundleVersion: "vevb-3" };
    await expect(verifyExportBundle(unknown as never)).rejects.toThrow(
      'verifyExportBundle: unsupported bundleVersion "vevb-3"',
    );
  });

  test("v2 parsing rejects open or malformed container and manifest shapes", async () => {
    const data = await fixture("export-bundle-v2-golden.json");
    const base = data.bundle as ExportBundleV2;
    for (const invalid of [
      { ...clone(base), hostedProjectId: "hosted_only" },
      { ...clone(base), files: [] },
      { ...clone(base), manifest: { ...clone(base.manifest), hostedRegion: "private" } },
      { ...clone(base), manifest: { ...clone(base.manifest), chainClaims: [] } },
    ]) {
      expect(() => parseExportBundle(JSON.stringify(invalid))).toThrow("export bundle: invalid vevb-2 container");
    }
  });

  test("malformed descriptor arrays return sanitized invalid results without throwing", async () => {
    const data = await fixture("export-bundle-v2-golden.json");
    const base = data.bundle as ExportBundleV2;
    for (const files of [null, [null], [{}]]) {
      const malformed = clone(base) as any;
      malformed.manifest.files = files;
      const report = await verifyExportBundle(malformed);
      expect(report.valid).toBe(false);
      expect(report.checks.structure).toBe(false);
      expect(report.issues).toEqual(["vevb-2 structure or chain claims are invalid"]);
      expect(() => parseExportBundle(JSON.stringify(malformed))).toThrow("export bundle: invalid vevb-2 container");
    }
  });

  test("rejects open or incomplete audit and edge envelopes and nested protocol records after hashes are rebound", async () => {
    const data = await fixture("export-bundle-v2-golden.json");
    const base = data.bundle as ExportBundleV2;
    const auditMutations: Array<(record: any) => void> = [
      (record) => delete record.appendedAt,
      (record) => {
        record.event.hostedProjectId = "hosted_only";
      },
      (record) => delete record.event.metadata,
      (record) => {
        record.event.actor.hostedUserId = "hosted_only";
      },
      (record) => delete record.event.actor.id,
    ];
    for (const mutate of auditMutations) {
      const bundle = clone(base);
      await rebindRecord(bundle, "records/audit-events.jsonl", mutate);
      expect((await verifyExportBundle(bundle)).checks.audit).toBe(false);
    }

    const edgeMutations: Array<(record: any) => void> = [
      (record) => delete record.appendedAt,
      (record) => {
        record.edge.hostedRegion = "private";
      },
      (record) => delete record.edge.metadata,
      (record) => {
        record.edge.from.hostedEntityId = "hosted_only";
      },
      (record) => delete record.edge.to.id,
    ];
    for (const mutate of edgeMutations) {
      const bundle = clone(base);
      await rebindRecord(bundle, "records/evidence-edges.jsonl", mutate);
      expect((await verifyExportBundle(bundle)).checks.edges).toBe(false);
    }
  });

  test("schema and runtime require exactly one descriptor for each mandatory v2 path", async () => {
    const schema = await Bun.file(join(import.meta.dir, "../../../../spec/export-bundle-v2.schema.json")).json();
    const descriptorSchema = schema.$defs.manifest.properties.files;
    expect(descriptorSchema.items.properties.path.enum).toEqual(V2_PATHS);
    expect(descriptorSchema.allOf.map((rule: any) => rule.contains.properties.path.const)).toEqual(V2_PATHS);
    expect(descriptorSchema.allOf.every((rule: any) => rule.minContains === 1 && rule.maxContains === 1)).toBe(true);

    const data = await fixture("export-bundle-v2-golden.json");
    const duplicate = clone(data.bundle as ExportBundleV2);
    duplicate.manifest.files[5]!.path = V2_PATHS[0];
    delete duplicate.files[V2_PATHS[5]];
    duplicate.files["records/hosted-only.jsonl"] = "";
    expect(() => parseExportBundle(JSON.stringify(duplicate))).toThrow("export bundle: invalid vevb-2 container");
  });

  test("binds exact UTF-8 byte sizes for all six files and reserves zero records for verification.json", async () => {
    const data = await fixture("export-bundle-v2-golden.json");
    const base = data.bundle as ExportBundleV2;
    expect(base.manifest.files.map((entry: any) => entry.bytes)).toEqual(
      base.manifest.files.map((entry) => new TextEncoder().encode(base.files[entry.path]!).byteLength),
    );

    const wrongBytes = clone(base) as any;
    wrongBytes.manifest.files[0].bytes += 1;
    wrongBytes.manifest.rootHash = await computeRootHash(wrongBytes.manifest.files);
    expect((await verifyExportBundle(wrongBytes)).checks.integrity).toBe(false);

    const verificationRecords = clone(base);
    verificationRecords.manifest.files.find((entry) => entry.path === "verification.json")!.records = 1;
    verificationRecords.manifest.rootHash = await computeRootHash(verificationRecords.manifest.files);
    expect((await verifyExportBundle(verificationRecords)).checks.structure).toBe(false);
  });

  test("uses one exact UTC-millisecond calendar timestamp contract in schema and runtime", async () => {
    const data = await fixture("export-bundle-v2-golden.json");
    const base = data.bundle as ExportBundleV2;
    const invalid = [
      "0000-02-29T00:00:00.000Z",
      "2026-08-24",
      "2026-02-30T00:00:00.000Z",
      "2026-08-24T00:00:00Z",
      "2026-08-24T07:00:00.000+07:00",
    ];
    for (const createdAt of invalid) {
      const bundle = clone(base);
      bundle.manifest.createdAt = createdAt;
      expect(() => parseExportBundle(JSON.stringify(bundle))).toThrow("export bundle: invalid vevb-2 container");
    }

    const schema = await Bun.file(join(import.meta.dir, "../../../../spec/export-bundle-v2.schema.json")).json();
    const timestampPattern = new RegExp(schema.$defs.timestamp.pattern);
    expect(invalid.every((value) => !timestampPattern.test(value))).toBe(true);
    expect(timestampPattern.test("2024-02-29T23:59:59.999Z")).toBe(true);
  });

  test("parses and verifies the pinned checkpoint-aware fixture", async () => {
    const data = await fixture("export-bundle-v2-golden.json");
    const bundle = parseExportBundle(JSON.stringify(data.bundle));
    expect(bundle.bundleVersion).toBe("vevb-2");
    expect((await verifyExportBundle(bundle)).valid).toBe(true);
  });

  test("directly rejects the self-contained tampered checkpoint fixture", async () => {
    const data = await fixture("export-bundle-v2-tampered.json");
    const bundle = parseExportBundle(JSON.stringify(data.bundle));
    const report = await verifyExportBundle(bundle);
    expect(report.valid).toBe(data.expected.valid);
    expect(report.checks.integrity).toBe(data.expected.integrity);
    expect("checkpoints" in report.checks && report.checks.checkpoints).toBe(data.expected.checkpoints);
  });

  test("builder reproduces the literal fixture and refuses implicit or partial checkpoint claims", async () => {
    const data = await fixture("export-bundle-v2-golden.json");
    const expected = data.bundle as ExportBundleV2;
    const input = {
      scope: expected.manifest.scope,
      range: expected.manifest.range,
      producer: expected.manifest.producer,
      createdAt: expected.manifest.createdAt,
      auditOrigin: expected.manifest.chainClaims.audit.origin,
      events: records(expected, "records/audit-events.jsonl"),
      edges: records(expected, "records/evidence-edges.jsonl"),
      commits: records(expected, "records/commits.jsonl"),
      checkpoints: records(expected, "records/retention-checkpoints.jsonl"),
      dispositions: records(expected, "records/retention-dispositions.jsonl"),
    };
    expect(await buildExportBundleV2(input)).toEqual(expected);
    await expect(buildExportBundleV2({ ...input, auditOrigin: undefined as never })).rejects.toThrow();
    await expect(buildExportBundleV2({ ...input, checkpoints: input.checkpoints.slice(1) })).rejects.toThrow();
    await expect(buildExportBundleV2({ ...input, commits: [{}] })).rejects.toThrow();
  });

  test("round-trips signed checkpoint and disposition claims under caller-trusted retention keys", async () => {
    const base = (await fixture("export-bundle-v2-golden.json")).bundle as ExportBundleV2;
    const checkpointFixture = await fixture("retention-checkpoints.json");
    const dispositionFixture = await fixture("retention-dispositions.json");
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
    const trustedPublicKey = Uint8Array.from(publicKeyDer.subarray(-32));
    const fingerprint = createHash("sha256").update(trustedPublicKey).digest("hex");
    const signatureShell = {
      algorithm: "ed25519" as const,
      publicKeyFingerprint: fingerprint,
      signature: Buffer.alloc(64).toString("base64"),
    };
    const checkpointInput = {
      ...checkpointFixture.cases[0].input,
      signaturePublicKeyFingerprint: fingerprint,
    };
    const checkpointToSign = createRetentionCheckpoint(checkpointInput, signatureShell);
    const checkpoint = createRetentionCheckpoint(checkpointInput, {
      ...signatureShell,
      signature: sign(null, Buffer.from(checkpointToSign.hash), privateKey).toString("base64"),
    });
    const dispositionInput = {
      ...dispositionFixture.cases[0].input,
      checkpointHash: checkpoint.hash,
      fromSequence: checkpoint.fromSequence,
      throughSequence: checkpoint.throughSequence,
      archiveRootHash: checkpoint.archiveRootHash,
      signaturePublicKeyFingerprint: fingerprint,
    };
    const dispositionToSign = createRetentionDisposition(dispositionInput, signatureShell);
    const disposition = createRetentionDisposition(dispositionInput, {
      ...signatureShell,
      signature: sign(null, Buffer.from(dispositionToSign.hash), privateKey).toString("base64"),
    });
    const bundle = await buildExportBundleV2({
      scope: base.manifest.scope,
      range: base.manifest.range,
      producer: base.manifest.producer,
      createdAt: base.manifest.createdAt,
      auditOrigin: { kind: "checkpoint", checkpointHash: checkpoint.hash },
      events: checkpointFixture.retainedRecords,
      edges: records(base, "records/evidence-edges.jsonl"),
      commits: [],
      checkpoints: [checkpoint],
      dispositions: [disposition],
    });
    const trusted = await verifyExportBundle(bundle, {
      retention: { trustedPublicKey, signatureVerifier: ed25519Verifier, requireSignature: true },
    });

    expect(trusted.valid).toBe(true);
    expect(trusted.retentionSignatures).toEqual({ checkpoints: "valid", dispositions: "valid" });

    const mismatched = await verifyExportBundle(bundle, {
      retention: { trustedPublicKey: new Uint8Array(32), signatureVerifier: ed25519Verifier, requireSignature: true },
    });
    expect(mismatched.valid).toBe(false);
    expect(mismatched.retentionSignatures).toEqual({ checkpoints: "invalid", dispositions: "invalid" });

    const unknown = await verifyExportBundle(bundle, { retention: { requireSignature: true } });
    expect(unknown.valid).toBe(false);
    expect(unknown.retentionSignatures).toEqual({ checkpoints: "skipped", dispositions: "skipped" });
  });

  test("fails closed on checkpoint, disposition, audit-tail, edge, commit, and manifest tampering", async () => {
    const data = await fixture("export-bundle-v2-golden.json");
    const base = data.bundle as ExportBundleV2;

    const checkpoint = clone(base);
    checkpoint.files["records/retention-checkpoints.jsonl"] = checkpoint.files[
      "records/retention-checkpoints.jsonl"
    ]!.replace('"throughHash":"6417', '"throughHash":"7417');
    await rebindFile(checkpoint, "records/retention-checkpoints.jsonl");
    expect((await verifyExportBundle(checkpoint)).checks.checkpoints).toBe(false);

    const disposition = clone(base);
    disposition.files["records/retention-dispositions.jsonl"] +=
      disposition.files["records/retention-dispositions.jsonl"]!.split("\n")[0] + "\n";
    await rebindFile(disposition, "records/retention-dispositions.jsonl");
    expect((await verifyExportBundle(disposition)).checks.dispositions).toBe(false);

    const audit = clone(base);
    audit.files["records/audit-events.jsonl"] = audit.files["records/audit-events.jsonl"]!.replace(
      '"previousHash":"6417',
      '"previousHash":"7417',
    );
    await rebindFile(audit, "records/audit-events.jsonl");
    expect((await verifyExportBundle(audit)).checks.audit).toBe(false);

    const edge = clone(base);
    edge.files["records/evidence-edges.jsonl"] = edge.files["records/evidence-edges.jsonl"]!.replace(
      '"previousHash":null',
      `"previousHash":"${"f".repeat(64)}"`,
    );
    await rebindFile(edge, "records/evidence-edges.jsonl");
    expect((await verifyExportBundle(edge)).checks.edges).toBe(false);

    const commit = clone(base);
    commit.files["records/commits.jsonl"] = "{}\n";
    await rebindFile(commit, "records/commits.jsonl");
    expect((await verifyExportBundle(commit)).checks.commits).toBe(false);

    const manifest = clone(base);
    manifest.manifest.chainClaims.audit.origin = { kind: "genesis" };
    expect((await verifyExportBundle(manifest)).checks.structure).toBe(false);
  });

  test("requires exact closed v2 shapes, supported algorithms, and an explicit origin", async () => {
    const data = await fixture("export-bundle-v2-golden.json");
    const base = data.bundle as ExportBundleV2;
    for (const mutated of [
      { ...clone(base), unknown: true },
      { ...clone(base), manifest: { ...clone(base.manifest), unknown: true } },
      { ...clone(base), manifest: { ...clone(base.manifest), chainClaims: undefined } },
      {
        ...clone(base),
        manifest: {
          ...clone(base.manifest),
          chainClaims: {
            ...clone(base.manifest.chainClaims),
            evidenceEdges: { origin: { kind: "checkpoint" }, completeness: "full" },
          },
        },
      },
    ]) {
      expect((await verifyExportBundle(mutated as ExportBundleV2)).checks.structure).toBe(false);
    }

    const unsupported = clone(base);
    unsupported.files["records/retention-checkpoints.jsonl"] = unsupported.files[
      "records/retention-checkpoints.jsonl"
    ]!.replace('"hashAlgorithm":"sha256"', '"hashAlgorithm":"sha512"');
    await rebindFile(unsupported, "records/retention-checkpoints.jsonl");
    expect((await verifyExportBundle(unsupported)).checks.checkpoints).toBe(false);

    const unknownEnvelope = clone(base);
    const auditRecord = JSON.parse(unknownEnvelope.files["records/audit-events.jsonl"]!.trim());
    auditRecord.hostedProjectId = "hosted_only";
    unknownEnvelope.files["records/audit-events.jsonl"] = `${canonicalJson(auditRecord)}\n`;
    await rebindFile(unknownEnvelope, "records/audit-events.jsonl");
    expect((await verifyExportBundle(unknownEnvelope)).checks.audit).toBe(false);

    const noncanonical = clone(base);
    noncanonical.files["records/audit-events.jsonl"] = noncanonical.files["records/audit-events.jsonl"]!.replace(
      '{"appendedAt"',
      '{ "appendedAt"',
    );
    await rebindFile(noncanonical, "records/audit-events.jsonl");
    expect((await verifyExportBundle(noncanonical)).checks.integrity).toBe(false);

    const malformedDisposition = clone(base);
    malformedDisposition.files["records/retention-dispositions.jsonl"] = "null\n";
    await rebindFile(malformedDisposition, "records/retention-dispositions.jsonl");
    expect((await verifyExportBundle(malformedDisposition)).checks.dispositions).toBe(false);

    const signedShape = clone(base) as any;
    signedShape.manifest.signaturePublicKeyFingerprint = "f".repeat(64);
    signedShape.signature = {
      algorithm: "rsa-pss",
      publicKeyFingerprint: "f".repeat(64),
      signature: "AA==",
    };
    expect((await verifyExportBundle(signedShape)).checks.structure).toBe(false);
  });

  test("accepts a checkpoint anchor with an empty complete tail only when the latest anchor matches", async () => {
    const data = await fixture("export-bundle-v2-golden.json");
    const base = data.bundle as ExportBundleV2;
    const empty = await buildExportBundleV2({
      scope: base.manifest.scope,
      range: base.manifest.range,
      producer: base.manifest.producer,
      createdAt: base.manifest.createdAt,
      auditOrigin: base.manifest.chainClaims.audit.origin,
      events: [],
      edges: records(base, "records/evidence-edges.jsonl"),
      commits: [],
      checkpoints: records(base, "records/retention-checkpoints.jsonl"),
      dispositions: [],
    });
    expect((await verifyExportBundle(empty)).valid).toBe(true);

    const wrongAnchor = clone(empty);
    if (wrongAnchor.manifest.chainClaims.audit.origin.kind !== "checkpoint") throw new Error("expected checkpoint");
    wrongAnchor.manifest.chainClaims.audit.origin.checkpointHash = "f".repeat(64);
    expect((await verifyExportBundle(wrongAnchor)).checks.structure).toBe(false);
  });

  test("keeps the existing vevb-1 golden container bytes literal", async () => {
    const data = await fixture("export-bundle-golden.json");
    const bytes = canonicalJson(data.bundle);
    expect(bytes.length).toBe(3840);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(
      "705962e1d6538c605598858fdcedcea64c2d7bba4781fb857b993ddc64f36095",
    );
    expect(data.bundle.manifest.rootHash).toBe("1b8a06a80fc04e25260ad385628d1a5a66596555929425a6976d1dccdb313f5f");
    expect(serializeExportBundle(data.bundle)).toBe(bytes);
  });
});
