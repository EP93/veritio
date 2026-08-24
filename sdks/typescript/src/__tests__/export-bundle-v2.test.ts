import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { join } from "node:path";
import {
  buildExportBundleV2,
  canonicalJson,
  computeRootHash,
  type ExportBundleV2,
  parseExportBundle,
  serializeExportBundle,
  verifyExportBundle,
} from "../index";

const CONFORMANCE_DIR = join(import.meta.dir, "../../../../spec/conformance");

/** Loads a committed conformance artifact without regenerating its expectations. */
async function fixture(name: string): Promise<any> {
  return Bun.file(join(CONFORMANCE_DIR, name)).json();
}

/** Deep-clones untrusted fixture data before a negative test mutates it. */
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
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
  bundle.manifest.rootHash = await computeRootHash(bundle.manifest.files);
}

describe("vevb-2 checkpoint-aware export", () => {
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
