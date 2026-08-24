import type {
  ExportBundleFileEntry,
  ExportBundleManifest,
  ExportBundleSignature,
  ExportBundleVerificationOptions,
} from "./export-bundle.js";
import { canonicalJson, sha256Hex, verifyCommitChain, verifyEdgeChain } from "./export-bundle-deps.js";
import type { AuditRecord, EvidenceEdgeRecord } from "./index.js";
import { verifyAuditRecords } from "./index.js";
import {
  type RetentionCheckpoint,
  type RetentionDisposition,
  type RetentionSignatureStatus,
  type RetentionVerificationOptions,
  verifyAuditRecordsFromCheckpoint,
  verifyRetentionCheckpointChain,
  verifyRetentionDisposition,
} from "./retention.js";

export type AuditOriginClaim = { kind: "genesis" } | { kind: "checkpoint"; checkpointHash: string };
export type GenesisOriginClaim = { kind: "genesis" };

export interface ExportBundleV2ChainClaims {
  audit:
    | { origin: { kind: "genesis" }; completeness: "full" }
    | { origin: { kind: "checkpoint"; checkpointHash: string }; completeness: "complete-retained-tail" };
  evidenceEdges: { origin: GenesisOriginClaim; completeness: "full" };
  evidenceCommits: { origin: GenesisOriginClaim; completeness: "empty" };
}

export interface ExportBundleV2Manifest {
  bundleVersion: "vevb-2";
  createdAt: string;
  scope: ExportBundleManifest["scope"];
  range: ExportBundleManifest["range"];
  producer: ExportBundleManifest["producer"];
  chainClaims: ExportBundleV2ChainClaims;
  files: ExportBundleFileEntry[];
  rootHash: string;
  signaturePublicKeyFingerprint?: string;
}

export interface ExportBundleV2 {
  bundleVersion: "vevb-2";
  manifest: ExportBundleV2Manifest;
  files: Record<string, string>;
  signature?: ExportBundleSignature;
}

export interface ExportBundleV2Input {
  scope: ExportBundleV2Manifest["scope"];
  range: ExportBundleV2Manifest["range"];
  producer: ExportBundleV2Manifest["producer"];
  createdAt: string;
  auditOrigin: AuditOriginClaim;
  events: unknown[];
  edges: unknown[];
  commits?: unknown[];
  checkpoints: unknown[];
  dispositions?: unknown[];
}

export interface ExportBundleV2VerificationReport {
  valid: boolean;
  checks: {
    structure: boolean;
    integrity: boolean;
    checkpoints: boolean;
    dispositions: boolean;
    audit: boolean;
    edges: boolean;
    commits: boolean;
    signature: "valid" | "invalid" | "absent" | "skipped";
  };
  issues: string[];
}

interface EmbeddedV2Verification {
  checkpoints: { valid: boolean; signature: RetentionSignatureStatus };
  dispositions: { valid: boolean; signature: RetentionSignatureStatus };
  audit: { valid: boolean };
  edges: { valid: boolean };
  commits: { valid: boolean };
}

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const CONTAINER_KEYS = new Set(["bundleVersion", "manifest", "files", "signature"]);
const MANIFEST_KEYS = new Set([
  "bundleVersion",
  "createdAt",
  "scope",
  "range",
  "producer",
  "chainClaims",
  "files",
  "rootHash",
  "signaturePublicKeyFingerprint",
]);
const SCOPE_KEYS = new Set(["tenantId", "workspaceId", "environment"]);
const RANGE_KEYS = new Set(["from", "to"]);
const PRODUCER_KEYS = new Set(["authority", "kind", "type", "id"]);
const CLAIM_KEYS = new Set(["audit", "evidenceEdges", "evidenceCommits"]);
const CHAIN_CLAIM_KEYS = new Set(["origin", "completeness"]);
const GENESIS_ORIGIN_KEYS = new Set(["kind"]);
const CHECKPOINT_ORIGIN_KEYS = new Set(["kind", "checkpointHash"]);
const FILE_ENTRY_KEYS = new Set(["path", "sha256", "records"]);
const SIGNATURE_KEYS = new Set(["algorithm", "publicKeyFingerprint", "signature"]);
const AUDIT_RECORD_KEYS = new Set([
  "event",
  "sequence",
  "previousHash",
  "hashAlgorithm",
  "canonicalization",
  "appendedAt",
  "idempotencyKeyHash",
  "hash",
]);
const EDGE_RECORD_KEYS = new Set([
  "edge",
  "sequence",
  "previousHash",
  "hashAlgorithm",
  "canonicalization",
  "appendedAt",
  "idempotencyKeyHash",
  "hash",
]);
const BASE64_SIGNATURE_PATTERN = /^[A-Za-z0-9+/]{86}==$/;
const RECORD_PATHS = [
  "records/audit-events.jsonl",
  "records/evidence-edges.jsonl",
  "records/commits.jsonl",
  "records/retention-checkpoints.jsonl",
  "records/retention-dispositions.jsonl",
] as const;
const REQUIRED_PATHS = [...RECORD_PATHS, "verification.json"] as const;

/**
 * Builds the closed vevb-2 container from host-injected records and an explicit
 * audit origin. Checkpoint claims must include every epoch from one through the
 * selected latest anchor; genesis claims must carry no retention records.
 */
export async function buildExportBundleV2(input: ExportBundleV2Input): Promise<ExportBundleV2> {
  const commits = input.commits ?? [];
  const dispositions = input.dispositions ?? [];
  if (!isAuditOrigin(input.auditOrigin)) throw new TypeError("export bundle v2: auditOrigin is required");
  if (
    !validScope(input.scope) ||
    !validRange(input.range) ||
    !validTimestamp(input.createdAt) ||
    !validProducer(input.producer)
  ) {
    throw new TypeError("export bundle v2: invalid manifest input");
  }
  if (commits.length !== 0) throw new TypeError("export bundle v2: EvidenceCommit records must be empty");

  const checkpoints = input.checkpoints as RetentionCheckpoint[];
  const receipts = dispositions as RetentionDisposition[];
  const checkpointVerdict = verifyCheckpointClaim(input.auditOrigin, checkpoints, input.scope.tenantId);
  if (!checkpointVerdict.valid) throw new TypeError("export bundle v2: incomplete or invalid checkpoint claim");
  const dispositionVerdict = verifyDispositionSet(receipts, checkpoints);
  if (!dispositionVerdict.valid) throw new TypeError("export bundle v2: invalid disposition set");
  const auditValid = verifyAuditClaim(input.auditOrigin, checkpoints, input.events, input.scope.tenantId);
  if (!auditValid) throw new TypeError("export bundle v2: invalid audit selection");
  const edgesValid =
    verifyEdgeChain(input.edges).valid &&
    recordsMatchTenant(input.edges, "edge", input.scope.tenantId) &&
    recordsHaveOnlyEnvelopeKeys(input.edges, EDGE_RECORD_KEYS);
  if (!edgesValid) throw new TypeError("export bundle v2: evidence edges must be a full genesis chain");

  const chainClaims: ExportBundleV2ChainClaims =
    input.auditOrigin.kind === "genesis"
      ? {
          audit: { origin: { kind: "genesis" }, completeness: "full" },
          evidenceEdges: { origin: { kind: "genesis" }, completeness: "full" },
          evidenceCommits: { origin: { kind: "genesis" }, completeness: "empty" },
        }
      : {
          audit: {
            origin: { kind: "checkpoint", checkpointHash: input.auditOrigin.checkpointHash },
            completeness: "complete-retained-tail",
          },
          evidenceEdges: { origin: { kind: "genesis" }, completeness: "full" },
          evidenceCommits: { origin: { kind: "genesis" }, completeness: "empty" },
        };
  const embedded: EmbeddedV2Verification = {
    checkpoints: checkpointVerdict,
    dispositions: dispositionVerdict,
    audit: { valid: auditValid },
    edges: { valid: edgesValid },
    commits: { valid: true },
  };
  const tracked = [
    trackedRecords("records/audit-events.jsonl", input.events),
    trackedRecords("records/evidence-edges.jsonl", input.edges),
    trackedRecords("records/commits.jsonl", commits),
    trackedRecords("records/retention-checkpoints.jsonl", checkpoints),
    trackedRecords("records/retention-dispositions.jsonl", receipts),
    { path: "verification.json", content: canonicalJson(embedded), records: 0 },
  ];
  const files = Object.fromEntries(tracked.map((file) => [file.path, file.content]));
  const manifestFiles = await Promise.all(
    tracked.map(async (file) => ({ path: file.path, sha256: await sha256Hex(file.content), records: file.records })),
  );
  const manifest: ExportBundleV2Manifest = {
    bundleVersion: "vevb-2",
    createdAt: input.createdAt,
    scope: input.scope,
    range: input.range,
    producer: input.producer,
    chainClaims,
    files: manifestFiles,
    rootHash: await computeV2RootHash(manifestFiles),
  };
  return { bundleVersion: "vevb-2", manifest, files };
}

/**
 * Verifies vevb-2 structure, exact bytes, retention anchors and receipts, the
 * anchored audit tail, the genesis edge chain, empty commits, and any detached
 * bundle signature without consulting a hosted service.
 */
export async function verifyExportBundleV2(
  bundle: ExportBundleV2,
  options: ExportBundleVerificationOptions = {},
): Promise<ExportBundleV2VerificationReport> {
  const issues: string[] = [];
  let structure = verifyV2Shape(bundle, issues);
  const signatureVerdict = await verifyV2Signature(bundle, options);
  if (signatureVerdict.issue) issues.push(signatureVerdict.issue);
  if (!structure) return failedV2Report(signatureVerdict.signature, issues);

  const manifest = bundle.manifest;
  const files = bundle.files;
  let integrity = true;
  if ((await computeV2RootHash(manifest.files)) !== manifest.rootHash) {
    integrity = false;
    issues.push("rootHash does not bind the manifest files");
  }
  for (const entry of manifest.files) {
    const payload = files[entry.path];
    if (typeof payload !== "string" || (await sha256Hex(payload)) !== entry.sha256) {
      integrity = false;
      issues.push(`sha256 mismatch for ${entry.path}`);
      continue;
    }
    if (
      (RECORD_PATHS as readonly string[]).includes(entry.path) &&
      splitRecordLines(payload).length !== entry.records
    ) {
      integrity = false;
      issues.push(`record count mismatch for ${entry.path}`);
    }
    if ((RECORD_PATHS as readonly string[]).includes(entry.path) && !isCanonicalJsonLines(payload)) {
      integrity = false;
      issues.push(`non-canonical record bytes for ${entry.path}`);
    }
  }

  const parsed = new Map<string, unknown[]>();
  const unparseable = new Set<string>();
  for (const path of RECORD_PATHS) {
    const value = parseJsonLines(files[path]);
    if (!value) {
      parsed.set(path, []);
      unparseable.add(path);
      issues.push(`unparseable record line in ${path}`);
    } else {
      parsed.set(path, value);
    }
  }
  const checkpoints = (parsed.get("records/retention-checkpoints.jsonl") ?? []) as RetentionCheckpoint[];
  const dispositions = (parsed.get("records/retention-dispositions.jsonl") ?? []) as RetentionDisposition[];
  const events = parsed.get("records/audit-events.jsonl") ?? [];
  const edges = parsed.get("records/evidence-edges.jsonl") ?? [];
  const commits = parsed.get("records/commits.jsonl") ?? [];
  const origin = manifest.chainClaims.audit.origin;
  const checkpointVerdict = verifyCheckpointClaim(origin, checkpoints, manifest.scope.tenantId, options.retention);
  if (origin.kind === "checkpoint" && checkpoints.at(-1)?.hash !== origin.checkpointHash) {
    structure = false;
    issues.push("audit checkpoint origin does not select the latest included checkpoint");
  }
  const dispositionVerdict = verifyDispositionSet(dispositions, checkpoints, options.retention);
  let checkpointOk = checkpointVerdict.valid;
  let dispositionOk = dispositionVerdict.valid;
  let audit = verifyAuditClaim(origin, checkpoints, events, manifest.scope.tenantId, options.retention);
  let edge =
    verifyEdgeChain(edges).valid &&
    recordsMatchTenant(edges, "edge", manifest.scope.tenantId) &&
    recordsHaveOnlyEnvelopeKeys(edges, EDGE_RECORD_KEYS);
  let commit = commits.length === 0 && verifyCommitChain(commits).valid;
  if (unparseable.has("records/retention-checkpoints.jsonl")) checkpointOk = false;
  if (unparseable.has("records/retention-dispositions.jsonl")) dispositionOk = false;
  if (unparseable.has("records/audit-events.jsonl")) audit = false;
  if (unparseable.has("records/evidence-edges.jsonl")) edge = false;
  if (unparseable.has("records/commits.jsonl")) commit = false;

  const embedded = parseEmbedded(files["verification.json"]);
  if (!embedded) {
    checkpointOk = dispositionOk = audit = edge = commit = false;
    issues.push("embedded verification report unreadable");
  } else {
    if (canonicalJson(embedded.checkpoints) !== canonicalJson(checkpointVerdict)) checkpointOk = false;
    if (canonicalJson(embedded.dispositions) !== canonicalJson(dispositionVerdict)) dispositionOk = false;
    if (embedded.audit.valid !== audit) audit = false;
    if (embedded.edges.valid !== edge) edge = false;
    if (embedded.commits.valid !== commit) commit = false;
  }
  if (!checkpointOk) issues.push("checkpoint chain verification failed");
  if (!dispositionOk) issues.push("disposition verification failed");
  if (!audit) issues.push("audit chain verification failed");
  if (!edge) issues.push("evidence-edge chain verification failed");
  if (!commit) issues.push("EvidenceCommit selection must be empty");
  const signatureSatisfied =
    signatureVerdict.signature !== "invalid" && !(options.requireSignature && signatureVerdict.signature === "absent");
  return {
    valid: structure && integrity && checkpointOk && dispositionOk && audit && edge && commit && signatureSatisfied,
    checks: {
      structure,
      integrity,
      checkpoints: checkpointOk,
      dispositions: dispositionOk,
      audit,
      edges: edge,
      commits: commit,
      signature: signatureVerdict.signature,
    },
    issues,
  };
}

/** Serializes one mandatory v2 record file as canonical JSONL. */
function trackedRecords(path: string, records: unknown[]): { path: string; content: string; records: number } {
  return { path, content: records.length ? `${records.map(canonicalJson).join("\n")}\n` : "", records: records.length };
}

/** Computes the format-neutral manifest file-map digest without mutating entries. */
async function computeV2RootHash(files: ExportBundleFileEntry[]): Promise<string> {
  const sorted = [...files].sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  return sha256Hex(canonicalJson(sorted));
}

/** Verifies the origin claim against a complete epoch-one checkpoint chain. */
function verifyCheckpointClaim(
  origin: AuditOriginClaim,
  checkpoints: RetentionCheckpoint[],
  tenantId: string,
  options: RetentionVerificationOptions = {},
): { valid: boolean; signature: RetentionSignatureStatus } {
  if (origin.kind === "genesis") return { valid: checkpoints.length === 0, signature: "absent" };
  if (checkpoints.length === 0) return { valid: false, signature: "absent" };
  const verdict = verifyRetentionCheckpointChain(checkpoints, options);
  const latest = checkpoints[checkpoints.length - 1];
  return {
    valid: verdict.ok && latest?.hash === origin.checkpointHash && latest.tenantId === tenantId,
    signature: verdict.signature,
  };
}

/** Verifies zero or one disposition per included epoch in checkpoint order. */
function verifyDispositionSet(
  dispositions: RetentionDisposition[],
  checkpoints: RetentionCheckpoint[],
  options: RetentionVerificationOptions = {},
): { valid: boolean; signature: RetentionSignatureStatus } {
  let signature: RetentionSignatureStatus = dispositions.length === 0 ? "absent" : "valid";
  let priorIndex = -1;
  const seen = new Set<string>();
  for (const disposition of dispositions) {
    if (!isPlainObject(disposition) || typeof disposition.checkpointHash !== "string") {
      return { valid: false, signature };
    }
    const checkpointIndex = checkpoints.findIndex((checkpoint) => checkpoint?.hash === disposition.checkpointHash);
    if (checkpointIndex < 0 || checkpointIndex <= priorIndex || seen.has(disposition.checkpointHash)) {
      return { valid: false, signature };
    }
    const verdict = verifyRetentionDisposition(disposition, checkpoints[checkpointIndex], options);
    signature = combineSignature(signature, verdict.signature);
    if (!verdict.ok) return { valid: false, signature };
    priorIndex = checkpointIndex;
    seen.add(disposition.checkpointHash);
  }
  return { valid: true, signature };
}

/** Verifies either a genesis audit chain or the exact tail after the latest checkpoint. */
function verifyAuditClaim(
  origin: AuditOriginClaim,
  checkpoints: RetentionCheckpoint[],
  events: unknown[],
  tenantId: string,
  options: RetentionVerificationOptions = {},
): boolean {
  if (!recordsMatchTenant(events, "event", tenantId)) return false;
  if (!recordsHaveOnlyEnvelopeKeys(events, AUDIT_RECORD_KEYS)) return false;
  if (origin.kind === "genesis") {
    try {
      return verifyAuditRecords(events as AuditRecord[]).ok;
    } catch {
      return false;
    }
  }
  const latest = checkpoints[checkpoints.length - 1];
  if (!latest || latest.hash !== origin.checkpointHash) return false;
  try {
    return verifyAuditRecordsFromCheckpoint(latest, events as AuditRecord[], options).ok;
  } catch {
    return false;
  }
}

/** Requires every selected record to carry the manifest tenant at its protocol scope. */
function recordsMatchTenant(records: unknown[], envelope: "event" | "edge", tenantId: string): boolean {
  return records.every(
    (record) =>
      isPlainObject(record) &&
      isPlainObject(record[envelope]) &&
      isPlainObject(record[envelope].scope) &&
      record[envelope].scope.tenantId === tenantId,
  );
}

/** Rejects hosted or unknown envelope fields before protocol hash helpers can ignore them. */
function recordsHaveOnlyEnvelopeKeys(records: unknown[], keys: ReadonlySet<string>): boolean {
  return records.every((record) => isPlainObject(record) && hasOnlyKeys(record, keys));
}

/** Validates every closed v2 container, manifest, claim, and file-map shape. */
function verifyV2Shape(bundle: ExportBundleV2, issues: string[]): boolean {
  if (!isPlainObject(bundle) || !hasOnlyKeys(bundle, CONTAINER_KEYS) || bundle.bundleVersion !== "vevb-2") {
    issues.push("invalid vevb-2 container shape");
    return false;
  }
  const manifest = bundle.manifest;
  const files = bundle.files;
  let valid = isPlainObject(manifest) && hasOnlyKeys(manifest, MANIFEST_KEYS) && isPlainObject(files);
  if (!valid) {
    issues.push("invalid vevb-2 manifest or files shape");
    return false;
  }
  valid =
    manifest.bundleVersion === "vevb-2" &&
    validScope(manifest.scope) &&
    validRange(manifest.range) &&
    validTimestamp(manifest.createdAt) &&
    validProducer(manifest.producer) &&
    validClaims(manifest.chainClaims) &&
    HASH_PATTERN.test(manifest.rootHash) &&
    Array.isArray(manifest.files);
  const paths: string[] = [];
  if (Array.isArray(manifest.files)) {
    for (const entry of manifest.files) {
      if (
        !isPlainObject(entry) ||
        !hasOnlyKeys(entry, FILE_ENTRY_KEYS) ||
        typeof entry.path !== "string" ||
        !HASH_PATTERN.test(String(entry.sha256)) ||
        !Number.isSafeInteger(entry.records) ||
        entry.records < 0 ||
        paths.includes(entry.path)
      )
        valid = false;
      else paths.push(entry.path);
    }
  }
  const fileKeys = Object.keys(files);
  if (
    paths.length !== REQUIRED_PATHS.length ||
    fileKeys.length !== REQUIRED_PATHS.length ||
    REQUIRED_PATHS.some((path) => !paths.includes(path) || !fileKeys.includes(path)) ||
    fileKeys.some((path) => typeof files[path] !== "string")
  )
    valid = false;
  if (Boolean(bundle.signature) !== Boolean(manifest.signaturePublicKeyFingerprint)) valid = false;
  if (
    manifest.signaturePublicKeyFingerprint !== undefined &&
    !HASH_PATTERN.test(manifest.signaturePublicKeyFingerprint)
  )
    valid = false;
  if (
    bundle.signature !== undefined &&
    (!isPlainObject(bundle.signature) ||
      !hasOnlyKeys(bundle.signature, SIGNATURE_KEYS) ||
      bundle.signature.algorithm !== "ed25519" ||
      !HASH_PATTERN.test(String(bundle.signature.publicKeyFingerprint)) ||
      bundle.signature.publicKeyFingerprint !== manifest.signaturePublicKeyFingerprint ||
      typeof bundle.signature.signature !== "string" ||
      !BASE64_SIGNATURE_PATTERN.test(bundle.signature.signature))
  )
    valid = false;
  if (!valid) issues.push("vevb-2 structure or chain claims are invalid");
  return valid;
}

/** Requires the explicit audit/edge/commit claim vocabulary and pairings. */
function validClaims(value: unknown): value is ExportBundleV2ChainClaims {
  if (!isPlainObject(value) || !hasOnlyKeys(value, CLAIM_KEYS)) return false;
  const audit = value.audit;
  const edges = value.evidenceEdges;
  const commits = value.evidenceCommits;
  if (!isPlainObject(audit) || !hasOnlyKeys(audit, CHAIN_CLAIM_KEYS) || !isAuditOrigin(audit.origin)) return false;
  if (audit.origin.kind === "genesis" ? audit.completeness !== "full" : audit.completeness !== "complete-retained-tail")
    return false;
  return isFixedClaim(edges, "full") && isFixedClaim(commits, "empty");
}

/** Requires an exact genesis origin paired with one fixed completeness value. */
function isFixedClaim(value: unknown, completeness: "full" | "empty"): boolean {
  return (
    isPlainObject(value) &&
    hasOnlyKeys(value, CHAIN_CLAIM_KEYS) &&
    value.completeness === completeness &&
    isPlainObject(value.origin) &&
    hasOnlyKeys(value.origin, GENESIS_ORIGIN_KEYS) &&
    value.origin.kind === "genesis"
  );
}

/** Narrows only the two supported audit origins without inferring a default. */
function isAuditOrigin(value: unknown): value is AuditOriginClaim {
  if (!isPlainObject(value)) return false;
  if (value.kind === "genesis") return hasOnlyKeys(value, GENESIS_ORIGIN_KEYS);
  return (
    value.kind === "checkpoint" &&
    hasOnlyKeys(value, CHECKPOINT_ORIGIN_KEYS) &&
    typeof value.checkpointHash === "string" &&
    HASH_PATTERN.test(value.checkpointHash)
  );
}

/** Validates the v2 tenant scope while preserving optional workspace/environment fields. */
function validScope(value: unknown): boolean {
  return (
    isPlainObject(value) &&
    hasOnlyKeys(value, SCOPE_KEYS) &&
    nonEmpty(value.tenantId) &&
    (value.workspaceId === undefined || nonEmpty(value.workspaceId)) &&
    (value.environment === undefined || nonEmpty(value.environment))
  );
}

/** Validates the caller-supplied export range without reading a clock. */
function validRange(value: unknown): boolean {
  return (
    isPlainObject(value) && hasOnlyKeys(value, RANGE_KEYS) && validTimestamp(value.from) && validTimestamp(value.to)
  );
}

/** Validates the portable producer principal shape. */
function validProducer(value: unknown): boolean {
  return (
    isPlainObject(value) &&
    hasOnlyKeys(value, PRODUCER_KEYS) &&
    nonEmpty(value.authority) &&
    value.kind === "principal" &&
    (value.type === "service" || value.type === "user") &&
    nonEmpty(value.id)
  );
}

/** Parses canonical record payload lines without exposing parser errors. */
function parseJsonLines(payload: unknown): unknown[] | null {
  if (typeof payload !== "string") return null;
  try {
    return splitRecordLines(payload).map((line) => JSON.parse(line));
  } catch {
    return null;
  }
}

/** Splits the required trailing-newline JSONL representation. */
function splitRecordLines(payload: string): string[] {
  if (payload === "") return [];
  const lines = payload.split("\n");
  if (lines.at(-1) === "") lines.pop();
  return lines;
}

/** Requires exact canonical JSON per line and the mandatory trailing newline. */
function isCanonicalJsonLines(payload: string): boolean {
  if (payload === "") return true;
  if (!payload.endsWith("\n")) return false;
  try {
    return splitRecordLines(payload).every((line) => canonicalJson(JSON.parse(line)) === line);
  } catch {
    return false;
  }
}

/** Parses the exact embedded v2 verdict shape so extra or renamed fields fail closed. */
function parseEmbedded(payload: unknown): EmbeddedV2Verification | null {
  if (typeof payload !== "string") return null;
  try {
    const value = JSON.parse(payload);
    if (!isPlainObject(value) || canonicalJson(value) !== payload) return null;
    if (Object.keys(value).sort().join(",") !== "audit,checkpoints,commits,dispositions,edges") return null;
    for (const key of ["audit", "edges", "commits"] as const) {
      if (
        !isPlainObject(value[key]) ||
        Object.keys(value[key]).join(",") !== "valid" ||
        typeof value[key].valid !== "boolean"
      )
        return null;
    }
    for (const key of ["checkpoints", "dispositions"] as const) {
      if (
        !isPlainObject(value[key]) ||
        Object.keys(value[key]).sort().join(",") !== "signature,valid" ||
        typeof value[key].valid !== "boolean" ||
        !isSignatureStatus(value[key].signature)
      )
        return null;
    }
    return value as EmbeddedV2Verification;
  } catch {
    return null;
  }
}

/** Verifies a detached bundle signature using the same manifest-digest contract as vevb-1. */
async function verifyV2Signature(
  bundle: ExportBundleV2,
  options: ExportBundleVerificationOptions,
): Promise<{ signature: "valid" | "invalid" | "absent" | "skipped"; issue?: string }> {
  if (!bundle.signature) {
    return options.requireSignature
      ? { signature: "absent", issue: "signature required but absent" }
      : { signature: "absent" };
  }
  if (!options.publicKey) return { signature: "skipped" };
  try {
    if (bundle.signature.algorithm !== "ed25519")
      return { signature: "invalid", issue: "unsupported signature algorithm" };
    const raw = await crypto.subtle.exportKey("raw", options.publicKey);
    const fingerprint = await sha256Bytes(raw);
    if (
      fingerprint !== bundle.signature.publicKeyFingerprint ||
      fingerprint !== bundle.manifest.signaturePublicKeyFingerprint
    ) {
      return { signature: "invalid", issue: "signature public key fingerprint mismatch" };
    }
    const payload = new TextEncoder().encode(await sha256Hex(canonicalJson(bundle.manifest)));
    const signature = Uint8Array.from(Buffer.from(bundle.signature.signature, "base64"));
    return (await crypto.subtle.verify("Ed25519", options.publicKey, signature, payload))
      ? { signature: "valid" }
      : { signature: "invalid", issue: "signature does not verify" };
  } catch {
    return { signature: "invalid", issue: "signature verification failed" };
  }
}

/** Creates a uniform structure-failure report before unsafe payload access. */
function failedV2Report(
  signature: "valid" | "invalid" | "absent" | "skipped",
  issues: string[],
): ExportBundleV2VerificationReport {
  return {
    valid: false,
    checks: {
      structure: false,
      integrity: false,
      checkpoints: false,
      dispositions: false,
      audit: false,
      edges: false,
      commits: false,
      signature,
    },
    issues,
  };
}

/** Aggregates retention signature states with invalid/skipped/absent precedence. */
function combineSignature(left: RetentionSignatureStatus, right: RetentionSignatureStatus): RetentionSignatureStatus {
  if (left === "invalid" || right === "invalid") return "invalid";
  if (left === "skipped" || right === "skipped") return "skipped";
  if (left === "absent" || right === "absent") return "absent";
  return "valid";
}

/** Hashes raw public-key bytes for signature fingerprint comparison. */
async function sha256Bytes(value: ArrayBuffer): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", value)))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** Narrows a JSON value to a non-array object. */
function isPlainObject(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Enforces additionalProperties false for each v2 protocol object. */
function hasOnlyKeys(value: object, keys: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => keys.has(key));
}

/** Requires non-empty protocol strings without normalization. */
function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** Requires a real ISO timestamp while leaving exact bytes caller-owned. */
function validTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

/** Recognizes the retention verifier's closed signature status set. */
function isSignatureStatus(value: unknown): value is RetentionSignatureStatus {
  return value === "valid" || value === "invalid" || value === "skipped" || value === "absent";
}
