/**
 * vevb-1 export-bundle manifest contract.
 *
 * This module defines the portable "Veritio Evidence Export Bundle v1" (vevb-1)
 * manifest types and the `rootHash` computation that binds a bundle's record
 * files into a single tamper-evident digest. The manifest is the signed,
 * verifiable index of an export: it names every record file, its per-file
 * content hash, and the deterministic `rootHash` over all files. Hashing here
 * MUST use the same canonical-JSON bytes and SHA-256 semantics as the rest of
 * the protocol, so all hashing routes through the export-bundle-deps shim.
 */

import { canonicalJson, sha256Hex, verifyCommitChain } from "./export-bundle-deps.js";
import { verifyAuditChainScoped, verifyEdgeChainScoped } from "./export-bundle-chain-modes.js";
import { verifyExportBundleV2, type ExportBundleV2, type ExportBundleV2Manifest, type ExportBundleV2VerificationReport } from "./export-bundle-v2.js";
import type { RetentionVerificationOptions } from "./retention.js";

/**
 * One record file inside an export bundle. `path` is the bundle-relative file
 * location (used as the stable sort key for `rootHash`), `sha256` is the
 * lowercase-hex SHA-256 of that file's bytes, and `records` is the count of
 * records the file contains. These fields are hashed into `rootHash`, so their
 * shape and semantics are part of the vevb-1 protocol surface.
 */
export interface ExportBundleFileEntry {
  path: string;
  sha256: string;
  records: number;
}

/**
 * The vevb-1 export-bundle manifest: the signed, verifiable index of an export.
 *
 * `bundleVersion` pins the format to `'vevb-1'`. `scope` and `range` describe
 * the tenant/workspace/environment and time window the export covers.
 * `producer` records the authoritative principal that produced the bundle.
 * `files` lists every record file, and `rootHash` is the deterministic digest
 * over those files (see {@link computeRootHash}) that a verifier recomputes to
 * confirm the manifest has not been altered. `annex` and
 * `signaturePublicKeyFingerprint` are optional and carry pack references and the
 * signing-key fingerprint when the bundle is signed.
 */
export interface ExportBundleManifest {
  bundleVersion: "vevb-1";
  createdAt: string;
  scope: { tenantId: string; workspaceId?: string; environment?: string };
  range: { from: string; to: string };
  producer: {
    authority: string;
    kind: "principal";
    type: "service" | "user";
    id: string;
  };
  files: ExportBundleFileEntry[];
  rootHash: string;
  /**
   * Chain-verification claim of this bundle (absent = `full`, the strict
   * start-at-one gapless claim). `windowed` and `filtered` declare partial
   * exports so the verifier holds the bundle to exactly the claim it makes —
   * see spec/export-bundle.md § Chain scopes.
   */
  chainScope?: "windowed" | "filtered";
  /**
   * Content filters a `filtered` bundle was produced under. Declared in the
   * manifest (and therefore hashed and signable) so a consumer can see what
   * was deliberately excluded. Field names are protocol-neutral.
   */
  filters?: { workspaceId?: string; actionPrefixes?: string[] };
  annex?: { packId: string; version: string }[];
  signaturePublicKeyFingerprint?: string;
}

/**
 * Computes the deterministic `rootHash` over a bundle's file entries.
 *
 * The entries are sorted by `path` in ascending byte order (raw `<`/`>`
 * comparison, not locale-aware) on a copy so the caller's array is not mutated,
 * then hashed as `sha256Hex(canonicalJson(sorted))`. Sorting makes the hash
 * order-insensitive: the same set of files produces the same `rootHash`
 * regardless of the order they were appended. Uses the protocol canonical-JSON
 * bytes and SHA-256 from the export-bundle shim so the digest matches what a
 * verifier recomputes. Async because the underlying SHA-256 helper is Promise-based.
 */
export async function computeRootHash(files: ExportBundleFileEntry[]): Promise<string> {
  const sorted = [...files].sort((left, right) => {
    if (left.path < right.path) return -1;
    if (left.path > right.path) return 1;
    return 0;
  });
  return sha256Hex(canonicalJson(sorted));
}

/**
 * A detached signature over an export bundle. `algorithm` is always `'ed25519'`
 * (the only scheme vevb-1 signs with). `publicKeyFingerprint` identifies the
 * signing key (the lowercase-hex SHA-256 of the raw exported public key bytes,
 * matching the manifest's `signaturePublicKeyFingerprint`), and `signature` is
 * the base64-encoded Ed25519 signature over the manifest digest. Produced by
 * {@link signExportBundle} and checked by {@link verifyExportBundle};
 * {@link buildExportBundle} never signs, so a bundle it produces has no
 * `signature`.
 */
export interface ExportBundleSignature {
  algorithm: "ed25519";
  publicKeyFingerprint: string;
  signature: string;
}

/**
 * Input to {@link buildExportBundle}: the authoritative context plus the raw
 * record arrays that make up an export.
 *
 * `scope`, `range`, and `producer` are copied verbatim into the manifest.
 * `createdAt` is supplied by the caller so the build is fully deterministic (no
 * clock reads). `events`, `edges`, and `commits` are the raw record arrays that
 * become the bundle's `records/*.jsonl` files and are fed to the chain
 * verifiers; they are typed `unknown[]` because a builder may serialize records
 * that predate a schema change. `commits` defaults to an empty set when absent.
 * `annex` optionally attaches evidence packs, each written to its own annex file
 * and referenced from the manifest.
 */
export interface ExportBundleInput {
  scope: ExportBundleManifest["scope"];
  range: ExportBundleManifest["range"];
  producer: ExportBundleManifest["producer"];
  createdAt: string;
  /** Chain claim of this export; absent = `full`. Filters require `filtered`. */
  chainScope?: "windowed" | "filtered";
  /** Content filters, declared in the manifest; only valid with `filtered`. */
  filters?: ExportBundleManifest["filters"];
  events: unknown[];
  edges: unknown[];
  commits?: unknown[];
  annex?: {
    packId: string;
    version: string;
    entries: { dutyId: string; recordIds: string[] }[];
  }[];
}

/**
 * A fully assembled vevb-1 export bundle: the {@link ExportBundleManifest} index
 * plus the concrete file contents it describes. `files` maps each bundle-relative
 * path to its exact serialized string (the same bytes hashed into the manifest),
 * so a consumer can persist the bundle or recompute its hashes directly.
 * `signature` is present only once a bundle has been signed by a later task.
 */
export interface ExportBundleV1 {
  bundleVersion: "vevb-1";
  manifest: ExportBundleManifest;
  files: Record<string, string>;
  signature?: ExportBundleSignature;
}

/** Discriminates the byte-stable legacy format from checkpoint-aware vevb-2. */
export type ExportBundle = ExportBundleV1 | ExportBundleV2;

/**
 * Serializes a record array into a `.jsonl` payload. Each record is emitted as
 * its own canonical-JSON line joined by `\n` with a trailing `\n`, so the file
 * hash is stable regardless of how the records were constructed. An empty record
 * set serializes to `''` (no trailing newline) rather than a lone `\n`, matching
 * the vevb-1 rule that a zero-record file is still listed in the manifest but
 * carries no bytes.
 */
function serializeRecords(records: unknown[]): string {
  if (records.length === 0) return "";
  return `${records.map((record) => canonicalJson(record)).join("\n")}\n`;
}

/**
 * Builds a deterministic vevb-1 export bundle from raw record arrays.
 *
 * The build is a pure function of its input: it never reads a clock or any
 * randomness, so the same input always yields byte-identical files and manifest.
 * It serializes the audit-event, evidence-edge, and commit arrays into fixed
 * `records/*.jsonl` paths (see {@link serializeRecords}); runs the three chain
 * verifiers over the raw inputs and stores their `{ audit, edges, commits }`
 * verdicts as canonical JSON in `verification.json`; hashes every file with
 * {@link sha256Hex}; and binds the file entries with {@link computeRootHash}.
 * Optional annex packs are written to `annex/<packId>.json` (sorted by `packId`),
 * listed in `manifest.files` like every other file so they are covered by
 * `rootHash`, and summarized in `manifest.annex` as `{ packId, version }`. The
 * returned bundle is unsigned.
 */
export async function buildExportBundle(input: ExportBundleInput): Promise<ExportBundleV1> {
  const commits = input.commits ?? [];
  const chainScope = input.chainScope ?? "full";

  // Fail closed on inconsistent scope declarations: filters without the
  // `filtered` claim would hide content removal behind a stricter-looking
  // scope, and scoped commit sets are not defined in v1 (commits always verify
  // under the strict rule, so a scoped bundle must not carry them).
  if (input.filters !== undefined && chainScope !== "filtered") {
    throw new Error("export bundle: filters require chainScope 'filtered'");
  }
  if (chainScope === "filtered" && input.filters === undefined) {
    throw new Error("export bundle: chainScope 'filtered' requires a filters declaration");
  }
  if (chainScope !== "full" && commits.length > 0) {
    throw new Error("export bundle: commits are not supported in a scoped bundle");
  }

  const sortedAnnex = input.annex
    ? [...input.annex].sort((left, right) => {
        if (left.packId < right.packId) return -1;
        if (left.packId > right.packId) return 1;
        return 0;
      })
    : undefined;

  // Fail closed on duplicate annex packIds: two packs sharing a packId would map
  // to one `annex/<packId>.json` key (last write wins) while manifest.files and
  // manifest.annex keep both, breaking the manifest↔files 1:1 invariant.
  if (sortedAnnex) {
    const seen = new Set<string>();
    for (const pack of sortedAnnex) {
      if (!/^[\x20-\x7E]+$/.test(pack.packId)) {
        throw new Error("export bundle: annex packId must be printable ASCII");
      }
      if (seen.has(pack.packId)) {
        throw new Error(`export bundle: duplicate annex packId "${pack.packId}"`);
      }
      seen.add(pack.packId);
    }
  }

  const trackedFiles: { path: string; content: string; records: number }[] = [
    { path: "records/audit-events.jsonl", content: serializeRecords(input.events), records: input.events.length },
    { path: "records/evidence-edges.jsonl", content: serializeRecords(input.edges), records: input.edges.length },
    { path: "records/commits.jsonl", content: serializeRecords(commits), records: commits.length },
    {
      path: "verification.json",
      content: canonicalJson({
        audit: verifyAuditChainScoped(input.events, chainScope),
        edges: verifyEdgeChainScoped(input.edges, chainScope),
        commits: verifyCommitChain(commits),
        // Only scoped bundles carry the marker so pre-existing full bundles
        // stay byte-identical.
        ...(chainScope !== "full" ? { chainScope } : {}),
      }),
      records: 0,
    },
    ...(sortedAnnex ?? []).map((pack) => ({
      path: `annex/${pack.packId}.json`,
      content: canonicalJson(pack),
      records: pack.entries.length,
    })),
  ];

  const files: Record<string, string> = {};
  for (const file of trackedFiles) {
    files[file.path] = file.content;
  }

  const manifestFiles: ExportBundleFileEntry[] = await Promise.all(
    trackedFiles.map(async (entry) => ({
      path: entry.path,
      sha256: await sha256Hex(entry.content),
      records: entry.records,
    })),
  );

  const manifest: ExportBundleManifest = {
    bundleVersion: "vevb-1",
    createdAt: input.createdAt,
    scope: input.scope,
    range: input.range,
    producer: input.producer,
    files: manifestFiles,
    rootHash: await computeRootHash(manifestFiles),
    ...(chainScope !== "full" ? { chainScope } : {}),
    ...(input.filters !== undefined ? { filters: input.filters } : {}),
    ...(sortedAnnex ? { annex: sortedAnnex.map((pack) => ({ packId: pack.packId, version: pack.version })) } : {}),
  };

  return { bundleVersion: "vevb-1", manifest, files };
}

/**
 * Lowercase-hex SHA-256 of raw bytes. Unlike {@link sha256Hex}, which hashes the
 * UTF-8 encoding of a string, this hashes the given bytes directly — used for the
 * public-key fingerprint, whose input is binary key material, not text.
 */
async function sha256HexOfBytes(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Computes a signing key's fingerprint: the lowercase-hex SHA-256 over the raw
 * (`'raw'`-format) exported public key bytes. The same public key always yields
 * the same fingerprint, so it can bind a signature to its verifying key without
 * carrying the key itself.
 */
async function publicKeyFingerprint(publicKey: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", publicKey);
  return sha256HexOfBytes(raw);
}

/** Base64-encodes raw bytes (standard alphabet, with padding). */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Decodes standard base64 into raw bytes. Throws on malformed input. */
function base64ToBytes(base64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(base64);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/**
 * The exact bytes an export-bundle signature covers: the UTF-8 encoding of
 * `sha256Hex(canonicalJson(manifest))`. Signing the manifest digest (rather than
 * the raw manifest) keeps the signed payload a fixed 64-byte hex string while
 * still binding every manifest field — `createdAt`, `scope`, `rootHash`,
 * `signaturePublicKeyFingerprint`, and the rest — so any manifest tamper after
 * signing invalidates the signature. The signer and verifier MUST derive the
 * payload identically for a signature to check out.
 */
async function signedManifestPayload(
  manifest: ExportBundleManifest | ExportBundleV2Manifest,
): Promise<Uint8Array<ArrayBuffer>> {
  // Copy through Uint8Array.from so the payload is backed by a plain ArrayBuffer,
  // which WebCrypto's sign/verify BufferSource parameter requires (TextEncoder's
  // output is typed over the wider ArrayBufferLike).
  return Uint8Array.from(new TextEncoder().encode(await sha256Hex(canonicalJson(manifest))));
}

/**
 * Signs an export bundle with an Ed25519 key, returning a NEW signed bundle.
 *
 * The input `bundle` is never mutated. Signing (1) derives the
 * {@link publicKeyFingerprint} of `publicKey` and writes it into a fresh
 * manifest as `signaturePublicKeyFingerprint` — this changes the manifest but not
 * `rootHash`, which binds only `files`; (2) signs the digest of that new manifest
 * (see {@link signedManifestPayload}) so the signature covers the fingerprint it
 * advertises; and (3) returns `{ ...bundle, manifest, signature }` with the
 * base64 Ed25519 signature. Ed25519 signing is deterministic, so the same bundle
 * and key always produce byte-identical output. The returned bundle verifies with
 * {@link verifyExportBundle} when given the matching `publicKey`.
 */
export async function signExportBundle<T extends ExportBundle>(
  bundle: T,
  privateKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<T> {
  const fingerprint = await publicKeyFingerprint(publicKey);
  const manifest = { ...bundle.manifest, signaturePublicKeyFingerprint: fingerprint } as T["manifest"];
  const payload = await signedManifestPayload(manifest);
  const signatureBytes = await crypto.subtle.sign("Ed25519", privateKey, payload);
  return {
    ...bundle,
    manifest,
    signature: {
      algorithm: "ed25519",
      publicKeyFingerprint: fingerprint,
      signature: bytesToBase64(new Uint8Array(signatureBytes)),
    },
  } as T;
}

/**
 * Serializes a full {@link ExportBundle} into its single-file container form:
 * the canonical JSON of the entire bundle. Routing through {@link canonicalJson}
 * (rather than `JSON.stringify`) keeps the container bytes deterministic and
 * key-sorted, so the same bundle always produces identical container text and a
 * downstream signature or hash over the container is stable.
 */
export function serializeExportBundle(bundle: ExportBundle): string {
  return canonicalJson(bundle);
}

/**
 * Parses a single-file container string back into an {@link ExportBundle}.
 *
 * This performs only the structural checks needed to trust the container shape,
 * not deep schema or integrity validation (the verifier owns that). It rejects,
 * with a sanitized `Error`, text that is not valid JSON or not a JSON object
 * (`'export bundle: invalid JSON container'`, never leaking the raw parser
 * message), any `bundleVersion` other than `'vevb-1'` or `'vevb-2'`
 * (`'export bundle: unsupported bundleVersion …'`), and a container whose
 * `manifest` or `files` is missing or not an object
 * (`'export bundle: missing manifest or files'`).
 */
export function parseExportBundle(text: string): ExportBundle {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("export bundle: invalid JSON container");
  }

  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("export bundle: invalid JSON container");
  }

  const container = parsed as Record<string, unknown>;

  if (container.bundleVersion !== "vevb-1" && container.bundleVersion !== "vevb-2") {
    throw new Error(`export bundle: unsupported bundleVersion ${JSON.stringify(container.bundleVersion)}`);
  }

  if (
    typeof container.manifest !== "object" ||
    container.manifest === null ||
    typeof container.files !== "object" ||
    container.files === null
  ) {
    throw new Error("export bundle: missing manifest or files");
  }

  return parsed as ExportBundle;
}

/**
 * The result of {@link verifyExportBundle}: an offline verdict over a vevb-1
 * bundle. `valid` is the single fail-closed answer a consumer trusts; it is true
 * only when every check holds. `checks` breaks the verdict into the four
 * independent gates — `structure` (manifest↔files shape and required paths),
 * `integrity` (per-file and root-hash recomputation), `chains` (record hash
 * chains re-verified and matched against the embedded report), and `signature`
 * (`'valid'`/`'invalid'` when present with a `publicKey`, `'skipped'` when
 * present without one, `'absent'` when unsigned). `issues`
 * carries sanitized, static failure descriptions — a path or packId may be
 * embedded, but never raw error text or record content.
 */
export interface ExportBundleVerificationReport {
  valid: boolean;
  checks: {
    structure: boolean;
    integrity: boolean;
    chains: boolean;
    signature: "valid" | "invalid" | "absent" | "skipped";
  };
  /**
   * The chain claim the bundle declared and was verified against (`full` when
   * `manifest.chainScope` is absent). Consumers deciding how much a `valid`
   * verdict proves must read this: only `full` proves nothing was removed.
   */
  chainScope: "full" | "windowed" | "filtered";
  issues: string[];
}

/** The three fixed record files that carry hash-chained evidence. */
const RECORD_PATHS = ["records/audit-events.jsonl", "records/evidence-edges.jsonl", "records/commits.jsonl"] as const;

/** Every path a well-formed manifest must list, independent of optional annex. */
const REQUIRED_PATHS = [...RECORD_PATHS, "verification.json"] as const;

/** Narrows a value to a non-null, non-array plain object before inspection. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Splits a `.jsonl` payload into its record lines. Records are `\n`-joined with a
 * single trailing newline (see {@link serializeRecords}), so the one empty
 * segment the trailing newline produces is dropped. An empty payload is zero
 * records, matching the zero-record file rule.
 */
function splitRecordLines(payload: string): string[] {
  if (payload === "") return [];
  const lines = payload.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

/**
 * Verifies a present detached signature against a caller-supplied public key,
 * returning a `'valid'`/`'invalid'` verdict plus an optional sanitized issue.
 *
 * Fail-closed: the algorithm must be `'ed25519'`; the fingerprint of `publicKey`
 * must match both `signature.publicKeyFingerprint` and the manifest's
 * `signaturePublicKeyFingerprint` (so a bundle cannot advertise one key and be
 * checked against another); the base64 signature must decode; and the Ed25519
 * signature must verify over {@link signedManifestPayload} recomputed from the
 * bundle's CURRENT manifest — any manifest tamper after signing changes that
 * payload and fails here. Malformed base64 or a throwing WebCrypto call is
 * caught and reported as `'invalid'` with a static message, never raw error text.
 */
async function verifyBundleSignature(
  bundle: ExportBundleV1,
  publicKey: CryptoKey,
): Promise<{ signature: "valid" | "invalid"; issue?: string }> {
  const sig = bundle.signature as ExportBundleSignature;
  if ((sig.algorithm as string) !== "ed25519") {
    return { signature: "invalid", issue: "unsupported signature algorithm" };
  }
  try {
    const fingerprint = await publicKeyFingerprint(publicKey);
    if (fingerprint !== sig.publicKeyFingerprint || fingerprint !== bundle.manifest?.signaturePublicKeyFingerprint) {
      return { signature: "invalid", issue: "signature public key fingerprint mismatch" };
    }
    const signatureBytes = base64ToBytes(sig.signature);
    const payload = await signedManifestPayload(bundle.manifest);
    const ok = await crypto.subtle.verify("Ed25519", publicKey, signatureBytes, payload);
    return ok ? { signature: "valid" } : { signature: "invalid", issue: "signature does not verify" };
  } catch {
    return { signature: "invalid", issue: "signature verification failed" };
  }
}

/**
 * Fail-closed offline verifier for a vevb-1 export bundle.
 *
 * Runs four independent gates over a bundle without any network or authority
 * call, so a recipient can trust an export purely from its bytes:
 *
 * - **structure** — `manifest` and `files` must be real objects and
 *   `manifest.files` a real array (the container parser's guards are shallow and
 *   deliberately let arrays through, so they are caught here); manifest paths and
 *   `files` keys must map 1:1 with no duplicates; and the three `records/*.jsonl`
 *   files plus `verification.json` must be present.
 * - **integrity** — every file's SHA-256 is recomputed from its bytes and
 *   compared to the manifest entry, `rootHash` is recomputed via
 *   {@link computeRootHash}, and each record file's line count is matched to its
 *   declared `records` count.
 * - **chains** — each record file is parsed back and re-run through the shim
 *   chain verifiers, whose `valid` verdicts must equal the embedded
 *   `verification.json`.
 * - **signature** — a present signature is checked against `opts.publicKey`
 *   (`'valid'`/`'invalid'`) via {@link verifyBundleSignature}; present without a
 *   key is `'skipped'`; absent is `'absent'` and fails only when
 *   `opts.requireSignature` is set. Only `'invalid'` (or a required-but-missing
 *   signature) drives the overall verdict false.
 *
 * Content problems never throw — they land in the report as sanitized issue
 * strings and drive `valid` to false. The function throws only for programmer
 * misuse: a `bundle` that is not an object.
 */
export interface ExportBundleVerificationOptions {
  publicKey?: CryptoKey;
  requireSignature?: boolean;
  /** Injected retention signature policy; core never reads keys from environment state. */
  retention?: RetentionVerificationOptions;
}

/** Dispatches verification only from the explicit container discriminator. */
export function verifyExportBundle(
  bundle: ExportBundleV1,
  opts?: ExportBundleVerificationOptions,
): Promise<ExportBundleVerificationReport>;
export function verifyExportBundle(
  bundle: ExportBundleV2,
  opts?: ExportBundleVerificationOptions,
): Promise<ExportBundleV2VerificationReport>;
export function verifyExportBundle(
  bundle: ExportBundle,
  opts?: ExportBundleVerificationOptions,
): Promise<ExportBundleVerificationReport | ExportBundleV2VerificationReport>;
export async function verifyExportBundle(
  bundle: ExportBundle,
  opts: ExportBundleVerificationOptions = {},
): Promise<ExportBundleVerificationReport | ExportBundleV2VerificationReport> {
  if (!isPlainObject(bundle)) {
    throw new TypeError("verifyExportBundle: expected an ExportBundle object");
  }
  if (bundle.bundleVersion === "vevb-2") return verifyExportBundleV2(bundle, opts);
  return verifyExportBundleV1(bundle, opts);
}

/** Preserves the original vevb-1 verification path byte-for-byte. */
async function verifyExportBundleV1(
  bundle: ExportBundleV1,
  opts: ExportBundleVerificationOptions = {},
): Promise<ExportBundleVerificationReport> {
  if (!isPlainObject(bundle)) {
    throw new TypeError("verifyExportBundle: expected an ExportBundle object");
  }

  const issues: string[] = [];
  const manifest = bundle.manifest;
  const files = bundle.files;

  // Signature: `signatureSatisfied` is the single gate the overall verdict reads.
  // A present signature is verified only when the caller supplies `publicKey`
  // ('valid'/'invalid'); present without a key is 'skipped' (satisfied — the
  // caller opted out); absent is 'absent' and satisfied unless `requireSignature`.
  let signature: ExportBundleVerificationReport["checks"]["signature"];
  let signatureSatisfied = true;
  const hasSignature = isPlainObject(bundle.signature);
  if (hasSignature) {
    if (opts?.publicKey) {
      const verdict = await verifyBundleSignature(bundle, opts.publicKey);
      signature = verdict.signature;
      if (verdict.issue) issues.push(verdict.issue);
      signatureSatisfied = signature === "valid";
    } else {
      signature = "skipped";
    }
  } else {
    signature = "absent";
    if (opts?.requireSignature) {
      signatureSatisfied = false;
      issues.push("signature required but absent");
    }
  }

  // Structure: prove the shape is safe to iterate before any hashing runs.
  let structure = true;
  const manifestOk = isPlainObject(manifest);
  const filesOk = isPlainObject(files);
  const manifestFilesOk = manifestOk && Array.isArray(manifest.files);

  if (!manifestOk) {
    structure = false;
    issues.push("manifest is not an object");
  }
  if (!filesOk) {
    structure = false;
    issues.push("files is not an object");
  }
  if (manifestOk && !Array.isArray(manifest.files)) {
    structure = false;
    issues.push("manifest.files is not an array");
  }

  // Chain scope: the bundle's own declaration selects which chain claim is
  // verified. An unknown value or an inconsistent filters declaration fails
  // closed as a structure error rather than silently verifying under `full`.
  const declaredScope = manifestOk ? (manifest as ExportBundleManifest).chainScope : undefined;
  let chainScope: ExportBundleVerificationReport["chainScope"] = "full";
  if (declaredScope !== undefined) {
    if (declaredScope === "windowed" || declaredScope === "filtered") {
      chainScope = declaredScope;
    } else {
      structure = false;
      issues.push("manifest.chainScope is not a known scope");
    }
  }
  if (manifestOk && (manifest as ExportBundleManifest).filters !== undefined && chainScope !== "filtered") {
    structure = false;
    issues.push("manifest.filters requires chainScope 'filtered'");
  }

  const canInspect = filesOk && manifestFilesOk;
  if (!canInspect) {
    return {
      valid: false,
      checks: { structure: false, integrity: false, chains: false, signature },
      chainScope,
      issues,
    };
  }

  const manifestFiles = manifest.files;
  const fileKeys = Object.keys(files);
  const manifestPaths: string[] = [];
  for (const entry of manifestFiles) {
    if (!isPlainObject(entry) || typeof entry.path !== "string") {
      structure = false;
      issues.push("manifest.files entry is malformed");
      continue;
    }
    if (manifestPaths.includes(entry.path)) {
      structure = false;
      issues.push(`duplicate manifest path ${entry.path}`);
    }
    manifestPaths.push(entry.path);
  }
  for (const path of manifestPaths) {
    if (!fileKeys.includes(path)) {
      structure = false;
      issues.push(`missing file payload for ${path}`);
    }
  }
  for (const key of fileKeys) {
    if (!manifestPaths.includes(key)) {
      structure = false;
      issues.push(`file key ${key} not listed in manifest`);
    }
  }
  for (const required of REQUIRED_PATHS) {
    if (!manifestPaths.includes(required)) {
      structure = false;
      issues.push(`required path missing: ${required}`);
    }
  }

  // Integrity: recompute every per-file hash and the binding rootHash, and match
  // each record file's declared count to its actual line count.
  let integrity = true;
  // computeRootHash sorts and canonicalizes the raw manifest entries, so a
  // malformed entry (e.g. a null in an otherwise array-shaped files list) can
  // throw. Contain it here — a crafted bundle must fail closed, never escape.
  try {
    const recomputedRoot = await computeRootHash(manifestFiles);
    if (recomputedRoot !== manifest.rootHash) {
      integrity = false;
      issues.push("rootHash does not bind the manifest files");
    }
  } catch {
    integrity = false;
    issues.push("rootHash could not be computed");
  }
  for (const entry of manifestFiles) {
    if (!isPlainObject(entry) || typeof entry.path !== "string") continue;
    const payload = files[entry.path];
    if (typeof payload !== "string") {
      integrity = false;
      issues.push(`missing payload for ${entry.path}`);
      continue;
    }
    if ((await sha256Hex(payload)) !== entry.sha256) {
      integrity = false;
      issues.push(`sha256 mismatch for ${entry.path}`);
    }
    if ((RECORD_PATHS as readonly string[]).includes(entry.path)) {
      if (entry.records !== splitRecordLines(payload).length) {
        integrity = false;
        issues.push(`record count mismatch for ${entry.path}`);
      }
    }
  }

  // Chains: parse each record file back and re-verify it, then confirm the fresh
  // verdicts agree with the embedded verification report.
  let chains = true;
  const parsedRecords: Record<string, unknown[]> = {};
  let allRecordsParsed = true;
  for (const path of RECORD_PATHS) {
    const payload = files[path];
    if (typeof payload !== "string") {
      chains = false;
      allRecordsParsed = false;
      issues.push(`unparseable record line in ${path}`);
      parsedRecords[path] = [];
      continue;
    }
    const records: unknown[] = [];
    let parsedOk = true;
    for (const line of splitRecordLines(payload)) {
      try {
        records.push(JSON.parse(line));
      } catch {
        chains = false;
        allRecordsParsed = false;
        parsedOk = false;
        issues.push(`unparseable record line in ${path}`);
        break;
      }
    }
    parsedRecords[path] = records;
    if (!parsedOk) continue;
  }

  if (allRecordsParsed) {
    const auditVerdict = verifyAuditChainScoped(parsedRecords["records/audit-events.jsonl"] ?? [], chainScope);
    const edgeVerdict = verifyEdgeChainScoped(parsedRecords["records/evidence-edges.jsonl"] ?? [], chainScope);
    const commitVerdict = verifyCommitChain(parsedRecords["records/commits.jsonl"] ?? []);
    // Scoped bundles must not smuggle commit records past the strict rule.
    if (chainScope !== "full" && (parsedRecords["records/commits.jsonl"] ?? []).length > 0) {
      chains = false;
      issues.push("commits are not supported in a scoped bundle");
    }

    let embedded: unknown;
    const embeddedPayload = files["verification.json"];
    if (typeof embeddedPayload === "string") {
      try {
        embedded = JSON.parse(embeddedPayload);
      } catch {
        embedded = undefined;
      }
    }

    if (
      !isPlainObject(embedded) ||
      !isPlainObject(embedded.audit) ||
      !isPlainObject(embedded.edges) ||
      !isPlainObject(embedded.commits)
    ) {
      chains = false;
      issues.push("embedded verification report unreadable");
    } else if (
      auditVerdict.valid !== embedded.audit.valid ||
      edgeVerdict.valid !== embedded.edges.valid ||
      commitVerdict.valid !== embedded.commits.valid
    ) {
      chains = false;
      issues.push("embedded verification report disagrees");
    }

    // The chains gate asserts the chains ARE valid, not merely that the
    // embedded report agrees. A bundle whose own report admits an invalid
    // chain must not produce an overall `valid: true`.
    if (!auditVerdict.valid || !edgeVerdict.valid || !commitVerdict.valid) {
      chains = false;
      issues.push("record chain verification failed");
    }
  }

  const valid = structure && integrity && chains && signatureSatisfied;

  return {
    valid,
    checks: { structure, integrity, chains, signature },
    chainScope,
    issues,
  };
}
