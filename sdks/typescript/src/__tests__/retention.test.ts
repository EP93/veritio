import { describe, expect, test } from "bun:test";
import { createPublicKey, verify } from "node:crypto";
import { join } from "node:path";
import type { AuditRecord } from "../index";
import {
  createRetentionCheckpoint,
  createRetentionDisposition,
  hashRetentionCheckpoint,
  hashRetentionDisposition,
  type RetentionCheckpoint,
  verifyAuditRecordsFromCheckpoint,
  verifyRetentionCheckpoint,
  verifyRetentionCheckpointChain,
  verifyRetentionDisposition,
} from "../retention";

const CONFORMANCE_DIR = join(import.meta.dir, "../../../../spec/conformance");

async function fixture<T>(name: string): Promise<T> {
  return (await Bun.file(join(CONFORMANCE_DIR, name)).json()) as T;
}

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function ed25519Verifier(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean {
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const key = createPublicKey({ key: Buffer.concat([spkiPrefix, publicKey]), format: "der", type: "spki" });
  return verify(null, message, key, signature);
}

describe("retention checkpoint protocol", () => {
  test("matches literal checkpoint hashes and detached signature fixture", async () => {
    const data = await fixture<any>("retention-checkpoints.json");
    const unsigned = createRetentionCheckpoint(data.cases[0].input);
    const signed = createRetentionCheckpoint(data.cases[1].input, data.cases[1].signature);

    expect(unsigned).toEqual(data.cases[0].expected);
    expect(hashRetentionCheckpoint(unsigned)).toBe(data.cases[0].expected.hash);
    expect(signed.hash).toBe(data.cases[1].expectedHash);
    expect(
      verifyRetentionCheckpoint(signed, {
        trustedPublicKey: hexBytes(data.publicKeyHex),
        signatureVerifier: ed25519Verifier,
        requireSignature: true,
      }),
    ).toEqual({ ok: true, signature: "valid" });
  });

  test("rejects invalid ids, unsafe integers, and non-millisecond timestamps", async () => {
    const data = await fixture<any>("retention-checkpoints.json");
    for (const rejection of data.constructorRejections) {
      expect(() =>
        createRetentionCheckpoint({ ...data.cases[0].input, [rejection.field]: rejection.value }),
      ).toThrow();
    }
  });

  test("requires exact epoch and range continuity", async () => {
    const data = await fixture<any>("retention-checkpoints.json");
    const first = createRetentionCheckpoint(data.cases[0].input);
    const { signaturePublicKeyFingerprint: _fingerprint, ...secondInput } = data.cases[1].input;
    const gap = createRetentionCheckpoint({ ...secondInput, fromSequence: 4, throughSequence: 4 });

    expect(verifyRetentionCheckpointChain([first, gap])).toEqual({
      ok: false,
      index: 1,
      reason: "range_mismatch",
      signature: "absent",
    });
  });

  test("reports valid when every checkpoint signature verifies", async () => {
    const data = await fixture<any>("retention-checkpoints.json");
    const fingerprint = data.cases[1].input.signaturePublicKeyFingerprint;
    const checkpoint = createRetentionCheckpoint(
      { ...data.cases[0].input, signaturePublicKeyFingerprint: fingerprint },
      data.cases[1].signature,
    );

    expect(
      verifyRetentionCheckpointChain([checkpoint], {
        trustedPublicKey: hexBytes(data.publicKeyHex),
        signatureVerifier: () => true,
        requireSignature: true,
      }),
    ).toEqual({ ok: true, signature: "valid" });
  });

  test("rejects a signature fingerprint not bound into the checkpoint hash", async () => {
    const data = await fixture<any>("retention-checkpoints.json");
    const signed = createRetentionCheckpoint(data.cases[1].input, {
      ...data.cases[1].signature,
      publicKeyFingerprint: "f".repeat(64),
    });

    expect(verifyRetentionCheckpoint(signed).reason).toBe("signature_fingerprint_mismatch");
  });

  test("verifies a retained audit tail from the checkpoint anchor", async () => {
    const data = await fixture<any>("retention-checkpoints.json");
    const checkpoint = createRetentionCheckpoint(data.cases[0].input);

    expect(verifyAuditRecordsFromCheckpoint(checkpoint, data.retainedRecords as AuditRecord[])).toEqual({
      ok: true,
      signature: "absent",
    });
    expect(
      verifyAuditRecordsFromCheckpoint(checkpoint, [
        { ...data.retainedRecords[0], previousHash: "f".repeat(64) },
      ] as AuditRecord[]).reason,
    ).toBe("previous_hash_mismatch");
  });
});

describe("retention disposition protocol", () => {
  test("matches the literal hash and binds the referenced checkpoint", async () => {
    const checkpoints = await fixture<any>("retention-checkpoints.json");
    const data = await fixture<any>("retention-dispositions.json");
    const checkpoint = createRetentionCheckpoint(checkpoints.cases[0].input);
    const disposition = createRetentionDisposition(data.cases[0].input, data.cases[0].signature);

    expect(disposition.hash).toBe(data.cases[0].expectedHash);
    expect(hashRetentionDisposition(disposition)).toBe(data.cases[0].expectedHash);
    expect(
      verifyRetentionDisposition(disposition, checkpoint, {
        trustedPublicKey: hexBytes(checkpoints.publicKeyHex),
        signatureVerifier: ed25519Verifier,
        requireSignature: true,
      }),
    ).toEqual({ ok: true, signature: "valid" });
  });

  test("fails closed on disposition/checkpoint mismatches", async () => {
    const checkpoints = await fixture<any>("retention-checkpoints.json");
    const data = await fixture<any>("retention-dispositions.json");
    const checkpoint = createRetentionCheckpoint(checkpoints.cases[0].input);
    const { signaturePublicKeyFingerprint: _fingerprint, ...baseInput } = data.cases[0].input;

    for (const rejection of data.mismatchRejections) {
      const disposition = createRetentionDisposition({ ...baseInput, [rejection.field]: rejection.value });
      expect(verifyRetentionDisposition(disposition, checkpoint).reason).toBe("checkpoint_mismatch");
    }
  });
});
