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
  test("schemas require calendar-valid UTC milliseconds and reject year zero", async () => {
    for (const fileName of ["retention-checkpoint.schema.json", "retention-disposition.schema.json"]) {
      const schema = (await Bun.file(join(import.meta.dir, `../../../../spec/${fileName}`)).json()) as {
        $defs: { timestamp: { format?: string; pattern: string } };
      };
      expect(schema.$defs.timestamp.format).toBe("date-time");
      expect(new RegExp(schema.$defs.timestamp.pattern).test("0000-01-01T00:00:00.000Z")).toBeFalse();
    }
  });

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

  test("constructors reject a mismatched signature fingerprint and verifiers reject record mutation", async () => {
    const data = await fixture<any>("retention-checkpoints.json");
    for (const rejection of data.signatureConstructorRejections) {
      expect(() =>
        createRetentionCheckpoint(data.cases[1].input, {
          ...data.cases[1].signature,
          publicKeyFingerprint: rejection.publicKeyFingerprint,
        }),
      ).toThrow();
    }

    const signed = createRetentionCheckpoint(data.cases[1].input, data.cases[1].signature);
    const mutated = {
      ...signed,
      signature: { ...signed.signature!, publicKeyFingerprint: "f".repeat(64) },
    };

    expect(verifyRetentionCheckpoint(mutated).reason).toBe("signature_fingerprint_mismatch");
  });

  test("checkpoint verification fails closed on non-objects and unknown fields", async () => {
    const data = await fixture<any>("retention-checkpoints.json");
    const unsigned = createRetentionCheckpoint(data.cases[0].input);
    const signed = createRetentionCheckpoint(data.cases[1].input, data.cases[1].signature);

    expect(verifyRetentionCheckpoint(null)).toEqual({
      ok: false,
      index: 0,
      reason: "invalid_checkpoint",
      signature: "absent",
    });
    expect(verifyRetentionCheckpoint({ ...unsigned, unexpected: true }).reason).toBe("invalid_checkpoint");
    expect(
      verifyRetentionCheckpoint({ ...signed, signature: { ...signed.signature!, unexpected: true } }).reason,
    ).toBe("signature_invalid");
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

  test("rejects mismatched signature construction and malformed receipt shapes", async () => {
    const checkpoints = await fixture<any>("retention-checkpoints.json");
    const data = await fixture<any>("retention-dispositions.json");
    const checkpoint = createRetentionCheckpoint(checkpoints.cases[0].input);

    for (const rejection of data.signatureConstructorRejections) {
      expect(() =>
        createRetentionDisposition(data.cases[0].input, {
          ...data.cases[0].signature,
          publicKeyFingerprint: rejection.publicKeyFingerprint,
        }),
      ).toThrow();
    }

    const signed = createRetentionDisposition(data.cases[0].input, data.cases[0].signature);
    expect(verifyRetentionDisposition(null, checkpoint).reason).toBe("invalid_disposition");
    expect(verifyRetentionDisposition({ ...signed, unexpected: true }, checkpoint).reason).toBe("invalid_disposition");
    expect(
      verifyRetentionDisposition(
        { ...signed, signature: { ...signed.signature!, unexpected: true } },
        checkpoint,
      ).reason,
    ).toBe("signature_invalid");
  });
});
