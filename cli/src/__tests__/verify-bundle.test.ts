import { describe, expect, test } from "bun:test";
import { buildExportBundle, serializeExportBundle, signExportBundle } from "@veritio/core";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseVerifyBundleArgs, runVerifyBundle } from "../index";

const buildInput = {
  scope: { tenantId: "ten_1" },
  range: { from: "2026-01-01T00:00:00Z", to: "2026-02-01T00:00:00Z" },
  producer: { authority: "veritio", kind: "principal" as const, type: "service" as const, id: "svc_test" },
  createdAt: "2026-07-06T00:00:00Z",
  events: [] as unknown[],
  edges: [] as unknown[],
};

async function tempFile(name: string, contents: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "veritio-verify-"));
  const path = join(dir, name);
  await writeFile(path, contents);
  return path;
}

describe("parseVerifyBundleArgs", () => {
  test("parses the positional file and flags", () => {
    expect(parseVerifyBundleArgs(["verify-bundle", "bundle.json", "--public-key", "key.raw", "--require-signature", "--json"])).toEqual({
      command: "verify-bundle",
      file: "bundle.json",
      publicKeyPath: "key.raw",
      requireSignature: true,
      json: true,
    });
  });

  test("requires a bundle file", () => {
    expect(() => parseVerifyBundleArgs(["verify-bundle"])).toThrow("Usage: veritio verify-bundle");
  });
});

describe("runVerifyBundle", () => {
  test("selects and reports checkpoint-aware vevb-2 verification", async () => {
    const fixture = await Bun.file(
      join(import.meta.dir, "../../../spec/conformance/export-bundle-v2-golden.json"),
    ).json();
    const file = await tempFile("bundle-v2.json", JSON.stringify(fixture.bundle));
    const output: string[] = [];
    const result = await runVerifyBundle(["verify-bundle", file], { write: (message) => output.push(message) });
    expect(result.code).toBe(0);
    expect(output.join("\n")).toContain("version: vevb-2");
    expect(output.join("\n")).toContain("checkpoints: pass");
    expect(output.join("\n")).toContain("dispositions: pass");
    expect(output.join("\n")).toContain("audit: pass");
    expect(output.join("\n")).toContain("edges: pass");
    expect(output.join("\n")).toContain("commits: pass");
  });

  test("returns 0 for a valid bundle file", async () => {
    const bundle = await buildExportBundle(buildInput);
    const file = await tempFile("bundle.json", serializeExportBundle(bundle));
    const output: string[] = [];
    const result = await runVerifyBundle(["verify-bundle", file], { write: (m) => output.push(m) });
    expect(result.code).toBe(0);
    expect(output.join("\n")).toContain("VALID");
    expect(output.join("\n")).toContain("unsigned — integrity verified, authenticity NOT verified");
  });

  test("returns nonzero for a tampered bundle file", async () => {
    const bundle = await buildExportBundle(buildInput);
    const tampered = { ...bundle, manifest: { ...bundle.manifest, rootHash: "0".repeat(64) } };
    const file = await tempFile("bundle.json", serializeExportBundle(tampered));
    const output: string[] = [];
    const result = await runVerifyBundle(["verify-bundle", file], {
      write: (m) => output.push(m),
    });
    expect(result.code).toBe(1);
    expect(output.join("\n")).toContain("INVALID");
  });

  test("--json emits a parseable report", async () => {
    const bundle = await buildExportBundle(buildInput);
    const file = await tempFile("bundle.json", serializeExportBundle(bundle));
    const output: string[] = [];
    const result = await runVerifyBundle(["verify-bundle", file, "--json"], { write: (m) => output.push(m) });
    expect(result.code).toBe(0);
    const report = JSON.parse(output.join("\n"));
    expect(report.valid).toBe(true);
    expect(report.checks).toBeDefined();
    expect(Array.isArray(report.issues)).toBe(true);
  });

  test("verifies a signed bundle against a raw public key file", async () => {
    const bundle = await buildExportBundle(buildInput);
    const keyPair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
    const signed = await signExportBundle(bundle, keyPair.privateKey, keyPair.publicKey);
    const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));

    const bundleFile = await tempFile("bundle.json", serializeExportBundle(signed));
    const keyFile = await tempFile("key.raw", "");
    await writeFile(keyFile, rawKey);

    const output: string[] = [];
    const result = await runVerifyBundle(
      ["verify-bundle", bundleFile, "--public-key", keyFile, "--require-signature"],
      { write: (m) => output.push(m) },
    );
    expect(result.code).toBe(0);
    expect(output.join("\n")).toContain("signature: valid");
  });

  test("returns nonzero for an unreadable file without leaking a stack trace", async () => {
    const errors: string[] = [];
    const result = await runVerifyBundle(["verify-bundle", "/no/such/bundle.json"], {
      writeError: (m) => errors.push(m),
    });
    expect(result.code).toBe(1);
    expect(errors.join("\n")).not.toContain("at ");
  });
});
