import { describe, expect, test } from "bun:test";
import { GatewayConfigError, parseGatewayConfig } from "./config";

const KEY_HASH = "a".repeat(64);

/** Minimal valid raw config used as the mutation base for failure cases. */
function validRaw(): Record<string, unknown> {
  return {
    tenantId: "tenant_demo",
    gatewayId: "gw_demo",
    evidenceDir: "/var/lib/veritio-gateway/evidence",
    providers: {
      anthropic: { baseUrl: "https://api.anthropic.com", apiKey: "sk-ant-secret-value" },
    },
    policies: {
      default: { providers: ["anthropic"], models: ["claude-sonnet-*"], endpoints: ["messages"] },
    },
    keys: [{ keyId: "vk_demo", keyHash: KEY_HASH, policy: "default" }],
  };
}

function fieldOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof GatewayConfigError) return error.field;
    throw error;
  }
  throw new Error("expected GatewayConfigError");
}

describe("parseGatewayConfig", () => {
  test("parses a valid config and applies defaults", () => {
    const config = parseGatewayConfig(validRaw());
    expect(config.tenantId).toBe("tenant_demo");
    expect(config.evidenceFailureMode).toBe("block");
    expect(config.captureContentHashes).toBe(true);
    expect(config.injectStreamUsage).toBe(true);
    expect(config.keys[0]?.policy).toBe("default");
  });

  test("fails closed on each missing required field", () => {
    for (const field of ["tenantId", "gatewayId", "evidenceDir"]) {
      const raw = validRaw();
      delete raw[field];
      expect(fieldOf(() => parseGatewayConfig(raw))).toBe(field);
    }
  });

  test("rejects unknown evidenceFailureMode", () => {
    const raw = validRaw();
    raw.evidenceFailureMode = "ignore";
    expect(fieldOf(() => parseGatewayConfig(raw))).toBe("evidenceFailureMode");
  });

  test("rejects non-hex keyHash", () => {
    const raw = validRaw();
    (raw.keys as Record<string, unknown>[])[0]!.keyHash = "not-hex";
    expect(fieldOf(() => parseGatewayConfig(raw))).toBe("keys[0].keyHash");
  });

  test("rejects duplicate keyId", () => {
    const raw = validRaw();
    const keys = raw.keys as Record<string, unknown>[];
    keys.push({ ...keys[0] });
    expect(fieldOf(() => parseGatewayConfig(raw))).toBe("keys[1].keyId");
  });

  test("rejects key referencing unknown policy", () => {
    const raw = validRaw();
    (raw.keys as Record<string, unknown>[])[0]!.policy = "missing";
    expect(fieldOf(() => parseGatewayConfig(raw))).toBe("keys[0].policy");
  });

  test("rejects policy referencing unconfigured provider", () => {
    const raw = validRaw();
    (raw.policies as Record<string, Record<string, unknown>>).default!.providers = ["openai"];
    expect(fieldOf(() => parseGatewayConfig(raw))).toBe("policies.default.providers");
  });

  test("rejects unknown provider name and unknown endpoint", () => {
    const raw = validRaw();
    (raw.providers as Record<string, unknown>).mistral = { baseUrl: "https://x", apiKey: "k" };
    expect(fieldOf(() => parseGatewayConfig(raw))).toBe("providers.mistral");

    const raw2 = validRaw();
    (raw2.policies as Record<string, Record<string, unknown>>).default!.endpoints = ["completions-legacy"];
    expect(fieldOf(() => parseGatewayConfig(raw2))).toBe("policies.default.endpoints");
  });

  test("ingest block is optional but all-or-nothing", () => {
    const withIngest = validRaw();
    withIngest.ingest = { url: "https://console.getveritio.com", key: "vrt_scoped" };
    expect(parseGatewayConfig(withIngest).ingest).toEqual({
      url: "https://console.getveritio.com",
      key: "vrt_scoped",
      startupMode: "held",
      canary: { maxBytes: 250_000, maxElapsedMs: 5_000, leaseMs: 30_000 },
    });
    expect(parseGatewayConfig(validRaw()).ingest).toBeUndefined();

    const missingKey = validRaw();
    missingKey.ingest = { url: "https://console.getveritio.com" };
    expect(fieldOf(() => parseGatewayConfig(missingKey))).toBe("ingest.key");
  });

  test("an explicit startup canary remains finite and may only lower hard ceilings", () => {
    const raw = validRaw();
    raw.ingest = {
      url: "https://console.getveritio.com",
      key: "vrt_scoped",
      startupMode: "canary",
      canary: { maxBytes: 100_000, maxElapsedMs: 1_000, leaseMs: 5_000 },
    };

    expect(parseGatewayConfig(raw).ingest).toMatchObject({
      startupMode: "canary",
      canary: { maxBytes: 100_000, maxElapsedMs: 1_000, leaseMs: 5_000 },
    });
  });

  test("rejects unbounded or expanded canary controls without echoing the ingest key", () => {
    const cases: Array<[string, unknown]> = [
      ["ingest.startupMode", "drain"],
      ["ingest.canary.maxBytes", 1_048_577],
      ["ingest.canary.maxElapsedMs", 15_001],
      ["ingest.canary.maxElapsedMs", Number.POSITIVE_INFINITY],
      ["ingest.canary.leaseMs", 1_000],
    ];
    for (const [field, value] of cases) {
      const raw = validRaw();
      raw.ingest = {
        url: "https://console.getveritio.com",
        key: "vrt_must_not_leak",
        startupMode: "canary",
        canary: { maxBytes: 250_000, maxElapsedMs: 5_000, leaseMs: 30_000 },
      };
      const segments = field.split(".").slice(1);
      let cursor = raw.ingest as Record<string, unknown>;
      for (const segment of segments.slice(0, -1)) cursor = cursor[segment] as Record<string, unknown>;
      cursor[segments.at(-1)!] = value;
      try {
        parseGatewayConfig(raw);
        throw new Error("expected config failure");
      } catch (error) {
        expect(error).toBeInstanceOf(GatewayConfigError);
        expect((error as GatewayConfigError).field).toBe(field);
        expect(String(error)).not.toContain("vrt_must_not_leak");
      }
    }
  });

  test("never echoes config values in error messages", () => {
    const raw = validRaw();
    (raw.providers as Record<string, Record<string, unknown>>).anthropic!.baseUrl = "";
    try {
      parseGatewayConfig(raw);
      throw new Error("expected throw");
    } catch (error) {
      expect(String(error)).not.toContain("sk-ant-secret-value");
    }
  });
});
