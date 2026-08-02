/**
 * Gateway configuration types and fail-closed parsing.
 *
 * This module is pure validation: it never reads files or environment
 * variables (the process boundary in `server.ts` does that, per the repo
 * rule that env/config I/O lives only at boundary modules). Parsing fails
 * closed: any missing or malformed field throws `GatewayConfigError` naming
 * the field path — but never echoing the offending value, because config
 * values include real provider API keys.
 */

/** Providers the gateway can front in the MVP. Translation between provider APIs is a non-goal. */
export type GatewayProvider = "anthropic" | "openai";

/**
 * Gateway-defined endpoint identifiers pinned to concrete provider paths
 * (`messages` → Anthropic POST /v1/messages, `chat-completions` → OpenAI
 * POST /v1/chat/completions). Paths outside the mapped set are denied.
 */
export type GatewayEndpoint = "messages" | "chat-completions";

/**
 * Upstream provider connection. `apiKey` is the real provider credential and
 * must exist only here — never in evidence, logs, or client-facing errors.
 * `baseUrl` pinning is how residency policy is expressed (e.g. EU endpoints).
 */
export interface ProviderConfig {
  baseUrl: string;
  apiKey: string;
}

/**
 * Named allowlist policy referenced by virtual keys. Deny is enforced, not
 * advisory: anything not listed is refused. Model entries are exact ids or
 * trailing-`*` prefixes; the single pattern `"*"` allows all models.
 */
export interface PolicyConfig {
  providers: GatewayProvider[];
  models: string[];
  endpoints: GatewayEndpoint[];
}

/**
 * A scoped, revocable virtual key. Only the sha256 hash of the presented key
 * string is stored; the gateway never persists or logs presented key values.
 * `keyId` is the stable non-PII identifier that flows into evidence as the
 * actor id; `team`/`app`/`environment` are operator labels for config hygiene
 * and are NOT emitted into events.
 */
export interface VirtualKeyConfig {
  keyId: string;
  keyHash: string;
  policy: string;
  team?: string;
  app?: string;
  environment?: string;
  revoked?: boolean;
}

/**
 * Optional ship-out of recorded evidence to a Veritio ingest endpoint
 * (hosted Veritio Cloud or a self-hosted ingest). Strictly additive: the
 * local evidence store stays authoritative, delivery is async via a local
 * outbox, and an unreachable endpoint never affects proxied traffic. `key`
 * is a scoped ingest credential (`vrt_…`) — server-side config only, never
 * logged or echoed. The gateway stays fully usable without this block
 * (hosted-provider features must not gate OSS usage).
 */
export interface IngestConfig {
  url: string;
  key: string;
  /** Held by default; canary grants one automatic request for this process. */
  startupMode: "held" | "canary";
  /** Finite one-request authorization compiled into the storage DispatchPermit. */
  canary: {
    maxBytes: number;
    maxElapsedMs: number;
    leaseMs: number;
  };
}

/**
 * Full gateway deployment configuration. One deployment serves one tenant
 * (`scope.tenantId` on every evidence event). `evidenceFailureMode: "block"`
 * is the fail-closed default: if evidence cannot be persisted locally the
 * gateway refuses new traffic rather than running unevidenced.
 */
export interface GatewayConfig {
  tenantId: string;
  gatewayId: string;
  evidenceDir: string;
  evidenceFailureMode: "block" | "degrade";
  captureContentHashes: boolean;
  injectStreamUsage: boolean;
  pricingCatalogPath?: string;
  ingest?: IngestConfig;
  providers: Partial<Record<GatewayProvider, ProviderConfig>>;
  policies: Record<string, PolicyConfig>;
  keys: VirtualKeyConfig[];
}

/**
 * Typed configuration failure. Carries the offending field path for operator
 * diagnostics while the message stays value-free (config may hold secrets).
 */
export class GatewayConfigError extends Error {
  readonly field: string;

  constructor(field: string, problem: string) {
    super(`invalid gateway config at "${field}": ${problem}`);
    this.name = "GatewayConfigError";
    this.field = field;
  }
}

const PROVIDERS: readonly GatewayProvider[] = ["anthropic", "openai"];
const ENDPOINTS: readonly GatewayEndpoint[] = ["messages", "chat-completions"];
const HEX_64 = /^[a-f0-9]{64}$/;
const DEFAULT_CANARY = Object.freeze({ maxBytes: 250_000, maxElapsedMs: 5_000, leaseMs: 30_000 });
const MAX_CANARY = Object.freeze({ maxBytes: 1_048_576, maxElapsedMs: 15_000, leaseMs: 60_000 });

/** Narrows to a plain object, failing closed with the field path otherwise. */
function requireObject(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new GatewayConfigError(field, "expected an object");
  }
  return value as Record<string, unknown>;
}

/** Requires a non-empty string, failing closed without echoing the value. */
function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new GatewayConfigError(field, "expected a non-empty string");
  }
  return value;
}

/** Optional boolean with a default; anything non-boolean fails closed. */
function optionalBoolean(value: unknown, field: string, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") {
    throw new GatewayConfigError(field, "expected a boolean");
  }
  return value;
}

/** Parses a positive integer without allowing config to raise a compiled-in hard ceiling. */
function optionalBoundedInteger(value: unknown, field: string, fallback: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > maximum) {
    throw new GatewayConfigError(field, `expected a positive integer no greater than ${maximum}`);
  }
  return value as number;
}

/**
 * Validates a parsed JSON value into a `GatewayConfig`, applying documented
 * defaults (`evidenceFailureMode: "block"`, `captureContentHashes: true`,
 * `injectStreamUsage: true`). Cross-references fail closed: every key must
 * name an existing policy, and every policy provider must be configured, so
 * a request can never reach an undefined enforcement state at runtime.
 */
export function parseGatewayConfig(raw: unknown): GatewayConfig {
  const root = requireObject(raw, "$");

  const tenantId = requireString(root.tenantId, "tenantId");
  const gatewayId = requireString(root.gatewayId, "gatewayId");
  const evidenceDir = requireString(root.evidenceDir, "evidenceDir");

  const failureMode = root.evidenceFailureMode ?? "block";
  if (failureMode !== "block" && failureMode !== "degrade") {
    throw new GatewayConfigError("evidenceFailureMode", 'expected "block" or "degrade"');
  }

  const captureContentHashes = optionalBoolean(root.captureContentHashes, "captureContentHashes", true);
  const injectStreamUsage = optionalBoolean(root.injectStreamUsage, "injectStreamUsage", true);
  const pricingCatalogPath =
    root.pricingCatalogPath === undefined ? undefined : requireString(root.pricingCatalogPath, "pricingCatalogPath");

  let ingest: IngestConfig | undefined;
  if (root.ingest !== undefined) {
    const entry = requireObject(root.ingest, "ingest");
    const startupMode = entry.startupMode ?? "held";
    if (startupMode !== "held" && startupMode !== "canary") {
      throw new GatewayConfigError("ingest.startupMode", 'expected "held" or "canary"');
    }
    const canaryRaw = entry.canary === undefined ? {} : requireObject(entry.canary, "ingest.canary");
    const maxElapsedMs = optionalBoundedInteger(
      canaryRaw.maxElapsedMs,
      "ingest.canary.maxElapsedMs",
      DEFAULT_CANARY.maxElapsedMs,
      MAX_CANARY.maxElapsedMs,
    );
    const leaseMs = optionalBoundedInteger(
      canaryRaw.leaseMs,
      "ingest.canary.leaseMs",
      DEFAULT_CANARY.leaseMs,
      MAX_CANARY.leaseMs,
    );
    if (leaseMs <= maxElapsedMs) {
      throw new GatewayConfigError("ingest.canary.leaseMs", "must exceed ingest.canary.maxElapsedMs");
    }
    ingest = {
      url: requireString(entry.url, "ingest.url"),
      key: requireString(entry.key, "ingest.key"),
      startupMode,
      canary: {
        maxBytes: optionalBoundedInteger(
          canaryRaw.maxBytes,
          "ingest.canary.maxBytes",
          DEFAULT_CANARY.maxBytes,
          MAX_CANARY.maxBytes,
        ),
        maxElapsedMs,
        leaseMs,
      },
    };
  }

  const providersRaw = requireObject(root.providers ?? {}, "providers");
  const providers: Partial<Record<GatewayProvider, ProviderConfig>> = {};
  for (const [name, value] of Object.entries(providersRaw)) {
    if (!PROVIDERS.includes(name as GatewayProvider)) {
      throw new GatewayConfigError(`providers.${name}`, "unknown provider");
    }
    const entry = requireObject(value, `providers.${name}`);
    providers[name as GatewayProvider] = {
      baseUrl: requireString(entry.baseUrl, `providers.${name}.baseUrl`),
      apiKey: requireString(entry.apiKey, `providers.${name}.apiKey`),
    };
  }

  const policiesRaw = requireObject(root.policies ?? {}, "policies");
  const policies: Record<string, PolicyConfig> = {};
  for (const [name, value] of Object.entries(policiesRaw)) {
    const entry = requireObject(value, `policies.${name}`);
    const providerList = entry.providers;
    if (!Array.isArray(providerList) || providerList.length === 0) {
      throw new GatewayConfigError(`policies.${name}.providers`, "expected a non-empty array");
    }
    for (const p of providerList) {
      if (!PROVIDERS.includes(p as GatewayProvider)) {
        throw new GatewayConfigError(`policies.${name}.providers`, "unknown provider");
      }
      if (providers[p as GatewayProvider] === undefined) {
        throw new GatewayConfigError(`policies.${name}.providers`, `provider "${p}" is not configured`);
      }
    }
    const models = entry.models;
    if (!Array.isArray(models) || models.length === 0 || models.some((m) => typeof m !== "string" || m.length === 0)) {
      throw new GatewayConfigError(`policies.${name}.models`, "expected a non-empty array of non-empty strings");
    }
    const endpoints = entry.endpoints;
    if (
      !Array.isArray(endpoints) ||
      endpoints.length === 0 ||
      endpoints.some((e) => !ENDPOINTS.includes(e as GatewayEndpoint))
    ) {
      throw new GatewayConfigError(`policies.${name}.endpoints`, "expected a non-empty array of known endpoints");
    }
    policies[name] = {
      providers: providerList as GatewayProvider[],
      models: models as string[],
      endpoints: endpoints as GatewayEndpoint[],
    };
  }

  const keysRaw = root.keys ?? [];
  if (!Array.isArray(keysRaw)) {
    throw new GatewayConfigError("keys", "expected an array");
  }
  const seenKeyIds = new Set<string>();
  const keys: VirtualKeyConfig[] = keysRaw.map((value, index) => {
    const entry = requireObject(value, `keys[${index}]`);
    const keyId = requireString(entry.keyId, `keys[${index}].keyId`);
    if (seenKeyIds.has(keyId)) {
      throw new GatewayConfigError(`keys[${index}].keyId`, "duplicate keyId");
    }
    seenKeyIds.add(keyId);
    const keyHash = requireString(entry.keyHash, `keys[${index}].keyHash`);
    if (!HEX_64.test(keyHash)) {
      throw new GatewayConfigError(`keys[${index}].keyHash`, "expected 64 lowercase hex characters (sha256)");
    }
    const policy = requireString(entry.policy, `keys[${index}].policy`);
    if (policies[policy] === undefined) {
      throw new GatewayConfigError(`keys[${index}].policy`, `references unknown policy "${policy}"`);
    }
    const key: VirtualKeyConfig = { keyId, keyHash, policy };
    if (entry.team !== undefined) key.team = requireString(entry.team, `keys[${index}].team`);
    if (entry.app !== undefined) key.app = requireString(entry.app, `keys[${index}].app`);
    if (entry.environment !== undefined) {
      key.environment = requireString(entry.environment, `keys[${index}].environment`);
    }
    if (entry.revoked !== undefined) {
      if (typeof entry.revoked !== "boolean") {
        throw new GatewayConfigError(`keys[${index}].revoked`, "expected a boolean");
      }
      key.revoked = entry.revoked;
    }
    return key;
  });

  return {
    tenantId,
    gatewayId,
    evidenceDir,
    evidenceFailureMode: failureMode,
    captureContentHashes,
    injectStreamUsage,
    ...(pricingCatalogPath === undefined ? {} : { pricingCatalogPath }),
    ...(ingest === undefined ? {} : { ingest }),
    providers,
    policies,
    keys,
  };
}
