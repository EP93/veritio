# @veritio/gateway

Self-hosted AI governance gateway: a transparent proxy in front of Anthropic and OpenAI that
turns your organization's AI traffic into governed, evidenced traffic.

- **Virtual keys** — real provider keys live only in the gateway config; teams get scoped,
  revocable keys with model allowlists attached.
- **Enforced policy** — provider / model / endpoint allowlists, decided before any byte leaves
  your network. Deny is enforced, not advisory. Provider base-URL pinning expresses residency routing
  (e.g. EU endpoints); it does not by itself guarantee residency compliance.
- **Metering** — provider-reported token usage costed in integer micro-USD from a versioned
  pricing catalog.
- **Evidence** — every request outcome becomes a hash-chained Veritio audit event
  (see `spec/ai-gateway-capture.md`): metadata and sha256 content hashes only, **never prompt or
  response bodies**. Chains verify offline with `@veritio/core`.
- **Transparent passthrough** — unmodified provider wire formats, streaming included. Your apps
  keep the official SDKs and change one line.

Veritio produces compliance *evidence*; it does not make you compliant and is not legal advice.

## Quickstart (single container)

1. Create `veritio-gateway.json` (real provider key stays here, on your infrastructure):

```jsonc
{
  "tenantId": "tenant_acme",
  "gatewayId": "gw_prod_eu",
  "evidenceDir": "/var/lib/veritio-gateway",
  "providers": {
    "anthropic": { "baseUrl": "https://api.anthropic.com", "apiKey": "sk-ant-…" }
  },
  "policies": {
    "marketing": { "providers": ["anthropic"], "models": ["claude-sonnet-*"], "endpoints": ["messages"] }
  },
  "keys": [
    {
      "keyId": "vk_marketing_prod",
      "keyHash": "<sha256 of the full virtual key string>",
      "policy": "marketing",
      "team": "marketing"
    }
  ]
}
```

Generate a virtual key and its hash:

```sh
key="vk_marketing_prod_$(openssl rand -hex 16)"
echo "key (give to the team): $key"
echo -n "$key" | shasum -a 256   # → keyHash (config)
```

2. Run the gateway:

```sh
docker run -p 8790:8790 \
  -v $PWD/veritio-gateway.json:/app/veritio-gateway.json:ro \
  -v veritio-evidence:/var/lib/veritio-gateway \
  veritio-gateway
```

(or without Docker: `VERITIO_GATEWAY_CONFIG=./veritio-gateway.json bun node_modules/@veritio/gateway/dist/server.js`)

3. Point unmodified SDKs at it:

```python
client = Anthropic(
    base_url="https://ai.internal.example",   # the gateway
    api_key="vk_marketing_prod_…",            # scoped virtual key
)
```

## What gets recorded

One audit event per request outcome (`ai.request.completed` / `denied` / `failed`) carrying
provider, model, endpoint, status, latency, provider-reported token usage, micro-USD cost, the
policy decision, and optional sha256 hashes of the exact request/response bytes. Nothing else:
no prompts, no completions, no key material. The full normative vocabulary lives in
[`spec/ai-gateway-capture.md`](../spec/ai-gateway-capture.md).

Evidence lands in a hash-chained JSONL store under `evidenceDir` and verifies offline:

```ts
import { verifyAuditRecords } from "@veritio/core";
import { createFileEvidenceStore } from "@veritio/storage";

const records = await createFileEvidenceStore("/var/lib/veritio-gateway").listEvents();
console.log(verifyAuditRecords(records)); // { ok: true } or the first broken link
```

## Evidence failure modes

`evidenceFailureMode` in config:

- `"block"` (default, fail closed): if evidence cannot be persisted, `/healthz` goes 503 and the
  gateway refuses new requests until writes succeed. Traffic never runs unevidenced.
- `"degrade"`: traffic keeps flowing; failed outcomes retry from a bounded queue, and an
  `ai.gateway.evidence.gap` marker event records any dropped outcomes once the store recovers.

## Operations

- `GET /healthz` — `{ status, pendingEvidence, shipOut }`, 200/503. `shipOut`
  contains only lifecycle state and counts; it never includes payloads, errors,
  credentials, or circuit ids. Cloud delivery state does not make the gateway
  unhealthy because the local evidence store remains authoritative.
- `SIGHUP` — reload the config file (key rotation/revocation without restart; a broken config
  keeps the previous one active).
- OpenAI streaming: the gateway injects `stream_options.include_usage` when absent so usage is
  reported (recorded as `mutatedRequest` in evidence; disable with `injectStreamUsage: false`).
- Config keys never appear in logs, errors, or evidence.
- Transparent passthrough means the gateway does not inject `anthropic-version`; clients keep
  setting provider-required headers themselves.

## Ship evidence to Veritio Cloud (optional)

Add an `ingest` block to the config to mirror every recorded event to a Veritio ingest
endpoint (hosted Veritio Cloud or your own):

```jsonc
{
  "ingest": { "url": "https://console.getveritio.com", "key": "vrt_…" }
}
```

`key` is a scoped ingest key created in the console. Semantics: the local evidence store
stays authoritative; delivery is asynchronous through a durable outbox under
`<evidenceDir>/outbox`; a cloud outage never affects proxied traffic. Ship-out starts in
`held` mode by default and ordinary maintenance ticks perform zero remote requests.
Retryable failures remain pending, permanent rejections are quarantined by the outbox,
and an economic-safety pause is persisted across gateway restarts.

To allow one startup recovery probe, opt in to a finite canary:

```jsonc
{
  "ingest": {
    "url": "https://console.getveritio.com",
    "key": "vrt_…",
    "startupMode": "canary",
    "canary": {
      "maxBytes": 250000,
      "maxElapsedMs": 5000,
      "leaseMs": 30000
    }
  }
}
```

The canary always uses exactly one-entry authorization and is consumed at most once for
the running gateway process. Later maintenance ticks never promote it into a backlog
drain. Config may lower the byte/time ceilings but cannot raise the compiled-in 1 MiB /
15 second hard limits; the request timeout uses the same elapsed-time ceiling. The lease
must be longer than the elapsed-time budget and cannot exceed 60 seconds. The
gateway is fully usable without an ingest block — no Veritio account required.

## Embedding in your own host

`startGateway` is the batteries-included entry. For custom hosts (own HTTP server, DB-backed
evidence store), wire `createGatewayHandler` directly with any sink that satisfies
`GatewayEvidenceSink` — see `DESIGN.md`.

## Status

Experimental, TypeScript-only server module (not part of the cross-language SDK parity surface;
the evidence vocabulary itself is language-neutral and normative). Hard budget cut-offs, rollup
dashboards, and hosted control-plane features are out of scope for this package.
