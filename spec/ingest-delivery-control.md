# Ingest Delivery Control Contract

Status: draft v1
Date: 2026-08-02

This document defines portable delivery lifecycle semantics for Veritio HTTP
ingest clients, local spools, and transactional outboxes. It does not change
the audit-event protocol, canonical JSON, hashing, redaction, evidence ordering,
or export formats.

## Delivery Classification

HTTP clients send `X-Veritio-Delivery: live-v1` for immediate capture and
`X-Veritio-Delivery: replay-v1` for a durable outbox delivery. Servers may use
the value only to select a stricter finite reservation; credentials and record
scope remain authoritative. Missing, malformed, or future values are treated
as `live-v1`, never as an unlimited or privileged mode.

## Goals

- Preserve locally captured evidence when a hosted or self-hosted ingest target
  is unavailable, over plan, or economically paused.
- Prevent an outage backlog from becoming an unbounded automatic replay.
- Make retry, safety hold, and permanent rejection distinguishable without
  relying only on HTTP status codes.
- Bound replay by entries, records, encoded bytes, elapsed time, and request
  rate across concurrent processes.
- Keep hosted-provider policy optional. OSS clients work with any conforming
  ingest target and remain useful without a Veritio Cloud account.

## Response Shape

An ingest target may include these fields in a non-2xx JSON response:

```json
{
  "error": "ingest is temporarily paused",
  "code": "economic_safety_hold",
  "deliveryDisposition": "pause",
  "retryable": false,
  "retryAt": "2026-08-02T12:00:00.000Z",
  "circuitId": "cir_01"
}
```

`deliveryDisposition` is the portable authority. `code` is a stable
target-specific reason suitable for operator display. `error` is sanitized
human-readable text. `retryAt` and `circuitId` are optional. Responses must not
contain credentials, connection details, personal data, evidence payloads, or
provider secrets.

### `retry`

- Retain the entry.
- Apply persistent exponential backoff with jitter and honor a later
  server-provided `retryAt`.
- Automatic attempts are allowed only within the configured global dispatch
  budget.
- Typical causes: transport failure, 429 rate limit, or a transient 5xx.

### `pause`

- Retain the entry without another automatic attempt.
- Persist the circuit reason, circuit id, and observation time.
- New capture continues to the local authoritative store and may continue to
  append to a bounded local spool.
- Only an explicit operator canary or a new operator-approved drain epoch may
  attempt delivery.
- Typical causes: economic circuit breaker, monthly quota, provider block, or
  an operator pause.

### `reject`

- Move the entry to quarantine; never silently delete it.
- Do not automatically retry it.
- Typical causes: malformed payload, tenant/scope mismatch, revoked
  credential, or idempotency conflict.

## Legacy Fallback

For a target that omits `deliveryDisposition`:

- transport failures, 429, and 5xx map to `retry`;
- other non-2xx responses map to `reject` and quarantine;
- a response whose JSON contains a recognized stable pause code maps to
  `pause`, even when an older target used a retryable 503 status.

The fallback exists for wire compatibility. New implementations must emit and
consume `deliveryDisposition`.

## Queue Lifecycle

Every durable queue entry has one of these states:

```txt
pending -> leased -> dispatched
              |  -> pending      (retry/backoff or expired lease)
              |  -> paused       (safety hold)
              |  -> quarantined  (permanent rejection; storage APIs may call this `dead`)
paused -> leased                 (explicit canary/drain epoch only)
```

A lease carries an unguessable token and expiry. Completion requires the same
token. At most one live lease exists for an entry. A crashed process leaves a
recoverable expired lease, not a permanently wedged entry.

Filesystem queues claim through an atomic same-filesystem rename under an
exclusive queue lock. Database queues claim transactionally with a lease token
and expiry. Queue ordering uses a persisted monotonic sequence; wall-clock file
names are not an ordering authority.

## Dispatch Policy

Clients expose `manual` and `bounded` replay modes. `bounded` is the default for
new installations; legacy queues enter `manual` hold until inspected.

The default bounded policy is:

| Limit | Recommended | Hard |
| --- | ---: | ---: |
| Backlog batches | 25 | 250 |
| Backlog encoded bytes | 5,000,000 | 50,000,000 |
| One automatic recovery epoch | 1 canary batch | 1 canary batch |
| Canary encoded bytes | 250,000 | 1,000,000 |
| Canary records | 100 | 500 |
| Drain elapsed time | 5 seconds | 15 seconds |
| Interval between attempts | 60 seconds | 10 seconds minimum |

Hard limits cannot be raised implicitly by a server response. A host or
operator may configure lower values. Raising hard limits requires explicit
configuration; it must never happen because a queue grew.

At the hard backlog bound the queue retains existing entries, enters manual
hold, and stops adding remote-delivery payloads. The local evidence store
continues to capture. Implementations must emit a clear operator signal that
cloud delivery is incomplete; they must not evict old evidence to make room.

## SDK And Host Configuration

Core event SDKs do not read environment variables. Adapter and gateway process
boundaries may translate environment or config-file values into an injected
`DeliveryPolicy`:

```ts
export interface DeliveryPolicy {
  mode: "manual" | "bounded";
  recommendedBacklogBatches: number;
  hardBacklogBatches: number;
  recommendedBacklogBytes: number;
  hardBacklogBytes: number;
  maxBatchesPerRun: number;
  maxRecordsPerRun: number;
  maxBytesPerRun: number;
  maxElapsedMs: number;
  minIntervalMs: number;
  leaseMs: number;
}
```

The Claude Code and Codex capture adapters, generic HTTP outbox dispatcher,
gateway loop, and future delivery clients must preserve the same three
dispositions and bounded-run semantics when they implement durable replay.

## Operator Controls

Queue tooling must support:

- `status`: counts and encoded bytes by lifecycle state plus current circuit;
- `pause`: sticky local hold with an operator reason;
- `canary`: one explicitly bounded attempt;
- `drain`: an explicit epoch with immutable run limits;
- `resume`: clear a local hold only after operator acknowledgement;
- `quarantine`: list/export entries and reasons without destructive cleanup.

No ordinary capture hook may silently promote a canary into a backlog drain.

## Conformance Requirements

A conforming implementation proves:

1. Fifty concurrent processes cannot acquire the same queue entry.
2. A crash after claim is recoverable after lease expiry.
3. Aggregate attempts, records, and bytes never exceed the configured run
   budget, including concurrent callers.
4. A `pause` response causes zero automatic attempts across 10,000 subsequent
   capture invocations.
5. A `reject` response quarantines and preserves the payload.
6. Clock rollback does not change queue order or bypass backoff.
7. Restarting the process preserves leases, backoff, pause state, and drain
   epoch.
8. Legacy queue entries do not auto-drain after an upgrade.
9. Candidate package/runtime changes cannot be published under a docs-only
   release declaration.
