# @veritio/core

Part of [Veritio](https://getveritio.com), the open-source evidence layer — see the [docs](https://getveritio.com/docs/) and [Veritio Cloud](https://getveritio.com/cloud/).

Protocol-first TypeScript SDK for Veritio audit trail and evidence graph records.

## Install

```sh
npm install @veritio/core
```

## Usage

```ts
import { MemoryAuditStore, createAuditEvent, createEvidenceEdge, hashEvidenceEdge } from "@veritio/core";

const store = new MemoryAuditStore();

const event = createAuditEvent({
  actor: { type: "user", id: "usr_123" },
  action: "org.member.invited",
  target: { type: "organization", id: "org_123" },
  scope: { tenantId: "org_123", environment: "production" },
  metadata: { role: "viewer" }
});

await store.append(event);

const edge = createEvidenceEdge({
  from: { type: "actor", id: "usr_123", actorType: "user" },
  relation: "created",
  to: { type: "runtime_event", id: event.id },
  scope: { tenantId: "org_123", environment: "production" },
  metadata: { reason: "member_invite" }
});

const edgeHash = hashEvidenceEdge(edge);
```

## Audit Templates

Use `auditTemplates` when an app wants the common auth, organization, data,
agent, and code-change actions without hand-writing action strings:

```ts
import { auditLogClassificationMetadata, auditTemplates, createAuditEvent } from "@veritio/core";

const signedIn = createAuditEvent(
  auditTemplates.auth.signedIn({
    userId: "usr_123",
    sessionId: "sess_123",
    scope: { tenantId: "org_123", environment: "production" },
    securityContext: {
      ipAddressHash: "sha256:client-ip",
      userAgentHash: "sha256:user-agent",
      location: { country: "US", region: "CA" },
    },
    metadata: auditLogClassificationMetadata({ visibility: "customer", surface: "app" }),
  }),
);

const filesChanged = createAuditEvent(
  auditTemplates.code.filesChanged({
    sourceTreeId: "tree_123",
    actor: { type: "ai_agent", id: "agent_codex" },
    scope: { tenantId: "org_123", environment: "production" },
    sessionId: "agt_sess_123",
    fileCount: 3,
    filePathHashes: ["sha256:path-a", "sha256:path-b"],
  }),
);
```

Agent and code templates reject raw prompt, diff, file-path, stdout/stderr, tool
argument, and bearer-token-like metadata. Use ids, counts, hashes, and bounded
status fields instead.

`auditLogClassificationMetadata` and `detectAuditLogClassifiers` provide
portable DX for filters such as internal/external/partner/system logs and
api/app/worker/cli/webhook surfaces. They only write/read metadata keys
(`logVisibility`, `logSurface`); they are not new protocol fields.

## Hash-Chain Verification

Records appended through any conforming `AuditStore` form a gapless,
hash-chained sequence per tenant. `verifyAuditRecords` replays the chain and
fails closed at the first broken link — a tampered payload, a deleted record,
or a reordered history all surface with an explicit index and reason:

```ts
import { MemoryAuditStore, createAuditRecorder, verifyAuditRecords } from "@veritio/core";

const store = new MemoryAuditStore();
const recorder = createAuditRecorder({ store });

await recorder.record({
  actor: { type: "user", id: "usr_123" },
  action: "entry.updated",
  target: { type: "entry", id: "ent_42" },
  scope: { tenantId: "org_123", environment: "production" },
  metadata: { fields: ["title"] },
});

const records = await store.list({ tenantId: "org_123" });
verifyAuditRecords(records); // { ok: true }

// Post-export tampering is detected: the stored hash no longer matches the
// record's canonical bytes.
const tampered = records.map((record) => ({
  ...record,
  event: { ...record.event, metadata: { fields: ["price"] } },
}));
verifyAuditRecords(tampered); // { ok: false, index: 0, reason: "hash_mismatch" }
```

`verifyEvidenceEdgeRecords` applies the same chain proof to evidence-graph
edges. See `examples/verify-tamper-detection` for every tamper class
(edit / delete / reorder / manifest swap) exercised end to end.

## Evidence Commits

`createEvidenceCommit` binds already-persisted records into an ordered Merkle
manifest, itself hash-chained per stream — the export-format layer that proves
a bundle's membership was not edited after commit:

```ts
import { createEvidenceCommit, verifyEvidenceCommits } from "@veritio/core";

const commit = createEvidenceCommit({
  commitId: "cmt_01",
  streamId: "str_org_123",
  sequence: 1,
  previousCommitHash: null,
  members: records.map((record, index) => ({
    index,
    recordType: "audit.record",
    recordId: record.event.id,
    recordHash: `sha256:${record.hash}`,
  })),
});

verifyEvidenceCommits([commit]); // { ok: true }
```

## Risk Scoring

Deterministic, explainable risk math pinned by cross-language conformance
fixtures: the same signals produce byte-identical scores in TypeScript, Python,
and Go (`veritio.reference.v1` policy).

```ts
import { rollupEpisodeRisk, scoreRiskSignals, withRiskSignals } from "@veritio/core";

const step = scoreRiskSignals({
  operationType: "delete",
  reversibility: "irreversible",
  envCriticality: "production",
  dataVolume: 250,
});
// step.score (0..1), step.level ("none".."critical"), step.factors — the full
// per-factor contribution breakdown for explainability.

const episode = rollupEpisodeRisk([
  { occurredAt: "2026-07-03T10:00:00.000Z", score: step.score },
  { occurredAt: "2026-07-03T10:00:20.000Z", score: 0.35 },
]);
// episode.score, episode.peak, episode.velocityScore, episode.stepCount

// Attach normalized signals to any event's metadata (fail-closed validation):
const metadata = withRiskSignals({ table: "invoices" }, { operationType: "bulk", fanOut: 40 });
```

### Temperature-derived policies

`riskPolicy` derives a full scoring policy from the reference constants with a
single knob — `0` is most lenient, `0.5` is the reference policy byte-for-byte,
`1` is strictest (multiples of `0.01` only; fail-closed otherwise):

```ts
import { riskPolicy, scoreRiskSignals } from "@veritio/core";

const signals = { operationType: "delete", envCriticality: "production" } as const;
scoreRiskSignals(signals, riskPolicy({ temperature: 0.2 })).level; // lenient banding
scoreRiskSignals(signals, riskPolicy({ temperature: 0.5 })).level; // reference banding
scoreRiskSignals(signals, riskPolicy({ temperature: 0.8 })).level; // strict banding
// Derived policyVersion is deterministic: "veritio.reference.v1+temp0.80"
```

Granular `overrides` deep-merge after derivation and require an explicit
`overrides.policyVersion` (fail closed), so hand-tuned policies stay honestly
labeled in hashed conclusions.

### Frequency rules (per-action bursts)

Episode rollups can detect action bursts — e.g. repeated failed logins — via
`rollup.frequencyRules`; steps carry an optional `action` and a fired rule can
only raise the episode score:

```ts
import { riskPolicy, rollupEpisodeRisk } from "@veritio/core";

const policy = riskPolicy({
  overrides: {
    policyVersion: "acme.auth-burst.v1",
    rollup: {
      frequencyRules: [{ actions: ["auth.login.failed"], windowSeconds: 300, threshold: 5, boost: 0.8 }],
    },
  },
});
const burst = rollupEpisodeRisk(
  failedLogins.map((e) => ({ occurredAt: e.occurredAt, score: 0.1, action: "auth.login.failed" })),
  policy,
);
// burst.frequencyScore === 0.8 → burst.level "critical" when >= 5 land inside 300s
```

Browser/edge bundles should import the crypto-free math directly from the
`@veritio/core/risk-score` subpath so `node:crypto` never enters the bundle.
See `docs/risk-scoring.md` for the scoring model and `spec/risk-scoring.md` for
the normative algorithm.

## security.risk Assertions

Publish a computed conclusion as an append-only, hashable assertion record and
a `security.risk.assessed` audit event:

```ts
import { buildSecurityRiskAssessedEvent, createSecurityRiskAssertion, hashAssertionRecord } from "@veritio/core";

const assertion = createSecurityRiskAssertion({
  scope: { tenantId: "org_123" },
  producerId: "risk_engine_1",
  subject: { authority: "veritio", kind: "activity", type: "agent_session", id: "sess_01" },
  idempotencyKey: "sess_01:step_9",
  conclusion: { score: step.score, level: step.level, policyVersion: step.policyVersion, assessment: "step" },
  factors: step.factors,
});
const assertionHash = hashAssertionRecord(assertion); // parity with hashAuditRecord

const eventInput = buildSecurityRiskAssessedEvent({
  scope: { tenantId: "org_123" },
  producerId: "risk_engine_1",
  subject: { authority: "veritio", kind: "activity", type: "agent_session", id: "sess_01" },
  conclusion: { score: step.score, level: step.level, policyVersion: step.policyVersion, assessment: "step" },
});
await recorder.record(eventInput);
```

## Agent Provenance Recorder

`createProvenanceRecorder` emits the `agent.*`, `change.*`, `review.*`, `ci.*`,
and `deploy.*` event families plus the evidence-graph edges connecting a
session's prompts, tool calls, file changes, reviews, builds, and deploys. The
host injects the event/edge sinks — the SDK core never touches storage or
environment state. `@veritio/storage`'s `createFileEvidenceStore` implements
both sinks out of the box:

```ts
import { createProvenanceRecorder } from "@veritio/core";
import { createFileEvidenceStore } from "@veritio/storage";

const provenance = createProvenanceRecorder(createFileEvidenceStore("./evidence"));
const { session } = await provenance.startSession({
  scope: { tenantId: "org_123", environment: "development" },
  sessionId: "sess_01",
  initiatedBy: { type: "user", id: "usr_123" },
  agentActor: { type: "ai_agent", id: "agent_claude_code" },
  agent: { name: "claude-code" },
  model: { provider: "anthropic", name: "claude-fable-5" },
});

await session.recordPrompt({ promptHash: "sha256-of-the-raw-prompt" });
await session.recordToolCall({ toolCallId: "tc_1", tool: "Edit", status: "succeeded" });
```

Only stable ids and content hashes travel — never raw prompts, diffs, or file
contents. `@veritio/claude-code` wires this recorder to Claude Code hooks
automatically; see `examples/claude-code-capture`.

## Governed Change Capture

`defineEntity` + `createGovernedActionDraft` are the default server-side DX for
forms, server actions, API routes, and worker mutations. The helper derives
stable change/activity ids, tenant-scoped idempotency hashes, and changed paths,
then delegates to `createGovernedChangeDraft` for the protocol event and edge
shape. Field policies (`full`, `keyed_digest`, `omit`) keep revision evidence
minimized by construction — a customer email can be proven changed without the
value ever entering evidence. See `docs/integrations.md` and the
`*-better-auth` examples for the full draft → outbox → read-model flow.

## Cross-Language Parity

Event creation, redaction, canonical JSON, record hashing, evidence commits
(`verifyEvidenceCommits`), risk scoring, `security.risk` assertion builders,
and the audit templates are byte-compatible across the TypeScript, Python, and
Go SDKs, pinned by `spec/conformance` fixtures. `MemoryAuditStore`,
`verifyAuditRecords` / `verifyEvidenceEdgeRecords`, and the provenance recorder
are TypeScript-only today (parity tracked in the repo rules).

Veritio supports evidence collection and verification workflows. It is not legal advice and does not make an application automatically compliant with any regulation or framework.
