# Veritio Go SDK

Go implementation of the Veritio evidence protocol: normalized audit events,
evidence-graph edges, canonical JSON, tamper-evident hashing, and deterministic
risk scoring — byte-identical with the TypeScript and Python SDKs, pinned by
the `spec/conformance` fixtures.

```go
import veritio "github.com/getveritio/veritio/sdks/go"
```

## Audit events

```go
event, err := veritio.CreateAuditEvent(veritio.AuditEventInput{
    OccurredAt: "2026-07-03T10:00:00.000Z",
    Actor:      veritio.Principal{Type: "user", ID: "usr_123"},
    Action:     "billing.plan.updated",
    Target:     veritio.Resource{Type: "billing.plan", ID: "plan_pro"},
    Scope:      &veritio.EvidenceScope{TenantID: "org_123", Environment: "production"},
})
hash, err := veritio.HashAuditEvent(event, nil) // previous hash chains records
```

## Audit Retention Checkpoints

The Go SDK provides the same portable, audit-only checkpoint/disposition
helpers as TypeScript and Python. The caller provides identifiers and exact UTC
millisecond times; core does not read clocks, environment, providers, or
legal-hold state. Existing genesis-only audit verification is unchanged; use
the anchored verifier for the retained tail.

```go
import (
    "fmt"
    "strings"

    veritio "github.com/getveritio/veritio/sdks/go"
)

func verifyRetainedTail(retainedAuditRecords []veritio.AuditRecord) error {
    checkpoint, err := veritio.CreateRetentionCheckpoint(veritio.RetentionCheckpointInput{
        CheckpointID: "rcp_org_123_1", TenantID: "org_123", ChainKind: "audit",
        Epoch: 1, FromSequence: 1, ThroughSequence: 1000,
        ThroughHash: strings.Repeat("a", 64), RecordCount: 1000,
        ArchiveRootHash: strings.Repeat("b", 64),
        CreatedAt: "2026-08-24T00:00:00.000Z",
    }, nil)
    if err != nil { return err }

    if result := veritio.VerifyRetentionCheckpointChain([]veritio.RetentionCheckpoint{checkpoint}, nil); !result.OK {
        return fmt.Errorf("checkpoint verification failed: %s", result.Reason)
    }
    if result := veritio.VerifyAuditRecordsFromCheckpoint(checkpoint, retainedAuditRecords, nil); !result.OK {
        return fmt.Errorf("tail verification failed: %s", result.Reason)
    }
    return nil
}
```

Optional detached signatures are checked through caller-supplied trust and
verification inputs, failing closed when required but unavailable. A checkpoint
and provider-delete receipt are evidence of a verified anchor and deletion
attempt, not proof that every provider replica or backup was erased; disposed
epoch bodies cannot be replayed. Evidence-edge and `EvidenceCommit` retention
are deliberately non-capable in v1. Checkpoint-aware exports are `vevb-2`
with the full checkpoint chain and retained audit tail; existing `vevb-1`
remains immutable and default.

## Governed Action Drafts

Use `DefineEntity` + `CreateGovernedActionDraft` inside Gin handlers, service
methods, or workers that already own authorization, tenant scope, before/after
rows, and storage. The helper derives stable change/activity ids, tenant-scoped
idempotency hashes, and changed paths before delegating to the lower-level
governed-change builder.

```go
projectEntry, err := veritio.DefineEntity(veritio.GovernedEntityDefinition{
    Authority: "app.example",
    Type: "project_entry",
    SchemaRef: "app.example/project-entry@1",
    FieldSetRef: "project-entry-governed-fields@1",
    Identity: func(row map[string]any) string { return row["id"].(string) },
    Fields: map[string]veritio.EntityFieldPolicy{
        "status": {Capture: "full"},
        "customerEmail": {Capture: "keyed_digest"},
    },
})
if err != nil {
    return err
}

draft, err := veritio.CreateGovernedActionDraft(veritio.GovernedActionDraftInput{
    Scope: veritio.EvidenceScope{TenantID: "org_123", Environment: "production"},
    Entity: projectEntry,
    Before: before,
    After: after,
    ActionType: "project_entry.updated",
    ActivityType: "project_entry.updated",
    InitiatedBy: veritio.EvidenceRef{Authority: "app.example.auth", Kind: "principal", Type: "user", ID: "usr_123"},
    PerformedBy: veritio.EvidenceRef{Authority: "app.example.auth", Kind: "principal", Type: "user", ID: "usr_123"},
    Producer: veritio.EvidenceRef{Authority: "app.example", Kind: "principal", Type: "service", ID: "api"},
    IdempotencyKey: fmt.Sprintf("project_entry:%s:v%d", after["id"], after["version"]),
    MutationBinding: "same_transaction",
    DigestKeys: veritio.DigestKeys{KeyedDigest: &veritio.KeyedDigestKey{KeyVersion: "email-v1", Secret: tenantDigestSecret}},
})
```

See `docs/integrations.md` and `examples/gin-governed-crud` for a complete
route and local evidence-chain example.

## Risk Scoring

Deterministic, explainable risk math (`veritio.reference.v1` policy):

```go
step, err := veritio.ScoreRiskSignals(veritio.RiskSignals{
    OperationType:  "delete",
    Reversibility:  "irreversible",
    EnvCriticality: "production",
    DataVolume:     250,
}, veritio.DefaultRiskPolicy)
// step.Score (0..1), step.Level ("none".."critical"), step.Factors

episode, err := veritio.RollupEpisodeRisk([]veritio.EpisodeRiskStep{
    {OccurredAt: "2026-07-03T10:00:00.000Z", Score: step.Score},
    {OccurredAt: "2026-07-03T10:00:20.000Z", Score: 0.35},
}, veritio.DefaultRiskPolicy)

// Attach normalized signals to event metadata (fail-closed validation):
metadata, err := veritio.WithRiskSignals(map[string]any{"table": "invoices"},
    veritio.RiskSignals{OperationType: "bulk", FanOut: 40})
```

`RiskPolicy` derives a full policy from the reference constants with one
temperature knob (`0` lenient, `0.5` = reference policy byte-for-byte, `1`
strictest; multiples of `0.01` only). Overrides apply after derivation and
require an explicit `PolicyVersion`:

```go
strict, err := veritio.RiskPolicy(veritio.RiskPolicyOptions{Temperature: veritio.Float64(0.8)})
// strict.PolicyVersion == "veritio.reference.v1+temp0.80"
```

Episode rollups detect per-action bursts (e.g. repeated failed logins) via
`RiskRollupPolicy.FrequencyRules`; steps carry an optional `Action` and a fired
rule can only raise the episode score. See `docs/risk-scoring.md` for the
scoring model and `spec/risk-scoring.md` for the normative algorithm.

## security.risk Assertions

```go
assertion, err := veritio.CreateSecurityRiskAssertion(veritio.SecurityRiskAssertionInput{
    Scope:          veritio.EvidenceScope{TenantID: "org_123"},
    ProducerID:     "risk_engine_1",
    Subject:        veritio.EvidenceRef{Authority: "veritio", Kind: "activity", Type: "agent_session", ID: "sess_01"},
    IdempotencyKey: "sess_01:step_9",
    Conclusion:     veritio.RiskConclusion{Score: step.Score, Level: step.Level, PolicyVersion: step.PolicyVersion, Assessment: "step"},
    Factors:        step.Factors,
})
assertionHash, err := veritio.HashAssertionRecord(assertion) // parity with HashAuditRecord
```

## Testing

```sh
go test ./...
```

The suite consumes the shared `spec/conformance` fixtures, so a green run
proves cross-language parity for events, hashing, redaction, governed-action
drafts, and risk scoring.
