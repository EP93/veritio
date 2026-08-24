# Veritio Python SDK

Initial Python SDK for creating normalized audit events and evidence graph edges, then verifying tamper-evident hashes.

```python
from veritio import create_evidence_edge, hash_evidence_edge

edge = create_evidence_edge(
    {
        "from": {"type": "agent_session", "id": "agt_sess_123"},
        "relation": "created",
        "to": {"type": "file", "id": "file_billing_plan", "pathHash": "sha256:..."},
        "scope": {"tenantId": "org_123", "environment": "production"},
        "metadata": {"reason": "ai_agent"},
    }
)

edge_hash = hash_evidence_edge(edge)
```

Audit templates return ordinary audit-event input dictionaries for common auth,
organization, data, agent, and code-change actions:

```python
from veritio import audit_log_classification_metadata, auth_session_created_template, create_audit_event

event = create_audit_event(
    auth_session_created_template(
        user_id="usr_123",
        session_id="sess_123",
        scope={"tenantId": "org_123", "environment": "production"},
        security_context={
            "ip_address_hash": "sha256:client-ip",
            "user_agent_hash": "sha256:user-agent",
            "location": {"country": "US", "region": "CA"},
        },
        metadata=audit_log_classification_metadata(visibility="customer", surface="app"),
    )
)
```

`audit_log_classification_metadata` and `detect_audit_log_classifiers` provide
portable filters for internal/external/partner/system logs and
api/app/worker/cli/webhook surfaces. They only use metadata keys
(`logVisibility`, `logSurface`); they are not protocol fields.

## Audit Retention Checkpoints

Python exposes the same audit-only checkpoint and disposition records as the
TypeScript and Go SDKs. Callers provide ids and UTC-millisecond timestamps; the
helpers do not read a clock, environment, provider, or legal-hold state.
`verify_audit_records_from_checkpoint` is deliberately separate from the
existing genesis-only audit verifier.

```python
from veritio import (
    create_retention_checkpoint,
    create_retention_disposition,
    verify_audit_records_from_checkpoint,
    verify_retention_checkpoint_chain,
    verify_retention_disposition,
)

checkpoint = create_retention_checkpoint({
    "checkpointId": "rcp_org_123_1",
    "tenantId": "org_123",
    "chainKind": "audit",
    "epoch": 1,
    "fromSequence": 1,
    "fromPreviousHash": None,
    "throughSequence": 1000,
    "throughHash": "a" * 64,
    "recordCount": 1000,
    "archiveRootHash": "b" * 64,
    "previousCheckpointHash": None,
    "createdAt": "2026-08-24T00:00:00.000Z",
})
verify_retention_checkpoint_chain([checkpoint])
verify_audit_records_from_checkpoint(checkpoint, retained_audit_records)

receipt = create_retention_disposition({
    "dispositionId": "rdp_org_123_1",
    "tenantId": "org_123",
    "chainKind": "audit",
    "checkpointHash": checkpoint["hash"],
    "fromSequence": checkpoint["fromSequence"],
    "throughSequence": checkpoint["throughSequence"],
    "archiveRootHash": checkpoint["archiveRootHash"],
    "policyReference": "retention-policy-v1",
    "disposedAt": "2026-08-24T00:05:00.000Z",
})
verify_retention_disposition(receipt, checkpoint)
```

Callers may inject a signature verifier and trusted public key; a requested
signature fails closed when unavailable. The checkpoint/receipt are an audit
trail of a verified anchor and provider-delete attempt, not proof that every
replica or backup is erased. Disposed epoch bodies cannot be replayed. In v1,
evidence-edge and `EvidenceCommit` retention remain non-capable, while
checkpoint-aware export behavior is `vevb-2` with a complete checkpoint chain
and retained audit tail; existing `vevb-1` remains immutable and default.

## Governed Action Drafts

Use `define_entity` + `create_governed_action_draft` inside FastAPI routes,
service methods, or workers that already own authorization, tenant scope,
before/after rows, and storage. The helper derives stable change/activity ids,
tenant-scoped idempotency hashes, and changed paths before delegating to the
lower-level governed-change builder.

```python
from veritio import create_governed_action_draft, define_entity

project_entity = define_entity(
    authority="app.example",
    entity_type="project_entry",
    schema_ref="app.example/project-entry@1",
    field_set_ref="project-entry-governed-fields@1",
    identity=lambda row: row["id"],
    fields={"status": {"capture": "full"}, "customerEmail": {"capture": "keyed_digest"}},
)

draft = create_governed_action_draft(
    {
        "scope": {"tenantId": "org_123", "environment": "production"},
        "entity": project_entity,
        "before": before,
        "after": after,
        "actionType": "project_entry.updated",
        "activityType": "project_entry.updated",
        "initiatedBy": {"authority": "app.example.auth", "kind": "principal", "type": "user", "id": "usr_123"},
        "performedBy": {"authority": "app.example.auth", "kind": "principal", "type": "user", "id": "usr_123"},
        "producer": {"authority": "app.example", "kind": "principal", "type": "service", "id": "api"},
        "idempotencyKey": f"project_entry:{after['id']}:v{after['version']}",
        "mutationBinding": "same_transaction",
        "digestKeys": {"keyedDigest": {"keyVersion": "email-v1", "secret": tenant_digest_secret}},
    }
)
```

See `docs/integrations.md` and `examples/fastapi-governed-crud` for a complete
route and local evidence-chain example.

## Risk Scoring

Deterministic, explainable risk math pinned by cross-language conformance
fixtures: the same signals produce byte-identical scores in TypeScript, Python,
and Go (`veritio.reference.v1` policy).

```python
from veritio import risk_policy, rollup_episode_risk, score_risk_signals, with_risk_signals

step = score_risk_signals(
    {
        "operationType": "delete",
        "reversibility": "irreversible",
        "envCriticality": "production",
        "dataVolume": 250,
    }
)
# step["score"] (0..1), step["level"] ("none".."critical"), step["factors"]

episode = rollup_episode_risk(
    [
        {"occurredAt": "2026-07-03T10:00:00.000Z", "score": step["score"]},
        {"occurredAt": "2026-07-03T10:00:20.000Z", "score": 0.35},
    ]
)
# episode["score"], episode["peak"], episode["velocityScore"], episode["stepCount"]

# Attach normalized signals to any event's metadata (fail-closed validation):
metadata = with_risk_signals({"table": "invoices"}, {"operationType": "bulk", "fanOut": 40})
```

`risk_policy` derives a full policy from the reference constants with one
temperature knob (`0` lenient, `0.5` = reference policy byte-for-byte, `1`
strictest; multiples of `0.01` only). Overrides deep-merge after derivation and
require an explicit `policyVersion`:

```python
strict = risk_policy({"temperature": 0.8})
# strict["policyVersion"] == "veritio.reference.v1+temp0.80"

burst_policy = risk_policy(
    {
        "overrides": {
            "policyVersion": "acme.auth-burst.v1",
            "rollup": {
                "frequencyRules": [
                    # >= 5 failed logins inside any 300s window adds a 0.8 boost.
                    {"actions": ["auth.login.failed"], "windowSeconds": 300, "threshold": 5, "boost": 0.8}
                ]
            },
        }
    }
)
rollup = rollup_episode_risk(
    [{"occurredAt": e["occurredAt"], "score": 0.1, "action": "auth.login.failed"} for e in failed_logins],
    burst_policy,
)
# rollup["frequencyScore"], rollup["frequencyMatches"] — rules only ever raise a score.
```

## security.risk Assertions

Publish a computed conclusion as an append-only, hashable assertion record:

```python
from veritio import create_security_risk_assertion, hash_assertion_record

assertion = create_security_risk_assertion(
    {
        "scope": {"tenantId": "org_123"},
        "producerId": "risk_engine_1",
        "subject": {"authority": "veritio", "kind": "activity", "type": "agent_session", "id": "sess_01"},
        "idempotencyKey": "sess_01:step_9",
        "conclusion": {
            "score": step["score"],
            "level": step["level"],
            "policyVersion": step["policyVersion"],
            "assessment": "step",
        },
        "factors": step["factors"],
    }
)
assertion_hash = hash_assertion_record(assertion)  # parity with hash_audit_record
```

See `docs/risk-scoring.md` for the scoring model and `spec/risk-scoring.md` for
the normative algorithm.
