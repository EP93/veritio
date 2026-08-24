# Veritio Evidence Export Bundle v2 — `vevb-2` (normative)

`vevb-2` is the checkpoint-aware export format. It is a new discriminator, not
an extension that changes any `vevb-1` byte, hash, parser verdict, API default,
or output. The v1 format remains normative in `export-bundle.md`.

## Container and deterministic bytes

The container has exactly `bundleVersion`, `manifest`, `files`, and an optional
detached `signature`. `bundleVersion` is `vevb-2` in both the container and
manifest. Unknown versions, keys, algorithms, or shapes fail closed. Record
files use the v1 canonical JSONL rule: one `veritio-json-v1` record per line, a
single trailing newline, and the empty string for zero records.

The mandatory file map contains exactly:

- `records/audit-events.jsonl`
- `records/evidence-edges.jsonl`
- `records/commits.jsonl`
- `records/retention-checkpoints.jsonl`
- `records/retention-dispositions.jsonl`
- `verification.json`

Every manifest entry is `{ path, sha256, records }`. `sha256` covers the exact
UTF-8 file bytes. `records` is the JSONL line count (`verification.json` uses
zero). `rootHash` is SHA-256 of canonical JSON for a copy of the six entries
sorted by path with raw UTF-16 code-unit ordering, identical to v1.

The optional Ed25519 bundle signature uses the v1 contract: its public-key
fingerprint is bound into the manifest, and the signature covers the UTF-8 bytes
of the 64-character SHA-256 of canonical manifest JSON. Signature trust is
caller-injected; core reads no environment, clock, or random source.

## Closed chain claims

`manifest.chainClaims` is mandatory and exact:

```json
{
  "audit": {
    "origin": { "kind": "checkpoint", "checkpointHash": "<64 lowercase hex>" },
    "completeness": "complete-retained-tail"
  },
  "evidenceEdges": {
    "origin": { "kind": "genesis" },
    "completeness": "full"
  },
  "evidenceCommits": {
    "origin": { "kind": "genesis" },
    "completeness": "empty"
  }
}
```

Audit may instead claim `{ origin: { kind: "genesis" }, completeness: "full" }`.
No origin is inferred while parsing. A genesis audit claim requires empty
checkpoint and disposition files and verifies with the existing full audit
verifier. A checkpoint origin requires `complete-retained-tail`; it cannot be
combined with a window, filter, or caller-defined completeness string.

Evidence edges are always a full chain from genesis and use the existing strict
edge verifier. Evidence commits are always genesis/empty and their file must be
the empty string. Retention v1 does not compact either record family.

## Checkpoint and disposition verification

For checkpoint origin, `retention-checkpoints.jsonl` contains the complete
checkpoint chain from epoch 1 through the selected latest checkpoint. The
manifest `checkpointHash` equals that latest checkpoint's hash. Verification
applies the retention checkpoint shape, algorithm, record hash, optional
signature policy, tenant, epoch, range, previous-tip, and previous-checkpoint
linkage rules in `retention-checkpoints.md`.

`retention-dispositions.jsonl` contains zero or one receipt for each included
checkpoint, in checkpoint epoch order. Each receipt must bind exactly the
included checkpoint's tenant, chain kind, checkpoint hash, range bounds, and
archive root. Duplicate, conflicting, reordered, or unbound receipts fail
closed. An absent receipt is never synthesized.

The audit file is the entire authoritative tail after the selected checkpoint.
Its first record must be sequence `throughSequence + 1` with `previousHash`
equal to the checkpoint `throughHash`; every later record is contiguous and
hash-valid under the anchored verifier. An empty tail is valid because the
checkpoint itself is the current anchor. A non-empty genesis audit file instead
starts at sequence 1 under the existing full verifier.

## Verification report and claims boundary

`verification.json` is canonical JSON with exact `checkpoints`, `dispositions`,
`audit`, `edges`, and `commits` verdicts. Checkpoint and disposition verdicts
also report the aggregate signature status: `valid`, `invalid`, `skipped`, or
`absent`. An offline verifier recomputes every verdict and requires exact
agreement with the embedded report. CLI and server summaries expose only these
verdicts and static issue strings; they do not print raw event bodies.

A valid bundle supports a tamper-evident continuity claim from its declared
origin. A checkpoint or disposition is not proof that every provider replica,
backup, or physical copy was erased, and this format does not guarantee legal
compliance or decide a retention period.

The committed `export-bundle-v2-golden.json` and
`export-bundle-v2-tampered.json` conformance artifacts pin the format. The v1
golden container remains independently pinned and unchanged. The tampered v2
fixture changes the first nibble of the latest checkpoint's `throughHash`
without updating the checkpoint hash, file digest, or root hash; an offline
verifier must report `valid: false`, `integrity: false`, and
`checkpoints: false`.
