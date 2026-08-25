# Retention checkpoint protocol v1

Retention checkpoints preserve audit-chain continuity after an authoritative store removes a verified contiguous prefix. They are evidence-support records, not proof that every physical copy was erased and not a decision about a lawful retention period.

## Checkpoint record

`retention-checkpoint.schema.json` is the normative shape. V1 is audit-only. IDs match `^[A-Za-z0-9._:-]{1,128}$`; integer fields are `1..9007199254740991`; timestamps are exact UTC milliseconds. The unsigned payload contains every field except `hash` and `signature`, including `signaturePublicKeyFingerprint` when signing is used. Its hash is lowercase `SHA-256(canonicalJson(unsignedPayload))` using `veritio-json-v1`.

Epoch 1 begins at sequence 1 with null prior record and checkpoint hashes. Each later epoch increments by one, begins at the prior checkpoint's `throughSequence + 1`, carries that checkpoint's `throughHash` as `fromPreviousHash`, and links `previousCheckpointHash` to the prior checkpoint hash. `recordCount` is exactly `throughSequence - fromSequence + 1`.

`archiveRootHash` is provider-neutral: SHA-256 of canonical JSON for the ordered, exactly contiguous array of covered segment descriptors. Bucket names and object keys are excluded. A checkpoint is not an `AuditStore`, does not reset sequence numbers, and never changes an existing audit record hash.

## Detached signatures

Unsigned records omit both fingerprint and signature fields. Signed records bind `signaturePublicKeyFingerprint` into the checkpoint or disposition hash, then sign the UTF-8 bytes of that 64-character lowercase hash. The signature object uses `algorithm: "ed25519"`, standard padded base64, and the same public-key fingerprint. Both fingerprints equal SHA-256 of the raw public key bytes.

Verification is host-injected and reports `valid`, `invalid`, `skipped`, or `absent`. A present signature without a trusted key/verifier is `skipped`; a caller-required signature fails when absent or skipped. Unknown algorithms, malformed base64, fingerprint mismatches, or verifier failures are invalid.

## Anchored verification

A checkpoint chain has one tenant and chain kind, consecutive epochs, exact range and hash continuity, and valid record hashes. Retained-tail verification starts at the checkpoint's `throughSequence` and `throughHash`. An empty tail is valid; otherwise the first record is sequence `throughSequence + 1` with `previousHash === throughHash`, and all later records follow the existing strict audit-record rules.

## Disposition receipt

`retention-disposition.schema.json` retains the checkpoint hash, exact range, archive root, fixed `provider-delete` method, non-personal policy reference, and caller-supplied UTC-millisecond time. Verification always receives the referenced checkpoint and requires exact tenant, chain kind, checkpoint hash, range, and archive-root equality. The receipt excludes event bodies, legal-hold reasons, user identity, provider keys/responses, and event metadata. It attests to the accepted disposal operation but cannot prove deletion from backups, replicas, or provider media. The `@veritio/storage` coordinator obtains this time from its host-injected asynchronous resolver only after provider deletion and direct-plus-prefix absence confirmation. Receipt-persistence failure may re-invoke that resolver, so the host must durably return the same time for the same exact tenant/checkpoint/attempt/disposition/policy-fence context. These coordinator rules do not add a field or host clock to the language-neutral receipt schema.
