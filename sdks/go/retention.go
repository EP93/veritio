package veritio

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"time"
)

const RetentionSchemaVersion = "1.0"
const RetentionCanonicalization = "veritio-json-v1"
const RetentionHashAlgorithm = "sha256"

var retentionIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var retentionPolicyReferencePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,256}$`)
var retentionHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var retentionTimestampPattern = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$`)
var retentionSignaturePattern = regexp.MustCompile(`^[A-Za-z0-9+/]{86}==$`)

type RetentionSignature struct {
	Algorithm            string `json:"algorithm"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint"`
	Signature            string `json:"signature"`
}

type RetentionCheckpointInput struct {
	CheckpointID                  string  `json:"checkpointId"`
	TenantID                      string  `json:"tenantId"`
	ChainKind                     string  `json:"chainKind"`
	Epoch                         int     `json:"epoch"`
	FromSequence                  int     `json:"fromSequence"`
	FromPreviousHash              *string `json:"fromPreviousHash"`
	ThroughSequence               int     `json:"throughSequence"`
	ThroughHash                   string  `json:"throughHash"`
	RecordCount                   int     `json:"recordCount"`
	ArchiveRootHash               string  `json:"archiveRootHash"`
	PreviousCheckpointHash        *string `json:"previousCheckpointHash"`
	CreatedAt                     string  `json:"createdAt"`
	SignaturePublicKeyFingerprint string  `json:"signaturePublicKeyFingerprint,omitempty"`
}

type RetentionCheckpoint struct {
	RecordType                    string              `json:"recordType"`
	SchemaVersion                 string              `json:"schemaVersion"`
	CheckpointID                  string              `json:"checkpointId"`
	TenantID                      string              `json:"tenantId"`
	ChainKind                     string              `json:"chainKind"`
	Epoch                         int                 `json:"epoch"`
	FromSequence                  int                 `json:"fromSequence"`
	FromPreviousHash              *string             `json:"fromPreviousHash"`
	ThroughSequence               int                 `json:"throughSequence"`
	ThroughHash                   string              `json:"throughHash"`
	RecordCount                   int                 `json:"recordCount"`
	ArchiveRootHash               string              `json:"archiveRootHash"`
	PreviousCheckpointHash        *string             `json:"previousCheckpointHash"`
	CreatedAt                     string              `json:"createdAt"`
	Canonicalization              string              `json:"canonicalization"`
	HashAlgorithm                 string              `json:"hashAlgorithm"`
	SignaturePublicKeyFingerprint string              `json:"signaturePublicKeyFingerprint,omitempty"`
	Hash                          string              `json:"hash"`
	Signature                     *RetentionSignature `json:"signature,omitempty"`
}

type RetentionDispositionInput struct {
	DispositionID                 string `json:"dispositionId"`
	TenantID                      string `json:"tenantId"`
	ChainKind                     string `json:"chainKind"`
	CheckpointHash                string `json:"checkpointHash"`
	FromSequence                  int    `json:"fromSequence"`
	ThroughSequence               int    `json:"throughSequence"`
	ArchiveRootHash               string `json:"archiveRootHash"`
	PolicyReference               string `json:"policyReference"`
	DisposedAt                    string `json:"disposedAt"`
	SignaturePublicKeyFingerprint string `json:"signaturePublicKeyFingerprint,omitempty"`
}

type RetentionDisposition struct {
	RecordType                    string              `json:"recordType"`
	SchemaVersion                 string              `json:"schemaVersion"`
	DispositionID                 string              `json:"dispositionId"`
	TenantID                      string              `json:"tenantId"`
	ChainKind                     string              `json:"chainKind"`
	CheckpointHash                string              `json:"checkpointHash"`
	FromSequence                  int                 `json:"fromSequence"`
	ThroughSequence               int                 `json:"throughSequence"`
	ArchiveRootHash               string              `json:"archiveRootHash"`
	Method                        string              `json:"method"`
	PolicyReference               string              `json:"policyReference"`
	DisposedAt                    string              `json:"disposedAt"`
	Canonicalization              string              `json:"canonicalization"`
	HashAlgorithm                 string              `json:"hashAlgorithm"`
	SignaturePublicKeyFingerprint string              `json:"signaturePublicKeyFingerprint,omitempty"`
	Hash                          string              `json:"hash"`
	Signature                     *RetentionSignature `json:"signature,omitempty"`
}

type RetentionSignatureVerifier func(publicKey, signature, message []byte) bool

type RetentionVerificationOptions struct {
	TrustedPublicKey  []byte
	RequireSignature  bool
	SignatureVerifier RetentionSignatureVerifier
}

type RetentionVerificationResult struct {
	OK        bool   `json:"ok"`
	Index     int    `json:"index,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Signature string `json:"signature"`
}

/*
CreateRetentionCheckpoint constructs a deterministic audit checkpoint without
reading host clocks, randomness, or trust configuration.
*/
func CreateRetentionCheckpoint(input RetentionCheckpointInput, signature *RetentionSignature) (RetentionCheckpoint, error) {
	if err := assertRetentionCheckpointInput(input); err != nil {
		return RetentionCheckpoint{}, err
	}
	if err := assertRetentionSignaturePair(input.SignaturePublicKeyFingerprint, signature); err != nil {
		return RetentionCheckpoint{}, err
	}
	checkpoint := RetentionCheckpoint{
		RecordType:                    "retention.checkpoint",
		SchemaVersion:                 RetentionSchemaVersion,
		CheckpointID:                  input.CheckpointID,
		TenantID:                      input.TenantID,
		ChainKind:                     input.ChainKind,
		Epoch:                         input.Epoch,
		FromSequence:                  input.FromSequence,
		FromPreviousHash:              copyStringPointer(input.FromPreviousHash),
		ThroughSequence:               input.ThroughSequence,
		ThroughHash:                   input.ThroughHash,
		RecordCount:                   input.RecordCount,
		ArchiveRootHash:               input.ArchiveRootHash,
		PreviousCheckpointHash:        copyStringPointer(input.PreviousCheckpointHash),
		CreatedAt:                     input.CreatedAt,
		Canonicalization:              RetentionCanonicalization,
		HashAlgorithm:                 RetentionHashAlgorithm,
		SignaturePublicKeyFingerprint: input.SignaturePublicKeyFingerprint,
		Signature:                     copyRetentionSignature(signature),
	}
	hash, err := HashRetentionCheckpoint(checkpoint)
	if err != nil {
		return RetentionCheckpoint{}, err
	}
	checkpoint.Hash = hash
	return checkpoint, nil
}

/*
HashRetentionCheckpoint hashes the canonical unsigned checkpoint payload and
excludes both its stored hash and detached signature.
*/
func HashRetentionCheckpoint(checkpoint RetentionCheckpoint) (string, error) {
	canonical, err := CanonicalJSON(retentionCheckpointHashPayload(checkpoint))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

/*
VerifyRetentionCheckpoint validates one checkpoint and delegates signature
verification through the caller-supplied verifier boundary.
*/
func VerifyRetentionCheckpoint(checkpoint RetentionCheckpoint, options *RetentionVerificationOptions) RetentionVerificationResult {
	return verifyRetentionCheckpointAt(checkpoint, options, 0)
}

/*
VerifyRetentionCheckpointChain validates a complete chain from epoch one with
exact tenant, range, prior-tip, and checkpoint-hash linkage.
*/
func VerifyRetentionCheckpointChain(checkpoints []RetentionCheckpoint, options *RetentionVerificationOptions) RetentionVerificationResult {
	signatureStatus := "valid"
	if len(checkpoints) == 0 {
		signatureStatus = "absent"
	}
	for index, checkpoint := range checkpoints {
		verified := verifyRetentionCheckpointAt(checkpoint, options, index)
		signatureStatus = combineRetentionSignatureStatus(signatureStatus, verified.Signature)
		if !verified.OK {
			verified.Signature = signatureStatus
			return verified
		}
		if checkpoint.Epoch != index+1 {
			return retentionFailure(index, "epoch_mismatch", signatureStatus)
		}
		if index == 0 {
			continue
		}
		previous := checkpoints[index-1]
		if checkpoint.TenantID != previous.TenantID {
			return retentionFailure(index, "tenant_mismatch", signatureStatus)
		}
		if checkpoint.ChainKind != previous.ChainKind {
			return retentionFailure(index, "chain_kind_mismatch", signatureStatus)
		}
		if checkpoint.FromSequence != previous.ThroughSequence+1 || !equalStringPointers(checkpoint.FromPreviousHash, &previous.ThroughHash) {
			return retentionFailure(index, "range_mismatch", signatureStatus)
		}
		if !equalStringPointers(checkpoint.PreviousCheckpointHash, &previous.Hash) {
			return retentionFailure(index, "previous_checkpoint_hash_mismatch", signatureStatus)
		}
	}
	return RetentionVerificationResult{OK: true, Signature: signatureStatus}
}

/*
VerifyAuditRecordsFromCheckpoint verifies a retained audit tail from the
checkpoint tip without changing the existing genesis-only chain semantics.
*/
func VerifyAuditRecordsFromCheckpoint(checkpoint RetentionCheckpoint, records []AuditRecord, options *RetentionVerificationOptions) RetentionVerificationResult {
	checkpointResult := VerifyRetentionCheckpoint(checkpoint, options)
	if !checkpointResult.OK {
		return checkpointResult
	}
	sequence := checkpoint.ThroughSequence
	previousHash := checkpoint.ThroughHash
	for index, record := range records {
		if record.Event.Scope == nil || record.Event.Scope.TenantID == "" {
			return retentionFailure(index, "missing_tenant_scope", checkpointResult.Signature)
		}
		if record.Event.Scope.TenantID != checkpoint.TenantID {
			return retentionFailure(index, "tenant_mismatch", checkpointResult.Signature)
		}
		if record.HashAlgorithm != RetentionHashAlgorithm {
			return retentionFailure(index, "unsupported_hash_algorithm", checkpointResult.Signature)
		}
		if record.Canonicalization != RetentionCanonicalization {
			return retentionFailure(index, "unsupported_canonicalization", checkpointResult.Signature)
		}
		if record.Sequence != sequence+1 {
			return retentionFailure(index, "sequence_mismatch", checkpointResult.Signature)
		}
		if record.PreviousHash == nil || *record.PreviousHash != previousHash {
			return retentionFailure(index, "previous_hash_mismatch", checkpointResult.Signature)
		}
		expectedHash, err := HashAuditRecord(record)
		if err != nil || record.Hash != expectedHash {
			return retentionFailure(index, "record_hash_mismatch", checkpointResult.Signature)
		}
		sequence = record.Sequence
		previousHash = record.Hash
	}
	return checkpointResult
}

/*
CreateRetentionDisposition constructs the minimal non-personal provider-delete
receipt and never accepts provider responses or event metadata.
*/
func CreateRetentionDisposition(input RetentionDispositionInput, signature *RetentionSignature) (RetentionDisposition, error) {
	if err := assertRetentionDispositionInput(input); err != nil {
		return RetentionDisposition{}, err
	}
	if err := assertRetentionSignaturePair(input.SignaturePublicKeyFingerprint, signature); err != nil {
		return RetentionDisposition{}, err
	}
	disposition := RetentionDisposition{
		RecordType:                    "retention.disposition",
		SchemaVersion:                 RetentionSchemaVersion,
		DispositionID:                 input.DispositionID,
		TenantID:                      input.TenantID,
		ChainKind:                     input.ChainKind,
		CheckpointHash:                input.CheckpointHash,
		FromSequence:                  input.FromSequence,
		ThroughSequence:               input.ThroughSequence,
		ArchiveRootHash:               input.ArchiveRootHash,
		Method:                        "provider-delete",
		PolicyReference:               input.PolicyReference,
		DisposedAt:                    input.DisposedAt,
		Canonicalization:              RetentionCanonicalization,
		HashAlgorithm:                 RetentionHashAlgorithm,
		SignaturePublicKeyFingerprint: input.SignaturePublicKeyFingerprint,
		Signature:                     copyRetentionSignature(signature),
	}
	hash, err := HashRetentionDisposition(disposition)
	if err != nil {
		return RetentionDisposition{}, err
	}
	disposition.Hash = hash
	return disposition, nil
}

/*
HashRetentionDisposition hashes the canonical unsigned receipt including its
optional bound public-key fingerprint.
*/
func HashRetentionDisposition(disposition RetentionDisposition) (string, error) {
	canonical, err := CanonicalJSON(retentionDispositionHashPayload(disposition))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

/*
VerifyRetentionDisposition verifies receipt integrity and requires exact
equality with the referenced checkpoint before accepting the disposal claim.
*/
func VerifyRetentionDisposition(disposition RetentionDisposition, checkpoint RetentionCheckpoint, options *RetentionVerificationOptions) RetentionVerificationResult {
	checkpointOptions := optionsWithoutRequiredSignature(options)
	checkpointResult := VerifyRetentionCheckpoint(checkpoint, checkpointOptions)
	if !checkpointResult.OK {
		return checkpointResult
	}
	if disposition.RecordType != "retention.disposition" || disposition.SchemaVersion != RetentionSchemaVersion || disposition.Method != "provider-delete" || disposition.Canonicalization != RetentionCanonicalization || disposition.HashAlgorithm != RetentionHashAlgorithm {
		return retentionFailure(0, "unsupported_protocol", "absent")
	}
	if err := assertRetentionDispositionInput(retentionDispositionAsInput(disposition)); err != nil {
		return retentionFailure(0, "invalid_disposition", "absent")
	}
	expectedHash, err := HashRetentionDisposition(disposition)
	if err != nil || !retentionHashPattern.MatchString(disposition.Hash) || disposition.Hash != expectedHash {
		return retentionFailure(0, "hash_mismatch", "absent")
	}
	signatureStatus, reason := verifyRetentionDetachedSignature(disposition.SignaturePublicKeyFingerprint, disposition.Signature, disposition.Hash, options)
	if reason != "" {
		return retentionFailure(0, reason, signatureStatus)
	}
	if disposition.TenantID != checkpoint.TenantID || disposition.ChainKind != checkpoint.ChainKind || disposition.CheckpointHash != checkpoint.Hash || disposition.FromSequence != checkpoint.FromSequence || disposition.ThroughSequence != checkpoint.ThroughSequence || disposition.ArchiveRootHash != checkpoint.ArchiveRootHash {
		return retentionFailure(0, "checkpoint_mismatch", signatureStatus)
	}
	return RetentionVerificationResult{OK: true, Signature: signatureStatus}
}

/*
verifyRetentionCheckpointAt applies protocol, hash, and injected-signature gates
to one checkpoint while retaining its stable input index.
*/
func verifyRetentionCheckpointAt(checkpoint RetentionCheckpoint, options *RetentionVerificationOptions, index int) RetentionVerificationResult {
	if checkpoint.RecordType != "retention.checkpoint" || checkpoint.SchemaVersion != RetentionSchemaVersion || checkpoint.Canonicalization != RetentionCanonicalization || checkpoint.HashAlgorithm != RetentionHashAlgorithm {
		return retentionFailure(index, "unsupported_protocol", "absent")
	}
	if err := assertRetentionCheckpointInput(retentionCheckpointAsInput(checkpoint)); err != nil {
		return retentionFailure(index, "invalid_checkpoint", "absent")
	}
	expectedHash, err := HashRetentionCheckpoint(checkpoint)
	if err != nil || !retentionHashPattern.MatchString(checkpoint.Hash) || checkpoint.Hash != expectedHash {
		return retentionFailure(index, "hash_mismatch", "absent")
	}
	signatureStatus, reason := verifyRetentionDetachedSignature(checkpoint.SignaturePublicKeyFingerprint, checkpoint.Signature, checkpoint.Hash, options)
	if reason != "" {
		return retentionFailure(index, reason, signatureStatus)
	}
	return RetentionVerificationResult{OK: true, Signature: signatureStatus}
}

/*
verifyRetentionDetachedSignature checks metadata and calls only an injected
verifier, keeping key authority outside the protocol core.
*/
func verifyRetentionDetachedSignature(fingerprint string, signature *RetentionSignature, hash string, options *RetentionVerificationOptions) (string, string) {
	requireSignature := options != nil && options.RequireSignature
	if fingerprint == "" && signature == nil {
		if requireSignature {
			return "absent", "signature_required"
		}
		return "absent", ""
	}
	if fingerprint == "" || signature == nil || signature.PublicKeyFingerprint != fingerprint {
		return "invalid", "signature_fingerprint_mismatch"
	}
	if signature.Algorithm != "ed25519" || !retentionSignaturePattern.MatchString(signature.Signature) {
		return "invalid", "signature_invalid"
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature.Signature)
	if err != nil || len(signatureBytes) != 64 {
		return "invalid", "signature_invalid"
	}
	if options == nil || len(options.TrustedPublicKey) == 0 || options.SignatureVerifier == nil {
		if requireSignature {
			return "skipped", "signature_required"
		}
		return "skipped", ""
	}
	keySum := sha256.Sum256(options.TrustedPublicKey)
	if hex.EncodeToString(keySum[:]) != fingerprint {
		return "invalid", "signature_fingerprint_mismatch"
	}
	if !options.SignatureVerifier(options.TrustedPublicKey, signatureBytes, []byte(hash)) {
		return "invalid", "signature_invalid"
	}
	return "valid", ""
}

/*
retentionCheckpointHashPayload selects only normative unsigned fields so
detached signature bytes or host extras cannot affect checkpoint hashes.
*/
func retentionCheckpointHashPayload(checkpoint RetentionCheckpoint) map[string]any {
	payload := map[string]any{
		"recordType": checkpoint.RecordType, "schemaVersion": checkpoint.SchemaVersion,
		"checkpointId": checkpoint.CheckpointID, "tenantId": checkpoint.TenantID, "chainKind": checkpoint.ChainKind,
		"epoch": checkpoint.Epoch, "fromSequence": checkpoint.FromSequence, "fromPreviousHash": checkpoint.FromPreviousHash,
		"throughSequence": checkpoint.ThroughSequence, "throughHash": checkpoint.ThroughHash, "recordCount": checkpoint.RecordCount,
		"archiveRootHash": checkpoint.ArchiveRootHash, "previousCheckpointHash": checkpoint.PreviousCheckpointHash,
		"createdAt": checkpoint.CreatedAt, "canonicalization": checkpoint.Canonicalization, "hashAlgorithm": checkpoint.HashAlgorithm,
	}
	if checkpoint.SignaturePublicKeyFingerprint != "" {
		payload["signaturePublicKeyFingerprint"] = checkpoint.SignaturePublicKeyFingerprint
	}
	return payload
}

/*
retentionDispositionHashPayload selects the fixed minimal receipt fields and
excludes its stored hash and detached signature.
*/
func retentionDispositionHashPayload(disposition RetentionDisposition) map[string]any {
	payload := map[string]any{
		"recordType": disposition.RecordType, "schemaVersion": disposition.SchemaVersion,
		"dispositionId": disposition.DispositionID, "tenantId": disposition.TenantID, "chainKind": disposition.ChainKind,
		"checkpointHash": disposition.CheckpointHash, "fromSequence": disposition.FromSequence, "throughSequence": disposition.ThroughSequence,
		"archiveRootHash": disposition.ArchiveRootHash, "method": disposition.Method, "policyReference": disposition.PolicyReference,
		"disposedAt": disposition.DisposedAt, "canonicalization": disposition.Canonicalization, "hashAlgorithm": disposition.HashAlgorithm,
	}
	if disposition.SignaturePublicKeyFingerprint != "" {
		payload["signaturePublicKeyFingerprint"] = disposition.SignaturePublicKeyFingerprint
	}
	return payload
}

/*
assertRetentionCheckpointInput enforces cross-language numeric, timestamp,
genesis, and internal range invariants before hashing.
*/
func assertRetentionCheckpointInput(input RetentionCheckpointInput) error {
	if !retentionIDPattern.MatchString(input.CheckpointID) || !retentionIDPattern.MatchString(input.TenantID) {
		return errors.New("checkpointId and tenantId must be portable ids")
	}
	if input.ChainKind != "audit" {
		return errors.New("chainKind must be audit")
	}
	if !retentionSafeInteger(input.Epoch) || !retentionSafeInteger(input.FromSequence) || !retentionSafeInteger(input.ThroughSequence) || !retentionSafeInteger(input.RecordCount) {
		return errors.New("retention numeric fields must be positive safe integers")
	}
	if !retentionHashPattern.MatchString(input.ThroughHash) || !retentionHashPattern.MatchString(input.ArchiveRootHash) || !retentionOptionalHash(input.FromPreviousHash) || !retentionOptionalHash(input.PreviousCheckpointHash) {
		return errors.New("retention hashes must be lowercase sha256")
	}
	if input.SignaturePublicKeyFingerprint != "" && !retentionHashPattern.MatchString(input.SignaturePublicKeyFingerprint) {
		return errors.New("signature fingerprint must be lowercase sha256")
	}
	if !retentionExactTimestamp(input.CreatedAt) {
		return errors.New("createdAt must be exact UTC milliseconds")
	}
	if input.ThroughSequence < input.FromSequence || input.RecordCount != input.ThroughSequence-input.FromSequence+1 {
		return errors.New("recordCount must equal the inclusive checkpoint range")
	}
	if input.Epoch == 1 {
		if input.FromSequence != 1 || input.FromPreviousHash != nil || input.PreviousCheckpointHash != nil {
			return errors.New("epoch one must begin at genesis")
		}
	} else if input.FromPreviousHash == nil || input.PreviousCheckpointHash == nil {
		return errors.New("later epochs must link prior record and checkpoint hashes")
	}
	return nil
}

/*
assertRetentionDispositionInput enforces the minimal non-personal receipt shape
and rejects unsafe ranges or policy references.
*/
func assertRetentionDispositionInput(input RetentionDispositionInput) error {
	if !retentionIDPattern.MatchString(input.DispositionID) || !retentionIDPattern.MatchString(input.TenantID) {
		return errors.New("dispositionId and tenantId must be portable ids")
	}
	if input.ChainKind != "audit" {
		return errors.New("chainKind must be audit")
	}
	if !retentionHashPattern.MatchString(input.CheckpointHash) || !retentionHashPattern.MatchString(input.ArchiveRootHash) {
		return errors.New("disposition hashes must be lowercase sha256")
	}
	if !retentionSafeInteger(input.FromSequence) || !retentionSafeInteger(input.ThroughSequence) || input.ThroughSequence < input.FromSequence {
		return errors.New("disposition range must use ordered positive safe integers")
	}
	if !retentionPolicyReferencePattern.MatchString(input.PolicyReference) {
		return errors.New("policyReference is invalid")
	}
	if !retentionExactTimestamp(input.DisposedAt) {
		return errors.New("disposedAt must be exact UTC milliseconds")
	}
	if input.SignaturePublicKeyFingerprint != "" && !retentionHashPattern.MatchString(input.SignaturePublicKeyFingerprint) {
		return errors.New("signature fingerprint must be lowercase sha256")
	}
	return nil
}

/*
assertRetentionSignaturePair requires fingerprint and detached signature fields
to be either both present or both absent at construction.
*/
func assertRetentionSignaturePair(fingerprint string, signature *RetentionSignature) error {
	if (fingerprint == "") != (signature == nil) {
		return errors.New("signature and fingerprint must appear together")
	}
	if signature == nil {
		return nil
	}
	if signature.Algorithm != "ed25519" || !retentionHashPattern.MatchString(signature.PublicKeyFingerprint) || !retentionSignaturePattern.MatchString(signature.Signature) {
		return errors.New("signature must use ed25519, lowercase fingerprint, and padded base64")
	}
	return nil
}

/* retentionSafeInteger keeps numeric fields exact across Go, Python, and JavaScript. */
func retentionSafeInteger(value int) bool {
	return value >= 1 && int64(value) <= int64(9007199254740991)
}

/* retentionOptionalHash validates null-or-lowercase-sha256 linkage fields. */
func retentionOptionalHash(value *string) bool {
	return value == nil || retentionHashPattern.MatchString(*value)
}

/* retentionExactTimestamp requires a real UTC instant with exact millisecond text. */
func retentionExactTimestamp(value string) bool {
	if !retentionTimestampPattern.MatchString(value) {
		return false
	}
	_, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	return err == nil
}

/* retentionCheckpointAsInput strips computed protocol fields for shape validation. */
func retentionCheckpointAsInput(checkpoint RetentionCheckpoint) RetentionCheckpointInput {
	return RetentionCheckpointInput{checkpoint.CheckpointID, checkpoint.TenantID, checkpoint.ChainKind, checkpoint.Epoch, checkpoint.FromSequence, checkpoint.FromPreviousHash, checkpoint.ThroughSequence, checkpoint.ThroughHash, checkpoint.RecordCount, checkpoint.ArchiveRootHash, checkpoint.PreviousCheckpointHash, checkpoint.CreatedAt, checkpoint.SignaturePublicKeyFingerprint}
}

/* retentionDispositionAsInput strips computed protocol fields for shape validation. */
func retentionDispositionAsInput(disposition RetentionDisposition) RetentionDispositionInput {
	return RetentionDispositionInput{disposition.DispositionID, disposition.TenantID, disposition.ChainKind, disposition.CheckpointHash, disposition.FromSequence, disposition.ThroughSequence, disposition.ArchiveRootHash, disposition.PolicyReference, disposition.DisposedAt, disposition.SignaturePublicKeyFingerprint}
}

/* copyStringPointer prevents caller mutation of linkage fields after construction. */
func copyStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

/* copyRetentionSignature prevents caller mutation of detached signature metadata. */
func copyRetentionSignature(value *RetentionSignature) *RetentionSignature {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

/* equalStringPointers compares nullable hash links by value. */
func equalStringPointers(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

/* retentionFailure builds the shared fail-closed verification result shape. */
func retentionFailure(index int, reason, signature string) RetentionVerificationResult {
	return RetentionVerificationResult{OK: false, Index: index, Reason: reason, Signature: signature}
}

/* combineRetentionSignatureStatus gives invalid and skipped states precedence across a chain. */
func combineRetentionSignatureStatus(current, next string) string {
	if current == "invalid" || next == "invalid" {
		return "invalid"
	}
	if current == "skipped" || next == "skipped" {
		return "skipped"
	}
	if current == "absent" || next == "absent" {
		return "absent"
	}
	return "valid"
}

/* optionsWithoutRequiredSignature verifies the referenced checkpoint independently of receipt policy. */
func optionsWithoutRequiredSignature(options *RetentionVerificationOptions) *RetentionVerificationOptions {
	if options == nil {
		return nil
	}
	return &RetentionVerificationOptions{TrustedPublicKey: options.TrustedPublicKey, SignatureVerifier: options.SignatureVerifier}
}
