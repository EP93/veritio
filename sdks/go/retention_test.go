package veritio

import (
	"crypto/ed25519"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestRetentionCheckpointFixtures(t *testing.T) {
	data := loadFixture(t, "retention-checkpoints.json")
	cases := retentionArrayValue(t, data["cases"])
	unsigned, err := CreateRetentionCheckpoint(decodeValue[RetentionCheckpointInput](t, mapValue(t, cases[0])["input"]), nil)
	if err != nil {
		t.Fatalf("CreateRetentionCheckpoint returned error: %v", err)
	}
	if !reflect.DeepEqual(toJSONMap(t, unsigned), mapValue(t, mapValue(t, cases[0])["expected"])) {
		t.Fatalf("unsigned checkpoint did not match fixture")
	}

	signedCase := mapValue(t, cases[1])
	signature := decodeValue[RetentionSignature](t, signedCase["signature"])
	signed, err := CreateRetentionCheckpoint(decodeValue[RetentionCheckpointInput](t, signedCase["input"]), &signature)
	if err != nil {
		t.Fatalf("CreateRetentionCheckpoint returned error: %v", err)
	}
	if signed.Hash != stringValue(t, signedCase["expectedHash"]) {
		t.Fatalf("signed checkpoint hash mismatch")
	}
	key, _ := hex.DecodeString(stringValue(t, data["publicKeyHex"]))
	result := VerifyRetentionCheckpoint(signed, &RetentionVerificationOptions{
		TrustedPublicKey: key,
		RequireSignature: true,
		SignatureVerifier: func(publicKey, signature, message []byte) bool {
			return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
		},
	})
	if !result.OK || result.Signature != "valid" {
		t.Fatalf("expected valid signed checkpoint, got %#v", result)
	}
}

func TestRetentionRejectsConstructorVectors(t *testing.T) {
	data := loadFixture(t, "retention-checkpoints.json")
	base := mapValue(t, mapValue(t, retentionArrayValue(t, data["cases"])[0])["input"])
	for _, raw := range retentionArrayValue(t, data["constructorRejections"]) {
		rejection := mapValue(t, raw)
		candidate := retentionCloneMap(base)
		candidate[stringValue(t, rejection["field"])] = rejection["value"]
		if _, err := CreateRetentionCheckpoint(decodeValue[RetentionCheckpointInput](t, candidate), nil); err == nil {
			t.Fatalf("expected rejection for %s", stringValue(t, rejection["name"]))
		}
	}
}

func TestRetentionChainAndAnchoredTail(t *testing.T) {
	data := loadFixture(t, "retention-checkpoints.json")
	cases := retentionArrayValue(t, data["cases"])
	first, _ := CreateRetentionCheckpoint(decodeValue[RetentionCheckpointInput](t, mapValue(t, cases[0])["input"]), nil)
	secondInput := decodeValue[RetentionCheckpointInput](t, mapValue(t, cases[1])["input"])
	secondInput.SignaturePublicKeyFingerprint = ""
	secondInput.FromSequence = 4
	secondInput.ThroughSequence = 4
	gap, _ := CreateRetentionCheckpoint(secondInput, nil)
	result := VerifyRetentionCheckpointChain([]RetentionCheckpoint{first, gap}, nil)
	if result.OK || result.Index != 1 || result.Reason != "range_mismatch" {
		t.Fatalf("expected range mismatch, got %#v", result)
	}
	records := decodeValue[[]AuditRecord](t, data["retainedRecords"])
	if result := VerifyAuditRecordsFromCheckpoint(first, records, nil); !result.OK {
		t.Fatalf("expected anchored tail to verify, got %#v", result)
	}
}

func TestRetentionSignatureFingerprintMismatch(t *testing.T) {
	data := loadFixture(t, "retention-checkpoints.json")
	entry := mapValue(t, retentionArrayValue(t, data["cases"])[1])
	signature := decodeValue[RetentionSignature](t, entry["signature"])
	signature.PublicKeyFingerprint = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	checkpoint, _ := CreateRetentionCheckpoint(decodeValue[RetentionCheckpointInput](t, entry["input"]), &signature)
	if result := VerifyRetentionCheckpoint(checkpoint, nil); result.Reason != "signature_fingerprint_mismatch" {
		t.Fatalf("expected fingerprint mismatch, got %#v", result)
	}
}

func TestRetentionAllSignedChainReportsValid(t *testing.T) {
	data := loadFixture(t, "retention-checkpoints.json")
	cases := retentionArrayValue(t, data["cases"])
	input := decodeValue[RetentionCheckpointInput](t, mapValue(t, cases[0])["input"])
	input.SignaturePublicKeyFingerprint = mapValue(t, cases[1])["input"].(map[string]any)["signaturePublicKeyFingerprint"].(string)
	signature := decodeValue[RetentionSignature](t, mapValue(t, cases[1])["signature"])
	checkpoint, err := CreateRetentionCheckpoint(input, &signature)
	if err != nil {
		t.Fatalf("CreateRetentionCheckpoint returned error: %v", err)
	}
	key, _ := hex.DecodeString(stringValue(t, data["publicKeyHex"]))
	result := VerifyRetentionCheckpointChain([]RetentionCheckpoint{checkpoint}, &RetentionVerificationOptions{
		TrustedPublicKey: key, RequireSignature: true,
		SignatureVerifier: func(_, _, _ []byte) bool { return true },
	})
	if !result.OK || result.Signature != "valid" {
		t.Fatalf("expected all-signed chain status valid, got %#v", result)
	}
}

func TestRetentionDispositionFixtureAndMismatch(t *testing.T) {
	checkpoints := loadFixture(t, "retention-checkpoints.json")
	dispositions := loadFixture(t, "retention-dispositions.json")
	checkpoint, _ := CreateRetentionCheckpoint(decodeValue[RetentionCheckpointInput](t, mapValue(t, retentionArrayValue(t, checkpoints["cases"])[0])["input"]), nil)
	entry := mapValue(t, retentionArrayValue(t, dispositions["cases"])[0])
	signature := decodeValue[RetentionSignature](t, entry["signature"])
	disposition, err := CreateRetentionDisposition(decodeValue[RetentionDispositionInput](t, entry["input"]), &signature)
	if err != nil || disposition.Hash != stringValue(t, entry["expectedHash"]) {
		t.Fatalf("disposition fixture mismatch: %v", err)
	}
	for _, raw := range retentionArrayValue(t, dispositions["mismatchRejections"]) {
		rejection := mapValue(t, raw)
		input := decodeValue[RetentionDispositionInput](t, entry["input"])
		input.SignaturePublicKeyFingerprint = ""
		switch stringValue(t, rejection["field"]) {
		case "checkpointHash":
			input.CheckpointHash = stringValue(t, rejection["value"])
		case "archiveRootHash":
			input.ArchiveRootHash = stringValue(t, rejection["value"])
		}
		mismatch, _ := CreateRetentionDisposition(input, nil)
		if result := VerifyRetentionDisposition(mismatch, checkpoint, nil); result.Reason != "checkpoint_mismatch" {
			t.Fatalf("expected checkpoint mismatch, got %#v", result)
		}
	}
}

func retentionCloneMap(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func retentionArrayValue(t *testing.T, value any) []any {
	t.Helper()
	typed, ok := value.([]any)
	if !ok {
		t.Fatalf("expected array, got %#v", value)
	}
	return typed
}
