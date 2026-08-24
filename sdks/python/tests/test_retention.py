import json
import unittest
from pathlib import Path

from veritio.retention import (
    create_retention_checkpoint,
    create_retention_disposition,
    hash_retention_checkpoint,
    hash_retention_disposition,
    verify_audit_records_from_checkpoint,
    verify_retention_checkpoint,
    verify_retention_checkpoint_chain,
    verify_retention_disposition,
)

CONFORMANCE_DIR = Path(__file__).resolve().parents[3] / "spec" / "conformance"


def fixture(name):
    return json.loads((CONFORMANCE_DIR / name).read_text(encoding="utf-8"))


class RetentionTests(unittest.TestCase):
    def test_checkpoint_hashes_and_injected_signature_verifier_match_fixture(self):
        data = fixture("retention-checkpoints.json")
        unsigned = create_retention_checkpoint(data["cases"][0]["input"])
        signed = create_retention_checkpoint(data["cases"][1]["input"], data["cases"][1]["signature"])

        self.assertEqual(unsigned, data["cases"][0]["expected"])
        self.assertEqual(hash_retention_checkpoint(unsigned), data["cases"][0]["expected"]["hash"])
        self.assertEqual(signed["hash"], data["cases"][1]["expectedHash"])

        public_key = bytes.fromhex(data["publicKeyHex"])
        expected_signature = data["cases"][1]["signature"]["signature"]

        def injected_verifier(key, signature, message):
            return key == public_key and signature == __import__("base64").b64decode(expected_signature) and message == signed["hash"].encode()

        self.assertEqual(
            verify_retention_checkpoint(
                signed,
                trusted_public_key=public_key,
                signature_verifier=injected_verifier,
                require_signature=True,
            ),
            {"ok": True, "signature": "valid"},
        )

    def test_checkpoint_rejection_vectors(self):
        data = fixture("retention-checkpoints.json")
        for rejection in data["constructorRejections"]:
            with self.subTest(rejection["name"]), self.assertRaises(TypeError):
                create_retention_checkpoint({**data["cases"][0]["input"], rejection["field"]: rejection["value"]})

    def test_checkpoint_chain_and_anchor_fail_closed(self):
        data = fixture("retention-checkpoints.json")
        first = create_retention_checkpoint(data["cases"][0]["input"])
        second_input = {key: value for key, value in data["cases"][1]["input"].items() if key != "signaturePublicKeyFingerprint"}
        gap = create_retention_checkpoint({**second_input, "fromSequence": 4, "throughSequence": 4})
        self.assertEqual(
            verify_retention_checkpoint_chain([first, gap]),
            {"ok": False, "index": 1, "reason": "range_mismatch", "signature": "absent"},
        )
        self.assertEqual(
            verify_audit_records_from_checkpoint(first, data["retainedRecords"]),
            {"ok": True, "signature": "absent"},
        )

    def test_signature_constructor_mismatch_and_record_mutation_are_rejected(self):
        data = fixture("retention-checkpoints.json")
        for rejection in data["signatureConstructorRejections"]:
            with self.subTest(rejection["name"]), self.assertRaises(TypeError):
                create_retention_checkpoint(
                    data["cases"][1]["input"],
                    {**data["cases"][1]["signature"], "publicKeyFingerprint": rejection["publicKeyFingerprint"]},
                )
        signed = create_retention_checkpoint(data["cases"][1]["input"], data["cases"][1]["signature"])
        mutated = {**signed, "signature": {**signed["signature"], "publicKeyFingerprint": "f" * 64}}
        self.assertEqual(verify_retention_checkpoint(mutated)["reason"], "signature_fingerprint_mismatch")

    def test_checkpoint_verification_rejects_non_objects_and_unknown_fields(self):
        data = fixture("retention-checkpoints.json")
        unsigned = create_retention_checkpoint(data["cases"][0]["input"])
        signed = create_retention_checkpoint(data["cases"][1]["input"], data["cases"][1]["signature"])
        self.assertEqual(
            verify_retention_checkpoint(None),
            {"ok": False, "index": 0, "reason": "invalid_checkpoint", "signature": "absent"},
        )
        self.assertEqual(verify_retention_checkpoint({**unsigned, "unexpected": True})["reason"], "invalid_checkpoint")
        self.assertEqual(
            verify_retention_checkpoint({**signed, "signature": {**signed["signature"], "unexpected": True}})["reason"],
            "signature_invalid",
        )

    def test_all_signed_checkpoint_chain_reports_valid(self):
        data = fixture("retention-checkpoints.json")
        fingerprint = data["cases"][1]["input"]["signaturePublicKeyFingerprint"]
        checkpoint = create_retention_checkpoint(
            {**data["cases"][0]["input"], "signaturePublicKeyFingerprint": fingerprint},
            data["cases"][1]["signature"],
        )
        self.assertEqual(
            verify_retention_checkpoint_chain(
                [checkpoint],
                trusted_public_key=bytes.fromhex(data["publicKeyHex"]),
                signature_verifier=lambda _key, _signature, _message: True,
                require_signature=True,
            ),
            {"ok": True, "signature": "valid"},
        )

    def test_disposition_hash_and_checkpoint_binding(self):
        checkpoints = fixture("retention-checkpoints.json")
        data = fixture("retention-dispositions.json")
        checkpoint = create_retention_checkpoint(checkpoints["cases"][0]["input"])
        disposition = create_retention_disposition(data["cases"][0]["input"], data["cases"][0]["signature"])
        self.assertEqual(disposition["hash"], data["cases"][0]["expectedHash"])
        self.assertEqual(hash_retention_disposition(disposition), data["cases"][0]["expectedHash"])

        for rejection in data["mismatchRejections"]:
            base_input = {key: value for key, value in data["cases"][0]["input"].items() if key != "signaturePublicKeyFingerprint"}
            mismatched = create_retention_disposition({**base_input, rejection["field"]: rejection["value"]})
            self.assertEqual(verify_retention_disposition(mismatched, checkpoint)["reason"], "checkpoint_mismatch")

    def test_disposition_rejects_signature_mismatch_and_malformed_shapes(self):
        checkpoints = fixture("retention-checkpoints.json")
        data = fixture("retention-dispositions.json")
        checkpoint = create_retention_checkpoint(checkpoints["cases"][0]["input"])
        for rejection in data["signatureConstructorRejections"]:
            with self.subTest(rejection["name"]), self.assertRaises(TypeError):
                create_retention_disposition(
                    data["cases"][0]["input"],
                    {**data["cases"][0]["signature"], "publicKeyFingerprint": rejection["publicKeyFingerprint"]},
                )
        signed = create_retention_disposition(data["cases"][0]["input"], data["cases"][0]["signature"])
        self.assertEqual(verify_retention_disposition(None, checkpoint)["reason"], "invalid_disposition")
        self.assertEqual(
            verify_retention_disposition({**signed, "unexpected": True}, checkpoint)["reason"],
            "invalid_disposition",
        )
        self.assertEqual(
            verify_retention_disposition(
                {**signed, "signature": {**signed["signature"], "unexpected": True}}, checkpoint
            )["reason"],
            "signature_invalid",
        )


if __name__ == "__main__":
    unittest.main()
