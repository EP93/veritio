"""Portable audit-retention checkpoint and disposition protocol helpers."""

from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime
from typing import Any, Callable

from .event import canonical_json, hash_audit_record

RETENTION_SCHEMA_VERSION = "1.0"
RETENTION_CANONICALIZATION = "veritio-json-v1"
RETENTION_HASH_ALGORITHM = "sha256"

_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_POLICY_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$"
)
_BASE64_SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9+/]{86}==$")

SignatureVerifier = Callable[[bytes, bytes, bytes], bool]


def create_retention_checkpoint(input_checkpoint: dict[str, Any], signature: dict[str, Any] | None = None) -> dict[str, Any]:
    """Construct a deterministic audit checkpoint without reading clocks, randomness, or host trust state."""
    _assert_checkpoint_input(input_checkpoint)
    _assert_signature_pair(input_checkpoint.get("signaturePublicKeyFingerprint"), signature)
    unsigned = _checkpoint_unsigned(input_checkpoint)
    checkpoint = {**unsigned, "hash": hash_retention_checkpoint(unsigned)}
    if signature is not None:
        checkpoint["signature"] = _normalize_signature(signature)
    return checkpoint


def hash_retention_checkpoint(checkpoint: dict[str, Any]) -> str:
    """Hash the canonical unsigned checkpoint payload while preserving an optional bound key fingerprint."""
    return hashlib.sha256(canonical_json(_checkpoint_hash_payload(checkpoint)).encode("utf-8")).hexdigest()


def verify_retention_checkpoint(
    checkpoint: dict[str, Any],
    *,
    trusted_public_key: bytes | None = None,
    signature_verifier: SignatureVerifier | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    """Verify one checkpoint and delegate Ed25519 verification to an injected callable boundary."""
    return _verify_checkpoint_at(
        checkpoint,
        0,
        trusted_public_key=trusted_public_key,
        signature_verifier=signature_verifier,
        require_signature=require_signature,
    )


def verify_retention_checkpoint_chain(
    checkpoints: list[dict[str, Any]],
    *,
    trusted_public_key: bytes | None = None,
    signature_verifier: SignatureVerifier | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    """Verify a complete epoch-one checkpoint chain with exact range, tip, tenant, and hash linkage."""
    signature_status = "absent" if len(checkpoints) == 0 else "valid"
    for index, checkpoint in enumerate(checkpoints):
        verified = _verify_checkpoint_at(
            checkpoint,
            index,
            trusted_public_key=trusted_public_key,
            signature_verifier=signature_verifier,
            require_signature=require_signature,
        )
        signature_status = _combine_signature_status(signature_status, verified["signature"])
        if not verified["ok"]:
            return {**verified, "signature": signature_status}
        if checkpoint["epoch"] != index + 1:
            return _failure(index, "epoch_mismatch", signature_status)
        if index == 0:
            continue
        previous = checkpoints[index - 1]
        if checkpoint["tenantId"] != previous["tenantId"]:
            return _failure(index, "tenant_mismatch", signature_status)
        if checkpoint["chainKind"] != previous["chainKind"]:
            return _failure(index, "chain_kind_mismatch", signature_status)
        if (
            checkpoint["fromSequence"] != previous["throughSequence"] + 1
            or checkpoint["fromPreviousHash"] != previous["throughHash"]
        ):
            return _failure(index, "range_mismatch", signature_status)
        if checkpoint["previousCheckpointHash"] != previous["hash"]:
            return _failure(index, "previous_checkpoint_hash_mismatch", signature_status)
    return {"ok": True, "signature": signature_status}


def verify_audit_records_from_checkpoint(
    checkpoint: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    trusted_public_key: bytes | None = None,
    signature_verifier: SignatureVerifier | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    """Verify retained audit rows from a checkpoint anchor without changing genesis-only verification semantics."""
    checkpoint_result = verify_retention_checkpoint(
        checkpoint,
        trusted_public_key=trusted_public_key,
        signature_verifier=signature_verifier,
        require_signature=require_signature,
    )
    if not checkpoint_result["ok"]:
        return checkpoint_result
    sequence = checkpoint["throughSequence"]
    previous_hash = checkpoint["throughHash"]
    for index, record in enumerate(records):
        tenant_id = record.get("event", {}).get("scope", {}).get("tenantId")
        if not isinstance(tenant_id, str) or not tenant_id:
            return _failure(index, "missing_tenant_scope", checkpoint_result["signature"])
        if tenant_id != checkpoint["tenantId"]:
            return _failure(index, "tenant_mismatch", checkpoint_result["signature"])
        if record.get("hashAlgorithm") != RETENTION_HASH_ALGORITHM:
            return _failure(index, "unsupported_hash_algorithm", checkpoint_result["signature"])
        if record.get("canonicalization") != RETENTION_CANONICALIZATION:
            return _failure(index, "unsupported_canonicalization", checkpoint_result["signature"])
        if record.get("sequence") != sequence + 1:
            return _failure(index, "sequence_mismatch", checkpoint_result["signature"])
        if record.get("previousHash") != previous_hash:
            return _failure(index, "previous_hash_mismatch", checkpoint_result["signature"])
        if record.get("hash") != hash_audit_record(record):
            return _failure(index, "record_hash_mismatch", checkpoint_result["signature"])
        sequence = record["sequence"]
        previous_hash = record["hash"]
    return checkpoint_result


def create_retention_disposition(input_disposition: dict[str, Any], signature: dict[str, Any] | None = None) -> dict[str, Any]:
    """Construct the minimal provider-delete receipt without retaining personal or provider-operational details."""
    _assert_disposition_input(input_disposition)
    _assert_signature_pair(input_disposition.get("signaturePublicKeyFingerprint"), signature)
    unsigned = _disposition_unsigned(input_disposition)
    disposition = {**unsigned, "hash": hash_retention_disposition(unsigned)}
    if signature is not None:
        disposition["signature"] = _normalize_signature(signature)
    return disposition


def hash_retention_disposition(disposition: dict[str, Any]) -> str:
    """Hash the canonical unsigned disposition receipt, including its optional bound key fingerprint."""
    return hashlib.sha256(canonical_json(_disposition_hash_payload(disposition)).encode("utf-8")).hexdigest()


def verify_retention_disposition(
    disposition: dict[str, Any],
    checkpoint: dict[str, Any],
    *,
    trusted_public_key: bytes | None = None,
    signature_verifier: SignatureVerifier | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    """Verify a receipt and require exact equality with its referenced checkpoint before accepting it."""
    checkpoint_result = verify_retention_checkpoint(
        checkpoint,
        trusted_public_key=trusted_public_key,
        signature_verifier=signature_verifier,
    )
    if not checkpoint_result["ok"]:
        return checkpoint_result
    if (
        disposition.get("recordType") != "retention.disposition"
        or disposition.get("schemaVersion") != RETENTION_SCHEMA_VERSION
        or disposition.get("method") != "provider-delete"
        or disposition.get("canonicalization") != RETENTION_CANONICALIZATION
        or disposition.get("hashAlgorithm") != RETENTION_HASH_ALGORITHM
    ):
        return _failure(0, "unsupported_protocol", "absent")
    try:
        _assert_disposition_input(disposition)
    except (TypeError, ValueError):
        return _failure(0, "invalid_disposition", "absent")
    if not _is_hash(disposition.get("hash")) or disposition["hash"] != hash_retention_disposition(disposition):
        return _failure(0, "hash_mismatch", "absent")
    signature_status, reason = _verify_detached_signature(
        disposition,
        trusted_public_key=trusted_public_key,
        signature_verifier=signature_verifier,
        require_signature=require_signature,
    )
    if reason is not None:
        return _failure(0, reason, signature_status)
    if (
        disposition["tenantId"] != checkpoint["tenantId"]
        or disposition["chainKind"] != checkpoint["chainKind"]
        or disposition["checkpointHash"] != checkpoint["hash"]
        or disposition["fromSequence"] != checkpoint["fromSequence"]
        or disposition["throughSequence"] != checkpoint["throughSequence"]
        or disposition["archiveRootHash"] != checkpoint["archiveRootHash"]
    ):
        return _failure(0, "checkpoint_mismatch", signature_status)
    return {"ok": True, "signature": signature_status}


def _verify_checkpoint_at(
    checkpoint: dict[str, Any],
    index: int,
    *,
    trusted_public_key: bytes | None,
    signature_verifier: SignatureVerifier | None,
    require_signature: bool,
) -> dict[str, Any]:
    """Apply shape, hash, and injected signature gates to one checkpoint at a stable result index."""
    if (
        checkpoint.get("recordType") != "retention.checkpoint"
        or checkpoint.get("schemaVersion") != RETENTION_SCHEMA_VERSION
        or checkpoint.get("canonicalization") != RETENTION_CANONICALIZATION
        or checkpoint.get("hashAlgorithm") != RETENTION_HASH_ALGORITHM
    ):
        return _failure(index, "unsupported_protocol", "absent")
    try:
        _assert_checkpoint_input(checkpoint)
    except (TypeError, ValueError):
        return _failure(index, "invalid_checkpoint", "absent")
    if not _is_hash(checkpoint.get("hash")) or checkpoint["hash"] != hash_retention_checkpoint(checkpoint):
        return _failure(index, "hash_mismatch", "absent")
    signature_status, reason = _verify_detached_signature(
        checkpoint,
        trusted_public_key=trusted_public_key,
        signature_verifier=signature_verifier,
        require_signature=require_signature,
    )
    if reason is not None:
        return _failure(index, reason, signature_status)
    return {"ok": True, "signature": signature_status}


def _verify_detached_signature(
    record: dict[str, Any],
    *,
    trusted_public_key: bytes | None,
    signature_verifier: SignatureVerifier | None,
    require_signature: bool,
) -> tuple[str, str | None]:
    """Validate signature metadata and invoke only the caller-supplied cryptographic verifier."""
    fingerprint = record.get("signaturePublicKeyFingerprint")
    signature = record.get("signature")
    if fingerprint is None and signature is None:
        return ("absent", "signature_required" if require_signature else None)
    if (
        not _is_hash(fingerprint)
        or not isinstance(signature, dict)
        or signature.get("publicKeyFingerprint") != fingerprint
    ):
        return ("invalid", "signature_fingerprint_mismatch")
    if signature.get("algorithm") != "ed25519" or not isinstance(signature.get("signature"), str):
        return ("invalid", "signature_invalid")
    try:
        if not _BASE64_SIGNATURE_PATTERN.fullmatch(signature["signature"]):
            raise ValueError("invalid base64 shape")
        signature_bytes = base64.b64decode(signature["signature"], validate=True)
    except (ValueError, TypeError):
        return ("invalid", "signature_invalid")
    if trusted_public_key is None or signature_verifier is None:
        return ("skipped", "signature_required" if require_signature else None)
    if hashlib.sha256(trusted_public_key).hexdigest() != fingerprint:
        return ("invalid", "signature_fingerprint_mismatch")
    try:
        valid = signature_verifier(trusted_public_key, signature_bytes, record["hash"].encode("utf-8"))
    except Exception:
        valid = False
    return ("valid", None) if valid else ("invalid", "signature_invalid")


def _checkpoint_unsigned(input_checkpoint: dict[str, Any]) -> dict[str, Any]:
    """Copy only normative checkpoint fields into their language-neutral unsigned payload."""
    payload = {
        "recordType": "retention.checkpoint",
        "schemaVersion": RETENTION_SCHEMA_VERSION,
        "checkpointId": input_checkpoint["checkpointId"],
        "tenantId": input_checkpoint["tenantId"],
        "chainKind": input_checkpoint["chainKind"],
        "epoch": input_checkpoint["epoch"],
        "fromSequence": input_checkpoint["fromSequence"],
        "fromPreviousHash": input_checkpoint["fromPreviousHash"],
        "throughSequence": input_checkpoint["throughSequence"],
        "throughHash": input_checkpoint["throughHash"],
        "recordCount": input_checkpoint["recordCount"],
        "archiveRootHash": input_checkpoint["archiveRootHash"],
        "previousCheckpointHash": input_checkpoint["previousCheckpointHash"],
        "createdAt": input_checkpoint["createdAt"],
        "canonicalization": RETENTION_CANONICALIZATION,
        "hashAlgorithm": RETENTION_HASH_ALGORITHM,
    }
    if input_checkpoint.get("signaturePublicKeyFingerprint") is not None:
        payload["signaturePublicKeyFingerprint"] = input_checkpoint["signaturePublicKeyFingerprint"]
    return payload


def _disposition_unsigned(input_disposition: dict[str, Any]) -> dict[str, Any]:
    """Copy only non-personal normative receipt fields and fix the v1 deletion method."""
    payload = {
        "recordType": "retention.disposition",
        "schemaVersion": RETENTION_SCHEMA_VERSION,
        "dispositionId": input_disposition["dispositionId"],
        "tenantId": input_disposition["tenantId"],
        "chainKind": input_disposition["chainKind"],
        "checkpointHash": input_disposition["checkpointHash"],
        "fromSequence": input_disposition["fromSequence"],
        "throughSequence": input_disposition["throughSequence"],
        "archiveRootHash": input_disposition["archiveRootHash"],
        "method": "provider-delete",
        "policyReference": input_disposition["policyReference"],
        "disposedAt": input_disposition["disposedAt"],
        "canonicalization": RETENTION_CANONICALIZATION,
        "hashAlgorithm": RETENTION_HASH_ALGORITHM,
    }
    if input_disposition.get("signaturePublicKeyFingerprint") is not None:
        payload["signaturePublicKeyFingerprint"] = input_disposition["signaturePublicKeyFingerprint"]
    return payload


def _checkpoint_hash_payload(checkpoint: dict[str, Any]) -> dict[str, Any]:
    """Select checkpoint hash fields explicitly so detached signature bytes can never affect the digest."""
    payload = {
        "recordType": checkpoint["recordType"],
        "schemaVersion": checkpoint["schemaVersion"],
        "checkpointId": checkpoint["checkpointId"],
        "tenantId": checkpoint["tenantId"],
        "chainKind": checkpoint["chainKind"],
        "epoch": checkpoint["epoch"],
        "fromSequence": checkpoint["fromSequence"],
        "fromPreviousHash": checkpoint["fromPreviousHash"],
        "throughSequence": checkpoint["throughSequence"],
        "throughHash": checkpoint["throughHash"],
        "recordCount": checkpoint["recordCount"],
        "archiveRootHash": checkpoint["archiveRootHash"],
        "previousCheckpointHash": checkpoint["previousCheckpointHash"],
        "createdAt": checkpoint["createdAt"],
        "canonicalization": checkpoint["canonicalization"],
        "hashAlgorithm": checkpoint["hashAlgorithm"],
    }
    if checkpoint.get("signaturePublicKeyFingerprint") is not None:
        payload["signaturePublicKeyFingerprint"] = checkpoint["signaturePublicKeyFingerprint"]
    return payload


def _disposition_hash_payload(disposition: dict[str, Any]) -> dict[str, Any]:
    """Select disposition hash fields explicitly so operational extras cannot enter protocol hashes."""
    payload = {
        "recordType": disposition["recordType"],
        "schemaVersion": disposition["schemaVersion"],
        "dispositionId": disposition["dispositionId"],
        "tenantId": disposition["tenantId"],
        "chainKind": disposition["chainKind"],
        "checkpointHash": disposition["checkpointHash"],
        "fromSequence": disposition["fromSequence"],
        "throughSequence": disposition["throughSequence"],
        "archiveRootHash": disposition["archiveRootHash"],
        "method": disposition["method"],
        "policyReference": disposition["policyReference"],
        "disposedAt": disposition["disposedAt"],
        "canonicalization": disposition["canonicalization"],
        "hashAlgorithm": disposition["hashAlgorithm"],
    }
    if disposition.get("signaturePublicKeyFingerprint") is not None:
        payload["signaturePublicKeyFingerprint"] = disposition["signaturePublicKeyFingerprint"]
    return payload


def _normalize_signature(signature: dict[str, Any]) -> dict[str, str]:
    """Copy only detached-signature protocol fields so host extras never enter stored records."""
    return {
        "algorithm": signature["algorithm"],
        "publicKeyFingerprint": signature["publicKeyFingerprint"],
        "signature": signature["signature"],
    }


def _assert_checkpoint_input(input_checkpoint: dict[str, Any]) -> None:
    """Enforce safe integers, exact timestamps, genesis rules, and internal checkpoint range consistency."""
    if not isinstance(input_checkpoint, dict):
        raise TypeError("checkpoint must be an object")
    _assert_id(input_checkpoint.get("checkpointId"), "checkpointId")
    _assert_id(input_checkpoint.get("tenantId"), "tenantId")
    if input_checkpoint.get("chainKind") != "audit":
        raise TypeError("chainKind must be audit")
    for field in ("epoch", "fromSequence", "throughSequence", "recordCount"):
        _assert_safe_integer(input_checkpoint.get(field), field)
    for field in ("throughHash", "archiveRootHash"):
        _assert_hash(input_checkpoint.get(field), field)
    for field in ("fromPreviousHash", "previousCheckpointHash"):
        value = input_checkpoint.get(field)
        if value is not None:
            _assert_hash(value, field)
    _assert_timestamp(input_checkpoint.get("createdAt"), "createdAt")
    if input_checkpoint.get("signaturePublicKeyFingerprint") is not None:
        _assert_hash(input_checkpoint["signaturePublicKeyFingerprint"], "signaturePublicKeyFingerprint")
    if (
        input_checkpoint["throughSequence"] < input_checkpoint["fromSequence"]
        or input_checkpoint["recordCount"] != input_checkpoint["throughSequence"] - input_checkpoint["fromSequence"] + 1
    ):
        raise TypeError("recordCount must equal the inclusive checkpoint range")
    if input_checkpoint["epoch"] == 1:
        if (
            input_checkpoint["fromSequence"] != 1
            or input_checkpoint.get("fromPreviousHash") is not None
            or input_checkpoint.get("previousCheckpointHash") is not None
        ):
            raise TypeError("epoch one must begin at genesis")
    elif input_checkpoint.get("fromPreviousHash") is None or input_checkpoint.get("previousCheckpointHash") is None:
        raise TypeError("later epochs must link prior record and checkpoint hashes")


def _assert_disposition_input(input_disposition: dict[str, Any]) -> None:
    """Enforce the minimal receipt field vocabulary without accepting provider or personal metadata."""
    if not isinstance(input_disposition, dict):
        raise TypeError("disposition must be an object")
    _assert_id(input_disposition.get("dispositionId"), "dispositionId")
    _assert_id(input_disposition.get("tenantId"), "tenantId")
    if input_disposition.get("chainKind") != "audit":
        raise TypeError("chainKind must be audit")
    for field in ("checkpointHash", "archiveRootHash"):
        _assert_hash(input_disposition.get(field), field)
    for field in ("fromSequence", "throughSequence"):
        _assert_safe_integer(input_disposition.get(field), field)
    if input_disposition["throughSequence"] < input_disposition["fromSequence"]:
        raise TypeError("disposition range must be ordered")
    policy_reference = input_disposition.get("policyReference")
    if not isinstance(policy_reference, str) or not _POLICY_REFERENCE_PATTERN.fullmatch(policy_reference):
        raise TypeError("policyReference is invalid")
    _assert_timestamp(input_disposition.get("disposedAt"), "disposedAt")
    if input_disposition.get("signaturePublicKeyFingerprint") is not None:
        _assert_hash(input_disposition["signaturePublicKeyFingerprint"], "signaturePublicKeyFingerprint")


def _assert_signature_pair(fingerprint: Any, signature: dict[str, Any] | None) -> None:
    """Require signed records to supply both the bound fingerprint and detached signature object."""
    if (fingerprint is None) != (signature is None):
        raise TypeError("signature and fingerprint must appear together")
    if signature is None:
        return
    if signature.get("algorithm") != "ed25519":
        raise TypeError("signature algorithm must be ed25519")
    _assert_hash(signature.get("publicKeyFingerprint"), "signature.publicKeyFingerprint")
    encoded = signature.get("signature")
    if not isinstance(encoded, str) or not _BASE64_SIGNATURE_PATTERN.fullmatch(encoded):
        raise TypeError("signature must be padded base64")


def _assert_id(value: Any, field: str) -> None:
    """Require a bounded portable protocol identifier without whitespace or host-specific syntax."""
    if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
        raise TypeError(f"{field} is invalid")


def _assert_safe_integer(value: Any, field: str) -> None:
    """Require positive integers that remain exact in every supported language runtime."""
    if type(value) is not int or value < 1 or value > 9007199254740991:
        raise TypeError(f"{field} must be a positive safe integer")


def _assert_hash(value: Any, field: str) -> None:
    """Require the protocol's unqualified 64-character lowercase SHA-256 form."""
    if not _is_hash(value):
        raise TypeError(f"{field} must be lowercase sha256")


def _is_hash(value: Any) -> bool:
    """Recognize the exact lowercase SHA-256 representation used by retention records."""
    return isinstance(value, str) and _HASH_PATTERN.fullmatch(value) is not None


def _assert_timestamp(value: Any, field: str) -> None:
    """Require a real UTC timestamp rendered with exactly millisecond precision."""
    if not isinstance(value, str) or not _TIMESTAMP_PATTERN.fullmatch(value):
        raise TypeError(f"{field} must be exact UTC milliseconds")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as error:
        raise TypeError(f"{field} must be exact UTC milliseconds") from error


def _failure(index: int, reason: str, signature: str) -> dict[str, Any]:
    """Build the cross-language fail-closed result shape used by retention verifiers."""
    return {"ok": False, "index": index, "reason": reason, "signature": signature}


def _combine_signature_status(current: str, next_status: str) -> str:
    """Aggregate chain signature status with invalid and skipped states taking precedence."""
    if "invalid" in (current, next_status):
        return "invalid"
    if "skipped" in (current, next_status):
        return "skipped"
    if "absent" in (current, next_status):
        return "absent"
    return "valid"
