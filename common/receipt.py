"""Ed25519 receipt payload construction, signing and verification.

A receipt covers exactly what the independent witness persistently observed:
batch id, filename, byte length and SHA-256 digest. The canonical byte form
is deterministic JSON so any party holding the public key can re-verify.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RECEIPT_VERSION = 1
MANIFEST_VERSION = 1
MANIFEST_KIND = "batch_seal_manifest"


def canonicalize(payload: dict) -> bytes:
    """Deterministic byte encoding of a receipt payload."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def make_payload(batch_id: str, filename: str, length: int, sha256: str,
                 issued_at: str | None = None) -> dict:
    return {
        "version": RECEIPT_VERSION,
        "batch_id": batch_id,
        "filename": filename,
        "length": int(length),
        "sha256": sha256,
        "issued_at": issued_at
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_public_key(fh.read())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def sign_payload(private_key: Ed25519PrivateKey, payload: dict) -> str:
    signature = private_key.sign(canonicalize(payload))
    return base64.b64encode(signature).decode("ascii")


def verify_payload(public_key: Ed25519PublicKey, payload: dict,
                   signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, canonicalize(payload))
        return True
    except (InvalidSignature, ValueError):
        return False


def build_envelope(private_key: Ed25519PrivateKey, batch_id: str,
                   filename: str, length: int, sha256: str,
                   issued_at: str | None = None) -> dict:
    payload = make_payload(batch_id, filename, length, sha256, issued_at)
    return {
        **payload,
        "algorithm": "Ed25519",
        "signature": sign_payload(private_key, payload),
        "public_key_fingerprint": public_key_fingerprint(
            private_key.public_key()
        ),
    }


def verify_envelope(public_key: Ed25519PublicKey, envelope: dict,
                    expected: dict | None = None) -> tuple[bool, str | None]:
    """Verify an envelope's signature against the fixed public key.

    ``expected`` optionally pins batch_id/filename/length/sha256 so a receipt
    cannot be replayed against a different original.
    """
    required = {"version", "batch_id", "filename", "length", "sha256",
                "issued_at", "signature", "algorithm"}
    missing = required - set(envelope)
    if missing:
        return False, f"receipt missing fields: {sorted(missing)}"
    if envelope.get("algorithm") != "Ed25519":
        return False, "unsupported receipt algorithm"
    if envelope.get("public_key_fingerprint") and \
            envelope["public_key_fingerprint"] != \
            public_key_fingerprint(public_key):
        return False, "public key fingerprint mismatch"
    payload = {k: envelope[k] for k in (
        "version", "batch_id", "filename", "length", "sha256", "issued_at")}
    if not verify_payload(public_key, payload, envelope["signature"]):
        return False, "Ed25519 signature verification failed"
    if expected:
        for field in ("batch_id", "filename", "length", "sha256"):
            if field in expected and payload.get(field) != expected[field]:
                return False, f"receipt field {field} does not match original"
    return True, None


# --------------------------------------------------------------------------- #
# Batch seal manifests
#
# A seal freezes a whole batch: one Ed25519 signature over the batch id, the
# seal time and the complete ordered list of (filename, length, SHA-256).  The
# signed payload is stored verbatim so the exact byte string that was signed
# can be re-verified later, independently of any list reconstruction code.
# --------------------------------------------------------------------------- #
def make_manifest_payload(batch_id: str, files: list[dict],
                          sealed_at: str | None = None) -> dict:
    """Build the order-sensitive manifest payload.

    ``files`` must already be sorted by the caller; the list is serialized as
    a list (not a set/map) so the signature pins the exact ordering as well.
    """
    return {
        "version": MANIFEST_VERSION,
        "kind": MANIFEST_KIND,
        "batch_id": batch_id,
        "file_count": len(files),
        "files": [
            {"filename": f["filename"], "length": int(f["length"]),
             "sha256": f["sha256"]}
            for f in files
        ],
        "sealed_at": sealed_at
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def build_manifest_envelope(private_key: Ed25519PrivateKey,
                            manifest: dict) -> dict:
    return {
        "payload_json": canonicalize(manifest).decode("utf-8"),
        "signature": sign_payload(private_key, manifest),
        "algorithm": "Ed25519",
        "public_key_fingerprint": public_key_fingerprint(
            private_key.public_key()),
    }


def verify_manifest_envelope(public_key: Ed25519PublicKey, envelope: dict,
                             expected_batch_id: str | None = None,
                             expected_files: list[dict] | None = None
                             ) -> tuple[bool, str | None]:
    """Verify a signed manifest against the fixed key and, optionally, a
    locally recomputed file list (batch id + every filename/length/SHA-256)."""
    import json as _json
    if envelope.get("algorithm") != "Ed25519":
        return False, "unsupported manifest algorithm"
    if envelope.get("public_key_fingerprint") and \
            envelope["public_key_fingerprint"] != \
            public_key_fingerprint(public_key):
        return False, "public key fingerprint mismatch"
    payload_json = envelope.get("payload_json")
    signature = envelope.get("signature")
    if not payload_json or not signature:
        return False, "manifest missing payload or signature"
    try:
        payload = _json.loads(payload_json)
    except (ValueError, TypeError):
        return False, "manifest payload is not valid JSON"
    if not isinstance(payload, dict):
        return False, "manifest payload is not an object"
    signed = _json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    # Compare the exact signed bytes, not just a re-serialized equivalent.
    if signed.decode("utf-8") != payload_json:
        return False, "manifest payload bytes are not canonical"
    if not verify_payload(public_key, payload, signature):
        return False, "Ed25519 manifest signature verification failed"
    if payload.get("kind") != MANIFEST_KIND:
        return False, "not a batch seal manifest"
    if payload.get("version") != MANIFEST_VERSION:
        return False, f"unsupported manifest version {payload.get('version')}"
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        return False, "manifest has no files"
    if payload.get("file_count") != len(files):
        return False, "manifest file_count does not match file list"
    names = set()
    for item in files:
        if not isinstance(item, dict) or \
                set(item) != {"filename", "length", "sha256"}:
            return False, "manifest file entry is malformed"
        if not isinstance(item["filename"], str) or \
                not isinstance(item["length"], int) or \
                not isinstance(item["sha256"], str):
            return False, "manifest file entry has wrong types"
        if item["filename"] in names:
            return False, "manifest lists a filename twice"
        names.add(item["filename"])
    if expected_batch_id is not None and \
            payload.get("batch_id") != expected_batch_id:
        return False, "manifest batch_id does not match the sealed batch"
    if expected_files is not None:
        expected = [{"filename": f["filename"],
                     "length": int(f["length"]),
                     "sha256": f["sha256"]} for f in expected_files]
        if files != expected:
            return False, "manifest file list does not match local originals"
    return True, None
