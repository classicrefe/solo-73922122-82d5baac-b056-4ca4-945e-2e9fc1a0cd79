"""Independent witness service.

Persists batch id, byte length and SHA-256 of every accepted original and
issues an Ed25519 receipt. Same batch + filename + content reuses the stored
receipt; a different content under the same key is rejected. The witness
keeps its own SQLite database in its own persistent volume and never trusts
digests computed by the archiver: it hashes every upload itself.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import gc
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from common.receipt import (
    build_envelope,
    build_manifest_envelope,
    load_private_key,
    make_manifest_payload,
    public_key_fingerprint,
)
from witness.db import (
    Database,
    ReceiptConflict,
    SealActive,
    SealMismatch,
)

MAX_UPLOAD_BYTES = int(os.getenv("WITNESS_MAX_UPLOAD_BYTES", 2 * 1024 * 1024))
DB_PATH = os.getenv("WITNESS_DB", "/data/witness.db")
KEY_PATH = os.getenv("WITNESS_KEY", "/keys/witness_ed25519.pem")
SEAL_DELAY_SECONDS = float(os.getenv("WITNESS_SEAL_DELAY_SECONDS", "0"))

KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

db: Database
private_key = None


def validate_key(batch_id: str, filename: str) -> None:
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    if not KEY_RE.fullmatch(filename) or filename in (".", ".."):
        raise HTTPException(400, "invalid filename")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db, private_key
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = Database(DB_PATH)
    private_key = load_private_key(KEY_PATH)
    # Grab the running uvicorn server so the test-only shutdown endpoint can
    # ask it to exit gracefully (the CI sandbox blocks the kill syscall).
    import uvicorn.server
    for obj in gc.get_objects():
        if isinstance(obj, uvicorn.server.Server):
            app.state.server = obj
            break
    yield
    db.close()


app = FastAPI(title="Independent Witness Service", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "service": "witness",
            "public_key_fingerprint": public_key_fingerprint(
                private_key.public_key())}


def _row_to_envelope(row) -> dict:
    envelope = json.loads(row["payload"])
    envelope["signature"] = row["signature"]
    return envelope


@app.post("/receipts")
async def accept_original(batch_id: str = Form(...),
                          filename: str = Form(...),
                          file: UploadFile = File(...)):
    """Accept an original, persist its identity and issue/reuse a receipt."""
    validate_key(batch_id, filename)

    # Stream to disk-bounded memory while independently hashing and measuring.
    hasher = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(
                413,
                f"file exceeds witness limit of {MAX_UPLOAD_BYTES} bytes",
            )
        hasher.update(chunk)
        chunks.append(chunk)
    if total == 0:
        raise HTTPException(400, "empty file is not accepted")
    digest = hasher.hexdigest()

    existing = db.get(batch_id, filename)
    if existing is not None:
        if existing["sha256"] == digest and existing["length"] == total:
            # Same batch, same file, same content: reuse the stored receipt.
            return JSONResponse(
                status_code=200,
                content={"reused": True,
                         "receipt": _row_to_envelope(existing)},
            )
        # Same key, different content: refuse to overwrite history.
        raise HTTPException(
            409,
            {
                "error": "content_conflict",
                "message": "a different original is already witnessed under "
                           "this batch_id/filename",
                "existing": {"length": existing["length"],
                             "sha256": existing["sha256"]},
                "submitted": {"length": total, "sha256": digest},
            },
        )

    envelope = build_envelope(private_key, batch_id, filename, total, digest)
    payload = {k: envelope[k] for k in (
        "version", "batch_id", "filename", "length", "sha256",
        "issued_at", "algorithm", "public_key_fingerprint")}
    fields = {
        "batch_id": batch_id,
        "filename": filename,
        "length": total,
        "sha256": digest,
        "issued_at": envelope["issued_at"],
        "payload": json.dumps(payload, sort_keys=True),
        "signature": envelope["signature"],
    }
    try:
        # Atomic against sealing: once a seal commits, no further original can
        # be accepted, so a sealed batch's manifest can never miss a record.
        status, row = db.accept_original(batch_id, filename, total, digest,
                                         fields)
    except SealActive:
        raise HTTPException(
            409,
            {"error": "batch_sealed",
             "message": "this batch is sealed; no further files are accepted",
             "batch_id": batch_id},
        )
    except ReceiptConflict as exc:
        raise HTTPException(
            409,
            {"error": "content_conflict",
             "message": "a different original is already witnessed under "
                        "this batch_id/filename",
             "existing": exc.existing,
             "submitted": {"length": total, "sha256": digest}},
        )
    if status == "reused":
        return JSONResponse(status_code=200,
                            content={"reused": True,
                                     "receipt": _row_to_envelope(row)})
    return JSONResponse(status_code=201,
                        content={"reused": False,
                                 "receipt": _row_to_envelope(row)})


@app.get("/receipts/{batch_id}/{filename}")
def get_receipt(batch_id: str, filename: str):
    validate_key(batch_id, filename)
    row = db.get(batch_id, filename)
    if row is None:
        raise HTTPException(404, "no receipt for this batch_id/filename")
    return {"receipt": _row_to_envelope(row)}


@app.get("/batches/{batch_id}")
def get_batch(batch_id: str):
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    rows = db.list_batch(batch_id)
    seal = db.get_seal(batch_id)
    return {
        "batch_id": batch_id,
        "count": len(rows),
        "sealed": seal is not None,
        "sealed_at": seal["sealed_at"] if seal is not None else None,
        "items": [
            {"filename": r["filename"], "length": r["length"],
             "sha256": r["sha256"], "issued_at": r["issued_at"],
             "receipt": _row_to_envelope(r)}
            for r in rows
        ],
    }


# --------------------------------------------------------------------------- #
# Batch sealing
# --------------------------------------------------------------------------- #
def _public_manifest(envelope: dict) -> dict:
    return {
        "batch_id": envelope["batch_id"],
        "manifest": json.loads(envelope["payload_json"]),
        # The exact canonical bytes that were signed; verifiers compare these
        # verbatim rather than trusting a re-serialization.
        "payload_json": envelope["payload_json"],
        "signature": envelope["signature"],
        "algorithm": envelope["algorithm"],
        "public_key_fingerprint": envelope["public_key_fingerprint"],
    }


def _validate_manifest_files(files: Any) -> list[dict] | None:
    if files is None:
        return None
    if not isinstance(files, list) or not files:
        raise HTTPException(400, "files must be a non-empty list")
    out = []
    seen = set()
    for item in files:
        if not isinstance(item, dict):
            raise HTTPException(400, "each file entry must be an object")
        filename = item.get("filename")
        length = item.get("length")
        sha = item.get("sha256")
        if not isinstance(filename, str) \
                or not KEY_RE.fullmatch(filename) \
                or filename in (".", ".."):
            raise HTTPException(400, "invalid filename in manifest")
        if not isinstance(length, int) or isinstance(length, bool) \
                or length <= 0:
            raise HTTPException(400, "invalid length in manifest")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise HTTPException(400, "invalid sha256 in manifest")
        if filename in seen:
            raise HTTPException(400, "duplicate filename in manifest")
        seen.add(filename)
        out.append({"filename": filename, "length": length, "sha256": sha})
    return out


def _seal_builder(batch_id: str):
    def build(rows):
        manifest = make_manifest_payload(batch_id, [
            {"filename": r["filename"], "length": r["length"],
             "sha256": r["sha256"]} for r in rows
        ])
        envelope = build_manifest_envelope(private_key, manifest)
        return (envelope["payload_json"], envelope["signature"],
                envelope["public_key_fingerprint"], manifest["sealed_at"])
    return build


@app.post("/seals")
def seal_batch(payload: dict = Body(...)):
    """Freeze a batch under one Ed25519-signed manifest.

    The caller may supply the exact file list it believes is complete
    (batch id, filename, length, SHA-256).  Sealing is refused unless that
    list matches the witness's own persisted receipts exactly, so an in-flight
    upload is either already included or explicitly rejected -- never silently
    left out.  Repeating the request returns the same single manifest.
    """
    batch_id = payload.get("batch_id")
    if not isinstance(batch_id, str) or not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    expected = _validate_manifest_files(payload.get("files"))
    if SEAL_DELAY_SECONDS > 0:
        # Test-only knob: lets the self test cancel the HTTP request after the
        # witness committed the seal but before the archive heard back.
        import time as _time
        _time.sleep(SEAL_DELAY_SECONDS)
    try:
        status, envelope = db.seal_batch(batch_id, expected,
                                         _seal_builder(batch_id))
    except SealMismatch as exc:
        raise HTTPException(409, exc.detail)
    return JSONResponse(status_code=201 if status == "sealed" else 200,
                        content={"result": status,
                                 "seal": _public_manifest(envelope)})


@app.get("/seals/{batch_id}")
def get_seal(batch_id: str):
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    envelope = db.seal_envelope(batch_id)
    if envelope is None:
        raise HTTPException(404, "batch is not sealed")
    # Never serve a manifest that does not verify against the witness's own
    # key; a damaged seal must surface as an error, not as a valid document.
    from common.receipt import verify_manifest_envelope
    ok, err = verify_manifest_envelope(
        private_key.public_key(), envelope, expected_batch_id=batch_id)
    if not ok:
        raise HTTPException(500, f"stored seal failed self-verification: {err}")
    return {"seal": _public_manifest(envelope)}


@app.get("/seals")
def list_seals():
    rows = db.list_all_seals()
    items = []
    for r in rows:
        items.append(_public_manifest({
            "batch_id": r["batch_id"],
            "payload_json": r["payload_json"],
            "signature": r["signature"],
            "algorithm": "Ed25519",
            "public_key_fingerprint": r["public_key_fingerprint"],
        }))
    return {"count": len(items), "items": items}


@app.get("/receipts")
def list_receipts():
    """The complete list of receipts the witness has ever issued.

    Each item carries the full signed envelope so a verifier needs only this
    one endpoint to check every receipt (plus the locally stored originals).
    """
    rows = db.list_all()
    return {
        "count": len(rows),
        "items": [
            {"batch_id": r["batch_id"], "filename": r["filename"],
             "length": r["length"], "sha256": r["sha256"],
             "issued_at": r["issued_at"], "receipt": _row_to_envelope(r)}
            for r in rows
        ],
    }


@app.post("/__selftest_shutdown")
def selftest_shutdown():
    """Test-only graceful shutdown (no signal permissions in CI sandbox)."""
    def _stop():
        app.state.server.should_exit = True
    import threading
    threading.Thread(target=_stop, daemon=True).start()
    return {"shutting_down": True}
