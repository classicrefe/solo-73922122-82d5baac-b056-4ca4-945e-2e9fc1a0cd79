"""Research data archiving web service.

The archiver uploads originals to an independent witness, verifies every
Ed25519 receipt with a fixed public key, and only reports success when the
local original, the catalog entry and the verified receipt are all present.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import gc
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
)
from fastapi.templating import Jinja2Templates

from archive.db import Database
from archive.witness_client import (
    WitnessClient,
    WitnessRefused,
    WitnessTimeout,
    WitnessUnreachable,
)
from common.receipt import (
    load_public_key,
    verify_envelope,
    verify_manifest_envelope,
)

MAX_UPLOAD_BYTES = int(os.getenv("ARCHIVE_MAX_UPLOAD_BYTES", 2 * 1024 * 1024))
DB_PATH = os.getenv("ARCHIVE_DB", "/data/archive.db")
STORAGE_DIR = Path(os.getenv("ARCHIVE_STORAGE", "/data/originals"))
PUBKEY_PATH = os.getenv("ARCHIVE_PUBLIC_KEY",
                        "/keys/witness_ed25519.pub.pem")
WITNESS_URL = os.getenv("WITNESS_URL", "http://witness:8001")
CRASH_MARKER = Path(os.getenv("ARCHIVE_CRASH_MARKER",
                              "/data/crash_after_witness.flag"))
# Test-only fault injection: die after the witness has signed the seal but
# before the archive stores it (simulates losing the response / local death).
SEAL_CRASH_MARKER = Path(os.getenv("ARCHIVE_SEAL_CRASH_MARKER",
                                   "/data/crash_after_seal.flag"))
# Test-only fault injection: make the local seal write fail once (simulates a
# disk/SQLite failure between witness signing and local storage).
SEAL_FAIL_MARKER = Path(os.getenv("ARCHIVE_SEAL_FAIL_MARKER",
                                  "/data/seal_write_fail.flag"))

KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

db: Database
witness: WitnessClient
public_key = None
templates = Jinja2Templates(directory=os.path.join(
    os.path.dirname(__file__), "templates"))

# One lock per batch: concurrent retries of the same batch are serialized so
# the same original can never be archived twice and only one seal can be
# produced. Different batches never share a lock, so a slow seal of one batch
# cannot block uploads or queries for any other batch.
_batch_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()

# A seal answers "is this batch frozen?" forever, so it must be durable.
SEAL_WITNESS_TIMEOUT = float(os.getenv("ARCHIVE_SEAL_TIMEOUT", "15"))


def batch_lock(batch_id: str) -> threading.Lock:
    with _locks_guard:
        lock = _batch_locks.get(batch_id)
        if lock is None:
            lock = threading.Lock()
            _batch_locks[batch_id] = lock
        return lock


def validate_keys(batch_id: str, filename: str) -> None:
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    if not KEY_RE.fullmatch(filename) or filename in (".", ".."):
        raise HTTPException(400, "invalid filename")


def storage_path(batch_id: str, filename: str) -> Path:
    return STORAGE_DIR / batch_id / filename


def sha256_file(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    length = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(64 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
            length += len(chunk)
    return hasher.hexdigest(), length


def row_to_dict(row) -> dict:
    data = dict(row)
    if data.get("receipt"):
        data["receipt"] = json.loads(data["receipt"])
    return data


def batch_status(batch_id: str) -> dict:
    rows = [row_to_dict(r) for r in db.list_batch(batch_id)]
    registered = [r for r in rows if r["status"] == "registered"]
    ok = bool(rows) and len(registered) == len(rows)
    seal = db.get_seal(batch_id)
    sealed_at = seal["sealed_at"] if seal is not None else None
    seal_intact = False
    if seal is not None and seal["state"] == "sealed":
        try:
            seal_intact, _ = verify_stored_seal(seal, check_content=False)
        except SealNotReady:
            seal_intact = False
    # Success requires local originals AND catalog AND verified receipts.
    complete = False
    if ok:
        complete = all(
            storage_path(batch_id, r["filename"]).is_file()
            and verify_receipt(r) for r in registered)
    if seal is not None:
        seal_state = seal["state"]
        if seal_state == "sealed":
            # A stored-but-not-reverifiable seal is never a success.
            status = "sealed" if seal_intact else "seal_unverified"
        elif seal_state == "sealing":
            # Outcome not yet known: never success, never re-opened for adds.
            status = "seal_pending"
        else:  # unverified
            status = "seal_failed"
    else:
        status = "complete" if complete else (
            "pending" if any(r["status"] == "pending" for r in rows)
            else "incomplete")
    return {
        "batch_id": batch_id,
        "status": status,
        # "sealed" is only true for a manifest that verifies right now; an
        # unverified/unresolved seal is reported through seal_state instead.
        "sealed": seal is not None and seal["state"] == "sealed"
        and seal_intact,
        "seal_state": seal["state"] if seal is not None else None,
        "sealed_at": sealed_at,
        "file_count": len(rows),
        "registered_count": len(registered),
        "files": rows,
    }


def local_matches_row(file_row: dict) -> bool:
    """Re-hash a stored original and compare to the catalog/length+digest."""
    path = storage_path(file_row["batch_id"], file_row["filename"])
    if not path.is_file():
        return False
    digest, length = sha256_file(path)
    return digest == file_row["sha256"] and length == file_row["length"]


def verify_receipt(file_row: dict) -> tuple[bool, str | None]:
    if not file_row.get("receipt"):
        return False, "no receipt in catalog"
    expected = {
        "batch_id": file_row["batch_id"],
        "filename": file_row["filename"],
        "length": file_row["length"],
        "sha256": file_row["sha256"],
    }
    return verify_envelope(public_key, file_row["receipt"], expected)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db, witness, public_key
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = Database(DB_PATH)
    witness = WitnessClient(WITNESS_URL)
    public_key = load_public_key(PUBKEY_PATH)
    # Grab the running uvicorn server for the test-only shutdown endpoint.
    import uvicorn.server
    for obj in gc.get_objects():
        if isinstance(obj, uvicorn.server.Server):
            app.state.server = obj
            break
    # After a restart, find and continue every batch left pending instead of
    # re-submitting anything blindly. Also recovers originals written before a
    # crash that happened ahead of local catalog registration.
    try:
        reconcile_pending()
    except Exception as exc:  # pragma: no cover - startup must not crash
        print(f"[startup] reconcile deferred: {exc}")
    # Seals whose outcome was unknown (process exited or witness response was
    # lost) are resumed against the witness; the manifest is only announced
    # once it verifies locally. Never reported as success blindly.
    threading.Thread(target=resume_seals, daemon=True,
                     name="seal-resume").start()
    yield
    db.close()


app = FastAPI(title="Research Data Archive", lifespan=lifespan)


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def page_index(request: Request):
    batches = [dict(r) for r in db.list_batches()]
    return templates.TemplateResponse(
        request,
        "index.html",
        {"batches": batches, "witness_url": WITNESS_URL},
    )


@app.get("/batches/{batch_id}", response_class=HTMLResponse)
def page_batch(request: Request, batch_id: str):
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    return templates.TemplateResponse(
        request,
        "batch.html",
        {"batch_id": batch_id},
    )


@app.get("/verify", response_class=HTMLResponse)
def page_verify(request: Request):
    return templates.TemplateResponse(request, "verify.html", {})


@app.get("/seals", response_class=HTMLResponse)
def page_seals(request: Request):
    batches = [dict(r) for r in db.list_batches()]
    return templates.TemplateResponse(
        request,
        "seals.html",
        {"batches": batches},
    )


# --------------------------------------------------------------------------- #
# Upload / download
# --------------------------------------------------------------------------- #
@app.post("/api/batches/{batch_id}/files")
def upload_file(batch_id: str,
                filename: str = Form(...),
                file: UploadFile = File(...)):
    # Sync endpoint on purpose: FastAPI runs it in a threadpool, so blocking
    # file IO and the synchronous witness call do not stall the event loop
    # and uploads of different batches truly run concurrently.
    validate_keys(batch_id, filename)

    # Read with the 2 MiB hard limit.
    hasher = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    src = file.file  # underlying sync spooled file object
    while True:
        chunk = src.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(
                413,
                f"file exceeds archive limit of {MAX_UPLOAD_BYTES} bytes",
            )
        hasher.update(chunk)
        chunks.append(chunk)
    if total == 0:
        raise HTTPException(400, "empty file is not accepted")
    content = b"".join(chunks)
    digest = hasher.hexdigest()

    with batch_lock(batch_id):
        existing = db.get_file(batch_id, filename)
        if existing is not None and existing["status"] == "registered" \
                and existing["sha256"] == digest:
            # Idempotent re-upload of identical content: nothing to do. This
            # holds even for a sealed batch -- the already-received original
            # keeps its original receipt instead of a new one.
            return {"result": "already_registered", "reused": True,
                    "batch": batch_status(batch_id)}
        # Sealing closes the batch permanently. Checked inside the lock so an
        # upload cannot race past a seal that is being committed for the same
        # batch; uploads of *other* batches take other locks and are unaffected.
        seal = db.get_seal(batch_id)
        if seal is not None:
            if seal["state"] == "sealed":
                raise HTTPException(
                    409,
                    "batch is sealed; no new files can be added. Re-uploading "
                    "an already-received original unchanged still works.",
                )
            if seal["state"] == "sealing":
                raise HTTPException(
                    409,
                    "a seal for this batch is in progress; the outcome is "
                    "being verified. No new files can be added.",
                )
            # 'unverified': the seal did not complete, but the file list was
            # already closed when it started. Do not silently re-open it.
            raise HTTPException(
                409,
                "a seal attempt for this batch is unresolved (待核); resolve "
                "or retry the seal before adding files.",
            )
        if existing is not None:
            if existing["sha256"] != digest:
                raise HTTPException(
                    409,
                    "different content already exists for this "
                    "batch_id/filename; the witnessed original is preserved",
                )
            # Same content still pending: fall through to reconciliation.

        target = storage_path(batch_id, filename)
        # Never overwrite a stored original, even on failure/cleanup paths.
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            # Unique temp name: concurrent uploads must not share a .part file.
            tmp = target.with_name(
                f".{target.name}.{uuid.uuid4().hex}.part")
            with open(tmp, "wb") as fh:
                fh.write(content)
            os.replace(tmp, target)

        try:
            response = witness.submit(batch_id, filename, content, digest)
        except WitnessUnreachable as exc:
            # Not yet known to be accepted: mark PENDING for verification;
            # must never be treated as "not accepted" and re-submitted blind.
            db.upsert_pending(batch_id, filename, total, digest,
                              f"witness unreachable: {exc}")
            return JSONResponse(
                status_code=202,
                content={"result": "pending",
                         "reason": "witness_unreachable",
                         "batch": batch_status(batch_id)},
            )
        except WitnessRefused as exc:
            # The witness explicitly refused. A concurrent seal that won the
            # race is a definitive rejection; so is a content conflict.
            detail = (exc.detail.get("error")
                      if isinstance(exc.detail, dict) else None)
            if detail == "batch_sealed":
                raise HTTPException(
                    409,
                    "batch was sealed by a concurrent request while this "
                    "upload was in flight; the file was not accepted",
                )
            if detail == "content_conflict":
                db.upsert_pending(batch_id, filename, total, digest,
                                  f"content conflict: {exc.detail}")
                raise HTTPException(409, exc.detail)
            raise HTTPException(
                409, f"witness refused the upload: {exc.detail}")
        except WitnessTimeout as exc:
            # The submission may have been accepted. Never assume either way.
            db.upsert_pending(batch_id, filename, total, digest,
                              f"witness response lost: {exc}")
            return JSONResponse(
                status_code=202,
                content={"result": "pending",
                         "reason": "witness_response_lost",
                         "batch": batch_status(batch_id)},
            )

        # Demo fault: the process dies after the witness accepted the original
        # but before the local catalog records the receipt. A marker file in
        # the persistent volume guarantees the crash happens only once.
        if CRASH_MARKER.exists():
            try:
                CRASH_MARKER.unlink()
            except OSError:
                pass
            print("[fault-injection] crashing after witness acceptance, "
                  "before local registration", flush=True)
            os._exit(1)

        envelope = response["receipt"]
        ok, err = verify_envelope(
            public_key, envelope,
            expected={"batch_id": batch_id, "filename": filename,
                      "length": total, "sha256": digest},
        )
        if not ok:
            db.upsert_pending(batch_id, filename, total, digest,
                              f"receipt verification failed: {err}")
            raise HTTPException(502, f"receipt verification failed: {err}")

        db.mark_registered(batch_id, filename, total, digest,
                           json.dumps(envelope, sort_keys=True))
        return {"result": "registered", "reused": response.get("reused"),
                "batch": batch_status(batch_id)}


@app.get("/api/batches")
def list_batches():
    return {"batches": [dict(r) for r in db.list_batches()]}


@app.get("/api/batches/{batch_id}")
def get_batch(batch_id: str):
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    rows = db.list_batch(batch_id)
    if not rows:
        raise HTTPException(404, "batch not found in local catalog")
    return batch_status(batch_id)


@app.get("/api/batches/{batch_id}/download/{filename}")
def download(batch_id: str, filename: str):
    validate_keys(batch_id, filename)
    row = db.get_file(batch_id, filename)
    if row is None or row["status"] != "registered":
        raise HTTPException(404, "file is not registered; download closed")
    path = storage_path(batch_id, filename)
    if not path.is_file():
        raise HTTPException(410, "registered original is missing on disk")
    digest, length = sha256_file(path)
    if digest != row["sha256"] or length != row["length"]:
        raise HTTPException(409, "stored original fails integrity check; "
                                 "download refused")
    receipt = json.loads(row["receipt"])
    ok, err = verify_envelope(
        public_key, receipt,
        expected={"batch_id": batch_id, "filename": filename,
                  "length": length, "sha256": digest},
    )
    if not ok:
        raise HTTPException(409, f"receipt invalid: {err}")
    # A sealed batch is frozen: content that no longer matches the signed
    # manifest must not be handed out as if it were the sealed original.
    seal = db.get_seal(batch_id)
    if seal is not None and seal["state"] == "sealed":
        ok, err = verify_stored_seal(seal)
        if not ok:
            raise HTTPException(409, f"batch seal invalid: {err}")
    return FileResponse(path, filename=filename,
                        media_type="application/octet-stream")


# --------------------------------------------------------------------------- #
# Batch sealing
# --------------------------------------------------------------------------- #
class SealNotReady(Exception):
    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


def seal_files_snapshot(batch_id: str, check_content: bool = True) -> list[dict]:
    """The complete, ordered file list that a seal must cover.

    Refuses if the batch is empty or has anything not fully registered, so a
    seal can never silently omit an in-flight file.  With ``check_content``
    the local bytes are re-hashed too (used when creating a seal and on the
    verification page); status reads pass False to avoid repeated hashing.
    """
    rows = db.list_batch(batch_id)
    if not rows:
        raise SealNotReady("batch has no files; nothing to seal")
    if any(r["status"] != "registered" for r in rows):
        raise SealNotReady(
            "batch still has unregistered (待核) files; reconcile them "
            "before sealing")
    if check_content:
        # An original sitting in the batch directory without a catalog row is
        # an in-flight/crashed upload. It must be reconciled (and therefore
        # either included or explicitly rejected) before the batch is frozen;
        # otherwise the seal would silently leave it outside the manifest.
        known = {r["filename"] for r in rows}
        batch_dir = STORAGE_DIR / batch_id
        if batch_dir.is_dir():
            stray = sorted(
                p.name for p in batch_dir.iterdir()
                if p.is_file() and not p.name.endswith(".part")
                and KEY_RE.fullmatch(p.name) and p.name not in known)
            if stray:
                raise SealNotReady(
                    "batch directory holds originals with no catalog row "
                    f"({', '.join(stray)}); run reconciliation before sealing")
    files = []
    for raw in rows:
        r = row_to_dict(raw)
        if check_content and not local_matches_row(r):
            raise SealNotReady(
                f"local original for {r['filename']} does not match its "
                "catalog digest/length; refusing to seal")
        ok, err = verify_receipt(r)
        if not ok:
            raise SealNotReady(
                f"receipt for {r['filename']} fails verification: {err}")
        files.append({"filename": r["filename"], "length": r["length"],
                      "sha256": r["sha256"]})
    return files


def verify_stored_seal(seal_row, expected_files: list[dict] | None = None,
                       batch_id: str | None = None,
                       check_content: bool = True
                       ) -> tuple[bool, str | None]:
    """Verify a stored manifest against the fixed public key and local files."""
    row = dict(seal_row)
    if expected_files is None:
        expected_files = seal_files_snapshot(row["batch_id"], check_content)
    envelope = {
        "payload_json": row["manifest_json"] or "",
        "signature": row["signature"] or "",
        "algorithm": row["algorithm"] or "",
        "public_key_fingerprint": row["public_key_fingerprint"] or "",
    }
    return verify_manifest_envelope(
        public_key, envelope, expected_batch_id=batch_id or row["batch_id"],
        expected_files=expected_files)


def _store_verified_seal(batch_id: str, envelope: dict,
                         expected_files: list[dict]) -> None:
    """Verify the witness's manifest and persist it, or fail closed.

    The manifest and signature are written in one UPDATE; on any error the
    row is explicitly moved to a non-downloadable state, so a half-written
    manifest can never appear on the download endpoint.
    """
    try:
        ok, err = verify_manifest_envelope(
            public_key, envelope, expected_batch_id=batch_id,
            expected_files=expected_files)
        if not ok:
            raise ValueError(f"manifest verification failed: {err}")
        manifest = json.loads(envelope["payload_json"])
        # An already-committed, still-verifiable seal is never replaced; only
        # the initial commitment (or recovery from a non-sealed state) writes.
        current = db.get_seal(batch_id)
        if current is not None and current["state"] == "sealed" and \
                current["manifest_json"] == envelope["payload_json"] and \
                current["signature"] == envelope["signature"]:
            return
        if SEAL_FAIL_MARKER.exists():
            # Fault injection: simulate a local write failure *before* any
            # manifest bytes are committed. The row must stay unverified.
            try:
                SEAL_FAIL_MARKER.unlink()
            except OSError:
                pass
            raise OSError("injected local seal write failure")
        db.mark_sealed(
            batch_id, len(expected_files), envelope["payload_json"],
            envelope["signature"], envelope.get("algorithm", "Ed25519"),
            envelope.get("public_key_fingerprint", ""), manifest["sealed_at"])
        row = db.get_seal(batch_id)
        ok, err = verify_stored_seal(row, expected_files, batch_id)
        if not ok:  # pragma: no cover - would indicate storage corruption
            raise ValueError(f"stored seal re-check failed: {err}")
    except HTTPException:
        raise
    except Exception as exc:
        # A manifest that did not pass local verification must never be kept
        # for reuse; drop it but keep the row (still non-downloadable).
        db.mark_seal_unverified(batch_id, str(exc))
        db.drop_seal_manifest(batch_id)
        raise HTTPException(502, f"witness manifest rejected: {exc}")


def _seal_response(batch_id: str, status_code: int = 200) -> JSONResponse:
    status = batch_status(batch_id)
    seal = db.get_seal(batch_id)
    payload = {"batch": status, "seal_state": status["status"]}
    if seal is not None:
        if seal["state"] == "sealed" and seal["manifest_json"]:
            payload["seal"] = {
                "batch_id": batch_id,
                "payload_json": seal["manifest_json"],
                "manifest": json.loads(seal["manifest_json"]),
                "signature": seal["signature"],
                "algorithm": seal["algorithm"],
                "public_key_fingerprint": seal["public_key_fingerprint"],
            }
        else:
            payload["seal"] = None
        payload["last_error"] = seal["last_error"]
    return JSONResponse(status_code=status_code, content=payload)


def seal_batch_now(batch_id: str) -> JSONResponse:
    """Seal/renew/resume a batch.  Caller must hold the batch lock.

    States:
      no seal          -> snapshot files, record intent+list, ask witness, store
      sealing          -> outcome unknown (timeout/lost response/crash):
                          ask the witness what happened; never report success
                          until its signed manifest is verified locally
      sealed           -> return the one existing manifest (idempotent)
      unverified       -> retry the same frozen file list; never re-open
    """
    seal = db.get_seal(batch_id)
    if seal is not None and seal["state"] == "sealed":
        try:
            ok, err = verify_stored_seal(seal, check_content=False)
        except SealNotReady as exc:
            ok, err = False, exc.detail
        if not ok:
            db.mark_seal_unverified(
                batch_id, f"stored seal no longer verifies: {err}")
            return _seal_response(batch_id, 409)
        try:
            files = seal_files_snapshot(batch_id)
            ok, err = verify_stored_seal(seal, files)
        except SealNotReady as exc:
            ok, err = False, exc.detail
        if not ok:
            db.mark_seal_unverified(
                batch_id, f"sealed originals no longer match: {err}")
            return _seal_response(batch_id, 409)
        return _seal_response(batch_id, 200)

    if seal is None:
        # Freeze the file list first, then persist it together with the intent.
        # From this point the batch is closed for new files even if the
        # witness call dies: the retry reuses exactly this list.
        files = seal_files_snapshot(batch_id)
        files_json = json.dumps(files, sort_keys=True)
        if not db.begin_seal(batch_id, files_json):
            # Another request/process claimed the seal first; re-read and
            # continue from its state instead of producing a second manifest.
            seal = db.get_seal(batch_id)
            if seal is not None and seal["state"] == "sealed":
                return _seal_response(batch_id, 200)
    if seal is None:
        seal = db.get_seal(batch_id)
    if seal is not None:
        try:
            files = json.loads(seal["files_json"])
        except (ValueError, KeyError):
            db.mark_seal_unverified(batch_id,
                                    "stored seal file list unreadable")
            return _seal_response(batch_id, 409)
        if seal["state"] == "unverified" and seal["manifest_json"]:
            # A manifest already exists but failed a later re-check (for
            # example a local write error or post-seal tampering). Do not ask
            # the witness for a different one: re-verify *this* manifest and
            # reuse it if it is now acceptable.
            try:
                _store_verified_seal(batch_id, {
                    "payload_json": seal["manifest_json"],
                    "signature": seal["signature"],
                    "algorithm": seal["algorithm"],
                    "public_key_fingerprint":
                        seal["public_key_fingerprint"],
                }, files)
            except HTTPException:
                return _seal_response(batch_id, 502)
            return _seal_response(batch_id, 200)

    # 1) Find out whether the witness already holds a seal for this batch
    #    (lost response, crash before local registration, or a retry).
    try:
        existing = witness.get_seal(batch_id)
    except WitnessUnreachable as exc:
        # Still unknown: keep the intent, do not claim success, do not reopen.
        db.set_seal_error(batch_id, f"witness unreachable: {exc}")
        return _seal_response(batch_id, 503)
    except WitnessRefused as exc:
        db.mark_seal_unverified(batch_id, f"witness refused seal lookup: {exc}")
        return _seal_response(batch_id, 502)

    if existing is not None:
        try:
            _store_verified_seal(batch_id, existing, files)
        except HTTPException:
            return _seal_response(batch_id, 502)
        return _seal_response(batch_id, 200)

    # 2) No seal yet: request one and verify the signed manifest before
    #    storing/announcing anything.
    try:
        result = witness.seal_batch(batch_id, files,
                                    timeout=SEAL_WITNESS_TIMEOUT)
    except WitnessTimeout as exc:
        # The request was sent; the manifest may exist. Keep "sealing" (待核),
        # never report success, never reopen for new files.
        db.set_seal_error(batch_id, f"seal response lost: {exc}")
        return _seal_response(batch_id, 202)
    except WitnessUnreachable as exc:
        db.set_seal_error(batch_id, f"witness unreachable: {exc}")
        return _seal_response(batch_id, 503)
    except WitnessRefused as exc:
        detail = exc.detail
        msg = (detail.get("error") if isinstance(detail, dict) else detail)
        db.mark_seal_unverified(batch_id, f"witness refused seal: {msg}")
        return _seal_response(batch_id, 409 if exc.status_code == 409 else 502)

    envelope = result.get("seal") or {}

    # Demo/fault injection: die after the witness signed the manifest but
    # before it is stored locally. On restart the seal must be recovered from
    # the witness, not re-created and not reported sealed on faith.
    if SEAL_CRASH_MARKER.exists():
        try:
            SEAL_CRASH_MARKER.unlink()
        except OSError:
            pass
        print("[fault-injection] crashing after witness sealed the batch, "
              "before local seal registration", flush=True)
        os._exit(1)

    try:
        _store_verified_seal(batch_id, envelope, files)
    except HTTPException:
        return _seal_response(batch_id, 502)
    return _seal_response(batch_id, 201)


@app.get("/api/seals")
def list_seals_api():
    batches = []
    for row in db.list_batches():
        item = dict(row)
        # Cheap status for the list view: no per-file re-hashing. Full
        # integrity is confirmed on the batch/seal detail and verify pages.
        if item.get("seal_state") == "sealed":
            status = "sealed"
        elif item.get("seal_state") == "sealing":
            status = "seal_pending"
        elif item.get("seal_state") == "unverified":
            status = "seal_failed"
        elif item["file_count"] and \
                item["registered_count"] == item["file_count"]:
            status = "complete"
        elif item["pending_count"]:
            status = "pending"
        else:
            status = "incomplete"
        batches.append({
            "batch_id": item["batch_id"],
            "file_count": item["file_count"],
            "registered_count": item["registered_count"],
            "seal_state": item.get("seal_state"),
            "sealed_at": item.get("sealed_at"),
            "status": status,
        })
    return {"batches": batches}


@app.post("/api/batches/{batch_id}/seal")
def seal_batch(batch_id: str):
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    try:
        with batch_lock(batch_id):
            return seal_batch_now(batch_id)
    except SealNotReady as exc:
        return JSONResponse(status_code=409,
                            content={"error": "not_ready",
                                     "detail": exc.detail,
                                     "batch": batch_status(batch_id)})


@app.post("/api/batches/{batch_id}/seal/retry")
def retry_seal(batch_id: str):
    """Resume an unresolved seal (状态不明/待核) using the same manifest."""
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    try:
        with batch_lock(batch_id):
            return seal_batch_now(batch_id)
    except SealNotReady as exc:
        return JSONResponse(status_code=409,
                            content={"error": "not_ready",
                                     "detail": exc.detail,
                                     "batch": batch_status(batch_id)})


@app.get("/api/batches/{batch_id}/seal")
def get_seal(batch_id: str):
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    rows = db.list_batch(batch_id)
    seal = db.get_seal(batch_id)
    if not rows and seal is None:
        raise HTTPException(404, "batch not found")
    status = batch_status(batch_id)
    out = {
        "batch_id": batch_id,
        "status": status["status"],
        "sealed": seal is not None and seal["state"] == "sealed",
        "seal_state": seal["state"] if seal is not None else None,
        "sealed_at": seal["sealed_at"] if seal is not None else None,
        "last_error": seal["last_error"] if seal is not None else None,
        "manifest": None,
        "download_url": None,
    }
    if seal is not None and seal["state"] == "sealed":
        try:
            ok, err = verify_stored_seal(seal, check_content=False)
        except SealNotReady as exc:
            ok, err = False, exc.detail
        if not ok:
            out["sealed"] = False
            out["seal_state"] = "unverified"
            out["error"] = f"stored seal invalid: {err}"
            return out
        # Report the manifest, but only advertise a download when the frozen
        # bytes on disk still match the signed manifest right now.
        try:
            content_ok, content_err = verify_stored_seal(
                seal, check_content=True)
        except SealNotReady as exc:
            content_ok, content_err = False, exc.detail
        out["manifest"] = json.loads(seal["manifest_json"])
        if content_ok:
            out["download_url"] = f"/api/batches/{batch_id}/seal/download"
        else:
            out["sealed"] = False
            out["status"] = "seal_unverified"
            out["error"] = f"sealed originals no longer match: {content_err}"
    return out


@app.get("/api/batches/{batch_id}/seal/download")
def download_seal(batch_id: str):
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    seal = db.get_seal(batch_id)
    if seal is None or seal["state"] != "sealed" or not seal["manifest_json"]:
        raise HTTPException(404, "no verified seal is available for download")
    # Re-verify signature + full local file list immediately before serving;
    # a damaged or inconsistent seal is never handed out as a downloadable
    # document.
    try:
        ok, err = verify_stored_seal(seal)
    except SealNotReady as exc:
        raise HTTPException(409, f"seal cannot be confirmed: {exc.detail}")
    if not ok:
        raise HTTPException(409, f"stored seal invalid: {err}")
    body = json.dumps({
        "batch_id": batch_id,
        "manifest": json.loads(seal["manifest_json"]),
        "signature": seal["signature"],
        "algorithm": seal["algorithm"],
        "public_key_fingerprint": seal["public_key_fingerprint"],
    }, ensure_ascii=False, indent=2, sort_keys=True)
    return PlainTextResponse(
        body,
        media_type="application/json",
        headers={"Content-Disposition":
                 f'attachment; filename="{batch_id}.seal.json"'},
    )


# --------------------------------------------------------------------------- #
# Reconciliation after disconnect / restart
# --------------------------------------------------------------------------- #
def discover_orphans() -> list[dict]:
    """Find stored originals that have no catalog row.

    This covers the crash window after the witness accepted an original but
    before local registration: the file is on disk, the catalog has nothing.
    """
    orphans: list[dict] = []
    if not STORAGE_DIR.is_dir():
        return orphans
    for batch_dir in sorted(STORAGE_DIR.iterdir()):
        if not batch_dir.is_dir() or not KEY_RE.fullmatch(batch_dir.name):
            continue
        batch_id = batch_dir.name
        for path in sorted(batch_dir.iterdir()):
            if not path.is_file() or path.name.endswith(".part") \
                    or not KEY_RE.fullmatch(path.name):
                continue
            if db.get_file(batch_id, path.name) is not None:
                continue  # catalog already knows this file
            digest, length = sha256_file(path)
            orphans.append({"batch_id": batch_id, "filename": path.name,
                            "length": length, "sha256": digest})
    return orphans


def reconcile_one(target: dict) -> dict:
    """Check one pending/orphan target against the witness and continue it.

    ``target`` always carries batch_id, filename, length, sha256. The witness
    is queried first: an existing receipt is reused, so a disconnect can never
    cause a blind re-submission.
    """
    batch_id, filename = target["batch_id"], target["filename"]
    result = {"batch_id": batch_id, "filename": filename}

    # A sealed batch is frozen: never register a new file into it, and never
    # submit an orphan to a witness that has closed the batch. Such a file is
    # explicitly rejected rather than silently dropped.
    seal = db.get_seal(batch_id)
    if seal is not None and db.get_file(batch_id, filename) is None:
        result.update(state="rejected",
                      reason="batch is sealed; file is outside the manifest")
        return result

    # Make sure the catalog has a pending row so the work is visible even if
    # the witness is currently unreachable.
    if db.get_file(batch_id, filename) is None:
        db.upsert_pending(batch_id, filename, target["length"],
                          target["sha256"], "recovered orphan: pending")

    try:
        info = witness.get_batch(batch_id)
    except WitnessUnreachable as exc:
        # Still unknown: keep pending, show "to be verified", never resubmit.
        db.set_error(batch_id, filename, f"witness unreachable: {exc}")
        result.update(state="pending", reason="witness_unreachable")
        return result

    match = next((it for it in info["items"]
                  if it["filename"] == filename), None)
    if match is None:
        # Witness explicitly says it never accepted this file. It is safe to
        # (re)submit exactly the locally stored original.
        path = storage_path(batch_id, filename)
        if not path.is_file():
            db.set_error(batch_id, filename,
                         "witness 404 and local original missing")
            result.update(state="pending",
                          reason="witness_404_and_local_missing")
            return result
        content = path.read_bytes()
        try:
            response = witness.submit(batch_id, filename, content,
                                      target["sha256"])
        except WitnessUnreachable as exc:
            db.set_error(batch_id, filename, f"witness unreachable: {exc}")
            result.update(state="pending", reason="witness_unreachable")
            return result
        except WitnessRefused as exc:
            detail = (exc.detail.get("error")
                      if isinstance(exc.detail, dict) else None)
            if detail == "batch_sealed":
                db.set_error(batch_id, filename,
                             "witness reports the batch is sealed")
                result.update(state="rejected", reason="witness_batch_sealed")
                return result
            raise
        envelope = response["receipt"]
    else:
        envelope = match["receipt"]

    ok, err = verify_envelope(
        public_key, envelope,
        expected={"batch_id": batch_id, "filename": filename,
                  "length": target["length"], "sha256": target["sha256"]},
    )
    if not ok:
        db.set_error(batch_id, filename, f"receipt verification failed: {err}")
        result.update(state="pending", reason=f"bad_receipt: {err}")
        return result

    db.mark_registered(batch_id, filename, target["length"],
                       target["sha256"],
                       json.dumps(envelope, sort_keys=True))
    result.update(state="registered",
                  reused=match is not None)
    return result


def reconcile_pending() -> dict:
    # Merge catalog-pending rows with on-disk orphans (crash before register),
    # keyed by (batch_id, filename) so nothing is processed twice.
    targets: dict[tuple[str, str], dict] = {}
    for row in db.list_pending():
        targets[(row["batch_id"], row["filename"])] = dict(row)
    for orphan in discover_orphans():
        targets.setdefault((orphan["batch_id"], orphan["filename"]), orphan)

    results = []
    for target in targets.values():
        with batch_lock(target["batch_id"]):
            # Re-read inside the lock: a concurrent upload may have finished.
            current = db.get_file(target["batch_id"], target["filename"])
            if current is not None and current["status"] == "registered":
                results.append({"batch_id": target["batch_id"],
                                "filename": target["filename"],
                                "state": "already_registered"})
                continue
            results.append(reconcile_one(target))
    return {"checked": len(results), "results": results}


@app.post("/api/reconcile")
def reconcile_endpoint():
    return reconcile_pending()


# --------------------------------------------------------------------------- #
# Seal recovery after restart
# --------------------------------------------------------------------------- #
def resume_seals() -> dict:
    """Resume every seal left in an unknown state (待核).

    A seal whose response was lost, or whose process exited between "asked the
    witness" and "stored the verified manifest", must be finished against the
    witness -- never assumed successful and never re-opened for new files.
    Runs in a background thread at startup so it never blocks uploads/queries.
    """
    results = []
    for seal in db.list_seals():
        batch_id = seal["batch_id"]
        if seal["state"] == "sealed":
            # Verify the committed seal is still internally consistent; mark
            # it unverified if it is not, so no download is offered.
            with batch_lock(batch_id):
                try:
                    ok, err = verify_stored_seal(seal, check_content=False)
                except SealNotReady as exc:
                    ok, err = False, exc.detail
                if not ok:
                    db.mark_seal_unverified(
                        batch_id, f"stored seal no longer verifies: {err}")
                    results.append({"batch_id": batch_id,
                                    "state": "unverified"})
            continue
        if seal["state"] != "sealing":
            continue
        with batch_lock(batch_id):
            try:
                response = seal_batch_now(batch_id)
                results.append({"batch_id": batch_id,
                                "state": response.status_code})
            except SealNotReady as exc:
                db.mark_seal_unverified(batch_id, exc.detail)
                results.append({"batch_id": batch_id, "state": "not_ready"})
            except Exception as exc:  # pragma: no cover - keep serving
                db.set_seal_error(batch_id, f"seal resume failed: {exc}")
                results.append({"batch_id": batch_id, "state": "error"})
    return {"checked": len(results), "results": results}


@app.post("/api/seals/resume")
def resume_seals_endpoint():
    return resume_seals()


# --------------------------------------------------------------------------- #
# Independent verification against the witness's issued-receipt list
# --------------------------------------------------------------------------- #
@app.get("/api/verify")
def verify_against_witness():
    try:
        listing = witness.list_receipts()
    except WitnessUnreachable as exc:
        # Witness unreachable: verification must NEVER be reported as passed.
        return JSONResponse(
            status_code=503,
            content={"passed": False, "witness_reachable": False,
                     "error": f"witness unreachable: {exc}", "batches": []},
        )

    batches: dict[str, dict] = {}
    for item in listing["items"]:
        batch_id, filename = item["batch_id"], item["filename"]
        problems: list[dict] = []

        # The full signed envelope travels with the listing; verify it
        # against the fixed public key (no extra witness round-trips).
        envelope_resp = item.get("receipt")
        sig_ok, sig_err = (False, "no receipt in witness listing")
        if envelope_resp is not None:
            sig_ok, sig_err = verify_envelope(public_key, envelope_resp)
        if not sig_ok:
            problems.append({"type": "receipt_signature_invalid",
                             "detail": sig_err})

        path = storage_path(batch_id, filename)
        if not path.is_file():
            problems.append({"type": "missing_original",
                             "detail": "witnessed file absent locally"})
            local_digest = local_length = None
        else:
            local_digest, local_length = sha256_file(path)
            if local_digest != item["sha256"] \
                    or local_length != item["length"]:
                problems.append({
                    "type": "tampered_original",
                    "detail": "local SHA-256/length differs from receipt",
                    "local_sha256": local_digest,
                    "receipt_sha256": item["sha256"],
                })

        catalog = db.get_file(batch_id, filename)
        if catalog is None:
            problems.append({"type": "catalog_missing",
                             "detail": "not registered in local catalog"})
        elif catalog["status"] != "registered":
            problems.append({"type": "catalog_pending",
                             "detail": f"catalog status is {catalog['status']}"})

        batches.setdefault(batch_id, {"batch_id": batch_id, "files": [],
                                      "passed": True})
        batches[batch_id]["files"].append({
            "filename": filename,
            "receipt": {"length": item["length"], "sha256": item["sha256"],
                        "issued_at": item["issued_at"]},
            "local": {"present": path.is_file(),
                      "length": local_length, "sha256": local_digest},
            "catalogued": catalog is not None,
            "receipt_signature_ok": sig_ok,
            "problems": problems,
        })
        if problems:
            batches[batch_id]["passed"] = False

    # An empty witness list is reported explicitly, not silently "passed":
    # there is nothing to verify, and callers must not read it as a clean bill.
    results = {
        "passed": all(b["passed"] for b in batches.values())
        and bool(batches),
        "empty": not batches,
        "witness_reachable": True,
        "receipt_count": listing["count"],
        "batches": sorted(batches.values(), key=lambda b: b["batch_id"]),
        "seals": [],
    }

    # Every locally sealed batch is cross-checked too: a seal that cannot be
    # re-verified, or that has no witness counterpart, fails verification.
    for seal in db.list_seals():
        batch_id = seal["batch_id"]
        entry = {"batch_id": batch_id, "state": seal["state"],
                 "passed": True, "problems": []}
        if seal["state"] == "sealed":
            try:
                ok, err = verify_stored_seal(
                    seal, check_content=False)
            except SealNotReady as exc:
                ok, err = False, exc.detail
            if not ok:
                entry["problems"].append({"type": "seal_invalid",
                                          "detail": err})
        else:
            entry["problems"].append({
                "type": "seal_unresolved",
                "detail": f"seal state is {seal['state']}; outcome 待核"})
        try:
            remote = witness.get_seal(batch_id)
        except WitnessUnreachable as exc:
            remote = None
            entry["problems"].append({
                "type": "seal_witness_unreachable", "detail": str(exc)})
        if remote is None:
            entry["problems"].append({
                "type": "seal_missing_at_witness",
                "detail": "no seal for this batch at the witness"})
        elif seal["state"] == "sealed":
            local_manifest = json.loads(seal["manifest_json"])
            if remote.get("payload_json") != seal["manifest_json"] or \
                    remote.get("signature") != seal["signature"]:
                entry["problems"].append({
                    "type": "seal_mismatch",
                    "detail": "local manifest differs from the witness seal"})
            if remote.get("manifest") and \
                    remote["manifest"].get("files") != \
                    local_manifest.get("files"):
                entry["problems"].append({
                    "type": "seal_mismatch",
                    "detail": "local manifest file list differs from witness"})
        if entry["problems"] and seal["state"] == "sealed":
            # A sealed batch that cannot be re-verified fails the whole check:
            # its files may still be individually intact, but the frozen list
            # is not provable.
            entry["passed"] = False
        if not entry["passed"]:
            results["passed"] = False
        results["seals"].append(entry)

    return results


# --------------------------------------------------------------------------- #
# Fault injection for the disconnect demo
# --------------------------------------------------------------------------- #
@app.post("/api/admin/arm-crash")
def arm_crash():
    CRASH_MARKER.parent.mkdir(parents=True, exist_ok=True)
    CRASH_MARKER.touch()
    return {"armed": True, "marker": str(CRASH_MARKER)}


@app.post("/api/admin/arm-seal-crash")
def arm_seal_crash():
    SEAL_CRASH_MARKER.parent.mkdir(parents=True, exist_ok=True)
    SEAL_CRASH_MARKER.touch()
    return {"armed": True, "marker": str(SEAL_CRASH_MARKER)}


@app.post("/api/admin/arm-seal-write-fail")
def arm_seal_write_fail():
    SEAL_FAIL_MARKER.parent.mkdir(parents=True, exist_ok=True)
    SEAL_FAIL_MARKER.touch()
    return {"armed": True, "marker": str(SEAL_FAIL_MARKER)}


@app.post("/__selftest_shutdown")
def selftest_shutdown():
    """Test-only graceful shutdown (no signal permissions in CI sandbox)."""
    def _stop():
        app.state.server.should_exit = True
    threading.Thread(target=_stop, daemon=True).start()
    return {"shutting_down": True}
