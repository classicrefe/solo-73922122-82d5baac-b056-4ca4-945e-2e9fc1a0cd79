"""SQLite persistence for the independent witness service.

Each operation opens its own connection: with a single shared connection,
closing a read cursor rolls back any open write transaction on that same
connection. WAL mode keeps concurrent readers/writers working correctly.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id    TEXT NOT NULL,
    filename    TEXT NOT NULL,
    length      INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    issued_at   TEXT NOT NULL,
    payload     TEXT NOT NULL,
    signature   TEXT NOT NULL,
    UNIQUE(batch_id, filename)
);
CREATE INDEX IF NOT EXISTS idx_receipts_batch ON receipts(batch_id);

CREATE TABLE IF NOT EXISTS seals (
    batch_id               TEXT PRIMARY KEY,
    payload_json           TEXT NOT NULL,
    signature              TEXT NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    sealed_at              TEXT NOT NULL,
    created_at             TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class SealActive(Exception):
    """The batch is sealed; no new original may be accepted."""

    def __init__(self, batch_id: str):
        super().__init__(f"batch {batch_id} is sealed")
        self.batch_id = batch_id


class ReceiptConflict(Exception):
    """A different original is already witnessed under this key."""

    def __init__(self, existing: dict):
        super().__init__("content conflict")
        self.existing = existing


class SealConflict(Exception):
    """A different manifest is already sealed for this batch."""

    def __init__(self, existing: dict):
        super().__init__("a different manifest is already sealed")
        self.existing = existing


class SealMismatch(Exception):
    """The requested manifest does not match the witness's receipts."""

    def __init__(self, detail: dict):
        super().__init__("manifest does not match witnessed receipts")
        self.detail = detail


def _envelope(row) -> dict:
    return {
        "payload_json": row["payload_json"],
        "signature": row["signature"],
        "algorithm": "Ed25519",
        "public_key_fingerprint": row["public_key_fingerprint"],
    }


class Database:
    def __init__(self, path: str):
        self._path = path
        with self.cursor() as cur:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @contextmanager
    def cursor(self):
        conn = sqlite3.connect(self._path, timeout=10)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

    def get(self, batch_id: str, filename: str) -> sqlite3.Row | None:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM receipts WHERE batch_id=? AND filename=?",
                (batch_id, filename),
            )
            return cur.fetchone()

    def insert(self, fields: dict) -> None:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO receipts
                   (batch_id, filename, length, sha256, issued_at,
                    payload, signature)
                   VALUES (:batch_id, :filename, :length, :sha256,
                           :issued_at, :payload, :signature)""",
                fields,
            )

    def accept_original(self, batch_id: str, filename: str, length: int,
                        sha256: str, fields: dict | None = None):
        """Atomically accept one original unless the batch is sealed.

        A write transaction (BEGIN IMMEDIATE) serializes this against sealing:
        either this receipt lands before the seal snapshot, or the seal is
        already committed and this upload is refused.  There is no window in
        which an accepted receipt can fall outside a seal while the witness
        also reports the batch as sealed.

        Returns ``(status, row)`` where status is "created" or "reused".
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM receipts WHERE batch_id=? AND filename=?",
                (batch_id, filename),
            ).fetchone()
            if existing is not None:
                # An already-witnessed original stays retrievable even after
                # the batch is sealed: same content reuses the same receipt.
                conn.execute("ROLLBACK")
                if existing["sha256"] == sha256 \
                        and existing["length"] == length:
                    return "reused", existing
                raise ReceiptConflict({"length": existing["length"],
                                       "sha256": existing["sha256"]})
            sealed = conn.execute(
                "SELECT 1 FROM seals WHERE batch_id=?", (batch_id,)
            ).fetchone()
            if sealed is not None:
                conn.execute("ROLLBACK")
                raise SealActive(batch_id)
            assert fields is not None
            conn.execute(
                """INSERT INTO receipts
                   (batch_id, filename, length, sha256, issued_at,
                    payload, signature)
                   VALUES (:batch_id, :filename, :length, :sha256,
                           :issued_at, :payload, :signature)""",
                fields,
            )
            row = conn.execute(
                "SELECT * FROM receipts WHERE batch_id=? AND filename=?",
                (batch_id, filename),
            ).fetchone()
            conn.execute("COMMIT")
            return "created", row
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # Seals
    # ------------------------------------------------------------------ #
    def get_seal(self, batch_id: str) -> sqlite3.Row | None:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM seals WHERE batch_id=?", (batch_id,))
            return cur.fetchone()

    def list_all_seals(self) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM seals ORDER BY batch_id")
            return cur.fetchall()

    def list_sealed_batch_ids(self) -> set[str]:
        with self.cursor() as cur:
            cur.execute("SELECT batch_id FROM seals")
            return {r["batch_id"] for r in cur.fetchall()}

    def seal_envelope(self, batch_id: str) -> dict | None:
        row = self.get_seal(batch_id)
        if row is None:
            return None
        return {
            "batch_id": row["batch_id"],
            **_envelope(row),
        }

    def seal_batch(self, batch_id: str, expected_files: list[dict] | None,
                   build_envelope):
        """Seal a batch atomically; idempotent for an identical file list.

        ``build_envelope(rows)`` must return (payload_json, signature,
        fingerprint, sealed_at) for the given receipt rows.  It runs while the
        write lock is held so no upload can slip in between snapshot and seal.

        Returns ``(status, envelope)`` where status is ``sealed`` or
        ``already_sealed``.  Raises SealActive if the batch was sealed by a
        concurrent request with a *different* file list.
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT * FROM receipts WHERE batch_id=? ORDER BY filename",
                (batch_id,),
            ).fetchall()
            if not rows:
                conn.execute("ROLLBACK")
                raise SealMismatch({"error": "empty_batch",
                                    "message": "batch has no witnessed files"})
            actual = [{"filename": r["filename"], "length": r["length"],
                       "sha256": r["sha256"]} for r in rows]
            if expected_files is not None and \
                    [{"filename": f["filename"],
                      "length": int(f["length"]),
                      "sha256": f["sha256"]} for f in expected_files] != actual:
                conn.execute("ROLLBACK")
                raise SealMismatch({
                    "error": "manifest_mismatch",
                    "message": "requested file list does not match the "
                               "witness's receipts",
                    "expected": actual,
                })
            existing = conn.execute(
                "SELECT * FROM seals WHERE batch_id=?", (batch_id,)
            ).fetchone()
            if existing is not None:
                # Already sealed: return the one and only manifest. Verify it
                # still covers exactly the witnessed receipts (uploads after
                # the seal are refused, so a mismatch means corruption).
                try:
                    signed = json.loads(existing["payload_json"])
                    signed_files = signed["files"]
                except (ValueError, KeyError, TypeError):
                    conn.execute("ROLLBACK")
                    raise SealMismatch({"error": "seal_unreadable",
                                        "message": "stored seal is unreadable"})
                conn.execute("ROLLBACK")
                if signed_files != actual:
                    raise SealMismatch({
                        "error": "seal_receipts_changed",
                        "message": "stored seal does not cover the current "
                                   "witnessed files",
                    })
                return "already_sealed", {
                    "batch_id": batch_id, **_envelope(existing)}
            payload_json, signature, fingerprint, sealed_at = \
                build_envelope(rows)
            conn.execute(
                """INSERT INTO seals
                   (batch_id, payload_json, signature,
                    public_key_fingerprint, sealed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (batch_id, payload_json, signature, fingerprint, sealed_at),
            )
            conn.execute("COMMIT")
            return "sealed", {
                "batch_id": batch_id,
                "payload_json": payload_json,
                "signature": signature,
                "algorithm": "Ed25519",
                "public_key_fingerprint": fingerprint,
            }
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_batch(self, batch_id: str) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM receipts WHERE batch_id=? ORDER BY filename",
                (batch_id,),
            )
            return cur.fetchall()

    def list_all(self) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM receipts ORDER BY batch_id, filename"
            )
            return cur.fetchall()

    def close(self) -> None:
        # Connections are per-operation; nothing persistent to close.
        return None
