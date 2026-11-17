"""SQLite persistence for the archiver (the local catalog).

Each operation opens its own connection: with a single shared connection,
closing a read cursor rolls back any open write transaction on that same
connection. WAL mode keeps concurrent readers/writers working correctly.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id      TEXT NOT NULL,
    filename      TEXT NOT NULL,
    length        INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('pending','registered')),
    receipt       TEXT,
    last_error    TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(batch_id, filename)
);
CREATE INDEX IF NOT EXISTS idx_files_batch ON files(batch_id);

-- Sealing is a small state machine, committed in single statements so a
-- write failure can never leave a half-written, downloadable manifest:
--   sealing    -> intent recorded, outcome not yet known (blocks new files)
--   sealed     -> witness-signed manifest verified and stored (downloadable)
--   unverified -> witness answered but the manifest could not be accepted
--                 (never downloadable, never reported as success, retryable)
CREATE TABLE IF NOT EXISTS seals (
    batch_id               TEXT PRIMARY KEY,
    state                  TEXT NOT NULL
                           CHECK (state IN ('sealing','sealed','unverified')),
    file_count             INTEGER,
    files_json             TEXT NOT NULL,
    manifest_json          TEXT,
    signature              TEXT,
    algorithm              TEXT,
    public_key_fingerprint TEXT,
    sealed_at              TEXT,
    last_error             TEXT,
    created_at             TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at             TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Database:
    def __init__(self, path: str):
        self._path = path
        with self.cursor() as cur:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.executescript(SCHEMA)

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

    def get_file(self, batch_id: str, filename: str) -> sqlite3.Row | None:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM files WHERE batch_id=? AND filename=?",
                (batch_id, filename),
            )
            return cur.fetchone()

    def list_batch(self, batch_id: str) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM files WHERE batch_id=? ORDER BY filename",
                (batch_id,),
            )
            return cur.fetchall()

    def list_batches(self) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                """SELECT f.batch_id,
                          COUNT(*) AS file_count,
                          SUM(CASE WHEN f.status='registered' THEN 1 ELSE 0 END)
                              AS registered_count,
                          SUM(CASE WHEN f.status='pending' THEN 1 ELSE 0 END)
                              AS pending_count,
                          MIN(f.created_at) AS first_seen,
                          s.state AS seal_state,
                          s.sealed_at AS sealed_at
                   FROM files f LEFT JOIN seals s ON s.batch_id = f.batch_id
                   GROUP BY f.batch_id
                   ORDER BY MIN(f.created_at) DESC"""
            )
            return cur.fetchall()

    def list_pending(self) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM files WHERE status='pending' "
                "ORDER BY batch_id, filename"
            )
            return cur.fetchall()

    def upsert_pending(self, batch_id: str, filename: str,
                       length: int, sha256: str, error: str | None) -> None:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO files (batch_id, filename, length, sha256,
                                      status, last_error)
                   VALUES (?, ?, ?, ?, 'pending', ?)
                   ON CONFLICT(batch_id, filename) DO UPDATE SET
                       length=excluded.length, sha256=excluded.sha256,
                       last_error=excluded.last_error,
                       updated_at=datetime('now')""",
                (batch_id, filename, length, sha256, error),
            )

    def mark_registered(self, batch_id: str, filename: str,
                        length: int, sha256: str, receipt: str) -> None:
        # Upsert, not a bare UPDATE: a fresh upload may never have had a
        # pending row, and an UPDATE matching zero rows would silently drop
        # the registration.
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO files (batch_id, filename, length, sha256,
                                      status, receipt, last_error)
                   VALUES (?, ?, ?, ?, 'registered', ?, NULL)
                   ON CONFLICT(batch_id, filename) DO UPDATE SET
                       length=excluded.length, sha256=excluded.sha256,
                       status='registered', receipt=excluded.receipt,
                       last_error=NULL, updated_at=datetime('now')""",
                (batch_id, filename, length, sha256, receipt),
            )

    def set_error(self, batch_id: str, filename: str,
                  error: str) -> None:
        with self.cursor() as cur:
            cur.execute(
                """UPDATE files SET last_error=?,
                       updated_at=datetime('now')
                   WHERE batch_id=? AND filename=?""",
                (error, batch_id, filename),
            )

    # ------------------------------------------------------------------ #
    # Seals
    # ------------------------------------------------------------------ #
    def get_seal(self, batch_id: str) -> sqlite3.Row | None:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM seals WHERE batch_id=?", (batch_id,))
            return cur.fetchone()

    def list_seals(self) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM seals ORDER BY batch_id")
            return cur.fetchall()

    def list_sealed_batches(self) -> set[str]:
        with self.cursor() as cur:
            cur.execute("SELECT batch_id FROM seals")
            return {r["batch_id"] for r in cur.fetchall()}

    def begin_seal(self, batch_id: str, files_json: str) -> bool:
        """Atomically claim the right to seal.  False => already sealed."""
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO seals (batch_id, state, files_json)
                   VALUES (?, 'sealing', ?)
                   ON CONFLICT(batch_id) DO NOTHING""",
                (batch_id, files_json),
            )
            return cur.rowcount == 1

    def mark_sealed(self, batch_id: str, file_count: int, manifest_json: str,
                    signature: str, algorithm: str,
                    fingerprint: str, sealed_at: str) -> None:
        with self.cursor() as cur:
            cur.execute(
                """UPDATE seals SET state='sealed', file_count=?,
                       manifest_json=?, signature=?, algorithm=?,
                       public_key_fingerprint=?, sealed_at=?, last_error=NULL,
                       updated_at=datetime('now')
                   WHERE batch_id=?""",
                (file_count, manifest_json, signature, algorithm,
                 fingerprint, sealed_at, batch_id),
            )

    def set_seal_error(self, batch_id: str, error: str,
                       state: str | None = None) -> None:
        with self.cursor() as cur:
            if state is None:
                cur.execute(
                    """UPDATE seals SET last_error=?,
                           updated_at=datetime('now')
                       WHERE batch_id=?""",
                    (error, batch_id),
                )
            else:
                cur.execute(
                    """UPDATE seals SET state=?, last_error=?,
                           updated_at=datetime('now')
                       WHERE batch_id=?""",
                    (state, error, batch_id),
                )

    def mark_seal_unverified(self, batch_id: str, error: str) -> None:
        # The manifest bytes are deliberately kept: a seal that failed a
        # re-check (for example post-seal tampering, or a transient storage
        # error) must remain auditable and recoverable once the cause is
        # fixed. The row is not downloadable while state != 'sealed'.
        with self.cursor() as cur:
            cur.execute(
                """UPDATE seals SET state='unverified', last_error=?,
                       sealed_at=NULL, updated_at=datetime('now')
                   WHERE batch_id=?""",
                (error, batch_id),
            )

    def drop_seal_manifest(self, batch_id: str) -> None:
        """Discard an unverifiable manifest (e.g. it failed signature
        verification and must never be served or reused)."""
        with self.cursor() as cur:
            cur.execute(
                """UPDATE seals SET manifest_json=NULL, signature=NULL,
                       algorithm=NULL, public_key_fingerprint=NULL,
                       updated_at=datetime('now')
                   WHERE batch_id=?""",
                (batch_id,),
            )

    def close(self) -> None:
        # Connections are per-operation; nothing persistent to close.
        return None
