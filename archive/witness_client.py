"""HTTP client for the independent witness service."""
from __future__ import annotations

from typing import Any

import httpx


class WitnessUnreachable(RuntimeError):
    """The witness cannot be reached; the request must NOT be retried blind."""


class WitnessRefused(RuntimeError):
    """The witness answered but explicitly refused the request (e.g. sealed).

    Unlike WitnessUnreachable, the outcome is known -- it is simply negative.
    """

    def __init__(self, status_code: int, detail: Any):
        super().__init__(f"witness refused with HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class WitnessTimeout(RuntimeError):
    """The request was sent but no response arrived: outcome unknown."""


class WitnessClient:
    def __init__(self, base_url: str, timeout: float = 5.0):
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=self._base, timeout=self._timeout)

    def health(self) -> dict[str, Any]:
        with self._client() as c:
            r = c.get("/health")
            r.raise_for_status()
            return r.json()

    def submit(self, batch_id: str, filename: str, content: bytes,
               sha256: str) -> dict[str, Any]:
        """Submit one original. Returns the witness envelope response."""
        try:
            with self._client() as c:
                r = c.post(
                    "/receipts",
                    data={"batch_id": batch_id, "filename": filename},
                    files={"file": (filename, content,
                                    "application/octet-stream")},
                )
        except httpx.ConnectError as exc:
            raise WitnessUnreachable(str(exc)) from exc
        except httpx.RequestError as exc:
            # Includes timeouts: the witness may have accepted the original.
            raise WitnessTimeout(str(exc)) from exc
        if r.status_code == 409:
            raise WitnessRefused(r.status_code, r.json())
        if r.status_code >= 400:
            raise WitnessRefused(r.status_code, r.text)
        return r.json()

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        try:
            with self._client() as c:
                r = c.get(f"/batches/{batch_id}")
        except httpx.RequestError as exc:
            raise WitnessUnreachable(str(exc)) from exc
        if r.status_code == 404:
            return {"batch_id": batch_id, "count": 0, "items": []}
        r.raise_for_status()
        return r.json()

    def list_receipts(self) -> dict[str, Any]:
        try:
            with self._client() as c:
                r = c.get("/receipts")
        except httpx.RequestError as exc:
            raise WitnessUnreachable(str(exc)) from exc
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------ #
    # Sealing
    # ------------------------------------------------------------------ #
    def seal_batch(self, batch_id: str, files: list[dict[str, Any]],
                   timeout: float | None = None) -> dict[str, Any]:
        """Ask the witness to sign the batch manifest.

        ``files`` is the exact, complete list the archiver has registered.
        The witness refuses if it disagrees, so an in-flight upload is either
        included or the seal fails loudly.

        Timeouts and unknown replies are ``WitnessTimeout``: the seal may
        exist and MUST be resolved by asking again, never assumed failed.
        ``WitnessRefused`` means the witness answered and said no.
        ``WitnessUnreachable`` means no connection could be made at all.
        """
        try:
            with self._client() as c:
                r = c.post("/seals", json={"batch_id": batch_id,
                                           "files": files},
                           timeout=timeout or self._timeout)
        except httpx.ConnectError as exc:
            raise WitnessUnreachable(str(exc)) from exc
        except httpx.RequestError as exc:
            # Includes timeouts: request may have reached the witness.
            raise WitnessTimeout(str(exc)) from exc
        if r.status_code >= 400:
            try:
                detail: Any = r.json()
            except ValueError:
                detail = r.text
            raise WitnessRefused(r.status_code, detail)
        return r.json()

    def get_seal(self, batch_id: str) -> dict[str, Any] | None:
        """Return the witness's seal for a batch, or None if it has none."""
        try:
            with self._client() as c:
                r = c.get(f"/seals/{batch_id}")
        except httpx.ConnectError as exc:
            raise WitnessUnreachable(str(exc)) from exc
        except httpx.RequestError as exc:
            raise WitnessUnreachable(str(exc)) from exc
        if r.status_code == 404:
            return None
        if r.status_code >= 400:
            raise WitnessRefused(r.status_code, r.text)
        return r.json().get("seal")
