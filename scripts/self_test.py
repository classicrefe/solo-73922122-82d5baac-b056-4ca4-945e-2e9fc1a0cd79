#!/usr/bin/env python3
"""End-to-end self test for the research data archive.

Spins up the real witness and archive uvicorn processes against temp
directories (stand-ins for the two Docker volumes) and exercises:

  1. health of both services
  2. normal upload: receipt issued, signature verifies, catalog + download
  3. idempotent re-upload (same batch/content reuses receipt, no duplication)
  4. different content under same key is rejected
  5. >2 MiB upload is refused
  6. concurrent double-window retries never double-archive, and distinct
     batches uploading in parallel each archive exactly once (no global lock)
  7. crash after witness acceptance -> restart -> automatic reconciliation
  7b. witness receipts and signatures survive a full restart (persistent
      volume), no data loss
  8. witness unreachable -> "pending/待核", never silently re-submitted
  9. verification page detects tampering, missing file, catalog omission
 10. forged receipts (foreign Ed25519 key) are rejected by the fixed key
 11. verification fails (503) while witness is down

Run:  python3 scripts/self_test.py
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
HOST = "127.0.0.1"


def free_port() -> int:
    """Pick an ephemeral free port (orphaned processes make fixed ports
    unsafe in sandboxes where kill(2) is blocked)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sk:
        sk.bind((HOST, 0))
        return sk.getsockname()[1]


PORT_W = free_port()
PORT_A = free_port()
PORT_A_ISOLATED = free_port()
PORT_W_FAULT = free_port()
PORT_A_FAULT = free_port()

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail else ""))


def wait_port(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def wait_down(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=1):
                time.sleep(0.3)
        except OSError:
            return True
    return False


def req(method: str, port: int, path: str, body=None, headers=None):
    conn = http.client.HTTPConnection(HOST, port, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        return resp.status, json.loads(raw.decode())
    except json.JSONDecodeError:
        return resp.status, raw


def multipart(fields: dict[str, str], file_field: str, filename: str,
              content: bytes) -> tuple[bytes, dict]:
    boundary = "----selftest" + uuid.uuid4().hex
    lines = []
    for name, value in fields.items():
        lines.append(f"--{boundary}\r\n".encode())
        lines.append(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        lines.append(value.encode() + b"\r\n")
    lines.append(f"--{boundary}\r\n".encode())
    lines.append(
        f'Content-Disposition: form-data; name="{file_field}"; '
        f'filename="{filename}"\r\n'.encode())
    lines.append(b"Content-Type: application/octet-stream\r\n\r\n")
    lines.append(content + b"\r\n")
    lines.append(f"--{boundary}--\r\n".encode())
    return b"".join(lines), {"Content-Type": f"multipart/form-data; "
                                             f"boundary={boundary}"}


def upload(port: int, batch: str, filename: str, content: bytes):
    body, headers = multipart(
        {"filename": filename}, "file", filename, content)
    return req("POST", port,
               f"/api/batches/{batch}/files", body, headers)


class Harness:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="archive-selftest-"))
        self.keys = self.tmp / "keys"
        self.wdata = self.tmp / "witness"
        self.adata = self.tmp / "archive"
        for d in (self.keys, self.wdata, self.adata):
            d.mkdir(parents=True)
        self.procs: list[subprocess.Popen] = []

    def gen_keys(self):
        priv = self.keys / "witness_ed25519.pem"
        pub = self.keys / "witness_ed25519.pub.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                        "-out", str(priv)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout",
                        "-out", str(pub)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start_witness(self, port=None, data_dir=None, extra_env=None):
        port = port or PORT_W
        data_dir = data_dir or self.wdata
        env = os.environ.copy()
        env.update({"WITNESS_DB": str(data_dir / "witness.db"),
                    "WITNESS_KEY": str(self.keys / "witness_ed25519.pem")})
        env.update(extra_env or {})
        p = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "witness.main:app",
             "--host", HOST, "--port", str(port)],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append((p, port, "/__selftest_shutdown"))
        return p

    def archive_env(self, port=PORT_A, witness_port=PORT_W,
                    crash_marker: Path | None = None, extra_env=None,
                    data_dir: Path | None = None):
        env = {
            "ARCHIVE_DB": str((data_dir or self.adata)
                              / f"archive-{port}.db"),
            "ARCHIVE_STORAGE": str((data_dir or self.adata)
                                   / f"originals-{port}"),
            "ARCHIVE_PUBLIC_KEY":
                str(self.keys / "witness_ed25519.pub.pem"),
            "WITNESS_URL": f"http://{HOST}:{witness_port}",
            "ARCHIVE_CRASH_MARKER": str(
                crash_marker or (self.adata / f"crash-{port}.flag")),
            "ARCHIVE_SEAL_CRASH_MARKER": str(
                self.adata / f"seal-crash-{port}.flag"),
            "ARCHIVE_SEAL_FAIL_MARKER": str(
                self.adata / f"seal-fail-{port}.flag"),
        }
        env.update(extra_env or {})
        return env

    def start_archive(self, port=PORT_A, witness_port=PORT_W,
                      crash_marker: Path | None = None, extra_env=None,
                      wait=True, data_dir: Path | None = None):
        env = os.environ.copy()
        env.update(self.archive_env(port, witness_port, crash_marker,
                                    extra_env, data_dir))
        p = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "archive.main:app",
             "--host", HOST, "--port", str(port)],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append((p, port, "/__selftest_shutdown"))
        if wait:
            wait_port(port)
        return p

    def shutdown_port(self, port: int) -> None:
        """Graceful shutdown through the test-only HTTP endpoint."""
        try:
            req("POST", port, "/__selftest_shutdown")
        except OSError:
            pass

    def cleanup(self):
        # Signals are blocked in this CI sandbox; stop via HTTP instead.
        for _, port, path in list(self.procs):
            try:
                req("POST", port, path)
            except OSError:
                pass
        deadline = time.time() + 8
        while time.time() < deadline:
            alive = [p for p, _, _ in self.procs if p.poll() is None]
            if not alive:
                break
            time.sleep(0.3)
        shutil.rmtree(self.tmp, ignore_errors=True)


def main() -> int:
    h = Harness()
    try:
        h.gen_keys()
        h.start_witness()
        h.start_archive()
        if not wait_port(PORT_W) or not wait_port(PORT_A):
            check("services start", False, "ports never came up")
            return 1
        check("services start", True,
              f"witness:{PORT_W} archive:{PORT_A}")

        # 1. health
        s, w = req("GET", PORT_W, "/health")
        check("witness health + key fingerprint",
              s == 200 and len(w["public_key_fingerprint"]) == 64)
        s, a = req("GET", PORT_A, "/api/batches")
        check("archive health endpoint", s == 200)

        # 1b. empty witness list must not be reported as "passed"
        s, empty_report = req("GET", PORT_A, "/api/verify")
        check("empty witness list is not a silent pass",
              s == 200 and empty_report["passed"] is False
              and empty_report["empty"] is True
              and empty_report["witness_reachable"] is True)

        # 2. normal upload
        b1 = "BATCH-001"
        content = b"site,temp_c,ph\nA,21.4,7.1\nB,19.8,6.8\n"
        s, r = upload(PORT_A, b1, "readings.csv", content)
        ok = (s == 200 and r["result"] == "registered"
              and r["batch"]["status"] == "complete"
              and r["batch"]["files"][0]["receipt"]["algorithm"] == "Ed25519")
        check("normal upload registers with Ed25519 receipt", ok,
              f"http={s}")
        s, dl = req("GET", PORT_A,
                     f"/api/batches/{b1}/download/readings.csv")
        check("download open only after full success",
              s == 200 and dl == content)
        s, witness_list = req("GET", PORT_W, "/receipts")
        check("witness independently persisted length+SHA256",
              s == 200 and witness_list["count"] == 1
              and witness_list["items"][0]["length"] == len(content))

        # 3. idempotent re-upload
        s, r = upload(PORT_A, b1, "readings.csv", content)
        check("same batch+content reuses receipt (idempotent)",
              s == 200 and r["result"] == "already_registered")
        s, witness_list = req("GET", PORT_W, "/receipts")
        check("idempotent retry creates no duplicate witness record",
              witness_list["count"] == 1)

        # 4. conflicting content rejected
        s, r = upload(PORT_A, b1, "readings.csv", content + b"TAMPERED\n")
        check("different content under same key rejected (409)",
              s == 409, str(r)[:120])
        s, dl = req("GET", PORT_A,
                     f"/api/batches/{b1}/download/readings.csv")
        check("rejected conflict leaves witnessed original intact",
              s == 200 and dl == content)

        # 5. size limit
        big = b"x" * (2 * 1024 * 1024 + 1)
        s, r = upload(PORT_A, "BATCH-BIG", "big.bin", big)
        check(">2 MiB upload refused", s == 413, f"http={s}")
        s, witness_list = req("GET", PORT_W, "/receipts")
        check("oversized file never reached witness",
              all(it["batch_id"] != "BATCH-BIG"
                  for it in witness_list["items"]))

        # 6. concurrent double-window retries
        b2 = "BATCH-CONC"
        c2 = b"concurrent-window-content-" + uuid.uuid4().hex.encode()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(upload, PORT_A, b2, "data.txt", c2)
                    for _ in range(2)]
            responses = [f.result() for f in futs]
        statuses = sorted(s for s, _ in responses)
        s, witness_list = req("GET", PORT_W, "/receipts")
        dupes = [it for it in witness_list["items"]
                 if it["batch_id"] == b2 and it["filename"] == "data.txt"]
        s, batch = req("GET", PORT_A, f"/api/batches/{b2}")
        check("concurrent retries: no double archive",
              len(dupes) == 1 and batch["file_count"] == 1
              and batch["status"] == "complete",
              f"http statuses={statuses}")

        # 6b. distinct batches in parallel: no global lock, each independent
        import concurrent.futures as cf
        cross = [(f"BATCH-X{i}", f"f{i}.csv",
                  b"cross-batch-" + uuid.uuid4().hex.encode())
                 for i in range(4)]
        with cf.ThreadPoolExecutor(max_workers=4) as ex:
            cross_resp = list(ex.map(
                lambda args: upload(PORT_A, *args), cross))
        cross_ok = all(s == 200 and r["result"] == "registered"
                       for s, r in cross_resp)
        cross_names = {b for b, _, _ in cross}
        s, witness_list = req("GET", PORT_W, "/receipts")
        cross_records = {b: 0 for b in cross_names}
        for it in witness_list["items"]:
            if it["batch_id"] in cross_records:
                cross_records[it["batch_id"]] += 1
        check("parallel distinct batches each archive exactly once",
              cross_ok and all(v == 1 for v in cross_records.values())
              and len(cross_records) == 4,
              f"records={cross_records}")

        # 7. crash after acceptance, restart, reconcile
        b3 = "BATCH-CRASH"
        c3 = b"crash-recovery-content"
        # Arm through the admin API (marker lives in the archive volume).
        s, r = req("POST", PORT_A, "/api/admin/arm-crash")
        armed = s == 200 and r["armed"]
        check("crash marker armed", armed)
        try:
            s, r = upload(PORT_A, b3, "f.csv", c3)
            crash_detail = f"http={s}"
        except OSError as exc:
            # The process exits mid-request; the connection dying is expected.
            crash_detail = f"connection reset as expected ({exc.__class__.__name__})"
        check("upload attempted across crash point", True, crash_detail)
        check("archive process actually exited",
              wait_down(PORT_A, 10), f"port {PORT_A} closed")
        # Restart with identical env (simulates Docker restart policy).
        restart_env = os.environ.copy()
        restart_env.update(h.archive_env(PORT_A, PORT_W))
        p2 = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "archive.main:app",
             "--host", HOST, "--port", str(PORT_A)],
            cwd=ROOT, env=restart_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        h.procs.append((p2, PORT_A, "/__selftest_shutdown"))
        check("archive restarts and reconnects", wait_port(PORT_A))
        # Startup reconciliation must query the witness and finish the batch.
        deadline = time.time() + 15
        batch = {}
        while time.time() < deadline:
            s, batch = req("GET", PORT_A, f"/api/batches/{b3}")
            if batch.get("status") == "complete":
                break
            time.sleep(0.5)
        check("restart auto-reconciles batch from witness receipt",
              batch.get("status") == "complete",
              f"status={batch.get('status')}")
        s, dl = req("GET", PORT_A,
                     f"/api/batches/{b3}/download/f.csv")
        check("reconciled original downloadable and byte-identical",
              s == 200 and dl == c3)
        s, witness_list = req("GET", PORT_W, "/receipts")
        check("reconciliation did not re-submit (no duplicate)",
              len([it for it in witness_list["items"]
                   if it["batch_id"] == b3]) == 1)

        # 7b. witness volume survives a full restart (persistent storage)
        persisted_count = witness_list["count"]
        h.shutdown_port(PORT_W)
        check("witness stopped for restart-persistence test",
              wait_down(PORT_W, 10))
        wp = h.start_witness()  # same WITNESS_DB path -> same volume
        check("witness restarts on its persistent volume", wait_port(PORT_W))
        s, after = req("GET", PORT_W, "/receipts")
        check("witness receipts survive restart (persistent volume)",
              s == 200 and after["count"] == persisted_count
              and persisted_count >= 1,
              f"before={persisted_count} after={after['count']}")
        # A stored receipt must still verify after the restart.
        from common.receipt import verify_envelope as _ve, \
            load_public_key as _lpk
        any_env = after["items"][0]["receipt"]
        ok_sig, _ = _ve(_lpk(h.keys / "witness_ed25519.pub.pem"), any_env)
        check("stored receipt signature still valid after restart", ok_sig)

        # 8. witness unreachable -> pending, not blind re-submit
        isolated_marker = h.adata / "crash-iso.flag"
        h.start_archive(port=PORT_A_ISOLATED, witness_port=8999,
                        crash_marker=isolated_marker)
        wait_port(PORT_A_ISOLATED)
        b4 = "BATCH-DISCONNECT"
        c4 = b"offline-buffer-content"
        s, r = upload(PORT_A_ISOLATED, b4, "g.csv", c4)
        check("witness unreachable => 202 pending (待核)",
              s == 202 and r["result"] == "pending"
              and r["reason"] == "witness_unreachable", f"http={s}")
        s, batch = req("GET", PORT_A_ISOLATED, f"/api/batches/{b4}")
        check("pending batch not reported complete / download closed",
              batch["status"] == "pending"
              and batch["files"][0]["status"] == "pending")
        s, _ = req("GET", PORT_A_ISOLATED,
                    f"/api/batches/{b4}/download/g.csv")
        check("download refused while pending", s in (404, 409))
        s, r = req("POST", PORT_A_ISOLATED, "/api/reconcile")
        check("reconcile while witness down keeps pending, never resubmits",
              s == 200 and r["results"][0]["state"] == "pending"
              and r["results"][0]["reason"] == "witness_unreachable")
        s, witness_list = req("GET", PORT_W, "/receipts")
        check("witness still has no record of disconnected batch",
              all(it["batch_id"] != b4 for it in witness_list["items"]))

        # 8b. seal against an unreachable witness -> 503, never success; then
        # the archive comes back up (same volumes) and confirms 待核, keeps the
        # batch closed, and resumes to the SAME single manifest.
        # A separate witness and archive volume keep these faults from
        # polluting the main verification checks below.
        fault_wdata = h.tmp / "faultwitness"
        fault_wdata.mkdir()
        h.start_witness(port=PORT_W_FAULT, data_dir=fault_wdata)
        check("isolated witness for seal fault tests", wait_port(PORT_W_FAULT))
        fault_dir = h.tmp / "faultarchive"
        fault_dir.mkdir()
        h.start_archive(port=PORT_A_FAULT, witness_port=PORT_W_FAULT, wait=True,
                        data_dir=fault_dir)
        b10 = "BATCH-SEAL-OFFLINE"
        upload(PORT_A_FAULT, b10, "o.csv", b"offline-seal\n")
        h.shutdown_port(PORT_W_FAULT)
        check("witness down for seal-outage test", wait_down(PORT_W_FAULT, 10))
        s, r = req("POST", PORT_A_FAULT, f"/api/batches/{b10}/seal")
        check("seal while witness is down is 503, not success",
              s == 503 and r.get("seal") is None, f"http={s}")
        s, st = req("GET", PORT_A_FAULT, f"/api/batches/{b10}")
        check("unresolved seal keeps batch closed and not successful",
              st["status"] == "seal_pending"
              and st["seal_state"] == "sealing", st["status"])
        s, r = upload(PORT_A_FAULT, b10, "late-offline.csv", b"late\n")
        check("unresolved seal still refuses new files (no re-open)",
              s == 409, str(r)[:120])
        s, _ = req("GET", PORT_A_FAULT,
                    f"/api/batches/{b10}/seal/download")
        check("no manifest is downloadable while the seal is unresolved",
              s == 404)
        # Witness returns; retry the same operation.
        h.start_witness(port=PORT_W_FAULT, data_dir=fault_wdata)
        check("witness restarted for seal resume", wait_port(PORT_W_FAULT))
        s, r = req("POST", PORT_A_FAULT, f"/api/batches/{b10}/seal/retry")
        check("retry after witness returns completes the seal",
              s in (200, 201) and r.get("seal") is not None, f"http={s}")
        sig_offline = r["seal"]["signature"]
        s, wseals = req("GET", PORT_W_FAULT, "/seals")
        same = [x for x in wseals["items"] if x["batch_id"] == b10]
        check("offline seal retry produced exactly one manifest",
              len(same) == 1 and same[0]["signature"] == sig_offline)
        # Files uploaded to the resolved batch are permanently closed.
        s, _ = upload(PORT_A_FAULT, b10, "late2.csv", b"late2\n")
        check("sealed batch stays closed after resumed seal", s == 409)

        # 8c. local seal write failure: no downloadable half manifest, the
        # batch is not reported successful, and the operation is retryable.
        b11 = "BATCH-SEAL-WRITEFAIL"
        upload(PORT_A_FAULT, b11, "w.csv", b"write-fail\n")
        s, _ = req("POST", PORT_A_FAULT, "/api/admin/arm-seal-write-fail")
        s, r = req("POST", PORT_A_FAULT, f"/api/batches/{b11}/seal")
        check("local seal write failure is reported as not sealed",
              s in (502, 503) and r.get("seal") is None, f"http={s}")
        s, dl = req("GET", PORT_A_FAULT,
                    f"/api/batches/{b11}/seal/download")
        check("write failure leaves no downloadable half manifest", s == 404)
        s, st = req("GET", PORT_A_FAULT, f"/api/batches/{b11}")
        check("write failure is never reported as sealed",
              st["sealed"] is False and st["status"] in
              ("seal_failed", "seal_pending"), json.dumps(st)[:300])
        s, r = upload(PORT_A_FAULT, b11, "w2.csv", b"write-fail-2\n")
        check("write failure does not re-open the batch for new files",
              s == 409, str(r)[:120])
        s, dl_orig = req("GET", PORT_A_FAULT,
                         f"/api/batches/{b11}/download/w.csv")
        check("unsealed-but-committed batch still serves its witnessed file",
              s == 200 and dl_orig == b"write-fail\n")
        s, r = req("POST", PORT_A_FAULT,
                    f"/api/batches/{b11}/seal/retry")
        check("uncommitted seal is retryable and completes",
              s in (200, 201) and r.get("seal") is not None, f"http={s}")
        # The retry must reuse the manifest the witness already holds.
        s, wseals = req("GET", PORT_W_FAULT, "/seals")
        same = [x for x in wseals["items"] if x["batch_id"] == b11]
        check("seal retry after write failure reuses one manifest",
              len(same) == 1
              and same[0]["signature"] == r["seal"]["signature"])
        s, dl = req("GET", PORT_A_FAULT,
                    f"/api/batches/{b11}/seal/download")
        check("retried seal becomes downloadable", s == 200)

        # 8d. witness accepts + signs the seal, but the response is lost (the
        # archive times out). Outcome is unknown: 202 / 待核, never success,
        # never re-opened; a resume asks the witness and adopts the SAME
        # manifest instead of creating a second one.
        h.shutdown_port(PORT_A_FAULT)
        h.shutdown_port(PORT_W_FAULT)
        check("fault services stopped for timeout test",
              wait_down(PORT_A_FAULT, 10) and wait_down(PORT_W_FAULT, 10))
        timeout_wdata = h.tmp / "timeoutwitness"
        timeout_wdata.mkdir()
        h.start_witness(port=PORT_W_FAULT, data_dir=timeout_wdata,
                        extra_env={"WITNESS_SEAL_DELAY_SECONDS": "2.5"})
        check("witness with delayed seal response is up",
              wait_port(PORT_W_FAULT))
        timeout_adata = h.tmp / "timeoutarchive"
        timeout_adata.mkdir()
        h.start_archive(port=PORT_A_FAULT, witness_port=PORT_W_FAULT,
                        data_dir=timeout_adata,
                        extra_env={"ARCHIVE_SEAL_TIMEOUT": "1"})
        b12 = "BATCH-SEAL-TIMEOUT"
        upload(PORT_A_FAULT, b12, "t.csv", b"timeout-seal\n")
        s, r = req("POST", PORT_A_FAULT, f"/api/batches/{b12}/seal")
        check("lost seal response => 202 待核, never success",
              s == 202 and r.get("seal") is None
              and r["batch"]["status"] == "seal_pending", f"http={s}")
        s, st = req("GET", PORT_A_FAULT, f"/api/batches/{b12}")
        check("lost seal response keeps the batch closed",
              st["status"] == "seal_pending"
              and st["seal_state"] == "sealing"
              and st["sealed"] is False, st["status"])
        s, _ = req("GET", PORT_A_FAULT,
                    f"/api/batches/{b12}/seal/download")
        check("no manifest is served while the seal outcome is unknown",
              s == 404)
        s, _ = upload(PORT_A_FAULT, b12, "late-timeout.csv", b"late\n")
        check("unknown-outcome seal refuses new files", s == 409)
        time.sleep(3.0)  # let the (already requested) witness seal commit
        s, wseals = req("GET", PORT_W_FAULT, "/seals")
        pre = [x for x in wseals["items"] if x["batch_id"] == b12]
        check("witness did commit a seal whose response was lost",
              len(pre) == 1)
        s, r = req("POST", PORT_A_FAULT, "/api/seals/resume")
        check("resume adopts the witness's existing manifest (no second seal)",
              s == 200
              and r["results"][0]["state"] in (200, 201), str(r)[:120])
        s, st = req("GET", PORT_A_FAULT, f"/api/batches/{b12}/seal")
        check("resumed seal reports sealed with a downloadable manifest",
              st.get("sealed") is True and st.get("download_url"), str(st)[:160])
        s, dl = req("GET", PORT_A_FAULT,
                    f"/api/batches/{b12}/seal/download")
        check("resumed manifest matches the witness's signature",
              s == 200 and dl["signature"] == pre[0]["signature"])
        s, wseals = req("GET", PORT_W_FAULT, "/seals")
        after = [x for x in wseals["items"] if x["batch_id"] == b12]
        check("resume created no duplicate manifest at the witness",
              len(after) == 1 and after[0]["signature"] == pre[0]["signature"])

        # 8e. upload/seal interleaving on the normal services: for each racing
        # batch, the witness must never hold a receipt outside the signed
        # manifest, whichever side wins.
        import threading as _th
        interleave_ok = True
        interleave_detail = []
        for i in range(3):
            bi = f"BATCH-SEAL-RACE-{i}"
            barrier = _th.Barrier(4)
            ups = []

            def _up(idx):
                barrier.wait()
                code, resp = upload(PORT_A, bi, f"r{idx}.csv",
                                    f"race-{i}-{idx}\n".encode())
                ups.append((f"r{idx}.csv", code))
            threads = [_th.Thread(target=_up, args=(j,)) for j in range(3)]
            for t in threads:
                t.start()
            barrier.wait()
            seal_res = req("POST", PORT_A, f"/api/batches/{bi}/seal")
            for t in threads:
                t.join()
            # An in-flight (still registering) file makes sealing refuse;
            # retry once every upload has settled.
            if seal_res[0] not in (200, 201):
                seal_res = req("POST", PORT_A,
                               f"/api/batches/{bi}/seal")
            s, st = req("GET", PORT_A, f"/api/batches/{bi}/seal")
            s, wl = req("GET", PORT_W, "/receipts")
            wfiles = {it["filename"] for it in wl["items"]
                      if it["batch_id"] == bi}
            mfiles = ({f["filename"] for f in st["manifest"]["files"]}
                      if st.get("manifest") else set())
            # Invariants: every upload was either accepted (status 200) or
            # explicitly rejected (409) -- nothing silently dropped; the
            # witness holds no receipt outside the manifest; the manifest is a
            # non-empty subset of the witnessed files; and every accepted
            # upload is inside the manifest.
            accepted = [fn for fn, code in ups if code == 200]
            rejected = [fn for fn, code in ups if code == 409]
            ok = (seal_res[0] in (200, 201) and st.get("sealed") is True
                  and wfiles and wfiles == mfiles
                  and mfiles.issubset(wfiles) and set(accepted) == mfiles
                  and len(ups) == 3
                  and len(accepted) + len(rejected) == 3)
            if not ok:
                interleave_ok = False
                interleave_detail.append(
                    (bi, seal_res[0], sorted(wfiles), sorted(mfiles),
                     sorted(accepted), rejected, st.get("status"),
                     st.get("seal_state"), st.get("last_error")))
        check("interleaved uploads are included in or rejected outside the "
              "manifest (no stray witness record)",
              interleave_ok, str(interleave_detail)[:300])

        # 9. verification against the witness's issued list
        s, report = req("GET", PORT_A, "/api/verify")
        check("clean verification passes from witness list",
              s == 200 and report["passed"] is True
              and report["witness_reachable"] is True,
              f"receipts={report.get('receipt_count')}")

        # 9a. tamper a stored original
        target = (h.adata / f"originals-{PORT_A}" / b1 / "readings.csv")
        original_bytes = target.read_bytes()
        target.write_bytes(original_bytes + b"EXTRA")
        s, report = req("GET", PORT_A, "/api/verify")
        problems = [p["type"] for f in report["batches"][0]["files"]
                    for p in f["problems"]]
        check("verification detects tampered original",
              not report["passed"] and "tampered_original" in problems,
              str(problems))
        target.write_bytes(original_bytes)  # restore

        # 9b. remove a local original (missing file)
        target = (h.adata / f"originals-{PORT_A}" / b2 / "data.txt")
        saved = target.read_bytes()
        target.unlink()
        s, report = req("GET", PORT_A, "/api/verify")
        problems = [p["type"] for b in report["batches"] for f in b["files"]
                    for p in f["problems"]]
        check("verification detects missing original",
              "missing_original" in problems)
        target.write_bytes(saved)  # restore

        # 9c. catalog omission: keep original+witness receipt, drop catalog row
        import sqlite3
        db_path = h.adata / f"archive-{PORT_A}.db"
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM files WHERE batch_id=? AND filename=?",
                     (b2, "data.txt"))
        conn.commit()
        conn.close()
        s, report = req("GET", PORT_A, "/api/verify")
        problems = [p["type"] for b in report["batches"] for f in b["files"]
                    for p in f["problems"]]
        check("verification detects catalog omission (目录漏登)",
              "catalog_missing" in problems)

        # 9d. a forged receipt (attacker's own Ed25519 key) must not verify
        # against the fixed public key pinned in the archiver.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey)
        from common.receipt import (
            build_envelope, load_private_key, load_public_key,
            verify_envelope)
        fixed_pub = load_public_key(h.keys / "witness_ed25519.pub.pem")
        forged = build_envelope(Ed25519PrivateKey.generate(),
                                b1, "readings.csv", len(content),
                                "0" * 64)
        ok_forge, err_forge = verify_envelope(fixed_pub, forged)
        check("forged receipt from foreign key rejected",
              ok_forge is False, err_forge or "")
        genuine = build_envelope(
            load_private_key(h.keys / "witness_ed25519.pem"),
            b1, "readings.csv", len(content), "0" * 64)
        ok_real, _ = verify_envelope(fixed_pub, genuine)
        check("genuine witness receipt verifies against fixed key",
              ok_real is True)

        # 9e. batch sealing --------------------------------------------------
        # Two files, then seal. The manifest must be witness-signed, cover
        # exactly the registered files, and be independently verifiable.
        b5 = "BATCH-SEAL"
        cf1 = b"alpha,1\n"
        cf2 = b"beta,2\n"
        s, _ = upload(PORT_A, b5, "a.csv", cf1)
        s2, _ = upload(PORT_A, b5, "b.csv", cf2)
        s, r = req("POST", PORT_A, f"/api/batches/{b5}/seal")
        seal = r.get("seal") or {}
        check("seal succeeds only after every file is registered",
              s == 201 and r["batch"]["status"] == "sealed"
              and s2 == 200, f"http={s}")
        check("seal manifest covers batch id + name/length/SHA-256 of all files",
              seal.get("batch_id") == b5
              and len(seal.get("manifest", {}).get("files", [])) == 2
              and {f["filename"] for f in seal["manifest"]["files"]} ==
              {"a.csv", "b.csv"}
              and all(set(f) == {"filename", "length", "sha256"}
                      for f in seal["manifest"]["files"]),
              str(seal.get("manifest"))[:160])
        from common.receipt import (
            verify_manifest_envelope, public_key_fingerprint as _pkf)
        ok_seal, err_seal = verify_manifest_envelope(
            fixed_pub,
            {"payload_json": seal.get("payload_json", ""),
             "signature": seal.get("signature", ""),
             "algorithm": seal.get("algorithm", ""),
             "public_key_fingerprint": seal.get(
                 "public_key_fingerprint", "")},
            expected_batch_id=b5,
            expected_files=seal["manifest"]["files"])
        check("seal manifest verifies with the fixed public key",
              ok_seal is True, err_seal or "")
        check("witness seal fingerprint matches the pinned key",
              seal.get("public_key_fingerprint") ==
              _pkf(fixed_pub))

        # A new file after sealing is permanently refused and leaves no
        # witness record outside the manifest.
        intruder = b"late,3\n"
        s, r = upload(PORT_A, b5, "late.csv", intruder)
        check("new file after sealing is refused (409)", s == 409, str(r)[:120])
        s, wl = req("GET", PORT_W, "/receipts")
        outside = [it for it in wl["items"]
                   if it["batch_id"] == b5 and
                   it["filename"] not in {"a.csv", "b.csv"}]
        check("refused late file left no witness record outside the manifest",
              outside == [])
        # Re-uploading an already-received identical original still works and
        # reuses the original receipt.
        s, r = upload(PORT_A, b5, "a.csv", cf1)
        check("identical re-upload after seal reuses the original receipt",
              s == 200 and r.get("result") == "already_registered"
              and r["batch"]["status"] == "sealed", str(r)[:120])
        # Repeating the seal returns the SAME one manifest (no second copy).
        s, r2 = req("POST", PORT_A, f"/api/batches/{b5}/seal")
        check("repeated seal returns the one existing manifest",
              s == 200 and r2["seal"]["signature"] == seal["signature"])
        # Manifest download is available and carries the exact signed payload.
        s, dl_seal = req("GET", PORT_A, f"/api/batches/{b5}/seal/download")
        check("sealed manifest is downloadable as a signed document",
              s == 200 and isinstance(dl_seal, dict)
              and dl_seal["signature"] == seal["signature"]
              and dl_seal["manifest"]["batch_id"] == b5)
        # No duplicate seals at the witness either.
        s, wseals = req("GET", PORT_W, "/seals")
        check("exactly one seal exists at the witness",
              sum(1 for it in wseals["items"] if it["batch_id"] == b5) == 1)

        # A seal with an unregistered (in-flight) file must be refused.
        b6 = "BATCH-SEAL-PARTIAL"
        h.start_archive(port=PORT_A_ISOLATED, witness_port=8999,
                        crash_marker=h.adata / "crash-iso.flag")
        wait_port(PORT_A_ISOLATED)
        s, _ = upload(PORT_A_ISOLATED, b6, "p.csv", b"partial\n")
        s, r = req("POST", PORT_A_ISOLATED, f"/api/batches/{b6}/seal")
        check("cannot seal a batch with a pending (在途) file",
              s == 409 and r.get("error") == "not_ready", f"http={s}")

        # Double-window duplicate seal: two concurrent seals -> one manifest.
        b7 = "BATCH-SEAL-CONC"
        upload(PORT_A, b7, "c1.csv", b"c1\n")
        upload(PORT_A, b7, "c2.csv", b"c2\n")
        import concurrent.futures as _cf
        with _cf.ThreadPoolExecutor(max_workers=2) as ex:
            seal_futs = [ex.submit(req, "POST", PORT_A,
                                   f"/api/batches/{b7}/seal")
                         for _ in range(2)]
            seal_res = [f.result() for f in seal_futs]
        sigs = {r["seal"]["signature"] for s, r in seal_res
                if isinstance(r, dict) and r.get("seal")}
        ok_codes = all(s in (200, 201) for s, _ in seal_res)
        s, wseals = req("GET", PORT_W, "/seals")
        witness_seals = [x for x in wseals["items"] if x["batch_id"] == b7]
        check("double-window duplicate seal produces one manifest",
              ok_codes and len(sigs) == 1 and len(witness_seals) == 1,
              f"codes={[s for s, _ in seal_res]} sigs={len(sigs)}")

        # A slow seal of one batch must not block other batches' uploads.
        b8 = "BATCH-SEAL-SLOW"
        upload(PORT_A, b8, "s1.csv", b"s1\n")
        with _cf.ThreadPoolExecutor(max_workers=1) as ex:
            slow = ex.submit(req, "POST", PORT_A,
                             f"/api/batches/{b8}/seal")
            time.sleep(0.2)
            t0 = time.time()
            s_other, r_other = upload(PORT_A, "BATCH-SEAL-OTHER", "o.csv",
                                      b"other\n")
            other_latency = time.time() - t0
            s, _ = req("GET", PORT_A, "/api/batches")
            slow_res = slow.result()
        check("a seal in flight does not block other uploads/queries",
              s_other == 200 and other_latency < 5.0 and slow_res[0] == 201,
              f"other upload {other_latency:.2f}s http={s_other}")

        # Seal crash: witness signs, archive dies before storing. On restart
        # the same manifest is recovered -- never a second one, never success
        # reported without verification.
        b9 = "BATCH-SEAL-CRASH"
        upload(PORT_A, b9, "x.csv", b"seal-crash\n")
        s, _ = req("POST", PORT_A, "/api/admin/arm-seal-crash")
        try:
            s, _ = req("POST", PORT_A, f"/api/batches/{b9}/seal")
            crash_http = s
        except OSError as exc:
            crash_http = f"connection reset ({exc.__class__.__name__})"
        check("archive exits after witness sealed, before local storage",
              wait_down(PORT_A, 10), f"http={crash_http}")
        s, st = req("GET", PORT_W, f"/seals/{b9}")
        witness_sig = (st.get("seal") or {}).get("signature")
        h.start_archive(port=PORT_A, witness_port=PORT_W, wait=True)
        deadline = time.time() + 20
        batch = {}
        while time.time() < deadline:
            s, batch = req("GET", PORT_A, f"/api/batches/{b9}/seal")
            if batch.get("sealed"):
                break
            time.sleep(0.3)
        check("restart recovers the same witness-sealed manifest",
              batch.get("sealed") is True
              and batch.get("manifest", {}).get("file_count") == 1,
              f"state={batch.get('seal_state')} err={batch.get('last_error')}")
        s, wseals = req("GET", PORT_W, "/seals")
        same = [x for x in wseals["items"] if x["batch_id"] == b9]
        check("crash recovery reuses the one witness manifest",
              len(same) == 1 and same[0]["signature"] == witness_sig)
        s, dl_seal = req("GET", PORT_A, f"/api/batches/{b9}/seal/download")
        check("recovered manifest is downloadable after restart",
              s == 200 and dl_seal["signature"] == witness_sig)

        # 9f. Verification cross-checks seals.
        s, report = req("GET", PORT_A, "/api/verify")
        seal_entries = {e["batch_id"]: e for e in report.get("seals", [])}
        check("verify page cross-checks each seal against the witness",
              s == 200 and seal_entries.get(b5, {}).get("passed") is True
              and seal_entries.get(b9, {}).get("passed") is True,
              str(list(seal_entries))[:160])

        # 9g. Tampering a sealed original after the seal: the seal is frozen,
        # so downloads and verification must fail while the state is not
        # silently re-reported as complete.
        sealed_path = h.adata / f"originals-{PORT_A}" / b5 / "a.csv"
        sealed_bytes = sealed_path.read_bytes()
        sealed_path.write_bytes(sealed_bytes + b"X")
        s, dl = req("GET", PORT_A, f"/api/batches/{b5}/download/a.csv")
        check("download of a tampered sealed original is refused",
              s == 409, f"http={s}")
        s, st = req("GET", PORT_A, f"/api/batches/{b5}/seal")
        check("sealed status is not reported while bytes disagree",
              st.get("sealed") is False, str(st)[:160])
        s, dl = req("GET", PORT_A, f"/api/batches/{b5}/seal/download")
        check("seal manifest download is refused while bytes disagree",
              s == 409, f"http={s}")
        s, report = req("GET", PORT_A, "/api/verify")
        check("verification fails on post-seal tampering",
              report["passed"] is False)
        # A retry while the bytes still disagree must not erase the signed
        # manifest (audit trail) and must remain non-successful.
        s, r = req("POST", PORT_A, f"/api/batches/{b5}/seal/retry")
        check("retry while sealed bytes disagree stays non-successful",
              s == 409 and r.get("seal") is None, f"http={s}")
        s, wseals = req("GET", PORT_W, "/seals")
        same = [x for x in wseals["items"] if x["batch_id"] == b5]
        check("failed re-check never creates a second manifest",
              len(same) == 1)
        sealed_path.write_bytes(sealed_bytes)  # restore
        s, r = req("POST", PORT_A, f"/api/batches/{b5}/seal/retry")
        check("restored sealed batch returns to sealed via the same manifest",
              s == 200 and r.get("seal") is not None
              and r["seal"]["signature"] == same[0]["signature"])
        s, dl = req("GET", PORT_A, f"/api/batches/{b5}/seal/download")
        check("seal manifest download recovers after restoring bytes",
              s == 200)

        # 9h. HTML pages render.
        import http.client as _hc
        pages_ok = True
        for page in ("/", "/seals", f"/batches/{b5}", "/verify"):
            c = _hc.HTTPConnection(HOST, PORT_A, timeout=10)
            c.request("GET", page)
            pr = c.getresponse()
            body = pr.read()
            c.close()
            if pr.status != 200 or b"<html" not in body:
                pages_ok = False
        check("upload/seal/batch/verify pages render", pages_ok)

        # 10. witness down => verification must not pass
        h.shutdown_port(PORT_W)
        check("witness process exits for the outage demo",
              wait_down(PORT_W, 10), f"port {PORT_W} closed")
        s, report = req("GET", PORT_A, "/api/verify")
        check("witness unreachable => verification 503, never passed",
              s == 503 and report["passed"] is False
              and report["witness_reachable"] is False)

    finally:
        h.cleanup()

    failed = [n for n, ok, _ in results if not ok]
    print("\n" + "=" * 64)
    print(f"self test summary: {len(results) - len(failed)}/"
          f"{len(results)} passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print("  -", n)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
