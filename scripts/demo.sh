#!/usr/bin/env bash
# End-to-end demonstrations against a running docker-compose stack:
#   1. disconnect/crash recovery (witness accepts, archive dies before
#      registering, restart reconciles from the witness, no double archive)
#   2. original corruption detected by the witness-driven verification page
#
# Usage:  ./scripts/demo.sh
set -euo pipefail

ARCHIVE_URL="${ARCHIVE_URL:-http://127.0.0.1:8000}"
WITNESS_URL="${WITNESS_URL:-http://127.0.0.1:8001}"
BATCH="BATCH-DEMO-$(date +%H%M%S)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

line() { printf '\n========== %s ==========\n' "$1"; }

line "0. service health"
curl -fsS "$WITNESS_URL/health" | python3 -m json.tool
curl -fsS "$ARCHIVE_URL/api/batches" >/dev/null && echo "archive reachable"

line "1. arm the crash marker (next upload dies after witness acceptance)"
curl -fsS -X POST "$ARCHIVE_URL/api/admin/arm-crash" | python3 -m json.tool

printf 'sample_id,reading\ns1,12.4\ns2,13.1\n' > "$TMP/readings.csv"
line "2. upload $TMP/readings.csv to batch $BATCH (connection will be cut)"
set +e
curl -sS -m 8 -X POST "$ARCHIVE_URL/api/batches/$BATCH/files" \
    -F filename=readings.csv -F "file=@$TMP/readings.csv"
echo
echo "(curl exit $? — expected: the archive container exited on purpose)"
set -e

line "3. wait for the restart policy to bring the archive back"
for _ in $(seq 1 20); do
  if curl -fsS "$ARCHIVE_URL/api/batches" >/dev/null 2>&1; then break; fi
  sleep 1
done

line "4. the witness already holds the receipt; the restart reconciles it"
curl -fsS "$WITNESS_URL/batches/$BATCH" | python3 -m json.tool
curl -fsS "$ARCHIVE_URL/api/batches/$BATCH" | python3 -m json.tool \
    | grep -E '"status"|"registered_count"'

line "5. confirm the witness has exactly ONE record (no duplicate re-archive)"
curl -fsS "$WITNESS_URL/receipts" | python3 -c "
import json,sys
items = json.load(sys.stdin)['items']
hits = [i for i in items if i['batch_id']=='$BATCH']
print(f'records for $BATCH: {len(hits)} (expected 1)')
assert len(hits) == 1"

line "6. full verification BEFORE tampering — should pass"
curl -fsS "$ARCHIVE_URL/api/verify" | python3 -c "
import json,sys
r = json.load(sys.stdin)
print('witness_reachable =', r['witness_reachable'], '| passed =', r['passed'])"

line "7. corrupt the stored original inside the archive volume"
docker exec research-archive sh -c \
  "printf 'CORRUPTED' >> /data/originals/$BATCH/readings.csv"
echo "appended bytes to /data/originals/$BATCH/readings.csv"

line "8. verification AFTER tampering — must report tampered_original"
curl -fsS "$ARCHIVE_URL/api/verify" | python3 -c "
import json,sys
r = json.load(sys.stdin)
assert r['passed'] is False
for b in r['batches']:
    if b['batch_id'] == '$BATCH':
        for f in b['files']:
            print('problems:', [p['type'] for p in f['problems']])
            assert any(p['type'] == 'tampered_original' for p in f['problems'])
print('tamper detected correctly')"

line "9. download now refuses the corrupted file"
set +e
curl -sS -o /dev/null -w "download HTTP %{http_code} (expected 409)\n" \
  "$ARCHIVE_URL/api/batches/$BATCH/download/readings.csv"
set -e

line "10. seal a fresh batch with two files"
SB="BATCH-SEAL-DEMO-$(date +%H%M%S)"
printf 'id,v\n1,a\n' > "$TMP/a.csv"
printf 'id,v\n2,b\n' > "$TMP/b.csv"
curl -fsS -X POST "$ARCHIVE_URL/api/batches/$SB/files" \
  -F filename=a.csv -F "file=@$TMP/a.csv" >/dev/null
curl -fsS -X POST "$ARCHIVE_URL/api/batches/$SB/files" \
  -F filename=b.csv -F "file=@$TMP/b.csv" >/dev/null
curl -fsS -X POST "$ARCHIVE_URL/api/batches/$SB/seal" | python3 -c "
import json,sys
r = json.load(sys.stdin)
m = r['seal']['manifest']
print('sealed:', r['batch']['status'], '| files:', m['file_count'])
for f in m['files']:
    print(' ', f['filename'], f['length'], f['sha256'][:16] + '...')
assert r['batch']['status'] == 'sealed'"

line "11. a late CSV after sealing must be refused (no record outside manifest)"
set +e
curl -sS -o /dev/null -w "late upload HTTP %{http_code} (expected 409)\n" \
  -X POST "$ARCHIVE_URL/api/batches/$SB/files" \
  -F filename=late.csv -F "file=@$TMP/a.csv"
set -e
curl -fsS "$WITNESS_URL/batches/$SB" | python3 -c "
import json,sys
r = json.load(sys.stdin)
print('witness files:', [i['filename'] for i in r['items']], '| sealed:', r['sealed'])
assert {i['filename'] for i in r['items']} == {'a.csv','b.csv'}"

line "12. download the signed manifest and verify it with the fixed public key"
curl -fsS "$ARCHIVE_URL/api/batches/$SB/seal/download" -o "$TMP/seal.json"
python3 - "$TMP/seal.json" <<'PY'
import json, sys
sys.path.insert(0, ".")
from common.receipt import load_public_key, verify_manifest_envelope
doc = json.load(open(sys.argv[1]))
ok, err = verify_manifest_envelope(
    load_public_key("keys/witness_ed25519.pub.pem"),
    {"payload_json": json.dumps(doc["manifest"], sort_keys=True,
                                separators=(",", ":"), ensure_ascii=False),
     "signature": doc["signature"], "algorithm": doc["algorithm"],
     "public_key_fingerprint": doc["public_key_fingerprint"]},
    expected_batch_id=doc["batch_id"])
print("manifest signature verifies:", ok, err or "")
assert ok
PY

line "13. re-sealing returns the same single manifest"
curl -fsS -X POST "$ARCHIVE_URL/api/batches/$SB/seal" | python3 -c "
import json,sys
r = json.load(sys.stdin)
print('status:', r['batch']['status'], '| reopened:', r['batch']['sealed'])
assert r['batch']['sealed'] is True"

line "DEMO COMPLETE"
echo "Open the web UI: $ARCHIVE_URL  (batch page: $ARCHIVE_URL/batches/$BATCH)"
echo "Seal page:       $ARCHIVE_URL/seals"
echo "Witness receipt list: $WITNESS_URL/receipts"
