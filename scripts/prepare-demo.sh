#!/usr/bin/env bash
# Prepare the on-disk state for the demo screencast.
#
# What it does:
#   1. Copies logs/sample-run/dlc-sample-run.{jsonl,index} into
#      logs/demo-run/ — a separate run-id so the pristine sample-run is
#      untouched.
#   2. Tampers ONE envelope in the demo run (the run_hayabusa envelope) by
#      appending a fabricated record to its persisted `data` field. The raw
#      stdout BLAKE3 in the header is untouched; only data_blake3 will
#      mismatch when the verifier checks integrity. This is the production
#      attack documented in tests/integration/test_spoliation.py
#      ::TestPersistedDataTampering — same path, same trigger.
#
# Why we do this for the demo:
#   The video must include "at least one self-correction sequence." A
#   pristine run never triggers Ralph Wiggum (everything verifies). By
#   pre-staging a tampered envelope, the verifier reliably rejects when
#   Claude cites it, exactly the scenario the spoliation tests cover.
#   It's a real production-verifier rejection, not a hand-built panel.
#
# Idempotent. Run again to restore + re-tamper. Use --clean to wipe.

set -euo pipefail

OATH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$OATH_ROOT/logs/sample-run"
DEMO_DIR="$OATH_ROOT/logs/demo-run"
SRC_RUN="dlc-sample-run"
DEMO_RUN="demo-run"

if [ "${1:-}" = "--clean" ]; then
  rm -rf "$DEMO_DIR"
  echo "Removed $DEMO_DIR" >&2
  exit 0
fi

if [ ! -f "$SRC_DIR/$SRC_RUN.jsonl" ]; then
  echo "ERROR: pristine sample-run not found at $SRC_DIR/$SRC_RUN.jsonl" >&2
  echo "       Run: PYTHONPATH=src python scripts/export_sample_run.py" >&2
  exit 1
fi

mkdir -p "$DEMO_DIR"
cp "$SRC_DIR/$SRC_RUN.jsonl" "$DEMO_DIR/$DEMO_RUN.jsonl"
cp "$SRC_DIR/$SRC_RUN.index" "$DEMO_DIR/$DEMO_RUN.index"

# Tamper the run_hayabusa envelope in place. Use Python so the canonical
# JSON shape is preserved exactly — `jq` would reorder keys.
"$(command -v python3 || command -v python || echo "$OATH_ROOT/.venv/bin/python")" - "$DEMO_DIR/$DEMO_RUN.jsonl" <<'PY'
import json, sys
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
out_lines = []
tampered_eid = None
for line in lines:
    if not line.strip():
        out_lines.append(line)
        continue
    env = json.loads(line)
    if env["header"]["tool_name"] == "run_hayabusa" and tampered_eid is None:
        # Inject a fabricated record. data_blake3 in the (untouched) header
        # will no longer match canonical(data), so the verifier rejects.
        if isinstance(env.get("data"), list) and env["data"]:
            fabricated = dict(env["data"][0])
            fabricated["__demo_tamper__"] = "fabricated-for-self-correction-demo"
            fabricated["rule_title"] = "FABRICATED — demo tamper marker"
            env["data"].append(fabricated)
        # Compute a short id from stdout_blake3 (the on-disk envelope_id is
        # the BLAKE3 of the signed header, but we just need a marker).
        tampered_eid = env["header"]["stdout_blake3"][:16]
    out_lines.append(json.dumps(env, separators=(",", ":"), sort_keys=True))
path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
if tampered_eid is None:
    print("WARN: no run_hayabusa envelope to tamper", file=sys.stderr)
else:
    print(f"tampered run_hayabusa envelope (stdout_blake3 prefix: {tampered_eid}…)", file=sys.stderr)
PY

# Print the tampered envelope id (the BLAKE3 of the signed header) so we
# can name it in the prompt or the recording shot list.
"$(command -v python3 || command -v python || echo "$OATH_ROOT/.venv/bin/python")" - "$DEMO_DIR/$DEMO_RUN.jsonl" "$DEMO_DIR/$DEMO_RUN.index" <<'PY'
import json, sys
from pathlib import Path

jsonl = Path(sys.argv[1])
index_path = Path(sys.argv[2])
ids = [line.split()[0] for line in index_path.read_text().splitlines() if line.strip()]
for i, line in enumerate(jsonl.read_text().splitlines()):
    if not line.strip(): continue
    env = json.loads(line)
    if env["header"]["tool_name"] == "run_hayabusa":
        print(f"\nTAMPERED envelope (for demo Ralph Wiggum trigger):")
        print(f"  tool        : run_hayabusa")
        print(f"  envelope_id : {ids[i]}")
        print(f"  records     : {len(env['data'])} (last one is fabricated)")
        print(f"  rule_title  : {env['data'][-1].get('rule_title','?')}")
        break
PY

cat <<EOF >&2

Demo state ready at $DEMO_DIR/.
The MCP server picks up envelopes from logs/ automatically. When Claude calls
oath_verify_claim citing the tampered envelope_id above, the verifier will
return RALPH_WIGGUM with reason "envelope.data does not match signed data_blake3".

To restore pristine state:
  bash scripts/prepare-demo.sh --clean
EOF
