#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: run_audit_cycle.sh <project_root> <api_root> [audit_dir] [iteration]

examples:
  bash scripts/run_audit_cycle.sh "/repo" "<api_root>" "/repo/audit" 1
  SKIP_RECON=1 bash scripts/run_audit_cycle.sh "/repo" "<api_root>" "/repo/audit" 2

notes:
  - default audit_dir: <project_root>/audit
  - default iteration: 1
EOF
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

PROJECT_ROOT_INPUT="$1"
API_ROOT_INPUT="$2"
AUDIT_DIR_INPUT="${3:-}"
ITERATION="${4:-1}"
SKIP_RECON="${SKIP_RECON:-0}"
CYCLE_RESUME="${CYCLE_RESUME:-0}"
GATE_MODE="${GATE_MODE:-advisory}"
HARDEN_MODE="${HARDEN_MODE:-final}"
AUDIT_TARGETS="${AUDIT_TARGETS:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROJECT_ROOT="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$PROJECT_ROOT_INPUT")"
if [[ "$API_ROOT_INPUT" = /* ]]; then
  API_ROOT="$API_ROOT_INPUT"
else
  API_ROOT="$PROJECT_ROOT/$API_ROOT_INPUT"
fi
if [[ -n "$AUDIT_DIR_INPUT" ]]; then
  AUDIT_DIR="$AUDIT_DIR_INPUT"
else
  AUDIT_DIR="$PROJECT_ROOT/audit"
fi
AUDIT_DIR="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$AUDIT_DIR")"
STATE_PATH="$AUDIT_DIR/cycle_state.json"
QUEUE_PATH="$AUDIT_DIR/work_queue.json"

write_state() {
  local phase="$1"
  local status="${2:-}"
  local note="${3:-}"
  local r2="${4:-false}"
  python3 - <<'PY' "$STATE_PATH" "$phase" "$ITERATION" "$PROJECT_ROOT" "$API_ROOT" "$AUDIT_DIR" "$status" "$note" "$r2"
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "schema_version": 1,
    "updated_at": datetime.now(timezone.utc).isoformat(),
    "phase": sys.argv[2],
    "iteration": int(sys.argv[3]),
    "project_root": sys.argv[4],
    "api_root": sys.argv[5],
    "audit_dir": sys.argv[6],
    "last_status": sys.argv[7],
    "note": sys.argv[8],
    "r2_required": str(sys.argv[9]).lower() == "true",
}
path.parent.mkdir(parents=True, exist_ok=True)
tmp = path.with_suffix(path.suffix + ".tmp")
tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
tmp.replace(path)
PY
}

write_queue_from_shards() {
  python3 - <<'PY' "$AUDIT_DIR" "$QUEUE_PATH"
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

audit_dir = Path(sys.argv[1])
queue_path = Path(sys.argv[2])
shards_path = audit_dir / "audit_target_shards.json"
queue = []
if shards_path.exists():
    data = json.loads(shards_path.read_text(encoding="utf-8"))
    for shard in data.get("shards", []):
        if not isinstance(shard, dict):
            continue
        sid = str(shard.get("shard_id", "")).strip()
        if not sid:
            continue
        queue.append(
            {
                "target": sid,
                "reason": f"dispatch {sid} from shard plan",
                "phase": "AUDIT",
                "priority": str(shard.get("priority", "P1")),
            }
        )
payload = {
    "schema_version": 1,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "queue": queue,
}
queue_path.parent.mkdir(parents=True, exist_ok=True)
queue_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

if [[ -n "$AUDIT_TARGETS" ]]; then
  SKIP_RECON="1"
  echo "[cycle] targeted rescan: AUDIT_TARGETS=${AUDIT_TARGETS}"
fi

echo "[cycle] project_root=${PROJECT_ROOT}"
echo "[cycle] api_root=${API_ROOT}"
echo "[cycle] audit_dir=${AUDIT_DIR}"
echo "[cycle] iteration=${ITERATION}"
write_state "INIT" "STARTED" "cycle bootstrap"

if [[ "$CYCLE_RESUME" == "1" && -f "$STATE_PATH" ]]; then
  resume_phase="$(python3 - <<'PY' "$STATE_PATH"
import json,sys
data=json.loads(open(sys.argv[1],encoding="utf-8").read())
print(str(data.get("phase","UNKNOWN")))
PY
)"
  echo "[cycle] resume mode enabled, last phase=${resume_phase}"
fi

python3 - <<'PY' "$PROJECT_ROOT" "$AUDIT_DIR"
import pathlib
import sys

project = pathlib.Path(sys.argv[1]).resolve()
audit = pathlib.Path(sys.argv[2]).resolve()
if not str(audit).startswith(str(project) + "/"):
    raise SystemExit(f"AUDIT_DIR must be under PROJECT_ROOT: {audit} !< {project}")
print(f"[cycle] PATH_OK: audit_dir={audit}")
PY

if [[ "$SKIP_RECON" != "1" ]]; then
  echo "[cycle] RECON"
  bash "$SCRIPT_DIR/phase0_recon_v6.sh" "$API_ROOT" "$AUDIT_DIR"
  python3 "$SCRIPT_DIR/gate.py" g0 "$AUDIT_DIR" --mode strict
  write_state "RECON_DONE" "OK" "recon complete and g0 strict pass"
else
  echo "[cycle] RECON skipped (SKIP_RECON=1)"
  write_state "RECON_DONE" "SKIPPED" "skip recon requested"
fi

echo "[cycle] refresh droid dispatch payloads"
python3 "$SCRIPT_DIR/build_droid_dispatch.py" \
  --audit-dir "$AUDIT_DIR" \
  --project-root "$PROJECT_ROOT" \
  --audit-dir-ref "$AUDIT_DIR"
write_queue_from_shards
write_state "AUDIT_PENDING" "ACTION_REQUIRED" "dispatch droids using audit/droid_dispatch/*.md"

if [[ ! -f "$AUDIT_DIR/findings.md" ]]; then
  if [[ "$HARDEN_MODE" == "interim" ]]; then
    echo "[cycle] findings.md missing; running interim harden for progress snapshot"
    write_state "HARDEN_RUNNING" "IN_PROGRESS" "interim harden (no findings.md)"
    bash "$SCRIPT_DIR/harden_delivery.sh" "$AUDIT_DIR" "$ITERATION" "$GATE_MODE" --mode interim || true
    write_state "DONE" "INTERIM" "interim delivery completed (no findings.md)"
    echo "INTERIM: progress snapshot at $AUDIT_DIR/progress.md (findings.md still needed for full delivery)"
    exit 0
  fi
  echo "ACTION_REQUIRED: findings.md missing. Run AUDIT droids first." >&2
  echo "ACTION_REQUIRED: use files from $AUDIT_DIR/droid_dispatch/<shard_id>.md and then rerun this script." >&2
  exit 10
fi

write_state "HARDEN_RUNNING" "IN_PROGRESS" "start harden delivery"
set +e
bash "$SCRIPT_DIR/harden_delivery.sh" "$AUDIT_DIR" "$ITERATION" "$GATE_MODE" --mode "$HARDEN_MODE"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
  write_state "DONE" "PASS" "delivery completed" "false"
  echo "[cycle] delivery PASS"
  echo "[cycle] generating progress report"
  python3 "$SCRIPT_DIR/build_progress.py" "$AUDIT_DIR" --iteration "$ITERATION" || true
  if [[ -f "$AUDIT_DIR/progress.md" ]]; then
    echo "AUDIT_COMPLETE: progress report at $AUDIT_DIR/progress.md"
  fi
  exit 0
fi

if [[ $rc -eq 2 ]]; then
  write_state "DONE" "COVERAGE_GAP" "coverage gap reported" "false"
  echo "[cycle] generating progress report"
  python3 "$SCRIPT_DIR/build_progress.py" "$AUDIT_DIR" --iteration "$ITERATION" || true
  echo "COVERAGE_GAP: see $AUDIT_DIR/progress.md for uncovered targets"
  exit 0
fi

if [[ $rc -eq 3 ]]; then
  echo "[cycle] JUDGE_REQUIRED; generating interim progress snapshot"
  bash "$SCRIPT_DIR/harden_delivery.sh" "$AUDIT_DIR" "$ITERATION" "$GATE_MODE" --mode interim || true
  write_state "JUDGE_REQUIRED" "ACTION_REQUIRED" "verdict skeleton generated; judge input required"
  echo "ACTION_REQUIRED: verdict skeleton generated. Fill it via Judge pass1/pass2 and write audit/verdict.json, then rerun this script." >&2
  echo "  skeleton: $AUDIT_DIR/verdict.skeleton.json" >&2
  if [[ -f "$AUDIT_DIR/progress.md" ]]; then
    echo "  interim progress: $AUDIT_DIR/progress.md" >&2
  fi
  exit 3
fi

write_state "FAILED" "ERROR" "harden failed with rc=${rc}"
echo "error: harden_delivery failed with exit code $rc" >&2
exit 1
