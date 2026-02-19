#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <audit_dir> [iteration] [gate_mode] [--mode interim|final]" >&2
  echo "  gate_mode: advisory|strict (default: advisory)" >&2
  exit 1
fi

AUDIT_DIR="$1"
ITERATION="${2:-1}"
GATE_MODE="${3:-${GATE_MODE:-advisory}}"
HARDEN_MODE="final"

# Parse --mode flag if present
if [[ "${4:-}" == "--mode" ]] && [[ -n "${5:-}" ]]; then
  HARDEN_MODE="$5"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ "$HARDEN_MODE" == "interim" ]]; then
  echo "[harden:interim] partial delivery mode"
  
  if [[ -f "${AUDIT_DIR}/findings.md" ]]; then
    echo "[harden:interim] validate findings.md"
    python3 "${SCRIPT_DIR}/validate_findings_md.py" --audit-dir "${AUDIT_DIR}" || {
      echo "WARNING: findings.md validation failed" >&2
    }
    echo "[harden:interim] extract findings"
    python3 "${SCRIPT_DIR}/extract_findings.py" "${AUDIT_DIR}" || {
      echo "WARNING: findings extraction failed" >&2
    }
  else
    echo "[harden:interim] findings.md not found; skipping validation/extraction"
  fi
  
  if [[ -f "${AUDIT_DIR}/verification.md" ]]; then
    echo "[harden:interim] extract verification"
    python3 "${SCRIPT_DIR}/extract_verification.py" "${AUDIT_DIR}" || {
      echo "WARNING: verification extraction failed" >&2
    }
  fi
  
  echo "[harden:interim] build coverage (interim)"
  python3 "${SCRIPT_DIR}/build_coverage.py" "${AUDIT_DIR}" --iteration "${ITERATION}" || {
    echo "WARNING: coverage build failed" >&2
  }
  
  echo "[harden:interim] build progress"
  python3 "${SCRIPT_DIR}/build_progress.py" "${AUDIT_DIR}" || {
    echo "WARNING: progress build failed" >&2
  }
  
  echo "[harden:interim] interim delivery complete"
  exit 0
fi

echo "[harden] validate findings.md"
python3 "${SCRIPT_DIR}/validate_findings_md.py" --audit-dir "${AUDIT_DIR}"

echo "[harden] check verification.md"
if [[ -f "${AUDIT_DIR}/verification.md" ]]; then
  python3 "${SCRIPT_DIR}/validate_schema.py" "${AUDIT_DIR}/verification.md" verification || {
    echo "WARNING: verification.md validation failed; continuing anyway" >&2
  }
else
  echo "WARNING: verification.md not found; Master L1 verification not yet completed" >&2
fi

echo "[harden] extract findings/chains"
python3 "${SCRIPT_DIR}/extract_findings.py" "${AUDIT_DIR}"

if [[ ! -f "${AUDIT_DIR}/verdict.json" ]]; then
  echo "[harden] verdict.json missing; generate skeleton/draft then stop for Judge"
  python3 "${SCRIPT_DIR}/generate_verdict_skeleton.py" "${AUDIT_DIR}" --out "${AUDIT_DIR}/verdict.skeleton.json" --overwrite
  if [[ ! -f "${AUDIT_DIR}/verdict_draft.md" ]]; then
    {
      echo "# Verdict Draft (generated)"
      echo ""
      echo "请基于 judge-pass1/pass2 填写下方 JSON，然后重新运行 harden。"
      echo ""
      echo '```json'
      cat "${AUDIT_DIR}/verdict.skeleton.json"
      echo '```'
    } > "${AUDIT_DIR}/verdict_draft.md"
    echo "[harden] created ${AUDIT_DIR}/verdict_draft.md from skeleton"
  fi
  echo "ACTION_REQUIRED: complete Judge and produce ${AUDIT_DIR}/verdict.json (or update verdict_draft.md then compile)." >&2
  exit 3
fi

if [[ -f "${AUDIT_DIR}/verdict_draft.md" ]]; then
  echo "[harden] compile verdict from draft/skeleton"
  python3 "${SCRIPT_DIR}/compile_verdict.py" "${AUDIT_DIR}" --overwrite
fi

echo "[harden] validate verdict schema"
python3 "${SCRIPT_DIR}/validate_schema.py" "${AUDIT_DIR}/verdict.json" verdict

echo "[harden] build coverage (iteration=${ITERATION})"
python3 "${SCRIPT_DIR}/build_coverage.py" "${AUDIT_DIR}" --iteration "${ITERATION}"

echo "[harden] check coverage"
python3 - <<'PY' "${AUDIT_DIR}/coverage.json"
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    print("WARNING: coverage.json not found", file=sys.stderr)
    sys.exit(0)
data = json.loads(path.read_text(encoding="utf-8"))
r2 = data.get("r2_required", False) or data.get("coverage_gap", False)
if r2:
    print("WARNING: coverage gap detected. See audit/progress.md for details.", file=sys.stderr)
else:
    print("coverage gate ok: no coverage gap")
PY

echo "[harden] export chains from attack-graph/findings"
python3 "${SCRIPT_DIR}/export_chains_from_attack_graph.py" "${AUDIT_DIR}" --overwrite

echo "[harden] compile report"
python3 "${SCRIPT_DIR}/compile_report.py" "${AUDIT_DIR}" --lang zh-CN

echo "[harden] final gate (mode=${GATE_MODE})"
python3 "${SCRIPT_DIR}/gate.py" all "${AUDIT_DIR}" --mode "${GATE_MODE}"

echo "[harden] delivery PASS (${GATE_MODE})"
