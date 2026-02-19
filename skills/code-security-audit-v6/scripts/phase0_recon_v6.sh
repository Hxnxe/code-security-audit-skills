#!/usr/bin/env bash
set -euo pipefail

API_ROOT="${1:-}"
AUDIT_DIR="${2:-audit}"
SKIP_SEMANTIC=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Parse optional --skip-semantic flag (can be 2nd or 3rd argument)
for arg in "$@"; do
  if [[ "$arg" == "--skip-semantic" ]]; then
    SKIP_SEMANTIC="true"
  fi
done

if [[ -z "$API_ROOT" ]]; then
  echo "usage: bash scripts/phase0_recon_v6.sh <api_root> [audit_dir] [--skip-semantic]" >&2
  exit 1
fi

API_ROOT_ABS="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$API_ROOT")"
PROJECT_ROOT="$(python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]).resolve(); c=[p,*p.parents]; out=p.parent
for x in c:
  if (x/"package.json").exists() or (x/"pyproject.toml").exists() or (x/".git").exists():
    out=x; break
print(out)' "$API_ROOT_ABS")"

if [[ "$AUDIT_DIR" = /* ]]; then
  AUDIT_DIR_ABS="$AUDIT_DIR"
else
  AUDIT_DIR_ABS="$PROJECT_ROOT/$AUDIT_DIR"
fi

mkdir -p "$AUDIT_DIR_ABS"

python3 "$SCRIPT_DIR/recon_lite.py" \
  "$API_ROOT_ABS" \
  --audit-dir "$AUDIT_DIR_ABS" \
  --project-root "$PROJECT_ROOT" \
  --max-files-per-shard "${AUDIT_MAX_FILES_PER_SHARD:-15}"

python3 "$SCRIPT_DIR/validate_schema.py" "$AUDIT_DIR_ABS/inventory.jsonl" inventory
python3 "$SCRIPT_DIR/validate_schema.py" "$AUDIT_DIR_ABS/attack-surface.jsonl" attack-surface

python3 "$SCRIPT_DIR/build_droid_dispatch.py" \
  --audit-dir "$AUDIT_DIR_ABS" \
  --project-root "$PROJECT_ROOT" \
  --audit-dir-ref "$AUDIT_DIR_ABS"

if [[ -z "$SKIP_SEMANTIC" ]]; then
  echo ""
  echo "ACTION_REQUIRED: Execute prompts/recon-semantic-v6.md to produce audit/recon-semantic-v6.md"
  echo ""
else
  echo "[recon-v6] LLM semantic RECON skipped (--skip-semantic)"
fi

python3 "$SCRIPT_DIR/gate.py" g0 "$AUDIT_DIR_ABS" --mode strict

echo "PHASE0_READY project_root=$PROJECT_ROOT audit_dir=$AUDIT_DIR_ABS"
