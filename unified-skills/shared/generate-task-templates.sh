#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DROID_DIR="$ROOT_DIR/../code-security-audit-skills/droids/droids"

mkdir -p "$ROOT_DIR/targets/codex/tasks" "$ROOT_DIR/targets/opencode/tasks"

for f in "$DROID_DIR"/*.md; do
  base="$(basename "$f" .md)"
  rel_source="code-security-audit-skills/droids/droids/${base}.md"
  phase="phase-unknown"
  mode="candidate_scan"
  output="audit/notes.md"

  case "$base" in
    sink-point-scanner|security-asset-scanner|data-model-analyzer|web-entry-discovery)
      phase="phase-1-map"; mode="map_build"; output="audit/map.json" ;;
    injection-scanner|access-scanner|infra-scanner)
      phase="phase-2-candidate"; mode="candidate_scan"; output="audit/scanner-alerts/${base}.md (ALERT/STATS only; master later merges into audit/risk-map.md)" ;;
    dataflow-analyzer)
      phase="phase-3-verify"; mode="deep_verify"; output="audit/dataflow.md" ;;
    access-validator|logic-analyzer|vulnerability-validator)
      phase="phase-3-verify"; mode="deep_verify"; output="audit/findings.md" ;;
    poc-generator)
      phase="phase-3-evidence"; mode="deep_verify"; output="audit/pocs.md" ;;
    security-analyst)
      phase="phase-3-consolidate"; mode="deep_verify"; output="audit/findings-consolidated.md" ;;
  esac

  for rt in codex opencode; do
    out="$ROOT_DIR/targets/$rt/tasks/${base}.task.md"
    cat > "$out" <<EOF
# Task: $base

## Runtime
$rt

## Source Droid
- Prompt source: $rel_source
- Load the source file as the role prompt.

## Phase
$phase

## Task Mode
$mode

## Inputs
- Required artifacts in audit/ (map/risk/read-log/hypotheses/business-model as required by source prompt).
- Repository code (read-only for this task).

## Output
- Primary target: $output
- Follow the source droid output format exactly.

## Invocation Contract
- Wrap execution with ../templates/subtask-prompt.md.
- Keep ALERT/STATS split for candidate scanners.
- Do not assign final severity in Phase 2 candidate scanners.
- Only report code that is actually read.
EOF
  done
done

for rt in codex opencode; do
  idx="$ROOT_DIR/targets/$rt/TASKS.md"
  {
    echo "# $rt Task Index"
    echo
    echo "## Phase 1 Map"
    ls -1 "$ROOT_DIR/targets/$rt/tasks" | grep -E '^(sink-point-scanner|security-asset-scanner|data-model-analyzer|web-entry-discovery)\.task\.md$' | sort | sed 's#^#- tasks/#'
    echo
    echo "## Phase 2 Candidate"
    ls -1 "$ROOT_DIR/targets/$rt/tasks" | grep -E '^(injection-scanner|access-scanner|infra-scanner)\.task\.md$' | sort | sed 's#^#- tasks/#'
    echo
    echo "## Phase 3 Verify"
    ls -1 "$ROOT_DIR/targets/$rt/tasks" | grep -E '^(dataflow-analyzer|access-validator|logic-analyzer|vulnerability-validator|poc-generator|security-analyst)\.task\.md$' | sort | sed 's#^#- tasks/#'
  } > "$idx"
done

echo "Generated task templates for codex/opencode under $ROOT_DIR/targets."
