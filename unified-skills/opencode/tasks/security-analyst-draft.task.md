# Task: security-analyst-draft

## Runtime
opencode

## Source Droid
- Prompt source: droids/security-analyst.md
- Load the source file as the role prompt.

## Phase
phase-2-candidate

## Task Mode
candidate_scan

## Inputs
- Required artifacts in audit/ (`map.json`, `risk-map.md`, `hypotheses.md`, `prereq-candidates.md`).
- Repository code (read-only for this task).

## Output
- Primary target: audit/attack-chains-draft.md
- Follow the source droid output format exactly.

## Invocation Contract
- Wrap execution with templates/subtask-prompt.md.
- MUST pass `mode=phase2_draft` to `security-analyst`.
- Only report code that is actually read.
