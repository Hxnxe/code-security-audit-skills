# Task: security-analyst

## Runtime
opencode

## Source Droid
- Prompt source: code-security-audit-skills/droids/droids/security-analyst.md
- Load the source file as the role prompt.

## Phase
phase-3-consolidate

## Task Mode
deep_verify

## Inputs
- Required artifacts in audit/ (map/risk/read-log/hypotheses/business-model as required by source prompt).
- Repository code (read-only for this task).

## Output
- Primary target: audit/findings-consolidated.md
- Follow the source droid output format exactly.

## Invocation Contract
- Wrap execution with ../templates/subtask-prompt.md.
- Keep ALERT/STATS split for candidate scanners.
- Do not assign final severity in Phase 2 candidate scanners.
- Only report code that is actually read.
