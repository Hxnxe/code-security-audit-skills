# Task: poc-generator

## Runtime
codex

## Source Droid
- Prompt source: code-security-audit-skills/droids/droids/poc-generator.md
- Load the source file as the role prompt.

## Phase
phase-3-evidence

## Task Mode
deep_verify

## Inputs
- Required artifacts in audit/ (map/risk/read-log/hypotheses/business-model as required by source prompt).
- Repository code (read-only for this task).

## Output
- Primary target: audit/pocs.md
- Follow the source droid output format exactly.

## Invocation Contract
- Wrap execution with ../templates/subtask-prompt.md.
- Keep ALERT/STATS split for candidate scanners.
- Do not assign final severity in Phase 2 candidate scanners.
- Only report code that is actually read.
