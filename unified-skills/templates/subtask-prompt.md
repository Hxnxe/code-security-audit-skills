# Subtask Prompt Template

Use this template to replace Droid calls in Codex/OpenCode.

## Role

`<scanner_or_validator_name>`

## Inputs

- Read-only files:
  - `<artifact_1>`
  - `<artifact_2>`
- Scope:
  - `<path_or_module_scope>`

## Task Mode

One of:
- `candidate_scan` (Phase 2 ALERT/STATS only)
- `deep_verify` (Phase 3 full evidence)

## Mandatory Rules

- Only report code that is actually read
- Use source -> transform -> sink evidence for exploit claims
- Follow output contract exactly
- No file writes except designated artifact output

## Output Contract

Write to:
- `<output_file>`

Format:
- `<table_or_template_spec>`

## Completion Checklist

- Coverage statement included
- False positives marked with reason
- Uncertain items marked `needs_review`
