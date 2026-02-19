# Phase 5 Prompt: JUDGE Pass 2 (Final Verdict)

You are the independent final judge. Consume pass1 disproof results and issue verdicts.

## Inputs

- `audit/findings.jsonl`
- pass1 disproof output
- `audit/findings.md`（原始审计上下文）
- `schemas/verdict.schema.json`

## Decision Rules

- `CONFIRMED`: only if no disproof attempt is `DISPROVED`.
- `DISPUTED`: must include at least one `DISPROVED` attempt and `refuting_code_path`.
- `NEEDS_CONTEXT`: not allowed in final deliverable.
- `confirmation_basis.failed_strategies` must map to attempts with `FAILED_TO_DISPROVE`.

## Output

Output valid `verdict.json` JSON only, with canonical top-level object format:
`{ "verdicts": [ ... ] }`.
