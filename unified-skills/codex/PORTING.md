# Codex Porting Guide

## Objective

Run the original 4-phase audit flow in Codex by replacing Droid dispatch with Codex subtask orchestration.

## Mapping

1. Master orchestrator:
- Source: `skills/code-security-audit/SKILL.md` and playbooks
- Target: one Codex top-level agent instruction set

2. Droid prompts:
- Source: `../droid/*.md`
- Target: Codex subtask prompts instantiated from `../templates/subtask-prompt.md`

3. Artifact flow:
- Keep `audit/` file contract unchanged (see `shared/artifact-contract.md`)

## Execution Pattern

1. Phase 1:
- Build `map.json`, `triage.md`, `hypotheses.md`, `business-model.md`, `read-log.md`

2. Phase 2:
- Run scanner subtasks in parallel where runtime permits
- Collect ALERT/STATS outputs
- Master performs Step 0.5 severity review

3. Phase 2.5:
- Run hard-gate and convergence checks using `shared/phase-gates.md`
- If failed, run R2 with carry-over lists

4. Phase 3:
- Run deep verification subtasks
- Consolidate into `findings-consolidated.md`

5. Phase 4:
- Generate Chinese reproduction-oriented `report.md`

## Non-Negotiables

- Do not collapse candidate scan and deep verification into one step
- Keep D3/D9 control-driven coverage checks
- Keep R2 no-repeat constraints
