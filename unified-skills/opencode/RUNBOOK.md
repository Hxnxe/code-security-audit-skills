# OpenCode Runbook

## Preparation

1. Load:
- `../shared/artifact-contract.md`
- `../shared/phase-gates.md`
- `./TASKS.md`

## Phase 1 - Map

Run:
- Master-only entry enumeration (default path)
- `tasks/sink-point-scanner.task.md`
- `tasks/security-asset-scanner.task.md`
- `tasks/data-model-analyzer.task.md`

Check:
- `audit/map.json`
- `audit/triage.md`
- `audit/hypotheses.md`
- `audit/business-model.md`
- `audit/read-log.md`

## Phase 2 - Candidate

Run in parallel if available:
- `tasks/injection-scanner.task.md`
- `tasks/access-scanner.task.md`
- `tasks/infra-scanner.task.md`

Master review step:
- review ALERT/STATS
- assign severity
- for D3/D9 run control-driven checks first (group endpoints by `controller_group`, then compare CRUD consistency and permission/ownership/state checks)
- write `audit/public-endpoint-review.md`
- write `audit/risk-map.md`
- write `audit/prereq-candidates.md` (initialize empty if no P0/P1)
- run `tasks/security-analyst-draft.task.md` (`mode=phase2_draft`)
- write `audit/attack-chains-draft.md` (Phase 2 draft synthesis output)

## Phase 2.5 - Gate

Enforce:
- D1/D2/D3/D11/D12 covered
- E1/E2/E4/E5/E6 covered
- Q1/Q2/Q3 converged

If not converged:
- execute R2 with carry-over lists
- re-check gate

## Phase 3 - Verify

Run:
- `tasks/dataflow-analyzer.task.md`
- `tasks/access-validator.task.md`
- `tasks/logic-analyzer.task.md`
- `tasks/vulnerability-validator.task.md`
- `tasks/poc-generator.task.md`
- `tasks/security-analyst.task.md` (`mode=phase3_final`, last)

Check:
- `audit/dataflow.md`
- `audit/findings.md`
- `audit/pocs.md`
- `audit/findings-consolidated.md`

## Phase 4 - Report

Generate:
- `audit/report.md` (Chinese, reproduction-oriented)

Must include:
- PoC for Critical/High
- reference summary for `hypotheses.md` and `read-log.md`
