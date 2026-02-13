# OpenCode Master Orchestrator Template

Use this as the top-level workflow instruction in OpenCode.

## Mission

Run the migrated security audit workflow end-to-end with unchanged methodology.

Read first:
- `../shared/artifact-contract.md`
- `../shared/phase-gates.md`
- `./TASKS.md`

## Runtime Rules

- Preserve phase isolation and hard gates.
- Do not merge candidate scan and deep verification.
- Phase 2 scanners output ALERT/STATS only.
- Severity is assigned by master review, not scanner tasks.

## Workflow

1. Phase 1: Build map artifacts
- Execute:
  - Master-only entry enumeration (do not delegate web entries by default)
  - `tasks/sink-point-scanner.task.md`
  - `tasks/security-asset-scanner.task.md`
  - `tasks/data-model-analyzer.task.md`
- Ensure:
  - `audit/map.json`
  - `audit/triage.md`
  - `audit/hypotheses.md`
  - `audit/business-model.md`
  - `audit/read-log.md`
- Gate check: Phase 1 -> 2

2. Phase 2: Candidate convergence
- Execute in parallel when supported:
  - `tasks/injection-scanner.task.md`
  - `tasks/access-scanner.task.md`
  - `tasks/infra-scanner.task.md`
- Master reviews ALERT/STATS with business baseline.
- For D3/D9, enforce control-driven review first: endpoint traversal by `controller_group` + CRUD consistency comparison.
- Run `tasks/security-analyst-draft.task.md` with `mode=phase2_draft`.
- Ensure:
  - `audit/public-endpoint-review.md`
  - `audit/risk-map.md`
  - `audit/prereq-candidates.md`
  - `audit/attack-chains-draft.md`
- Gate check: Phase 2 -> 2.5

3. Phase 2.5: Coverage and convergence gate
- Run D/E/Q checks.
- Hard gate includes D1/D2/D3/D11/D12 and E1/E2/E4/E5/E6.
- If failed, run R2 only on uncovered scope.
- R2 input must carry:
  - covered dimensions
  - uncovered dimensions
  - analyzed files
  - CLEAN surfaces

4. Phase 3: Deep verification
- Execute:
  - `tasks/dataflow-analyzer.task.md`
  - `tasks/access-validator.task.md`
  - `tasks/logic-analyzer.task.md`
  - `tasks/vulnerability-validator.task.md`
  - `tasks/poc-generator.task.md`
  - `tasks/security-analyst.task.md` with `mode=phase3_final` (final consolidation)
- Ensure:
  - `audit/dataflow.md`
  - `audit/findings.md`
  - `audit/pocs.md`
  - `audit/findings-consolidated.md`
- Gate check: Phase 3 -> 4

5. Phase 4: Report generation
- Output `audit/report.md` (Chinese, reproduction-oriented).
- Critical/High findings require PoC.

## Final Output

Return:
- phase gate status
- consolidated risks
- generated artifacts
