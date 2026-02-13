# Codex Master Orchestrator Template

Use this as the top-level runtime instruction in Codex.

## Mission

Execute a full security audit using the migrated task set while preserving:
- phase boundaries
- hard gates
- artifact contract

Read first:
- `../shared/artifact-contract.md`
- `../shared/phase-gates.md`
- `./TASKS.md`

## Runtime Rules

- Do not skip phases.
- Do not start next phase before gate pass.
- Each phase reads `audit/` files fresh.
- Keep D3/D9 control-driven coverage checks.

## Phase Plan

1. Phase 1 (Map Build)
- Run tasks:
  - `tasks/sink-point-scanner.task.md`
  - `tasks/security-asset-scanner.task.md`
  - `tasks/data-model-analyzer.task.md`
  - `tasks/web-entry-discovery.task.md` (optional fallback if needed)
- Produce:
  - `audit/map.json`
  - `audit/triage.md`
  - `audit/hypotheses.md`
  - `audit/read-log.md`
  - `audit/business-model.md`
- Validate gate: Phase 1 -> 2

2. Phase 2 (Candidate Scan)
- Run tasks (parallel where possible):
  - `tasks/injection-scanner.task.md`
  - `tasks/access-scanner.task.md`
  - `tasks/infra-scanner.task.md`
- Keep scanner outputs as ALERT/STATS.
- Master performs Step 0.5 review and severity assignment.
- Produce:
  - `audit/public-endpoint-review.md`
  - `audit/risk-map.md`
- Validate gate: Phase 2 -> 2.5

3. Phase 2.5 (Coverage + Convergence)
- Evaluate D/E/Q checks.
- If gate fails, run R2 with carry-over lists:
  - covered dimensions
  - uncovered dimensions
  - analyzed files
  - CLEAN surfaces
- Re-check until pass.

4. Phase 3 (Deep Verify)
- Run tasks:
  - `tasks/dataflow-analyzer.task.md`
  - `tasks/access-validator.task.md`
  - `tasks/logic-analyzer.task.md`
  - `tasks/vulnerability-validator.task.md`
  - `tasks/poc-generator.task.md`
  - `tasks/security-analyst.task.md` (last)
- Produce:
  - `audit/dataflow.md`
  - `audit/findings.md`
  - `audit/pocs.md`
  - `audit/findings-consolidated.md`
- Validate gate: Phase 3 -> 4

5. Phase 4 (Report)
- Generate `audit/report.md` in Chinese, reproduction-oriented format.
- Critical/High findings must include PoC.

## Final Output

Return:
- gate pass summary
- key findings summary
- artifact file list
