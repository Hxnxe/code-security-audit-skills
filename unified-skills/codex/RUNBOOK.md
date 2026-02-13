# Codex Runbook

## Phase 1

1. Run `tasks/sink-point-scanner.task.md`
2. Run `tasks/security-asset-scanner.task.md`
3. Run `tasks/data-model-analyzer.task.md`
4. Optional fallback: `tasks/web-entry-discovery.task.md`
5. Verify outputs:
- `audit/map.json`
- `audit/triage.md`
- `audit/hypotheses.md`
- `audit/read-log.md`
- `audit/business-model.md`

## Phase 2

1. Run in parallel:
- `tasks/injection-scanner.task.md`
- `tasks/access-scanner.task.md`
- `tasks/infra-scanner.task.md`
2. Merge scanner outputs into master review queue.
3. Master performs Step 0.5 review and builds:
- `audit/public-endpoint-review.md`
- `audit/risk-map.md`

## Phase 2.5

1. Evaluate D1-D12 status.
2. Evaluate E1-E5 evidence checks.
3. Evaluate Q1-Q3 convergence checks.
4. If failed, run R2 on uncovered scope only.

## Phase 3

1. Run verification tasks:
- `tasks/dataflow-analyzer.task.md`
- `tasks/access-validator.task.md`
- `tasks/logic-analyzer.task.md`
- `tasks/vulnerability-validator.task.md`
2. Run evidence task:
- `tasks/poc-generator.task.md`
3. Run consolidation task last:
- `tasks/security-analyst.task.md`

## Phase 4

1. Build Chinese report:
- `audit/report.md`
2. Ensure Critical/High findings include PoC.
