# OpenCode Quickstart

## 1) Prepare

From repo root, ensure migration files exist:
- `./SYSTEM-PROMPT.md`
- `./RUNBOOK.md`
- `./TASKS.md`

## 2) Start OpenCode Session

Paste the full content of:
- `./SYSTEM-PROMPT.md`

Provide runtime inputs:
- `RepoRoot=<your-repo-root>`
- `Mode=full`
- `Scope=<optional-subdir>`

## 3) Execute by Phase

Follow:
- `./RUNBOOK.md`

Use tasks from:
- `./tasks/*.task.md`

## 4) Gate Enforcement

At each boundary, enforce:
- `../shared/phase-gates.md`

If Phase 2.5 fails, trigger R2 and pass structured carry-over using:
- `./R2-HANDOFF-TEMPLATE.md`

## 5) Deliverables

Minimum final outputs in `audit/`:
- `map.json`
- `triage.md`
- `hypotheses.md`
- `read-log.md`
- `business-model.md`
- `public-endpoint-review.md`
- `risk-map.md`
- `dataflow.md`
- `findings.md`
- `pocs.md`
- `findings-consolidated.md`
- `report.md`
