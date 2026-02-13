# OpenCode Delivery Checklist

Mark complete only when all checks pass.

## A. Orchestration

- [ ] `SYSTEM-PROMPT.md` loaded as top-level instruction
- [ ] `RUNBOOK.md` followed phase by phase
- [ ] `TASKS.md` used to select task files

## B. Gate Compliance

- [ ] Phase 1 -> 2 gate passed
- [ ] Phase 2 -> 2.5 gate passed
- [ ] Phase 2.5 hard gate passed (D1/D2/D3/D11/D12, E1/E2/E4/E5/E6)
- [ ] Phase 2.5 convergence passed (Q1/Q2/Q3) or R2 completed and re-passed
- [ ] Phase 3 -> 4 gate passed

## C. Artifacts

- [ ] `audit/map.json`
- [ ] `audit/triage.md`
- [ ] `audit/hypotheses.md`
- [ ] `audit/read-log.md`
- [ ] `audit/business-model.md`
- [ ] `audit/public-endpoint-review.md`
- [ ] `audit/risk-map.md`
- [ ] `audit/prereq-candidates.md`
- [ ] `audit/attack-chains-draft.md`
- [ ] `audit/dataflow.md`
- [ ] `audit/findings.md`
- [ ] `audit/pocs.md`
- [ ] `audit/findings-consolidated.md`
- [ ] `audit/report.md`

## D. Quality

- [ ] Candidate scanners kept ALERT/STATS split
- [ ] Final severity assigned in master review
- [ ] D3/D9 assessed with control-driven checks
- [ ] Critical/High in report include PoC
- [ ] Report language is Chinese and reproduction-oriented
