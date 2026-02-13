# Shared Phase Gates

These gates must remain hard stops across all runtimes.

## Phase 1 -> Phase 2

Require:
- `audit/map.json` exists and `entries` is non-empty
- Manifest coverage check passed: `map.json#entries.length / route_file_count >= 0.95`
- `audit/triage.md` exists
- `audit/hypotheses.md` exists
- `audit/read-log.md` exists
- `audit/business-model.md` exists

## Phase 2 -> Phase 2.5

Require:
- `audit/public-endpoint-review.md` exists
- `audit/risk-map.md` exists
- `audit/prereq-candidates.md` exists
- `audit/attack-chains-draft.md` exists
- `audit/read-log.md` updated during Phase 2

## Phase 2.5 -> Phase 3

Hard gate:
- D1, D2, D3, D11, D12 are `Covered`
- E1, E2, E4, E5, E6 are `Covered`

Convergence gate:
- Q1, Q2, Q3 are all `NO`
- If any is `YES`, run R2 and re-check

## R2 Carry-Over Lists

R2 input must contain:
- Covered dimensions
- Uncovered dimensions
- Analyzed files
- CLEAN surfaces

## Phase 3 -> Phase 4

Require:
- `audit/findings.md`
- `audit/dataflow.md`
- `audit/findings-consolidated.md`
