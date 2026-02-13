# Shared Artifact Contract

All targets must produce and consume the same files under `audit/`.

## Required Files by Phase

1. Phase 1:
- `audit/map.json`
- `audit/triage.md`
- `audit/hypotheses.md`
- `audit/read-log.md`
- `audit/business-model.md`

2. Phase 2:
- `audit/public-endpoint-review.md`
- `audit/risk-map.md`
- `audit/prereq-candidates.md`
- `audit/attack-chains-draft.md`

3. Phase 3:
- `audit/dataflow.md`
- `audit/findings.md`
- `audit/findings-consolidated.md`
- `audit/pocs.md` (or embedded PoC section in findings/report)

4. Phase 4:
- `audit/report.md`

## map.json Minimum Schema

`entries` should include:
- `route`
- `method`
- `handler`
- `auth_required`
- `permission_annotation`
- `resource_type`
- `ownership_check`
- `controller_group`
- `has_write`
- `needs_field_audit`

Also required:
- `sinks`
- `configs`
- `models`
- `public_endpoints`

## Compatibility Rule

If target runtime adds metadata, append fields only. Do not remove core fields.
