# OpenCode Porting Guide

## Objective

Adapt the existing security audit skillset to OpenCode while preserving methodology and artifact compatibility.

## Mapping

1. Orchestration:
- Use OpenCode workflow/task primitives as the master runner
- Keep phase boundaries and hard gates unchanged

2. Scanner/validator roles:
- Convert each Droid into an OpenCode task profile
- Reuse role intent and output formats, not platform-specific wording

3. Files:
- Maintain the same `audit/` outputs to ensure cross-runtime comparability

## Recommended Rollout

1. MVP:
- Implement Phase 1 + Phase 2 + Phase 2.5 only
- Verify gate pass/fail behavior on 1-2 real repos

2. Full:
- Add Phase 3 deep verification profiles
- Add Phase 4 Chinese report generation

3. Stabilization:
- Compare outputs against current runtime on the same target repo
- Tune false positive/false negative tradeoffs

## Guardrails

- Keep ALERT/STATS split in candidate stage
- Keep four-step verification in deep stage
- Keep read-log as coverage evidence source

## Ready-to-Run Bundle

- System prompt: `./SYSTEM-PROMPT.md`
- Execution steps: `./QUICKSTART.md`
- R2 handoff structure: `./R2-HANDOFF-TEMPLATE.md`
- Acceptance checklist: `./DELIVERY-CHECKLIST.md`
