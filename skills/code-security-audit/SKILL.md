---
name: code-security-audit
description: Orchestrates a full automated code security audit across 4 phases - map building, parallel scanning, convergence checking, and deep verification with coverage self-check. Use when the user asks for a security audit, penetration test, vulnerability assessment, or code review focused on security of a web application codebase.
version: 1.1.0
tags: [security, audit, dataflow, coverage, webapp]
---

# Code Security Audit - Master Orchestrator

## When to Use
- Security audit / penetration test / vulnerability assessment
- Security-focused code review of a web application

## Inputs
| Input | Required | Notes |
|------|----------|-------|
| RepoRoot | yes | Project root for `audit/` outputs |
| Mode | no | `full` (default) / `pr` / `diff` |
| Scope | no | Subdir / service path if monorepo |
| SeverityThreshold | no | default: `medium` |

## Phase Index (Hard-Gated)
| Phase | Playbook | Outputs | Gate |
|------|----------|---------|------|
| 1 | `playbooks/phase1-recon.md` | map.json, triage.md, hypotheses.md, read-log.md, business-model.md | All exist + non-empty |
| 2 | `playbooks/phase2-scan.md` | public-endpoint-review.md, risk-map.md | Both exist |
| 2.5 | `playbooks/phase2.5-check.md` | coverage table + convergence | D1/D2/D3 + E1/E2/E4/E5 must be ✅ |
| 3 | `playbooks/phase3-verify.md` | findings.md, dataflow.md, findings-consolidated.md | risk-map exists + gate passed |
| 4 | `output-templates.md` | report.md | report generated |

## Global Rules (Summary)
- Only report code you have READ.
- Every finding must include source→transform→sink evidence.
- Structured output only (use templates).
- Output cap & anti-repetition apply.
- Phase gate violations are hard stops.
- Context isolation: each phase reads `audit/` files fresh.

Full rules: `rules/global-rules.md`

## Core Method References
- Universal questions: `rules/universal-questions.md`
- Audit dimensions: `rules/dimensions.md`
- Constraints: `rules/constraints.md`
- Scope: `rules/scope.md`

## Output Templates
See `output-templates.md` for all required formats.
