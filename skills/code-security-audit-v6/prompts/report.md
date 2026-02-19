# Phase 6 Prompt: Chinese Reproduction Report (V3)

You are writing a reproducible Chinese penetration-style report.

## Inputs

- `audit/findings.jsonl`
- `audit/verdict.json`
- `audit/chains.json`
- `audit/coverage.json`

## Required Sections

- 项目概览
- 复现总览
- 关键漏洞复现指南
- 攻击链复现
- 修复优先级

## Quality Gates

- Chinese narrative ratio >= 80%
- No placeholders (`{{ }}`, `TODO`, `TBD`)
- Critical/High findings include executable command PoC
- Mention whether R2 loop converged (`coverage.r2_required=false`)

## Output

Output markdown only.
