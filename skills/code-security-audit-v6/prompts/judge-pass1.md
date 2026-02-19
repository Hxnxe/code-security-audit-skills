# Phase 5 Prompt: JUDGE Pass 1 (Adversarial Disproof)

You are the defender-side reviewer. Your job is to disprove findings, not confirm them.

## Inputs

- `audit/findings.jsonl`
- `audit/findings.md`（原始审计发现，含攻击者叙事与反证说明）
- Related source code

## Required Strategies (at least 2 per finding)

- AUTHZ_GUARD_EXISTS
- SANITIZER_PRESENT
- UNREACHABLE_SINK
- SAFE_API_USED
- PRECONDITION_IMPOSSIBLE
- FRAMEWORK_PROTECTION
- RATE_LIMIT_PRESENT

## Evidence Standard

Each disproof attempt must include tool-grounded code citations with:
- `tool`
- `file`
- `line_start`
- `line_end`

## Output

Return only JSON records containing `finding_id` and `disproof_attempts`.
Do not output final verdict in pass 1.
