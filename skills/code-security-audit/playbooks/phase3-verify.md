# Phase 3: Deep Verification

## Context Isolation Rule

**Do NOT reference Phase 1/2 conversation history.** All needed data is in audit/ files. Read them fresh:
- `audit/risk-map.md` for P0/P1 ranked findings to verify
- `audit/map.json` for context (entries, sinks, models)
- `audit/hypotheses.md` for attack chain construction
- `audit/attack-chains-draft.md` for Phase 3 verification prioritization

This phase starts from files, not from memory.

## Gate Check (Entry)

Before executing Phase 3, verify:

1. Phase 2.5 hard gate passed: D1/D2/D3/D11/D12 = ✅, E1/E2/E4/E5/E6 = ✅
2. Phase 2.5 convergence check passed: Q1/Q2/Q3 all = NO (or R2 completed)
3. `audit/risk-map.md` exists with P0/P1 ranked entries
4. `audit/attack-chains-draft.md` exists (can be empty only if no P0/P1 findings)

**If ANY check fails → STOP. Return to Phase 2.5.**

---

## Four-Step Verification

**Only audit P0/P1 files** from risk-map.md. For each suspicious finding, apply the **Four-Step Verification**:

| Step | Question | Pass Criteria |
|------|----------|---------------|
| 1. Dataflow Completeness | Is there a complete path from Source to Sink with no effective sanitization? | Full chain documented |
| 2. Protection Bypassability | Can security checks be circumvented? (blacklist gaps, encoding tricks, type confusion) | Bypass method identified |
| 3. Precondition Satisfiability | Can an attacker actually reach this code path? (auth required? specific role?) | Reachability confirmed |
| 4. Impact Scope | What is the maximum damage? (RCE / full DB leak / account takeover) | Impact classified |

**All 4 pass** → Confirmed vulnerability, record in `audit/findings.md` with full call chain.
**Any step fails** → Downgrade to "needs manual review" or exclude.

---

## Step 0: Attack-Chain Guided Prioritization

Read `audit/attack-chains-draft.md` and prioritize validation order:
1. Findings on chain front segments (`ENTRY` / `STEPPING_STONE`) first
2. Findings tied to unresolved prerequisites (`resolved=false`) next
3. Remaining P0/P1 findings by risk-map rank

Pass this ordering to all Step 1 verification Droids.

---

## Sub-agent Dispatch

Invoke these Droid subagents via the Task tool during Phase 3:

**Step 1 — Deep verification (parallel where possible)**:
- **`dataflow-analyzer`** Droid — Bidirectional trace (reverse + forward), second-order detection → `audit/dataflow.md`
- **`access-validator`** Droid — Deep auth + authz verification (D2+D3 combined) → auth/authz findings
- **`logic-analyzer`** Droid — Business logic flaws (D9) + vulnerability pattern correlation → logic findings
- **`vulnerability-validator`** Droid — Four-step verification on all traces, classify verdicts → `audit/findings.md`

**Step 2 — Evidence generation**:
- **`poc-generator`** Droid — Generate PoC for CONFIRMED findings → embedded in `audit/findings.md`

**Step 3 — Consolidation (CRITICAL: runs last, sees everything)**:
- **`security-analyst`** Droid (`mode=phase3_final`) — Reads ALL Phase 3 outputs + map.json. Performs:
  - Cross-finding correlation and deduplication
  - Attack chain construction (combining 2+ vulns)
  - Severity recalibration with full context
  - Coverage gap identification
  - → `audit/findings-consolidated.md` (the definitive output)

---

## Phase 4: Report Generation (20% effort)

Read `output-templates.md` for format specifications. Generate `audit/report.md` in **全中文 + 渗透复现导向**格式，并确保：
- **Critical / High** 漏洞必须包含 PoC（使用 `audit/pocs.md`）
- 报告结构包含：项目概览、复现总览表、关键漏洞复现指南、修复优先级、占位符说明

**Note**: `audit/hypotheses.md` and `audit/read-log.md` are mandatory artifacts even though they are not defined in output-templates.md. Include a summary reference to both in the report.
