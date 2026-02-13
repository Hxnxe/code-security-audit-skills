# Phase 2.5: Coverage Self-Check & Convergence

## Gate Check (Entry)

Before executing Phase 2.5 checks, verify:

1. `audit/public-endpoint-review.md` exists
2. `audit/risk-map.md` exists
3. `audit/read-log.md` has been updated during Phase 2

**If ANY check fails → STOP. Return to Phase 2 and complete missing steps.**

---

## Dimension Coverage Matrix

Execute this self-check after Phase 2 scanning completes. For each dimension, assess coverage status honestly.

| ID | Dimension | Key Question | Status |
|----|-----------|-------------|--------|
| D1 | Injection | Can user input reach SQL/CMD/LDAP/SSTI execution points? | |
| D2 | Authentication | Is token generation, validation, and expiration complete and secure? | |
| D3 | Authorization | Does every sensitive operation verify user ownership/permission? | |
| D4 | Deserialization | Is untrusted data deserialized anywhere? | |
| D5 | File Operations | Are upload/download paths user-controllable? | |
| D6 | SSRF | Are server-side HTTP request URLs user-controllable? | |
| D7 | Cryptography | Hardcoded keys? Weak algorithms? Insecure random? | |
| D8 | Configuration | Debug endpoints exposed? CORS too broad? Verbose errors? DoS/ReDoS? | |
| D9 | Business Logic | Race conditions? Skippable workflows? Price manipulation? TOCTOU? | |
| D10 | Supply Chain | Do dependencies have known CVEs? | |
| D11 | Info Disclosure | Do public endpoints expose PII, configs, secrets, or internal state? | |
| D12 | Data Exposure | Do non-admin endpoint responses include unnecessary sensitive fields (over-serialization)? | |

**Status Definitions (Track-Specific):**
- ✅ **Covered (sink-driven dimensions: D1, D2, D4-D8, D10-D12)**: representative sinks were READ, fan-out to sibling callsites/modules was performed, and dataflow or control guards were verified.
- ✅ **Covered (control-driven dimensions: D3, D9)**: endpoint traversal completed by `controller_group`, CRUD consistency comparison completed, and permission/ownership/state-transition checks were verified for each group.
- ⚠️ **Shallow**: only grep/pattern evidence exists, or only single-point validation without required fan-out/control comparison.
- ❌ **Not Covered**: dimension was not examined at all.

---

## Exhaustive Read Verification

These checks use `audit/read-log.md` as the canonical evidence source. Self-reporting "covered" without read-log entries is a FAILURE.

| ID | Check | Verification Method | Status |
|----|-------|---------------------|--------|
| E1 | All public endpoints covered | Count (deep-read + shallow-read + shallow-clear) entries in read-log where auth=public == count in map.json#public_endpoints. Priority 3 "shallow-clear" entries count as covered only if triage F/G scans ran successfully. | |
| E2 | All auth endpoints Read | Glob auth-related files vs read-log entries where purpose=entry and file matches auth glob patterns | |
| E3 | ORM escape hatches searched | If ast-grep available: run structural search. Fallback: rg ".(literal\|raw\|extra\|text\|unsafe)\(". All dangerous matches must appear in map.json#sinks | |
| E4 | ast-grep triage executed | audit/triage.md exists with >0 entries. All WRITE/LEAK entries have corresponding read-log rows | |
| E5 | Sink aggregator files Read | All AUTH_AGGREGATOR and DB_AGGREGATOR files from triage.md have corresponding read-log entries | |

---

## Hard Gate (Phase 2.5 → Phase 3)

**D1 (Injection), D2 (Authentication), D3 (Authorization) MUST ALL be ✅.**
**E1 (Public endpoints Read), E2 (Auth endpoints Read) MUST ALL be ✅.**
**E4 (ast-grep triage verified) MUST be ✅ if ast-grep is available.**
**E5 (Sink aggregator files Read) MUST be ✅.**

If any hard-gate check is not ✅ → trigger R2 before Phase 3. Non-negotiable.

---

## Convergence Check (Three Questions)

After the hard gate passes, answer these three questions:

| # | Question | Check Method | If YES → |
|---|----------|-------------|----------|
| Q1 | Are there triage.md tagged files NOT present in read-log.md? | Diff triage.md file paths vs read-log file column | R2: read the missing files |
| Q2 | Are there risk-map.md entries with "dataflow: TBD" or chain_confidence: low? | Count entries with incomplete dataflow | R2: trace the incomplete dataflows |
| Q3 | Do any hypotheses in hypotheses.md have missing links with no corresponding risk-map findings? | For each hypothesis, check if every listed "Missing link" primitive has at least one risk-map entry | R2: specifically search for the missing primitive type |

**Q1 or Q2 or Q3 = YES → trigger R2 targeting the specific gaps.**
**All three = NO → proceed to Phase 3.**

---

## R2 Trigger Conditions

R2 is triggered when:
- **D1, D2, or D3** is not ✅ (mandatory)
- **E1, E2, E4, or E5** is not ✅ (mandatory)
- **2 or more** of D4-D12 are ❌ (recommended)
- **Q1, Q2, or Q3** = YES (convergence failure)

---

## R2 Execution Constraints

When R2 launches, carry these four lists from R1:

```
1. Covered dimensions list      → R2 skips these entirely
2. Uncovered dimensions list    → R2 only creates Agents for these
3. Analyzed files list          → R2 does not re-read these files
4. CLEAN surfaces list          → R2 does not re-scan these attack surfaces unless new contradictory evidence appears
```

**R2 Agent allocation**:
- 1-2 gaps → 1 scanner Droid
- 3-4 gaps → 2 scanner Droids
- 5+ gaps → 3 scanner Droids

**R2 Prohibited Actions**:
- Do NOT re-grep keywords already searched in R1
- Do NOT re-read files already fully analyzed in R1
- Do NOT re-scan attack surfaces declared CLEAN in R1

---

## Self-Check Output Template

After self-check, output the following table:

```markdown
## Coverage Self-Check Results

| ID | Dimension | Status | Evidence |
|----|-----------|--------|----------|
| D1 | Injection | ✅ | Traced 12 SQL sinks, 3 cmd sinks |
| D2 | Authentication | ⚠️ | Grep-searched JWT patterns, not deep-dived |
| D3 | Authorization | ❌ | Not examined |
| ... | ... | ... | ... |

**Decision**: R2 required — D2 needs deep audit, D3 not covered.
**R2 Scope**: auth-scanner (D2), authz-scanner (D3)
```
