# Phase 2: Parallel Scanning

## Context Isolation Rule

**Do NOT reference Phase 1 conversation history.** All needed data is in audit/ files. Read them fresh:
- `audit/map.json` for entries, sinks, configs, models
- `audit/triage.md` for high-risk file shortlist
- `audit/hypotheses.md` for attack hypothesis priorities
- `audit/prereq-candidates.md` (if exists) for unresolved prerequisite tracking

This phase starts from files, not from memory.

## Gate Check (Entry)

Before executing Phase 2, verify these artifacts exist:

1. `audit/map.json` exists and contains `entries` array with > 0 items
2. `audit/triage.md` exists and contains > 0 tagged entries
3. `audit/hypotheses.md` exists
4. `audit/read-log.md` exists and contains > 0 entries

**If ANY check fails → STOP. Return to Phase 1 and complete missing steps.**

Initialization rule:
- Ensure `audit/prereq-candidates.md` exists at Phase 2 start (create an empty file with header if missing), so downstream gates are deterministic even when no P0/P1 is found.

---

## Step 0: Triage-Driven Endpoint Review

**This step uses triage.md + aggregator tags from Phase 1 to prioritize what to Read.**

**Prerequisite**: Read `audit/business-model.md` first. All Q7 and Q3 judgments in this step MUST explicitly compare against the behavior signatures and sensitive data inventory.

**Executed by**: Master agent (NOT delegated)

**Priority 1 — Deep Read (triage tags A/B/C/D/E):**

P1-A: Auth chain — AUTH_AGGREGATOR files + all auth/-related files from triage.md
       Auth bypass amplifies all other vulnerabilities. Always audit first.
P1-B: Public write operations — WRITE / UPDATE_USER / CREATE tagged files
P1-C: Sink aggregator points — DB_AGGREGATOR files from triage.md (reading one covers many call paths)
P1-D: Data leaks + SQL injection — LEAK tagged files + ast-grep SQL sink files

For each file, Read the **complete** handler and apply Q1-Q7.
Pay special attention to:
- **Q5** (Side effects): Public endpoint that modifies state → WHY?
- **Q7** (Intent coherence): Does the code match the endpoint name?
- **Q3** (Data exit): Check every `include` chain — what fields are returned?

**Priority 2 — Shallow Read (triage tags F/G only, not in A-E):**

Read **first 30 lines** of each Q3_FLAG/Q5_FLAG file. Ask only 3 questions:
- Q1: Who can call this? (already known: public)
- Q3: What does the response contain? Any PII/config/secrets?
- Q5: Does it modify state? Is the caller verified?

If Q3 or Q5 reveals a problem → escalate to Priority 1 (full Read + Q1-Q7).
If clean → mark as "shallow-clear" in read-log.

**Priority 3 — No Read needed:**

Public endpoints with zero triage tags (no A-G flags). Mark as "shallow-clear: no flags from F/G scan" in read-log. E1 counts these as covered.

**Output**: `audit/public-endpoint-review.md` — one section per Priority 1 file (Q1-Q7), one line per Priority 2 file (Q1/Q3/Q5 verdict), Priority 3 listed as bulk "cleared by triage".
Batch-write all Step 0 reads to `audit/read-log.md` after Step 0 completes.

**Why master agent?** This step requires semantic reasoning (Q5: "is this mutation authorized?", Q7: "does the code match its name?"). Pattern-matching Droids cannot do this.

**Parallelization**: Step 0 (master reads endpoints) and Step 1+2 (scanner dispatch) can run in parallel. Scanners depend on map.json, NOT on public-endpoint-review.md. Launch scanners immediately after the direction decision — do not wait for Step 0 to complete.

**Real-time Prerequisite Tracking (MANDATORY):**
Whenever Step 0 or Step 0.5 produces any P0/P1 finding, master agent MUST immediately:
1. Append a prerequisite row to `audit/prereq-candidates.md` using this schema:
   - `finding_id`
   - `type` (`user_info` | `credentials` | `session` | `config` | `timing` | `access_token`)
   - `description`
   - `required_for`
   - `search_hint`
   - `resolved` (`true/false`)
   - `resolved_by` (finding_id or null)
2. Run targeted search immediately using `search_hint` across the full `api_root` (not only current module).
3. If matched, Read matched files and evaluate chain linkage now (do not defer to Phase 3).
4. If unresolved, keep `resolved=false` for Phase 3 follow-up.

---

## Step 1: Scanner Direction Decision

Read `audit/map.json`, then apply this decision logic:

| map.json signal | Scanner to invoke | Skip condition |
|----------------|-------------------|----------------|
| `sinks` contains sql_injection/command_injection/ssti/ldap_injection types | **`injection-scanner`** (D1) | No injection-type sinks found |
| `entries` have endpoints without auth, `models` lack ownership fields, or `configs` show weak token config | **`access-scanner`** (D2+D3) | All endpoints authed, all models have ownership, token config solid |
| `sinks` contains deserialization/ssrf/file_operation, or `configs` show hardcoded secrets/debug mode | **`infra-scanner`** (D4-D10) | No infra-related sinks or config issues |

Track declaration:
- D1 / D4-D8 / D10-D12 default to sink-driven + dataflow validation.
- D3 and D9 must run control-driven first (endpoint traversal + CRUD consistency comparison by `controller_group`), then confirm sinks.

**Output a brief decision log before invoking**:
```
Phase 2 Direction Decision:
- injection-scanner: INVOKE (map shows 12 sql sinks, 3 cmd sinks)
- access-scanner: INVOKE (5 models lack ownership, 3 endpoints missing auth)
- infra-scanner: SKIP (no deserialization/SSRF sinks, config looks solid)
Invoking 2 of 3 scanners.
```

---

## Step 2: Scanner Dispatch

For each selected direction, invoke the corresponding Droid via Task tool:
- **`injection-scanner`** — D1: SQL/CMD/LDAP/SSTI injection paths
- **`access-scanner`** — D2+D3: Auth gaps, IDOR, privilege escalation, mass assignment
- **`infra-scanner`** — D4-D10: Deserialization, file ops, SSRF, crypto, config, business logic, supply chain

Each Droid works independently with read-only access.

---

## Step 0.5: Master Review of Scanner ALERT Queues

**Executed by**: Master agent (NOT delegated). This is the "commander reviews sentinel reports" step.

**Prerequisite**: All scanners from Step 2 have returned their ALERT + STATS output.

**Process:**

1. **Load baseline**: Read `audit/business-model.md` (behavior signatures + sensitive data inventory)
2. **Collect ALERTs**: Gather all ALERT entries from the 3 scanner outputs
3. **For each ALERT entry**:
   - Read the source file (if not already read in Step 0)
   - Apply Q1-Q7 with **explicit baseline comparison**:
     - Q3: Cross-reference response fields with sensitive data inventory. "Does this endpoint return settings? Business-model.md says settings cache contains JWT_SECRET → CONFIRMED leak."
     - Q7: Compare code behavior with behavior signatures. "Business-model.md says login never modifies user, but this endpoint calls updateUser → CONFIRMED logic flaw."
   - **Verdict**: Assign P0/P1/P2 severity + brief justification, OR dismiss as false positive with reason
4. **Review STATS L3 samples**: Read the 5 suggested sample endpoints from each scanner's L3 section. Apply Q1/Q3/Q5 (shallow check). If any reveals a problem → escalate to ALERT.
5. **Review STATS L4**: Cross-reference with business-model.md sensitive data inventory. If "N public endpoints touch settings table" is non-zero and settings contains secrets → escalate affected endpoints to ALERT.
6. **False-negative spot-check (MANDATORY)**:
   - For each scanner's key "no-issue" claim, sample at least 3 endpoints/files marked clean.
   - Use an independent strategy (master `rg`/`ast-grep`) for scanner-specific patterns.
   - If any contradiction is found, invalidate that scanner's corresponding "no-issue" conclusions and re-run or master-takeover that dimension.

**Output**: Reviewed findings ready for Step 3 merge. Each has master-assigned severity.

Batch-write all Step 0.5 reads to `audit/read-log.md`.

---

## Step 3: Result Merge

Combine Step 0 findings + Step 0.5 reviewed ALERTs into `audit/risk-map.md` — files ranked by priority P0 (critical) / P1 (high).

**Each risk-map entry MUST include these fields:**

| Field | Required | Description |
|-------|----------|-------------|
| File | yes | File path and line number |
| Sink Type | yes | e.g., sql_injection, command_injection, missing_auth |
| Suspected Dataflow | yes | Initial source → sink fragment |
| Scanner | yes | Which scanner found it |
| chain_role | yes | One of: `ENTRY`, `STEPPING_STONE`, `TERMINAL`, `AMPLIFIER` |
| chain_confidence | yes | One of: `low`, `med`, `high` |
| hypothesis_link | optional | Which hypothesis (H1/H2/...) this finding supports |

**chain_role definitions:**
- `ENTRY`: Attack surface entry point (public endpoint, unauthenticated interface)
- `STEPPING_STONE`: Intermediate capability (info disclosure → enables further attack, SSRF primitive)
- `TERMINAL`: Final impact point (RCE, database read/write, key extraction)
- `AMPLIFIER`: Force multiplier (batch operations, no rate limit, auth bypass enabling other attacks)

**chain_confidence definitions:**
- `low`: Suspected but dataflow not yet traced
- `med`: Partial dataflow confirmed, some gaps remain
- `high`: Full source-to-sink path confirmed with minimal gaps

**Output**: `audit/risk-map.md` with chain metadata for every entry

---

## Step 3.5: Draft Attack Chain Synthesis (Phase 2)

Invoke `security-analyst` once at the end of Phase 2 to produce draft chains for Phase 3 prioritization.

**Input set (Phase 2 draft mode)**:
- `audit/map.json`
- `audit/risk-map.md`
- `audit/hypotheses.md`
- `audit/prereq-candidates.md`

**Output**:
- `audit/attack-chains-draft.md` (draft prerequisite graph + draft attack chains)
