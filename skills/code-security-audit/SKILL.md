---
name: code-security-audit
description: Orchestrates a full automated code security audit across 4 phases - map building, parallel scanning, convergence checking, and deep verification with coverage self-check. Use when the user asks for a security audit, penetration test, vulnerability assessment, or code review focused on security of a web application codebase.
---

# Code Security Audit - Master Orchestrator

## Core Philosophy

Four principles govern every audit decision:

1. **Read before judge** — You cannot find what you have not read. Glob the filesystem to enumerate ALL entry points; grep is a hint, not a source of truth.
2. **No false positives over missed bugs** — Only report code you have READ. Every finding MUST include source-to-sink dataflow evidence. No guessing.
3. **Questions over patterns** — Do not rely on pattern/regex lists to decide what is dangerous. Read code, then ask the 7 universal security questions (see below). Pattern lists are finite; attacker creativity is not.
4. **Decision over search** — The model is smart enough. The bottleneck is: **where to look, how deep, when to stop**.

## 7 Universal Security Questions

For every handler you Read, ask these questions. They replace framework-specific pattern matching:

```
Q1. Trust boundary:  Who can call this? Unauthenticated / authenticated / admin?
Q2. Data entry:      Where does user input come from? (params / query / body / headers / URL path)
Q3. Data exit:       What does the response contain? Any PII / config / secrets / internal state?
Q4. DB interaction:  Does input enter a query? Is it parameterized? Any literal/raw/template concatenation?
Q5. Side effects:    Does this operation modify state? Is the caller's authority verified before mutation?
Q6. External calls:  Does it make network requests? Is the URL derived from user input?
Q7. Intent coherence: Does what the code ACTUALLY DOES match what the endpoint name/docs CLAIM it does?
```

## Audit Dimensions (D1–D12)

| ID | Dimension | One-Line Definition |
|----|-----------|---------------------|
| D1 | Injection | User input reaches SQL/CMD/LDAP/SSTI execution points |
| D2 | Authentication | Token generation, validation, expiration completeness |
| D3 | Authorization | Every sensitive operation verifies user ownership/permission |
| D4 | Deserialization | Untrusted data deserialized |
| D5 | File Operations | Upload/download paths user-controllable |
| D6 | SSRF | Server-side HTTP request URLs user-controllable |
| D7 | Cryptography | Hardcoded keys, weak algorithms, insecure random |
| D8 | Configuration | Debug endpoints, CORS, verbose errors, DoS/ReDoS |
| D9 | Business Logic | Race conditions, skippable workflows, price manipulation, TOCTOU |
| D10 | Supply Chain | Dependencies with known CVEs |
| D11 | Info Disclosure | Public endpoints expose PII/configs/secrets/internal state |
| D12 | Data Exposure | Non-admin responses include unnecessary sensitive fields (over-serialization) |

Note: Attack chains are NOT a dimension. They are enforced via Phase 1 hypotheses + Phase 2.5 convergence check (Q3).

## Phase State Machine

Each phase has an explicit playbook to load, required outputs, and a hard gate.

### Phase 1: Recon & Map Building (10% effort)
- **Load**: Read("~/.factory/skills/code-security-audit/playbooks/phase1-recon.md") and execute all steps
- **Outputs**: `audit/map.json`, `audit/triage.md`, `audit/hypotheses.md`, `audit/read-log.md`, `audit/business-model.md`
- **Gate → Phase 2**: All 5 output files exist. map.json has entries > 0. triage.md has entries > 0. business-model.md has at least 1 module signature + sensitive data inventory.

### Phase 2: Parallel Scanning (30% effort)
- **Load**: Read("~/.factory/skills/code-security-audit/playbooks/phase2-scan.md") and execute all steps
- **Context rule**: Do NOT reference Phase 1 conversation history. Read audit/ files fresh.
- **Outputs**: `audit/public-endpoint-review.md`, `audit/risk-map.md`
- **Gate → Phase 2.5**: Both output files exist.

### Phase 2.5: Convergence Check
- **Load**: Read("~/.factory/skills/code-security-audit/playbooks/phase2.5-check.md") and execute all checks
- **Gate → Phase 3**: D1/D2/D3 ✅ + E1/E2/E4/E5 ✅ + convergence Q1/Q2/Q3 all NO. Otherwise → R2 then re-check.

### Phase 3: Deep Verification (40% effort)
- **Load**: Read("~/.factory/skills/code-security-audit/playbooks/phase3-verify.md") and execute all steps
- **Context rule**: Do NOT reference Phase 1/2 conversation history. Read audit/ files fresh.
- **Outputs**: `audit/findings.md`, `audit/dataflow.md`, `audit/findings-consolidated.md`

### Phase 4: Report (20% effort)
- **Load**: Read("~/.factory/skills/code-security-audit/output-templates.md") for format, generate `audit/report.md`
- **Outputs**: `audit/report.md`

**Hard rule**: If ANY phase's required output files do not exist, the next phase MUST NOT begin. This is a prohibition, not a suggestion.

**Context isolation**: Each phase reads its inputs from audit/ files, not from conversation memory. Phase 1 outputs a ≤20 line summary before proceeding. Phases 2+ start by reading files, not by recalling what happened before.

## Output Protocol

**Anti-repetition**: If the same status message appears >2 times consecutively, collapse into one line + immediately execute the next tool call. If >3 repetitions occur, treat as a loop — stop text output and proceed to the next Step.

**Output cap**: A single chat response MUST NOT exceed 80 lines of content. If a tool result (rg --json, ast-grep --json, scanner output) exceeds 80 lines, write the full output to an audit/ file and display only a summary + top 10 entries in chat.

**Phase-end summary**: Every phase (not just Phase 1) ends with a ≤15 line summary before proceeding. Format:
- Phase N complete. Key stats: [counts]. Next: Phase N+1.

## Attack Hypothesis Framework

After Phase 1 map building, generate 3–5 attack hypotheses in `audit/hypotheses.md`.

**Rules:**
1. Hypotheses MUST be grounded in map.json entries only (do NOT invent endpoints not in the map)
2. Each hypothesis MUST include: Claim, Evidence (map/triage references), Missing links, Status (open/supported/refuted)
3. Missing links drive Phase 2 search priorities

**Primitive labels (chain_role)** — required on each risk-map entry in Phase 2:

| Label | Meaning |
|-------|---------|
| ENTRY | Attack surface entry point (public endpoint, unauthenticated interface) |
| STEPPING_STONE | Intermediate capability (info leak, SSRF primitive) |
| TERMINAL | Final impact point (RCE, DB read/write, key extraction) |
| AMPLIFIER | Force multiplier (batch ops, no rate limit, auth bypass) |

Attach `chain_confidence: low|med|high` to indicate dataflow completeness (not vulnerability confirmation).

## Agent Constraint Rules (3 Rules Only)

### Rule 1: Only report code you have READ
- Never guess file paths or code content.
- All code citations must come from actual Read tool output.

### Rule 2: Every finding must have dataflow evidence
- Must specify: **Entry point → Intermediate processing → Sink point**.
- A single dangerous function call (e.g., `exec(cmd)`) without source tracing is NOT a valid finding.

### Rule 3: Structured output only
- Every vulnerability must follow the fixed template. No free-form prose.

```
## [Type] SQL Injection
- File: `src/main/java/.../UserDAO.java:45`
- Entry: `HttpServletRequest.getParameter("id")`
- Sink: `Statement.executeQuery(sql)`
- Dataflow: `id` → `String.format("SELECT * FROM user WHERE id = %s", id)`
- Verification: No sanitization, integer param accepts `1 OR 1=1`
- Severity: Critical
```

## Output Files

All outputs go to `audit/` directory. See [output-templates.md](~/.factory/skills/code-security-audit/output-templates.md) for complete format specifications.

| File | Phase | Format | Content |
|------|-------|--------|---------|
| `audit/map.json` | 1 | JSON | Tech stack, entries, sinks, configs, models, modules |
| `audit/risk-map.md` | 2 | Markdown | P0/P1 prioritized file list with sink types |
| `audit/dataflow.md` | 3 | Markdown | Complete Source→Transform→Sink chains |
| `audit/findings.md` | 3 | Markdown | Vulnerability details: type, severity, conditions, remediation |
| `audit/report.md` | 4 | Markdown | Executive summary, coverage stats, attack chains |

Additional mandatory artifacts not in output-templates.md: `audit/hypotheses.md`, `audit/read-log.md`. These are protocol artifacts required by the phase state machine.

## Supported Languages

- **Python**: Flask, Django, FastAPI, Tornado
- **Java**: Spring Boot, Struts, Servlet
- **Go**: Gin, Echo, net/http
- **PHP**: Laravel, ThinkPHP, raw PHP
- **Node.js**: Express, Koa, Fastify, **Nitro/Nuxt (file-based routing)**, Next.js, SvelteKit, Remix
