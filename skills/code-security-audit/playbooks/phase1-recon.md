# Phase 1: Reconnaissance & Map Building

## Gate Check (Entry)

No prior artifacts required — this is the first phase.

---

## Code Navigation Strategy

This audit relies on three capabilities working together:
- **Skills** define HOW to audit (the methodology)
- **Code navigation** provides the ability to UNDERSTAND code (like an IDE)
- **The model** reasons about security implications

For code navigation, use LSP-equivalent techniques throughout all phases:

| IDE Action | Implementation | When to Use |
|-----------|---------------|-------------|
| **Go-to-definition** | `rg "def func_name\|function func_name\|const func_name"` then Read | Understanding what a function does |
| **Find-references** | `rg "func_name\("` scoped to relevant dirs | Finding all callers of a function |
| **Follow-the-data** | Read caller → map param position → Read callee → trace renamed var | Tracking data across function boundaries |
| **Scope-aware search** | `rg "pattern" specific/directory/ -n` | Narrowing search to relevant module |
| **Structural search** | `ast-grep -p 'PATTERN' --lang LANG --json` | Distinguishing dangerous calls from safe ones by AST structure (see below) |

**PREFER precise navigation over broad grep.** Instead of `grep -rn "eval" .`, do `rg "eval\(" src/routes/ --type js -n` — scope matters for accuracy and token efficiency.

### ast-grep: Structural Code Search (Optional Enhancement)

**ast-grep** (tree-sitter based) understands code structure, not just text. It fills a gap ripgrep cannot: distinguishing safe calls from dangerous ones by AST node type.

**When to use ast-grep instead of ripgrep:**

| Scenario | ripgrep (text) | ast-grep (AST) |
|----------|---------------|-----------------|
| Find all calls to `Sequelize.literal(` | `rg "Sequelize\.literal\("` — finds ALL calls | `ast-grep -p 'Sequelize.literal(\`$$$\`)' --lang ts` — finds only calls with template literals (dangerous) |
| Find template string SQL | `rg "\.query\("` — finds safe and unsafe | `ast-grep -p '$DB.query(\`$$$\`)' --lang ts` — finds only template literal queries |
| Multiline code | Misses across line breaks | Matches regardless of formatting |

**Usage**: Check availability first: `which ast-grep || which sg`. If not installed, fall back to ripgrep + Read to manually verify each match.

**Key patterns for security scanning:**
```bash
# ORM escape hatch with template literal (dangerous)
ast-grep -p 'Sequelize.literal(`$$$`)' --lang ts --json
ast-grep -p '$OBJ.raw(`$$$`)' --lang ts --json
ast-grep -p '$OBJ.query(`$$$`)' --lang ts --json

# Python f-string in SQL context
ast-grep -p 'text(f"$$$")' --lang py --json
ast-grep -p 'execute(f"$$$")' --lang py --json

# Command injection with template
ast-grep -p 'exec(`$$$`)' --lang ts --json
```

---

## Step 1: Entry Point Exhaustive Enumeration

**Principle: Glob is truth, grep is a hint. Use Glob to find ALL route files, then Read metadata.**

**Executed by**: Master agent (NOT delegated)

1. **Detect routing strategy** by checking project files:
   - `nitro.config.ts` / `nuxt.config.ts` → Nitro file-based routing
   - `next.config.js` / `app/` directory → Next.js App Router
   - `svelte.config.js` → SvelteKit
   - `package.json` with express/koa/fastify → Explicit route registration
   - `requirements.txt` / `manage.py` → Django/Flask
   - `pom.xml` / `build.gradle` → Spring Boot

2. **File-based routing** (Nitro/Next/SvelteKit/Remix):
   ```
   Glob: ["**/*.get.ts", "**/*.post.ts", "**/*.put.ts", "**/*.del.ts",
          "**/*.delete.ts", "**/*.patch.ts", "**/*.ws.ts",
          "**/*.get.js", "**/*.post.js", "**/route.ts", "**/route.js",
          "**/+page.server.ts", "**/+server.ts"]
   in the discovered API root directory
   ```
   Derive route path from file path. `[param]` = dynamic segment, `(group)` = invisible group.

   **Batch metadata extraction** (do NOT Read each file individually):
   ```bash
   # One command extracts auth status for ALL route files
   rg "requiresAuth" --type ts -n {api_root} --json
   ```
   Parse the JSON output to classify each file. Only Read individual files if `requiresAuth` is ambiguous or missing from rg output.

3. **Explicit routing** (Express/Flask/Spring/Gin):
   grep for route registrations AND Glob for `routes/`, `controllers/`, `api/`, `views/` directories.
   **Validation**: If Glob file count > 2x grep entry count → grep missed entries, master agent Reads all Glob-found files directly.

4. **Classify every entry**:
   - 🔴 **Public** (`requiresAuth: false` or no auth middleware)
   - 🟡 **Authenticated** (`requiresAuth: true`)
   - ⚪ **Admin** (requires admin role)

**Output**: `audit/map.json` with `entries` array populated.

---

## Step 1.5: ast-grep Triage

**Goal**: Before any sub-agent launches, use ast-grep + rg to produce a high-risk file shortlist. This runs in <30 seconds and costs 0 LLM tokens.

**Executed by**: Master agent (NOT delegated)

**Prerequisite**: `which ast-grep` — if not installed, skip to manual Step 0 in Phase 2.

Run these commands and save output to `audit/triage.md`:

**A. Public endpoints with write operations (account takeover class):**
```bash
for f in $(rg -l "requiresAuth: false" {api_root}); do
  ast-grep -p 'models.$M.update($$$)' --lang ts "$f" --json 2>/dev/null | \
    python3 -c "import json,sys;d=json.load(sys.stdin);[print(f'WRITE: {f}:{i[\"range\"][\"start\"][\"line\"]}') for i in d]" 2>/dev/null
  ast-grep -p 'updateUser($$$)' --lang ts "$f" --json 2>/dev/null | \
    python3 -c "import json,sys;d=json.load(sys.stdin);[print(f'UPDATE_USER: {f}:{i[\"range\"][\"start\"][\"line\"]}') for i in d]" 2>/dev/null
  ast-grep -p 'models.$M.create($$$)' --lang ts "$f" --json 2>/dev/null | \
    python3 -c "import json,sys;d=json.load(sys.stdin);[print(f'CREATE: {f}:{i[\"range\"][\"start\"][\"line\"]}') for i in d]" 2>/dev/null
done
```

**B. SQL injection sinks (template literal only — safe calls excluded):**
```bash
ast-grep -p 'Sequelize.literal(`$$$`)' --lang ts --json
ast-grep -p 'sequelize.literal(`$$$`)' --lang ts --json
ast-grep -p '$OBJ.query(`$$$`)' --lang ts --json
```

**C. Public endpoints leaking sensitive fields:**
```bash
for f in $(rg -l "requiresAuth: false" {api_root} | grep -v admin); do
  has_user=$(rg -c "model: models.user" "$f" 2>/dev/null || echo 0)
  has_email=$(rg -c '"email"' "$f" 2>/dev/null || echo 0)
  [ "$has_user" -gt 0 ] && [ "$has_email" -gt 0 ] && echo "LEAK: $f"
done
```

**D. Reverse trace from high-value assets:**
```bash
echo "=== Who modifies user password? ==="
rg "hashedPassword|\.update.*password" --type ts -l {api_root}
echo "=== Who queries master wallet? ==="
rg "ecosystemMasterWallet|ecosystem_master_wallet" --type ts -l
echo "=== Who queries wallet private keys? ==="
rg "walletData|wallet_data" --type ts -l {api_root}
```

**E. Sink Aggregator Identification:**

Identify security-critical aggregation points (functions/modules called by many files):

1. **Auth aggregators (path heuristic):**
   Glob: ["**/auth/utils.*", "**/auth/helpers.*", "**/middleware/auth.*",
          "**/lib/auth.*", "**/guards/*", "**/policies/*", "**/interceptors/auth*"]
   → Mark each found file as AUTH_AGGREGATOR

2. **DB/query wrapper aggregators (path heuristic):**
   Glob: ["**/utils/query.*", "**/utils/db.*", "**/helpers/db.*",
          "**/lib/database.*", "**/db/wrapper.*", "**/services/base*"]
   → Mark each found file as DB_AGGREGATOR

Processing rule: AUTH_AGGREGATOR and DB_AGGREGATOR files enter Phase 2 Step 0 Priority 1.

**F. Q3 bulk scan — data exit analysis in ALL public endpoints:**

Three sub-scans (F1/F2/F3) to catch different data exit patterns:

```bash
# F1: Sensitive field names in source code
for f in $(rg -l "requiresAuth: false" {api_root}); do
  rg -c '"email"|"password"|"secret"|"key"|"token"|"phone"|"private"' "$f" 2>/dev/null | \
    grep -v '^0$' && echo "Q3_FLAG_F1: $f"
done

# F2: Indirect data exits — returns cache/config/settings objects (no sensitive keywords in source,
#     but the returned object contains secrets at runtime)
for f in $(rg -l "requiresAuth: false" {api_root}); do
  rg -c "getSettings|getConfig|cache\.get|cacheManager|process\.env|\.env\b" "$f" 2>/dev/null | \
    grep -v '^0$' && echo "Q3_FLAG_F2: $f"
done

# F3: Deep include chains (include depth >= 2 means nested model joins — high PII leak risk)
for f in $(rg -l "requiresAuth: false" {api_root}); do
  # Count lines containing "include:" or "include: [" — depth >= 2 means nested includes
  depth=$(rg -c "include:" "$f" 2>/dev/null || echo 0)
  [ "$depth" -ge 2 ] && echo "Q3_FLAG_F3: $f (include_depth=$depth)"
done
```

F1 catches direct PII in attributes. F2 catches settings/config/cache object returns. F3 catches nested ORM include chains that pull in user.email etc.

**G. Q5 bulk scan — write operations in ALL public endpoints:**
```bash
for f in $(rg -l "requiresAuth: false" {api_root}); do
  rg -c "\.update\(|\.create\(|\.destroy\(|\.delete\(|\.save\(|\.upsert\(" "$f" 2>/dev/null | \
    grep -v '^0$' && echo "Q5_FLAG: $f"
done
```
This catches public-endpoint-with-side-effects that ast-grep A-class may miss due to non-standard function names.

**Processing rule for F/G**: Files tagged Q3_FLAG or Q5_FLAG that are NOT already tagged by A-E are added to triage.md as secondary priority. They enter Phase 2 Step 0 Priority 2 (shallow read — first 30 lines + Q1/Q3/Q5 only, not full Q1-Q7).

**Output**: `audit/triage.md` with tagged entries.

**Processing rules summary**:
- A/B/C/D/E tags → Phase 2 Step 0 **Priority 1** (deep read: full handler + Q1-Q7)
- F/G tags (not already in A-E) → Phase 2 Step 0 **Priority 2** (shallow read: first 30 lines + Q1/Q3/Q5)
- Remaining public endpoints (no tags) → **Priority 3** (marked "shallow-clear" in read-log, no Read needed)

---

## Step 2: Parallel Sub-agent Map Building

Invoke these Droids in parallel:
1. **`sink-point-scanner`** Droid — Dangerous sink points → `map.json#sinks`
2. **`security-asset-scanner`** Droid — Sensitive configs, secrets, crypto → `map.json#configs`
3. **`data-model-analyzer`** Droid — Data models, ownership, relationships → `map.json#models`

Note: `web-entry-discovery` is NO LONGER delegated. Step 1 above replaces it.

---

## Step 3: Sub-agent Result Validation

**MANDATORY** after each sub-agent returns.

The master agent validates:

- **Looping detection**: If output contains the same sentence repeated > 3 times → sub-agent failed, master agent takes over that task.
- **sink-point-scanner check**: Run `rg "\.(literal|raw|extra|text|unsafe)\(" --type ts --type js --type py` independently. If matches exist but are absent from sinks list → master agent supplements.
- **Completeness check**: If any sub-agent returns 0 results → treat as failure, master agent runs the scan directly.

---

## Step 4: Merge into map.json

Merge all outputs into `audit/map.json`:
- `tech_stack`: language, framework, middleware, ORM, auth mechanism
- `entries`: all HTTP entry points with route, method, handler, auth status, trust level (🔴/🟡/⚪)
- `sinks`: all dangerous sinks with type, file, line, function
- `configs`: security-relevant configurations and secrets
- `models`: data models with ownership relationships
- `modules`: functional module breakdown
- `public_endpoints`: filtered list of all 🔴 public entries (for Phase 2 Step 0)

---

## Step 5: Attack Hypothesis Generation

Based on map.json + triage.md, generate 3–5 attack hypotheses and save to `audit/hypotheses.md`.

**Rules:**
1. Every hypothesis MUST be grounded in map.json entries (discovered modules, entry points, assets). Do NOT invent endpoints or capabilities not found in the map.
2. Each hypothesis MUST include:
   - **Claim**: What the attacker achieves (e.g., "Anonymous user achieves account takeover")
   - **Evidence**: Which specific map.json/triage.md entries support this (file paths, entry IDs)
   - **Missing links**: Which primitives are needed but not yet confirmed (drives Phase 2 priority search)
   - **Status**: `open` (initial) / `supported` / `refuted`
3. Missing links become Phase 2's priority search targets.

**Example hypothesis:**
| Field | Value |
|-------|-------|
| Claim | Anonymous → account takeover via public write endpoint |
| Evidence | triage.md WRITE tag on `/api/user/update`, map.json shows auth_required=false |
| Missing links | Need to confirm if password/email fields are writable without auth |
| Status | open |

**Output**: `audit/hypotheses.md`

---

## Step 6: Business Mental Model Construction

**Goal**: Build a behavioral baseline so Phase 2 can detect "code does something it shouldn't" (Q7) and "response contains something it shouldn't" (Q3).

**Executed by**: Master agent (NOT delegated). This requires LLM semantic reasoning.

**Process:**

1. **Module identification**: From map.json entries, group endpoints by top-level module (auth, wallet, exchange, blog, admin, settings, etc.)

2. **Representative endpoint selection (LLM decides)**: For each module, choose 1-2 endpoints that represent the module's core operation. Selection heuristic:
   - Auth module → the main login endpoint + the main register endpoint
   - Financial modules → the main withdraw/transfer endpoint
   - Content modules → the main detail/show endpoint (not list)
   - Settings → the main settings retrieval endpoint
   - Admin → one representative admin-only endpoint

3. **Read 5-8 representative endpoints** (full handler). For each, extract:
   - **Normal behavior signature**: What this endpoint does, step by step ("verify password → check match → createSession. Does NOT modify user.")
   - **Data returned**: What fields/objects appear in the response
   - **Auth model**: How this module handles authentication/authorization

4. **Sensitive data inventory**: From models in map.json + representative endpoint reads, list:
   - Which database tables/caches contain secrets (Settings cache → JWT_SECRET, SMTP_PASSWORD, payment keys)
   - Which models have PII fields (User → email, phone; Wallet → private_key)
   - Which objects MUST NOT appear in public responses

**Output**: `audit/business-model.md`

```markdown
## Module Behavior Signatures

### Auth
- Normal login (index.post.ts): verify email+password → if match → createSession. Never modifies user data.
- Normal register (register.post.ts): check email unique → hash password → create user → createSession.

### Wallet
- Withdraw: requires auth + 2FA + ownership check on wallet_id.
...

## Sensitive Data Inventory

| Source | Sensitive fields | Must NOT be in public response |
|--------|-----------------|-------------------------------|
| Settings cache | JWT_SECRET, SMTP_PASSWORD, payment gateway keys | Any public endpoint returning settings |
| User model | email, phone, hashedPassword | Public endpoints (only expose to self/admin) |
| Wallet model | private_key, mnemonic | Any non-admin endpoint |
```

**Budget**: 5-8 Read calls. This step should take < 3 minutes.

**Output**: `audit/business-model.md`

---

## Read Log Protocol

`audit/read-log.md` tracks which files were actually Read. It is the canonical evidence for E1/E2/E5 coverage verification in Phase 2.5.

**Schema:**

| phase | file | range | purpose | auth |
|-------|------|-------|---------|------|
| 1 | src/routes/login.post.ts | 1-45 | entry | public |
| 2 | src/middleware/auth.ts | full | aggregator | n/a |

**Batch write rule (CRITICAL for performance):**
- Do NOT append after every Read. This would double tool call count.
- Instead: mentally track reads during each Step, then write ALL rows for that Step in ONE batch at Step end.
- Phase 1 → one write at end of Phase 1 (all Steps combined)
- Phase 2 Step 0 → one write after Step 0 completes
- Phase 2 Scanners → master merges sub-agent reads in one write after Step 3
- Phase 3 → one write after all Phase 3 sub-agents return

**Output**: `audit/read-log.md`

---

## Phase 1 Completion Protocol

When ALL Phase 1 steps are done, output a **Phase 1 Summary** (max 20 lines):

```
## Phase 1 Summary
- Tech stack: [language] + [framework] + [ORM] + [auth mechanism]
- Total endpoints: N (public: X, authenticated: Y, admin: Z)
- Triage hits: N files tagged (WRITE: A, LEAK: B, SQL: C, AGGREGATOR: D)
- Hypotheses: H1 [one-line], H2 [one-line], H3 [one-line]
- Key risk areas: [2-3 sentence summary]
```

Then proceed to Phase 2. All detailed data is in audit/ files — do NOT carry Phase 1 conversation details forward mentally.

---

## Attack Hypothesis Framework (Phase 1 Output)

Generate 3–5 attack hypotheses in `audit/hypotheses.md`.

Rules:
1. Must be grounded in map.json entries only.
2. Each includes: Claim, Evidence (map/triage refs), Missing links, Status.
3. Missing links drive Phase 2 priority search.

Output fields:
- Claim
- Evidence
- Missing links
- Status: open/supported/refuted
