# Code Security Audit Skills

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**English** | [中文文档](PROJECT-INTRODUCTION.zh-CN.md)

A structured, phase-gated AI-powered code security audit framework designed for Web applications. Unlike single-pass scanners, this system implements a rigorous 4-phase workflow with hard gates, artifact contracts, and role-based agent coordination.

## Why This Project?

Common AI security tools suffer from:
- No convergence checks → unmanageable false positives/negatives
- No phase gates → unstable, skip-prone workflows
- No artifact contracts → scattered results, poor collaboration
- Reports not reproduction-ready → hard to action

**This framework solves these with:**
- 4-phase hard-gated workflow (Phase 1→2→2.5→3→4)
- Unified `audit/` artifact contract for all phases
- Scanner (candidate) / Validator (deep verify) separation
- Attack-chain priority verification
- Reproduction-ready Chinese reports with PoCs

## Quick Start

### Installation

#### Codex (Project-level)
```bash
# Place skills in project directory
mkdir -p .codex/skills
cp -r skills/code-security-audit .codex/skills/
```

#### OpenCode
```bash
mkdir -p .opencode/skills
cp -r unified-skills/opencode .opencode/skills/code-security-audit
```

### Usage
```
Use skill code-security-audit to run the full workflow 
(Phase 1->2->2.5->3->4) on repository [target-repo]
```

## Supported Languages & Frameworks

| Language | Frameworks |
|----------|-----------|
| Python | Flask, Django, FastAPI, Tornado |
| Java | Spring Boot, Struts, Servlet |
| Go | Gin, Echo, net/http |
| PHP | Laravel, ThinkPHP |
| Node.js | Express, Koa, Fastify, Nitro/Nuxt, Next.js, SvelteKit, Remix |

## Workflow Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Phase 1: Recon & Map Building                              │
│  - Entry point enumeration (Glob is truth, grep is hint)    │
│  - Sink/Model/Config discovery                              │
│  - Attack hypothesis generation                             │
│  - Business mental model construction                       │
│  Gate: Manifest Coverage >= 95%                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 2: Parallel Candidate Scan                           │
│  - 6 scanners run in parallel (injection/access/infra...)   │
│  - ALERT + STATS output (no final severity)                 │
│  - Master agent semantic review                             │
│  - Attack-chain draft generation                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 2.5: Coverage & Convergence Gate                     │
│  - D1/D2/D3/D11/D12 must be ✅ (hard gate)                  │
│  - E1/E2/E4/E5/E6 must be ✅ (hard gate)                    │
│  - If failed → R2 remediation loop                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 3: Deep Verification                                 │
│  - Dataflow tracing (entry → transform → sink)              │
│  - Four-step verification per finding                       │
│  - PoC generation for Critical/High                         │
│  - Finding consolidation & deduplication                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 4: Report Generation                                 │
│  - Full Chinese reproduction-oriented report                │
│  - Attack chain walkthrough (AC-001, AC-002...)             │
│  - PoC for all Critical/High findings                       │
│  - Priority-ordered remediation guide                       │
└─────────────────────────────────────────────────────────────┘
```

## Audit Dimensions (D1-D12)

| Dimension | Focus Area |
|-----------|-----------|
| D1 | Injection (SQL, Command, LDAP, SSTI) |
| D2 | Broken Authentication |
| D3 | Sensitive Data Exposure |
| D4 | XML External Entities |
| D5 | Broken Access Control |
| D6 | Security Misconfiguration |
| D7 | Cross-Site Scripting (XSS) |
| D8 | Insecure Deserialization |
| D9 | Using Components with Known Vulnerabilities |
| D10 | Insufficient Logging & Monitoring |
| D11 | SSRF (Server-Side Request Forgery) |
| D12 | Crypto & Secrets Management |

## Universal Questions (Q1-Q7)

Every endpoint is evaluated against these semantic questions:

| Question | Purpose |
|----------|---------|
| Q1 | Does the endpoint perform untrusted input handling? |
| Q2 | Are there authentication/authorization bypass risks? |
| Q3 | Does the response contain sensitive data leakage? |
| Q4 | Are there unsafe deserialization or file operations? |
| Q5 | Does the endpoint have unintended write operations? |
| Q6 | Are there race conditions or TOCTOU vulnerabilities? |
| Q7 | Does the code behavior match business expectations? |

## Directory Structure

```
code-security-audit-skills/
├── skills/
│   └── code-security-audit/
│       ├── playbooks/          # Phase 1-4 execution guides
│       ├── rules/              # Global rules, scope, constraints
│       └── output-templates.md # Report & finding templates
├── droids/
│   └── droids/                 # Agent role definitions
│       ├── injection-scanner.md
│       ├── access-scanner.md
│       ├── dataflow-analyzer.md
│       └── ...
├── unified-skills/             # Cross-runtime packages
│   ├── codex/                  # Codex runtime
│   ├── opencode/               # OpenCode runtime
│   ├── droid/                  # Direct prompt mode
│   ├── shared/                 # Shared gates & contracts
│   └── templates/              # Subtask templates
└── PROJECT-INTRODUCTION.zh-CN.md
```

## Output Artifacts

All outputs are written to `audit/` directory:

| Phase | Artifacts |
|-------|-----------|
| 1 | `map.json`, `triage.md`, `hypotheses.md`, `read-log.md`, `business-model.md` |
| 2 | `public-endpoint-review.md`, `risk-map.md`, `prereq-candidates.md`, `attack-chains-draft.md` |
| 3 | `dataflow.md`, `findings.md`, `findings-consolidated.md`, `pocs.md` |
| 4 | `report.md` (Chinese, reproduction-oriented) |

## Key Features

### Hard Gates
- Manifest Coverage Gate: `entries/route_files >= 95%`
- Phase 2.5 Gate: D1/D2/D3/D11/D12 + E1/E2/E4/E5/E6 must pass
- No phase skipping allowed

### Artifact Contract
- All phases read/write to `audit/` directory
- Structured JSON for automation
- Human-readable markdown for review

### Scanner/Validator Separation
- Phase 2 scanners: candidate discovery only (ALERT/STATS)
- Phase 3 validators: deep verification with evidence
- Master agent: final severity assignment

### Attack-Chain Priority
- Phase 2 generates attack chain drafts
- Phase 3 verifies by chain priority
- Report includes full chain walkthrough

## Comparison with Alternatives

| Feature | This Framework | Typical AI Scanner |
|---------|---------------|-------------------|
| Phase gates | Hard gates | Single pass |
| Artifact contract | Structured `audit/` | Chat output |
| Role separation | Scanner ≠ Validator | Single agent |
| Report quality | Reproduction-ready | Explanatory only |
| Attack chains | Full chain analysis | Isolated findings |

## Requirements

- Read access to target codebase
- Write access to `audit/` directory
- Text search capability (e.g., `ripgrep`)
- (Optional) LSP for precise code navigation in Phase 3

## Limitations

- Does not replace dynamic penetration testing
- Does not replace manual business logic review
- Requires platform support for skill registration

## Roadmap

- More runtime adapters
- Language/framework-specific policy packs
- CI/CD integration for PR/diff auditing
- Auto-generated patch suggestions

## License

MIT License - see LICENSE for details.

---

**Core Value**: This project is not "yet another scanner" — it's about **productizing AI security audit workflows**: executable, verifiable, reviewable, deliverable, and reproducible.
