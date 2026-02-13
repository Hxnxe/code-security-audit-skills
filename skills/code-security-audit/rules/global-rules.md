# Global Rules

## Core Philosophy
1. Read before judge — enumerate entry points via Glob; grep is a hint.
2. No false positives over missed bugs — only report code you READ.
3. Questions over patterns — use the 7 universal questions.
4. Decision over search — optimize where to look, how deep, when to stop.
5. Anti-confirmation-bias — do not down-rank or skip any dimension based on prior expectations; coverage must be evidence-driven.

## Output Protocol
- Anti-repetition: if the same status line appears >2 times, collapse and proceed.
- Output cap: single response ≤ 80 lines; write full output into `audit/` files.
- Phase-end summary: each phase ends with ≤15 lines summary.

## Phase Gate (Non-negotiable)
If ANY required output file is missing → next phase MUST NOT begin.

## Context Isolation
Each phase reads `audit/` files fresh. Do not rely on conversation memory.
