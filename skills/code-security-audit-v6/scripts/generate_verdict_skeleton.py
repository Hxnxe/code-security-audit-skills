#!/usr/bin/env python3
"""Generate schema-valid verdict skeleton from findings.jsonl.

This script removes schema-guessing from LLM execution:
- machine builds the exact verdict structure
- LLM only fills what_was_checked / why_failed / result evidence details
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


DEFAULT_STRATEGIES: Tuple[str, str] = ("AUTHZ_GUARD_EXISTS", "SANITIZER_PRESENT")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate verdict skeleton from findings.jsonl")
    parser.add_argument("audit_dir", nargs="?", default="audit", help="Audit directory")
    parser.add_argument(
        "--findings",
        default=None,
        help="Findings JSONL path (default: <audit_dir>/findings.jsonl)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output verdict skeleton path (default: <audit_dir>/verdict.skeleton.json)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting existing output file",
    )
    return parser.parse_args()


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                out.append(obj)
    return out


def finding_id_key(record: Dict[str, Any]) -> Tuple[int, str]:
    finding_id = str(record.get("id") or record.get("finding_id") or "")
    if finding_id.startswith("F-"):
        suffix = finding_id[2:]
        if suffix.isdigit():
            return (int(suffix), finding_id)
    return (10**9, finding_id)


def pick_reference(record: Dict[str, Any]) -> Tuple[str, int, int]:
    evidence = record.get("evidence_bundle", {})
    if isinstance(evidence, dict):
        refs = evidence.get("primary_refs", [])
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                file_path = str(ref.get("file", "")).strip()
                line_start = int(ref.get("line_start", 0) or 0)
                line_end = int(ref.get("line_end", 0) or 0)
                if file_path and line_start > 0 and line_end >= line_start:
                    tool = str(ref.get("tool", "")).strip().upper() or "READ"
                    if tool not in {"LSP", "AST_GREP", "RG", "GLOB", "READ", "BASH"}:
                        tool = "READ"
                    return file_path, line_start, line_end

    file_path = str(record.get("file", "")).strip() or "TODO_FILE"
    line = int(record.get("line", 1) or 1)
    if line < 1:
        line = 1
    return file_path, line, line


def make_disproof_attempt(strategy: str, file_path: str, line_start: int, line_end: int) -> Dict[str, Any]:
    return {
        "strategy": strategy,
        "what_was_checked": f"TODO: verify {strategy} around cited code path",
        "evidence_citations": [
            {
                "tool": "READ",
                "file": file_path,
                "line_start": line_start,
                "line_end": line_end,
            }
        ],
        "result": "FAILED_TO_DISPROVE",
    }


def make_confirmation_basis(strategies: Iterable[str], file_path: str, line_start: int, line_end: int) -> Dict[str, Any]:
    return {
        "failed_strategies": [
            {
                "strategy": strategy,
                "why_failed": f"TODO: explain why {strategy} cannot disprove finding",
                "checked_locations": [f"{file_path}:{line_start}-{line_end}"],
            }
            for strategy in strategies
        ]
    }


def build_verdict_record(record: Dict[str, Any]) -> Dict[str, Any]:
    finding_id = str(record.get("id") or record.get("finding_id") or "").strip()
    if not finding_id:
        raise ValueError("finding record missing id/finding_id")

    file_path, line_start, line_end = pick_reference(record)
    attempts = [
        make_disproof_attempt(DEFAULT_STRATEGIES[0], file_path, line_start, line_end),
        make_disproof_attempt(DEFAULT_STRATEGIES[1], file_path, line_start, line_end),
    ]

    return {
        "schema_version": 1,
        "finding_id": finding_id,
        "validity_verdict": "CONFIRMED",
        "severity_action": "UNCHANGED",
        "disproof_attempts": attempts,
        "confirmation_basis": make_confirmation_basis(DEFAULT_STRATEGIES, file_path, line_start, line_end),
        "independent_code_refs": [
            {
                "tool": "READ",
                "file": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "note": "TODO: replace/confirm with independent evidence if needed",
            }
        ],
    }


def main() -> int:
    args = parse_args()
    audit_dir = Path(args.audit_dir).resolve()
    findings_path = Path(args.findings) if args.findings else audit_dir / "findings.jsonl"
    out_path = Path(args.out) if args.out else audit_dir / "verdict.skeleton.json"

    if not findings_path.exists():
        print(f"error: findings.jsonl not found: {findings_path}")
        return 1

    if out_path.exists() and not args.overwrite:
        print(f"error: output already exists: {out_path} (use --overwrite)")
        return 1

    findings = load_jsonl(findings_path)
    if not findings:
        print(f"error: findings list is empty: {findings_path}")
        return 1

    findings_sorted = sorted(findings, key=finding_id_key)
    verdicts = [build_verdict_record(row) for row in findings_sorted]

    payload = {
        "schema_version": 1,
        "verdicts": verdicts,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"generated verdict skeleton: {out_path} (verdicts={len(verdicts)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
