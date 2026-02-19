#!/usr/bin/env python3
"""Export chains.json from attack-graph.md with findings.md fallback."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import validate_schema as schema_validator
from shared_utils import get_verified_finding_ids


CHAIN_HEADING_RE = re.compile(
    r"^###\s*(?:攻击链|Attack\s*Chain)\s*(AC-[A-Za-z0-9_-]+)\s*:\s*(.+?)\s*$",
    re.IGNORECASE,
)
FINDING_REF_RE = re.compile(r"(F-[A-Za-z0-9_-]+)")
PIPE_ROW_RE = re.compile(r"^\|.*\|$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export chains.json from attack-graph/findings"
    )
    parser.add_argument("audit_dir", nargs="?", default="audit", help="Audit directory")
    parser.add_argument("--attack-graph", default=None, help="attack-graph.md path")
    parser.add_argument("--findings", default=None, help="findings.md path")
    parser.add_argument(
        "--out", default=None, help="output path (default: <audit_dir>/chains.json)"
    )
    parser.add_argument(
        "--overwrite", action="store_true", help="overwrite output if exists"
    )
    return parser.parse_args()


def normalize_file_line_refs(text: str) -> List[str]:
    refs: List[str] = []
    for token in re.split(r"[,\s]+", text):
        value = token.strip()
        if ":" in value and "/" in value:
            refs.append(value)
    return refs


def finding_ids_in_text(text: str) -> List[str]:
    found: List[str] = []
    for match in FINDING_REF_RE.finditer(text):
        fid = match.group(1)
        if fid not in found:
            found.append(fid)
    return found


def parse_chain_blocks(text: str) -> List[Tuple[str, str, List[str]]]:
    blocks: List[Tuple[str, str, List[str]]] = []
    current_id = ""
    current_title = ""
    current_lines: List[str] = []
    for raw in text.splitlines():
        m = CHAIN_HEADING_RE.match(raw.strip())
        if m:
            if current_id:
                blocks.append((current_id, current_title, current_lines))
            current_id = m.group(1).strip()
            current_title = m.group(2).strip()
            current_lines = []
            continue
        if current_id:
            current_lines.append(raw)
    if current_id:
        blocks.append((current_id, current_title, current_lines))
    return blocks


def parse_steps_from_block(lines: List[str]) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        if PIPE_ROW_RE.match(stripped) and not stripped.startswith("|---"):
            cols = [c.strip() for c in stripped.split("|")]
            if len(cols) >= 5:
                try:
                    order = int(cols[1])
                except Exception:
                    order = len(steps) + 1
                description = cols[2] or f"step-{order}"
                fids = finding_ids_in_text(cols[3])
                if not fids:
                    continue
                evidence = normalize_file_line_refs(cols[4])
                steps.append(
                    {
                        "order": order,
                        "description": description,
                        "finding_refs": fids,
                        "evidence_refs": evidence,
                    }
                )
                continue

        if stripped.startswith("- "):
            text = stripped[2:].strip()
            fids = finding_ids_in_text(text)
            if not fids:
                continue
            steps.append(
                {
                    "order": len(steps) + 1,
                    "description": text,
                    "finding_refs": fids,
                    "evidence_refs": normalize_file_line_refs(text),
                }
            )

    return steps


def parse_chains(text: str) -> List[Dict[str, Any]]:
    chains: List[Dict[str, Any]] = []
    for chain_id, title, block_lines in parse_chain_blocks(text):
        steps = parse_steps_from_block(block_lines)
        if not steps:
            refs = finding_ids_in_text("\n".join(block_lines))
            if refs:
                steps = [
                    {
                        "order": 1,
                        "description": "derived from chain narrative",
                        "finding_refs": refs,
                        "evidence_refs": [],
                    }
                ]
        if not steps:
            continue
        chains.append(
            {
                "chain_id": chain_id,
                "title": title,
                "steps": steps,
                "narrative": "\n".join(block_lines).strip(),
            }
        )
    return chains


def load_findings_ids(findings_jsonl: Path) -> set[str]:
    out: set[str] = set()
    if not findings_jsonl.exists():
        return out
    with findings_jsonl.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                fid = str(row.get("id", "")).strip()
                if fid:
                    out.add(fid)
    return out


def anti_story_check(
    payload: Dict[str, Any],
    valid_findings: set[str],
    verified_ids: set[str] | None = None,
) -> List[str]:
    errors: List[str] = []
    for chain in payload.get("chains", []):
        chain_id = str(chain.get("chain_id", ""))
        for step in chain.get("steps", []):
            refs = [str(x) for x in step.get("finding_refs", []) if str(x)]
            if not refs:
                errors.append(f"{chain_id}: step missing finding_refs")
                continue
            for fid in refs:
                if valid_findings and fid not in valid_findings:
                    errors.append(
                        f"{chain_id}: step references unknown finding_id {fid}"
                    )
                if verified_ids is not None and fid not in verified_ids:
                    errors.append(
                        f"{chain_id}: step references unverified finding {fid} (UNVERIFIED_REFERENCE)"
                    )
    return errors


def validate_chains(payload: Dict[str, Any]) -> None:
    schema = schema_validator.load_schema("chains")
    schema_validator.validate(payload, schema, [])


def main() -> int:
    args = parse_args()
    audit_dir = Path(args.audit_dir).resolve()
    attack_graph_path = (
        Path(args.attack_graph) if args.attack_graph else audit_dir / "attack-graph.md"
    )
    findings_path = Path(args.findings) if args.findings else audit_dir / "findings.md"
    out_path = Path(args.out) if args.out else audit_dir / "chains.json"

    if out_path.exists() and not args.overwrite:
        print(
            f"error: output already exists: {out_path} (use --overwrite)",
            file=sys.stderr,
        )
        return 1

    source = ""
    chains: List[Dict[str, Any]] = []
    if attack_graph_path.exists():
        chains = parse_chains(
            attack_graph_path.read_text(encoding="utf-8", errors="ignore")
        )
        source = "attack-graph"
    if not chains and findings_path.exists():
        chains = parse_chains(
            findings_path.read_text(encoding="utf-8", errors="ignore")
        )
        source = "findings-fallback"

    payload: Dict[str, Any] = {
        "schema_version": 1,
        "chains": chains,
    }

    try:
        validate_chains(payload)
    except Exception as exc:
        print(f"error: chains schema validation failed: {exc}", file=sys.stderr)
        return 1

    finding_ids = load_findings_ids(audit_dir / "findings.jsonl")
    verified_ids = get_verified_finding_ids(audit_dir)
    if not (audit_dir / "verification.jsonl").exists():
        print(
            "WARNING: verification.jsonl not found; verification cross-check skipped",
            file=sys.stderr,
        )
        verified_ids = None

    anti_story_errors = anti_story_check(payload, finding_ids, verified_ids)
    if anti_story_errors:
        hard_errors = [e for e in anti_story_errors if "UNVERIFIED_REFERENCE" not in e]
        warnings = [e for e in anti_story_errors if "UNVERIFIED_REFERENCE" in e]

        if warnings:
            print("warning: unverified finding references in chains:", file=sys.stderr)
            for w in warnings[:20]:
                print(f"  - {w}", file=sys.stderr)

        if hard_errors:
            print("error: anti-story-chain check failed:", file=sys.stderr)
            for err in hard_errors[:50]:
                print(f"- {err}", file=sys.stderr)
            return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"chains exported: {out_path} (source={source or 'none'}, chains={len(chains)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
