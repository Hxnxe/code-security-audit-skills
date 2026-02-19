#!/usr/bin/env python3
"""Extract verification entries from audit/verification.md into verification.jsonl."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

VERIFICATION_HEADING_RE = re.compile(r"^###\s*(V-[A-Za-z0-9_-]+)\s*:\s*(.+?)\s*$")
FINDING_REF_RE = re.compile(r"F-[A-Za-z0-9_-]+")

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract verification.jsonl from verification.md"
    )
    parser.add_argument("audit_dir", nargs="?", default="audit", help="Audit directory")
    parser.add_argument(
        "--out",
        dest="output_jsonl",
        default=None,
        help="Output verification.jsonl path (default: <audit_dir>/verification.jsonl)",
    )
    return parser.parse_args()


def parse_md_sections(
    lines: Sequence[str],
    heading_re: re.Pattern[str],
    stop_on_h2: bool = False,
) -> List[Tuple[str, str, List[str]]]:
    sections: List[Tuple[str, str, List[str]]] = []
    current_id = ""
    current_title = ""
    current_block: List[str] = []

    for line in lines:
        stripped = line.strip()
        if current_id and stop_on_h2 and stripped.startswith("## "):
            sections.append((current_id, current_title, current_block))
            current_id = ""
            current_title = ""
            current_block = []
            continue

        match = heading_re.match(line.strip())
        if match:
            if current_id:
                sections.append((current_id, current_title, current_block))
            current_id = match.group(1).strip()
            current_title = match.group(2).strip()
            current_block = []
            continue
        if current_id:
            current_block.append(line)

    if current_id:
        sections.append((current_id, current_title, current_block))
    return sections


def find_label_value(block_text: str, label: str) -> str:
    pattern = re.compile(rf"\*\*{re.escape(label)}\*\*\s*:\s*(.+)")
    match = pattern.search(block_text)
    return match.group(1).strip() if match else ""


def extract_finding_refs(block_text: str) -> str:
    matches = FINDING_REF_RE.findall(block_text)
    unique_ids: List[str] = []
    for fid in matches:
        if fid not in unique_ids:
            unique_ids.append(fid)
    return ", ".join(unique_ids)


def parse_verification_entries(markdown: str) -> List[Dict[str, Any]]:
    lines = markdown.splitlines()
    sections = parse_md_sections(lines, VERIFICATION_HEADING_RE, stop_on_h2=True)
    entries: List[Dict[str, Any]] = []

    for entry_id, title, block_lines in sections:
        block_text = "\n".join(block_lines)

        source = find_label_value(block_text, "来源")
        file_ref = find_label_value(block_text, "文件")
        data_flow_trace = find_label_value(block_text, "数据流追踪")
        verification_conclusion = find_label_value(block_text, "验证结论")
        evidence = find_label_value(block_text, "证据")
        finding_refs = extract_finding_refs(block_text)

        # Warn if required fields are missing
        missing_fields = []
        if not source:
            missing_fields.append("来源")
        if not file_ref:
            missing_fields.append("文件")
        if not data_flow_trace:
            missing_fields.append("数据流追踪")
        if not verification_conclusion:
            missing_fields.append("验证结论")
        if not evidence:
            missing_fields.append("证据")

        if missing_fields:
            print(
                f"WARNING: {entry_id} missing labels: {', '.join(missing_fields)}",
                file=sys.stderr,
            )

        entry = {
            "entry_id": entry_id,
            "title": title,
            "source": source,
            "file": file_ref,
            "data_flow_trace": data_flow_trace,
            "verification_conclusion": verification_conclusion,
            "evidence": evidence,
            "finding_refs": finding_refs,
        }
        entries.append(entry)

    return entries


def dump_verification_jsonl(path: Path, entries: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main() -> int:
    args = parse_args()
    audit_dir = Path(args.audit_dir)
    input_md = audit_dir / "verification.md"
    output_jsonl = (
        Path(args.output_jsonl)
        if args.output_jsonl
        else audit_dir / "verification.jsonl"
    )

    if not input_md.exists():
        print(
            f"error: verification.md not found: {input_md}",
            file=sys.stderr,
        )
        return 1

    markdown = input_md.read_text(encoding="utf-8")
    entries = parse_verification_entries(markdown)

    if not entries:
        print(
            "error: No V-XXX entries found in verification.md",
            file=sys.stderr,
        )
        return 1

    dump_verification_jsonl(output_jsonl, entries)

    # Summary statistics
    confirmed = sum(1 for e in entries if e["verification_conclusion"] == "CONFIRMED")
    disputed = sum(1 for e in entries if e["verification_conclusion"] == "DISPUTED")
    needs_deeper = sum(
        1 for e in entries if e["verification_conclusion"] == "NEEDS_DEEPER"
    )

    msg = (
        f"Extracted {len(entries)} verification entries "
        f"({confirmed} confirmed, {disputed} disputed, {needs_deeper} needs_deeper)"
    )
    print(msg, file=sys.stderr)
    print(f"verification extracted: {len(entries)} -> {output_jsonl}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
