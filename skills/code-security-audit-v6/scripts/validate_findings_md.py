#!/usr/bin/env python3
"""Validate findings.md contract before extraction/hardening."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


FINDING_HEADING_RE = re.compile(r"^###\s*(F-[A-Za-z0-9_-]+)\s*:\s*(.+?)\s*$")
P0_SECTION_RE = re.compile(r"^##\s*P0\s*:")
MI_LABEL_RE = re.compile(
    r"\*\*(?:MI-ID|MI_ID|Must[- ]?Investigate(?:\s*ID)?)\*\*\s*:\s*([A-Za-z0-9_-]+)",
    re.IGNORECASE,
)
MI_NORM_RE = re.compile(r"[^A-Za-z0-9]")
FILE_LINE_RE = re.compile(
    r"(?P<file>[A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+):(?P<line>\d+)|"
    r"(?P<file2>[A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+)#L(?P<line2>\d+)"
)

REQUIRED_CHINESE_LABELS = [
    "MI-ID",
    "调查结论",
    "类型",
    "文件",
    "严重程度",
    "攻击者视角",
    "反证检查",
    "前置条件",
    "修复建议",
]

ALLOWED_RESOLUTION = {"CONFIRMED", "DISPUTED", "INCONCLUSIVE"}
ALLOWED_SEVERITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate findings.md contract")
    parser.add_argument("--audit-dir", default="audit", help="Audit directory")
    parser.add_argument(
        "--allow-missing-mi",
        action="store_true",
        help="Do not fail on missing must_investigate MI IDs (debug only)",
    )
    return parser.parse_args()


def normalize_file(value: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    if text.startswith("./"):
        text = text[2:]
    return text


def files_match(left: str, right: str) -> bool:
    a = normalize_file(left)
    b = normalize_file(right)
    if not a or not b:
        return False
    if a == b:
        return True
    return a.endswith(f"/{b}") or b.endswith(f"/{a}")


def normalize_mi(value: str) -> str:
    text = MI_NORM_RE.sub("", str(value or "")).upper()
    if not text.startswith("MI"):
        return ""
    suffix = text[2:]
    if not suffix.isdigit():
        return ""
    return f"MI{int(suffix):04d}"


def parse_finding_blocks(markdown: str) -> List[Tuple[str, str]]:
    blocks: List[Tuple[str, str]] = []
    current_id = ""
    current_lines: List[str] = []
    for raw in markdown.splitlines():
        match = FINDING_HEADING_RE.match(raw.strip())
        if match:
            if current_id:
                blocks.append((current_id, "\n".join(current_lines)))
            current_id = match.group(1).strip()
            current_lines = []
            continue
        if current_id:
            current_lines.append(raw)
    if current_id:
        blocks.append((current_id, "\n".join(current_lines)))
    return blocks


def label_exists(block: str, label: str) -> bool:
    return re.search(rf"\*\*{re.escape(label)}\*\*\s*:", block) is not None


def label_value(block: str, label: str) -> str:
    match = re.search(rf"\*\*{re.escape(label)}\*\*\s*:\s*(.+)", block)
    return match.group(1).strip() if match else ""


def parse_p0_files(audit_targets_text: str) -> List[str]:
    p0_files: List[str] = []
    in_p0 = False
    for raw in audit_targets_text.splitlines():
        line = raw.strip()
        if P0_SECTION_RE.match(line):
            in_p0 = True
            continue
        if line.startswith("## ") and in_p0:
            break
        if not in_p0:
            continue
        if (
            not line.startswith("|")
            or line.startswith("|---")
            or line.startswith("| #")
        ):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) < 4:
            continue
        file_col = cols[1]
        if not file_col or file_col in {"文件", "-", "path/to/file.ts"}:
            continue
        p0_files.append(normalize_file(file_col))
    dedup: List[str] = []
    seen = set()
    for item in p0_files:
        if item not in seen:
            seen.add(item)
            dedup.append(item)
    return dedup


def parse_lsp_section(markdown: str) -> Tuple[bool, Dict[str, bool]]:
    section_found = False
    in_section = False
    coverage: Dict[str, bool] = {}
    for raw in markdown.splitlines():
        line = raw.strip()
        if line.startswith("## "):
            if line.startswith("## P0 语义证据覆盖（LSP）"):
                section_found = True
                in_section = True
                continue
            if in_section:
                break
        if not in_section:
            continue
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cols = [c.strip() for c in line.split("|")]
        if len(cols) < 6:
            continue
        file_col = normalize_file(cols[1])
        if not file_col or file_col in {"P0文件", "file"}:
            continue
        lsp_col = cols[3]
        reason_col = cols[4]
        lsp_upper = lsp_col.upper()
        reason_upper = reason_col.upper()
        has_lsp = (
            bool(lsp_col)
            and lsp_col not in {"-", "N/A", "NA", "无"}
            and "RG_FALLBACK" not in lsp_upper
        )
        has_fallback = "RG_FALLBACK" in lsp_upper and "LSP_UNAVAILABLE" in reason_upper
        coverage[file_col] = coverage.get(file_col, False) or (has_lsp or has_fallback)
    return section_found, coverage


def parse_required_mi(audit_dir: Path) -> List[str]:
    must_path = audit_dir / "must_investigate.jsonl"
    if not must_path.exists():
        return []
    out: List[str] = []
    seen = set()
    with must_path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            mi = normalize_mi(str(obj.get("anomaly_id", "") or obj.get("mi_id", "")))
            if mi and mi not in seen:
                seen.add(mi)
                out.append(mi)
    return out


def parse_found_mi(markdown: str) -> List[str]:
    out: List[str] = []
    seen = set()
    for match in MI_LABEL_RE.finditer(markdown):
        mi = normalize_mi(match.group(1))
        if mi and mi not in seen:
            seen.add(mi)
            out.append(mi)
    return out


def main() -> int:
    args = parse_args()
    audit_dir = Path(args.audit_dir)
    findings_path = audit_dir / "findings.md"
    targets_path = audit_dir / "audit_targets.md"

    if not findings_path.exists():
        print(f"error: findings.md not found: {findings_path}", file=sys.stderr)
        return 1
    if not targets_path.exists():
        print(f"error: audit_targets.md not found: {targets_path}", file=sys.stderr)
        return 1

    findings_md = findings_path.read_text(encoding="utf-8", errors="ignore")
    targets_md = targets_path.read_text(encoding="utf-8", errors="ignore")

    errors: List[str] = []
    warnings: List[str] = []

    blocks = parse_finding_blocks(findings_md)
    if not blocks:
        errors.append("no finding blocks found. Require headings like: ### F-XXX: 标题")
    else:
        ids = [fid for fid, _block in blocks]
        if len(set(ids)) != len(ids):
            errors.append("duplicate finding IDs detected in findings.md")

    for fid, block in blocks:
        for label in REQUIRED_CHINESE_LABELS:
            if not label_exists(block, label):
                errors.append(f"{fid}: missing required label '**{label}**'")

        resolution = label_value(block, "调查结论").upper()
        if resolution and resolution not in ALLOWED_RESOLUTION:
            errors.append(f"{fid}: invalid 调查结论={resolution!r}")

        severity = label_value(block, "严重程度").upper()
        if severity and severity not in ALLOWED_SEVERITY:
            errors.append(f"{fid}: invalid 严重程度={severity!r}")

        file_val = label_value(block, "文件")
        file_match = next(FILE_LINE_RE.finditer(file_val), None)
        if not file_match:
            errors.append(f"{fid}: **文件** must contain file:line")

        mi_val = label_value(block, "MI-ID")
        if mi_val and mi_val.upper() != "N/A":
            mi_norm = normalize_mi(mi_val)
            if not mi_norm:
                errors.append(f"{fid}: invalid MI-ID format: {mi_val!r}")

    if "## 已检查无问题" not in findings_md:
        errors.append("missing section: ## 已检查无问题")

    section_found, lsp_coverage = parse_lsp_section(findings_md)
    if not section_found:
        errors.append("missing section: ## P0 语义证据覆盖（LSP）")

    p0_files = parse_p0_files(targets_md)
    if not p0_files:
        warnings.append("no P0 targets found in audit_targets.md")
    else:
        missing_rows: List[str] = []
        invalid_rows: List[str] = []
        for p0 in p0_files:
            matches = [ok for fp, ok in lsp_coverage.items() if files_match(p0, fp)]
            if not matches:
                missing_rows.append(p0)
            elif not any(matches):
                invalid_rows.append(p0)
        if missing_rows:
            errors.append(
                "P0 LSP coverage missing rows for files: "
                + ", ".join(missing_rows[:20])
            )
        if invalid_rows:
            errors.append(
                "P0 LSP coverage invalid rows (needs LSP or LSP_UNAVAILABLE+RG_FALLBACK): "
                + ", ".join(invalid_rows[:20])
            )

    required_mi = parse_required_mi(audit_dir)
    if required_mi:
        found_mi = set(parse_found_mi(findings_md))
        missing_mi = [mi for mi in required_mi if mi not in found_mi]
        if missing_mi:
            message = "missing must_investigate MI IDs in findings.md: " + ", ".join(
                missing_mi[:30]
            )
            if args.allow_missing_mi:
                warnings.append(message)
            else:
                errors.append(message)

    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)

    if errors:
        print("findings.md validation failed:", file=sys.stderr)
        for err in errors[:120]:
            print(f"- {err}", file=sys.stderr)
        script_dir = Path(__file__).resolve().parent
        audit_template = script_dir.parent / "prompts" / "audit.md"
        print(f"hint: see required template in {audit_template}", file=sys.stderr)
        print(
            "hint: minimal finding block example:\n"
            "### F-001: [漏洞标题]\n"
            "- **MI-ID**: MI0001\n"
            "- **调查结论**: CONFIRMED\n"
            "- **类型**: AUTH_BYPASS\n"
            "- **文件**: <api_root>/example/endpoint.ts:42\n"
            "- **严重程度**: HIGH\n"
            "- **攻击者视角**: ...\n"
            "- **反证检查**: ...\n"
            "- **前置条件**: 无需认证\n"
            "- **修复建议**: ...",
            file=sys.stderr,
        )
        return 1

    print(
        "findings.md validation passed: "
        f"findings={len(blocks)}, p0_targets={len(p0_files)}, lsp_rows={len(lsp_coverage)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
