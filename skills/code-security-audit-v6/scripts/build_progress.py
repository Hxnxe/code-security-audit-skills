#!/usr/bin/env python3
"""Build progress.md report from audit artifacts.

This script generates a human-readable progress report by filling in the
templates/progress-report.md template with data from audit artifacts.
It replaces the R2 auto-loop decision mechanism, allowing users to review
coverage and decide whether to continue scanning.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from shared_utils import load_jsonl, normalize_file, files_match, now_utc  # type: ignore

FILE_LINE_RE = re.compile(
    r"(?P<file>[A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+):(?P<line>\d+)|(?P<file2>[A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+)#L(?P<line2>\d+)"
)
FINDING_HEADING_RE = re.compile(r"^###\s*(F-[A-Za-z0-9_-]+)\s*:\s*(.+?)\s*$")
FILE_LABEL_RE = re.compile(r"\*\*(?:文件|文件路径|File|file)\*\*\s*:\s*(.+)")
SEVERITY_LABEL_RE = re.compile(r"\*\*(?:严重程度|Severity)\*\*\s*:\s*(.+)")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Build progress.md report from audit artifacts"
    )
    parser.add_argument("audit_dir", nargs="?", default="audit", help="Audit directory")
    parser.add_argument(
        "--template",
        default=None,
        help="Path to progress report template (default: templates/progress-report.md)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output path (default: <audit_dir>/progress.md)",
    )
    parser.add_argument(
        "--iteration",
        type=int,
        default=1,
        help="Current R2 loop iteration",
    )
    return parser.parse_args()


def extract_audited_files_from_markdown(markdown_text: str) -> list[str]:
    lines = markdown_text.splitlines()
    files: list[str] = []
    seen: set[str] = set()

    in_finding = False
    for raw in lines:
        stripped = raw.strip()
        if FINDING_HEADING_RE.match(stripped):
            in_finding = True
            continue
        if stripped.startswith("## "):
            in_finding = False
        if not in_finding:
            continue

        match = FILE_LABEL_RE.search(stripped)
        if not match:
            continue
        value = match.group(1).strip().strip("`").strip()
        if not value:
            continue

        fl = FILE_LINE_RE.search(value)
        if fl:
            path = fl.group("file") or fl.group("file2") or ""
            if path:
                norm = normalize_file(path)
                if norm and norm not in seen:
                    seen.add(norm)
                    files.append(norm)
                continue

        plain = normalize_file(value)
        if plain and " " not in plain and plain not in seen:
            seen.add(plain)
            files.append(plain)

    in_checked_section = False
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("## 已检查无问题"):
            in_checked_section = True
            continue
        if stripped.startswith("## ") and in_checked_section:
            in_checked_section = False
            continue
        if not in_checked_section:
            continue
        if not stripped.startswith("|") or stripped.startswith("|---"):
            continue
        cols = [c.strip().strip("`") for c in stripped.split("|")]
        if len(cols) < 3:
            continue
        file_col = normalize_file(cols[1])
        if not file_col or file_col in {"文件", "file", "path/to/file.ts"}:
            continue
        if file_col not in seen:
            seen.add(file_col)
            files.append(file_col)

    return files


def count_targets(audit_dir: Path) -> dict[str, int | float]:
    """Count total/audited/uncovered targets from audit_targets.md and findings.md.

    Returns:
        dict with keys: total, audited, uncovered, coverage_pct
    """
    targets_path = audit_dir / "audit_targets.md"
    total = 0
    
    if targets_path.exists():
        content = targets_path.read_text(encoding="utf-8")
        lines = content.splitlines()
        in_p0_or_p1 = False
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("## P0:") or stripped.startswith("## P1:"):
                in_p0_or_p1 = True
                continue
            if stripped.startswith("## "):
                in_p0_or_p1 = False
                continue
            if in_p0_or_p1 and stripped.startswith("|") and not stripped.startswith("|---"):
                cols = [c.strip() for c in stripped.split("|")]
                if len(cols) >= 3 and cols[1] and cols[1] not in {"文件", "File", "file", "Path"}:
                    total += 1
    
    findings_path = audit_dir / "findings.md"
    findings_jsonl_path = audit_dir / "findings.jsonl"
    
    audited_files = set()
    
    if findings_path.exists():
        content = findings_path.read_text(encoding="utf-8")
        md_files = extract_audited_files_from_markdown(content)
        audited_files.update(md_files)
    
    if findings_jsonl_path.exists():
        findings = load_jsonl(findings_jsonl_path)
        for finding in findings:
            file_path = normalize_file(finding.get("file", ""))
            if file_path:
                audited_files.add(file_path)
    
    audited = len(audited_files)
    uncovered = max(0, total - audited)
    coverage_pct = (audited / total * 100) if total > 0 else 0.0
    
    return {
        "total": total,
        "audited": audited,
        "uncovered": uncovered,
        "coverage_pct": coverage_pct,
    }


def extract_findings_summary(audit_dir: Path) -> list[dict[str, str]]:
    """Extract finding summaries from findings.md or findings.jsonl.

    Returns:
        list of dicts with keys: id, severity, file, desc
    """
    findings_path = audit_dir / "findings.md"
    if not findings_path.exists():
        return []
    
    content = findings_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    
    findings = []
    current_finding = None
    
    for line in lines:
        stripped = line.strip()
        
        match = FINDING_HEADING_RE.match(stripped)
        if match:
            if current_finding:
                findings.append(current_finding)
            
            finding_id = match.group(1)
            desc = match.group(2)
            current_finding = {
                "id": finding_id,
                "desc": desc,
                "severity": "",
                "file": "",
            }
            continue
        
        if current_finding:
            sev_match = SEVERITY_LABEL_RE.search(stripped)
            if sev_match:
                current_finding["severity"] = sev_match.group(1).strip()
                continue
            
            file_match = FILE_LABEL_RE.search(stripped)
            if file_match:
                file_value = file_match.group(1).strip().strip("`")
                fl = FILE_LINE_RE.search(file_value)
                if fl:
                    path = fl.group("file") or fl.group("file2") or ""
                    if path:
                        current_finding["file"] = normalize_file(path)
                else:
                    current_finding["file"] = normalize_file(file_value)
    
    if current_finding:
        findings.append(current_finding)
    
    return findings


def build_uncovered_table(audit_dir: Path) -> list[dict[str, str | int]]:
    """Build list of uncovered high-risk files from inventory.jsonl.

    Returns:
        list of dicts with keys: file, risk_score, stratum, reason
    """
    inventory_path = audit_dir / "inventory.jsonl"
    if not inventory_path.exists():
        return []
    
    inventory = load_jsonl(inventory_path)
    
    findings_path = audit_dir / "findings.md"
    findings_jsonl_path = audit_dir / "findings.jsonl"
    
    audited_files = set()
    
    if findings_path.exists():
        content = findings_path.read_text(encoding="utf-8")
        md_files = extract_audited_files_from_markdown(content)
        audited_files.update(md_files)
    
    if findings_jsonl_path.exists():
        findings = load_jsonl(findings_jsonl_path)
        for finding in findings:
            file_path = normalize_file(finding.get("file", ""))
            if file_path:
                audited_files.add(file_path)
    
    uncovered = []
    for item in inventory:
        file_path = normalize_file(item.get("file", ""))
        if not file_path:
            continue
        
        is_audited = any(files_match(file_path, af) for af in audited_files)
        if not is_audited:
            uncovered.append({
                "file": file_path,
                "risk_score": item.get("risk_score", 0),
                "stratum": item.get("stratum", ""),
                "reason": item.get("reason", ""),
            })
    
    uncovered.sort(key=lambda x: x["risk_score"], reverse=True)
    return uncovered[:20]


def render_progress(template_path: Path, data: dict[str, Any]) -> str:
    """Render progress report by filling template placeholders.

    Args:
        template_path: Path to progress-report.md template
        data: dict with keys: timestamp, iteration, target_counts, findings, uncovered_files

    Returns:
        Rendered markdown string
    """
    template = template_path.read_text(encoding="utf-8")
    
    result = template
    result = result.replace("{{GENERATED_AT}}", data["timestamp"])
    result = result.replace("{{ITERATION}}", str(data["iteration"]))
    
    target_counts = data["target_counts"]
    result = result.replace("{{TOTAL_TARGETS}}", str(target_counts["total"]))
    result = result.replace("{{AUDITED}}", str(target_counts["audited"]))
    result = result.replace("{{AUDITED_PCT}}", f"{target_counts['coverage_pct']:.1f}")
    
    findings = data["findings"]
    result = result.replace("{{CONFIRMED_COUNT}}", str(len(findings)))
    result = result.replace("{{PENDING_COUNT}}", str(data.get("pending_count", 0)))
    
    findings_table_rows = []
    for finding in findings:
        row = f"| {finding['id']} | {finding['severity']} | {finding['file']} | {finding['desc']} |"
        findings_table_rows.append(row)
    
    findings_table = "\n".join(findings_table_rows) if findings_table_rows else "| - | - | - | 暂无 |"
    result = result.replace("{{FINDINGS_TABLE}}", findings_table)
    
    uncovered_files = data["uncovered_files"]
    uncovered_table_rows = []
    for idx, item in enumerate(uncovered_files, 1):
        row = f"| {idx} | {item['file']} | {item['risk_score']} | {item['stratum']} | {item['reason']} |"
        uncovered_table_rows.append(row)
    
    uncovered_table = "\n".join(uncovered_table_rows) if uncovered_table_rows else "| - | - | - | - | - |"
    result = result.replace("{{UNCOVERED_TABLE}}", uncovered_table)
    
    recommendations = data.get("recommendations", "")
    result = result.replace("{{RECOMMENDATIONS}}", recommendations)
    
    return result


def main():
    """CLI entry point."""
    args = parse_args()
    audit_dir = Path(args.audit_dir)
    
    if args.template:
        template_path = Path(args.template)
    else:
        template_path = SCRIPT_DIR.parent / "templates" / "progress-report.md"
    
    if args.out:
        out_path = Path(args.out)
    else:
        out_path = audit_dir / "progress.md"
    
    timestamp = now_utc()
    target_counts = count_targets(audit_dir)
    findings = extract_findings_summary(audit_dir)
    uncovered_files = build_uncovered_table(audit_dir)
    
    coverage_pct = target_counts["coverage_pct"]
    if coverage_pct >= 80:
        recommendations = "覆盖率已达到 80% 以上，建议生成最终报告。"
    elif coverage_pct >= 50:
        recommendations = "覆盖率已达到 50% 以上，建议继续审计剩余高风险目标或生成中期报告。"
    else:
        recommendations = "覆盖率较低，建议优先审计上表中的高风险目标。"
    
    data = {
        "timestamp": timestamp,
        "iteration": args.iteration,
        "target_counts": target_counts,
        "findings": findings,
        "uncovered_files": uncovered_files,
        "pending_count": 0,
        "recommendations": recommendations,
    }
    
    rendered = render_progress(template_path, data)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    
    print(f"build_progress: wrote {out_path}")
    print(f"  total_targets={target_counts['total']}")
    print(f"  audited={target_counts['audited']}")
    print(f"  coverage={target_counts['coverage_pct']:.1f}%")
    print(f"  confirmed_findings={len(findings)}")
    print(f"  uncovered_high_risk={len(uncovered_files)}")


if __name__ == "__main__":
    main()
