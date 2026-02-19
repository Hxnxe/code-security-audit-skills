#!/usr/bin/env python3
"""Build coverage.json for V4 audit flow."""

from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
STRATUM_CRITICAL = {"S1", "S2", "S3", "S4", "S6"}
CRITICAL_MODULE_HINTS = {"admin", "finance", "auth", "wallet"}
CATEGORY_HINTS = {
    "auth": ["/auth/"],
    "admin": ["/admin/"],
    "finance": ["/finance/", "/wallet/", "/payment/"],
    "api": ["/api/"],
    "config": ["/config/", "/settings/"],
}
FILE_LINE_RE = re.compile(
    r"(?P<file>[A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+):(?P<line>\d+)|"
    r"(?P<file2>[A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+)#L(?P<line2>\d+)"
)
FINDING_HEADING_RE = re.compile(r"^###\s*(F-[A-Za-z0-9_-]+)\s*:\s*(.+?)\s*$")
FILE_LABEL_RE = re.compile(r"\*\*(?:文件|文件路径|File|file)\*\*\s*:\s*(.+)")

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

_shared_utils = importlib.import_module("shared_utils")

load_json = _shared_utils.load_json
load_jsonl = _shared_utils.load_jsonl
now_utc = _shared_utils.now_utc
normalize_file = _shared_utils.normalize_file
files_match = _shared_utils.files_match
load_manifest = _shared_utils.load_manifest
load_verification_index = _shared_utils.load_verification_index


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build coverage metrics for code-security-audit V4"
    )
    parser.add_argument("audit_dir", nargs="?", default="audit", help="Audit directory")
    parser.add_argument(
        "--out", default=None, help="Output path (default: <audit_dir>/coverage.json)"
    )
    parser.add_argument(
        "--iteration", type=int, default=1, help="Current loop iteration"
    )
    parser.add_argument(
        "--critical-min",
        type=float,
        default=None,
        help="Minimum critical surface coverage ratio (default: dynamic by critical endpoint count)",
    )
    parser.add_argument(
        "--endpoint-audit-min",
        type=float,
        default=None,
        help="Minimum endpoint audit coverage ratio (default: dynamic by critical endpoint count)",
    )
    parser.add_argument(
        "--known-min",
        type=float,
        default=None,
        help="Optional known-vuln recall threshold",
    )
    parser.add_argument(
        "--known-recall",
        type=float,
        default=None,
        help="Optional known-vuln recall ratio value",
    )
    parser.add_argument(
        "--known", default=None, help="Optional known-vulns baseline json path"
    )
    parser.add_argument(
        "--verdict", default=None, help="Optional verdict path for recall computation"
    )
    parser.add_argument(
        "--mode",
        choices=["interim", "final"],
        default="final",
        help="interim: skip threshold checks; final: full validation",
    )
    return parser.parse_args()


def safe_ratio(num: int, den: int) -> float:
    if den <= 0:
        return 1.0
    return num / den


def file_in_candidates(target: Any, candidates: Sequence[str]) -> bool:
    return any(files_match(target, candidate) for candidate in candidates)


def extract_referenced_files(markdown_text: str) -> List[str]:
    files: List[str] = []
    seen: set[str] = set()
    for match in FILE_LINE_RE.finditer(markdown_text):
        path = match.group("file") or match.group("file2") or ""
        if not path:
            continue
        path = normalize_file(path)
        if path.startswith(("http://", "https://")):
            continue
        if path not in seen:
            seen.add(path)
            files.append(path)
    return files


def extract_audited_files_from_markdown(markdown_text: str) -> List[str]:
    lines = markdown_text.splitlines()
    files: List[str] = []
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


def normalize_verdicts(data: Any) -> Dict[str, str]:
    if data is None:
        return {}
    if isinstance(data, dict) and isinstance(data.get("verdicts"), list):
        items = data["verdicts"]
    elif isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = [data]
    else:
        items = []

    out: Dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        finding_id = str(item.get("finding_id", ""))
        if finding_id:
            out[finding_id] = str(item.get("validity_verdict", "CONFIRMED"))
    return out


def finding_matches_known(finding: Dict[str, Any], known: Dict[str, Any]) -> bool:
    known_file = str(known.get("file", "")).lower()
    finding_file = str(finding.get("file", "")).lower()
    if known_file and known_file in finding_file:
        return True

    hints = {str(h).upper() for h in known.get("detection_hints", [])}
    if not hints:
        return False

    fields = [
        str(finding.get("type", "")).upper(),
        str(finding.get("impact", "")).upper(),
        " ".join(str(x).upper() for x in finding.get("anomaly_refs", [])),
    ]
    joined = " ".join(fields)
    return any(hint in joined for hint in hints)


def compute_known_recall(
    findings: List[Dict[str, Any]],
    verdicts: Dict[str, str],
    known: List[Dict[str, Any]],
) -> float:
    confirmed = [
        f
        for f in findings
        if verdicts.get(str(f.get("id", "")), "CONFIRMED") != "DISPUTED"
    ]
    matched = 0
    for kv in known:
        if any(finding_matches_known(finding, kv) for finding in confirmed):
            matched += 1
    return safe_ratio(matched, len(known))


def infer_stratum(record: Dict[str, Any]) -> str:
    existing = str(record.get("stratum", "")).strip().upper()
    if existing:
        return existing

    method = str(record.get("method", "")).upper()
    auth_declared = str(record.get("auth_declared", ""))
    is_public = bool(record.get("effective_public", False))
    tags = {
        str(tag).strip().upper() for tag in record.get("tags", []) if str(tag).strip()
    }

    module = str(record.get("module", "")).lower().strip()
    file_path = str(record.get("file", "")).replace("\\", "/").lower()
    wrapped = f"/{file_path}/"
    critical_module = (
        "CRITICAL_MODULE" in tags
        or module in CRITICAL_MODULE_HINTS
        or any(f"/{hint}/" in wrapped for hint in CRITICAL_MODULE_HINTS)
    )

    if is_public and ("WRITE_OP" in tags or method in WRITE_METHODS):
        return "S1"
    if is_public and ("SENSITIVE_IO" in tags or "INCLUDE_DEEP" in tags):
        return "S2"
    if is_public:
        return "S3"
    if auth_declared == "absent":
        return "S4"
    if critical_module:
        return "S5"
    if "TRIAGE_FLAGGED" in tags:
        return "S6"
    return "S7"


def infer_categories(file_path: str) -> List[str]:
    wrapped = f"/{normalize_file(file_path).lower()}/"
    categories: List[str] = []
    for category, hints in CATEGORY_HINTS.items():
        if any(hint in wrapped for hint in hints):
            categories.append(category)
    return categories


def category_threshold(total: int, base: float) -> float:
    if total <= 1:
        return 1.0
    if total <= 3:
        return 0.67
    return max(0.30, base)


def dynamic_coverage_threshold(total: int, requested: float | None) -> float:
    if requested is not None:
        return requested
    if total >= 100:
        return 0.30
    if total >= 40:
        return 0.45
    return 0.60


def render_coverage_gap(
    out_path: Path,
    category_rows: Sequence[Dict[str, Any]],
    reasons: Sequence[str],
    next_targets: Sequence[str],
    delta: Dict[str, float],
) -> None:
    lines: List[str] = []
    lines.append("# coverage-gap")
    lines.append("")
    lines.append("## 未达标类别")
    if category_rows:
        lines.append("| 类别 | 已覆盖 | 总量 | 覆盖率 | 阈值 |")
        lines.append("|---|---:|---:|---:|---:|")
        for row in category_rows:
            lines.append(
                f"| {row['category']} | {row['covered']} | {row['total']} | {row['ratio']:.0%} | {row['threshold']:.0%} |"
            )
    else:
        lines.append("- 无")
    lines.append("")
    lines.append("## 覆盖缺口原因")
    if reasons:
        for reason in reasons:
            lines.append(f"- {reason}")
    else:
        lines.append("- 无")
    lines.append("")
    lines.append("## 进度变化（相对上一轮）")
    if delta:
        for key, value in delta.items():
            lines.append(f"- {key}: {value:+.2%}")
    else:
        lines.append("- 无上一轮基线")
    lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()
    audit_dir = Path(args.audit_dir)
    out_path = Path(args.out) if args.out else audit_dir / "coverage.json"

    previous_coverage = load_json(out_path)

    inventory = load_jsonl(audit_dir / "inventory.jsonl")
    signals = load_jsonl(audit_dir / "attack-surface.jsonl")
    findings = load_jsonl(audit_dir / "findings.jsonl")
    scope_stats = load_json(audit_dir / "scope_stats.json") or {}
    findings_md = (
        (audit_dir / "findings.md").read_text(encoding="utf-8")
        if (audit_dir / "findings.md").exists()
        else ""
    )

    signal_files = [
        normalize_file(s.get("file", ""))
        for s in signals
        if normalize_file(s.get("file", ""))
    ]
    runtime_endpoint_coverage_ratio = safe_ratio(
        sum(
            1
            for ep in inventory
            if file_in_candidates(ep.get("file", ""), signal_files)
        ),
        len(inventory),
    )

    non_runtime_total = int(scope_stats.get("non_runtime_assets_total", 0))
    non_runtime_signal_files = {
        normalize_file(s.get("file", ""))
        for s in signals
        if "non_runtime" in s.get("tags", []) and normalize_file(s.get("file", ""))
    }
    non_runtime_asset_coverage_ratio = safe_ratio(
        len(non_runtime_signal_files), non_runtime_total
    )

    critical_endpoints = [
        ep for ep in inventory if infer_stratum(ep) in STRATUM_CRITICAL
    ]
    if not critical_endpoints:
        critical_endpoints = inventory

    critical_min = dynamic_coverage_threshold(
        len(critical_endpoints), args.critical_min
    )
    endpoint_min = dynamic_coverage_threshold(
        len(critical_endpoints), args.endpoint_audit_min
    )

    critical_files = [
        normalize_file(ep.get("file", ""))
        for ep in critical_endpoints
        if normalize_file(ep.get("file", ""))
    ]

    finding_files = [
        normalize_file(f.get("file", ""))
        for f in findings
        if normalize_file(f.get("file", ""))
    ]
    md_referenced_files = extract_referenced_files(findings_md)
    md_audited_files = extract_audited_files_from_markdown(findings_md)
    audited_candidates = (
        set(finding_files) | set(md_referenced_files) | set(md_audited_files)
    )

    uncovered_high_risk = []
    for ep in inventory:
        ep_file = normalize_file(ep.get("file", ""))
        if not ep_file:
            continue
        if file_in_candidates(ep_file, list(audited_candidates)):
            continue
        uncovered_high_risk.append(
            {
                "file": ep_file,
                "risk_score": int(ep.get("risk_score", 0)),
                "stratum": str(ep.get("stratum", "S7")),
            }
        )
    uncovered_high_risk.sort(key=lambda x: -x["risk_score"])
    uncovered_high_risk = uncovered_high_risk[:30]

    # --- New multi-axis metrics ---
    manifest = load_manifest(audit_dir)
    verification_index = load_verification_index(audit_dir)

    # 1. shard_completion_ratio: completed shards / total shards
    shards_path = audit_dir / "audit_target_shards.json"
    total_shards = 0
    if shards_path.exists():
        shards_data = load_json(shards_path)
        if isinstance(shards_data, list):
            total_shards = len(shards_data)
    completed_shards = len(
        {e.get("shard_id") for e in manifest if e.get("status") == "done"}
    )
    shard_completion_ratio = safe_ratio(completed_shards, total_shards)

    # 2. evidence_quality_ratio: verified findings / total findings
    confirmed_count = sum(
        1
        for v in verification_index.values()
        if v.get("verification_conclusion") == "CONFIRMED"
    )
    evidence_quality_ratio = (
        safe_ratio(confirmed_count, len(findings)) if findings else 0.0
    )

    # 3. risk_coverage_ratio: S1+S2 files covered / total S1+S2 files
    high_risk_files = [
        normalize_file(ep.get("file", ""))
        for ep in inventory
        if ep.get("stratum") in ("S1", "S2") and normalize_file(ep.get("file", ""))
    ]
    high_risk_covered = sum(
        1 for f in high_risk_files if file_in_candidates(f, list(audited_candidates))
    )
    risk_coverage_ratio = safe_ratio(high_risk_covered, len(high_risk_files))

    critical_surface_coverage_ratio = safe_ratio(
        sum(
            1
            for ep in critical_endpoints
            if file_in_candidates(ep.get("file", ""), list(audited_candidates))
        ),
        len(critical_endpoints),
    )

    endpoint_audit_coverage_ratio = safe_ratio(
        sum(
            1
            for ep in critical_endpoints
            if file_in_candidates(ep.get("file", ""), list(audited_candidates))
        ),
        len(critical_endpoints),
    )

    findings_with_evidence_ratio = safe_ratio(
        sum(
            1
            for finding in findings
            if len(((finding.get("evidence_bundle", {}) or {}).get("primary_refs", [])))
            >= 1
        ),
        len(findings),
    )

    recall_ratio = args.known_recall
    if args.known:
        known_path = Path(args.known)
        verdict_path = (
            Path(args.verdict) if args.verdict else audit_dir / "verdict.json"
        )
        if known_path.exists():
            known_data = load_json(known_path)
            if isinstance(known_data, list):
                verdict_map = normalize_verdicts(load_json(verdict_path))
                recall_ratio = compute_known_recall(findings, verdict_map, known_data)

    thresholds: Dict[str, float] = {
        "critical_surface_min": critical_min,
        "endpoint_audit_min": endpoint_min,
    }
    if args.known_min is not None:
        thresholds["known_vuln_recall_min"] = args.known_min

    metrics: Dict[str, float] = {
        "runtime_endpoint_coverage_ratio": runtime_endpoint_coverage_ratio,
        "non_runtime_asset_coverage_ratio": non_runtime_asset_coverage_ratio,
        "endpoint_audit_coverage_ratio": endpoint_audit_coverage_ratio,
        "critical_surface_coverage_ratio": critical_surface_coverage_ratio,
        "findings_with_evidence_ratio": findings_with_evidence_ratio,
        "shard_completion_ratio": shard_completion_ratio,
        "evidence_quality_ratio": evidence_quality_ratio,
        "risk_coverage_ratio": risk_coverage_ratio,
    }
    if recall_ratio is not None:
        metrics["known_vuln_recall_ratio"] = recall_ratio

    if args.mode == "interim":
        coverage: Dict[str, Any] = {
            "schema_version": 1,
            "generated_at": now_utc(),
            "iteration": max(1, args.iteration),
            "mode": "interim",
            "metrics": metrics,
            "content_gate_passed": True,
            "coverage_gap": False,
            "gap_reasons": [],
            "uncovered_high_risk": uncovered_high_risk,
            "summary": "interim coverage snapshot",
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(coverage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"coverage generated (interim): {out_path}")
        for k, v in metrics.items():
            if isinstance(v, float):
                print(f"  {k}={v:.2%}")
        return 0

    r2_reasons: List[str] = []
    if critical_surface_coverage_ratio < critical_min:
        r2_reasons.append(
            f"critical surface coverage low ({critical_surface_coverage_ratio:.2%} < {critical_min:.2%})"
        )
    if endpoint_audit_coverage_ratio < endpoint_min:
        r2_reasons.append(
            f"endpoint audit coverage low ({endpoint_audit_coverage_ratio:.2%} < {endpoint_min:.2%})"
        )
    if args.known_min is not None:
        if recall_ratio is None:
            r2_reasons.append(
                "known_vuln_recall_min provided but known_vuln_recall_ratio missing"
            )
        elif recall_ratio < args.known_min:
            r2_reasons.append(
                f"known vuln recall low ({recall_ratio:.2%} < {args.known_min:.2%})"
            )

    category_rows: List[Dict[str, Any]] = []
    for category in CATEGORY_HINTS:
        category_files = []
        for ep in critical_endpoints:
            ep_file = normalize_file(ep.get("file", ""))
            if not ep_file:
                continue
            if category in infer_categories(ep_file):
                category_files.append(ep_file)

        category_files = sorted(set(category_files))
        total = len(category_files)
        if total == 0:
            continue

        covered = sum(
            1
            for path in category_files
            if file_in_candidates(path, list(audited_candidates))
        )
        ratio = safe_ratio(covered, total)
        threshold = category_threshold(total, endpoint_min)
        if ratio < threshold:
            category_rows.append(
                {
                    "category": category,
                    "covered": covered,
                    "total": total,
                    "ratio": ratio,
                    "threshold": threshold,
                }
            )
            r2_reasons.append(
                f"category coverage low ({category}: {ratio:.2%} < {threshold:.2%}, {covered}/{total})"
            )

    coverage_gap = bool(r2_reasons)
    content_gate_passed = not coverage_gap

    coverage: Dict[str, Any] = {
        "schema_version": 1,
        "generated_at": now_utc(),
        "iteration": max(1, args.iteration),
        "thresholds": thresholds,
        "metrics": metrics,
        "content_gate_passed": content_gate_passed,
        "coverage_gap": coverage_gap,
        "gap_reasons": r2_reasons,
        "uncovered_high_risk": uncovered_high_risk,
        "summary": "coverage ok" if content_gate_passed else "coverage gap detected",
    }
    prev_metrics = (
        previous_coverage.get("metrics", {})
        if isinstance(previous_coverage, dict)
        else {}
    )
    delta: Dict[str, float] = {}
    for key, value in metrics.items():
        prev = prev_metrics.get(key)
        if isinstance(prev, (int, float)):
            delta[key] = float(value) - float(prev)
    if delta:
        improved = [k for k, v in delta.items() if v > 0]
        regressed = [k for k, v in delta.items() if v < 0]
        coverage["delta"] = delta
        coverage["progress"] = {
            "improved_metrics": improved,
            "regressed_metrics": regressed,
        }
    if category_rows:
        coverage["roi_recommendations"] = [
            f"prioritize category={row['category']} gap={row['covered']}/{row['total']}"
            for row in category_rows[:5]
        ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(coverage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    render_coverage_gap(
        audit_dir / "coverage-gap.md", category_rows, r2_reasons, [], delta
    )

    print(f"coverage generated: {out_path}")
    print(f"critical_surface_coverage_ratio={critical_surface_coverage_ratio:.2%}")
    print(f"endpoint_audit_coverage_ratio={endpoint_audit_coverage_ratio:.2%}")
    print(f"coverage_gap={str(coverage_gap).lower()}")
    if delta:
        print(
            "coverage_delta="
            + ", ".join(f"{k}:{v:+.2%}" for k, v in sorted(delta.items()))
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
