#!/usr/bin/env python3
"""Compile a Chinese reproduction-oriented report from audit artifacts."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
PRE_REPORT_GATES = ["g0"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile report.md from findings/chains/verdict.")
    parser.add_argument("audit_dir", nargs="?", default="audit", help="Audit directory")
    parser.add_argument("--lang", default="zh-CN", help="Report language (default zh-CN)")
    parser.add_argument("--out", default=None, help="Output markdown file (default <audit_dir>/report.md)")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Strict mode: fail report generation if pre-report gates fail",
    )
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Bypass pre-report gate enforcement (debug only; not for delivery)",
    )
    return parser.parse_args()


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def severity_rank(sev: str) -> int:
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return order.get(sev, 0)


def normalize_verdicts(verdict_data: Any) -> Dict[str, Dict[str, Any]]:
    if verdict_data is None:
        return {}
    if isinstance(verdict_data, dict) and isinstance(verdict_data.get("verdicts"), list):
        items = verdict_data["verdicts"]
    elif isinstance(verdict_data, list):
        items = verdict_data
    elif isinstance(verdict_data, dict):
        items = [verdict_data]
    else:
        items = []

    out: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        fid = str(item.get("finding_id", ""))
        if fid:
            out[fid] = item
    return out


def resolved_severity(finding: Dict[str, Any], verdict: Dict[str, Any] | None) -> str:
    if verdict and verdict.get("severity_action") in {"DOWNGRADED", "UPGRADED"}:
        adjusted = verdict.get("severity_adjusted")
        if isinstance(adjusted, str) and adjusted:
            return adjusted
    return str(finding.get("severity", "INFO"))


def normalize_chains(chains_data: Any) -> List[Dict[str, Any]]:
    if isinstance(chains_data, list):
        return [c for c in chains_data if isinstance(c, dict)]
    if isinstance(chains_data, dict):
        if isinstance(chains_data.get("chains"), list):
            return [c for c in chains_data["chains"] if isinstance(c, dict)]
        return [chains_data]
    return []


def normalize_poc_text(value: Any) -> str:
    """Normalize PoC text so report always contains a single clean fenced block."""
    text = str(value or "").strip()
    if not text:
        return "curl -s 'http://target/api/path'"

    fenced = re.match(r"^\s*```(?:bash|sh|zsh)?\s*\n(.*?)\n```\s*$", text, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()

    cleaned: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("```"):
            continue
        if line.lower() in {"bash", "sh", "zsh"} and not cleaned:
            continue
        cleaned.append(raw.rstrip())

    normalized = "\n".join(cleaned).strip()
    return normalized or "curl -s 'http://target/api/path'"


def run_pre_report_gates(audit_dir: Path, strict: bool = False) -> List[str]:
    gate_script = SCRIPT_DIR / "gate.py"
    if not gate_script.exists():
        raise RuntimeError(f"missing gate script: {gate_script}")

    warnings: List[str] = []
    for gate in PRE_REPORT_GATES:
        cmd = [sys.executable, str(gate_script), gate, str(audit_dir), "--mode", "strict"]
        completed = subprocess.run(cmd, capture_output=True, text=True)
        if completed.returncode != 0:
            details = "\n".join(
                part.strip()
                for part in [completed.stdout, completed.stderr]
                if isinstance(part, str) and part.strip()
            )
            message = f"pre-report {gate} failed for {audit_dir}\n{details}"
            if strict:
                raise RuntimeError(message)
            warnings.append(message)
    return warnings


def render_report(
    findings: List[Dict[str, Any]],
    verdicts: Dict[str, Dict[str, Any]],
    chains: List[Dict[str, Any]],
    precheck_warnings: List[str] | None = None,
) -> str:
    lines: List[str] = []
    precheck_warnings = precheck_warnings or []

    lines.append("# 安全审计复现报告")
    lines.append("")
    lines.append("## 项目概览")
    lines.append(f"- 审计日期：{datetime.utcnow().strftime('%Y-%m-%d')} UTC")
    lines.append("- 审计方式：RECON -> AUDIT -> HARDEN")
    lines.append("- 报告语言：中文")
    if precheck_warnings:
        lines.append("- 预检查状态：存在未通过项（非 strict 模式继续生成），结论可能受覆盖率影响。")
    lines.append("")

    if precheck_warnings:
        lines.append("## 预检查警告")
        lines.append("")
        for msg in precheck_warnings:
            first_line = msg.strip().splitlines()[0] if msg.strip() else "pre-report gate failed"
            lines.append(f"- {first_line}")
        lines.append("")

    enriched: List[Dict[str, Any]] = []
    for finding in findings:
        fid = str(finding.get("id", ""))
        verdict = verdicts.get(fid)
        if verdict and verdict.get("validity_verdict") == "DISPUTED":
            continue
        sev = resolved_severity(finding, verdict)
        row = dict(finding)
        row["severity_final"] = sev
        row["verdict"] = verdict.get("validity_verdict", "CONFIRMED") if verdict else "CONFIRMED"
        enriched.append(row)

    enriched.sort(key=lambda f: severity_rank(str(f.get("severity_final", "INFO"))), reverse=True)
    critical_high = [f for f in enriched if f.get("severity_final") in {"CRITICAL", "HIGH"}]

    lines.append("## 复现总览（Critical/High）")
    lines.append("")
    lines.append("| 编号 | 等级 | 类型 | 路径 | 前置条件 | PoC |")
    lines.append("|---|---|---|---|---|---|")
    for finding in critical_high:
        pre = ", ".join(finding.get("preconditions", [])) or "无"
        lines.append(
            f"| {finding.get('id', '-') } | {finding.get('severity_final', '-') } | {finding.get('type', '-') } | "
            f"{finding.get('file', '-') }:{finding.get('line', '-') } | {pre} | 是 |"
        )
    if not critical_high:
        lines.append("| - | - | - | - | - | - |")
    lines.append("")

    lines.append("## 关键漏洞复现指南")
    lines.append("")
    target_findings = critical_high if critical_high else enriched
    for finding in target_findings:
        lines.append(f"### {finding.get('id', 'F-UNKNOWN')} [{finding.get('type', '未知类型')}]")
        lines.append(f"- 影响：{finding.get('impact', '未提供')}")
        pre = ", ".join(finding.get("preconditions", [])) or "无"
        lines.append(f"- 前置条件：{pre}")
        attacker_view = str(finding.get("attacker_narrative", "")).strip()
        if attacker_view:
            lines.append(f"- 攻击者视角：{attacker_view}")

        refs = ((finding.get("evidence_bundle", {}) or {}).get("primary_refs", []))
        lines.append("- 复现步骤：")
        lines.append(f"1. 根据证据定位 `{finding.get('file', '-')}`:{finding.get('line', '-')}。")
        lines.append("2. 构造与 PoC 一致的输入并发送请求。")
        lines.append("3. 观察响应与副作用并记录证据。")

        if isinstance(refs, list) and refs:
            lines.append("- 关键代码证据：")
            for ref in refs[:3]:
                if not isinstance(ref, dict):
                    continue
                tool = ref.get("tool", "READ")
                file_path = ref.get("file", "-")
                line_start = ref.get("line_start", "-")
                line_end = ref.get("line_end", "-")
                lines.append(f"  - 代码证据（{tool}）：{file_path}:{line_start}-{line_end}")

        lines.append("- 复现命令（PoC）：")
        lines.append("```bash")
        poc = normalize_poc_text(finding.get("poc", "curl -s 'http://target/api/path'"))
        lines.append(poc)
        lines.append("```")
        lines.append(f"- 修复建议：{finding.get('remediation', '请补充修复建议。')}")
        lines.append("")

    lines.append("## 攻击链复现")
    lines.append("")
    if chains:
        for idx, chain in enumerate(chains, start=1):
            chain_id = chain.get("id", f"AC-{idx:03d}")
            lines.append(f"### {chain_id} {chain.get('name', '攻击链')}")
            lines.append(f"- 起点：{chain.get('entry', '未认证或低权限入口')}")
            lines.append(f"- 终点：{chain.get('impact', '高价值影响')}")
            lines.append(f"- 杀伤力：{chain.get('severity', 'HIGH')}")
            lines.append("")
            lines.append("| 步骤 | 漏洞编号 | 操作 | 获得能力 |")
            lines.append("|---|---|---|---|")
            steps = chain.get("steps", [])
            if isinstance(steps, list) and steps:
                for sidx, step in enumerate(steps, start=1):
                    if not isinstance(step, dict):
                        continue
                    lines.append(
                        f"| {sidx} | {step.get('finding_id', '-') } | {step.get('action', '-') } | {step.get('capability', '-') } |"
                    )
            else:
                lines.append("| 1 | - | 结合 findings 逐步复现 | 能力提升 |")
            lines.append("")
    else:
        lines.append("### AC-001 基础链路")
        lines.append("- 起点：公开入口")
        lines.append("- 终点：敏感数据读取或状态篡改")
        lines.append("- 杀伤力：HIGH")
        lines.append("")
        lines.append("| 步骤 | 漏洞编号 | 操作 | 获得能力 |")
        lines.append("|---|---|---|---|")
        lines.append("| 1 | - | 结合 findings 逐项复现 | 初始能力 |")
        lines.append("")

    lines.append("## 修复优先级")
    lines.append("1. 优先修复未认证且可形成攻击链起点的高危端点。")
    lines.append("2. 优先修复凭据修改、资金变更、密钥泄露相关漏洞。")
    lines.append("3. 修复后重新执行 gate 与 coverage 校验。")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if args.lang.lower() != "zh-cn":
        print("warning: only zh-CN template is currently supported; continuing with zh-CN output")

    audit_dir = Path(args.audit_dir)
    out_path = Path(args.out) if args.out else audit_dir / "report.md"

    precheck_warnings: List[str] = []
    if not args.allow_incomplete:
        try:
            precheck_warnings = run_pre_report_gates(audit_dir, strict=args.strict)
            for warning in precheck_warnings:
                print(f"warning: {warning}", file=sys.stderr)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            print(
                "hint: run RECON first and ensure G0 passes before report generation, or run without --strict.",
                file=sys.stderr,
            )
            return 1

    if not args.allow_incomplete:
        coverage_path = audit_dir / "coverage.json"
        if coverage_path.exists():
            coverage_data = load_json(coverage_path)
            if isinstance(coverage_data, dict) and coverage_data.get("r2_required"):
                print(
                    "error: coverage.r2_required=true; return to AUDIT phase with coverage.next_targets before generating report.",
                    file=sys.stderr,
                )
                print(
                    f"hint: next_targets={coverage_data.get('next_targets', [])[:10]}",
                    file=sys.stderr,
                )
                return 1

    findings = load_jsonl(audit_dir / "findings.jsonl")
    verdicts = normalize_verdicts(load_json(audit_dir / "verdict.json"))
    chains = normalize_chains(load_json(audit_dir / "chains.json"))

    report = render_report(findings, verdicts, chains, precheck_warnings=precheck_warnings)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report + "\n", encoding="utf-8")

    print(f"report generated: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
