#!/usr/bin/env python3
"""Extract findings/chains from audit/findings.md into JSON artifacts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

FINDING_HEADING_RE = re.compile(r"^###\s*(F-[A-Za-z0-9_-]+)\s*:\s*(.+?)\s*$")
CHAIN_HEADING_RE = re.compile(
    r"^###\s*(?:攻击链|Attack\s*Chain)\s*(AC-[A-Za-z0-9_-]+)\s*:\s*(.+?)\s*$",
    re.IGNORECASE,
)
MI_LABEL_RE = re.compile(
    r"\*\*(?:MI-ID|MI_ID|Must[- ]?Investigate(?:\s*ID)?)\*\*\s*:\s*([A-Za-z0-9_-]+)",
    re.IGNORECASE,
)
FILE_LINE_RE = re.compile(
    r"(?P<file>[A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+):(?P<line>\d+)|"
    r"(?P<file2>[A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+)#L(?P<line2>\d+)"
)
FILE_ONLY_RE = re.compile(r"([A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+)")
SEVERITY_SET = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from shared_utils import load_jsonl, normalize_file, files_match, normalize_mi_id


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract findings.jsonl/chains.json from findings.md")
    parser.add_argument("audit_dir", nargs="?", default="audit", help="Audit directory")
    parser.add_argument("--in", dest="input_md", default=None, help="Input markdown path (default: <audit_dir>/findings.md)")
    parser.add_argument("--out", dest="output_jsonl", default=None, help="Output findings.jsonl path")
    parser.add_argument("--chains", dest="chains_json", default=None, help="Output chains.json path")
    parser.add_argument(
        "--lenient",
        action="store_true",
        help="Downgrade extraction quality errors to warnings instead of failing",
    )
    return parser.parse_args()





def load_inventory_files(audit_dir: Path) -> List[str]:
    inventory_path = audit_dir / "inventory.jsonl"
    if not inventory_path.exists():
        return []
    files: List[str] = []
    seen: set[str] = set()
    for row in load_jsonl(inventory_path):
        file_path = normalize_file(row.get("file", ""))
        if not file_path or file_path in seen:
            continue
        seen.add(file_path)
        files.append(file_path)
    return files





def canonicalize_file(path: str, inventory_files: Sequence[str]) -> str:
    normalized = normalize_file(path)
    if not normalized:
        return normalized
    if not inventory_files:
        return normalized

    candidates: List[str] = []
    for inv in inventory_files:
        if files_match(inv, normalized):
            candidates.append(inv)

    if not candidates:
        return normalized

    def score(candidate: str) -> Tuple[int, int]:
        cand = normalize_file(candidate)
        if cand == normalized:
            return (0, len(cand))
        if normalized.endswith(f"/{cand}"):
            return (1, len(cand))
        if cand.endswith(f"/{normalized}"):
            return (2, len(cand))
        return (3, len(cand))

    return min(candidates, key=score)


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


def extract_evidence_refs(block_lines: Sequence[str]) -> List[Tuple[str, int]]:
    refs: List[Tuple[str, int]] = []
    in_evidence = False
    for raw in block_lines:
        stripped = raw.strip()
        if re.match(r"^-?\s*\*\*(?:证据|Evidence)\*\*\s*:", stripped, flags=re.IGNORECASE):
            in_evidence = True
            for path, line in iter_file_line_refs(stripped):
                refs.append((path, line))
            continue

        if in_evidence and re.match(r"^-?\s*\*\*.+\*\*\s*:", stripped):
            break

        if not in_evidence:
            continue

        for path, line in iter_file_line_refs(stripped):
            refs.append((path, line))

    return refs


def find_label_value(block_text: str, label: str) -> str:
    pattern = re.compile(rf"\*\*{re.escape(label)}\*\*\s*:\s*(.+)")
    match = pattern.search(block_text)
    return match.group(1).strip() if match else ""





_LABEL_ALIASES: Dict[str, List[str]] = {
    "严重程度": ["严重程度", "Severity", "severity"],
    "类型": ["类型", "问题类型", "漏洞类型", "Type", "type", "Category"],
    "文件": ["文件", "文件路径", "File", "file"],
    "行号": ["行号", "Line", "line"],
    "攻击者视角": ["攻击者视角", "描述", "问题描述", "Attacker Perspective", "Description", "description"],
    "前置条件": ["前置条件", "认证要求", "权限要求", "Preconditions", "preconditions", "Prerequisites"],
    "修复建议": ["修复建议", "Remediation", "remediation", "Fix"],
    "反证检查": ["反证检查", "Disproof Check", "disproof", "Counter-evidence"],
}


def find_label_value_bilingual(block_text: str, label: str) -> str:
    candidates = _LABEL_ALIASES.get(label, [label])
    for candidate in candidates:
        result = find_label_value(block_text, candidate)
        if result:
            return result
    return ""


def iter_file_line_refs(text: str) -> Iterable[Tuple[str, int]]:
    for match in FILE_LINE_RE.finditer(text):
        file_path = match.group("file") or match.group("file2") or ""
        line_raw = match.group("line") or match.group("line2") or ""
        if not file_path or not line_raw:
            continue
        if file_path.startswith(("http://", "https://")):
            continue
        try:
            line = int(line_raw)
        except ValueError:
            continue
        if line < 1:
            continue
        yield normalize_file(file_path), line


def iter_file_only_refs(text: str) -> Iterable[str]:
    for match in FILE_ONLY_RE.finditer(text):
        file_path = match.group(1) or ""
        if not file_path:
            continue
        if file_path.startswith(("http://", "https://")):
            continue
        yield normalize_file(file_path)


def looks_like_file_path(value: str) -> bool:
    text = normalize_file(value)
    if not text:
        return False
    if "." in text:
        return True
    return "/" in text


def parse_poc(block_lines: Sequence[str]) -> str:
    in_block = False
    collected: List[str] = []
    for raw in block_lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if stripped.startswith("```"):
            if not in_block:
                in_block = True
                continue
            break
        if in_block:
            collected.append(line)
    poc = "\n".join(collected).strip()
    if poc:
        return poc
    return "curl -s 'http://target/api/path'"


def parse_commands_from_poc(poc: str) -> List[str]:
    commands: List[str] = []
    for raw in poc.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        commands.append(line)
    return commands


def parse_preconditions(text: str) -> List[str]:
    value = text.strip()
    if not value:
        return ["无"]
    parts = re.split(r"\s*[/,;，；]\s*", value)
    out = [p.strip() for p in parts if p.strip()]
    return out or [value]


def choose_primary_file_line(
    block_text: str,
    fallback_refs: List[Tuple[str, int]],
    inventory_files: Sequence[str],
) -> Tuple[str, int]:
    file_field = find_label_value_bilingual(block_text, "文件")
    for path, line in iter_file_line_refs(file_field):
        return canonicalize_file(path, inventory_files), line

    # Dotfiles (e.g. `.env`) and plain file paths without line markers.
    cleaned = file_field.strip().strip("`").strip()
    if cleaned:
        cleaned = normalize_file(cleaned)
        if cleaned and " " not in cleaned and looks_like_file_path(cleaned):
            line_field = find_label_value_bilingual(block_text, "行号")
            line_match = re.search(r"([0-9]+)", line_field or "")
            line_value = int(line_match.group(1)) if line_match else 1
            return canonicalize_file(cleaned, inventory_files), max(1, line_value)

    file_guess_match = re.search(r"([A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+)", file_field)
    if file_guess_match:
        line_field = find_label_value_bilingual(block_text, "行号")
        line_match = re.search(r"([0-9]+)", line_field or "")
        line_value = int(line_match.group(1)) if line_match else 1
        return canonicalize_file(normalize_file(file_guess_match.group(1)), inventory_files), max(1, line_value)

    for path in iter_file_only_refs(block_text):
        if path:
            return canonicalize_file(path, inventory_files), 1

    if fallback_refs:
        return canonicalize_file(fallback_refs[0][0], inventory_files), fallback_refs[0][1]
    return "unknown.ts", 1


def refs_to_primary_evidence(
    refs: List[Tuple[str, int]],
    inventory_files: Sequence[str],
) -> List[Dict[str, Any]]:
    seen: set[Tuple[str, int]] = set()
    out: List[Dict[str, Any]] = []
    for path, line in refs:
        path = canonicalize_file(path, inventory_files)
        key = (path, line)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "tool": "READ",
                "file": path,
                "line_start": line,
                "line_end": line,
                "note": "extracted from findings.md",
            }
        )
    return out


def map_signals_by_file(signals: Sequence[Dict[str, Any]], file_path: str) -> List[str]:
    ids: List[str] = []
    for signal in signals:
        sid = str(signal.get("signal_id", "")).strip()
        if not sid:
            continue
        if files_match(file_path, signal.get("file")):
            ids.append(sid)
    return sorted(set(ids))


def parse_findings(
    markdown: str,
    signals: Sequence[Dict[str, Any]],
    inventory_files: Sequence[str],
) -> List[Dict[str, Any]]:
    lines = markdown.splitlines()
    sections = parse_md_sections(lines, FINDING_HEADING_RE, stop_on_h2=True)
    findings: List[Dict[str, Any]] = []

    for finding_id, title, block_lines in sections:
        block_text = "\n".join(block_lines)
        refs = extract_evidence_refs(block_lines)
        if not refs:
            refs = list(iter_file_line_refs(block_text))
        file_path, line = choose_primary_file_line(block_text, refs, inventory_files)

        sev = find_label_value_bilingual(block_text, "严重程度").upper()
        if sev not in SEVERITY_SET:
            sev = "MEDIUM"

        finding_type = find_label_value_bilingual(block_text, "类型") or "UNSPECIFIED"
        attacker_narrative = find_label_value_bilingual(block_text, "攻击者视角")
        if not attacker_narrative:
            attacker_narrative = f"发现 {title}，需结合证据进一步评估攻击者路径。"
        pre_text = find_label_value_bilingual(block_text, "前置条件")
        remediation = find_label_value_bilingual(block_text, "修复建议") or "修复缺失鉴权与数据最小化控制。"
        disproof = find_label_value_bilingual(block_text, "反证检查") or "未发现可反驳该漏洞成立的充分防护。"
        impact = title

        poc = parse_poc(block_lines)
        commands = parse_commands_from_poc(poc)

        primary_refs = refs_to_primary_evidence(refs, inventory_files)
        if not primary_refs:
            primary_refs = refs_to_primary_evidence([(file_path, line)], inventory_files)

        finding = {
            "schema_version": 1,
            "id": finding_id,
            "hypothesis_id": "DIRECT",
            "type": finding_type,
            "file": file_path,
            "line": line,
            "source": "code evidence",
            "sink": "security impact",
            "dataflow": disproof,
            "exploitability": "PROVEN",
            "severity": sev,
            "preconditions": parse_preconditions(pre_text),
            "impact": impact,
            "poc": poc,
            "remediation": remediation,
            "chain_refs": [],
            "anomaly_refs": [],
            "discovered_from_signal_ids": map_signals_by_file(signals, file_path),
            "evidence_bundle": {
                "primary_refs": primary_refs,
                "commands": commands,
                "auth_context": pre_text or "未说明",
                "taint_summary": disproof,
            },
            "confidence": 0.85,
            "attacker_narrative": attacker_narrative,
        }
        findings.append(finding)

    return findings


def parse_chains(markdown: str) -> List[Dict[str, Any]]:
    lines = markdown.splitlines()
    sections = parse_md_sections(lines, CHAIN_HEADING_RE, stop_on_h2=True)
    chains: List[Dict[str, Any]] = []

    for chain_id, title, block_lines in sections:
        block_text = "\n".join(block_lines)
        path_line = ""
        for raw in block_lines:
            if "->" in raw:
                path_line = raw.strip().lstrip("- ").strip()
                break

        entry = "公开入口"
        impact = "权限提升或高价值操作"
        if path_line:
            segments = [seg.strip() for seg in path_line.split("->") if seg.strip()]
            if segments:
                entry = segments[0]
                impact = segments[-1]

        finding_ids = re.findall(r"(F-[A-Za-z0-9_-]+)", block_text)
        unique_ids: List[str] = []
        for fid in finding_ids:
            if fid not in unique_ids:
                unique_ids.append(fid)

        steps = [
            {
                "finding_id": fid,
                "action": f"利用 {fid}",
                "capability": "能力提升",
            }
            for fid in unique_ids
        ]

        chains.append(
            {
                "id": chain_id,
                "name": title,
                "entry": entry,
                "impact": impact,
                "severity": "HIGH",
                "steps": steps,
            }
        )

    return chains


def extract_mi_ids_from_markdown(markdown: str) -> List[str]:
    lines = markdown.splitlines()
    sections = parse_md_sections(lines, FINDING_HEADING_RE, stop_on_h2=True)
    out: List[str] = []
    seen: set[str] = set()
    for _fid, _title, block_lines in sections:
        block = "\n".join(block_lines)
        for match in MI_LABEL_RE.finditer(block):
            mi = normalize_mi_id(match.group(1))
            if mi and mi not in seen:
                seen.add(mi)
                out.append(mi)
    return out


def attach_chain_refs(findings: List[Dict[str, Any]], chains: Sequence[Dict[str, Any]]) -> None:
    refs_by_finding: Dict[str, List[str]] = {}
    for chain in chains:
        cid = str(chain.get("id", "")).strip()
        if not cid:
            continue
        for step in chain.get("steps", []):
            if not isinstance(step, dict):
                continue
            fid = str(step.get("finding_id", "")).strip()
            if not fid:
                continue
            refs_by_finding.setdefault(fid, [])
            if cid not in refs_by_finding[fid]:
                refs_by_finding[fid].append(cid)

    for finding in findings:
        fid = str(finding.get("id", "")).strip()
        if fid in refs_by_finding:
            finding["chain_refs"] = refs_by_finding[fid]


def dump_findings(path: Path, findings: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for finding in findings:
            fh.write(json.dumps(finding, ensure_ascii=False) + "\n")


def dump_chains(path: Path, chains: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"chains": list(chains)}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    audit_dir = Path(args.audit_dir)
    input_md = Path(args.input_md) if args.input_md else audit_dir / "findings.md"
    output_jsonl = Path(args.output_jsonl) if args.output_jsonl else audit_dir / "findings.jsonl"
    chains_json = Path(args.chains_json) if args.chains_json else audit_dir / "chains.json"

    if not input_md.exists():
        raise SystemExit(f"input findings markdown does not exist: {input_md}")

    markdown = input_md.read_text(encoding="utf-8")
    signals = load_jsonl(audit_dir / "attack-surface.jsonl")
    inventory_files = load_inventory_files(audit_dir)

    findings = parse_findings(markdown, signals, inventory_files)
    chains = parse_chains(markdown)
    attach_chain_refs(findings, chains)

    suspicious_unparsed = (
        "## ALERT" in markdown
        or "| File | Trigger |" in markdown
        or "| File | Sink Type |" in markdown
        or ("**Level**" in markdown and "**Pattern**" in markdown)
        or ("### " in markdown and "F-" in markdown and not findings)
    )
    if not args.lenient and suspicious_unparsed and not findings:
        print(
            "error: 0 findings extracted from findings.md but input looks like alert/report content. "
            "Use canonical format `### F-XXX:` with Chinese labels, or run "
            "`validate_findings_md.py` before extraction.",
            file=sys.stderr,
        )
        return 1

    dump_findings(output_jsonl, findings)
    dump_chains(chains_json, chains)

    unknown_count = sum(1 for f in findings if f.get("file") == "unknown.ts")
    empty_narrative = sum(1 for f in findings if not f.get("attacker_narrative"))

    if unknown_count > 0:
        print(
            f"WARNING: {unknown_count}/{len(findings)} findings have file=unknown.ts (label extraction likely failed)",
            file=sys.stderr,
        )
    if findings and empty_narrative > len(findings) * 0.5:
        print(
            f"WARNING: {empty_narrative}/{len(findings)} findings have empty attacker_narrative",
            file=sys.stderr,
        )

    must_path = audit_dir / "must_investigate.jsonl"
    if must_path.exists():
        try:
            must_rows = load_jsonl(must_path)
            required_mi = {
                normalize_mi_id(row.get("anomaly_id", "") or row.get("mi_id", ""))
                for row in must_rows
            }
            required_mi = {x for x in required_mi if x}
            found_mi = set(extract_mi_ids_from_markdown(markdown))
            missing_mi = sorted(required_mi - found_mi)
            extra_mi = sorted(found_mi - required_mi)
            if missing_mi:
                print(
                    f"WARNING: missing MI-ID coverage in findings.md: {', '.join(missing_mi[:20])}",
                    file=sys.stderr,
                )
            if extra_mi:
                print(
                    f"WARNING: unknown MI-ID in findings.md (not in must_investigate): {', '.join(extra_mi[:20])}",
                    file=sys.stderr,
                )
        except Exception as exc:
            print(f"WARNING: unable to run MI-ID consistency check: {exc}", file=sys.stderr)

    if not args.lenient and findings:
        if unknown_count > 0 or empty_narrative > len(findings) * 0.5:
            print(
                "error: extraction quality too low for delivery. Fix findings.md labels "
                "(must use Chinese: **严重程度**:, **文件**:, etc.) or re-run with --lenient",
                file=sys.stderr,
            )
            return 1

    print(f"findings extracted: {len(findings)} -> {output_jsonl}")
    print(f"chains extracted: {len(chains)} -> {chains_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
