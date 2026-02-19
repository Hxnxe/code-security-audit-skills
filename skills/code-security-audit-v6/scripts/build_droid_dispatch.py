#!/usr/bin/env python3
"""Build explicit droid dispatch payloads from shard plan.

Outputs per shard:
- audit/droid_dispatch/<shard_id>.json
- audit/droid_dispatch/<shard_id>.md
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from shared_utils import estimate_tokens, ALL_AGENTS, normalize_file, files_match, normalize_mi_id


AGENTS = tuple(ALL_AGENTS)

INJECTION_HINTS = (
    "sql",
    "query",
    "literal",
    "injection",
    "sink_sql",
    "sql_raw",
    "sql_literal",
    "raw_query",
    "sequelize",
    "raw",
    "command-exec",
    "cmd_exec",
    "exec",
)
INFRA_HINTS = (
    "non-runtime",
    "seed",
    "seeder",
    "migration",
    ".env",
    "credential",
    "secret",
    "config",
    "default password",
    "hardcoded",
)
ACCESS_HINTS = (
    "auth",
    "login",
    "permission",
    "requiresauth",
    "public",
    "settings",
    "blog",
    "semantic contradiction",
    "pii",
    "email",
    "phone",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build explicit droid dispatch payloads")
    parser.add_argument("--audit-dir", default="audit", help="Audit directory")
    parser.add_argument(
        "--shard-id",
        default=None,
        help="Only generate for a single shard id (e.g., S001). Default: all shards",
    )
    parser.add_argument(
        "--project-root",
        default="<project_root>",
        help="Project root placeholder used in prompt snippets",
    )
    parser.add_argument(
        "--audit-dir-ref",
        default="<audit_dir>",
        help="Audit dir placeholder used in prompt snippets",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=80000,
        help="Token budget per agent per shard (default: 80000)",
    )
    return parser.parse_args()





def load_mi_index(audit_dir: Path) -> Dict[str, List[str]]:
    path = audit_dir / "must_investigate.jsonl"
    if not path.exists():
        return {}

    index: Dict[str, List[str]] = {}
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            file_path = normalize_file(str(row.get("file", "")))
            mi_id = normalize_mi_id(str(row.get("anomaly_id", "") or row.get("mi_id", "")))
            if not file_path or not mi_id:
                continue
            index.setdefault(file_path, [])
            if mi_id not in index[file_path]:
                index[file_path].append(mi_id)
    return index


def resolve_mi_ids(file_path: str, mi_index: Dict[str, List[str]]) -> List[str]:
    normalized = normalize_file(file_path)
    if not normalized:
        return []
    direct = mi_index.get(normalized, [])
    if direct:
        return list(direct)

    merged: List[str] = []
    for key, ids in mi_index.items():
        if files_match(key, normalized):
            for mi in ids:
                if mi not in merged:
                    merged.append(mi)
    return merged


def classify_target(file_path: str, reason: str) -> str:
    normalized_file = normalize_file(file_path)
    reason_lower = str(reason or "").lower()
    corpus = f"{normalized_file} {reason_lower}"

    sink_tokens = extract_sink_tokens(reason_lower)
    if sink_tokens:
        if any(token in {"credential_write", "password_write", "auth_write"} for token in sink_tokens):
            return "access-scanner"
        if any(token in {"sql_raw", "sql_literal", "raw_query", "sink_sql", "sink_sql_literal"} for token in sink_tokens):
            return "injection-scanner"
        if any(token in {"cmd_exec", "command_exec", "sink_cmd_exec"} for token in sink_tokens):
            return "injection-scanner"

    if any(h in corpus for h in INJECTION_HINTS):
        return "injection-scanner"
    if any(h in corpus for h in INFRA_HINTS):
        return "infra-scanner"
    if any(h in corpus for h in ACCESS_HINTS):
        return "access-scanner"
    return "access-scanner"


def extract_sink_tokens(reason_lower: str) -> List[str]:
    marker = "dangerous sinks:"
    if marker not in reason_lower:
        return []
    tail = reason_lower.split(marker, 1)[1]
    # "credential_write, sql_literal" -> ["credential_write", "sql_literal"]
    out: List[str] = []
    for raw in re.split(r"[,\s]+", tail):
        token = raw.strip(" .;|")
        if token:
            out.append(token)
    return out


def load_shards(path: Path) -> List[Dict[str, object]]:
    if not path.exists():
        raise FileNotFoundError(f"missing shard plan: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    shards = data.get("shards", [])
    if not isinstance(shards, list):
        raise ValueError("audit_target_shards.json invalid: .shards must be list")
    out: List[Dict[str, object]] = []
    for shard in shards:
        if isinstance(shard, dict):
            out.append(shard)
    return out


def build_assignment(
    shard: Dict[str, object],
    mi_index: Dict[str, List[str]],
) -> Dict[str, List[Dict[str, object]]]:
    assigned: Dict[str, List[Dict[str, object]]] = {agent: [] for agent in AGENTS}
    targets = shard.get("targets", [])
    if not isinstance(targets, list):
        return assigned

    for item in targets:
        if not isinstance(item, dict):
            continue
        file_path = normalize_file(str(item.get("file", "")))
        reason = str(item.get("reason", "-"))
        if not file_path:
            continue
        agent = classify_target(file_path, reason)
        mi_ids = resolve_mi_ids(file_path, mi_index)
        assigned[agent].append(
            {
                "file": file_path,
                "reason": reason,
                "stratum": str(item.get("stratum", "-")),
                "mi_ids": mi_ids,
            }
        )
    return assigned


def render_prompt_block(
    agent: str,
    shard_id: str,
    items: Sequence[Dict[str, object]],
    project_root: str,
    audit_dir_ref: str,
) -> str:
    if agent == "chain-synthesizer":
        return "\n".join(
            [
                f"### {agent} / {shard_id}",
                "",
                "Task payload (copy into Task prompt):",
                "",
                f"Project root: {project_root}",
                f"Audit dir: {audit_dir_ref}",
                f"Current shard: {shard_id}",
                "输入来源（只读）：",
                "- audit/findings.md",
                "- audit/findings.jsonl (if exists)",
                "- audit/scanner-alerts/*.md (if exists)",
                "输出：audit/attack-graph.md",
                "约束：禁止创建新 F-XXX，仅可串联已存在 findings。",
                "",
            ]
        )

    lines: List[str] = []
    lines.append(f"### {agent} / {shard_id}")
    lines.append("")
    lines.append("Task payload (copy into Task prompt):")
    lines.append("")
    lines.append(f"Project root: {project_root}")
    lines.append(f"Audit dir: {audit_dir_ref}")
    lines.append(f"Current shard: {shard_id}")
    lines.append("请只审计以下文件（必须逐个给出结论）：")
    for item in items:
        mi_ids = item.get("mi_ids", [])
        mi_text = ",".join(str(x) for x in mi_ids) if isinstance(mi_ids, list) and mi_ids else "N/A"
        lines.append(
            f"- {item['file']}  # MI-ID={mi_text} reason={item['reason']} stratum={item['stratum']}"
        )
    lines.append("")
    lines.append("约束：若文件行包含 MI-ID，不得自造新 MI-ID；逐文件结论必须复用上述 MI-ID。")
    lines.append("")
    lines.append("输出必须包含: ALERT / STATS / LSP_EVIDENCE / 逐文件结论")
    lines.append("")
    return "\n".join(lines)


def render_dispatch_md(
    shard_id: str,
    shard_priority: str,
    assigned: Dict[str, List[Dict[str, object]]],
    project_root: str,
    audit_dir_ref: str,
) -> str:
    total = sum(len(v) for v in assigned.values())
    lines: List[str] = []
    lines.append(f"# Droid Dispatch {shard_id}")
    lines.append("")
    lines.append(f"- priority: {shard_priority}")
    lines.append(f"- targets: {total}")
    lines.append("")
    lines.append("| agent | files |")
    lines.append("|---|---:|")
    for agent in AGENTS:
        lines.append(f"| {agent} | {len(assigned[agent])} |")
    lines.append("")
    for agent in AGENTS:
        lines.append(
            render_prompt_block(
                agent=agent,
                shard_id=shard_id,
                items=assigned[agent],
                project_root=project_root,
                audit_dir_ref=audit_dir_ref,
            )
        )
    return "\n".join(lines).strip() + "\n"


def main() -> int:
    args = parse_args()
    audit_dir = Path(args.audit_dir).resolve()
    shards_path = audit_dir / "audit_target_shards.json"
    dispatch_dir = audit_dir / "droid_dispatch"
    dispatch_dir.mkdir(parents=True, exist_ok=True)
    mi_index = load_mi_index(audit_dir)

    shards = load_shards(shards_path)
    if args.shard_id:
        shards = [s for s in shards if str(s.get("shard_id", "")) == args.shard_id]
        if not shards:
            raise SystemExit(f"shard not found: {args.shard_id}")

    generated = 0
    for shard in shards:
        shard_id = str(shard.get("shard_id", "")).strip()
        if not shard_id:
            continue
        priority = str(shard.get("priority", "P1"))
        assigned = build_assignment(shard, mi_index)
        
        for agent, items in assigned.items():
            if not items:
                continue
            texts: List[str] = []
            for item in items:
                file_path = audit_dir / str(item.get("file", ""))
                if file_path.exists():
                    try:
                        texts.append(file_path.read_text(encoding="utf-8", errors="ignore"))
                    except OSError:
                        pass
            tokens = estimate_tokens(texts)
            if tokens > args.max_tokens:
                msg = (
                    f"WARNING: {shard_id}/{agent} estimated {tokens} tokens > budget {args.max_tokens}. "
                    "Consider splitting into sub-shards."
                )
                print(msg, file=sys.stderr)
        
        payload = {
            "schema_version": 1,
            "shard_id": shard_id,
            "priority": priority,
            "agents": {
                agent: {
                    "target_count": len(items),
                    "targets": items,
                }
                for agent, items in assigned.items()
            },
        }

        json_path = dispatch_dir / f"{shard_id}.json"
        md_path = dispatch_dir / f"{shard_id}.md"
        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        md_path.write_text(
            render_dispatch_md(
                shard_id=shard_id,
                shard_priority=priority,
                assigned=assigned,
                project_root=args.project_root,
                audit_dir_ref=args.audit_dir_ref,
            ),
            encoding="utf-8",
        )
        generated += 1

    print(f"droid dispatch generated: {generated} shard(s) -> {dispatch_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
