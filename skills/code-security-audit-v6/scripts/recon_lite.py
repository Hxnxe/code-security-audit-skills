#!/usr/bin/env python3
"""V6 lightweight RECON builder.

Generate V5-compatible artifacts with lightweight rg/sg scanning:
- inventory.jsonl
- attack-surface.jsonl
- scope_stats.json
- batches.json
- attack_surface_stats.json
- anomalies.jsonl
- must_investigate.jsonl
- audit_targets.md
- repo_overview.md
- audit_target_shards.json
- audit_target_shards.md
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from shared_utils import now_utc, normalize_file


LANG_MAP = {
    ".py": "python",
    ".go": "go",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".kt": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "bash",
    ".pl": "perl",
    ".r": "r",
    ".lua": "lua",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".ml": "ocaml",
}

STRATUM_ORDER = ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]
CRITICAL_STRATA = {"S1", "S2", "S3", "S4", "S6"}
SINK_FOCUS_CATEGORIES = {"SINK_SQL_LITERAL", "AUTH_LOGIC_WEAKNESS", "CONFIG_EXPOSURE"}

RG_GLOBAL_EXCLUDES = [
    "!**/node_modules/**",
    "!**/.git/**",
    "!**/.opencode/**",
    "!**/audit/**",
    "!**/dist/**",
    "!**/build/**",
    "!**/coverage/**",
    "!**/vendor/**",
]

SEC_KW_RE = re.compile(r"\b(password|secret|token|auth)\b", re.IGNORECASE)

PATH_ENDPOINT_HINT_RE = re.compile(
    r"(^|/)(route|routes|controller|controllers|handler|handlers|endpoint|endpoints)(/|\.|$)",
    re.IGNORECASE,
)
PATH_WRITE_HINT_RE = re.compile(
    r"(create|update|upsert|delete|destroy|save|write)", re.IGNORECASE
)
PATH_SENSITIVE_HINT_RE = re.compile(
    r"(auth|login|register|password|secret|token|wallet|finance|payment|admin|user|profile)",
    re.IGNORECASE,
)
PATH_TRIAGE_HINT_RE = re.compile(r"(query|sql|db|command|exec|shell)", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build V6 RECON artifacts from rg/sg.")
    parser.add_argument("api_root", help="API root path")
    parser.add_argument("--audit-dir", default="audit", help="Audit output directory")
    parser.add_argument(
        "--project-root",
        default=None,
        help="Project root (auto-inferred when omitted)",
    )
    parser.add_argument(
        "--rules-dir",
        default=str((SCRIPT_DIR.parent / "rules" / "patterns").resolve()),
        help="Pattern rules directory",
    )
    parser.add_argument(
        "--max-files-per-shard",
        type=int,
        default=15,
        help="Maximum files per shard",
    )
    parser.add_argument(
        "--target-limit",
        type=int,
        default=60,
        help="Total P0+P1 target cap",
    )
    parser.add_argument(
        "--tokens-per-line",
        type=int,
        default=15,
        help="Estimated tokens per source line",
    )
    return parser.parse_args()


def infer_project_root(api_root: Path) -> Path:
    for parent in [api_root, *api_root.parents]:
        if (
            (parent / "package.json").exists()
            or (parent / ".git").exists()
            or (parent / "pyproject.toml").exists()
        ):
            return parent
    return api_root.parent


def run_cmd(cmd: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(cmd), cwd=str(cwd), capture_output=True, text=True)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def has_lang(path: str) -> bool:
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix not in LANG_MAP:
        return False
    if p.name.endswith(".d.ts") or p.name.endswith(".min.js"):
        return False
    return True


def detect_language(path: str) -> str:
    return LANG_MAP.get(Path(path).suffix.lower(), "unknown")


def list_files(api_root: Path) -> List[str]:
    if not shutil.which("rg"):
        raise RuntimeError("rg is required but not found")
    cmd = ["rg", "--files"]
    for glob_pat in RG_GLOBAL_EXCLUDES:
        cmd.extend(["-g", glob_pat])
    cmd.append(".")
    completed = run_cmd(cmd, api_root)
    if completed.returncode not in {0, 1}:
        raise RuntimeError(f"rg --files failed: {completed.stderr.strip()}")
    out: List[str] = []
    seen = set()
    for raw in completed.stdout.splitlines():
        rel = normalize_file(raw)
        if not rel or rel in seen:
            continue
        seen.add(rel)
        out.append(rel)
    return sorted(out)


def estimate_lines(path: Path) -> int:
    # Fast estimate: avoid reading full files during RECON.
    try:
        size = int(path.stat().st_size)
    except OSError:
        return 1
    if size <= 0:
        return 1
    return max(1, min(50000, int(size / 40) + 1))


def is_likely_endpoint_fast(file_path: str, language: str) -> bool:
    normalized = normalize_file(file_path).lower()
    wrapped = f"/{normalized}/"
    if PATH_ENDPOINT_HINT_RE.search(normalized):
        return True
    if language in {"typescript", "javascript"} and normalized.endswith(
        (".get.ts", ".post.ts", ".put.ts", ".patch.ts", ".delete.ts")
    ):
        return True
    if language == "python" and any(
        x in wrapped for x in ("/views/", "/api/", "/urls.py/")
    ):
        return True
    if language == "go" and any(x in wrapped for x in ("/handlers/", "/handler/")):
        return True
    if language == "java" and any(
        x in wrapped for x in ("/controller/", "/controllers/")
    ):
        return True
    return False


def classify_stratum(
    sink_hits: Sequence[str], flags: Sequence[str], likely_endpoint: bool
) -> str:
    flags_set = set(flags)
    sink_set = set(sink_hits)
    if likely_endpoint and "WRITE_OP" in sink_set:
        return "S1"
    if likely_endpoint and "SENSITIVE_IO" in sink_set:
        return "S2"
    if likely_endpoint:
        return "S3"
    if not likely_endpoint and "TRIAGE_FLAGGED" in flags_set:
        return "S4"
    if "CRITICAL_MODULE" in flags_set:
        return "S5"
    if "TRIAGE_FLAGGED" in flags_set:
        return "S6"
    return "S7"


def compute_risk_score(
    sink_hits: Sequence[str],
    flags: Sequence[str],
    stratum: str,
    likely_endpoint: bool,
    lines: int,
) -> int:
    score = 0
    stratum_scores = {
        "S1": 100,
        "S2": 80,
        "S3": 60,
        "S4": 50,
        "S5": 70,
        "S6": 40,
        "S7": 10,
    }
    score += stratum_scores.get(stratum, 0)
    score += len(set(sink_hits)) * 10
    score += len(set(flags)) * 5
    if likely_endpoint:
        score += 20
    if lines > 1000:
        score += 20
    elif lines > 500:
        score += 10
    return score


def is_critical_module(module: str, file_path: str) -> bool:
    hints = {"admin", "finance", "auth", "wallet"}
    module_norm = module.lower().strip()
    if module_norm in hints:
        return True
    wrapped = f"/{normalize_file(file_path).lower()}/"
    return any(f"/{hint}/" in wrapped for hint in hints)


def build_inventory(api_root: Path, all_files: Sequence[str]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for rel in all_files:
        if not has_lang(rel):
            continue
        abs_path = api_root / rel
        language = detect_language(rel)
        likely = is_likely_endpoint_fast(rel, language)
        lines = estimate_lines(abs_path)
        module = rel.split("/", 1)[0] if "/" in rel else rel

        sink_hits: List[str] = []
        flags: List[str] = []
        if PATH_WRITE_HINT_RE.search(rel):
            sink_hits.append("WRITE_OP")
            flags.append("WRITE_OP")
        if PATH_SENSITIVE_HINT_RE.search(rel):
            sink_hits.append("SENSITIVE_IO")
            flags.append("SENSITIVE_IO")
        if likely and PATH_TRIAGE_HINT_RE.search(rel):
            sink_hits.append("TRIAGE_FLAGGED")
            flags.append("TRIAGE_FLAGGED")
        if is_critical_module(module, rel):
            flags.append("CRITICAL_MODULE")

        stratum = classify_stratum(sink_hits, flags, likely)
        risk_score = compute_risk_score(sink_hits, flags, stratum, likely, lines)

        rec: Dict[str, Any] = {
            "file": rel,
            "language": language,
            "likely_endpoint": likely,
            "stratum": stratum,
            "risk_score": risk_score,
            "lines": lines,
            "module": module,
        }
        if sink_hits:
            rec["sink_hits"] = sorted(set(sink_hits))
        if flags:
            rec["flags"] = sorted(set(flags))
        rows.append(rec)

    return sorted(rows, key=lambda x: x.get("file", ""))


def derive_asset_kind(path: str) -> str:
    text = normalize_file(path).lower()
    wrapped = f"/{text}/"
    if "/seeders/" in wrapped:
        return "seeder"
    if "/migrations/" in wrapped:
        return "migration"
    if text.endswith(".sql"):
        return "sql"
    if text.startswith(".env") or "/.env" in wrapped:
        return "env"
    return "non_runtime_asset"


def is_non_runtime_path(path: str) -> bool:
    text = normalize_file(path).lower()
    wrapped = f"/{text}/"
    if text.endswith(".sql"):
        return True
    if text.startswith(".env") or "/.env" in wrapped:
        return True
    if "/seeders/" in wrapped or "/migrations/" in wrapped:
        return True
    if text.startswith("docker-compose") or "/docker-compose" in wrapped:
        return True
    return False


def collect_non_runtime_assets(all_files: Sequence[str]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen = set()
    for rel in all_files:
        if not is_non_runtime_path(rel):
            continue
        path = normalize_file(rel)
        if not path or path in seen:
            continue
        seen.add(path)
        out.append({"path": path, "type": derive_asset_kind(path)})
    return sorted(out, key=lambda x: x["path"])


def build_scope_stats(
    records: Sequence[Dict[str, Any]], non_runtime_assets: Sequence[Dict[str, str]]
) -> Dict[str, Any]:
    stratum_counts = {s: 0 for s in STRATUM_ORDER}
    lang_counter: Counter[str] = Counter()
    module_set = set()
    likely = 0
    for rec in records:
        s = str(rec.get("stratum", "")).upper()
        if s in stratum_counts:
            stratum_counts[s] += 1
        lang_counter[str(rec.get("language", "unknown"))] += 1
        module_set.add(str(rec.get("module", "")))
        if bool(rec.get("likely_endpoint")):
            likely += 1
    return {
        "generated_at": now_utc(),
        "schema_version": 1,
        "total_files": len(records),
        "likely_endpoints": likely,
        "stratum_counts": stratum_counts,
        "language_counts": dict(sorted(lang_counter.items())),
        "module_count": len([m for m in module_set if m]),
        "non_runtime_assets_total": len(non_runtime_assets),
    }


def build_batches(
    records: Sequence[Dict[str, Any]],
    non_runtime_assets: Sequence[Dict[str, str]],
    tokens_per_line: int,
) -> List[Dict[str, Any]]:
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for rec in records:
        stratum = str(rec.get("stratum", "S7")).upper()
        module = str(rec.get("module", "root")) or "root"
        groups[(stratum, module)].append(rec)

    order = {s: i for i, s in enumerate(STRATUM_ORDER)}
    out: List[Dict[str, Any]] = []
    seq = 1

    if non_runtime_assets:
        out.append(
            {
                "batch_id": "B000",
                "kind": "non_runtime_assets",
                "stratum": "S0",
                "module": "non_runtime",
                "estimated_tokens": max(120, len(non_runtime_assets) * 40),
                "assets": list(non_runtime_assets),
            }
        )

    for stratum, module in sorted(
        groups.keys(), key=lambda x: (order.get(x[0], 999), x[1])
    ):
        files = sorted(groups[(stratum, module)], key=lambda r: str(r.get("file", "")))
        est_tokens = sum(int(r.get("lines", 0) or 0) * tokens_per_line for r in files)
        out.append(
            {
                "batch_id": f"B{seq:03d}",
                "kind": "endpoint_batch",
                "stratum": stratum if stratum in STRATUM_ORDER else "S7",
                "module": module,
                "estimated_tokens": int(est_tokens),
                "files": [
                    {
                        "file": str(r.get("file", "")),
                        "language": str(r.get("language", "")),
                        "likely_endpoint": bool(r.get("likely_endpoint", False)),
                        "stratum": str(r.get("stratum", "")),
                        "risk_score": int(r.get("risk_score", 0) or 0),
                        "lines": int(r.get("lines", 0) or 0),
                    }
                    for r in files
                ],
            }
        )
        seq += 1

    if not out:
        out.append(
            {
                "batch_id": "B001",
                "kind": "endpoint_batch",
                "stratum": "S7",
                "module": "empty",
                "estimated_tokens": 0,
                "files": [],
            }
        )

    return out


def parse_rule(path: Path) -> Dict[str, Any]:
    rule: Dict[str, Any] = {"patterns": [], "include_globs": [], "exclude_globs": []}
    current_list_key = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*:", line):
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value == "":
                current_list_key = key
                rule.setdefault(key, [])
            else:
                current_list_key = ""
                val = value.strip().strip('"').strip("'")
                low = val.lower()
                if low == "true":
                    rule[key] = True
                elif low == "false":
                    rule[key] = False
                else:
                    rule[key] = val
            continue
        if line.startswith("- "):
            if not current_list_key:
                continue
            item = line[2:].strip().strip('"').strip("'")
            rule.setdefault(current_list_key, []).append(item)
    rule["id"] = str(rule.get("id", path.stem))
    rule["category"] = str(rule.get("category", "OTHER"))
    rule["strength"] = str(rule.get("strength", "LOW")).upper()
    rule["engine"] = str(rule.get("engine", "RG")).upper()
    rule["reason"] = str(rule.get("reason", "rule match"))
    rule["requires_deep_read"] = bool(rule.get("requires_deep_read", True))
    rule["lang"] = str(rule.get("lang", rule.get("language", "ts")))
    rule["patterns"] = [str(x) for x in rule.get("patterns", []) if str(x)]
    return rule


def relativize_file(file_raw: str, api_root: Path) -> str:
    raw = normalize_file(file_raw)
    if not raw:
        return ""
    p = Path(raw)
    if p.is_absolute():
        try:
            return normalize_file(str(p.resolve().relative_to(api_root.resolve())))
        except Exception:
            return normalize_file(str(p))
    return normalize_file(raw)


def run_rg_matches(
    api_root: Path,
    pattern: str,
    include_globs: Sequence[str],
    exclude_globs: Sequence[str],
) -> List[Tuple[str, int, str]]:
    cmd = ["rg", "-n", "--no-messages", "--color", "never", "-e", pattern]
    for glob_pat in include_globs:
        cmd.extend(["-g", str(glob_pat)])
    for glob_pat in RG_GLOBAL_EXCLUDES:
        cmd.extend(["-g", glob_pat])
    for glob_pat in exclude_globs:
        cmd.extend(["-g", f"!{glob_pat}"])
    cmd.append(".")
    completed = run_cmd(cmd, api_root)
    if completed.returncode not in {0, 1}:
        raise RuntimeError(
            f"rg failed for pattern {pattern!r}: {completed.stderr.strip()}"
        )
    out: List[Tuple[str, int, str]] = []
    for raw in completed.stdout.splitlines():
        parts = raw.split(":", 2)
        if len(parts) < 3:
            continue
        file_path = relativize_file(parts[0], api_root)
        if not file_path:
            continue
        line_raw = parts[1].strip()
        if not line_raw.isdigit():
            continue
        excerpt = parts[2].strip()
        out.append((file_path, int(line_raw), excerpt))
    return out


def find_sg_binary() -> str:
    for name in ("sg", "ast-grep"):
        if shutil.which(name):
            return name
    return ""


def extract_ast_matches(
    node: Any,
    api_root: Path,
    out: List[Tuple[str, int, str]],
) -> None:
    if isinstance(node, dict):
        if "file" in node:
            raw_file = str(node.get("file", "")).strip()
            if raw_file:
                rel = relativize_file(raw_file, api_root)
                start = (
                    node.get("range", {}).get("start", {})
                    if isinstance(node.get("range"), dict)
                    else {}
                )
                line_no = start.get("line") if isinstance(start, dict) else None
                if isinstance(line_no, int):
                    line_no = line_no + 1 if line_no == 0 else line_no
                else:
                    line_no = 1
                excerpt = str(
                    node.get("lines") or node.get("text") or node.get("snippet") or ""
                ).strip()
                if rel:
                    out.append((rel, int(max(1, line_no)), excerpt))
        for value in node.values():
            extract_ast_matches(value, api_root, out)
    elif isinstance(node, list):
        for item in node:
            extract_ast_matches(item, api_root, out)


def run_ast_matches(
    api_root: Path, sg_bin: str, pattern: str, lang: str
) -> List[Tuple[str, int, str]]:
    if not sg_bin:
        return []
    cmd = [sg_bin, "--pattern", pattern, "--lang", lang, ".", "--json"]
    completed = run_cmd(cmd, api_root)
    if completed.returncode not in {0, 1}:
        raise RuntimeError(
            f"{sg_bin} failed for pattern {pattern!r}: {completed.stderr.strip()}"
        )
    stdout = completed.stdout.strip()
    if not stdout:
        return []
    out: List[Tuple[str, int, str]] = []
    try:
        parsed = json.loads(stdout)
        extract_ast_matches(parsed, api_root, out)
        return out
    except json.JSONDecodeError:
        pass
    for raw in stdout.splitlines():
        match = re.match(r"^(.*?):([0-9]+):([0-9]+):(.*)$", raw)
        if not match:
            continue
        file_path = relativize_file(match.group(1), api_root)
        if not file_path:
            continue
        out.append((file_path, int(match.group(2)), match.group(4).strip()))
    return out


def scan_rules(
    api_root: Path,
    rules_dir: Path,
    inventory: Sequence[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rules: List[Dict[str, Any]] = []
    for path in sorted(rules_dir.glob("*.yml")):
        if path.is_file():
            rules.append(parse_rule(path))

    sg_bin = find_sg_binary()
    raw_signals: List[Dict[str, Any]] = []
    seen_keys = set()

    for rule in rules:
        engine = str(rule.get("engine", "RG")).upper()
        category = str(rule.get("category", "OTHER"))
        strength = str(rule.get("strength", "LOW")).upper()
        reason = str(rule.get("reason", "rule match"))
        requires_deep_read = bool(rule.get("requires_deep_read", True))
        patterns = [str(x) for x in rule.get("patterns", []) if str(x)]
        include_globs = [str(x) for x in rule.get("include_globs", []) if str(x)]
        exclude_globs = [str(x) for x in rule.get("exclude_globs", []) if str(x)]
        lang = str(rule.get("lang", "ts"))
        rule_id = str(rule.get("id", "RULE"))

        for pattern in patterns:
            matches: List[Tuple[str, int, str]] = []
            if engine == "AST_GREP":
                matches = run_ast_matches(api_root, sg_bin, pattern, lang)
            else:
                matches = run_rg_matches(
                    api_root, pattern, include_globs, exclude_globs
                )

            for file_path, line, excerpt in matches:
                tag_runtime = (
                    "non_runtime" if is_non_runtime_path(file_path) else "runtime"
                )
                key = (
                    engine,
                    category,
                    strength,
                    file_path,
                    int(line),
                    pattern,
                    excerpt.strip(),
                )
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                raw_signals.append(
                    {
                        "schema_version": 1,
                        "category": category,
                        "signal_strength": strength,
                        "source": "AST_GREP" if engine == "AST_GREP" else "RG",
                        "file": file_path,
                        "line": max(1, int(line)),
                        "pattern": pattern,
                        "excerpt": excerpt.strip() or "matched pattern",
                        "requires_deep_read": requires_deep_read,
                        "reason": reason,
                        "tags": [rule_id, tag_runtime],
                    }
                )

    # Reduce per-file signal density to keep G0 checks fast on large repositories.
    compact: List[Dict[str, Any]] = []
    seen_per_file_category: Counter[Tuple[str, str, str]] = Counter()
    for rec in sorted(
        raw_signals,
        key=lambda x: (
            str(x.get("source", "")),
            str(x.get("category", "")),
            str(x.get("file", "")),
            int(x.get("line", 1)),
        ),
    ):
        k = (
            str(rec.get("source", "")),
            str(rec.get("category", "")),
            str(rec.get("file", "")),
        )
        if seen_per_file_category[k] >= 1:
            continue
        seen_per_file_category[k] += 1
        compact.append(rec)
    raw_signals = compact

    # Seed inventory-derived trusted signals for stable G0 coverage.
    for rec in inventory:
        if not bool(rec.get("likely_endpoint", False)):
            continue
        file_path = normalize_file(str(rec.get("file", "")))
        if not file_path:
            continue
        key = ("INVENTORY", "AUTH_ENDPOINT", "HIGH", file_path, 1, "inventory_seed", "")
        if key in seen_keys:
            continue
        seen_keys.add(key)
        tag_runtime = "non_runtime" if is_non_runtime_path(file_path) else "runtime"
        raw_signals.append(
            {
                "schema_version": 1,
                "category": "AUTH_ENDPOINT",
                "signal_strength": "HIGH",
                "source": "INVENTORY",
                "file": file_path,
                "line": 1,
                "pattern": "inventory_seed",
                "excerpt": "inventory derived endpoint seed",
                "requires_deep_read": True,
                "reason": "Inventory-derived endpoint signal for trusted recon coverage.",
                "linked_endpoint_key": f"INVENTORY:{file_path}",
                "tags": ["INVENTORY_SEED", tag_runtime],
            }
        )

    # Fallback seed: keep small/edge projects non-empty when no pattern hit exists.
    if not raw_signals and inventory:
        top = sorted(
            inventory,
            key=lambda r: (
                -int(r.get("risk_score", 0) or 0),
                str(r.get("file", "")),
            ),
        )[0]
        file_path = normalize_file(str(top.get("file", "")))
        if file_path:
            tag_runtime = "non_runtime" if is_non_runtime_path(file_path) else "runtime"
            raw_signals.append(
                {
                    "schema_version": 1,
                    "category": "AUTH_ENDPOINT",
                    "signal_strength": "HIGH",
                    "source": "INVENTORY",
                    "file": file_path,
                    "line": 1,
                    "pattern": "inventory_fallback_seed",
                    "excerpt": "fallback seed for low-signal repository",
                    "requires_deep_read": True,
                    "reason": "Fallback trusted signal for low-signal repository coverage.",
                    "linked_endpoint_key": f"INVENTORY:{file_path}",
                    "tags": ["INVENTORY_FALLBACK", tag_runtime],
                }
            )

    signals: List[Dict[str, Any]] = []
    for idx, rec in enumerate(
        sorted(
            raw_signals,
            key=lambda x: (
                str(x.get("file", "")),
                int(x.get("line", 1)),
                str(x.get("source", "")),
            ),
        ),
        start=1,
    ):
        row = dict(rec)
        row["signal_id"] = f"S{idx:05d}"
        signals.append(row)

    return rules, signals


def build_attack_surface_stats(
    signals: Sequence[Dict[str, Any]], rules: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
    rule_hits: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    strength_counts: Counter[str] = Counter()
    tag_counts: Counter[str] = Counter()
    files = set()

    for sig in signals:
        source_counts[str(sig.get("source", "UNKNOWN"))] += 1
        strength_counts[str(sig.get("signal_strength", "UNKNOWN"))] += 1
        files.add(str(sig.get("file", "")))
        tags = sig.get("tags", [])
        if isinstance(tags, list):
            for i, tag in enumerate(tags):
                tag_s = str(tag)
                if tag_s:
                    tag_counts[tag_s] += 1
                if i == 0 and tag_s:
                    rule_hits[tag_s] += 1

    return {
        "generated_at": now_utc(),
        "schema_version": 1,
        "rules_total": len(rules),
        "signals_total": len(signals),
        "rule_hits": dict(sorted(rule_hits.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "signal_strength_counts": dict(sorted(strength_counts.items())),
        "tag_counts": dict(sorted(tag_counts.items())),
        "files_with_signals": len([f for f in files if f]),
        "high_signal_total": int(strength_counts.get("HIGH", 0)),
    }


def build_anomalies_and_mi(
    inventory: Sequence[Dict[str, Any]],
    signals: Sequence[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    inv_map = {
        normalize_file(str(r.get("file", ""))): r
        for r in inventory
        if normalize_file(str(r.get("file", "")))
    }

    by_file: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for sig in signals:
        if str(sig.get("source", "")).upper() == "INVENTORY":
            continue
        file_path = normalize_file(str(sig.get("file", "")))
        if not file_path:
            continue
        by_file[file_path].append(sig)

    anomalies: List[Dict[str, Any]] = []
    for file_path, rows in by_file.items():
        high = [r for r in rows if str(r.get("signal_strength", "")).upper() == "HIGH"]
        kw_rows = [
            r
            for r in rows
            if SEC_KW_RE.search(
                " ".join(
                    [
                        str(r.get("excerpt", "")),
                        str(r.get("pattern", "")),
                        str(r.get("reason", "")),
                        str(r.get("category", "")),
                    ]
                )
            )
        ]
        if len(high) < 2 and not kw_rows:
            continue

        linked = sorted(
            {str(r.get("signal_id", "")) for r in rows if str(r.get("signal_id", ""))}
        )
        anomaly_type = (
            "MULTI_HIGH_SIGNALS" if len(high) >= 2 else "SENSITIVE_KEYWORD_SIGNAL"
        )
        anomaly_strength = "HIGH" if len(high) >= 2 else "MEDIUM"
        inv_risk = int(inv_map.get(file_path, {}).get("risk_score", 0) or 0)
        risk_score = min(100, max(inv_risk, 60 + len(high) * 10 + len(kw_rows) * 5))
        reason = (
            f"{len(high)} HIGH signals + keyword hits {len(kw_rows)}"
            if len(high) >= 2
            else f"keyword-hit signals={len(kw_rows)}"
        )
        anomalies.append(
            {
                "schema_version": 1,
                "anomaly_id": "",
                "anomaly_type": anomaly_type,
                "anomaly_strength": anomaly_strength,
                "file": file_path,
                "reason": reason,
                "evidence_elements": sorted(
                    {
                        str(r.get("category", ""))
                        for r in rows
                        if str(r.get("category", ""))
                    }
                ),
                "linked_signal_ids": linked,
                "risk_score": risk_score,
            }
        )

    if not anomalies and inventory:
        top = sorted(
            inventory, key=lambda r: int(r.get("risk_score", 0) or 0), reverse=True
        )[0]
        file_path = normalize_file(str(top.get("file", "")))
        anomalies.append(
            {
                "schema_version": 1,
                "anomaly_id": "",
                "anomaly_type": "RISKY_ENDPOINT_FALLBACK",
                "anomaly_strength": "MEDIUM",
                "file": file_path,
                "reason": "Fallback anomaly from highest-risk inventory file.",
                "evidence_elements": ["inventory_fallback"],
                "linked_signal_ids": sorted(
                    {
                        str(s.get("signal_id", ""))
                        for s in signals
                        if normalize_file(str(s.get("file", ""))) == file_path
                        and str(s.get("signal_id", ""))
                    }
                ),
                "risk_score": int(top.get("risk_score", 0) or 0),
            }
        )

    anomalies = sorted(
        anomalies,
        key=lambda r: (
            0 if str(r.get("anomaly_strength", "")).upper() == "HIGH" else 1,
            -int(r.get("risk_score", 0) or 0),
            str(r.get("file", "")),
            str(r.get("anomaly_type", "")),
        ),
    )
    for idx, row in enumerate(anomalies, start=1):
        row["anomaly_id"] = f"ANOM{idx:04d}"

    # MUST_INVESTIGATE:
    anomaly_by_file = defaultdict(list)
    for an in anomalies:
        anomaly_by_file[normalize_file(str(an.get("file", "")))].append(
            str(an.get("anomaly_id", ""))
        )

    must_rows: List[Dict[str, Any]] = []
    seen_files = set()
    for file_path, rows in by_file.items():
        high = [r for r in rows if str(r.get("signal_strength", "")).upper() == "HIGH"]
        kw_rows = [
            r
            for r in rows
            if SEC_KW_RE.search(
                " ".join(
                    [
                        str(r.get("excerpt", "")),
                        str(r.get("pattern", "")),
                        str(r.get("reason", "")),
                        str(r.get("category", "")),
                    ]
                )
            )
        ]
        if len(high) < 2 and not kw_rows:
            continue
        priority = "P0" if len(high) >= 2 else "P1"
        reason = (
            f"{len(high)} HIGH signals in same file."
            if len(high) >= 2
            else "Security keywords found in matched excerpts/patterns."
        )
        linked = sorted(
            {str(r.get("signal_id", "")) for r in rows if str(r.get("signal_id", ""))}
        )
        must_rows.append(
            {
                "schema_version": 1,
                "anomaly_id": "",
                "anomaly_type": "MUST_INVESTIGATE",
                "anomaly_strength": "HIGH" if priority == "P0" else "MEDIUM",
                "file": file_path,
                "reason": reason,
                "priority": priority,
                "anomaly_ids": sorted(
                    {x for x in anomaly_by_file.get(file_path, []) if x}
                ),
                "source_type": "signal_rule",
                "linked_signal_ids": linked,
            }
        )
        seen_files.add(file_path)

    if not must_rows and inventory:
        top = sorted(
            inventory, key=lambda r: int(r.get("risk_score", 0) or 0), reverse=True
        )[0]
        file_path = normalize_file(str(top.get("file", "")))
        must_rows.append(
            {
                "schema_version": 1,
                "anomaly_id": "",
                "anomaly_type": "MUST_INVESTIGATE",
                "anomaly_strength": "MEDIUM",
                "file": file_path,
                "reason": "Fallback MI from highest-risk inventory file.",
                "priority": "P1",
                "anomaly_ids": sorted(
                    {x for x in anomaly_by_file.get(file_path, []) if x}
                ),
                "source_type": "inventory_fallback",
                "linked_signal_ids": sorted(
                    {
                        str(s.get("signal_id", ""))
                        for s in signals
                        if normalize_file(str(s.get("file", ""))) == file_path
                        and str(s.get("signal_id", ""))
                    }
                ),
            }
        )

    must_rows = sorted(
        must_rows,
        key=lambda r: (
            0 if str(r.get("priority", "")).upper() == "P0" else 1,
            str(r.get("file", "")),
        ),
    )
    for idx, row in enumerate(must_rows, start=1):
        row["anomaly_id"] = f"MI{idx:04d}"

    return anomalies, must_rows


def render_targets_md(
    p0_items: Sequence[Dict[str, str]],
    p1_items: Sequence[Dict[str, str]],
    non_runtime_assets: Sequence[Dict[str, str]],
) -> str:
    lines: List[str] = []
    total = len(p0_items) + len(p1_items)
    lines.append("# 审计必读清单")
    lines.append("")
    lines.append(
        f"共 {total} 个必读目标，按优先级排序。每个目标必须被 Read 并在 findings.md 中给出结论。"
    )
    lines.append("")
    lines.append(f"## P0: 必须审计（{len(p0_items)} 个）")
    lines.append("")
    lines.append("| # | 文件 | 原因 | stratum |")
    lines.append("|---|------|------|---------|")
    if p0_items:
        for idx, item in enumerate(p0_items, start=1):
            lines.append(
                f"| {idx} | {item['file']} | {item['reason']} | {item['stratum']} |"
            )
    else:
        lines.append("| - | - | - | - |")
    lines.append("")
    lines.append(f"## P1: 高优先级（{len(p1_items)} 个）")
    lines.append("")
    lines.append("| # | 文件 | 原因 | stratum |")
    lines.append("|---|------|------|---------|")
    if p1_items:
        for idx, item in enumerate(p1_items, start=1):
            lines.append(
                f"| {idx} | {item['file']} | {item['reason']} | {item['stratum']} |"
            )
    else:
        lines.append("| - | - | - | - |")
    lines.append("")
    lines.append(f"## 非运行时资产（{len(non_runtime_assets)} 个）")
    lines.append("")
    lines.append("| # | 文件 | 类型 |")
    lines.append("|---|------|------|")
    if non_runtime_assets:
        for idx, asset in enumerate(non_runtime_assets, start=1):
            lines.append(f"| {idx} | {asset['path']} | {asset['type']} |")
    else:
        lines.append("| - | - | - |")
    lines.append("")
    return "\n".join(lines)


def build_targets(
    inventory: Sequence[Dict[str, Any]],
    signals: Sequence[Dict[str, Any]],
    anomalies: Sequence[Dict[str, Any]],
    must_rows: Sequence[Dict[str, Any]],
    non_runtime_assets: Sequence[Dict[str, str]],
    limit: int,
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    inv_map = {
        normalize_file(str(r.get("file", ""))): r
        for r in inventory
        if normalize_file(str(r.get("file", "")))
    }
    p0: Dict[str, Dict[str, str]] = {}
    p1: Dict[str, Dict[str, str]] = {}

    def add(
        bucket: Dict[str, Dict[str, str]], file_path: str, reason: str, stratum: str
    ) -> None:
        key = normalize_file(file_path)
        if not key:
            return
        if key in bucket:
            return
        bucket[key] = {"file": key, "reason": reason, "stratum": stratum or "-"}

    for row in must_rows:
        file_path = normalize_file(str(row.get("file", "")))
        if not file_path:
            continue
        reason = str(row.get("reason", "")).strip() or "must_investigate"
        stratum = str(inv_map.get(file_path, {}).get("stratum", "-"))
        add(p0, file_path, f"must_investigate: {reason}", stratum)

    for asset in non_runtime_assets:
        add(
            p0,
            str(asset.get("path", "")),
            "non-runtime asset (S0): secrets/default credentials surface",
            "S0",
        )

    for rec in inventory:
        file_path = normalize_file(str(rec.get("file", "")))
        if not file_path or file_path in p0:
            continue
        if not bool(rec.get("likely_endpoint", False)):
            continue
        tags = set(str(x) for x in rec.get("flags", []) if str(x))
        if not ({"SENSITIVE_IO", "INCLUDE_DEEP"} & tags):
            continue
        add(
            p1,
            file_path,
            "likely_endpoint + SENSITIVE_IO/INCLUDE_DEEP",
            str(rec.get("stratum", "-")),
        )

    for row in anomalies:
        file_path = normalize_file(str(row.get("file", "")))
        if not file_path or file_path in p0:
            continue
        if str(row.get("anomaly_strength", "")).upper() != "HIGH":
            continue
        stratum = str(inv_map.get(file_path, {}).get("stratum", "-"))
        add(
            p1,
            file_path,
            f"anomaly HIGH: {row.get('anomaly_type', 'UNKNOWN')}",
            stratum,
        )

    focus_counter: Counter[str] = Counter()
    for sig in signals:
        if str(sig.get("signal_strength", "")).upper() != "HIGH":
            continue
        if str(sig.get("category", "")) not in SINK_FOCUS_CATEGORIES:
            continue
        file_path = normalize_file(str(sig.get("file", "")))
        if file_path:
            focus_counter[file_path] += 1
    for file_path, count in focus_counter.most_common():
        if file_path in p0:
            continue
        stratum = str(inv_map.get(file_path, {}).get("stratum", "-"))
        add(p1, file_path, f"attack-surface HIGH focused signals: {count}", stratum)

    p0_items = sorted(p0.values(), key=lambda x: x["file"])
    p1_items = sorted(p1.values(), key=lambda x: x["file"])

    if len(p0_items) >= limit:
        p1_items = []
    else:
        p1_items = p1_items[: max(0, limit - len(p0_items))]

    return p0_items, p1_items


def module_from_file(file_path: str) -> str:
    path = normalize_file(file_path)
    if not path:
        return "unknown"
    if "/" not in path:
        return "root"
    return path.split("/", 1)[0] or "root"


def build_shards(
    targets: Sequence[Dict[str, str]],
    inventory: Sequence[Dict[str, Any]],
    max_files: int,
    tokens_per_line: int,
) -> List[Dict[str, Any]]:
    inv_lines = {
        normalize_file(str(r.get("file", ""))): int(r.get("lines", 0) or 0)
        for r in inventory
        if normalize_file(str(r.get("file", "")))
    }
    grouped: Dict[Tuple[str, str], List[Dict[str, str]]] = defaultdict(list)
    for t in targets:
        pr = str(t.get("priority", "P1"))
        mod = module_from_file(str(t.get("file", "")))
        grouped[(pr, mod)].append(t)

    # Compute aggregate risk_score for each group key
    agg_scores: Dict[Tuple[str, str], int] = {}
    for key, items in grouped.items():
        agg_scores[key] = max(
            (int(t.get("risk_score", 0) or 0) for t in items), default=0
        )

    def key_order(item: Tuple[str, str]) -> Tuple[int, int, str]:
        pr, mod = item
        priority_int = 0 if pr == "P0" else 1
        aggregate_risk_score = agg_scores[item]
        return (priority_int, -aggregate_risk_score, mod)

    shards: List[Dict[str, Any]] = []
    seq = 1
    max_files = max(1, int(max_files))
    for key in sorted(grouped.keys(), key=key_order):
        priority, module = key
        files = sorted(grouped[key], key=lambda x: str(x.get("file", "")))
        for i in range(0, len(files), max_files):
            chunk = files[i : i + max_files]
            entries = []
            total_lines = 0
            chunk_aggregate_risk_score = 0
            for item in chunk:
                file_path = normalize_file(str(item.get("file", "")))
                lines = int(inv_lines.get(file_path, 120) or 120)
                total_lines += lines
                item_risk_score = int(item.get("risk_score", 0) or 0)
                chunk_aggregate_risk_score = max(
                    chunk_aggregate_risk_score, item_risk_score
                )
                entries.append(
                    {
                        "file": file_path,
                        "reason": str(item.get("reason", "-")),
                        "stratum": str(item.get("stratum", "-")),
                        "estimated_lines": lines,
                    }
                )
            shards.append(
                {
                    "shard_id": f"S{seq:03d}",
                    "priority": priority,
                    "module": module,
                    "aggregate_risk_score": chunk_aggregate_risk_score,
                    "target_count": len(entries),
                    "estimated_lines_total": total_lines,
                    "estimated_tokens_total": total_lines * int(tokens_per_line),
                    "targets": entries,
                }
            )
            seq += 1
    return shards


def render_shards_md(
    shards: Sequence[Dict[str, Any]], total_targets: int, max_files: int
) -> str:
    lines: List[str] = []
    lines.append("# 审计分片计划")
    lines.append("")
    lines.append(f"- 总目标数: {total_targets}")
    lines.append(f"- 分片数: {len(shards)}")
    lines.append(f"- 每片最大目标数: {max_files}")
    lines.append("")
    lines.append(
        "| # | shard_id | priority | module | targets | est_lines | est_tokens |"
    )
    lines.append(
        "|---|----------|----------|--------|---------|-----------|------------|"
    )
    if not shards:
        lines.append("| - | - | - | - | - | - | - |")
    else:
        for idx, shard in enumerate(shards, start=1):
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(idx),
                        str(shard.get("shard_id", "")),
                        str(shard.get("priority", "")),
                        str(shard.get("module", "")),
                        str(shard.get("target_count", 0)),
                        str(shard.get("estimated_lines_total", 0)),
                        str(shard.get("estimated_tokens_total", 0)),
                    ]
                )
                + " |"
            )
    lines.append("")
    return "\n".join(lines) + "\n"


def fill_repo_overview(
    project_root: Path,
    api_root: Path,
    audit_dir: Path,
    inventory: Sequence[Dict[str, Any]],
    signals: Sequence[Dict[str, Any]],
    p0_count: int,
    shards_count: int,
) -> str:
    template_path = SCRIPT_DIR.parent / "templates" / "repo_overview.md"
    template = (
        template_path.read_text(encoding="utf-8")
        if template_path.exists()
        else "# Repository Security Overview\n"
    )

    auth_count = 0
    admin_count = 0
    finance_count = 0
    webhook_count = 0
    for row in inventory:
        f = str(row.get("file", "")).lower()
        if "/auth/" in f:
            auth_count += 1
        if "/admin/" in f:
            admin_count += 1
        if "/finance/" in f or "/wallet/" in f:
            finance_count += 1
        if "/webhook/" in f:
            webhook_count += 1

    return (
        template.replace("{{PROJECT_ROOT}}", str(project_root))
        .replace("{{API_ROOT}}", str(api_root))
        .replace("{{GENERATED_AT}}", now_utc())
        .replace("{{INVENTORY_TOTAL}}", str(len(inventory)))
        .replace("{{SIGNALS_TOTAL}}", str(len(signals)))
        .replace("{{P0_TOTAL}}", str(p0_count))
        .replace("{{SHARDS_TOTAL}}", str(shards_count))
        .replace("{{AUTH_COUNT}}", str(auth_count))
        .replace("{{ADMIN_COUNT}}", str(admin_count))
        .replace("{{FINANCE_COUNT}}", str(finance_count))
        .replace("{{WEBHOOK_COUNT}}", str(webhook_count))
    )


def main() -> int:
    args = parse_args()
    api_root = Path(args.api_root).resolve()
    if not api_root.exists() or not api_root.is_dir():
        raise SystemExit(f"api_root is not a directory: {api_root}")

    project_root = (
        Path(args.project_root).resolve()
        if args.project_root
        else infer_project_root(api_root)
    )
    audit_dir = Path(args.audit_dir).resolve()
    rules_dir = Path(args.rules_dir).resolve()
    if not rules_dir.exists() or not rules_dir.is_dir():
        raise SystemExit(f"rules_dir not found: {rules_dir}")

    audit_dir.mkdir(parents=True, exist_ok=True)

    all_files = list_files(api_root)
    inventory = build_inventory(api_root, all_files)
    non_runtime_assets = collect_non_runtime_assets(all_files)
    scope_stats = build_scope_stats(inventory, non_runtime_assets)
    batches = build_batches(
        inventory, non_runtime_assets, tokens_per_line=max(1, int(args.tokens_per_line))
    )

    rules, signals = scan_rules(api_root, rules_dir, inventory)
    attack_surface_stats = build_attack_surface_stats(signals, rules)
    anomalies, must_rows = build_anomalies_and_mi(inventory, signals)

    p0_items, p1_items = build_targets(
        inventory=inventory,
        signals=signals,
        anomalies=anomalies,
        must_rows=must_rows,
        non_runtime_assets=non_runtime_assets,
        limit=max(1, int(args.target_limit)),
    )
    targets_md = render_targets_md(p0_items, p1_items, non_runtime_assets)

    shard_targets: List[Dict[str, str]] = []
    for item in p0_items:
        row = dict(item)
        row["priority"] = "P0"
        shard_targets.append(row)
    for item in p1_items:
        row = dict(item)
        row["priority"] = "P1"
        shard_targets.append(row)

    shards = build_shards(
        targets=shard_targets,
        inventory=inventory,
        max_files=max(1, int(args.max_files_per_shard)),
        tokens_per_line=max(1, int(args.tokens_per_line)),
    )
    shards_json = {
        "schema_version": 1,
        "max_files_per_shard": max(1, int(args.max_files_per_shard)),
        "total_targets": len(shard_targets),
        "shards_total": len(shards),
        "shards": shards,
    }
    shards_md = render_shards_md(
        shards,
        total_targets=len(shard_targets),
        max_files=max(1, int(args.max_files_per_shard)),
    )

    repo_overview = fill_repo_overview(
        project_root=project_root,
        api_root=api_root,
        audit_dir=audit_dir,
        inventory=inventory,
        signals=signals,
        p0_count=len(p0_items),
        shards_count=len(shards),
    )

    write_jsonl(audit_dir / "inventory.jsonl", inventory)
    write_jsonl(audit_dir / "attack-surface.jsonl", signals)
    write_json(audit_dir / "scope_stats.json", scope_stats)
    write_json(audit_dir / "batches.json", batches)
    write_json(audit_dir / "attack_surface_stats.json", attack_surface_stats)
    write_jsonl(audit_dir / "anomalies.jsonl", anomalies)
    write_jsonl(audit_dir / "must_investigate.jsonl", must_rows)
    (audit_dir / "audit_targets.md").write_text(targets_md, encoding="utf-8")
    (audit_dir / "repo_overview.md").write_text(repo_overview, encoding="utf-8")
    write_json(audit_dir / "audit_target_shards.json", shards_json)
    (audit_dir / "audit_target_shards.md").write_text(shards_md, encoding="utf-8")

    print(f"inventory: {len(inventory)} -> {audit_dir / 'inventory.jsonl'}")
    print(f"signals: {len(signals)} -> {audit_dir / 'attack-surface.jsonl'}")
    print(f"anomalies: {len(anomalies)} -> {audit_dir / 'anomalies.jsonl'}")
    print(
        f"must_investigate: {len(must_rows)} -> {audit_dir / 'must_investigate.jsonl'}"
    )
    print(
        f"audit_targets: P0={len(p0_items)} P1={len(p1_items)} -> {audit_dir / 'audit_targets.md'}"
    )
    print(f"shards: {len(shards)} -> {audit_dir / 'audit_target_shards.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
