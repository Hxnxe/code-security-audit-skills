#!/usr/bin/env python3
"""Machine-checkable gates for code-security-audit V4."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import validate_schema as schema_validator
from shared_utils import (
    SCAN_AGENTS,
    ALL_AGENTS,
    normalize_file,
    files_match,
    normalize_mi_id,
    load_jsonl,
    load_json,
    now_utc,
    load_verification_index,
    get_verified_finding_ids,
)


WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
GATE_ORDER = ["g0", "g1"]
DEFAULT_REQUIRED_AGENTS = SCAN_AGENTS
STRATUM_ENDPOINT_ORDER = ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]
ALL_STRATA = ["S0", *STRATUM_ENDPOINT_ORDER]
CRITICAL_MODULE_HINTS = {"admin", "finance", "auth", "wallet"}
CRITICAL_STRATA = {"S1", "S2", "S3", "S4", "S6"}
GATE_MODE = "advisory"
FILE_LINE_RE = re.compile(
    r"(?P<file>[A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+):(?P<line>\d+)|"
    r"(?P<file2>[A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+)#L(?P<line2>\d+)"
)
FINDING_HEADING_RE = re.compile(r"^###\s*(F-[A-Za-z0-9_-]+)\s*:\s*(.+?)\s*$")
MI_LABEL_RE = re.compile(
    r"\*\*(?:MI-ID|MI_ID|Must[- ]?Investigate(?:\s*ID)?)\*\*\s*:\s*([A-Za-z0-9_-]+)",
    re.IGNORECASE,
)
RESOLUTION_LABEL_RE = re.compile(
    r"\*\*(?:调查结论|结论|Resolution|Status)\*\*\s*:\s*(CONFIRMED|DISPUTED|INCONCLUSIVE)",
    re.IGNORECASE,
)
RULE_ID_RE = re.compile(r"^\s*id\s*:\s*([A-Za-z0-9_]+)\s*$")
SIGNAL_ID_RE = re.compile(r"^S\d{5}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run V4 gates against audit artifacts."
    )
    parser.add_argument("gate", choices=[*GATE_ORDER, "all"], help="Gate id")
    parser.add_argument(
        "audit_dir", nargs="?", default="audit", help="Audit output directory"
    )
    parser.add_argument(
        "--mode",
        choices=["advisory", "strict"],
        default="advisory",
        help="advisory: always exit 0 and emit status; strict: fail with non-zero when gate fails",
    )
    parser.add_argument(
        "--status-out",
        default=None,
        help="Status output JSON path (default: <audit_dir>/status.json)",
    )
    return parser.parse_args()


def require(path: Path) -> Tuple[bool, str]:
    if not path.exists():
        return False, f"missing file: {path}"
    return True, ""


def normalize_method(value: Any) -> str:
    return str(value or "").strip().upper()


def infer_stratum(record: Dict[str, Any]) -> str:
    existing = str(record.get("stratum", "")).strip().upper()
    if existing in STRATUM_ENDPOINT_ORDER:
        return existing

    # Gracefully handle legacy or missing fields with defaults.
    method = normalize_method(record.get("method", ""))
    auth_declared = str(record.get("auth_declared", ""))
    is_public = bool(record.get("effective_public", False))
    tags = {
        str(tag).strip().upper() for tag in record.get("tags", []) if str(tag).strip()
    }

    module = str(record.get("module", "")).lower().strip()
    file_path = normalize_file(record.get("file")).lower()
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


def signal_links_to_endpoint(signal: Dict[str, Any], endpoint: Dict[str, Any]) -> bool:
    endpoint_file = normalize_file(endpoint.get("file"))
    signal_file = normalize_file(signal.get("file"))

    if files_match(endpoint_file, signal_file):
        return True

    linked = str(signal.get("linked_endpoint_key", "")).strip()
    if linked:
        endpoint_method = normalize_method(endpoint.get("method", ""))
        if endpoint_method:
            expected = f"{endpoint_method}:{endpoint_file}"
            if linked == expected:
                return True
            if linked.startswith(f"{endpoint_method}:"):
                linked_path = normalize_file(linked.split(":", 1)[1])
                if files_match(endpoint_file, linked_path):
                    return True
        elif ":" in linked:
            linked_path = normalize_file(linked.split(":", 1)[1])
            if files_match(endpoint_file, linked_path):
                return True
    return False


def run_schema_check(path: Path, schema_name: str) -> Tuple[bool, List[str]]:
    ok, message = require(path)
    if not ok:
        return False, [message]

    try:
        schema = schema_validator.load_schema(schema_name)
    except Exception as exc:
        return False, [f"schema load error: {schema_name}: {exc}"]

    errors: List[str] = []
    checked = 0
    try:
        if schema_name == "verdict":
            raw_data = load_json(path)
            schema_validator.validate(raw_data, schema, [])
            if isinstance(raw_data, dict) and isinstance(
                raw_data.get("verdicts"), list
            ):
                checked = len(raw_data.get("verdicts", []))
            else:
                checked = 1
        else:
            records = list(schema_validator.load_records(path))
            for idx, record in records:
                checked += 1
                try:
                    schema_validator.validate(record, schema, [])
                except schema_validator.ValidationError as exc:
                    errors.append(f"{path.name} record {idx}: {exc}")
    except schema_validator.ValidationError as exc:
        errors.append(f"{path.name} record 1: {exc}")
    except Exception as exc:
        return False, [f"unable to read {path}: {exc}"]

    if errors:
        return False, [
            f"schema validation failed: {path.name} ({schema_name})"
        ] + errors[:50]
    return True, [f"schema ok: {path.name} ({checked} records, {schema_name})"]


def check_required_subagents(
    audit_dir: Path,
    required_agents: set[str] | None = None,
) -> Tuple[List[str], List[str], set[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    required = set(required_agents or DEFAULT_REQUIRED_AGENTS)

    search_roots: List[Path] = []
    try:
        search_roots.append(audit_dir.parent.resolve())
    except Exception:
        search_roots.append(audit_dir.parent)
    try:
        cwd_resolved = Path.cwd().resolve()
        if cwd_resolved not in search_roots:
            search_roots.append(cwd_resolved)
    except Exception:
        cwd_path = Path.cwd()
        if cwd_path not in search_roots:
            search_roots.append(cwd_path)

    config_path: Path | None = None
    for base in search_roots:
        for node in [base, *base.parents]:
            candidate = node / "opencode.json"
            if candidate.exists():
                config_path = candidate
                break
        if config_path is not None:
            break

    if config_path is None:
        warnings.append(
            "opencode config not found in audit_dir parent/cwd ancestry (agent registration check skipped)"
        )
        return errors, warnings, set()

    try:
        config_data = load_json(config_path)
    except Exception as exc:
        errors.append(f"unable to parse opencode.json: {exc}")
        return errors, warnings, set()

    if not isinstance(config_data, dict):
        errors.append("opencode.json must be an object")
        return errors, warnings, set()

    agents = config_data.get("agent")
    if not isinstance(agents, dict):
        errors.append("opencode.json missing object field: agent")
        return errors, warnings, set()

    registered = set(agents.keys())

    missing = sorted(required - registered)
    if missing:
        errors.append(
            "required subagents not registered in opencode.json: " + ", ".join(missing)
        )
        return errors, warnings, registered

    for name in sorted(required):
        info = agents.get(name)
        if not isinstance(info, dict):
            errors.append(f"agent.{name} must be an object")
            continue
        mode = str(info.get("mode", "")).strip()
        prompt = str(info.get("prompt", "")).strip()
        if mode != "subagent":
            errors.append(f"agent.{name}.mode must be 'subagent' (got {mode!r})")
        if not prompt:
            errors.append(f"agent.{name}.prompt is required")

    return errors, warnings, registered


def load_pattern_rule_ids() -> set[str]:
    rules_dir = SCRIPT_DIR.parent / "rules" / "patterns"
    if not rules_dir.exists():
        return set()
    out: set[str] = set()
    for path in sorted(rules_dir.glob("*.yml")):
        try:
            for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                match = RULE_ID_RE.match(raw.strip())
                if match:
                    out.add(match.group(1).strip().upper())
                    break
        except OSError:
            continue
    return out


def classify_signal_trust(
    signal: Dict[str, Any], rule_ids: set[str]
) -> Tuple[bool, str]:
    source = str(signal.get("source", "")).strip().upper()
    if source == "MANUAL":
        return False, "source=MANUAL"

    signal_id = str(signal.get("signal_id", "")).strip()
    if not SIGNAL_ID_RE.match(signal_id):
        return False, "invalid_signal_id_format"

    file_path = normalize_file(signal.get("file", ""))
    line_no = int(signal.get("line", 0) or 0)
    if not file_path or line_no <= 0:
        return False, "missing_file_or_line"

    tags_raw = signal.get("tags", [])
    tags = {
        str(tag).strip().upper()
        for tag in tags_raw
        if isinstance(tag, str) and str(tag).strip()
    }
    if source in {"RG", "AST_GREP"}:
        if not tags:
            return False, "missing_rule_tag"
        if rule_ids and not any(tag in rule_ids for tag in tags):
            return False, "unknown_rule_tag"
        return True, "trusted"

    if source == "INVENTORY":
        linked = str(signal.get("linked_endpoint_key", "")).strip()
        method = normalize_method(signal.get("method", ""))
        route = str(signal.get("route", "")).strip()
        if linked or (method and route):
            return True, "trusted"
        if bool(signal.get("likely_endpoint")):
            return True, "trusted"
        return False, "inventory_without_endpoint_link"

    return False, f"unsupported_source={source or 'EMPTY'}"


def check_stratified_batch_order(batches: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(batches, list) or not batches:
        errors.append("batches.json is empty or invalid")
        return errors

    has_non_runtime = any(
        isinstance(b, dict) and b.get("kind") == "non_runtime_assets" for b in batches
    )
    if has_non_runtime:
        first = batches[0] if isinstance(batches[0], dict) else {}
        if first.get("kind") != "non_runtime_assets":
            errors.append("non_runtime_assets batch must be first")
        if str(first.get("stratum", "")).upper() != "S0":
            errors.append("non_runtime_assets batch must carry stratum=S0")

    order_index = {stratum: idx for idx, stratum in enumerate(STRATUM_ENDPOINT_ORDER)}
    prev_order = -1
    for idx, batch in enumerate(batches, start=1):
        if not isinstance(batch, dict) or batch.get("kind") != "endpoint_batch":
            continue
        stratum = str(batch.get("stratum", "")).upper()
        if stratum not in order_index:
            errors.append(f"endpoint batch {idx} missing/invalid stratum: {stratum!r}")
            continue
        current_order = order_index[stratum]
        if current_order < prev_order:
            errors.append("endpoint batches are not ordered by strata S1->S7")
            break
        prev_order = current_order

    return errors


def check_scope_stats(
    scope_stats: Any, inventory: Sequence[Dict[str, Any]]
) -> List[str]:
    errors: List[str] = []
    if not isinstance(scope_stats, dict):
        return ["scope_stats.json must be an object"]

    stratum_counts = scope_stats.get("stratum_counts", {})
    if not isinstance(stratum_counts, dict):
        errors.append("scope_stats.stratum_counts missing or invalid")
        return errors

    missing = [s for s in STRATUM_ENDPOINT_ORDER if s not in stratum_counts]
    if missing:
        errors.append(f"scope_stats.stratum_counts missing keys: {', '.join(missing)}")

    actual: Dict[str, int] = {s: 0 for s in STRATUM_ENDPOINT_ORDER}
    for ep in inventory:
        actual[infer_stratum(ep)] += 1

    for stratum in STRATUM_ENDPOINT_ORDER:
        expected = int(stratum_counts.get(stratum, 0))
        if expected != actual[stratum]:
            errors.append(
                f"scope_stats stratum_counts mismatch {stratum}: expected={expected}, actual={actual[stratum]}"
            )

    return errors


def g0_critical_min_threshold(total_critical_endpoints: int) -> float:
    # First-principles: RECON gate should detect broken reconnaissance, not force near-complete
    # vulnerability discovery before AUDIT starts. Use dynamic thresholds by surface size.
    if total_critical_endpoints >= 100:
        return 0.65
    if total_critical_endpoints >= 40:
        return 0.70
    return 0.80


def run_g0(audit_dir: Path) -> Tuple[bool, List[str]]:
    inventory_path = audit_dir / "inventory.jsonl"
    surface_path = audit_dir / "attack-surface.jsonl"
    batches_path = audit_dir / "batches.json"
    scope_stats_path = audit_dir / "scope_stats.json"
    signal_stats_path = audit_dir / "attack_surface_stats.json"
    anomalies_path = audit_dir / "anomalies.jsonl"
    must_investigate_path = audit_dir / "must_investigate.jsonl"

    for path in (
        inventory_path,
        surface_path,
        batches_path,
        scope_stats_path,
        signal_stats_path,
        anomalies_path,
        must_investigate_path,
    ):
        ok, message = require(path)
        if not ok:
            return False, [message]

    lines: List[str] = []
    overall = True

    for path, schema in (
        (inventory_path, "inventory"),
        (surface_path, "attack-surface"),
    ):
        ok, sub = run_schema_check(path, schema)
        lines.extend(sub)
        if not ok:
            overall = False

    if not overall:
        return False, ["G0 FAIL: schema check failed"] + lines

    inventory = load_jsonl(inventory_path)
    signals = load_jsonl(surface_path)
    batches = load_json(batches_path)
    scope_stats = load_json(scope_stats_path)
    signal_stats = load_json(signal_stats_path)

    errors: List[str] = []
    warnings: List[str] = []

    agent_errors, agent_warnings, _registered_agents = check_required_subagents(
        audit_dir, set(DEFAULT_REQUIRED_AGENTS)
    )
    errors.extend(agent_errors)
    warnings.extend(agent_warnings)

    empty_project = False
    if not inventory and not signals:
        empty_project = True
        warnings.append(
            "inventory and attack-surface are empty; treat as empty project"
        )
    else:
        if not inventory:
            errors.append("inventory is empty")
        if not signals:
            errors.append("attack-surface is empty")

    if not isinstance(signal_stats, dict):
        errors.append("attack_surface_stats.json is empty or invalid")
    else:
        expected_total = signal_stats.get("signals_total")
        if (
            isinstance(expected_total, int)
            and expected_total >= 0
            and expected_total != len(signals)
        ):
            errors.append(
                "attack-surface integrity mismatch: "
                f"attack_surface_stats.signals_total={expected_total}, actual={len(signals)}"
            )

        expected_source_counts = signal_stats.get("source_counts")
        if isinstance(expected_source_counts, dict):
            actual_source_counts = Counter(
                str(sig.get("source", "UNKNOWN")) for sig in signals
            )
            source_mismatches: List[str] = []
            for source, expected_raw in expected_source_counts.items():
                try:
                    expected = int(expected_raw)
                except (TypeError, ValueError):
                    continue
                actual = int(actual_source_counts.get(str(source), 0))
                if actual != expected:
                    source_mismatches.append(
                        f"{source}: stats={expected}, actual={actual}"
                    )
            if source_mismatches:
                errors.append(
                    "attack-surface integrity mismatch in source_counts: "
                    + "; ".join(source_mismatches[:10])
                )

    if empty_project:
        critical_endpoints = []
    else:
        critical_endpoints = [
            rec for rec in inventory if infer_stratum(rec) in CRITICAL_STRATA
        ]
        if not critical_endpoints:
            critical_endpoints = inventory

    rule_ids = load_pattern_rule_ids()
    trusted_signals: List[Dict[str, Any]] = []
    untrusted_reasons: Counter[str] = Counter()
    for signal in signals:
        trusted, reason = classify_signal_trust(signal, rule_ids)
        if trusted:
            trusted_signals.append(signal)
        else:
            untrusted_reasons[reason] += 1

    covered = sum(
        1
        for rec in critical_endpoints
        if any(signal_links_to_endpoint(sig, rec) for sig in trusted_signals)
    )
    coverage_ratio = covered / len(critical_endpoints) if critical_endpoints else 1.0

    covered_all = sum(
        1
        for rec in critical_endpoints
        if any(signal_links_to_endpoint(sig, rec) for sig in signals)
    )
    coverage_ratio_all = (
        covered_all / len(critical_endpoints) if critical_endpoints else 1.0
    )
    uncovered_critical_files = [
        normalize_file(rec.get("file", ""))
        for rec in critical_endpoints
        if not any(signal_links_to_endpoint(sig, rec) for sig in trusted_signals)
    ]
    uncovered_critical_files = [f for f in uncovered_critical_files if f]

    if not trusted_signals and not empty_project:
        errors.append("no trusted machine-generated signals found in attack-surface")

    critical_min = g0_critical_min_threshold(len(critical_endpoints))
    if coverage_ratio < critical_min and not empty_project:
        errors.append(
            f"critical surface coverage too low (trusted signals only): "
            f"{coverage_ratio:.2%} ({covered}/{len(critical_endpoints)}) < {critical_min:.0%}"
        )
        if coverage_ratio_all >= critical_min:
            errors.append(
                "coverage appears inflated by untrusted signals (all-signals coverage passes but trusted-only coverage fails)"
            )

    high_signal_total = sum(
        1
        for sig in trusted_signals
        if str(sig.get("signal_strength", "")).upper() == "HIGH"
    )
    if high_signal_total == 0 and not empty_project:
        errors.append("no HIGH trusted signals found in attack-surface")

    if untrusted_reasons:
        reason_parts = [
            f"{key}={value}" for key, value in untrusted_reasons.most_common()
        ]
        lines.append(
            "G0 WARN: ignored untrusted signals for gate coverage: "
            + ", ".join(reason_parts[:10])
        )
    lines.append(
        "G0 INFO: trusted_signals="
        f"{len(trusted_signals)}/{len(signals)}, "
        f"trusted_critical_coverage={coverage_ratio:.2%}, "
        f"all_signals_critical_coverage={coverage_ratio_all:.2%}, "
        f"critical_min={critical_min:.0%}"
    )
    if uncovered_critical_files:
        lines.append(
            "G0 INFO: uncovered critical targets sample: "
            + ", ".join(uncovered_critical_files[:10])
        )

    errors.extend(check_stratified_batch_order(batches))
    errors.extend(check_scope_stats(scope_stats, inventory))

    recon_semantic_path_v6 = audit_dir / "recon-semantic-v6.md"
    recon_semantic_path_legacy = audit_dir / "recon-semantic.md"
    recon_semantic_path = (
        recon_semantic_path_v6
        if recon_semantic_path_v6.exists()
        else recon_semantic_path_legacy
    )
    if recon_semantic_path.exists():
        recon_text = recon_semantic_path.read_text(encoding="utf-8", errors="ignore")
        if "路由清单" not in recon_text:
            warnings.append(f"{recon_semantic_path.name} missing '路由清单' section")
        if "认证边界" not in recon_text:
            warnings.append(f"{recon_semantic_path.name} missing '认证边界' section")
        lines.append(f"G0 INFO: {recon_semantic_path.name} present and validated")
    else:
        warnings.append("recon-semantic-v6.md not found; LLM RECON not yet executed")

    optional_nav = [
        "codeelements.jsonl",
        "edges.jsonl",
        "sources_sinks.jsonl",
        "data_catalog.jsonl",
    ]
    for name in optional_nav:
        path = audit_dir / name
        if not path.exists():
            warnings.append(f"optional navigation artifact missing: {name}")

    for warning in warnings:
        lines.append(f"G0 WARN: {warning}")

    if errors:
        lines.append(
            "G0 NEXT: rerun RECON/fallback to regenerate inventory + attack-surface + attack_surface_stats consistently."
        )
        lines.append(
            "G0 NEXT: suggested commands: "
            'bash "$SKILL_ROOT/scripts/phase0_recon_v6.sh" "$API_ROOT" "$AUDIT_DIR" '
            '&& python3 "$SKILL_ROOT/scripts/gate.py" g0 "$AUDIT_DIR"'
        )
        return False, ["G0 FAIL: recon gate failed"] + errors[:50] + lines

    lines.append(
        "G0 PASS: "
        f"critical_coverage={coverage_ratio:.2%} ({covered}/{len(critical_endpoints)}), "
        f"high_signals={high_signal_total}"
    )
    return True, lines


def verdict_records(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict) and isinstance(data.get("verdicts"), list):
        return [x for x in data["verdicts"] if isinstance(x, dict)]
    if isinstance(data, dict):
        return [data]
    return []


_PROJECT_FILE_INDEX_CACHE: Dict[Path, Dict[str, Path]] = {}


def project_file_index(project_root: Path) -> Dict[str, Path]:
    cached = _PROJECT_FILE_INDEX_CACHE.get(project_root)
    if cached is not None:
        return cached

    index: Dict[str, Path] = {}
    try:
        for path in project_root.rglob("*"):
            if not path.is_file():
                continue
            try:
                rel = normalize_file(path.relative_to(project_root))
            except Exception:
                continue
            if rel and rel not in index:
                index[rel] = path
    except OSError:
        pass

    _PROJECT_FILE_INDEX_CACHE[project_root] = index
    return index


def canonical_existing_file(cited_file: str, audit_dir: Path) -> Path | None:
    candidate = Path(cited_file)
    if candidate.is_absolute() and candidate.exists():
        return candidate

    project_root = audit_dir.parent
    normalized = normalize_file(cited_file)
    if not normalized:
        return None

    direct_candidates = [
        project_root / normalized,
        project_root / "backend" / "src" / "api" / normalized,
        project_root / "backend" / normalized,
        project_root / "backend" / "src" / normalized,
        Path.cwd() / normalized,
    ]
    for direct in direct_candidates:
        try:
            resolved = direct.resolve()
        except OSError:
            continue
        if resolved.exists():
            return resolved

    index = project_file_index(project_root)
    if normalized in index:
        return index[normalized]

    suffix_matches: List[Tuple[int, str]] = []
    wrapped = f"/{normalized}"
    for rel in index.keys():
        if rel.endswith(wrapped) or normalized.endswith(f"/{rel}"):
            suffix_matches.append((len(rel), rel))
    if suffix_matches:
        suffix_matches.sort()
        return index[suffix_matches[0][1]]

    return None


def resolve_cited_file(cited_file: str, audit_dir: Path) -> Path | None:
    return canonical_existing_file(cited_file, audit_dir)


def valid_line_span(path: Path, line_start: int, line_end: int) -> bool:
    try:
        line_count = 0
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line_count, _ in enumerate(fh, start=1):
                pass
    except OSError:
        return False

    if line_count <= 0:
        return False
    if line_start < 1 or line_end < line_start:
        return False
    return line_end <= line_count


def has_shell_command(text: str) -> bool:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(
            r"^(curl|wget|http|python3?|sqlmap|nc|openssl|node|bash|sh)\b", line
        ):
            return True
    return False


def is_cjk(ch: str) -> bool:
    code = ord(ch)
    return (
        0x4E00 <= code <= 0x9FFF
        or 0x3400 <= code <= 0x4DBF
        or 0x20000 <= code <= 0x2A6DF
        or 0x2A700 <= code <= 0x2B73F
        or 0x2B740 <= code <= 0x2B81F
        or 0x2B820 <= code <= 0x2CEAF
        or 0xF900 <= code <= 0xFAFF
    )


def narrative_only(text: str) -> str:
    no_code = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    kept: List[str] = []
    for raw in no_code.splitlines():
        line = raw.strip()
        if not line:
            continue
        line = re.sub(r"`[^`]*`", "", line)
        if line.startswith("|") or line.endswith("|"):
            continue
        kept.append(line)
    return "\n".join(kept)


def chinese_ratio(text: str) -> float:
    text = narrative_only(text)
    total = 0
    chinese = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        has_alpha = any(ch.isascii() and ch.isalpha() for ch in line)
        has_cjk = any(is_cjk(ch) for ch in line)
        if not has_alpha and not has_cjk:
            continue
        total += 1
        if has_cjk:
            chinese += 1
    return 0.0 if total == 0 else chinese / total


def has_command_poc(text: str) -> bool:
    blocks = re.findall(
        r"```(?:bash|sh|zsh)?\n(.*?)```", text, flags=re.IGNORECASE | re.DOTALL
    )
    for block in blocks:
        if has_shell_command(block):
            return True
    return False


def parse_markdown_finding_blocks(text: str) -> List[Tuple[str, str]]:
    lines = text.splitlines()
    blocks: List[Tuple[str, str]] = []
    current_id = ""
    current_lines: List[str] = []
    for raw in lines:
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


def extract_mi_resolution_map(findings_md_text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for _fid, block in parse_markdown_finding_blocks(findings_md_text):
        mi_ids = [normalize_mi_id(m.group(1)) for m in MI_LABEL_RE.finditer(block)]
        mi_ids = [mi for mi in mi_ids if mi]
        if not mi_ids:
            continue
        status_match = RESOLUTION_LABEL_RE.search(block)
        status = status_match.group(1).upper() if status_match else "MISSING"
        for mi in mi_ids:
            out[mi] = status
    return out


def extract_finding_resolution_map(findings_md_text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for finding_id, block in parse_markdown_finding_blocks(findings_md_text):
        status_match = RESOLUTION_LABEL_RE.search(block)
        if not status_match:
            continue
        out[finding_id] = status_match.group(1).upper()
    return out


def extract_p0_lsp_coverage_map(findings_md_text: str) -> Tuple[bool, Dict[str, bool]]:
    lines = findings_md_text.splitlines()
    section_found = False
    in_section = False
    coverage: Dict[str, bool] = {}

    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("## "):
            if stripped.startswith("## P0 语义证据覆盖（LSP）"):
                section_found = True
                in_section = True
                continue
            if in_section:
                break

        if not in_section:
            continue
        if not stripped.startswith("|") or stripped.startswith("|---"):
            continue

        cols = [c.strip() for c in stripped.split("|")]
        if len(cols) < 6:
            continue
        file_col = normalize_file(cols[1])
        if not file_col or file_col in {"p0文件", "file"}:
            continue
        lsp_col = cols[3]
        reason_col = cols[4]

        lsp_upper = lsp_col.upper()
        reason_upper = reason_col.upper()

        has_lsp_trace = (
            bool(lsp_col)
            and lsp_col not in {"-", "N/A", "NA", "无"}
            and "RG_FALLBACK" not in lsp_upper
        )
        has_fallback = "RG_FALLBACK" in lsp_upper and "LSP_UNAVAILABLE" in reason_upper
        valid = has_lsp_trace or has_fallback

        coverage[file_col] = coverage.get(file_col, False) or valid

    return section_found, coverage


def check_must_investigate_resolution(
    audit_dir: Path, findings: Sequence[Dict[str, Any]], findings_md_text: str
) -> Tuple[List[str], List[str]]:
    must_path = audit_dir / "must_investigate.jsonl"
    if not must_path.exists():
        return [], []

    must_rows = load_jsonl(must_path)
    required_ids = {
        normalize_mi_id(row.get("anomaly_id", "") or row.get("mi_id", ""))
        for row in must_rows
    }
    required_ids = {x for x in required_ids if x}
    if not required_ids:
        return [], []

    errors: List[str] = []
    warnings: List[str] = []
    mi_status = extract_mi_resolution_map(findings_md_text)
    finding_status = extract_finding_resolution_map(findings_md_text)
    required_file_by_id = {
        normalize_mi_id(
            row.get("anomaly_id", "") or row.get("mi_id", "")
        ): normalize_file(row.get("file", ""))
        for row in must_rows
    }
    required_file_by_id = {k: v for k, v in required_file_by_id.items() if k and v}

    if mi_status:
        effective_status = dict(mi_status)

        unresolved = sorted(required_ids - set(effective_status.keys()))
        resolved_via_file: List[str] = []
        if unresolved:
            finding_files_by_id: Dict[str, set[str]] = {}
            for finding in findings:
                fid = str(finding.get("id", "")).strip()
                if not fid:
                    continue
                files: set[str] = set()
                file_value = normalize_file(finding.get("file", ""))
                if file_value:
                    files.add(file_value)
                bundle = (
                    finding.get("evidence_bundle", {})
                    if isinstance(finding.get("evidence_bundle"), dict)
                    else {}
                )
                refs = (
                    bundle.get("primary_refs", [])
                    if isinstance(bundle.get("primary_refs"), list)
                    else []
                )
                for ref in refs:
                    if not isinstance(ref, dict):
                        continue
                    ref_file = normalize_file(ref.get("file", ""))
                    if ref_file:
                        files.add(ref_file)
                if files:
                    finding_files_by_id[fid] = files

            for mi in unresolved:
                target_file = required_file_by_id.get(mi, "")
                if not target_file:
                    continue
                matched_status = ""
                for fid, files in finding_files_by_id.items():
                    if not any(files_match(target_file, f) for f in files):
                        continue
                    status = finding_status.get(fid, "")
                    if status in {"CONFIRMED", "DISPUTED", "INCONCLUSIVE"}:
                        matched_status = status
                        break
                if matched_status:
                    effective_status[mi] = matched_status
                    resolved_via_file.append(mi)

        unresolved = sorted(required_ids - set(effective_status.keys()))
        if unresolved:
            errors.append(
                f"must_investigate unresolved IDs: {', '.join(unresolved[:20])}"
            )
            unresolved_files = [
                required_file_by_id.get(mi, "")
                for mi in unresolved
                if required_file_by_id.get(mi, "")
            ]
            if unresolved_files:
                warnings.append(
                    "must_investigate unresolved files sample: "
                    + ", ".join(unresolved_files[:20])
                )

        inconclusive = sorted(
            mi
            for mi in required_ids
            if effective_status.get(mi, "MISSING") == "INCONCLUSIVE"
        )
        if inconclusive:
            errors.append(
                f"must_investigate has INCONCLUSIVE items that require R2 or WAIVED before delivery: "
                f"{', '.join(inconclusive[:20])}"
            )

        missing_status = sorted(
            mi
            for mi in required_ids
            if effective_status.get(mi, "MISSING") == "MISSING"
        )
        if missing_status:
            errors.append(
                f"must_investigate missing 调查结论 for IDs: {', '.join(missing_status[:20])}"
            )

        extra = sorted(mi for mi in mi_status.keys() if mi not in required_ids)
        if extra:
            warnings.append(
                f"findings.md contains MI-ID not present in must_investigate.jsonl: {', '.join(extra[:10])}"
            )
        if resolved_via_file:
            warnings.append(
                "must_investigate resolved via file-level fallback for IDs: "
                + ", ".join(sorted(resolved_via_file)[:20])
            )
        return errors, warnings

    warnings.append(
        "MI-ID resolution map missing in findings.md; falling back to legacy file-level check"
    )
    must_files = {
        normalize_file(row.get("file", ""))
        for row in must_rows
        if normalize_file(row.get("file", ""))
    }
    finding_files: set[str] = set()
    for finding in findings:
        file_value = normalize_file(finding.get("file", ""))
        if file_value:
            finding_files.add(file_value)
        bundle = (
            finding.get("evidence_bundle", {})
            if isinstance(finding.get("evidence_bundle"), dict)
            else {}
        )
        refs = (
            bundle.get("primary_refs", [])
            if isinstance(bundle.get("primary_refs"), list)
            else []
        )
        for ref in refs:
            if isinstance(ref, dict):
                ref_file = normalize_file(ref.get("file", ""))
                if ref_file:
                    finding_files.add(ref_file)
    unresolved_files = sorted(
        file_path
        for file_path in must_files
        if not any(files_match(file_path, seen) for seen in finding_files)
    )
    if unresolved_files:
        errors.append(
            f"must_investigate unresolved files (legacy fallback): {', '.join(unresolved_files[:20])}"
        )
    return errors, warnings


def read_span_text(path: Path, line_start: int, line_end: int, context: int = 1) -> str:
    if line_start < 1:
        line_start = 1
    if line_end < line_start:
        line_end = line_start
    wanted_start = max(1, line_start - context)
    wanted_end = line_end + context
    collected: List[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for idx, raw in enumerate(fh, start=1):
                if idx < wanted_start:
                    continue
                if idx > wanted_end:
                    break
                collected.append(raw.rstrip("\n"))
    except OSError:
        return ""
    return "\n".join(collected).lower()


def semantic_tokens_for_finding(finding: Dict[str, Any]) -> List[str]:
    corpus = " ".join(
        [
            str(finding.get("type", "")),
            str(finding.get("impact", "")),
            str(finding.get("source", "")),
            str(finding.get("sink", "")),
            str(finding.get("dataflow", "")),
        ]
    ).lower()
    tokens: List[str] = []
    if any(k in corpus for k in ("sql", "literal", "injection", "query")):
        tokens.extend(["sql", "literal", "query", "sequelize"])
    if any(k in corpus for k in ("auth", "credential", "password", "session", "token")):
        tokens.extend(
            ["auth", "requiresauth", "password", "session", "token", "update"]
        )
    if any(k in corpus for k in ("pii", "email", "disclosure", "privacy")):
        tokens.extend(["email", "phone", "attributes", "include", "user"])
    if any(k in corpus for k in ("config", "secret", "key", "env", "settings")):
        tokens.extend(["config", "settings", "secret", "key", "env"])
    dedup: List[str] = []
    for token in tokens:
        if token not in dedup:
            dedup.append(token)
    return dedup


def check_chains_contract(
    audit_dir: Path, finding_ids: set[str], registered_agents: set[str]
) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    chains_path = audit_dir / "chains.json"
    attack_graph_path = audit_dir / "attack-graph.md"
    chain_required = "chain-synthesizer" in registered_agents

    if not chains_path.exists():
        if chain_required:
            errors.append("missing file: chains.json (chain-synthesizer is registered)")
        elif attack_graph_path.exists():
            warnings.append("attack-graph.md exists but chains.json missing")
        else:
            warnings.append(
                "chains.json missing (legacy mode; chain-synthesizer not registered)"
            )
        return errors, warnings

    ok, lines = run_schema_check(chains_path, "chains")
    if not ok:
        errors.extend(lines)
        return errors, warnings
    for line in lines:
        warnings.append(f"chains_schema: {line}")

    try:
        data = load_json(chains_path)
    except Exception as exc:
        errors.append(f"unable to parse chains.json: {exc}")
        return errors, warnings

    chains = data.get("chains", []) if isinstance(data, dict) else []
    if not isinstance(chains, list):
        errors.append("chains.json invalid: chains must be a list")
        return errors, warnings

    for chain in chains:
        if not isinstance(chain, dict):
            continue
        chain_id = str(chain.get("chain_id", "")).strip() or "UNKNOWN_CHAIN"
        steps = chain.get("steps", [])
        if not isinstance(steps, list) or not steps:
            errors.append(f"{chain_id}: chain requires non-empty steps")
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            refs = [
                str(x).strip() for x in step.get("finding_refs", []) if str(x).strip()
            ]
            if not refs:
                errors.append(f"{chain_id}: step missing finding_refs")
                continue
            for fid in refs:
                if finding_ids and fid not in finding_ids:
                    errors.append(
                        f"{chain_id}: step references unknown finding_id {fid}"
                    )
    return errors, warnings


def derive_delivery_level(gate_ok: bool, coverage: Any) -> str:
    if gate_ok:
        return "CERTIFIED"
    if isinstance(coverage, dict):
        if bool(coverage.get("r2_required")) or not bool(
            coverage.get("content_gate_passed", False)
        ):
            return "PARTIAL"
    return "BROKEN"


def write_status_file(
    status_path: Path,
    gate_name: str,
    mode: str,
    overall: bool,
    gate_results: List[Dict[str, Any]],
    audit_dir: Path,
) -> None:
    coverage_path = audit_dir / "coverage.json"
    coverage = load_json(coverage_path) if coverage_path.exists() else {}
    payload = {
        "schema_version": 1,
        "generated_at": now_utc(),
        "gate": gate_name,
        "mode": mode,
        "overall_pass": overall,
        "delivery_level": derive_delivery_level(overall, coverage),
        "coverage": {
            "r2_required": bool(coverage.get("r2_required"))
            if isinstance(coverage, dict)
            else False,
            "content_gate_passed": bool(coverage.get("content_gate_passed"))
            if isinstance(coverage, dict)
            else False,
            "metrics": coverage.get("metrics", {})
            if isinstance(coverage, dict)
            else {},
            "next_targets": coverage.get("next_targets", [])
            if isinstance(coverage, dict)
            else [],
        },
        "gates": gate_results,
    }
    status_path.parent.mkdir(parents=True, exist_ok=True)
    status_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def run_g1(audit_dir: Path) -> Tuple[bool, List[str]]:
    findings_path = audit_dir / "findings.jsonl"
    findings_md_path = audit_dir / "findings.md"
    verdict_path = audit_dir / "verdict.json"
    coverage_path = audit_dir / "coverage.json"
    report_path = audit_dir / "report.md"

    for path in (findings_path, findings_md_path, verdict_path, coverage_path):
        ok, message = require(path)
        if not ok:
            return False, [message]

    lines: List[str] = []
    overall = True
    for path, schema in (
        (findings_path, "finding"),
        (verdict_path, "verdict"),
        (coverage_path, "coverage"),
    ):
        ok, sub = run_schema_check(path, schema)
        lines.extend(sub)
        if not ok:
            overall = False

    if not overall:
        return False, ["G1 FAIL: final artifact schema check failed"] + lines

    findings = load_jsonl(findings_path)
    findings_md_text = findings_md_path.read_text(encoding="utf-8", errors="ignore")
    verdicts = verdict_records(load_json(verdict_path))
    coverage = load_json(coverage_path)
    report_text = (
        report_path.read_text(encoding="utf-8", errors="ignore")
        if report_path.exists()
        else ""
    )

    errors: List[str] = []
    agent_errors, agent_warnings, registered_agents = check_required_subagents(
        audit_dir, set(ALL_AGENTS)
    )
    errors.extend(agent_errors)
    for warning in agent_warnings:
        lines.append(f"G1 WARN: {warning}")

    finding_ids = {str(f.get("id", "")) for f in findings if str(f.get("id", ""))}
    chain_errors, chain_warnings = check_chains_contract(
        audit_dir, finding_ids, registered_agents
    )
    errors.extend(chain_errors)
    for warning in chain_warnings:
        lines.append(f"G1 WARN: {warning}")

    unknown_file_count = sum(
        1
        for finding in findings
        if normalize_file(finding.get("file", "")) in {"", "unknown.ts"}
    )
    if unknown_file_count > 0:
        errors.append(
            f"findings.jsonl extraction quality invalid: {unknown_file_count}/{len(findings)} findings have file=unknown.ts or empty"
        )

    empty_narrative_count = sum(
        1
        for finding in findings
        if not str(finding.get("attacker_narrative", "")).strip()
    )
    if findings and empty_narrative_count > len(findings) * 0.5:
        errors.append(
            f"findings.jsonl extraction quality invalid: {empty_narrative_count}/{len(findings)} findings missing attacker_narrative"
        )

    mi_errors, mi_warnings = check_must_investigate_resolution(
        audit_dir, findings, findings_md_text
    )
    errors.extend(mi_errors)
    for warning in mi_warnings:
        lines.append(f"G1 WARN: {warning}")

    verification_path = audit_dir / "verification.jsonl"
    if not verification_path.exists():
        warning = "verification.jsonl not found; verification cross-link skipped"
        if GATE_MODE == "strict":
            errors.append(warning)
        else:
            lines.append(f"G1 WARN: {warning}")
    else:
        verification_index = load_verification_index(audit_dir)
        verified_ids = get_verified_finding_ids(audit_dir)

        unverified_count = 0
        for finding in findings:
            fid = str(finding.get("id", ""))
            if fid and fid not in verified_ids:
                unverified_count += 1

        if unverified_count > 0:
            ratio = unverified_count / max(len(findings), 1)
            msg = (
                f"verification cross-link: {unverified_count}/{len(findings)} findings "
                "lack verified V-XXX entry"
            )
            if ratio > 0.5:
                errors.append(msg)
            else:
                lines.append(f"G1 WARN: {msg}")

    replay_total = 0
    replay_failures = 0
    for idx, finding in enumerate(findings, start=1):
        sev = str(finding.get("severity", "")).upper()
        if sev in {"CRITICAL", "HIGH"} and not has_shell_command(
            str(finding.get("poc", ""))
        ):
            errors.append(
                f"finding {idx}: CRITICAL/HIGH requires executable PoC command"
            )

        bundle = (
            finding.get("evidence_bundle", {})
            if isinstance(finding.get("evidence_bundle"), dict)
            else {}
        )
        primary_refs = (
            bundle.get("primary_refs", [])
            if isinstance(bundle.get("primary_refs"), list)
            else []
        )
        if not primary_refs:
            errors.append(f"finding {idx}: evidence_bundle.primary_refs is empty")
            continue

        semantic_tokens = semantic_tokens_for_finding(finding)
        semantic_hit = False
        for ref in primary_refs:
            if not isinstance(ref, dict):
                continue
            cited_file = str(ref.get("file", "")).strip()
            line_start = int(ref.get("line_start", 0) or 0)
            line_end = int(ref.get("line_end", line_start) or line_start)
            if not cited_file:
                continue
            replay_total += 1
            resolved = resolve_cited_file(cited_file, audit_dir)
            if resolved is None:
                replay_failures += 1
                errors.append(
                    f"finding {idx}: evidence replay failed, missing file: {cited_file}"
                )
                continue
            if (
                line_start > 0
                and line_end > 0
                and not valid_line_span(resolved, line_start, line_end)
            ):
                replay_failures += 1
                errors.append(
                    f"finding {idx}: evidence replay failed, invalid line span {line_start}-{line_end} for {cited_file}"
                )
                continue

            if semantic_tokens and line_start > 0 and line_end > 0:
                span = read_span_text(resolved, line_start, line_end, context=1)
                if span and any(token in span for token in semantic_tokens):
                    semantic_hit = True

        if semantic_tokens and not semantic_hit:
            lines.append(
                f"G1 WARN: finding {idx} {sev or 'UNKNOWN'} evidence semantic replay weak (no token hit in cited line spans)"
            )

    if replay_total > 0 and replay_failures / replay_total > 0.3:
        errors.append(
            f"evidence replay failure ratio too high: {replay_failures}/{replay_total} (>30%)"
        )

    for idx, record in enumerate(verdicts, start=1):
        fid = str(record.get("finding_id", "")).strip()
        if not fid:
            errors.append(f"verdict {idx}: missing finding_id")
            continue
        if fid not in finding_ids:
            errors.append(f"verdict {idx}: unknown finding_id {fid}")

        status = str(record.get("validity_verdict", ""))
        attempts = record.get("disproof_attempts", [])
        if status == "NEEDS_CONTEXT":
            errors.append(f"verdict {idx}: final verdict cannot be NEEDS_CONTEXT")

        if not isinstance(attempts, list) or len(attempts) < 2:
            errors.append(f"verdict {idx}: disproof_attempts must be >=2")
            continue

        normalized = [a for a in attempts if isinstance(a, dict)]
        disproved_count = sum(
            1 for a in normalized if str(a.get("result", "")).strip() == "DISPROVED"
        )
        failed_to_disprove = {
            str(a.get("strategy", "")).strip()
            for a in normalized
            if str(a.get("result", "")).strip() == "FAILED_TO_DISPROVE"
        }

        if status == "DISPUTED":
            if disproved_count < 1:
                errors.append(
                    f"verdict {idx}: DISPUTED requires at least one DISPROVED attempt"
                )
            if "refuting_code_path" not in record:
                errors.append(f"verdict {idx}: DISPUTED requires refuting_code_path")

        if status == "CONFIRMED":
            if disproved_count > 0:
                errors.append(
                    f"verdict {idx}: CONFIRMED cannot contain DISPROVED attempts"
                )
            if "confirmation_basis" not in record:
                errors.append(f"verdict {idx}: CONFIRMED requires confirmation_basis")
            if not failed_to_disprove:
                errors.append(
                    f"verdict {idx}: CONFIRMED requires FAILED_TO_DISPROVE attempts"
                )

            basis = record.get("confirmation_basis")
            if isinstance(basis, dict):
                items = basis.get("failed_strategies", [])
                basis_strategies = {
                    str(item.get("strategy", "")).strip()
                    for item in items
                    if isinstance(item, dict) and str(item.get("strategy", "")).strip()
                }
                if not basis_strategies:
                    errors.append(
                        f"verdict {idx}: confirmation_basis.failed_strategies must not be empty"
                    )
                elif not basis_strategies.issubset(failed_to_disprove):
                    errors.append(
                        f"verdict {idx}: confirmation_basis strategies must map to FAILED_TO_DISPROVE attempts"
                    )

    delivery_ready = False
    if not isinstance(coverage, dict):
        errors.append("coverage.json must be an object")
    else:
        content_gate_passed = bool(coverage.get("content_gate_passed"))
        r2_required = bool(coverage.get("r2_required"))
        delivery_ready = content_gate_passed and not r2_required

        if not content_gate_passed:
            errors.append("coverage.content_gate_passed must be true")
        if r2_required:
            errors.append("coverage.r2_required must be false for final delivery")

        metrics = (
            coverage.get("metrics", {})
            if isinstance(coverage.get("metrics"), dict)
            else {}
        )
        thresholds = (
            coverage.get("thresholds", {})
            if isinstance(coverage.get("thresholds"), dict)
            else {}
        )

        checks = [
            ("critical_surface_coverage_ratio", "critical_surface_min"),
            ("endpoint_audit_coverage_ratio", "endpoint_audit_min"),
        ]
        for metric_key, threshold_key in checks:
            metric = float(metrics.get(metric_key, 0.0))
            threshold = float(thresholds.get(threshold_key, 0.0))
            if metric < threshold:
                errors.append(
                    f"{metric_key}={metric:.2%} below threshold {threshold_key}={threshold:.2%}"
                )

        if "known_vuln_recall_min" in thresholds:
            recall = float(metrics.get("known_vuln_recall_ratio", 0.0))
            threshold = float(thresholds.get("known_vuln_recall_min", 0.0))
            if recall < threshold:
                errors.append(
                    f"known_vuln_recall_ratio={recall:.2%} below threshold={threshold:.2%}"
                )

    # --- P0 target coverage check ---
    audit_targets_path = audit_dir / "audit_targets.md"
    if audit_targets_path.exists():
        targets_text = audit_targets_path.read_text(encoding="utf-8", errors="ignore")
        p0_files: List[str] = []
        in_p0_section = False
        for raw_line in targets_text.splitlines():
            stripped = raw_line.strip()
            if stripped.startswith("## P0"):
                in_p0_section = True
                continue
            if stripped.startswith("## ") and in_p0_section:
                in_p0_section = False
                continue
            if not in_p0_section:
                continue
            if (
                not stripped.startswith("|")
                or stripped.startswith("|---")
                or stripped.startswith("| #")
            ):
                continue
            cols = [c.strip() for c in stripped.split("|")]
            # cols: ['', '#', 'file', 'reason', 'stratum', '']
            if len(cols) >= 4:
                file_col = cols[2]
                if file_col and file_col != "-" and file_col != "文件":
                    p0_files.append(normalize_file(file_col))

        if p0_files:
            p0_files = list(dict.fromkeys(p0_files))
            finding_files: set[str] = set()
            for finding in findings:
                val = normalize_file(finding.get("file", ""))
                if val:
                    finding_files.add(val)

                bundle = (
                    finding.get("evidence_bundle", {})
                    if isinstance(finding.get("evidence_bundle"), dict)
                    else {}
                )
                for ref in bundle.get("primary_refs", []):
                    if isinstance(ref, dict):
                        ev_file = normalize_file(ref.get("file", ""))
                        if ev_file:
                            finding_files.add(ev_file)

            findings_md_path = audit_dir / "findings.md"
            if findings_md_path.exists():
                md_text = findings_md_path.read_text(encoding="utf-8", errors="ignore")
                for match in FILE_LINE_RE.finditer(md_text):
                    ref_file = match.group("file") or match.group("file2") or ""
                    if ref_file:
                        finding_files.add(normalize_file(ref_file))

            covered_p0 = sum(
                1 for pf in p0_files if any(files_match(pf, ff) for ff in finding_files)
            )
            p0_ratio = covered_p0 / len(p0_files) if p0_files else 1.0

            if p0_ratio < 0.5:
                errors.append(
                    f"P0 target coverage critically low: {covered_p0}/{len(p0_files)} ({p0_ratio:.0%}). "
                    f"audit_targets.md lists {len(p0_files)} mandatory files but only {covered_p0} appear in findings."
                )
            elif p0_ratio < 0.8:
                lines.append(
                    f"G1 WARN: P0 target coverage below 80%: {covered_p0}/{len(p0_files)} ({p0_ratio:.0%})"
                )
            else:
                lines.append(
                    f"G1 INFO: P0 target coverage ok: {covered_p0}/{len(p0_files)} ({p0_ratio:.0%})"
                )

            # P0 LSP semantic evidence coverage check
            section_found, lsp_map = extract_p0_lsp_coverage_map(findings_md_text)
            if not section_found:
                errors.append("findings.md missing section: ## P0 语义证据覆盖（LSP）")
            else:
                lsp_missing: List[str] = []
                lsp_invalid: List[str] = []
                for pf in p0_files:
                    matched = [
                        ok
                        for file_path, ok in lsp_map.items()
                        if files_match(pf, file_path)
                    ]
                    if not matched:
                        lsp_missing.append(pf)
                    elif not any(matched):
                        lsp_invalid.append(pf)

                if lsp_missing:
                    errors.append(
                        "P0 LSP coverage missing rows for files: "
                        + ", ".join(lsp_missing[:20])
                    )
                if lsp_invalid:
                    errors.append(
                        "P0 LSP coverage invalid (needs LSP trace or LSP_UNAVAILABLE+RG_FALLBACK): "
                        + ", ".join(lsp_invalid[:20])
                    )

                lsp_ok = len(p0_files) - len(lsp_missing) - len(lsp_invalid)
                lsp_ratio = lsp_ok / len(p0_files) if p0_files else 1.0
                lines.append(
                    f"G1 INFO: P0 LSP evidence coverage {lsp_ok}/{len(p0_files)} ({lsp_ratio:.0%})"
                )

    ratio = 0.0
    if delivery_ready:
        ok, message = require(report_path)
        if not ok:
            errors.append(message)
        else:
            required_sections = [
                "项目概览",
                "复现总览",
                "关键漏洞复现指南",
                "攻击链复现",
                "修复优先级",
            ]
            for section in required_sections:
                if section not in report_text:
                    errors.append(f"missing report section: {section}")

            ratio = chinese_ratio(report_text)
            if ratio < 0.8:
                errors.append(f"Chinese ratio too low: {ratio:.2%} (<80%)")

            placeholders = ["{{", "}}", "TODO", "TBD", "[待补充]", "to be filled"]
            for marker in placeholders:
                if marker in report_text:
                    errors.append(f"placeholder marker found: {marker}")

            if not has_command_poc(report_text):
                errors.append("no executable command found in fenced PoC blocks")
    else:
        lines.append(
            "G1 INFO: report quality checks skipped until coverage converges (r2_required/content_gate_passed)"
        )

    if errors:
        return False, ["G1 FAIL: final delivery gate failed"] + errors[:80] + lines

    lines.append(
        "G1 PASS: "
        f"findings={len(findings)}, verdicts={len(verdicts)}, "
        f"report_chinese_ratio={ratio:.2%}, evidence_refs={replay_total}"
    )
    return True, lines


def run_named_gate(gate: str, audit_dir: Path) -> Tuple[bool, List[str]]:
    if gate == "g0":
        return run_g0(audit_dir)
    if gate == "g1":
        return run_g1(audit_dir)
    raise ValueError(f"unsupported gate: {gate}")


def main() -> int:
    args = parse_args()
    global GATE_MODE
    GATE_MODE = args.mode
    audit_dir = Path(args.audit_dir)
    status_out = (
        Path(args.status_out) if args.status_out else (audit_dir / "status.json")
    )
    gate_results: List[Dict[str, Any]] = []

    if args.gate == "all":
        overall = True
        for gate in GATE_ORDER:
            ok, lines = run_named_gate(gate, audit_dir)
            for line in lines:
                print(line)
            gate_results.append({"gate": gate, "ok": ok, "lines": lines})
            if not ok:
                overall = False
    else:
        ok, lines = run_named_gate(args.gate, audit_dir)
        for line in lines:
            print(line)
        overall = ok
        gate_results.append({"gate": args.gate, "ok": ok, "lines": lines})

    write_status_file(
        status_out, args.gate, args.mode, overall, gate_results, audit_dir
    )
    print(f"status written: {status_out}")

    if args.mode == "advisory":
        if not overall:
            print(
                "ADVISORY: gate not fully satisfied; see status.json for next actions."
            )
        return 0
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
