#!/usr/bin/env python3
"""Shared helpers for code-security-audit scripts.

Keep helpers in one place to avoid subtle contract drift across scripts.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_file(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    if text.startswith("./"):
        text = text[2:]
    return text


def files_match(left: Any, right: Any) -> bool:
    a = normalize_file(left)
    b = normalize_file(right)
    if not a or not b:
        return False
    if a == b:
        return True
    return a.endswith(f"/{b}") or b.endswith(f"/{a}")


def normalize_mi_id(value: Any) -> str:
    text = re.sub(r"[^A-Za-z0-9]", "", str(value or "")).upper()
    if not text.startswith("MI"):
        return ""
    suffix = text[2:]
    if not suffix.isdigit():
        return ""
    return f"MI{int(suffix):04d}"


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                out.append(obj)
    return out


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    tmp.replace(path)


def estimate_tokens(parts: Iterable[str]) -> int:
    text = "\n".join(str(x) for x in parts)
    if not text:
        return 0
    # Simple and stable approximation (no external tokenizer dependency).
    return max(1, int(len(text) / 4))


# --- Agent registry constants ---
SCAN_AGENTS = frozenset({"access-scanner", "injection-scanner", "infra-scanner"})
ALL_AGENTS = frozenset({*SCAN_AGENTS, "chain-synthesizer"})


def append_manifest_entry(audit_dir: Path, entry: Dict[str, Any]) -> None:
    """Append a single JSONL line to manifest.jsonl.

    Args:
        audit_dir: Path to audit directory
        entry: Dictionary to append as JSONL line
    """
    audit_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = audit_dir / "manifest.jsonl"
    with manifest_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def load_manifest(audit_dir: Path) -> List[Dict[str, Any]]:
    """Load manifest.jsonl from audit directory.

    Args:
        audit_dir: Path to audit directory

    Returns:
        List of manifest entries, empty list if file missing
    """
    return load_jsonl(audit_dir / "manifest.jsonl")


def load_verification_index(audit_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Load verification.jsonl and index by entry_id.

    Args:
        audit_dir: Path to audit directory

    Returns:
        Dictionary keyed by entry_id (V-XXX), empty dict if file missing
    """
    entries = load_jsonl(audit_dir / "verification.jsonl")
    result: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        entry_id = entry.get("entry_id")
        if entry_id:
            result[entry_id] = entry
    return result


def get_verified_finding_ids(audit_dir: Path) -> Set[str]:
    """Extract finding IDs from verified entries in verification.jsonl.

    Args:
        audit_dir: Path to audit directory

    Returns:
        Set of finding IDs (F-XXX) where verification_conclusion is CONFIRMED
    """
    entries = load_jsonl(audit_dir / "verification.jsonl")
    verified_ids: Set[str] = set()

    for entry in entries:
        if entry.get("verification_conclusion") == "CONFIRMED":
            finding_refs = entry.get("finding_refs", "")
            if finding_refs:
                # Split comma-separated string and strip whitespace
                ids = [fid.strip() for fid in finding_refs.split(",")]
                verified_ids.update(ids)

    return verified_ids
