#!/usr/bin/env python3
"""Compile verdict draft/skeleton into schema-valid verdict.json."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import validate_schema as schema_validator


FENCED_JSON_RE = re.compile(r"```json\s*(.*?)```", re.IGNORECASE | re.DOTALL)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile verdict draft to verdict.json")
    parser.add_argument("audit_dir", nargs="?", default="audit", help="Audit directory")
    parser.add_argument("--draft", default=None, help="Draft path (default: <audit_dir>/verdict_draft.md)")
    parser.add_argument("--skeleton", default=None, help="Skeleton path (default: <audit_dir>/verdict.skeleton.json)")
    parser.add_argument("--out", default=None, help="Output path (default: <audit_dir>/verdict.json)")
    parser.add_argument("--overwrite", action="store_true", help="Allow overwriting verdict.json")
    return parser.parse_args()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_draft_payload(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="ignore")
    match = FENCED_JSON_RE.search(text)
    if match:
        return json.loads(match.group(1).strip())
    return json.loads(text.strip())


def normalize_payload(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict) and isinstance(data.get("verdicts"), list):
        payload = dict(data)
    elif isinstance(data, list):
        payload = {"schema_version": 1, "verdicts": data}
    elif isinstance(data, dict):
        payload = {"schema_version": 1, "verdicts": [data]}
    else:
        raise ValueError("unsupported verdict payload type")

    if "schema_version" not in payload:
        payload["schema_version"] = 1
    verdicts = payload.get("verdicts", [])
    if not isinstance(verdicts, list):
        raise ValueError("verdicts must be a list")
    for row in verdicts:
        if isinstance(row, dict) and "schema_version" not in row:
            row["schema_version"] = 1
    return payload


def index_by_finding_id(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in payload.get("verdicts", []):
        if not isinstance(row, dict):
            continue
        finding_id = str(row.get("finding_id", "")).strip()
        if finding_id:
            out[finding_id] = row
    return out


def deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        merged: Dict[str, Any] = dict(base)
        for key, value in override.items():
            if key in merged:
                merged[key] = deep_merge(merged[key], value)
            else:
                merged[key] = value
        return merged
    # Arrays and scalars are replaced entirely by override
    return override


def merge_with_skeleton(skeleton: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    base_rows = [row for row in skeleton.get("verdicts", []) if isinstance(row, dict)]
    over_index = index_by_finding_id(override)
    out_rows: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for row in base_rows:
        fid = str(row.get("finding_id", "")).strip()
        if fid and fid in over_index:
            out_rows.append(deep_merge(row, over_index[fid]))
            seen.add(fid)
        else:
            out_rows.append(row)

    for fid, row in over_index.items():
        if fid not in seen:
            out_rows.append(row)

    return {
        "schema_version": 1,
        "verdicts": out_rows,
    }


def validate_verdict(payload: Dict[str, Any]) -> None:
    schema = schema_validator.load_schema("verdict")
    schema_validator.validate(payload, schema, [])


def main() -> int:
    args = parse_args()
    audit_dir = Path(args.audit_dir).resolve()
    draft_path = Path(args.draft) if args.draft else audit_dir / "verdict_draft.md"
    skeleton_path = Path(args.skeleton) if args.skeleton else audit_dir / "verdict.skeleton.json"
    out_path = Path(args.out) if args.out else audit_dir / "verdict.json"

    if out_path.exists() and not args.overwrite:
        print(f"error: output already exists: {out_path} (use --overwrite)", file=sys.stderr)
        return 1

    skeleton_payload: Dict[str, Any] | None = None
    if skeleton_path.exists():
        skeleton_payload = normalize_payload(load_json(skeleton_path))

    draft_payload: Dict[str, Any] | None = None
    if draft_path.exists():
        try:
            draft_payload = normalize_payload(parse_draft_payload(draft_path))
        except Exception as exc:
            print(f"error: failed to parse draft {draft_path}: {exc}", file=sys.stderr)
            return 1

    if draft_payload is None and skeleton_payload is None:
        print(
            f"error: neither draft nor skeleton exists ({draft_path}, {skeleton_path})",
            file=sys.stderr,
        )
        return 1

    if draft_payload is not None and skeleton_payload is not None:
        compiled = merge_with_skeleton(skeleton_payload, draft_payload)
        source = "draft+skeleton"
    elif draft_payload is not None:
        compiled = draft_payload
        source = "draft"
    else:
        compiled = skeleton_payload or {"schema_version": 1, "verdicts": []}
        source = "skeleton"

    try:
        validate_verdict(compiled)
    except Exception as exc:
        print(f"error: compiled verdict does not satisfy schema: {exc}", file=sys.stderr)
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(compiled, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"compiled verdict: {out_path} (source={source}, verdicts={len(compiled.get('verdicts', []))})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

