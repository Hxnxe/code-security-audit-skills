#!/usr/bin/env python3
"""Strict JSON/JSONL validator without external dependencies."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


SCHEMA_FILE = {
    "inventory": "inventory.schema.json",
    "attack-surface": "attack-surface.schema.json",
    "finding": "finding.schema.json",
    "verdict": "verdict.schema.json",
    "coverage": "coverage.schema.json",
    "chains": "chains.schema.json",
    "work-queue": "work_queue.schema.json",
    "cycle-state": "cycle_state.schema.json",
    "verification": "verification.schema.json",
    # Legacy/optional navigation schemas kept for backwards compatibility.
    "codeelement": "../legacy/v3/schemas/codeelement.schema.json",
    "edge": "../legacy/v3/schemas/edge.schema.json",
    "source-sink": "../legacy/v3/schemas/source-sink.schema.json",
    "data-catalog": "../legacy/v3/schemas/data-catalog.schema.json",
    "anomaly": "../legacy/v3/schemas/anomaly.schema.json",
}


class ValidationError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate JSON/JSONL files against skill schemas.")
    parser.add_argument("input_path", help="Path to JSON or JSONL file")
    parser.add_argument("schema", choices=sorted(SCHEMA_FILE.keys()), help="Schema name")
    return parser.parse_args()


def schema_root() -> Path:
    return Path(__file__).resolve().parent.parent / "schemas"


def load_schema(name: str) -> Dict[str, Any]:
    path = schema_root() / SCHEMA_FILE[name]
    return json.loads(path.read_text(encoding="utf-8"))


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_number(value: Any) -> bool:
    return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)


def type_ok(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return is_int(value)
    if expected == "number":
        return is_number(value)
    if expected == "boolean":
        return isinstance(value, bool)
    return True


def format_path(path: List[str | int]) -> str:
    if not path:
        return "$"
    out = "$"
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}"
    return out


def ensure(condition: bool, message: str, path: List[str | int]) -> None:
    if not condition:
        raise ValidationError(f"{format_path(path)}: {message}")


def matches(value: Any, schema: Dict[str, Any]) -> bool:
    try:
        validate(value, schema, [])
        return True
    except ValidationError:
        return False


def validate_conditions(value: Any, schema: Dict[str, Any], path: List[str | int]) -> None:
    for condition in schema.get("allOf", []):
        cond_if = condition.get("if")
        cond_then = condition.get("then")
        if cond_if and cond_then and matches(value, cond_if):
            validate(value, cond_then, path)


def validate(value: Any, schema: Dict[str, Any], path: List[str | int]) -> None:
    if "const" in schema:
        ensure(value == schema["const"], f"expected const {schema['const']!r}", path)

    if "enum" in schema:
        ensure(value in schema["enum"], f"value {value!r} not in enum", path)

    expected = schema.get("type")
    if expected:
        ensure(type_ok(value, expected), f"expected type {expected}", path)

    if expected == "string":
        if "minLength" in schema:
            ensure(len(value) >= schema["minLength"], f"string shorter than {schema['minLength']}", path)
        if "maxLength" in schema:
            ensure(len(value) <= schema["maxLength"], f"string longer than {schema['maxLength']}", path)
        if "pattern" in schema:
            ensure(re.match(schema["pattern"], value) is not None, f"string does not match pattern {schema['pattern']}", path)

    if expected in {"integer", "number"}:
        if "minimum" in schema:
            ensure(value >= schema["minimum"], f"value < minimum {schema['minimum']}", path)
        if "maximum" in schema:
            ensure(value <= schema["maximum"], f"value > maximum {schema['maximum']}", path)

    if expected == "array":
        if "minItems" in schema:
            ensure(len(value) >= schema["minItems"], f"array has fewer than {schema['minItems']} items", path)
        if "maxItems" in schema:
            ensure(len(value) <= schema["maxItems"], f"array has more than {schema['maxItems']} items", path)
        if schema.get("uniqueItems"):
            seen = set()
            for idx, item in enumerate(value):
                key = json.dumps(item, sort_keys=True, ensure_ascii=False)
                ensure(key not in seen, "array items must be unique", path + [idx])
                seen.add(key)
        item_schema = schema.get("items")
        if item_schema:
            for idx, item in enumerate(value):
                validate(item, item_schema, path + [idx])

    if expected == "object":
        required = schema.get("required", [])
        for key in required:
            ensure(key in value, f"missing required field {key!r}", path)

        properties = schema.get("properties", {})
        allow_extra = schema.get("additionalProperties", True)
        if allow_extra is False:
            for key in value.keys():
                ensure(key in properties, f"unexpected field {key!r}", path)

        for key, subschema in properties.items():
            if key in value:
                validate(value[key], subschema, path + [key])

    validate_conditions(value, schema, path)


def load_records(path: Path) -> Iterable[Tuple[int, Any]]:
    if path.suffix == ".jsonl":
        with path.open("r", encoding="utf-8") as fh:
            for idx, raw in enumerate(fh, start=1):
                line = raw.strip()
                if not line:
                    continue
                yield idx, json.loads(line)
        return

    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        for idx, item in enumerate(data, start=1):
            yield idx, item
    else:
        yield 1, data


def validate_verification_md(path: Path) -> Tuple[bool, List[str]]:
    """Validate verification.md markdown structure.
    
    Returns (success, errors) tuple.
    """
    errors: List[str] = []
    
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return False, [f"unable to read verification.md: {exc}"]
    
    # Check for required summary section
    if "## 验证摘要" not in content:
        errors.append("missing required section: ## 验证摘要")
    
    # Find all V-XXX entries
    entry_pattern = re.compile(r"^###\s*(V-[A-Za-z0-9_-]+)\s*:\s*(.+?)\s*$", re.MULTILINE)
    entries = entry_pattern.findall(content)
    
    if not entries:
        errors.append("no verification entries found. Require headings like: ### V-XXX: 标题")
        return len(errors) == 0, errors
    
    # Required labels for each entry
    required_labels = [
        "来源",
        "文件",
        "数据流追踪",
        "验证结论",
        "证据",
    ]
    
    # Parse entry blocks
    lines = content.split("\n")
    current_entry_id = ""
    current_block_lines: List[str] = []
    entry_blocks: Dict[str, str] = {}
    
    for line in lines:
        match = entry_pattern.match(line.strip())
        if match:
            if current_entry_id:
                entry_blocks[current_entry_id] = "\n".join(current_block_lines)
            current_entry_id = match.group(1).strip()
            current_block_lines = []
            continue
        if current_entry_id:
            current_block_lines.append(line)
    
    if current_entry_id:
        entry_blocks[current_entry_id] = "\n".join(current_block_lines)
    
    # Validate each entry
    for entry_id, block in entry_blocks.items():
        for label in required_labels:
            if not re.search(rf"\*\*{re.escape(label)}\*\*\s*:", block):
                errors.append(f"{entry_id}: missing required label '**{label}**'")
        
        # Validate 验证结论 value
        conclusion_match = re.search(r"\*\*验证结论\*\*\s*:\s*(.+)", block)
        if conclusion_match:
            conclusion = conclusion_match.group(1).strip().upper()
            if conclusion not in {"CONFIRMED", "DISPUTED", "NEEDS_DEEPER"}:
                errors.append(f"{entry_id}: invalid 验证结论={conclusion!r}")
        
        # Validate 文件 contains file:line
        file_match = re.search(r"\*\*文件\*\*\s*:\s*(.+)", block)
        if file_match:
            file_val = file_match.group(1).strip()
            if not re.search(r"[A-Za-z0-9_./\-\[\]()]+\.[A-Za-z0-9_]+:\d+", file_val):
                errors.append(f"{entry_id}: **文件** must contain file:line format")
    
    return len(errors) == 0, errors


def main() -> int:
    args = parse_args()
    input_path = Path(args.input_path)
    if not input_path.exists():
        print(f"input file does not exist: {input_path}", file=sys.stderr)
        return 1

    errors: List[str] = []
    checked = 0

    if args.schema == "verification":
        success, md_errors = validate_verification_md(input_path)
        if not success:
            for err in md_errors:
                print(err, file=sys.stderr)
            return 1
        checked = 1
        print(f"validated {checked} records against {args.schema}")
        return 0

    schema = load_schema(args.schema)

    if args.schema == "verdict":
        try:
            data = json.loads(input_path.read_text(encoding="utf-8"))
            validate(data, schema, [])
            if isinstance(data, dict) and isinstance(data.get("verdicts"), list):
                checked = len(data["verdicts"])
            else:
                checked = 1
        except ValidationError as exc:
            errors.append(f"record 1: {exc}")
        except Exception as exc:
            errors.append(f"record 1: unable to parse verdict document: {exc}")

        if errors:
            for err in errors:
                print(err, file=sys.stderr)
            return 1

        print(f"validated {checked} records against {args.schema}")
        return 0

    for idx, record in load_records(input_path):
        checked += 1
        try:
            validate(record, schema, [])
        except ValidationError as exc:
            errors.append(f"record {idx}: {exc}")

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    print(f"validated {checked} records against {args.schema}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
