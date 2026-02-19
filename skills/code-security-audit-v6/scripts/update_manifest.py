#!/usr/bin/env python3
"""CLI for appending to and viewing manifest.jsonl.

Provides two modes:
  - Append mode (default): Add a manifest entry for a shard/agent/status
  - Show mode (--show): Display current manifest state grouped by shard_id
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

# Add scripts directory to path for shared_utils import
sys.path.insert(0, str(Path(__file__).parent))

from shared_utils import append_manifest_entry, load_manifest, now_utc  # type: ignore


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manage manifest.jsonl: append entries or display current state"
    )
    parser.add_argument(
        "audit_dir",
        type=Path,
        help="Path to audit directory",
    )
    parser.add_argument(
        "--shard-id",
        type=str,
        help="Shard ID (required for append mode)",
    )
    parser.add_argument(
        "--agent",
        type=str,
        help="Agent name (required for append mode)",
    )
    parser.add_argument(
        "--status",
        type=str,
        default="done",
        help="Status (default: done)",
    )
    parser.add_argument(
        "--files",
        type=str,
        help="Comma-separated list of files covered",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Display current manifest state",
    )

    args = parser.parse_args()

    # Show mode
    if args.show:
        manifest = load_manifest(args.audit_dir)
        if not manifest:
            print("manifest is empty")
            return 0

        # Group by shard_id
        by_shard = defaultdict(list)
        for entry in manifest:
            by_shard[entry.get("shard_id", "?")].append(entry)

        total = len(manifest)
        done = sum(1 for e in manifest if e.get("status") == "done")
        print(f"Manifest: {total} entries, {done} done")
        print()
        for shard_id in sorted(by_shard.keys()):
            entries = by_shard[shard_id]
            for e in entries:
                print(
                    f"  {shard_id} | {e.get('agent', '?'):20s} | {e.get('status', '?'):10s} | {e.get('timestamp', '?')}"
                )
        return 0

    # Append mode (default)
    if not args.shard_id or not args.agent:
        parser.error(
            "--shard-id and --agent are required for append mode (or use --show)"
        )

    entry = {
        "shard_id": args.shard_id,
        "agent": args.agent,
        "status": args.status,
        "timestamp": now_utc(),
        "files_covered": (
            [f.strip() for f in args.files.split(",") if f.strip()]
            if args.files
            else []
        ),
    }
    append_manifest_entry(args.audit_dir, entry)
    print(f"manifest updated: {args.shard_id} / {args.agent} / {args.status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
