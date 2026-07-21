#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import Settings
from app.store import IncidentStore


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Preview or apply HCWW incident retention cleanup.")
    parser.add_argument(
        "--db-path",
        default="",
        help="SQLite database path. Defaults to HCWW_AGENT_DB_PATH or Settings default.",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=None,
        help="Rows older than this many days are eligible for cleanup.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete eligible rows. Omit to preview only.",
    )
    args = parser.parse_args(argv)

    settings = None
    if not args.db_path or args.retention_days is None:
        settings = Settings()
    db_path = args.db_path or settings.db_path
    retention_days = args.retention_days if args.retention_days is not None else settings.retention_days

    store = IncidentStore(db_path)
    result = store.cleanup_retention(
        retention_days=retention_days,
        apply=args.apply,
    )
    print(json.dumps({"retention": result}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
