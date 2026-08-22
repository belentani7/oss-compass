from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import audit, render_json, render_text
from .ledger import ValidationLedger


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit open-source project readiness locally.")
    subparsers = parser.add_subparsers(dest="command")

    audit_parser = subparsers.add_parser("audit", help="Audit open-source project readiness locally")
    audit_parser.add_argument("path", nargs="?", default=".", help="Project directory to audit")
    audit_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    ledger_parser = subparsers.add_parser("ledger-verify", help="Verify a PVC-U NDJSON audit ledger offline")
    ledger_parser.add_argument("path", type=Path, help="Path to a ledger NDJSON file")
    ledger_parser.add_argument("--head", help="Expected final entry hash")
    ledger_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    raw_args = sys.argv[1:]
    if not raw_args or raw_args[0] not in {"audit", "ledger-verify"}:
        raw_args.insert(0, "audit")
    args = parser.parse_args(raw_args)
    if args.command == "ledger-verify":
        ledger = ValidationLedger.from_ndjson(args.path)
        result = ledger.verify(expected_head_hash=args.head)
        payload = result.to_dict()
        print(json.dumps(payload, sort_keys=True) if args.json else (
            f"ledger: {'valid' if result.valid else 'invalid'}\nentries: {result.entry_count}\nhead: {result.head_hash}"
            + ("\nerrors: " + "; ".join(result.errors) if result.errors else "")
        ))
        return 0 if result.valid else 1

    report = audit(Path(args.path))
    print(render_json(report) if args.json else render_text(report))
    return 0 if report.score >= 75 else 1


if __name__ == "__main__":
    raise SystemExit(main())
