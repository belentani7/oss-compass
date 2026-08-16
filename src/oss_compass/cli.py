from __future__ import annotations

import argparse
from pathlib import Path

from .core import audit, render_json, render_text


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit open-source project readiness locally.")
    parser.add_argument("path", nargs="?", default=".", help="Project directory to audit")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()
    report = audit(Path(args.path))
    print(render_json(report) if args.json else render_text(report))
    return 0 if report.score >= 75 else 1


if __name__ == "__main__":
    raise SystemExit(main())
