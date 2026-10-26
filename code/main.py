"""Run the deletion audit and write output.csv."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from evidence import DATASET, ROOT, load_catalog
from output import dump_steps, read_cases, write_output
from rules import audit_case


def audit_all(cases: list[dict], catalog) -> list[dict]:
    rows = []
    for case in cases:
        status, steps = audit_case(catalog, case)
        rows.append(
            {
                "case_id": case["case_id"],
                "deletion_status": status,
                "steps_json": dump_steps(steps),
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit deletion requests and write output.csv")
    parser.add_argument(
        "--requests",
        default=str(DATASET / "deletion_requests.csv"),
        help="CSV of cases to audit",
    )
    parser.add_argument(
        "--out",
        default=str(ROOT / "output.csv"),
        help="Where to write the prediction file",
    )
    args = parser.parse_args()
    catalog = load_catalog()
    cases = read_cases(Path(args.requests))
    rows = audit_all(cases, catalog)
    write_output(Path(args.out), rows)
    print(f"wrote {len(rows)} rows to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
