"""Serialize steps and write output.csv."""

from __future__ import annotations

import csv
import json
from pathlib import Path

def dump_steps(steps: list[dict]) -> str:
    return json.dumps(steps, separators=(",", ":"), ensure_ascii=False)


def case_sort(case_id: str) -> int:
    return int(case_id.split("_", 1)[1])


def read_cases(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_output(path: Path, rows: list[dict]) -> None:
    rows = sorted(rows, key=lambda row: case_sort(row["case_id"]))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(rows)
