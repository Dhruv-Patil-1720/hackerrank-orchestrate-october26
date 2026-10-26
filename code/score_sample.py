"""Compare a prediction CSV with dataset/sample_output.csv."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def load(path: Path) -> dict[str, dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        return {row["case_id"]: row for row in csv.DictReader(handle)}


def steps_of(raw: str) -> list[dict]:
    return json.loads(raw)


def field_score(expected: list[dict], predicted: list[dict]) -> tuple[int, int]:
    width = max(len(expected), len(predicted), 1) if (expected or predicted) else 1
    if not expected and not predicted:
        return 1, 1
    matched = 0
    total = max(len(expected), len(predicted)) * len(FIELDS)
    for index in range(max(len(expected), len(predicted))):
        exp = expected[index] if index < len(expected) else None
        pred = predicted[index] if index < len(predicted) else None
        for name in FIELDS:
            if exp is not None and pred is not None and exp.get(name) == pred.get(name):
                matched += 1
    return matched, total


def main() -> None:
    predicted_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "output.csv"
    expected_rows = load(ROOT / "dataset" / "sample_output.csv")
    predicted_rows = load(predicted_path)
    status_hit = 0
    exact_hit = 0
    field_hit = 0
    field_total = 0
    failures = []
    for case_id, expected in expected_rows.items():
        predicted = predicted_rows.get(case_id)
        if predicted is None:
            failures.append(f"{case_id} missing")
            field_total += max(len(steps_of(expected["steps_json"])), 1) * len(FIELDS)
            continue
        status_ok = predicted["deletion_status"] == expected["deletion_status"]
        status_hit += int(status_ok)
        exp_steps = steps_of(expected["steps_json"])
        pred_steps = steps_of(predicted["steps_json"])
        exact_ok = exp_steps == pred_steps
        exact_hit += int(exact_ok)
        matched, total = field_score(exp_steps, pred_steps)
        field_hit += matched
        field_total += total
        if not exact_ok:
            failures.append(
                f"{case_id} status {predicted['deletion_status']} vs {expected['deletion_status']} "
                f"steps {len(pred_steps)} vs {len(exp_steps)}"
            )
    count = len(expected_rows)
    print(f"status {status_hit}/{count}")
    print(f"exact {exact_hit}/{count}")
    ratio = field_hit / field_total if field_total else 0
    print(f"field {field_hit}/{field_total} {ratio:.3f}")
    print("failing")
    for line in failures:
        print(line)


if __name__ == "__main__":
    main()
