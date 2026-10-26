"""Repository paths. Resolved from this file so every module shares one root."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
