"""Read evidence screenshots with Gemma 4 and cache the JSON.

Uses the same model id as the fairclaim project: gemma-4-26b-a4b-it.
The API key is read from GEMINI_API_KEY and is never written to disk.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
CACHE = ROOT / "code" / "cache" / "screenshots"
MODEL = "gemma-4-26b-a4b-it"
URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"

PROMPT = """Read this Northstar Shop admin screenshot. Copy only text you can see.
Return one JSON object with a records array. Each record has:
resource_id (such as account_123, search_123, analytics_123, support_123, export_123, backup_123, data_flow_123, audit_record_123, tombstone_123, marketing_123),
system_id (account_service, search_service, analytics_platform, support_platform, export_service, backup_service, integration_service, security_service, identity_service, marketing_platform, or object_storage),
emails (array),
user_ids (array of user_N values),
phones (array),
state (present, absent, anonymized, redacted, active, blocked, or disabled).
Leave unknown fields empty. Do not invent an identifier that is not printed in the image.
"""


def cache_path(file_id: str) -> Path:
    return CACHE / f"{file_id}.json"


def call_model(png: bytes) -> dict:
    key = os.environ.get("GEMINI_API_KEY", "")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not set")
    body = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {"inline_data": {"mime_type": "image/png", "data": base64.b64encode(png).decode("ascii")}},
                    {"text": PROMPT},
                ],
            }
        ],
        "generationConfig": {"temperature": 0},
    }
    payload = json.dumps(body).encode("utf-8")
    CACHE.mkdir(parents=True, exist_ok=True)
    header_path = CACHE / ".headers"
    header_path.write_text(f"Content-Type: application/json\nx-goog-api-key: {key}\n", encoding="utf-8")
    header_path.chmod(0o600)
    last_error = "unknown error"
    try:
        for attempt in range(4):
            completed = subprocess.run(
                [
                    "curl",
                    "-sS",
                    "-m",
                    "90",
                    "-X",
                    "POST",
                    URL,
                    "-H",
                    f"@{header_path}",
                    "--data-binary",
                    "@-",
                ],
                input=payload,
                capture_output=True,
                check=False,
            )
            text = completed.stdout.decode("utf-8", errors="replace")
            if completed.returncode == 0 and text.startswith("{"):
                parsed = json.loads(text)
                if "error" not in parsed:
                    return parsed
                code = parsed.get("error", {}).get("code", 0)
                last_error = f"HTTP {code} {parsed.get('error', {}).get('status', '')}"
                if code not in {500, 502, 503, 504}:
                    break
            else:
                detail = completed.stderr.decode("utf-8", errors="replace")[:180]
                last_error = detail or f"curl {completed.returncode}"
            time.sleep(2 ** attempt)
    finally:
        header_path.unlink(missing_ok=True)
    raise RuntimeError(last_error)


def answer_text(payload: dict) -> str:
    parts = payload.get("candidates", [{}])[0].get("content", {}).get("parts", [])
    return "".join(part.get("text", "") for part in parts if not part.get("thought"))


def usage_of(payload: dict) -> dict:
    meta = payload.get("usageMetadata") or {}
    return {
        "promptTokenCount": meta.get("promptTokenCount", 0),
        "candidatesTokenCount": meta.get("candidatesTokenCount", 0),
        "thoughtsTokenCount": meta.get("thoughtsTokenCount", 0),
    }


def load_env_file() -> None:
    path = ROOT / ".env"
    if os.environ.get("GEMINI_API_KEY") or not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        name, value = text.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip().strip('"').strip("'"))


def main() -> None:
    load_env_file()
    CACHE.mkdir(parents=True, exist_ok=True)
    manifest = list(csv.DictReader((DATASET / "evidence_files.csv").open(encoding="utf-8")))
    totals = {"promptTokenCount": 0, "candidatesTokenCount": 0, "thoughtsTokenCount": 0, "calls": 0}
    for row in manifest:
        if not row["file_path"].endswith(".png"):
            continue
        destination = cache_path(row["file_id"])
        if destination.exists():
            print(f"{row['file_id']} cached")
            continue
        png = (DATASET / row["file_path"]).read_bytes()
        digest = hashlib.sha256(png).hexdigest()
        try:
            payload = call_model(png)
        except RuntimeError as error:
            destination.write_text(
                json.dumps({"file_id": row["file_id"], "error": str(error)[:200], "sha256": digest}, indent=2),
                encoding="utf-8",
            )
            print(f"{row['file_id']} error")
            continue
        text = answer_text(payload)
        usage = usage_of(payload)
        for key_name, value in usage.items():
            totals[key_name] += value or 0
        totals["calls"] += 1
        destination.write_text(
            json.dumps(
                {
                    "file_id": row["file_id"],
                    "model": MODEL,
                    "sha256": digest,
                    "usage": usage,
                    "answer": text,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"{row['file_id']} ok tokens {usage['promptTokenCount']}+{usage['candidatesTokenCount']}")
    (CACHE / "usage.json").write_text(json.dumps({"model": MODEL, **totals}, indent=2), encoding="utf-8")
    print("usage", totals)


if __name__ == "__main__":
    main()
