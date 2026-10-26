"""Identity resolution and whether a request authorizes deletion."""

from __future__ import annotations

import csv
import re
from collections import defaultdict

from paths import DATASET

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"(?<![A-Za-z0-9_])user_\d+(?!\d)")
HASH_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")

NA_PATTERNS = re.compile(
    "|".join(
        [
            r"not asking for deletion",
            r"do not close the account",
            r"don'?t delete",
            r"do not delete",
            r"leave the account active",
            r"leave my profile",
            r"keep the account",
            r"marketing lists only",
            r"stop the promotional",
            r"still want receipts",
            r"resetting the login",
            r"change the email address",
            r"misspelled",
            r"without removing",
            r"portable format",
            r"copy of last year",
            r"copy of the information",
            r"what personal information you hold",
            r"not a request to erase",
            r"information request",
        ]
    ),
    re.IGNORECASE,
)

def digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def add_token(bucket: set[str], value: str | None) -> None:
    if value is None:
        return
    text = str(value).strip()
    if not text or text.lower() in {"null", "none", "n/a"}:
        return
    for email in EMAIL_RE.findall(text):
        bucket.add(email.lower())
    for user in USER_RE.findall(text):
        bucket.add(user)
    for digest in HASH_RE.findall(text):
        bucket.add(digest.lower())
    if text.startswith("+") or (digits(text) and len(digits(text)) >= 8 and "@" not in text):
        number = digits(text)
        if len(number) >= 8:
            bucket.add("tel:" + number)

def load_identities() -> tuple[dict, dict[str, set[str]]]:
    users: dict[str, dict] = {}
    token_users: dict[str, set[str]] = defaultdict(set)
    for row in csv.DictReader((DATASET / "user_identities.csv").open(encoding="utf-8")):
        users[row["user_id"]] = row
        for token in tokens_from_identity_row(row):
            token_users[token].add(row["user_id"])
    for row in csv.DictReader((DATASET / "user_audit_log.csv").open(encoding="utf-8")):
        bucket: set[str] = set()
        add_token(bucket, row["old_value"])
        add_token(bucket, row["new_value"])
        for token in bucket:
            token_users[token].add(row["user_id"])
    return users, token_users


def tokens_from_identity_row(row: dict) -> set[str]:
    bucket: set[str] = set()
    add_token(bucket, row["user_id"])
    add_token(bucket, row["email"])
    add_token(bucket, row["phone"])
    add_token(bucket, row["email_hash"])
    return bucket


def authorizes_deletion(request_text: str) -> bool:
    return NA_PATTERNS.search(request_text or "") is None


def resolve_user(catalog: Catalog, email: str) -> str | None:
    matches = catalog.token_users.get(email.lower(), set())
    if len(matches) == 1:
        return next(iter(matches))
    return None


def users_for_tokens(catalog: Catalog, tokens: set[str]) -> set[str]:
    found: set[str] = set()
    for token in tokens:
        found |= catalog.token_users.get(token, set())
    return found
