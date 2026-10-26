"""Evidence parsers. Each file becomes observations. Rules decide what they mean."""

from __future__ import annotations

import csv
import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from identity import add_token, load_identities
from paths import DATASET, ROOT

RESOURCE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:account|search|analytics|support|export|backup|tombstone|marketing|cache|object)_\d+"
    r"|data_flow_\d+|audit_record_\d+|legal_hold_\d+"
)
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
KV_RE = re.compile(r"(\w+)=(\"([^\"]*)\"|(\S+))")

SYSTEM_ALIAS = {
    "support_replica": "support_platform",
    "account_failover_replica": "account_service",
    "account_replication_cluster": "account_service",
    "customer_account_service": "account_service",
    "object_store": "object_storage",
    "attachment_preview": "support_platform",
}

COLLECTION_META = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "backup_catalog": ("backup_service", "BACKUP_ARCHIVE"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "customer_export_jobs": ("export_service", "USER_EXPORT"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "support_conversations": ("support_platform", "SUPPORT_MESSAGE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "retained_order_records": ("legal_service", "LEGAL_HOLD_RECORD"),
}

PREFIX_META = [
    ("audit_record_", "security_service", "SECURITY_AUDIT_LOG"),
    ("data_flow_", "integration_service", "DATA_FLOW"),
    ("legal_hold_", "legal_service", "LEGAL_HOLD_RECORD"),
    ("account_", "account_service", "USER_PROFILE"),
    ("search_", "search_service", "SEARCH_INDEX_ENTRY"),
    ("analytics_", "analytics_platform", "ANALYTICS_PROFILE"),
    ("support_", "support_platform", "SUPPORT_MESSAGE"),
    ("export_", "export_service", "USER_EXPORT"),
    ("backup_", "backup_service", "BACKUP_ARCHIVE"),
    ("tombstone_", "identity_service", "ACCOUNT_TOMBSTONE"),
    ("marketing_", "marketing_platform", "MARKETING_PROFILE"),
    ("cache_", "cache_service", "CACHE_ENTRY"),
    ("object_", "object_storage", "SUPPORT_ATTACHMENT"),
]

PII_KEYS = {
    "email",
    "owner_email",
    "requester_email",
    "customer_email",
    "phone",
    "owner_phone",
    "requester_phone",
    "email_hash",
    "full_name",
    "display_name",
    "requester_name",
    "name",
}
CATEGORY_ACTION = {
    "USER_PROFILE": "DELETE",
    "SECONDARY_IDENTIFIER": "DELETE",
    "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE",
    "SUPPORT_ATTACHMENT": "DELETE",
    "SUPPORT_MESSAGE": "REDACT",
    "ANALYTICS_PROFILE": "ANONYMIZE",
    "PRODUCT_TELEMETRY": "ANONYMIZE",
    "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE",
    "EMAIL_DELIVERY_LOG": "REDACT",
    "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN",
    "BACKUP_ARCHIVE": "RESTORE",
    "DATA_FLOW": "FLOW",
    "ACCOUNT_TOMBSTONE": "REDACT",
}

LINK_KEYS = PII_KEYS | {
    "user_id",
    "customer_reference",
    "subject_reference",
    "subject_ref",
    "lookup_key",
    "correlation_key",
    "subject_key",
    "owner_key",
    "match_key",
    "query",
    "subject_selector",
    "scan_key",
}


def parse_ts(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    match = TS_RE.search(value)
    if not match:
        return None
    return datetime.strptime(match.group(0), "%Y-%m-%dT%H:%M:%SZ")


def canon_system(name: str | None) -> str:
    if not name:
        return ""
    name = str(name).strip()
    return SYSTEM_ALIAS.get(name, name)


def meta_for_resource(resource_id: str) -> tuple[str, str]:
    for prefix, system, category in PREFIX_META:
        if resource_id.startswith(prefix):
            return system, category
    return "", ""

@dataclass
class Obs:
    file_id: str
    file_captured: datetime
    observed_at: datetime
    system_id: str
    resource_id: str
    category: str
    idents: set[str] = field(default_factory=set)
    exists: bool | None = None
    identifiable: bool | None = None
    anonymized: bool | None = None
    redacted: bool | None = None
    flow_enabled: bool | None = None
    restore_allowed: bool | None = None
    account_snapshot: bool = False


@dataclass
class Activity:
    activity_id: str
    event_time: datetime
    event_type: str
    target_system: str
    resource_id: str
    reported_result: str


@dataclass
class Catalog:
    users: dict
    token_users: dict[str, set[str]]
    observations: list[Obs]
    by_resource: dict[str, list[Obs]]
    activities: dict[str, list[Activity]]
    account_snapshot_ids: dict[str, set[str]]
    account_snapshot_time: dict[str, datetime]


def load_catalog() -> Catalog:
    users, token_users = load_identities()
    manifest = list(csv.DictReader((DATASET / "evidence_files.csv").open(encoding="utf-8")))
    observations: list[Obs] = []
    account_snapshot_ids: dict[str, set[str]] = {}
    account_snapshot_time: dict[str, datetime] = {}
    for row in manifest:
        file_id = row["file_id"]
        captured = parse_ts(row["captured_at"])
        if captured is None:
            continue
        path = DATASET / row["file_path"]
        suffix = path.suffix.lower()
        try:
            if suffix == ".json":
                observations.extend(parse_json_file(file_id, captured, path))
            elif suffix == ".sql":
                observations.extend(parse_sql_file(file_id, captured, path))
            elif suffix == ".log":
                observations.extend(parse_log_file(file_id, captured, path))
            elif suffix == ".txt":
                observations.extend(parse_text_file(file_id, captured, path))
            elif suffix == ".pdf":
                observations.extend(parse_pdf_file(file_id, captured, path))
            elif suffix == ".png":
                observations.extend(parse_screenshot_cache(file_id, captured))
        except Exception:
            continue
    by_resource: dict[str, list[Obs]] = defaultdict(list)
    for obs in observations:
        by_resource[obs.resource_id].append(obs)
        if obs.account_snapshot and obs.exists:
            account_snapshot_ids.setdefault(obs.file_id, set()).add(obs.resource_id)
            account_snapshot_time[obs.file_id] = obs.file_captured
    activities: dict[str, list[Activity]] = defaultdict(list)
    link_tokens: dict[str, set[str]] = defaultdict(set)
    link_pattern = re.compile(r"to\s+(\S+)\s+and\s+(user_\d+)", re.IGNORECASE)
    for row in csv.DictReader((DATASET / "system_activity.csv").open(encoding="utf-8")):
        when = parse_ts(row["event_time"])
        if when is None:
            continue
        activities[row["resource_id"]].append(
            Activity(
                row["activity_id"],
                when,
                row["event_type"],
                canon_system(row["target_system"]),
                row["resource_id"],
                row["reported_result"],
            )
        )
        if row["event_type"] == "LINK_RESOURCE_IDENTITY":
            bucket: set[str] = set()
            add_token(bucket, row["details"])
            matched = link_pattern.search(row["details"])
            if matched:
                add_token(bucket, matched.group(1))
                add_token(bucket, matched.group(2))
            if bucket:
                link_tokens[row["resource_id"]] |= bucket
    for obs in observations:
        extra = link_tokens.get(obs.resource_id)
        if extra and not obs.idents:
            obs.idents |= set(extra)
    return Catalog(
        users=users,
        token_users=token_users,
        observations=observations,
        by_resource=by_resource,
        activities=activities,
        account_snapshot_ids=account_snapshot_ids,
        account_snapshot_time=account_snapshot_time,
    )

def parse_json_file(file_id: str, captured: datetime, path: Path) -> list[Obs]:
    data = json.loads(path.read_text(encoding="utf-8"))
    found: list[Obs] = []
    walk_json(data, file_id, captured, captured, "", "", found)
    return found


def walk_json(node, file_id, captured, observed, system, category, found: list[Obs]) -> None:
    if isinstance(node, list):
        for item in node:
            walk_json(item, file_id, captured, observed, system, category, found)
        return
    if not isinstance(node, dict):
        return
    local_observed = parse_ts(node.get("observed_at") or node.get("captured_at") or node.get("recorded_at") or node.get("updated_at")) or observed
    local_system = canon_system(node.get("system") or node.get("data_store") or node.get("source_system")) or system
    collection = node.get("collection") or ""
    local_category = category
    if collection in COLLECTION_META:
        meta_system, meta_category = COLLECTION_META[collection]
        local_system = local_system or meta_system
        local_category = meta_category
    if "resource_id" in node and isinstance(node.get("resource_id"), str):
        found.append(obs_from_mapping(file_id, captured, local_observed, local_system, local_category, node))
    if "service_exports" in node and isinstance(node["service_exports"], dict):
        for service, body in node["service_exports"].items():
            walk_json(body, file_id, captured, local_observed, canon_system(service), local_category, found)
        rest = {k: v for k, v in node.items() if k != "service_exports"}
        for value in rest.values():
            if isinstance(value, (dict, list)):
                walk_json(value, file_id, captured, local_observed, local_system, local_category, found)
        return
    for key, value in node.items():
        if key in {"resource_id", "service_exports"}:
            continue
        if isinstance(value, (dict, list)):
            walk_json(value, file_id, captured, local_observed, local_system, local_category, found)


def obs_from_mapping(file_id, captured, observed, system, category, node: dict) -> Obs:
    resource_id = str(node["resource_id"])
    prefix_system, prefix_category = meta_for_resource(resource_id)
    system = canon_system(system) or prefix_system
    category = category or node.get("record_type") or prefix_category
    if isinstance(category, str):
        category = category.strip()
    else:
        category = prefix_category
    if category in {"USER_PROFILE", "SEARCH_INDEX_ENTRY"}:
        pass
    tokens: set[str] = set()
    collect_tokens(node, tokens)
    exists, identifiable, anonymized, redacted, flow_enabled, restore_allowed = flags_from_mapping(node, category, tokens)
    account_snapshot = category == "USER_PROFILE" and exists is True
    return Obs(
        file_id=file_id,
        file_captured=captured,
        observed_at=observed or captured,
        system_id=system,
        resource_id=resource_id,
        category=category or prefix_category,
        idents=tokens,
        exists=exists,
        identifiable=identifiable,
        anonymized=anonymized,
        redacted=redacted,
        flow_enabled=flow_enabled,
        restore_allowed=restore_allowed,
        account_snapshot=account_snapshot,
    )


def collect_tokens(node, tokens: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in LINK_KEYS or key in {"lookup_key", "correlation_key"}:
                add_token(tokens, value if isinstance(value, str) else None)
            elif isinstance(value, (dict, list)):
                collect_tokens(value, tokens)
            elif isinstance(value, str) and key in {"message_text", "message_excerpt", "subject_reference"}:
                add_token(tokens, value)
    elif isinstance(node, list):
        for item in node:
            collect_tokens(item, tokens)


def as_bool(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "enabled", "active", "hit", "found"}:
        return True
    if text in {"0", "false", "no", "disabled", "blocked", "miss", "not_found"}:
        return False
    return None


def flags_from_mapping(node: dict, category: str, tokens: set[str]) -> tuple:
    status = node.get("status_code")
    rows = node.get("rows")
    result = str(node.get("result") or node.get("account_status") or "").upper()
    exists: bool | None = True
    if status in {404, "404"} or rows in {0, "0"} or result in {"NOT_FOUND", "ABSENT", "MISSING"}:
        exists = False
    if node.get("profile") is None and "status_code" in node and status in {404, "404"}:
        exists = False
    if "download_available" in node:
        exists = bool(node.get("download_available"))
    identifiable = pii_present(node, category, tokens)
    anonymized = None
    redacted = None
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"} and exists:
        anonymized = not identifiable
    if result == "ANONYMIZED":
        anonymized = True
        identifiable = False
    if result == "REDACTED" or (isinstance(node.get("message_text"), str) and "[REDACTED]" in node["message_text"]):
        redacted = True
        identifiable = False
    if category == "ACCOUNT_TOMBSTONE" and exists:
        redacted = not identifiable
    if category == "SUPPORT_MESSAGE" and exists and not identifiable:
        redacted = True
    flow_enabled = None
    if "enabled" in node:
        flow_enabled = as_bool(node.get("enabled"))
    restore_allowed = None
    if "restore_allowed" in node:
        restore_allowed = as_bool(node.get("restore_allowed"))
    if result == "BLOCKED":
        restore_allowed = False
    if result == "ACTIVE" and category == "BACKUP_ARCHIVE":
        restore_allowed = True
    if result == "DISABLED" and category == "DATA_FLOW":
        flow_enabled = False
    if result == "IDENTIFIABLE":
        identifiable = True
        anonymized = False
        redacted = False
    return exists, identifiable, anonymized, redacted, flow_enabled, restore_allowed


def pii_present(node: dict, category: str, tokens: set[str]) -> bool:
    direct = False
    for key in ("email", "owner_email", "requester_email", "customer_email", "phone", "owner_phone", "requester_phone", "email_hash", "full_name", "name", "requester_name", "display_name"):
        value = node.get(key)
        if isinstance(value, str) and value.strip() and value.strip().lower() not in {"null", "none"}:
            direct = True
    profile = node.get("profile")
    if isinstance(profile, dict):
        direct = direct or pii_present(profile, category, tokens)
    document = node.get("document")
    if isinstance(document, dict):
        direct = direct or pii_present(document, category, tokens)
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY", "ACCOUNT_TOMBSTONE"}:
        for key in ("user_id", "customer_reference"):
            value = node.get(key)
            if isinstance(value, str) and value.startswith("user_"):
                direct = True
    if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
        return False
    if category == "ACCOUNT_TOMBSTONE":
        return direct
    return direct or any(token.startswith("tel:") or "@" in token or (len(token) == 64 and "user_" not in token) for token in tokens if category not in {"SECURITY_AUDIT_LOG"})


def parse_sql_file(file_id: str, captured: datetime, path: Path) -> list[Obs]:
    script = path.read_text(encoding="utf-8", errors="replace")
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(script)
    except sqlite3.DatabaseError:
        connection.close()
        return []
    found: list[Obs] = []
    tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for table in tables:
        if table.startswith("sqlite"):
            continue
        columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
        meta_system, meta_category = COLLECTION_META.get(table, ("", ""))
        account_snapshot = "profile" in table
        for values in connection.execute(f"SELECT * FROM {table}"):
            record = dict(zip(columns, values))
            payload = {}
            for key, value in list(record.items()):
                if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
                    try:
                        payload.update(json.loads(value))
                    except json.JSONDecodeError:
                        pass
            record.update(payload)
            resource_id = record.get("resource_id")
            if not isinstance(resource_id, str):
                continue
            system = canon_system(record.get("system") or record.get("source_system") or meta_system)
            category = record.get("record_type") or record.get("collection") or meta_category
            if category in COLLECTION_META:
                system, category = COLLECTION_META[category][0] or system, COLLECTION_META[category][1]
            if not system or not category:
                prefix_system, prefix_category = meta_for_resource(resource_id)
                system = system or prefix_system
                category = category if category in CATEGORY_ACTION else prefix_category
            observed = parse_ts(str(record.get("updated_at") or record.get("captured_at") or "")) or captured
            obs = obs_from_mapping(file_id, captured, observed, system, category if isinstance(category, str) else "", record)
            obs.account_snapshot = account_snapshot and obs.category == "USER_PROFILE" and obs.exists is True
            obs.exists = True if obs.exists is None else obs.exists
            found.append(obs)
    connection.close()
    return found


def parse_log_file(file_id: str, captured: datetime, path: Path) -> list[Obs]:
    traces: dict[str, list[dict]] = defaultdict(list)
    solo: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = parse_log_line(line)
        if not fields:
            continue
        trace = fields.get("trace_id") or fields.get("requestId")
        if trace and not str(trace).startswith("tr-"):
            trace = fields.get("trace_id")
        if trace:
            traces[trace].append(fields)
        elif fields.get("resource_id"):
            solo.append(fields)
    found: list[Obs] = []
    for parts in list(traces.values()) + [[item] for item in solo]:
        obs = obs_from_log_parts(file_id, captured, parts)
        if obs is not None:
            found.append(obs)
    return found


def parse_log_line(line: str) -> dict:
    fields: dict[str, str] = {}
    stamp = TS_RE.search(line)
    if stamp:
        fields["timestamp"] = stamp.group(0)
    brace = line.find("{")
    if brace >= 0 and "message=" not in line:
        try:
            payload = json.loads(line[brace:])
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            for key, value in payload.items():
                if isinstance(value, (str, int, float)):
                    fields[str(key)] = str(value)
            return fields
    # Cloud runtime lines store the real fields inside message="...\"key\"=\"value\"...".
    text = line.replace('\\"', '"')
    for match in KV_RE.finditer(text):
        fields[match.group(1)] = match.group(3) if match.group(3) is not None else match.group(4)
    if "service" not in fields and fields.get("function"):
        fields["service"] = fields["function"]
    if "trace_id" not in fields and str(fields.get("requestId", "")).startswith("tr-"):
        fields["trace_id"] = fields["requestId"]
    if "trace_id" not in fields:
        bare = re.search(r"\b(tr-[A-Za-z0-9-]+)\b", line)
        if bare:
            fields["trace_id"] = bare.group(1)
    return fields


def obs_from_log_parts(file_id: str, captured: datetime, parts: list[dict]) -> Obs | None:
    merged: dict[str, str] = {}
    for part in parts:
        merged.update(part)
    resource_id = merged.get("resource_id")
    if not resource_id or not RESOURCE_RE.fullmatch(resource_id):
        return None
    tokens: set[str] = set()
    for key in LINK_KEYS:
        add_token(tokens, merged.get(key))
    add_token(tokens, merged.get("matched_value"))
    observed = parse_ts(merged.get("timestamp")) or captured
    system = canon_system(merged.get("service") or merged.get("logger") or merged.get("system"))
    prefix_system, prefix_category = meta_for_resource(resource_id)
    system = system or prefix_system
    category = prefix_category
    event = (merged.get("event") or "").lower()
    if "contact" in event and resource_id.startswith("analytics"):
        category = "MARKETING_PROFILE"
    elif "attachment" in event and resource_id.startswith("support"):
        category = "SUPPORT_ATTACHMENT"
    elif "contact" in event and resource_id.startswith("support"):
        category = "SUPPORT_ATTACHMENT"
    elif "analytics" in event:
        category = "ANALYTICS_PROFILE"
    elif "restore" in event or "backup" in event:
        category = "BACKUP_ARCHIVE"
    elif "connector" in event or "heartbeat" in event or resource_id.startswith("data_flow"):
        category = "DATA_FLOW"
    elif "audit" in event:
        category = "SECURITY_AUDIT_LOG"
    elif "export" in event:
        category = "USER_EXPORT"
    elif "index" in event or "search" in event:
        category = "SEARCH_INDEX_ENTRY"
    elif "profile" in event or resource_id.startswith("account"):
        category = "USER_PROFILE"
    elif "message" in event or "support" in event:
        category = "SUPPORT_MESSAGE"
    exists: bool | None = None
    rows = merged.get("rows")
    status = merged.get("http_status")
    result = (merged.get("result") or "").lower()
    if rows == "0" or status == "404":
        exists = False
    elif (rows and rows != "0") or status == "200" or result == "hit":
        exists = True
    elif result == "not_found" and "cache" not in event:
        exists = False
    if exists is None and event.endswith("completed") and "cache" not in event:
        exists = True
    if merged.get("marker_found") == "false" and exists is None:
        exists = True
    identifiable = None
    anonymized = None
    redacted = None
    if merged.get("direct_identifiers") != "1" and (
        merged.get("direct_identifiers") == "0" or (
        merged.get("email") in {None, "null"} and merged.get("phone") in {None, "null"} and merged.get("email_hash") in {None, "null"} and category == "ANALYTICS_PROFILE"
        )
    ):
        if category == "ANALYTICS_PROFILE":
            identifiable = False
            anonymized = True
            exists = True if exists is None else exists
    if any(token for token in tokens if "@" in token or token.startswith("tel:") or (len(token) == 64)):
        if category not in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
            identifiable = True if anonymized is not True else identifiable
    if category == "SECURITY_AUDIT_LOG":
        identifiable = False
        if exists is None and merged.get("integrity_check") == "passed":
            exists = True
    flow_enabled = as_bool(merged.get("enabled"))
    restore_allowed = as_bool(merged.get("restore_allowed"))
    if merged.get("deletion_block") == "false" and merged.get("eligible") == "true":
        restore_allowed = True
        exists = True if exists is None else exists
    if merged.get("deletion_block") == "true":
        restore_allowed = False
    decision = (merged.get("decision") or "").lower()
    if decision == "deny":
        restore_allowed = False
        exists = True if exists is None else exists
    elif decision == "allow":
        restore_allowed = True
        exists = True if exists is None else exists
    if merged.get("message_text") == "[REDACTED]":
        redacted = True
        identifiable = False
    if exists is None and (identifiable or flow_enabled is not None or restore_allowed is not None):
        exists = True
    if exists is None:
        return None
    return Obs(
        file_id=file_id,
        file_captured=captured,
        observed_at=observed,
        system_id=system,
        resource_id=resource_id,
        category=category,
        idents=tokens,
        exists=exists,
        identifiable=identifiable,
        anonymized=anonymized,
        redacted=redacted,
        flow_enabled=flow_enabled,
        restore_allowed=restore_allowed,
        account_snapshot=False,
    )


def parse_text_file(file_id: str, captured: datetime, path: Path) -> list[Obs]:
    found: list[Obs] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 6:
            continue
        observed = parse_ts(parts[0]) or captured
        system = canon_system(parts[1])
        resource_id = parts[2]
        if not RESOURCE_RE.fullmatch(resource_id):
            continue
        category = parts[3]
        result = parts[4].upper()
        subject = parts[5]
        tokens: set[str] = set()
        add_token(tokens, subject)
        node = {
            "resource_id": resource_id,
            "record_type": category,
            "result": result,
            "subject_reference": subject,
        }
        obs = obs_from_mapping(file_id, captured, observed, system, category, node)
        obs.idents |= tokens
        if result == "NOT_FOUND":
            obs.exists = False
            obs.identifiable = False
        elif result == "ANONYMIZED":
            obs.exists = True
            obs.anonymized = True
            obs.identifiable = False
        elif result == "REDACTED":
            obs.exists = True
            obs.redacted = True
            obs.identifiable = False
        elif result == "FOUND":
            obs.exists = True
        elif result == "IDENTIFIABLE":
            obs.exists = True
            obs.identifiable = True
        elif result == "ACTIVE":
            obs.exists = True
            if category in {"DATA_FLOW"}:
                obs.flow_enabled = True
            if category in {"BACKUP_ARCHIVE"}:
                obs.restore_allowed = True
        elif result == "BLOCKED":
            obs.exists = True
            obs.restore_allowed = False
        elif result == "DISABLED":
            obs.exists = True
            obs.flow_enabled = False
        found.append(obs)
    return found


def parse_screenshot_cache(file_id: str, captured: datetime) -> list[Obs]:
    path = ROOT / "code" / "cache" / "screenshots" / f"{file_id}.json"
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    answer = payload.get("answer") or ""
    fenced = re.search(r"\{[\s\S]*\}", answer)
    if not fenced:
        return []
    try:
        records = json.loads(fenced.group(0)).get("records") or []
    except json.JSONDecodeError:
        return []
    found: list[Obs] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        resource_id = str(record.get("resource_id") or "")
        if not RESOURCE_RE.fullmatch(resource_id):
            continue
        tokens: set[str] = set()
        for email in record.get("emails") or []:
            add_token(tokens, email)
        for user_id in record.get("user_ids") or []:
            add_token(tokens, user_id)
        for phone in record.get("phones") or []:
            add_token(tokens, phone)
        if not tokens:
            continue
        system, category = meta_for_resource(resource_id)
        system = canon_system(record.get("system_id")) or system
        state = str(record.get("state") or "").lower()
        exists = False if state == "absent" else True
        identifiable = state not in {"anonymized", "redacted", "absent"}
        found.append(
            Obs(
                file_id=file_id,
                file_captured=captured,
                observed_at=captured,
                system_id=system,
                resource_id=resource_id,
                category=category,
                idents=tokens,
                exists=exists,
                identifiable=identifiable and exists,
                anonymized=state == "anonymized",
                redacted=state == "redacted",
                flow_enabled=True if state == "active" and category == "DATA_FLOW" else (False if state == "disabled" else None),
                restore_allowed=True if state == "active" and category == "BACKUP_ARCHIVE" else (False if state == "blocked" else None),
            )
        )
    return found


def parse_pdf_file(file_id: str, captured: datetime, path: Path) -> list[Obs]:
    try:
        from pypdf import PdfReader
    except ImportError:
        return []
    reader = PdfReader(str(path))
    text = "\n".join((page.extract_text() or "") for page in reader.pages)
    tokens: set[str] = set()
    add_token(tokens, text)
    resources = set(RESOURCE_RE.findall(text))
    found: list[Obs] = []
    for resource_id in resources:
        system, category = meta_for_resource(resource_id)
        if resource_id.startswith("support_"):
            category = "SUPPORT_ATTACHMENT"
        exists = True
        identifiable = any("@" in token or token.startswith("tel:") for token in tokens)
        if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
            identifiable = False
        found.append(
            Obs(
                file_id=file_id,
                file_captured=captured,
                observed_at=captured,
                system_id=system,
                resource_id=resource_id,
                category=category,
                idents=set(tokens),
                exists=exists,
                identifiable=identifiable,
                anonymized=False,
                redacted=False,
                account_snapshot=False,
            )
        )
    return found


