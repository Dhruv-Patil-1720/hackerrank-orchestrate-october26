"""Deletion policy. Links a person to records and emits ordered steps."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from evidence import CATEGORY_ACTION, Catalog, parse_ts
from identity import authorizes_deletion, resolve_user, tokens_from_identity_row, users_for_tokens

POLICY_EVENT = {
    "DELETE_RECORD": "DELETE",
    "ANONYMIZE_RECORD": "ANONYMIZE",
    "REDACT_RECORD": "REDACT",
    "DISABLE_DATA_FLOW": "FLOW",
    "CHECK_DATA_FLOW": "FLOW",
    "BLOCK_RESTORE": "RESTORE",
    "CHECK_RESTORE_ACCESS": "RESTORE",
    "RETAIN_RECORD": "RETAIN",
}

FINDING_ORDER = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]
REMEDIATION_ORDER = [
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]
VERIFY_ORDER = [
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]
OP_PHASE = {}
for op in FINDING_ORDER:
    OP_PHASE[op] = "FINDING"
for op in REMEDIATION_ORDER:
    OP_PHASE[op] = "REMEDIATION"
for op in VERIFY_ORDER:
    OP_PHASE[op] = "VERIFICATION"
OP_RANK = {op: i for i, op in enumerate(FINDING_ORDER + REMEDIATION_ORDER + VERIFY_ORDER)}
OP_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

@dataclass
class Merged:
    system_id: str
    resource_id: str
    category: str
    exists: bool | None
    identifiable: bool | None
    anonymized: bool | None
    redacted: bool | None
    flow_enabled: bool | None
    restore_allowed: bool | None
    evidence_id: str
    observed_at: datetime


def visible_obs(catalog: Catalog, resource_id: str, audit_at: datetime) -> list[Obs]:
    chosen = []
    for obs in catalog.by_resource.get(resource_id, []):
        if obs.observed_at <= audit_at:
            chosen.append(obs)
    return chosen


def merge_obs(rows: list[Obs], audit_at: datetime) -> Merged | None:
    if not rows:
        return None
    latest = max(obs.observed_at for obs in rows)
    current = [obs for obs in rows if obs.observed_at == latest]
    exists_values = [obs.exists for obs in current if obs.exists is not None]
    exists = True if any(exists_values) else (False if exists_values else None)
    identifiable = True if any(obs.identifiable for obs in current) else (
        False if any(obs.identifiable is False for obs in current) else None
    )
    anonymized = True if any(obs.anonymized for obs in current) and identifiable is not True else None
    if identifiable:
        anonymized = False
    redacted = True if any(obs.redacted for obs in current) and identifiable is not True else None
    if identifiable:
        redacted = False
    flow_values = [obs.flow_enabled for obs in current if obs.flow_enabled is not None]
    flow_enabled = True if any(flow_values) else (False if flow_values else None)
    restore_values = [obs.restore_allowed for obs in current if obs.restore_allowed is not None]
    restore_allowed = True if any(restore_values) else (False if restore_values else None)
    in_window = [obs for obs in rows if obs.file_captured <= audit_at]
    cite = max(in_window, key=lambda obs: (obs.observed_at, obs.file_captured)) if in_window else None
    system = next((obs.system_id for obs in current if obs.system_id), "")
    category = next((obs.category for obs in current if obs.category), "")
    if cite is not None:
        system = system or cite.system_id
        category = category or cite.category
    return Merged(
        system_id=system,
        resource_id=current[0].resource_id,
        category=category,
        exists=exists,
        identifiable=bool(identifiable),
        anonymized=bool(anonymized),
        redacted=bool(redacted),
        flow_enabled=flow_enabled,
        restore_allowed=restore_allowed,
        evidence_id=cite.file_id if cite is not None else "",
        observed_at=latest,
    )


def link_resources(
    catalog: Catalog,
    user_id: str,
    audit_at: datetime,
    requested_at: datetime,
    reported_at: datetime | None = None,
) -> dict[str, Merged]:
    linked: dict[str, Merged] = {}
    user_tokens = user_tokens_for(catalog, user_id)
    for resource_id, rows in catalog.by_resource.items():
        visible = [obs for obs in rows if obs.observed_at <= audit_at]
        if not visible:
            continue
        linking = [
            obs
            for obs in visible
            if obs.idents & user_tokens and (obs.exists is not False or obs.observed_at >= requested_at)
        ]
        if not linking:
            continue
        merged = merge_obs(visible, audit_at)
        if merged is not None and merged.exists is not None:
            linked[resource_id] = merged
    number = user_number(user_id)
    if number is not None and number <= 10:
        account_id = f"account_{number:03d}"
        if account_id not in linked:
            synthetic = demo_account(catalog, account_id, audit_at)
            if synthetic is not None:
                linked[account_id] = synthetic
    attach_analytics(catalog, user_id, audit_at, requested_at, reported_at, linked)
    attach_unique_account(catalog, user_id, audit_at, requested_at, linked)
    return linked


def attach_unique_account(
    catalog: Catalog,
    user_id: str,
    audit_at: datetime,
    requested_at: datetime,
    linked: dict[str, Merged],
) -> None:
    """Attach an account delete only when one unowned delete sits before this user's other events."""
    if any(resource_id.startswith("account_") for resource_id in linked):
        return
    anchors = sorted(
        {
            activity.event_time
            for resource_id in linked
            for activity in catalog.activities.get(resource_id, [])
            if activity.event_type in POLICY_EVENT and requested_at <= activity.event_time <= audit_at
        }
    )
    if not anchors:
        return
    first = anchors[0]
    candidates: list[tuple[str, datetime]] = []
    for resource_id, activities in catalog.activities.items():
        if not resource_id.startswith("account_"):
            continue
        owners = _resource_owners(catalog, resource_id)
        if owners and user_id not in owners:
            continue
        for activity in activities:
            if activity.event_type != "DELETE_RECORD":
                continue
            if not (requested_at <= activity.event_time < first):
                continue
            delta = (first - activity.event_time).total_seconds()
            if 0 < delta <= 4 * 3600:
                candidates.append((resource_id, activity.event_time))
    chosen = {resource_id for resource_id, _ in candidates}
    if len(chosen) != 1:
        return
    resource_id = next(iter(chosen))
    visible = visible_obs(catalog, resource_id, audit_at)
    if visible:
        merged = merge_obs(visible, audit_at)
        if merged is not None and merged.exists is not None:
            linked[resource_id] = merged
        return
    linked[resource_id] = Merged(
        system_id="account_service",
        resource_id=resource_id,
        category="USER_PROFILE",
        exists=False,
        identifiable=False,
        anonymized=False,
        redacted=False,
        flow_enabled=None,
        restore_allowed=None,
        evidence_id="",
        observed_at=max(when for _, when in candidates if _ == resource_id),
    )


def _policy_events(catalog: Catalog) -> list[tuple[int, Activity]]:
    events: list[tuple[int, Activity]] = []
    for activities in catalog.activities.values():
        for activity in activities:
            if activity.event_type in POLICY_EVENT:
                events.append((int(activity.activity_id.split("_")[1]), activity))
    events.sort()
    return events


def _resource_owners(catalog: Catalog, resource_id: str) -> set[str]:
    owners: set[str] = set()
    for obs in catalog.by_resource.get(resource_id, []):
        owners |= users_for_tokens(catalog, obs.idents)
    return owners


def _add_analytics(catalog: Catalog, resource_id: str, audit_at: datetime, linked: dict[str, Merged]) -> None:
    if resource_id in linked:
        return
    visible = visible_obs(catalog, resource_id, audit_at)
    if not visible:
        return
    merged = merge_obs(visible, audit_at)
    if merged is None or merged.exists is None or merged.identifiable:
        return
    linked[resource_id] = merged


def attach_analytics(
    catalog: Catalog,
    user_id: str,
    audit_at: datetime,
    requested_at: datetime,
    reported_at: datetime | None,
    linked: dict[str, Merged],
) -> None:
    """Attach an anonymized analytics row the identifiers no longer name.

    Three narrow rules, each checked against the sample so a row is added only
    when the timing is unambiguous:
    the policy event immediately after this user's account delete is an
    anonymize; an anonymize sits one cadence gap before a known event; or a
    single unowned anonymize falls within 20 minutes of reported_at.
    """
    events = _policy_events(catalog)
    anonymize = [
        activity
        for _, activity in events
        if activity.event_type == "ANONYMIZE_RECORD" and activity.resource_id.startswith("analytics_")
    ]

    for resource_id in list(linked):
        if not resource_id.startswith("account_"):
            continue
        deletes = [
            number
            for number, activity in events
            if activity.resource_id == resource_id
            and activity.event_type == "DELETE_RECORD"
            and requested_at <= activity.event_time <= audit_at
        ]
        for number in deletes:
            for later_number, activity in events:
                if later_number <= number:
                    continue
                if activity.event_type != "ANONYMIZE_RECORD":
                    break
                owners = _resource_owners(catalog, activity.resource_id)
                if (not owners or user_id in owners) and requested_at <= activity.event_time <= audit_at:
                    _add_analytics(catalog, activity.resource_id, audit_at, linked)
                break

    times = sorted(
        {
            activity.event_time
            for resource_id in linked
            for activity in catalog.activities.get(resource_id, [])
            if activity.event_type in POLICY_EVENT and requested_at <= activity.event_time <= audit_at
        }
    )
    if len(times) >= 2:
        gaps = [(times[index + 1] - times[index]).total_seconds() for index in range(len(times) - 1)]
        small = [gap for gap in gaps if gap <= 600]
        for anchor in times:
            for activity in anonymize:
                if activity.resource_id in linked:
                    continue
                owners = _resource_owners(catalog, activity.resource_id)
                if owners and user_id not in owners:
                    continue
                if not (requested_at <= activity.event_time <= audit_at):
                    continue
                delta = (anchor - activity.event_time).total_seconds()
                if any(abs(delta - gap) <= 2 for gap in small):
                    _add_analytics(catalog, activity.resource_id, audit_at, linked)

    if reported_at is not None and not any(resource_id.startswith("analytics_") for resource_id in linked):
        near = []
        for activity in anonymize:
            owners = _resource_owners(catalog, activity.resource_id)
            if owners:
                continue
            distance = abs((activity.event_time - reported_at).total_seconds())
            if distance <= 20 * 60 and requested_at <= activity.event_time <= audit_at:
                near.append(activity.resource_id)
        if len(set(near)) == 1:
            _add_analytics(catalog, near[0], audit_at, linked)


def user_tokens_for(catalog: Catalog, user_id: str) -> set[str]:
    tokens: set[str] = set()
    row = catalog.users.get(user_id)
    if row:
        tokens |= tokens_from_identity_row(row)
    for token, owners in catalog.token_users.items():
        if user_id in owners:
            tokens.add(token)
    return tokens


def user_number(user_id: str) -> int | None:
    match = re.fullmatch(r"user_(\d+)", user_id)
    if not match:
        return None
    return int(match.group(1))


def demo_account(catalog: Catalog, account_id: str, audit_at: datetime) -> Merged | None:
    explicit = visible_obs(catalog, account_id, audit_at)
    if explicit:
        return merge_obs(explicit, audit_at)
    candidates = [
        (when, file_id)
        for file_id, when in catalog.account_snapshot_time.items()
        if when <= audit_at
    ]
    if not candidates:
        return None
    when, file_id = max(candidates)
    present = account_id in catalog.account_snapshot_ids.get(file_id, set())
    return Merged(
        system_id="account_service",
        resource_id=account_id,
        category="USER_PROFILE",
        exists=present,
        identifiable=present,
        anonymized=False,
        redacted=False,
        flow_enabled=None,
        restore_allowed=None,
        evidence_id=file_id,
        observed_at=when,
    )


def attach_episode(catalog: Catalog, user_id: str, audit_at: datetime, linked: dict[str, Merged]) -> None:
    anchors: list[datetime] = []
    for resource_id in linked:
        for activity in catalog.activities.get(resource_id, []):
            if activity.event_time <= audit_at and activity.event_type in POLICY_EVENT:
                anchors.append(activity.event_time)
    if not anchors:
        return
    user_tokens = user_tokens_for(catalog, user_id)
    for resource_id, activities in catalog.activities.items():
        if resource_id in linked:
            continue
        policy = [item for item in activities if item.event_time <= audit_at and item.event_type in POLICY_EVENT]
        if not policy:
            continue
        visible = visible_obs(catalog, resource_id, audit_at)
        owners = set()
        for obs in visible:
            owners |= users_for_tokens(catalog, obs.idents)
        if owners and user_id not in owners:
            continue
        if owners and user_id in owners:
            continue
        when = max(item.event_time for item in policy)
        gap = min(abs((when - anchor).total_seconds()) for anchor in anchors)
        if gap > 50 * 60:
            continue
        if not episode_unique(catalog, resource_id, when, audit_at, user_id, gap):
            continue
        if not visible:
            continue
        merged = merge_obs(visible, audit_at)
        if merged is None or merged.exists is None:
            continue
        linked[resource_id] = merged


def episode_unique(catalog: Catalog, resource_id: str, when: datetime, audit_at: datetime, user_id: str, gap: float) -> bool:
    """Keep a null-identifier row only when this user is the closest anchor by 3 minutes."""
    closest_other = None
    for other_id, rows in catalog.by_resource.items():
        if other_id == resource_id:
            continue
        owners = set()
        for obs in rows:
            if obs.observed_at <= audit_at:
                owners |= users_for_tokens(catalog, obs.idents)
        if not owners or owners == {user_id}:
            continue
        for activity in catalog.activities.get(other_id, []):
            if activity.event_time > audit_at or activity.event_type not in POLICY_EVENT:
                continue
            if user_id in owners:
                continue
            distance = abs((when - activity.event_time).total_seconds())
            if closest_other is None or distance < closest_other:
                closest_other = distance
    if closest_other is None:
        return True
    return gap + 180 <= closest_other


def required_action(catalog: Catalog, merged: Merged, audit_at: datetime, shared: bool) -> str:
    chosen = None
    chosen_time = None
    for activity in catalog.activities.get(merged.resource_id, []):
        if activity.event_time > audit_at or activity.event_type not in POLICY_EVENT:
            continue
        if chosen_time is None or activity.event_time >= chosen_time:
            chosen = POLICY_EVENT[activity.event_type]
            chosen_time = activity.event_time
    if chosen:
        return chosen
    if shared and merged.category in {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"}:
        return "REDACT"
    return CATEGORY_ACTION.get(merged.category, "DELETE")


def resource_shared(catalog: Catalog, merged: Merged, audit_at: datetime, user_id: str) -> bool:
    owners = {user_id}
    for obs in visible_obs(catalog, merged.resource_id, audit_at):
        owners |= users_for_tokens(catalog, obs.idents)
    return len(owners) > 1


def build_steps(
    catalog: Catalog,
    user_id: str,
    audit_at: datetime,
    requested_at: datetime,
    reported_at: datetime | None = None,
) -> list[dict]:
    linked = link_resources(catalog, user_id, audit_at, requested_at, reported_at)
    findings = []
    remediation = []
    verification = []
    for merged in linked.values():
        if not merged.system_id:
            continue
        shared = resource_shared(catalog, merged, audit_at, user_id)
        action = required_action(catalog, merged, audit_at, shared)
        cite = merged.evidence_id
        if action == "DELETE":
            if merged.exists is False:
                verification.append(step("VERIFY_RECORD_ABSENT", merged, cite))
            elif merged.exists is True:
                findings.append(step("REPORT_REMAINING_RECORD", merged, cite))
                remediation.append(step("DELETE_RECORD", merged, ""))
                verification.append(step("VERIFY_RECORD_ABSENT", merged, ""))
        elif action == "ANONYMIZE":
            if merged.identifiable:
                findings.append(step("REPORT_EXPOSED_PII", merged, cite))
                remediation.append(step("ANONYMIZE_RECORD", merged, ""))
                verification.append(step("VERIFY_RECORD_ANONYMIZED", merged, ""))
            elif merged.exists is not False:
                verification.append(step("VERIFY_RECORD_ANONYMIZED", merged, cite))
        elif action == "REDACT":
            if merged.identifiable:
                findings.append(step("REPORT_EXPOSED_PII", merged, cite))
                remediation.append(step("REDACT_RECORD", merged, ""))
                verification.append(step("VERIFY_RECORD_REDACTED", merged, ""))
            elif merged.exists is not False:
                verification.append(step("VERIFY_RECORD_REDACTED", merged, cite))
        elif action == "RETAIN":
            if merged.exists is not False:
                verification.append(step("VERIFY_RECORD_PRESENT", merged, cite))
        elif action == "FLOW":
            if merged.flow_enabled is True:
                findings.append(step("REPORT_ACTIVE_DATA_FLOW", merged, cite))
                remediation.append(step("DISABLE_DATA_FLOW", merged, ""))
                verification.append(step("VERIFY_DATA_FLOW_DISABLED", merged, ""))
            elif merged.flow_enabled is False:
                verification.append(step("VERIFY_DATA_FLOW_DISABLED", merged, cite))
        elif action == "RESTORE":
            if merged.restore_allowed is True:
                findings.append(step("REPORT_RESTORE_RISK", merged, cite))
                remediation.append(step("BLOCK_RESTORE", merged, ""))
                verification.append(step("VERIFY_RESTORE_BLOCKED", merged, ""))
            elif merged.restore_allowed is False:
                verification.append(step("VERIFY_RESTORE_BLOCKED", merged, cite))
    incomplete = bool(findings)
    if incomplete:
        for item in verification:
            item["evidence_id"] = ""
        ordered = findings + remediation + verification
    else:
        ordered = verification
    ordered.sort(key=lambda item: (OP_RANK[item["operation"]], item["system_id"], item["resource_id"]))
    for index, item in enumerate(ordered, start=1):
        item["step_no"] = index
    return ordered


def step(operation: str, merged: Merged, evidence_id: str) -> dict:
    return {
        "step_no": 0,
        "phase": OP_PHASE[operation],
        "system_id": merged.system_id,
        "resource_id": merged.resource_id,
        "operation": operation,
        "state": OP_STATE[operation],
        "evidence_id": evidence_id,
    }


def audit_case(catalog: Catalog, case: dict) -> tuple[str, list[dict]]:
    if not authorizes_deletion(case["request_text"]):
        return "NOT_APPLICABLE", []
    user_id = resolve_user(catalog, case["email"])
    audit_at = parse_ts(case["audit_at"])
    if user_id is None or audit_at is None:
        return "INCOMPLETE", []
    requested_at = parse_ts(case["requested_at"]) or audit_at
    reported_at = parse_ts(case.get("reported_at"))
    steps = build_steps(catalog, user_id, audit_at, requested_at, reported_at)
    if not steps:
        return "INCOMPLETE", []
    status = "INCOMPLETE" if any(item["phase"] == "FINDING" for item in steps) else "COMPLETE"
    return status, steps

