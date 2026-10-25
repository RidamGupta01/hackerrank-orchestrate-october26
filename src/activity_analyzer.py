"""Analyze identity-linked operations and data-recreation paths."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping

from src.evidence_models import (
    EvidenceIdentifier,
    EvidenceObservation,
    RecordState,
    TemporalBasis,
)
from src.evidence_parser import parse_timestamp
from src.identity_resolver import IdentityRelationship, IdentityResolution, ResolutionStatus

_ACTIVITY_COLUMNS = {
    "activity_id",
    "event_time",
    "event_type",
    "source_system",
    "target_system",
    "resource_id",
    "reported_result",
    "details",
}
_RULE_COLUMNS = {"rule_id", "data_category", "condition", "required_action"}
_EVENT_KINDS = {
    "DELETE_RECORD": "DELETION",
    "REDACT_RECORD": "REDACTION",
    "ANONYMIZE_RECORD": "ANONYMIZATION",
    "SYNC_RECORD": "SYNCHRONIZATION",
    "CREATE_EXPORT": "EXPORT",
    "INDEX_RECORD": "SEARCH_INDEXING",
    "REFRESH_CACHE": "CACHE_REFRESH",
    "RESTORE_BACKUP": "BACKUP_RESTORATION",
    "BLOCK_RESTORE": "RESTORE_BLOCK",
    "DISABLE_DATA_FLOW": "FLOW_DISABLE",
    "CHECK_DATA_FLOW": "FLOW_STATUS_CHECK",
    "CHECK_RESTORE_ACCESS": "RESTORE_ACCESS_CHECK",
    "RETAIN_RECORD": "RETENTION",
    "UPDATE_RECORD": "UPDATE",
    "SEND_EMAIL": "MESSAGE_DELIVERY",
    "CLASSIFY_REQUEST": "REQUEST_CLASSIFICATION",
    "LINK_RESOURCE_IDENTITY": "IDENTITY_RESOURCE_LINK",
}
_IDENTIFIER_FIELDS = {
    "email": "email",
    "phone": "phone",
    "email_hash": "email_hash",
    "user_id": "user_id",
    "name": "name",
}


class ProcessState(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    RESTORABLE = "RESTORABLE"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ActivityEvent:
    activity_id: str
    occurred_at: datetime
    event_type: str
    event_kind: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    result_is_claim: bool
    execution_stage: str
    reported_process_state: str | None
    process_state_is_claim: bool
    temporal_basis: TemporalBasis
    association_basis: tuple[str, ...]
    corroborating_file_ids: tuple[str, ...]
    association_activity_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "activity_id": self.activity_id,
            "occurred_at": _format_timestamp(self.occurred_at),
            "event_type": self.event_type,
            "event_kind": self.event_kind,
            "source_system": self.source_system,
            "target_system": self.target_system,
            "resource_id": self.resource_id,
            "reported_result": self.reported_result,
            "result_is_claim": self.result_is_claim,
            "execution_stage": self.execution_stage,
            "reported_process_state": self.reported_process_state,
            "process_state_is_claim": self.process_state_is_claim,
            "temporal_basis": self.temporal_basis.value,
            "association_basis": list(self.association_basis),
            "corroborating_file_ids": list(self.corroborating_file_ids),
            "association_activity_ids": list(self.association_activity_ids),
        }


@dataclass(frozen=True)
class ProcessAssessment:
    resource_id: str
    system_id: str | None
    process_kind: str
    state: ProcessState
    state_temporal_basis: TemporalBasis
    observed_at: datetime | None
    source_evidence_ids: tuple[str, ...]
    corroborating_activity_ids: tuple[str, ...]
    data_category: str | None
    policy_rule_id: str | None
    policy_action: str | None
    policy_condition: str | None
    can_recreate_data: bool | None
    observed_can_recreate_data: bool | None
    state_basis: str
    excluded_after_audit_evidence_ids: tuple[str, ...]
    latest_activity_claim: str | None
    latest_activity_id: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "resource_id": self.resource_id,
            "system_id": self.system_id,
            "process_kind": self.process_kind,
            "state": self.state.value,
            "state_temporal_basis": self.state_temporal_basis.value,
            "observed_at": _format_timestamp(self.observed_at),
            "source_evidence_ids": list(self.source_evidence_ids),
            "corroborating_activity_ids": list(self.corroborating_activity_ids),
            "data_category": self.data_category,
            "policy_rule_id": self.policy_rule_id,
            "policy_action": self.policy_action,
            "policy_condition": self.policy_condition,
            "can_recreate_data": self.can_recreate_data,
            "observed_can_recreate_data": self.observed_can_recreate_data,
            "state_basis": self.state_basis,
            "excluded_after_audit_evidence_ids": list(
                self.excluded_after_audit_evidence_ids
            ),
            "latest_activity_claim": self.latest_activity_claim,
            "latest_activity_id": self.latest_activity_id,
        }


@dataclass(frozen=True)
class ActivityReport:
    audit_at: datetime
    events: tuple[ActivityEvent, ...]
    processes: tuple[ProcessAssessment, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "audit_at": _format_timestamp(self.audit_at),
            "events": [event.to_dict() for event in self.events],
            "processes": [process.to_dict() for process in self.processes],
        }


@dataclass(frozen=True)
class _ActivityRow:
    activity_id: str
    occurred_at: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass(frozen=True)
class _PolicyRule:
    rule_id: str
    condition: str
    action: str


class ActivityAnalyzer:
    """Correlate activity to one confirmed subject and corroborating evidence.

    Activity result columns are retained as claims. A process is considered
    active/restorable/disabled/blocked only when a case-linked evidence record
    explicitly exposes its current state.
    """

    def __init__(
        self,
        activity: Iterable[Mapping[str, str]],
        *,
        policy_rules: Iterable[Mapping[str, str]] = (),
    ) -> None:
        self._activity = tuple(_parse_activity_row(row) for row in activity)
        self._rules = _parse_policy_rules(policy_rules)
        self._validate_activity_ids()

    @classmethod
    def from_csv(
        cls,
        activity_path: str | Path,
        *,
        rules_path: str | Path | None = None,
    ) -> ActivityAnalyzer:
        activity = _read_csv(activity_path, _ACTIVITY_COLUMNS)
        rules = _read_csv(rules_path, _RULE_COLUMNS) if rules_path else ()
        return cls(activity, policy_rules=rules)

    def analyze(
        self,
        identifiers: Iterable[EvidenceIdentifier | object],
        audit_at: str | datetime,
        *,
        evidence: Iterable[EvidenceObservation] = (),
    ) -> ActivityReport:
        cutoff = _parse_required_timestamp(audit_at, "audit_at")
        subject_identifiers = _normalize_identifiers(identifiers)
        evidence_records = tuple(evidence)
        linked_evidence = tuple(
            observation
            for observation in evidence_records
            if _evidence_matches_identifiers(observation, subject_identifiers)
        )
        evidence_by_resource: dict[str, list[EvidenceObservation]] = {}
        for observation in linked_evidence:
            if observation.resource_id:
                evidence_by_resource.setdefault(observation.resource_id, []).append(observation)

        relevant: list[ActivityEvent] = []
        activity_link_ids: dict[str, set[str]] = {}
        for row in self._activity:
            if row.event_type == "LINK_RESOURCE_IDENTITY" and _identifiers_in_text(
                row.details, subject_identifiers
            ):
                activity_link_ids.setdefault(row.resource_id, set()).add(row.activity_id)
        for row in self._activity:
            direct_identifiers = _identifiers_in_text(row.details, subject_identifiers)
            matching_evidence = evidence_by_resource.get(row.resource_id, [])
            linked_activity_ids = activity_link_ids.get(row.resource_id, set())
            if not direct_identifiers and not matching_evidence and not linked_activity_ids:
                continue
            association_basis: list[str] = []
            if direct_identifiers:
                association_basis.append("activity_details_identifier")
            if matching_evidence:
                association_basis.append("evidence_resource_identifier_correlation")
            if linked_activity_ids and not direct_identifiers and not matching_evidence:
                association_basis.append("activity_identity_link_claim")
            relevant.append(
                ActivityEvent(
                    activity_id=row.activity_id,
                    occurred_at=row.occurred_at,
                    event_type=row.event_type,
                    event_kind=_EVENT_KINDS.get(row.event_type, "OTHER"),
                    source_system=row.source_system,
                    target_system=row.target_system,
                    resource_id=row.resource_id,
                    reported_result=row.reported_result,
                    result_is_claim=True,
                    execution_stage=_execution_stage(row.details),
                    reported_process_state=_claimed_process_state(row),
                    process_state_is_claim=True,
                    temporal_basis=(
                        TemporalBasis.HISTORICAL
                        if row.occurred_at < cutoff
                        else TemporalBasis.AT_AUDIT
                        if row.occurred_at == cutoff
                        else TemporalBasis.AFTER_AUDIT
                    ),
                    association_basis=tuple(association_basis),
                    corroborating_file_ids=tuple(
                        sorted({item.source_evidence_id for item in matching_evidence})
                    ),
                    association_activity_ids=tuple(sorted(linked_activity_ids - {row.activity_id})),
                )
            )
        relevant.sort(key=lambda item: (item.occurred_at, item.activity_id))
        processes = self._assess_processes(
            cutoff,
            linked_evidence,
            tuple(relevant),
        )
        return ActivityReport(cutoff, tuple(relevant), processes)

    def analyze_resolution(
        self,
        resolution: IdentityResolution,
        *,
        evidence: Iterable[EvidenceObservation] = (),
    ) -> ActivityReport:
        if resolution.status is not ResolutionStatus.CONFIRMED:
            raise ValueError("activity analysis requires a confirmed identity resolution")
        return self.analyze(
            resolution.identity_relationships,
            resolution.audit_at,
            evidence=evidence,
        )

    def _assess_processes(
        self,
        cutoff: datetime,
        observations: tuple[EvidenceObservation, ...],
        events: tuple[ActivityEvent, ...],
    ) -> tuple[ProcessAssessment, ...]:
        activity_by_resource: dict[str, list[ActivityEvent]] = {}
        for event in events:
            activity_by_resource.setdefault(event.resource_id, []).append(event)

        observations_by_resource: dict[str, list[EvidenceObservation]] = {}
        for observation in observations:
            if observation.resource_id:
                observations_by_resource.setdefault(observation.resource_id, []).append(observation)

        processes: list[ProcessAssessment] = []
        process_resource_ids = set(observations_by_resource)
        process_resource_ids.update(
            event.resource_id
            for event in events
            if _event_may_describe_process(event.event_type)
        )
        for resource_id in process_resource_ids:
            records = observations_by_resource.get(resource_id, [])
            record = _latest_cutoff_observation(records, cutoff)
            state, process_kind = _current_process_state(record, resource_id)
            related_events = activity_by_resource.get(resource_id, [])
            if state is ProcessState.UNKNOWN and not related_events and not records:
                continue
            category = record.data_category if record else _category_for_resource(resource_id)
            rule = self._rules.get(category or "")
            if rule is None and resource_id.startswith("backup_"):
                rule = self._rules.get("BACKUP_ARCHIVE")
                category = category or ("BACKUP_ARCHIVE" if rule else None)
            state_temporal_basis = (
                _capture_temporal_basis(record.captured_at, cutoff)
                if record is not None
                else TemporalBasis.AFTER_AUDIT
                if records
                else TemporalBasis.UNKNOWN
            )
            observed_risk = _recreation_risk(state, process_kind)
            can_recreate = (
                observed_risk
                if state_temporal_basis is TemporalBasis.AT_AUDIT
                else None
            )
            excluded_future_ids = tuple(
                sorted({
                    item.source_evidence_id
                    for item in records
                    if item.captured_at > cutoff
                    or item.temporal_basis is TemporalBasis.AFTER_AUDIT
                    or (item.observed_at is not None and item.observed_at > cutoff)
                })
            )
            processes.append(
                ProcessAssessment(
                    resource_id=resource_id,
                    system_id=(record.system_id if record else None) or _system_for_resource(resource_id),
                    process_kind=process_kind,
                    state=state,
                    state_temporal_basis=state_temporal_basis,
                    observed_at=record.observed_at if record else None,
                    source_evidence_ids=tuple(
                        sorted({
                            item.source_evidence_id
                            for item in records
                            if item.captured_at <= cutoff
                            and item.temporal_basis is not TemporalBasis.AFTER_AUDIT
                            and (item.observed_at is None or item.observed_at <= cutoff)
                        })
                    ),
                    corroborating_activity_ids=tuple(
                        sorted({event.activity_id for event in related_events})
                    ),
                    data_category=category,
                    policy_rule_id=rule.rule_id if rule else None,
                    policy_action=rule.action if rule else None,
                    policy_condition=rule.condition if rule else None,
                    can_recreate_data=can_recreate,
                    observed_can_recreate_data=observed_risk,
                    state_basis=(
                        "case_linked_evidence_snapshot"
                        if record is not None and state is not ProcessState.UNKNOWN
                        else "no_cutoff_eligible_evidence"
                        if records
                        else "activity_claim_only"
                    ),
                    excluded_after_audit_evidence_ids=excluded_future_ids,
                    latest_activity_claim=_latest_claim(related_events, cutoff),
                    latest_activity_id=_latest_claim_event_id(related_events, cutoff),
                )
            )
        processes.sort(key=lambda item: (item.system_id, item.resource_id))
        return tuple(processes)

    def _validate_activity_ids(self) -> None:
        ids = [row.activity_id for row in self._activity]
        if len(ids) != len(set(ids)):
            raise ValueError("activity_id values must be unique")


def _read_csv(path: str | Path, required: set[str]) -> list[dict[str, str]]:
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None:
            raise ValueError(f"{path} is missing a CSV header")
        missing = required.difference(reader.fieldnames)
        if missing:
            raise ValueError(f"{path} is missing required columns: {', '.join(sorted(missing))}")
        return list(reader)


def _parse_activity_row(row: Mapping[str, str]) -> _ActivityRow:
    missing = _ACTIVITY_COLUMNS.difference(row)
    if missing:
        raise ValueError(f"activity row is missing fields: {', '.join(sorted(missing))}")
    required_values = {
        key: row[key].strip()
        for key in _ACTIVITY_COLUMNS
        if key != "details"
    }
    if any(not value for value in required_values.values()):
        raise ValueError("activity row contains an empty required field")
    occurred_at = _parse_required_timestamp(row["event_time"], "event_time")
    event_type = row["event_type"].strip()
    return _ActivityRow(
        activity_id=row["activity_id"].strip(),
        occurred_at=occurred_at,
        event_type=event_type,
        source_system=row["source_system"].strip(),
        target_system=row["target_system"].strip(),
        resource_id=row["resource_id"].strip(),
        reported_result=row["reported_result"].strip(),
        details=row["details"],
    )


def _claimed_process_state(row: _ActivityRow) -> str | None:
    if row.reported_result != "SUCCESS":
        return None
    details = row.details.casefold()
    if row.event_type == "CHECK_DATA_FLOW":
        if re.search(r"\bremains enabled\b|\bis enabled\b|\bflow is active\b", details):
            return ProcessState.ACTIVE.value
        if re.search(r"\bdisabled\b|\bstopped\b|\bnot enabled\b", details):
            return ProcessState.DISABLED.value
    if row.event_type == "CHECK_RESTORE_ACCESS":
        if re.search(r"\bcan still be restored\b|\brestore access (?:is )?enabled\b", details):
            return ProcessState.RESTORABLE.value
        if re.search(r"\brestore (?:is )?blocked\b|\baccess (?:is )?blocked\b", details):
            return ProcessState.BLOCKED.value
    if row.event_type == "DISABLE_DATA_FLOW":
        return ProcessState.DISABLED.value
    if row.event_type == "BLOCK_RESTORE":
        return ProcessState.BLOCKED.value
    return None


def _execution_stage(details: str) -> str:
    text = details.casefold()
    if re.search(r"\b(submitted|queued|requested|started|scheduled)\b", text):
        return "OPERATION_ATTEMPT"
    if re.search(r"\b(completed|received the final result|processed|confirmed)\b", text):
        return "RESULT_CLAIM"
    return "EVENT_CLAIM"


def _event_may_describe_process(event_type: str) -> bool:
    return event_type in {
        "CHECK_DATA_FLOW",
        "CHECK_RESTORE_ACCESS",
        "DISABLE_DATA_FLOW",
        "BLOCK_RESTORE",
        "RESTORE_BACKUP",
    }


def _latest_claim(
    events: list[ActivityEvent],
    cutoff: datetime,
) -> str | None:
    candidates = [
        event for event in events
        if event.occurred_at <= cutoff and event.reported_process_state is not None
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda event: (event.occurred_at, event.activity_id)).reported_process_state


def _latest_claim_event_id(
    events: list[ActivityEvent],
    cutoff: datetime,
) -> str | None:
    candidates = [
        event for event in events
        if event.occurred_at <= cutoff and event.reported_process_state is not None
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda event: (event.occurred_at, event.activity_id)).activity_id


def _parse_policy_rules(
    rows: Iterable[Mapping[str, str]],
) -> dict[str, _PolicyRule]:
    rules: dict[str, _PolicyRule] = {}
    for row in rows:
        missing = _RULE_COLUMNS.difference(row)
        if missing:
            raise ValueError(f"policy row is missing fields: {', '.join(sorted(missing))}")
        category = row["data_category"].strip()
        if not category or category in rules:
            raise ValueError("policy categories must be nonempty and unique")
        rules[category] = _PolicyRule(
            row["rule_id"].strip(),
            row["condition"].strip(),
            row["required_action"].strip(),
        )
    return rules


def _normalize_identifiers(
    identifiers: Iterable[EvidenceIdentifier | IdentityRelationship],
) -> tuple[EvidenceIdentifier, ...]:
    unique: dict[tuple[str, str], EvidenceIdentifier] = {}
    for item in identifiers:
        if isinstance(item, EvidenceIdentifier):
            identifier = item
        else:
            identifier = EvidenceIdentifier(item.identifier_type, item.identifier_value)
        kind = _IDENTIFIER_FIELDS.get(identifier.identifier_type.casefold())
        value = identifier.identifier_value.strip()
        if kind and value:
            unique[(kind, _normalize_value(value))] = EvidenceIdentifier(kind, value)
    return tuple(unique.values())


def _identifiers_in_text(
    text: str,
    identifiers: tuple[EvidenceIdentifier, ...],
) -> tuple[EvidenceIdentifier, ...]:
    matches: list[EvidenceIdentifier] = []
    for identifier in identifiers:
        if identifier.identifier_type == "phone":
            digits = re.sub(r"\D", "", identifier.identifier_value)
            if len(digits) >= 8 and re.search(
                r"(?<!\d)" + r"\D*".join(map(re.escape, digits)) + r"(?!\d)",
                text,
            ):
                matches.append(identifier)
                continue
        if identifier.identifier_type == "name":
            pattern = rf"(?<!\w){re.escape(identifier.identifier_value)}(?!\w)"
        else:
            pattern = rf"(?<![A-Za-z0-9]){re.escape(identifier.identifier_value)}(?![A-Za-z0-9])"
        if re.search(pattern, text, flags=re.IGNORECASE):
            matches.append(identifier)
    return tuple(matches)


def _evidence_matches_identifiers(
    observation: EvidenceObservation,
    identifiers: tuple[EvidenceIdentifier, ...],
) -> bool:
    target_values = {
        (identifier.identifier_type, _normalize_value(identifier.identifier_value))
        for identifier in identifiers
    }
    return any(
        (found.identifier_type, _normalize_value(found.identifier_value)) in target_values
        for found in observation.identifiers_found
    )


def _latest_cutoff_observation(
    records: list[EvidenceObservation],
    cutoff: datetime,
) -> EvidenceObservation | None:
    eligible = [
        item
        for item in records
        if item.captured_at <= cutoff
        and item.temporal_basis is not TemporalBasis.AFTER_AUDIT
        and (item.observed_at is None or item.observed_at <= cutoff)
    ]
    if not eligible:
        return None
    return max(
        eligible,
        key=lambda item: (
            item.captured_at,
            item.observed_at or item.captured_at,
            item.source_evidence_id,
        ),
    )


def _current_process_state(
    observation: EvidenceObservation | None,
    resource_id: str,
) -> tuple[ProcessState, str]:
    if observation is None:
        if resource_id.startswith("backup_"):
            return ProcessState.UNKNOWN, "RESTORE_PATH"
        if resource_id.startswith("data_flow_"):
            return ProcessState.UNKNOWN, "DATA_FLOW"
        return ProcessState.UNKNOWN, "UNKNOWN"
    category = (observation.data_category or "").upper()
    text = " ".join(str(value) for value in observation.attributes.values()).casefold()
    resource = (observation.resource_id or "").casefold()
    if category == "BACKUP_ARCHIVE" or resource.startswith("backup_"):
        process_kind = "RESTORE_PATH"
        value = _observation_boolean(observation, "restore_allowed", text)
        if value is True:
            return ProcessState.RESTORABLE, process_kind
        if value is False:
            return ProcessState.BLOCKED, process_kind
        if observation.state is RecordState.PRESENT:
            return ProcessState.UNKNOWN, process_kind
        return ProcessState.UNKNOWN, process_kind
    if resource.startswith("data_flow_") or "connector" in category.casefold():
        process_kind = "DATA_FLOW"
        value = _observation_boolean(observation, "enabled", text)
        if value is True:
            return ProcessState.ACTIVE, process_kind
        if value is False:
            return ProcessState.DISABLED, process_kind
        return ProcessState.UNKNOWN, process_kind
    return ProcessState.UNKNOWN, "OTHER"


def _recreation_risk(
    state: ProcessState,
    process_kind: str,
) -> bool | None:
    if process_kind == "RESTORE_PATH":
        return state is ProcessState.RESTORABLE if state is not ProcessState.UNKNOWN else None
    if process_kind == "DATA_FLOW":
        return state is ProcessState.ACTIVE if state is not ProcessState.UNKNOWN else None
    return None


def _capture_temporal_basis(captured_at: datetime, cutoff: datetime) -> TemporalBasis:
    if captured_at == cutoff:
        return TemporalBasis.AT_AUDIT
    return TemporalBasis.HISTORICAL if captured_at < cutoff else TemporalBasis.AFTER_AUDIT


def _observation_boolean(
    observation: EvidenceObservation,
    field: str,
    text: str,
) -> bool | None:
    value = observation.attributes.get(field)
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "1", "yes", "enabled", "active", "allowed", "restorable"}:
            return True
        if normalized in {"false", "0", "no", "disabled", "inactive", "blocked", "denied"}:
            return False
    patterns = (
        rf"\b{field}\b\s*[:=]\s*[\"']?(true|1|yes|enabled|active|allowed|restorable)\b",
        rf"\b{field}\b\s*[:=]\s*[\"']?(false|0|no|disabled|inactive|blocked|denied)\b",
    )
    if re.search(patterns[0], text):
        return True
    if re.search(patterns[1], text):
        return False
    if field == "enabled" and re.search(r"\bremains enabled\b|\bflow is active\b", text):
        return True
    if field == "enabled" and re.search(r"\bdisabled\b|\bnot enabled\b|\bstopped\b", text):
        return False
    if field == "restore_allowed" and re.search(r"\bcan still be restored\b|\brestore allowed\b", text):
        return True
    if field == "restore_allowed" and re.search(r"\brestore (?:is )?blocked\b|\brestore access blocked\b", text):
        return False
    return None


def _category_for_resource(resource_id: str) -> str | None:
    if resource_id.startswith("backup_"):
        return "BACKUP_ARCHIVE"
    return None


def _system_for_resource(resource_id: str) -> str | None:
    if resource_id.startswith("backup_"):
        return "backup_service"
    if resource_id.startswith("data_flow_"):
        return "integration_service"
    return None


def _normalize_value(value: str) -> str:
    return re.sub(r"[\s()\-]", "", value).casefold()


def _parse_required_timestamp(value: str | datetime, field_name: str) -> datetime:
    parsed = parse_timestamp(value.isoformat() if isinstance(value, datetime) else value)
    if parsed is None:
        raise ValueError(f"{field_name} must be a timezone-aware ISO-8601 timestamp")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
