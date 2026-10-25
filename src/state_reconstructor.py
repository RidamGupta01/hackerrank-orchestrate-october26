"""Reconstruct auditable record and process state at a request cutoff."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Mapping

from src.activity_analyzer import ActivityReport, ProcessAssessment, ProcessState
from src.evidence_models import (
    EvidenceObservation,
    RecordState,
    TemporalBasis,
)
from src.evidence_parser import parse_timestamp
from src.identity_resolver import IdentityResolution, ResolutionStatus
from src.policy_engine import (
    ConditionOutcome,
    PolicyAction,
    PolicyDecision,
    PolicyEngine,
)


class DeletionAuthorization(str, Enum):
    REQUESTED = "REQUESTED"
    NOT_REQUESTED = "NOT_REQUESTED"
    UNKNOWN = "UNKNOWN"


class AuditStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ConditionStatus(str, Enum):
    SATISFIED = "SATISFIED"
    FAILED = "FAILED"
    UNRESOLVED = "UNRESOLVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class AuthorizationAssessment:
    outcome: DeletionAuthorization
    evidence_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class MandatoryCondition:
    condition_id: str
    status: ConditionStatus
    reason: str
    system_id: str | None
    resource_id: str | None
    data_category: str | None
    source_evidence_ids: tuple[str, ...]
    source_activity_ids: tuple[str, ...]
    policy_rule_id: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "condition_id": self.condition_id,
            "status": self.status.value,
            "reason": self.reason,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "data_category": self.data_category,
            "source_evidence_ids": list(self.source_evidence_ids),
            "source_activity_ids": list(self.source_activity_ids),
            "policy_rule_id": self.policy_rule_id,
        }


@dataclass(frozen=True)
class ReconstructedResource:
    system_id: str | None
    resource_id: str
    data_category: str | None
    state: RecordState
    state_temporal_basis: TemporalBasis
    identifiers_present: tuple[str, ...]
    source_evidence_ids: tuple[str, ...]
    source_locations: tuple[str, ...]
    conflict: bool
    policy_decision: PolicyDecision

    def to_dict(self) -> dict[str, object]:
        return {
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "data_category": self.data_category,
            "state": self.state.value,
            "state_temporal_basis": self.state_temporal_basis.value,
            "identifiers_present": list(self.identifiers_present),
            "source_evidence_ids": list(self.source_evidence_ids),
            "source_locations": list(self.source_locations),
            "conflict": self.conflict,
            "policy_decision": self.policy_decision.to_dict(),
        }


@dataclass(frozen=True)
class StateReconstruction:
    status: AuditStatus
    audit_at: datetime
    authorization: AuthorizationAssessment
    resources: tuple[ReconstructedResource, ...]
    processes: tuple[ProcessAssessment, ...]
    mandatory_conditions: tuple[MandatoryCondition, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "audit_at": _format_timestamp(self.audit_at),
            "authorization": {
                "outcome": self.authorization.outcome.value,
                "evidence_ids": list(self.authorization.evidence_ids),
                "reason": self.authorization.reason,
            },
            "resources": [item.to_dict() for item in self.resources],
            "processes": [item.to_dict() for item in self.processes],
            "mandatory_conditions": [
                item.to_dict() for item in self.mandatory_conditions
            ],
        }


class StateReconstructor:
    """Combine identity, policy, observations, and activity without guessing."""

    def __init__(self, policy_engine: PolicyEngine) -> None:
        self.policy_engine = policy_engine

    def reconstruct(
        self,
        identity: IdentityResolution,
        evidence: Iterable[EvidenceObservation],
        activity: ActivityReport,
        authorization: AuthorizationAssessment,
        *,
        policy_facts_by_resource: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> StateReconstruction:
        cutoff = _parse_timestamp(identity.audit_at)
        if activity.audit_at != cutoff:
            raise ValueError("activity report audit_at does not match identity resolution")

        conditions: list[MandatoryCondition] = []
        if authorization.outcome is DeletionAuthorization.NOT_REQUESTED:
            if not authorization.evidence_ids:
                conditions.append(
                    _condition(
                        "authorization_evidence",
                        ConditionStatus.UNRESOLVED,
                        "Non-deletion authorization was asserted without provenance.",
                    )
                )
                return self._result(
                    AuditStatus.INCOMPLETE,
                    cutoff,
                    authorization,
                    (),
                    (),
                    conditions,
                )
            return self._result(
                AuditStatus.NOT_APPLICABLE,
                cutoff,
                authorization,
                (),
                (),
                (
                    _condition(
                        "deletion_authorization",
                        ConditionStatus.SATISFIED,
                        "Evidence establishes that deletion was not requested.",
                        evidence_ids=authorization.evidence_ids,
                    ),
                ),
            )
        if authorization.outcome is DeletionAuthorization.UNKNOWN:
            conditions.append(
                _condition(
                    "deletion_authorization",
                    ConditionStatus.UNRESOLVED,
                    authorization.reason or "Request authorization is not established.",
                    evidence_ids=authorization.evidence_ids,
                )
            )
        elif authorization.outcome is DeletionAuthorization.REQUESTED:
            conditions.append(
                _condition(
                    "deletion_authorization",
                    ConditionStatus.SATISFIED
                    if authorization.evidence_ids
                    else ConditionStatus.UNRESOLVED,
                    authorization.reason
                    if authorization.evidence_ids
                    else "Deletion authorization was asserted without provenance.",
                    evidence_ids=authorization.evidence_ids,
                )
            )

        if identity.status is not ResolutionStatus.CONFIRMED:
            conditions.append(
                _condition(
                    "identity_resolution",
                    ConditionStatus.UNRESOLVED,
                    "Subject identity is not confirmed; no resource can be safely attributed.",
                )
            )
            return self._result(
                AuditStatus.INCOMPLETE,
                cutoff,
                authorization,
                (),
                (),
                conditions,
            )

        supplied_evidence = tuple(evidence)
        linked = tuple(
            observation
            for observation in supplied_evidence
            if _matches_identity(observation, identity)
        )
        grouped = _group_resources(linked)
        facts_by_resource = policy_facts_by_resource or {}
        resources: list[ReconstructedResource] = []
        for key, observations in sorted(grouped.items()):
            system_id, resource_id, category = key
            facts = dict(facts_by_resource.get(resource_id, {}))
            facts.setdefault(
                "record_attributable_to_user",
                any(item.identifiers_found for item in observations),
            )
            facts.setdefault(
                "log_contains_user_email",
                any(
                    any(identifier.identifier_type.casefold() == "email" for identifier in item.identifiers_found)
                    for item in observations
                ),
            )
            policy = self.policy_engine.evaluate_record(category, facts=facts)
            resource, resource_conditions = _reconstruct_resource(
                system_id,
                resource_id,
                category,
                observations,
                policy,
                cutoff,
            )
            resources.append(resource)
            conditions.extend(resource_conditions)

        assessed_paths = tuple(
            item
            for item in activity.processes
            if item.process_kind in {"RESTORE_PATH", "DATA_FLOW"}
        )
        if not assessed_paths:
            conditions.append(
                _condition(
                    "recreation_path_coverage",
                    ConditionStatus.UNRESOLVED,
                    "No identity-linked flow or restore-path assessment establishes that data cannot be recreated.",
                )
            )
        process_conditions = _reconstruct_processes(assessed_paths, cutoff)
        conditions.extend(process_conditions)

        if not grouped:
            conditions.append(
                _condition(
                    "evidence_coverage",
                    ConditionStatus.UNRESOLVED,
                    "No identity-linked evidence establishes the state of relevant resources.",
                )
            )
        failed = any(item.status is ConditionStatus.FAILED for item in conditions)
        unresolved = any(item.status is ConditionStatus.UNRESOLVED for item in conditions)
        status = AuditStatus.COMPLETE if not failed and not unresolved else AuditStatus.INCOMPLETE
        return self._result(
            status,
            cutoff,
            authorization,
            tuple(resources),
            activity.processes,
            conditions,
        )

    @staticmethod
    def _result(
        status: AuditStatus,
        cutoff: datetime,
        authorization: AuthorizationAssessment,
        resources: tuple[ReconstructedResource, ...],
        processes: tuple[ProcessAssessment, ...],
        conditions: Iterable[MandatoryCondition],
    ) -> StateReconstruction:
        ordered_conditions = tuple(
            sorted(
                conditions,
                key=lambda item: (
                    item.system_id or "",
                    item.resource_id or "",
                    item.condition_id,
                ),
            )
        )
        return StateReconstruction(
            status,
            cutoff,
            authorization,
            resources,
            processes,
            ordered_conditions,
        )


def _reconstruct_resource(
    system_id: str | None,
    resource_id: str,
    category: str | None,
    observations: tuple[EvidenceObservation, ...],
    decision: PolicyDecision,
    cutoff: datetime,
) -> tuple[ReconstructedResource, tuple[MandatoryCondition, ...]]:
    cutoff_observations = tuple(
        item
        for item in observations
        if item.captured_at <= cutoff
        and item.temporal_basis is not TemporalBasis.AFTER_AUDIT
        and (item.observed_at is None or item.observed_at <= cutoff)
    )
    eligible = tuple(
        item for item in cutoff_observations if not item.is_operation_attempt
    )
    current = tuple(item for item in eligible if item.captured_at == cutoff)
    chosen = current or eligible
    provenance_observations = chosen or cutoff_observations
    latest = max(
        chosen,
        key=lambda item: (item.captured_at, item.observed_at or item.captured_at),
        default=None,
    )
    states = {item.state for item in current if item.state is not RecordState.UNKNOWN}
    conflict = len(states) > 1
    state = RecordState.UNKNOWN if conflict or latest is None else latest.state
    basis = (
        TemporalBasis.AT_AUDIT
        if current and not conflict
        else TemporalBasis.HISTORICAL
        if latest is not None
        else TemporalBasis.UNKNOWN
    )
    source_evidence_ids = tuple(
        sorted({item.source_evidence_id for item in provenance_observations})
    )
    locations = tuple(
        sorted({item.source_location for item in provenance_observations})
    )
    identifiers = tuple(
        sorted(
            {
                f"{identifier.identifier_type}:{identifier.identifier_value}"
                for item in provenance_observations
                for identifier in item.identifiers_found
            }
        )
    )
    resource = ReconstructedResource(
        system_id,
        resource_id,
        category,
        state,
        basis,
        identifiers,
        source_evidence_ids,
        locations,
        conflict,
        decision,
    )
    condition_list: list[MandatoryCondition] = []
    base_fields = {
        "system_id": system_id,
        "resource_id": resource_id,
        "data_category": category,
        "source_evidence_ids": source_evidence_ids,
        "source_activity_ids": (),
        "policy_rule_id": decision.rule_id,
    }
    if not current:
        condition_list.append(
            MandatoryCondition(
                f"resource_state_at_audit:{resource_id}",
                ConditionStatus.UNRESOLVED,
                (
                    "Only historical evidence is available; it does not verify resource state at audit_at."
                    if latest is not None
                    else "No cutoff-eligible observation establishes resource state."
                ),
                **base_fields,
            )
        )
        return resource, tuple(condition_list)
    if conflict:
        condition_list.append(
            MandatoryCondition(
                f"resource_consistency:{resource_id}",
                ConditionStatus.FAILED,
                "Cutoff evidence contains contradictory resource states.",
                **base_fields,
            )
        )
        return resource, tuple(condition_list)
    if decision.unresolved_policy or decision.condition_outcome is ConditionOutcome.UNRESOLVED:
        condition_list.append(
            MandatoryCondition(
                f"policy_mapping:{resource_id}",
                ConditionStatus.UNRESOLVED,
                decision.reason,
                **base_fields,
            )
        )
        return resource, tuple(condition_list)
    if decision.condition_outcome is ConditionOutcome.DOES_NOT_APPLY:
        condition_list.append(
            MandatoryCondition(
                f"policy_condition:{resource_id}",
                ConditionStatus.NOT_APPLICABLE,
                decision.reason,
                **base_fields,
            )
        )
        return resource, tuple(condition_list)
    condition_list.append(
        _evaluate_policy_state(
            resource,
            current,
            decision,
        )
    )
    return resource, tuple(condition_list)


def _evaluate_policy_state(
    resource: ReconstructedResource,
    observations: tuple[EvidenceObservation, ...],
    decision: PolicyDecision,
) -> MandatoryCondition:
    common = {
        "system_id": resource.system_id,
        "resource_id": resource.resource_id,
        "data_category": resource.data_category,
        "source_evidence_ids": resource.source_evidence_ids,
        "source_activity_ids": (),
        "policy_rule_id": decision.rule_id,
    }
    if decision.required_action is None:
        return MandatoryCondition(
            f"policy_action:{resource.resource_id}",
            ConditionStatus.UNRESOLVED,
            "Policy action is not mapped.",
            **common,
        )
    state = resource.state
    if decision.required_action is PolicyAction.DELETE:
        status = ConditionStatus.SATISFIED if state is RecordState.ABSENT else (
            ConditionStatus.FAILED if state in {
                RecordState.PRESENT, RecordState.REDACTED, RecordState.ANONYMIZED
            } else ConditionStatus.UNRESOLVED
        )
        reason = (
            "Required record absence is established at audit_at."
            if status is ConditionStatus.SATISFIED
            else "Record remains present or treated rather than absent."
            if status is ConditionStatus.FAILED
            else "Record absence is not established at audit_at."
        )
    elif decision.required_action is PolicyAction.REDACT:
        removed = _explicitly_removed_fields(observations)
        identifiers_remaining = _remaining_identifiers(resource, decision)
        required = set(decision.required_identifier_removal)
        if state is RecordState.ABSENT:
            status = ConditionStatus.FAILED
            reason = "Policy requires retaining this record in redacted form, but it is absent."
        elif state is RecordState.UNKNOWN:
            status = ConditionStatus.UNRESOLVED
            reason = "Record presence and redaction state are not established."
        elif identifiers_remaining:
            status = ConditionStatus.FAILED
            reason = "Identifying values prohibited by the policy remain linked to the record."
        elif state is RecordState.REDACTED and required.issubset(removed):
            status = ConditionStatus.SATISFIED
            reason = "The required identifying fields are explicitly evidenced as removed."
        else:
            status = ConditionStatus.UNRESOLVED
            reason = "Absence of all policy-prohibited identifiers is not explicitly established."
    elif decision.required_action is PolicyAction.ANONYMIZE:
        removed = _explicitly_removed_fields(observations)
        required = set(decision.required_identifier_removal)
        identifiers_remaining = _remaining_identifiers(resource, decision)
        if state is RecordState.ABSENT:
            status = ConditionStatus.FAILED
            reason = "Policy requires preserving the record in anonymized form, but it is absent."
        elif identifiers_remaining:
            status = ConditionStatus.FAILED
            reason = "The record remains attributable through a confirmed identifier."
        elif state is RecordState.ANONYMIZED and required.issubset(removed):
            status = ConditionStatus.SATISFIED
            reason = "Anonymization and removal of required identifier fields are explicitly evidenced."
        else:
            status = ConditionStatus.UNRESOLVED
            reason = "Irreversible unlinking and removal of all identifying fields are not established."
    else:
        status = ConditionStatus.SATISFIED if state is RecordState.PRESENT else (
            ConditionStatus.FAILED if state is RecordState.ABSENT else ConditionStatus.UNRESOLVED
        )
        reason = (
            "The policy-required retained record is present at audit_at."
            if status is ConditionStatus.SATISFIED
            else "A policy-required retained record is absent."
            if status is ConditionStatus.FAILED
            else "Presence of the policy-required retained record is not established."
        )
    return MandatoryCondition(
        f"policy:{resource.resource_id}",
        status,
        reason,
        **common,
    )


def _reconstruct_processes(
    processes: tuple[ProcessAssessment, ...],
    cutoff: datetime,
) -> tuple[MandatoryCondition, ...]:
    conditions: list[MandatoryCondition] = []
    for process in processes:
        if process.process_kind not in {"RESTORE_PATH", "DATA_FLOW"}:
            continue
        source_activities = process.corroborating_activity_ids
        base = {
            "system_id": process.system_id,
            "resource_id": process.resource_id,
            "data_category": process.data_category,
            "source_evidence_ids": process.source_evidence_ids,
            "source_activity_ids": source_activities,
            "policy_rule_id": process.policy_rule_id,
        }
        if process.state_temporal_basis is TemporalBasis.AFTER_AUDIT:
            status = ConditionStatus.UNRESOLVED
            reason = "Process evidence was captured after audit_at."
        elif process.state_temporal_basis is TemporalBasis.HISTORICAL:
            status = ConditionStatus.UNRESOLVED
            reason = "Historical process state cannot establish whether the path was disabled at audit_at."
        elif process.state is ProcessState.ACTIVE or process.state is ProcessState.RESTORABLE:
            status = ConditionStatus.FAILED
            reason = "A data flow or restore path can recreate or restore subject data at audit_at."
        elif process.state is ProcessState.DISABLED or process.state is ProcessState.BLOCKED:
            status = ConditionStatus.SATISFIED
            reason = "Evidence establishes that the recreation or restore path is disabled/blocked at audit_at."
        else:
            status = ConditionStatus.UNRESOLVED
            reason = "No evidence establishes that the recreation or restore path is disabled/blocked at audit_at."
        conditions.append(
            MandatoryCondition(
                f"recreation_prevention:{process.resource_id}",
                status,
                reason,
                **base,
            )
        )
        if process.process_kind == "RESTORE_PATH" and process.policy_action == "RETAIN":
            if process.state in {ProcessState.BLOCKED, ProcessState.RESTORABLE}:
                retain_status = ConditionStatus.SATISFIED
                retain_reason = (
                    "The backup is retained and restore access is restricted or explicitly assessable."
                    if process.state is ProcessState.BLOCKED
                    else "The retained backup is present; restore risk is separately reported."
                )
            else:
                retain_status = ConditionStatus.UNRESOLVED
                retain_reason = "Backup retention/presence is not established at audit_at."
            conditions.append(
                MandatoryCondition(
                    f"backup_retention:{process.resource_id}",
                    retain_status,
                    retain_reason,
                    **base,
                )
            )
    return tuple(conditions)


def _group_resources(
    observations: tuple[EvidenceObservation, ...],
) -> dict[tuple[str | None, str, str | None], tuple[EvidenceObservation, ...]]:
    grouped: dict[tuple[str | None, str, str | None], list[EvidenceObservation]] = {}
    for observation in observations:
        if not observation.resource_id:
            continue
        key = (observation.system_id, observation.resource_id, observation.data_category)
        grouped.setdefault(key, []).append(observation)
    return {key: tuple(value) for key, value in grouped.items()}


def _matches_identity(
    observation: EvidenceObservation,
    identity: IdentityResolution,
) -> bool:
    expected = {
        (item.identifier_type.casefold(), _normalize_identifier(item.identifier_value))
        for item in identity.identity_relationships
    }
    return any(
        (item.identifier_type.casefold(), _normalize_identifier(item.identifier_value))
        in expected
        for item in observation.identifiers_found
    )


def _explicitly_removed_fields(
    observations: tuple[EvidenceObservation, ...],
) -> set[str]:
    fields: set[str] = set()
    for observation in observations:
        for key in (
            "redacted_fields",
            "fields_redacted",
            "removed_identifiers",
            "identifiers_removed",
            "anonymized_fields",
        ):
            values = observation.attributes.get(key, ())
            if isinstance(values, str):
                values = (values,)
            if isinstance(values, (tuple, list, set)):
                fields.update(_normalize_field(str(value)) for value in values)
        if observation.attributes.get("anonymized") is True:
            fields.update({"name", "email", "phone", "email_hash", "user_id"})
    return fields


def _remaining_identifiers(
    resource: ReconstructedResource,
    decision: PolicyDecision,
) -> tuple[str, ...]:
    forbidden = set(decision.required_identifier_removal)
    permitted = set(decision.permitted_identifier_types)
    present = {
        value.partition(":")[0]
        for value in resource.identifiers_present
    }
    return tuple(sorted((present.intersection(forbidden | {"user_id"}) - permitted)))


def _normalize_field(value: str) -> str:
    normalized = value.casefold().replace("-", "_").replace(" ", "_")
    if normalized in {"emailhash", "email_hash"}:
        return "email_hash"
    if normalized in {"userid", "user_id", "customer_reference", "customer_id"}:
        return "user_id"
    return normalized


def _normalize_identifier(value: str) -> str:
    return "".join(value.split()).casefold()


def _condition(
    condition_id: str,
    status: ConditionStatus,
    reason: str,
    *,
    evidence_ids: tuple[str, ...] = (),
    activity_ids: tuple[str, ...] = (),
) -> MandatoryCondition:
    return MandatoryCondition(
        condition_id,
        status,
        reason,
        None,
        None,
        None,
        evidence_ids,
        activity_ids,
        None,
    )


def _parse_timestamp(value: datetime) -> datetime:
    parsed = parse_timestamp(value.isoformat())
    if parsed is None:
        raise ValueError("audit_at must be timezone-aware")
    return parsed


def _format_timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
