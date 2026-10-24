"""Deterministic identity resolution using the supplied identity CSVs."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping


class ResolutionStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class IdentityRelationship:
    user_id: str
    identifier_type: str
    identifier_value: str
    source_file: str
    source_record_id: str
    observed_at: datetime
    relation_kind: str

    def to_dict(self) -> dict[str, str]:
        return {
            "user_id": self.user_id,
            "identifier_type": self.identifier_type,
            "identifier_value": self.identifier_value,
            "source_file": self.source_file,
            "source_record_id": self.source_record_id,
            "observed_at": format_timestamp(self.observed_at),
            "relation_kind": self.relation_kind,
        }


@dataclass(frozen=True)
class IdentityResolution:
    status: ResolutionStatus
    request_email: str
    requested_at: datetime
    audit_at: datetime
    user_id: str | None
    candidate_user_ids: tuple[str, ...]
    matched_relationships: tuple[IdentityRelationship, ...]
    identity_relationships: tuple[IdentityRelationship, ...]
    later_candidate_user_ids: tuple[str, ...]
    unresolved_reason: str | None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible result without unrelated user records."""
        return {
            "status": self.status.value,
            "request_email": self.request_email,
            "requested_at": format_timestamp(self.requested_at),
            "audit_at": format_timestamp(self.audit_at),
            "user_id": self.user_id,
            "candidate_user_ids": list(self.candidate_user_ids),
            "matched_relationships": [
                relationship.to_dict()
                for relationship in self.matched_relationships
            ],
            "identity_relationships": [
                relationship.to_dict()
                for relationship in self.identity_relationships
            ],
            "later_candidate_user_ids": list(self.later_candidate_user_ids),
            "unresolved_reason": self.unresolved_reason,
        }


@dataclass(frozen=True)
class _IdentityRecord:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: datetime


@dataclass(frozen=True)
class _AuditRecord:
    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str
    new_value: str


_IDENTITY_COLUMNS = {
    "user_id",
    "name",
    "email",
    "phone",
    "email_hash",
    "updated_at",
}
_AUDIT_COLUMNS = {
    "audit_id",
    "user_id",
    "event_time",
    "field_name",
    "old_value",
    "new_value",
}
_AUDIT_IDENTIFIER_TYPES = {"email", "phone", "email_hash"}
_SNAPSHOT_IDENTIFIER_FIELDS = ("name", "email", "phone", "email_hash")


def parse_timestamp(value: str | datetime, field_name: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError(f"{field_name} must be an ISO-8601 timestamp") from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_csv(path: str | Path, required_columns: set[str]) -> list[dict[str, str]]:
    with Path(path).open(encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        if reader.fieldnames is None:
            raise ValueError(f"{path} is missing a CSV header")
        missing_columns = required_columns.difference(reader.fieldnames)
        if missing_columns:
            raise ValueError(
                f"{path} is missing required columns: "
                f"{', '.join(sorted(missing_columns))}"
            )
        return list(reader)


class IdentityResolver:
    """Resolve a request email to a stable user ID with dated provenance.

    Email matching is case-insensitive and trims surrounding whitespace. No
    fuzzy matching, name matching, substring matching, or cross-user merging is
    performed.
    """

    def __init__(
        self,
        identities: Iterable[Mapping[str, str]],
        audit_log: Iterable[Mapping[str, str]],
    ) -> None:
        self._identities = tuple(
            _IdentityRecord(
                user_id=_required_value(row, "user_id", "user_identities.csv"),
                name=_required_value(row, "name", "user_identities.csv"),
                email=_required_value(row, "email", "user_identities.csv"),
                phone=_required_value(row, "phone", "user_identities.csv"),
                email_hash=_required_value(
                    row, "email_hash", "user_identities.csv"
                ),
                updated_at=parse_timestamp(row["updated_at"], "updated_at"),
            )
            for row in identities
        )
        self._audit_log = tuple(
            _AuditRecord(
                audit_id=_required_value(row, "audit_id", "user_audit_log.csv"),
                user_id=_required_value(row, "user_id", "user_audit_log.csv"),
                event_time=parse_timestamp(row["event_time"], "event_time"),
                field_name=_required_value(
                    row, "field_name", "user_audit_log.csv"
                ),
                old_value=_required_value(
                    row, "old_value", "user_audit_log.csv"
                ),
                new_value=_required_value(
                    row, "new_value", "user_audit_log.csv"
                ),
            )
            for row in audit_log
        )
        self._validate_unique_ids()

    @classmethod
    def from_csv(
        cls,
        identities_path: str | Path,
        audit_log_path: str | Path,
    ) -> IdentityResolver:
        identities = _read_csv(identities_path, _IDENTITY_COLUMNS)
        audit_log = _read_csv(audit_log_path, _AUDIT_COLUMNS)
        return cls(identities, audit_log)

    def resolve_request(self, request: Mapping[str, str]) -> IdentityResolution:
        for field_name in ("email", "requested_at", "audit_at"):
            if field_name not in request:
                raise ValueError(f"request is missing required field: {field_name}")
        return self.resolve_email(
            request_email=request["email"],
            requested_at=request["requested_at"],
            audit_at=request["audit_at"],
        )

    def resolve_email(
        self,
        request_email: str,
        requested_at: str | datetime,
        audit_at: str | datetime,
    ) -> IdentityResolution:
        requested_time = parse_timestamp(requested_at, "requested_at")
        audit_time = parse_timestamp(audit_at, "audit_at")
        if audit_time < requested_time:
            raise ValueError("audit_at must not be earlier than requested_at")

        normalized_email = _normalize_email(request_email)
        if not normalized_email:
            return self._result(
                ResolutionStatus.UNRESOLVED,
                request_email,
                requested_time,
                audit_time,
                (),
                (),
                (),
                "EMPTY_REQUEST_EMAIL",
            )

        request_matches = tuple(
            relationship
            for relationship in self._email_relationships()
            if _normalize_email(relationship.identifier_value) == normalized_email
            and relationship.observed_at <= requested_time
            and not self._snapshot_is_superseded(relationship, requested_time)
        )
        request_candidates = _unique_user_ids(request_matches)
        if len(request_candidates) > 1:
            return self._result(
                ResolutionStatus.AMBIGUOUS,
                request_email,
                requested_time,
                audit_time,
                request_candidates,
                request_matches,
                (),
                "EMAIL_MATCHES_MULTIPLE_USERS_AT_REQUEST_TIME",
            )

        if not request_candidates:
            later_matches = tuple(
                relationship
                for relationship in self._email_relationships()
                if _normalize_email(relationship.identifier_value) == normalized_email
                and requested_time < relationship.observed_at <= audit_time
                and not self._snapshot_is_superseded(relationship, audit_time)
            )
            return self._result(
                ResolutionStatus.UNRESOLVED,
                request_email,
                requested_time,
                audit_time,
                (),
                (),
                _unique_user_ids(later_matches),
                (
                    "IDENTITY_ONLY_OBSERVED_AFTER_REQUEST"
                    if later_matches
                    else "NO_MATCHING_IDENTITY_EVIDENCE"
                ),
            )

        user_id = request_candidates[0]
        audit_relationships = tuple(
            relationship
            for relationship in self._relationships_for_user(user_id)
            if relationship.observed_at <= audit_time
            and not self._snapshot_is_superseded(relationship, audit_time)
        )
        return self._result(
            ResolutionStatus.CONFIRMED,
            request_email,
            requested_time,
            audit_time,
            request_candidates,
            request_matches,
            (),
            None,
            user_id=user_id,
            identity_relationships=audit_relationships,
        )

    def _email_relationships(self) -> tuple[IdentityRelationship, ...]:
        relationships: list[IdentityRelationship] = []
        for identity in self._identities:
            relationships.append(
                IdentityRelationship(
                    user_id=identity.user_id,
                    identifier_type="email",
                    identifier_value=identity.email,
                    source_file="user_identities.csv",
                    source_record_id=identity.user_id,
                    observed_at=identity.updated_at,
                    relation_kind="snapshot",
                )
            )
        for audit in self._audit_log:
            if audit.field_name != "email":
                continue
            relationships.extend(
                (
                    IdentityRelationship(
                        user_id=audit.user_id,
                        identifier_type="email",
                        identifier_value=audit.old_value,
                        source_file="user_audit_log.csv",
                        source_record_id=audit.audit_id,
                        observed_at=audit.event_time,
                        relation_kind="previous_value",
                    ),
                    IdentityRelationship(
                        user_id=audit.user_id,
                        identifier_type="email",
                        identifier_value=audit.new_value,
                        source_file="user_audit_log.csv",
                        source_record_id=audit.audit_id,
                        observed_at=audit.event_time,
                        relation_kind="new_value",
                    ),
                )
            )
        return tuple(relationships)

    def _relationships_for_user(
        self, user_id: str
    ) -> tuple[IdentityRelationship, ...]:
        relationships: list[IdentityRelationship] = []
        for identity in self._identities:
            if identity.user_id != user_id:
                continue
            for identifier_type in _SNAPSHOT_IDENTIFIER_FIELDS:
                value = getattr(identity, identifier_type)
                if value:
                    relationships.append(
                        IdentityRelationship(
                            user_id=user_id,
                            identifier_type=identifier_type,
                            identifier_value=value,
                            source_file="user_identities.csv",
                            source_record_id=user_id,
                            observed_at=identity.updated_at,
                            relation_kind="snapshot",
                        )
                    )
        for audit in self._audit_log:
            if audit.user_id != user_id:
                continue
            if audit.field_name not in _AUDIT_IDENTIFIER_TYPES:
                continue
            relationships.extend(
                (
                    IdentityRelationship(
                        user_id=user_id,
                        identifier_type=audit.field_name,
                        identifier_value=audit.old_value,
                        source_file="user_audit_log.csv",
                        source_record_id=audit.audit_id,
                        observed_at=audit.event_time,
                        relation_kind="previous_value",
                    ),
                    IdentityRelationship(
                        user_id=user_id,
                        identifier_type=audit.field_name,
                        identifier_value=audit.new_value,
                        source_file="user_audit_log.csv",
                        source_record_id=audit.audit_id,
                        observed_at=audit.event_time,
                        relation_kind="new_value",
                    ),
                )
            )
        return tuple(
            sorted(
                relationships,
                key=lambda relationship: (
                    relationship.observed_at,
                    relationship.source_file,
                    relationship.source_record_id,
                    relationship.identifier_type,
                    relationship.relation_kind,
                    relationship.identifier_value,
                ),
            )
        )

    def _snapshot_is_superseded(
        self,
        relationship: IdentityRelationship,
        cutoff: datetime,
    ) -> bool:
        if relationship.relation_kind != "snapshot":
            return False

        return any(
            audit.user_id == relationship.user_id
            and audit.field_name == relationship.identifier_type
            and relationship.observed_at < audit.event_time <= cutoff
            and audit.old_value == relationship.identifier_value
            for audit in self._audit_log
        )

    def _result(
        self,
        status: ResolutionStatus,
        request_email: str,
        requested_at: datetime,
        audit_at: datetime,
        candidate_user_ids: tuple[str, ...],
        matched_relationships: tuple[IdentityRelationship, ...],
        later_candidate_user_ids: tuple[str, ...],
        unresolved_reason: str | None,
        *,
        user_id: str | None = None,
        identity_relationships: tuple[IdentityRelationship, ...] = (),
    ) -> IdentityResolution:
        return IdentityResolution(
            status=status,
            request_email=request_email,
            requested_at=requested_at,
            audit_at=audit_at,
            user_id=user_id,
            candidate_user_ids=candidate_user_ids,
            matched_relationships=matched_relationships,
            identity_relationships=identity_relationships,
            later_candidate_user_ids=later_candidate_user_ids,
            unresolved_reason=unresolved_reason,
        )

    def _validate_unique_ids(self) -> None:
        identity_ids = [identity.user_id for identity in self._identities]
        if len(identity_ids) != len(set(identity_ids)):
            raise ValueError("user_identities.csv contains duplicate user_id values")
        audit_ids = [record.audit_id for record in self._audit_log]
        if len(audit_ids) != len(set(audit_ids)):
            raise ValueError("user_audit_log.csv contains duplicate audit_id values")


def _required_value(row: Mapping[str, str], field_name: str, source: str) -> str:
    value = row[field_name]
    if not value:
        raise ValueError(f"{source} contains an empty {field_name}")
    return value


def _normalize_email(value: str) -> str:
    return value.strip().casefold()


def _unique_user_ids(
    relationships: Iterable[IdentityRelationship],
) -> tuple[str, ...]:
    return tuple(sorted({relationship.user_id for relationship in relationships}))
