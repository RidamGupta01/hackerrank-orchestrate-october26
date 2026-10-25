"""Shared types for evidence observations and their provenance."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping


class RecordState(str, Enum):
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


class TemporalBasis(str, Enum):
    HISTORICAL = "HISTORICAL"
    AT_AUDIT = "AT_AUDIT"
    AFTER_AUDIT = "AFTER_AUDIT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class EvidenceIdentifier:
    identifier_type: str
    identifier_value: str


@dataclass(frozen=True)
class EvidenceManifestEntry:
    evidence_id: str
    path: str
    origin: str
    captured_at: datetime


@dataclass(frozen=True)
class EvidenceObservation:
    system_id: str | None
    resource_id: str | None
    data_category: str | None
    observed_at: datetime | None
    captured_at: datetime
    identifiers_found: tuple[EvidenceIdentifier, ...]
    source_evidence_id: str
    source_location: str
    state: RecordState
    temporal_basis: TemporalBasis
    is_operation_attempt: bool = False
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ParsedEvidenceRecord:
    """Identifier-bearing facts parsed from one bounded source location."""

    system_id: str | None
    resource_id: str | None
    data_category: str | None
    observed_at: datetime | None
    identifiers: tuple[EvidenceIdentifier, ...]
    source_location: str
    state: RecordState = RecordState.UNKNOWN
    is_operation_attempt: bool = False
    attributes: Mapping[str, Any] = field(default_factory=dict)
