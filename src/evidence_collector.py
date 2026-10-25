"""Discover and normalize manifest-backed evidence for a confirmed identity."""

from __future__ import annotations

import csv
import logging
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable

from src.evidence_models import (
    EvidenceIdentifier,
    EvidenceManifestEntry,
    EvidenceObservation,
    ParsedEvidenceRecord,
    TemporalBasis,
)
from src.evidence_parser import parse_evidence_file, parse_timestamp
from src.identity_resolver import IdentityResolution, ResolutionStatus

LOGGER = logging.getLogger(__name__)
_MANIFEST_COLUMNS = {"file_id", "file_path", "origin", "captured_at"}


class EvidenceCollector:
    """Search every manifest entry for supplied confirmed identifiers.

    The collector does not resolve identity itself. Pass all current and
    historical identifiers from one confirmed identity-resolution result.
    """

    def __init__(
        self,
        dataset_dir: str | Path,
        *,
        manifest_path: str | Path | None = None,
    ) -> None:
        self.dataset_dir = Path(dataset_dir).resolve()
        self.evidence_dir = (self.dataset_dir / "evidence").resolve()
        self.manifest_path = Path(manifest_path) if manifest_path else self.dataset_dir / "evidence_files.csv"
        self.manifest = self._read_manifest()

    def collect(
        self,
        identifiers: Iterable[EvidenceIdentifier | object],
        audit_at: str | datetime,
    ) -> tuple[EvidenceObservation, ...]:
        cutoff = parse_timestamp(audit_at.isoformat() if isinstance(audit_at, datetime) else audit_at)
        if cutoff is None:
            raise ValueError("audit_at must be a timezone-aware ISO-8601 timestamp")
        normalized_identifiers = _normalize_input_identifiers(identifiers)
        if not normalized_identifiers:
            return ()

        observations: list[EvidenceObservation] = []
        for entry in self.manifest:
            try:
                parsed_records = parse_evidence_file(
                    entry.path,
                    evidence_id=entry.evidence_id,
                    captured_at=entry.captured_at,
                )
            except (
                OSError, UnicodeError, ValueError, RuntimeError, csv.Error, sqlite3.Error
            ) as exc:
                LOGGER.warning(
                    "Evidence parser failed: evidence_id=%s error_type=%s",
                    entry.evidence_id,
                    type(exc).__name__,
                )
                continue
            for record in parsed_records:
                matches = _matching_identifiers(record, normalized_identifiers)
                if not matches:
                    continue
                observed_at = record.observed_at or entry.captured_at
                observations.append(
                    EvidenceObservation(
                        system_id=record.system_id or entry.origin,
                        resource_id=record.resource_id,
                        data_category=record.data_category,
                        observed_at=observed_at,
                        captured_at=entry.captured_at,
                        identifiers_found=matches,
                        source_evidence_id=entry.evidence_id,
                        source_location=record.source_location,
                        state=record.state,
                        temporal_basis=_temporal_basis(
                            observed_at, entry.captured_at, cutoff
                        ),
                        is_operation_attempt=record.is_operation_attempt,
                        attributes=record.attributes,
                    )
                )
        return tuple(observations)

    def collect_for_resolution(
        self,
        resolution: IdentityResolution,
    ) -> tuple[EvidenceObservation, ...]:
        """Collect with every identifier in a confirmed, cutoff-bounded resolution."""
        if resolution.status is not ResolutionStatus.CONFIRMED:
            raise ValueError("evidence collection requires a confirmed identity resolution")
        return self.collect(resolution.identity_relationships, resolution.audit_at)

    def _read_manifest(self) -> tuple[EvidenceManifestEntry, ...]:
        entries: list[EvidenceManifestEntry] = []
        with self.manifest_path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames is None or not _MANIFEST_COLUMNS.issubset(reader.fieldnames):
                raise ValueError("evidence manifest is missing required columns")
            seen_ids: set[str] = set()
            seen_paths: set[str] = set()
            for row_number, row in enumerate(reader, 2):
                evidence_id = row["file_id"].strip()
                relative_path = row["file_path"].strip()
                origin = row["origin"].strip()
                captured_at = parse_timestamp(row["captured_at"])
                if not evidence_id or not relative_path or not origin or captured_at is None:
                    raise ValueError(f"invalid evidence manifest row {row_number}")
                candidate = (self.dataset_dir / relative_path).resolve()
                if not candidate.is_relative_to(self.dataset_dir) or not candidate.is_file():
                    raise ValueError(f"evidence path is missing or outside dataset at row {row_number}")
                if evidence_id in seen_ids or relative_path in seen_paths:
                    raise ValueError("evidence manifest contains duplicate identifiers or paths")
                seen_ids.add(evidence_id)
                seen_paths.add(relative_path)
                entries.append(
                    EvidenceManifestEntry(evidence_id, str(candidate), origin, captured_at)
                )
        return tuple(entries)


def _normalize_input_identifiers(
    identifiers: Iterable[EvidenceIdentifier | object],
) -> tuple[EvidenceIdentifier, ...]:
    result: list[EvidenceIdentifier] = []
    for item in identifiers:
        if isinstance(item, EvidenceIdentifier):
            identifier = item
        else:
            identifier_type = getattr(item, "identifier_type", None)
            identifier_value = getattr(item, "identifier_value", None)
            if not isinstance(identifier_type, str) or not isinstance(identifier_value, str):
                raise TypeError("identifiers must be EvidenceIdentifier or identity relationships")
            identifier = EvidenceIdentifier(identifier_type, identifier_value)
        if identifier.identifier_value.strip():
            result.append(identifier)
    seen: set[tuple[str, str]] = set()
    unique: list[EvidenceIdentifier] = []
    for item in result:
        key = (item.identifier_type.casefold(), _normalize(item.identifier_value))
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return tuple(unique)


def _matching_identifiers(
    record: ParsedEvidenceRecord,
    candidates: tuple[EvidenceIdentifier, ...],
) -> tuple[EvidenceIdentifier, ...]:
    parsed_values: dict[str, set[str]] = {}
    for found in record.identifiers:
        parsed_values.setdefault(found.identifier_type.casefold(), set()).add(
            _normalize(found.identifier_value)
        )
    text = str(record.attributes.get("excerpt", ""))
    matches: list[EvidenceIdentifier] = []
    for candidate in candidates:
        normalized = _normalize(candidate.identifier_value)
        known = parsed_values.get(candidate.identifier_type.casefold(), set())
        if normalized in known or _contains_identifier(
            text, candidate.identifier_value, candidate.identifier_type
        ):
            matches.append(candidate)
    return tuple(matches)


def _contains_identifier(text: str, value: str, identifier_type: str) -> bool:
    if not text or not value:
        return False
    if identifier_type.casefold() == "name":
        return re.search(
            rf"(?:^|[=:|,;(\[])\s*{re.escape(value)}(?=\s*(?:[,;:|)\].]|$))",
            text,
            flags=re.IGNORECASE | re.MULTILINE,
        ) is not None
    if re.search(
        rf"(?<![A-Za-z0-9]){re.escape(value)}(?![A-Za-z0-9])",
        text,
        flags=re.IGNORECASE,
    ):
        return True
    # Phone numbers are commonly formatted differently in logs and documents.
    digits = re.sub(r"\D", "", value)
    if digits and len(digits) >= 8:
        phone_pattern = r"[\s()+-]*".join(re.escape(digit) for digit in digits)
        return re.search(rf"(?<!\d){phone_pattern}(?!\d)", text) is not None
    return False


def _normalize(value: str) -> str:
    return re.sub(r"[\s()\-]", "", value).casefold()


def _temporal_basis(
    observed_at: datetime,
    captured_at: datetime,
    cutoff: datetime,
) -> TemporalBasis:
    if captured_at > cutoff or observed_at > cutoff:
        return TemporalBasis.AFTER_AUDIT
    if observed_at == cutoff:
        return TemporalBasis.AT_AUDIT
    return TemporalBasis.HISTORICAL
