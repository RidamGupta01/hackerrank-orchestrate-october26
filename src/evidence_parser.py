"""Deterministic, provenance-preserving parsers for evidence formats."""

from __future__ import annotations

import csv
import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping

from src.evidence_models import EvidenceIdentifier, ParsedEvidenceRecord, RecordState

LOGGER = logging.getLogger(__name__)
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
MAX_TEXT_RECORD_CHARS = 1200
_TIMESTAMP_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_RESOURCE_PATTERN = re.compile(r"\b[a-z][a-z0-9]*_[0-9]+\b", re.IGNORECASE)
_USER_PATTERN = re.compile(r"\buser_[A-Za-z0-9-]+\b", re.IGNORECASE)
_HASH_PATTERN = re.compile(r"\b[a-f0-9]{40,64}\b", re.IGNORECASE)
_PHONE_PATTERN = re.compile(r"(?<!\w)\+?\d[\d ()-]{7,}\d(?!\w)")
_ID_KEYS = {
    "email": "email",
    "email_address": "email",
    "requester_email": "email",
    "owner_email": "email",
    "customer_email": "email",
    "subject_email": "email",
    "phone": "phone",
    "requester_phone": "phone",
    "owner_phone": "phone",
    "customer_phone": "phone",
    "email_hash": "email_hash",
    "user_id": "user_id",
    "customer_reference": "user_id",
    "subject_reference": "user_id",
    "subject_ref": "user_id",
    "correlation_key": "user_id",
    "full_name": "name",
    "display_name": "name",
    "requester_name": "name",
    "name": "name",
}
_SYSTEM_KEYS = ("system", "system_id", "data_store", "origin_system", "service")
_RESOURCE_KEYS = ("resource_id", "record_id", "id")
_CATEGORY_KEYS = ("record_type", "data_category", "collection", "collection_name")
_TIME_KEYS = (
    "observed_at", "recorded_at", "captured_at", "indexed_at", "event_time",
    "timestamp", "created_at", "exported_at", "updated_at",
)


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def parse_evidence_file(
    path: str | Path,
    *,
    evidence_id: str,
    captured_at: datetime,
) -> tuple[ParsedEvidenceRecord, ...]:
    """Parse and cache a manifest file; returned content is data, never instructions."""
    source = Path(path)
    size = source.stat().st_size
    if size > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence file exceeds configured size limit")
    stat = source.stat()
    return _parse_cached(
        str(source.resolve()),
        stat.st_mtime_ns,
        size,
        evidence_id,
        captured_at.isoformat(),
    )


@lru_cache(maxsize=192)
def _parse_cached(
    path: str,
    modified_ns: int,
    size: int,
    evidence_id: str,
    captured_at_text: str,
) -> tuple[ParsedEvidenceRecord, ...]:
    del modified_ns, size
    source = Path(path)
    suffix = source.suffix.casefold()
    if suffix == ".json":
        return _parse_json(source)
    if suffix in {".jsonl", ".ndjson"}:
        return _parse_json_lines(source)
    if suffix == ".csv":
        return _parse_csv(source)
    if suffix in {".log", ".txt"}:
        return _parse_text(source)
    if suffix == ".sql":
        return _parse_sql(source, captured_at_text)
    if suffix == ".pdf":
        return _parse_pdf(source)
    if suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff"}:
        return _parse_image(source)
    LOGGER.warning("Unsupported evidence format: evidence_id=%s", evidence_id)
    return ()


def _mapping_records(
    value: Any,
    location: str,
    inherited: Mapping[str, Any] | None = None,
) -> Iterable[ParsedEvidenceRecord]:
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from _mapping_records(item, f"{location}[{index}]", inherited)
        return
    if not isinstance(value, dict):
        return

    context = dict(inherited or {})
    context.update({key: item for key, item in value.items() if key in _SYSTEM_KEYS})
    context.update({key: item for key, item in value.items() if key in _TIME_KEYS})
    context.update({key: item for key, item in value.items() if key in _CATEGORY_KEYS})
    context.update({key: item for key, item in value.items() if key in _RESOURCE_KEYS})

    identifiers = list(_identifiers_from_mapping(value))
    for key, item in value.items():
        if isinstance(item, str):
            identifiers.extend(_identifiers_from_text(item))
    identifiers = _unique_identifiers(identifiers)
    timestamp = next(
        (parse_timestamp(context[key]) for key in _TIME_KEYS if context.get(key)),
        None,
    )
    system = next(
        (str(context[key]) for key in _SYSTEM_KEYS if context.get(key) is not None),
        None,
    )
    resource = next(
        (str(context[key]) for key in _RESOURCE_KEYS if context.get(key) is not None),
        None,
    )
    category = next(
        (str(context[key]) for key in _CATEGORY_KEYS if context.get(key) is not None),
        None,
    )
    state, attempted = _mapping_state(value)
    if identifiers:
        yield ParsedEvidenceRecord(
            system_id=system,
            resource_id=resource,
            data_category=category,
            observed_at=timestamp,
            identifiers=tuple(identifiers),
            source_location=location,
            state=state,
            is_operation_attempt=attempted,
            attributes=_safe_attributes(value),
        )
    for key, item in value.items():
        if isinstance(item, (dict, list)):
            yield from _mapping_records(item, f"{location}.{key}", context)


def _identifiers_recursive(value: Any) -> list[EvidenceIdentifier]:
    if isinstance(value, dict):
        return list(_identifiers_from_mapping(value)) + [
            identifier
            for item in value.values()
            for identifier in _identifiers_recursive(item)
        ]
    if isinstance(value, list):
        return [identifier for item in value for identifier in _identifiers_recursive(item)]
    if isinstance(value, str):
        return _identifiers_from_text(value)
    return []


def _identifiers_from_mapping(value: Mapping[str, Any]) -> list[EvidenceIdentifier]:
    output: list[EvidenceIdentifier] = []
    for key, item in value.items():
        identifier_type = _ID_KEYS.get(str(key).casefold())
        if identifier_type and isinstance(item, (str, int)):
            text = str(item).strip()
            if text:
                output.append(EvidenceIdentifier(identifier_type, text))
    return output


def _identifiers_from_text(text: str) -> list[EvidenceIdentifier]:
    found = [EvidenceIdentifier("email", match) for match in _EMAIL_PATTERN.findall(text)]
    found.extend(EvidenceIdentifier("user_id", match) for match in _USER_PATTERN.findall(text))
    found.extend(EvidenceIdentifier("resource_id", match) for match in _RESOURCE_PATTERN.findall(text))
    found.extend(EvidenceIdentifier("email_hash", match) for match in _HASH_PATTERN.findall(text))
    found.extend(EvidenceIdentifier("phone", match.strip()) for match in _PHONE_PATTERN.findall(text))
    return found


def _unique_identifiers(
    identifiers: Iterable[EvidenceIdentifier],
) -> list[EvidenceIdentifier]:
    seen: set[tuple[str, str]] = set()
    output: list[EvidenceIdentifier] = []
    for identifier in identifiers:
        key = (identifier.identifier_type, _normalize(identifier.identifier_value))
        if key not in seen:
            seen.add(key)
            output.append(identifier)
    return output


def _normalize(value: str) -> str:
    return re.sub(r"[\s()\-]", "", value).casefold()


def _mapping_state(value: Mapping[str, Any]) -> tuple[RecordState, bool]:
    status_values = [
        str(value.get(key, ""))
        for key in ("result", "status", "state", "lookup_result", "status_code", "http_status")
    ]
    compact_statuses = {
        re.sub(r"[\s_-]+", "", item).casefold()
        for item in status_values
        if item.strip()
    }
    event = " ".join(str(value.get(key, "")) for key in ("event", "event_name", "operation")).casefold().strip()
    attempt = any(
        term in event
        for term in (
            "started", "attempt", "requested", "queued", "delete", "redact",
            "anonymize", "restore", "sync", "update", "disable", "block",
        )
    )
    if attempt:
        return RecordState.UNKNOWN, True
    if compact_statuses.intersection({"notfound", "nomatch", "404", "miss", "absent"}):
        return RecordState.ABSENT, attempt
    if compact_statuses.intersection({"found", "present", "hit", "identifiable", "active"}):
        return RecordState.PRESENT, attempt
    if value.get("profile", object()) is None and compact_statuses.intersection({"404", "notfound"}):
        return RecordState.ABSENT, attempt
    if not compact_statuses and not event and value.get("resource_id"):
        if _identifiers_from_mapping(value):
            return RecordState.PRESENT, False
    return RecordState.UNKNOWN, attempt


def _safe_attributes(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "result", "status", "state", "status_code", "http_status", "event",
        "event_name", "operation", "enabled", "restore_allowed", "account_status",
        "updated_at", "indexed_at", "event_time", "observed_at", "recorded_at",
        "captured_at",
    }
    return {
        key: item
        for key, item in value.items()
        if key.casefold() in allowed and isinstance(item, (str, int, float, bool, type(None)))
    }


def _parse_json(source: Path) -> tuple[ParsedEvidenceRecord, ...]:
    payload = json.loads(source.read_text(encoding="utf-8-sig"))
    return tuple(_mapping_records(payload, "$"))


def _parse_json_lines(source: Path) -> tuple[ParsedEvidenceRecord, ...]:
    records: list[ParsedEvidenceRecord] = []
    for number, line in enumerate(source.read_text(encoding="utf-8-sig").splitlines(), 1):
        if line.strip():
            records.extend(_mapping_records(json.loads(line), f"line:{number}"))
    return tuple(records)


def _parse_csv(source: Path) -> tuple[ParsedEvidenceRecord, ...]:
    records: list[ParsedEvidenceRecord] = []
    with source.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        for row_number, row in enumerate(reader, 2):
            records.extend(_mapping_records(row, f"row:{row_number}"))
    return tuple(records)


def _parse_text(source: Path) -> tuple[ParsedEvidenceRecord, ...]:
    records: list[ParsedEvidenceRecord] = []
    for number, line in enumerate(source.read_text(encoding="utf-8-sig", errors="replace").splitlines(), 1):
        if line.lstrip().startswith("{"):
            try:
                structured = json.loads(line)
            except json.JSONDecodeError:
                pass
            else:
                records.extend(_mapping_records(structured, f"line:{number}"))
                continue
        identifiers = _identifiers_from_text(line)
        timestamp_match = _TIMESTAMP_PATTERN.search(line)
        observed_at = parse_timestamp(timestamp_match.group(0)) if timestamp_match else None
        fields = {
            key.casefold(): quoted if quoted else bare
            for key, quoted, bare in re.findall(
                r'([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|([^,\s]+))', line
            )
        }
        system = next((fields[key] for key in ("system", "service", "source_system") if key in fields), None)
        resource = next((fields[key] for key in ("resource_id", "resource", "target_resource") if key in fields), None)
        category = next((fields[key] for key in ("record_type", "category", "data_category") if key in fields), None)
        state, attempt = _text_state(line, fields)
        records.append(
            ParsedEvidenceRecord(
                system, resource, category, observed_at, tuple(_unique_identifiers(identifiers)),
                f"line:{number}", state, attempt,
                {"excerpt": line[:MAX_TEXT_RECORD_CHARS]},
            )
        )
    return tuple(records)


def _text_state(line: str, fields: Mapping[str, str]) -> tuple[RecordState, bool]:
    text = line.casefold()
    mapped_state, operation_attempt = _mapping_state(fields)
    if operation_attempt or any(
        term in text
        for term in ("lookup_started", "scan_started", "query_started", "attempt=", "retry")
    ):
        return RecordState.UNKNOWN, True
    if mapped_state is not RecordState.UNKNOWN:
        return mapped_state, False
    if any(term in text for term in ("not_found", "not-found", "not found", "rows=0", "rows\":\"0", "result=miss", "result\":\"miss", "http_status=404", "http_status\":\"404")):
        return RecordState.ABSENT, False
    if any(term in text for term in ("result=hit", "result\":\"hit", "rows=1", "rows\":\"1", "status=found", "state=present")):
        return RecordState.PRESENT, False
    return RecordState.UNKNOWN, False


def _parse_sql(
    source: Path,
    captured_at_text: str,
) -> tuple[ParsedEvidenceRecord, ...]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    def authorize(action: int, arg1: str | None, arg2: str | None, database: str, trigger: str | None) -> int:
        del database, trigger
        allowed = {
            sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_INDEX,
            sqlite3.SQLITE_INSERT, sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_REINDEX,
            sqlite3.SQLITE_READ, sqlite3.SQLITE_SELECT,
        }
        if action == sqlite3.SQLITE_UPDATE and (arg1 or "").casefold() in {
            "sqlite_master", "sqlite_schema"
        }:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION:
            function_name = (arg1 or arg2 or "").casefold()
            return sqlite3.SQLITE_OK if function_name == "json_valid" else sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_PRAGMA and (arg1 or "").casefold() == "foreign_keys":
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY

    connection.set_authorizer(authorize)
    try:
        script = "".join(
            line
            for line in source.read_text(encoding="utf-8-sig").splitlines(keepends=True)
            if not line.lstrip().startswith("--")
        )
        statement = ""
        for character in script:
            statement += character
            if character == ";" and sqlite3.complete_statement(statement):
                sql = statement.strip()
                statement = ""
                if sql:
                    connection.execute(sql)
        if statement.strip():
            raise ValueError("incomplete SQL statement")
        connection.set_authorizer(None)
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        records: list[ParsedEvidenceRecord] = []
        for table_row in tables:
            table = table_row["name"]
            escaped_table = table.replace('"', '""')
            columns = connection.execute(f'PRAGMA table_info("{escaped_table}")').fetchall()
            names = [column["name"] for column in columns]
            if not names:
                continue
            for row_number, row in enumerate(
                connection.execute(f'SELECT * FROM "{escaped_table}"'), 1
            ):
                mapped = dict(row)
                mapped.setdefault("captured_at", captured_at_text)
                # Expand JSON payload columns while retaining table and row provenance.
                for column_name in ("record_json", "json", "payload"):
                    payload = mapped.get(column_name)
                    if isinstance(payload, str):
                        try:
                            decoded = json.loads(payload)
                        except json.JSONDecodeError:
                            continue
                        mapped.update(decoded if isinstance(decoded, dict) else {})
                records.extend(_mapping_records(mapped, f"table:{table}/row:{row_number}"))
    finally:
        connection.close()
    return tuple(records)


def _parse_pdf(source: Path) -> tuple[ParsedEvidenceRecord, ...]:
    try:
        import pymupdf as fitz
    except ImportError as exc:
        try:
            import fitz
        except ImportError:
            raise RuntimeError("PDF parsing requires PyMuPDF") from exc
    document = fitz.open(source)
    records: list[ParsedEvidenceRecord] = []
    try:
        for page_number, page in enumerate(document, 1):
            text = page.get_text("text")
            if text.strip():
                records.extend(_text_records_from_block(text, f"page:{page_number}"))
    finally:
        document.close()
    return tuple(records)


def _text_records_from_block(text: str, location: str) -> list[ParsedEvidenceRecord]:
    output: list[ParsedEvidenceRecord] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for chunk_number, start in enumerate(range(0, len(line), MAX_TEXT_RECORD_CHARS), 1):
            excerpt = line[start:start + MAX_TEXT_RECORD_CHARS]
            if not excerpt.strip():
                continue
            identifiers = tuple(_unique_identifiers(_identifiers_from_text(excerpt)))
            timestamp_match = _TIMESTAMP_PATTERN.search(excerpt)
            timestamp = parse_timestamp(timestamp_match.group(0)) if timestamp_match else None
            suffix = f"/line:{line_number}"
            if len(line) > MAX_TEXT_RECORD_CHARS:
                suffix += f"/chunk:{chunk_number}"
            output.append(
                ParsedEvidenceRecord(
                    system_id=None, resource_id=None, data_category=None, observed_at=timestamp,
                    identifiers=identifiers, source_location=f"{location}{suffix}",
                    state=RecordState.UNKNOWN, attributes={"excerpt": excerpt},
                )
            )
    return output


def _parse_image(source: Path) -> tuple[ParsedEvidenceRecord, ...]:
    try:
        from PIL import Image
        import pytesseract
    except ImportError as exc:
        raise RuntimeError("Image text extraction requires Pillow and pytesseract") from exc
    with Image.open(source) as image:
        text = pytesseract.image_to_string(image)
    return tuple(_text_records_from_block(text, "image:ocr"))
