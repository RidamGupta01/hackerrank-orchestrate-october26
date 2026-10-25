# Evidence investigation

## Components

- `src/evidence_models.py` defines the shared `EvidenceObservation` record,
  provenance identifiers, manifest entries, record-state enum, and temporal
  basis enum.
- `src/evidence_parser.py` contains deterministic format adapters. The parser
  emits bounded record-level observations and source locations; it does not
  receive prompts or infer deletion policy.
- `src/evidence_collector.py` validates and reads the manifest, searches every
  manifest-listed evidence file for the current and historical identifiers
  supplied by a confirmed `IdentityResolution`, then emits normalized
  observations.

Example:

```python
from src.evidence_collector import EvidenceCollector
from src.evidence_models import EvidenceIdentifier

collector = EvidenceCollector("dataset")
observations = collector.collect(
    [EvidenceIdentifier("email", "former@example.test"),
     EvidenceIdentifier("user_id", "user_123")],
    audit_at="2026-10-01T12:00:00Z",
)
```

Prefer `EvidenceCollector.collect_for_resolution(resolution)`. It requires a
`CONFIRMED` identity and searches all its `identity_relationships`, not just
the request email. The collector does not resolve or merge identities and an
empty identifier list returns no observations.
Manifest paths are constrained to the dataset directory and must exist.

## Normalized evidence contract

Each `EvidenceObservation` retains:

| Field | Meaning |
|---|---|
| `system_id` | Source system parsed from the record, falling back to manifest origin |
| `resource_id` | Resource identifier only when present in the source |
| `data_category` | Record type/collection/category when available |
| `observed_at` | Record/snapshot observation time, or manifest capture time if unavailable |
| `captured_at` | Evidence file capture time from the manifest, kept separate from record dates |
| `identifiers_found` | Exact supplied current/historical identifiers that matched |
| `source_evidence_id` | Manifest `file_id`; never synthesized |
| `source_location` | JSON path, CSV row, SQL table/row, text line, PDF page, or OCR location |
| `state` | `PRESENT`, `ABSENT`, `REDACTED`, `ANONYMIZED`, `ACTIVE`, `BLOCKED`, `DISABLED`, or `UNKNOWN` |
| `temporal_basis` | `HISTORICAL`, `AT_AUDIT`, `AFTER_AUDIT`, or `UNKNOWN` |
| `is_operation_attempt` | Marks operational events that do not establish resource state |
| `attributes` | Small, allowlisted status fields or a bounded text excerpt |

`PRESENT` means the source contains an identifier-bearing record or an explicit
positive readback. `ABSENT` is emitted only for explicit negative lookup results
such as `NOT_FOUND`, a miss, or an HTTP 404 readback. A start, retry, queued
operation, success claim, or lack of a matching record is not proof of absence;
those remain `UNKNOWN`. Operation attempts are marked and are never converted
to a presence/absence finding by the collector.

`REDACTED` and `ANONYMIZED` are explicit treatment observations; they do not by
themselves prove that every policy-required identifier was removed.
`ACTIVE`, `BLOCKED`, and `DISABLED` represent explicitly parsed process/access
states and are used for flow or restore analysis, not as record-presence
states. The state reconstructor independently excludes operation-attempt
observations when evaluating resource outcomes.

Only an observation timestamp exactly equal to `audit_at` is tagged
`AT_AUDIT`. Earlier observations remain `HISTORICAL` and later ones
`AFTER_AUDIT`. Evidence files captured after `audit_at` are always tagged
`AFTER_AUDIT`, even when they contain an older event date; later-captured
evidence cannot establish the earlier state. The collector does not project an
older result forward to the audit cutoff. A missing record is never
synthesized as an `ABSENT` record.

## Supported adapters

The adapters cover formats present in the supplied evidence manifest, plus
CSV and JSON Lines for reusable inputs:

- **JSON / JSON Lines:** recursively visits objects and records JSON paths;
  understands common system, resource, category, timestamp, and identity field
  names across snapshot bundles, service-resource exports, and report records.
- **CSV:** reads each data row with its row number as provenance.
- **Logs / text:** processes one bounded line at a time, extracting timestamps,
  common key/value fields, identifiers, explicit lookup results, and resource
  IDs. It does not interpret an operation start as a result.
- **SQLite-compatible SQL snapshots:** loads into an isolated in-memory
  database. SQLite's authorizer limits script operations to table/index
  creation, inserts, transactions, and the `foreign_keys` pragma. `ATTACH`,
  extension loading, arbitrary functions, and other SQL operations are denied.
  JSON-text record payloads are expanded for identifier matching while table
  and row provenance is retained.
- **PDF:** extracts page text locally with PyMuPDF (`fitz`, optional) and
  records matching text with page provenance.
- **Images:** runs local OCR through Pillow and `pytesseract` when both Python
  packages and a local Tesseract executable are available. It does not upload
  screenshots or invent OCR results. If OCR is unavailable, the collector logs
  a sanitized parser failure and that image contributes no observations.

Parsing results are cached in-process by resolved file path, modification time,
size, manifest evidence ID, and capture timestamp. Cache entries contain only
deterministically parsed record structures. File-size limits and bounded
excerpts limit accidental over-retrieval.

## Failure handling and privacy

Malformed or unsupported evidence is logged with only its manifest evidence ID
and exception type. Personal values and exception messages are not logged.
Failures do not create positive or negative records. Untrusted evidence text is
treated solely as data: embedded instructions are never evaluated. No LLM is
called by these adapters.

This module performs evidence discovery and normalization only. It does not
classify deletion status, apply deletion rules, decide authorization, or claim
that an operation succeeded.
