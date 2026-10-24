# Data Dictionary

## Conventions

The CSVs are UTF-8 text and were read with Python's `csv.DictReader`. CSV cells are strings; timestamp fields are ISO-8601 UTC strings ending in `Z`, not parsed/native datetime columns. No empty CSV cells were found. The template `dataset/output.csv` has a header and no data rows. The root submission output was absent at analysis time.

## Input CSVs

### `dataset/deletion_requests.csv` — 518 rows

| Column | Observed type / meaning | Nonempty distinct values | Verified notes |
|---|---|---:|---|
| `case_id` | String identifier | 518 | Unique per request. |
| `email` | String email supplied with request | 517 | One value is repeated across two requests; includes current and historical values. |
| `requested_at` | UTC ISO-8601 string | 508 | Range: 2026-01-05T06:00:00Z–2026-09-24T08:00:00Z. |
| `reported_status` | Categorical string | 3 | `COMPLETE`, `PARTIALLY_COMPLETE`, `NOT_STARTED`; counts 254, 152, 112. |
| `reported_at` | UTC ISO-8601 string | 238 | Range: 2026-01-06T06:00:00Z–2026-09-26T02:00:00Z. |
| `audit_at` | UTC ISO-8601 string | 72 | Range: 2026-01-29T12:00:00Z–2026-10-01T12:00:00Z; state cutoff. |
| `request_text` | Free-text string | 375 | Nonempty; language and wording vary. |

Every request satisfies `requested_at <= reported_at` and `requested_at <= audit_at`. Do not treat `reported_status` as the audited status.

### `dataset/sample_deletion_requests.csv` — 32 rows

Has the same seven columns and types as the full request file. `case_id` and `email` are unique within this sample. All 32 request texts are distinct. Timestamp distinct counts are 30 (`requested_at`), 22 (`reported_at`), and 13 (`audit_at`). The sample spans 2026-08-17T12:00:00Z–2026-09-13T11:00:00Z in `requested_at`, 2026-08-19T12:00:00Z–2026-09-15T11:00:00Z in `reported_at`, and 2026-09-03T11:30:00Z–2026-10-01T12:00:00Z in `audit_at`.

### `dataset/user_identities.csv` — 850 rows

| Column | Observed type / meaning | Distinct | Verified notes |
|---|---|---:|---|
| `user_id` | String stable subject identifier | 850 | Unique. |
| `name` | String display/legal name | 847 | Three repeated values; not a unique key. |
| `email` | String current email | 850 | Unique in this snapshot. |
| `phone` | String phone number | 850 | Unique in this snapshot. |
| `email_hash` | String hash/identifier | 850 | Unique in this snapshot. |
| `updated_at` | UTC ISO-8601 string | 850 | Unique; range: 2023-06-22T10:59:00Z–2026-08-30T01:02:00Z. |

### `dataset/user_audit_log.csv` — 306 rows

| Column | Observed type / meaning | Distinct | Verified notes |
|---|---|---:|---|
| `audit_id` | String audit-row identifier | 306 | Unique. |
| `user_id` | String subject key | 196 | 196 users; all exist in `user_identities.csv`. |
| `event_time` | UTC ISO-8601 string | 198 | Range: 2024-12-14T16:31:44Z–2026-06-03T08:42:31Z. |
| `field_name` | Categorical string | 3 | `email` (107 rows), `email_hash` (107), `phone` (92). |
| `old_value` | String prior field value | 306 | Unique in this file. |
| `new_value` | String replacement field value | 306 | Unique in this file. |

Email audit rows involve 105 distinct users. For joining a request email, both old and new audited email values are relevant; the audit log is not a complete log of name changes.

### `dataset/system_activity.csv` — 4,011 rows

| Column | Observed type / meaning | Distinct | Verified notes |
|---|---|---:|---|
| `activity_id` | String event identifier | 4,011 | Unique. |
| `event_time` | UTC ISO-8601 string | 4,011 | Range: 2026-01-04T14:56:29Z–2026-10-01T10:18:34Z. |
| `event_type` | Categorical string | 17 | See event values below. |
| `source_system` | Categorical string | 11 | See system values below. |
| `target_system` | Categorical string | 19 | See system values below. |
| `resource_id` | String resource reference | 3,948 | 63 IDs recur; not unique per event. |
| `reported_result` | Categorical string | 3 | `SUCCESS` (2,914), `FAILED` (721), `PARTIAL` (376). Claims, not resource-state proof. |
| `details` | Free-text string | 4,011 | Unique text per row; may contain identity/resource references. |

Observed `event_type` values: `ANONYMIZE_RECORD`, `BLOCK_RESTORE`, `CHECK_DATA_FLOW`, `CHECK_RESTORE_ACCESS`, `CLASSIFY_REQUEST`, `CREATE_EXPORT`, `DELETE_RECORD`, `DISABLE_DATA_FLOW`, `INDEX_RECORD`, `LINK_RESOURCE_IDENTITY`, `REDACT_RECORD`, `REFRESH_CACHE`, `RESTORE_BACKUP`, `RETAIN_RECORD`, `SEND_EMAIL`, `SYNC_RECORD`, `UPDATE_RECORD`.

Observed `source_system` values: `account_service`, `backup_service`, `data_catalog`, `deletion_worker`, `export_service`, `integration_service`, `notification_service`, `privacy_intake`, `profile_service`, `security_service`, `support_platform`.

Observed `target_system` values: `account_failover_replica`, `account_replication_cluster`, `account_service`, `analytics_platform`, `archive_service`, `backup_service`, `cache_service`, `email_delivery_service`, `export_service`, `identity_service`, `integration_service`, `legal_service`, `marketing_platform`, `object_storage`, `object_store`, `privacy_case_management`, `search_service`, `security_service`, `support_platform`.

### `dataset/deletion_rules.csv` — 15 rows

| Column | Observed type / meaning | Distinct | Verified notes |
|---|---|---:|---|
| `rule_id` | String rule identifier | 15 | Unique (`rule_01`–`rule_15`). |
| `data_category` | Categorical string | 15 | Unique category per row. |
| `condition` | String policy condition | 9 | Conditions are shared across categories. |
| `required_action` | Categorical string | 4 | `DELETE`, `REDACT`, `ANONYMIZE`, `RETAIN`. |

Categories are `ACCOUNT_TOMBSTONE`, `ANALYTICS_PROFILE`, `BACKUP_ARCHIVE`, `CACHE_ENTRY`, `EMAIL_DELIVERY_LOG`, `LEGAL_HOLD_RECORD`, `MARKETING_PROFILE`, `PRODUCT_TELEMETRY`, `SEARCH_INDEX_ENTRY`, `SECONDARY_IDENTIFIER`, `SECURITY_AUDIT_LOG`, `SUPPORT_ATTACHMENT`, `SUPPORT_MESSAGE`, `USER_EXPORT`, and `USER_PROFILE`. Read the actual condition/action row before deciding treatment.

### `dataset/evidence_files.csv` — 94 rows

| Column | Observed type / meaning | Distinct | Verified notes |
|---|---|---:|---|
| `file_id` | String evidence identifier | 94 | Unique; e.g. `evidence_01`–`evidence_94`. |
| `file_path` | Relative path string | 94 | Unique; every referenced file exists. |
| `origin` | Categorical source string | 30 | Repeated across many files. |
| `captured_at` | UTC ISO-8601 string | 93 | Range: 2026-01-29T11:44:59Z–2026-10-01T12:00:00Z. |

The manifest has no user/case key. The CSV is the authoritative map from `file_id` to path, origin, and capture time.

### `dataset/sample_output.csv` — 32 rows

| Column | Observed type / meaning | Distinct | Verified notes |
|---|---|---:|---|
| `case_id` | String request key | 32 | Exactly covers sample request IDs; sorted. |
| `deletion_status` | Categorical string | 2 | `COMPLETE` (10), `INCOMPLETE` (22); no `NOT_APPLICABLE` example. |
| `steps_json` | JSON text containing an array | 32 | Valid arrays; 1–14 steps per row, 193 total. |

Each step contains exactly `step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id`. The 193 sample steps passed consecutive numbering, allowed phase/operation ordering, and provenance checks. All sample references are manifest file IDs. `COMPLETE` steps cite evidence and are verification-only. For `INCOMPLETE`, findings cite evidence; remediation and post-remediation verification use an empty `evidence_id`.

### `dataset/output.csv` — empty reference template

Header: `case_id,deletion_status,steps_json`; zero data rows. Do not write generated predictions into this supplied dataset file.

## Evidence-specific schemas

### JSON

JSON is heterogeneous; these are observed family-level structures, not one global schema:

- **12 snapshot bundles:** root keys `exported_at`, `source`, `snapshots`; 116 snapshot objects. Each snapshot has `captured_at`, `collection`, `data_store`, and `records`. Record collections include profile, search, analytics, support, export, connector, backup, audit, and legal-retention shapes.
- **11 service-resource exports:** root `exported_at`, `region`, `service_exports`, `source`; service sections for account, analytics, backup, export, integration, search, security, and support.
- **Three record-oriented reports/ledgers:** records commonly have `record_type`, `recorded_at`, `resource_id`, `result`, `subject_reference`, and `system`.
- **Analytics report:** `captured_at`, `collection`, `records`, `source`; its two records include user identifiers and profile/activity fields.
- **Export-job report:** `captured_at`, `collection`, `records`, `source`; two records include resource ID, owner email, file name, availability, expiry, and included sections.

Inspect each file's actual keys and records; do not coerce these families into a guessed common record schema.

### SQLite-compatible SQL

All 24 `.sql` files were parsed in memory. All tables use SQLite declarations such as `TEXT` and `INTEGER`.

- **11 customer-data inventory captures** have a `snapshot_scope(origin_system TEXT PRIMARY KEY, captured_at TEXT NOT NULL)` plus service tables: `customer_profiles`, `customer_search_documents`, `customer_analytics_profiles`, `support_records`, `customer_exports`, `connector_subscriptions`, `backup_restore_entries`, and `security_audit_records`. Their schemas expose resource IDs, customer references/direct identifiers, status or policy fields, and update timestamps.
- **Read/reporting/regional data snapshots** use `customer_data_primary(resource_id, origin_system, collection_name, record_json, updated_at)` and matching replica tables (`customer_data_read_replica`, `customer_data_reporting_replica`, or two regional replica tables). Each listed column is `TEXT`.
- **Failover data snapshot:** primary and failover tables use the same five-field generic schema; record payloads are JSON text.
- **Account failover snapshot:** `customer_profiles_primary` and `customer_profiles_failover_replica` have `resource_id`, `user_id`, `full_name`, `email`, `phone`, `account_status`, and `updated_at` columns (all `TEXT`).
- **Search-primary snapshot:** `search_documents_primary` has `resource_id`, `display_name`, `email`, `source_resource_id`, and `indexed_at` columns (all `TEXT`).

Replica filenames and table names identify the capture topology, but row equality must be checked from each snapshot. Snapshot scope and embedded `updated_at` values are separate timestamps.

### Logs, plain text, PDFs, and images

- 26 `.log` files use several line conventions. Timestamps and relevant fields such as service, event, trace, resource, subject, and matched identifier are generally embedded in text; parse each layout explicitly.
- The 46-line TXT handover uses delimited timestamp/system/resource/category/result/reference lines.
- Four PDFs are text-extractable business records with different document layouts, not tabular CSV schemas. Preserve page/document provenance and distinguish record dates from file metadata.
- Eleven PNG screenshots are human-readable UI captures, not structured tables. Pillow reports RGB images; no OCR engine is installed, so machine OCR output is not currently available.

## Relationship map

```text
deletion_requests.email
  ├── user_identities.email (current snapshot)
  └── user_audit_log.old_value/new_value where field_name = "email"
         └── user_audit_log.user_id → user_identities.user_id

system_activity.resource_id / details
  └── evidence contents (resource and identifier correlations; no direct FK)

evidence_files.file_id
  └── evidence_files.file_path → supplied evidence file

sample_output.case_id
  └── sample_deletion_requests.case_id
```

The request-to-email join is verified for this dataset as described above; evidence matching remains per-record and time-bounded. Do not infer joins from names or file-manifest rows alone.
