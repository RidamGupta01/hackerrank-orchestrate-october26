# Dataset Analysis

## Scope and method

Inspected every CSV in `dataset/`, the sample output JSON payloads, every manifest entry and path, all 28 JSON files, all 24 SQL exports, all 26 logs, the single text file, all 4 PDFs, and all 11 PNG screenshots. CSV structure and relationships were profiled with Python's CSV/date parsers; JSON was parsed with the standard library; SQL was parsed into isolated in-memory SQLite databases after checking that the scripts contain only `CREATE`, `INSERT`, transaction, and `PRAGMA` statements; PDFs were text-extracted with `pypdf`; screenshots were opened and visually inspected, with dimensions read using Pillow. No source dataset file was edited.

The supplied CSV values are text at the CSV layer. Every nonempty timestamp field inspected is ISO-8601 UTC text ending in `Z`. All CSV fields in the inspected files have zero empty values except that the two output templates have zero data rows.

## Files, schemas, and row counts

| File | Rows | Verified header |
|---|---:|---|
| `deletion_requests.csv` | 518 | `case_id,email,requested_at,reported_status,reported_at,audit_at,request_text` |
| `sample_deletion_requests.csv` | 32 | Same as deletion requests |
| `sample_output.csv` | 32 | `case_id,deletion_status,steps_json` |
| `user_identities.csv` | 850 | `user_id,name,email,phone,email_hash,updated_at` |
| `user_audit_log.csv` | 306 | `audit_id,user_id,event_time,field_name,old_value,new_value` |
| `system_activity.csv` | 4,011 | `activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details` |
| `deletion_rules.csv` | 15 | `rule_id,data_category,condition,required_action` |
| `evidence_files.csv` | 94 | `file_id,file_path,origin,captured_at` |
| `output.csv` (dataset template) | 0 | `case_id,deletion_status,steps_json` |

The root-level submission `output.csv` was not present during inspection. The dataset template contains its header only.

## Identifiers and relationships

- `case_id`, `user_id`, `audit_id`, `activity_id`, `rule_id`, and `file_id` are nonempty string identifiers. The request, identity, audit, activity, rule, and evidence-manifest primary identifiers are unique within their respective files.
- There are 850 unique current `user_id` values. All 196 distinct `user_id` values in the identity audit log exist in the current identity snapshot.
- The 518 request email values match exactly one user when current identity emails and old/new email values in email audit rows are considered together. 418 request rows match a current email; 100 match historical email values only. The requests resolve to 517 distinct users because one email is repeated across two requests. No request email maps to multiple user IDs in this join.
- Email changes appear in 107 audit rows associated with 105 users. The other audited identity fields are `phone` and `email_hash`; the three observed `field_name` values are exactly `email`, `email_hash`, and `phone`.
- `activity_id` is unique in the 4,011-row global activity stream. It contains 3,948 distinct `resource_id` values; 63 resource IDs occur more than once, so resource IDs are not event primary keys. Activity rows are not directly keyed by `case_id`.
- The evidence manifest has 94 unique `file_id` values and 94 unique paths; every referenced path exists. Its `origin` has 30 distinct values. It does not provide a case/user foreign key.
- The request and sample `case_id` sets are distinct within each file. Sample output IDs exactly match the 32 sample request IDs and are sorted.

## Time ranges and temporal relationships

All timestamps below were parsed as UTC:

| File / field | Minimum | Maximum |
|---|---|---|
| Requests `requested_at` | 2026-01-05T06:00:00Z | 2026-09-24T08:00:00Z |
| Requests `reported_at` | 2026-01-06T06:00:00Z | 2026-09-26T02:00:00Z |
| Requests `audit_at` | 2026-01-29T12:00:00Z | 2026-10-01T12:00:00Z |
| Identity `updated_at` | 2023-06-22T10:59:00Z | 2026-08-30T01:02:00Z |
| Audit `event_time` | 2024-12-14T16:31:44Z | 2026-06-03T08:42:31Z |
| Activity `event_time` | 2026-01-04T14:56:29Z | 2026-10-01T10:18:34Z |
| Manifest `captured_at` | 2026-01-29T11:44:59Z | 2026-10-01T12:00:00Z |

For all 518 requests, `requested_at <= reported_at` and `requested_at <= audit_at`; no ordering violations were found. Each decision still needs its own `audit_at` cutoff: later activity, evidence, or identity changes cannot be projected backward.

All four PDFs have a PDF metadata creation time of `2026-10-23 12:45:12 +05:00`, while their manifest `captured_at` values differ and are earlier. The PDFs contain record-specific dates as well. Do not silently equate PDF-generation metadata, an event date in its body, and the manifest capture time; retain their distinct meanings and use the relevant, supported timestamp for the claim being made.

## Sample requests compared with sample outputs

- The 32 output rows cover exactly the 32 sample requests in ascending `case_id` order.
- Sample statuses are 10 `COMPLETE` and 22 `INCOMPLETE`; no sample is `NOT_APPLICABLE`.
- There are 193 total steps. Each step has exactly the seven required fields, consecutive `step_no` values, valid JSON arrays, and phases/operations in the required ordering. Every sample passed these structural and ordering checks.
- All nonempty sample `evidence_id` values resolve to a manifest `file_id`; the sample uses file citations rather than activity/audit IDs. Findings cite evidence. `COMPLETE` rows contain verification-only steps with citations. `INCOMPLETE` remediation and future verification steps have empty citations.
- Reported workflow state is not a reliable answer: among the sample requests, 11 reported `COMPLETE` cases are `INCOMPLETE` in the supplied answer, and 3 reported `NOT_STARTED` cases are `COMPLETE`.
- The sample exercises remaining profiles, search entries, support records, exports, exposed PII, analytics, active integrations, restore risks, retained audit records, and account tombstones. Cases 31–32 demonstrate that a tombstone can require redaction rather than deletion. A request explicitly warns that a similar email belongs to another person, making exact identity correlation important.
- Sample cases include multilingual requests (including Spanish, French, and Japanese) and historical email references. The sample alone does not cover every request-intent or ambiguity category.

## Evidence format and structure findings

There are 94 manifest-backed evidence files: 28 JSON, 26 `.log`, 24 SQLite-compatible `.sql`, 11 PNG, 4 PDF, and 1 TXT. They are distributed among `evidence/records/`, `evidence/logs/`, `evidence/databases/`, `evidence/images/`, and `evidence/documents/`. Full paths, capture timestamps, origins, and formats are listed in [evidence_inventory.md](./evidence_inventory.md).

- **JSON (28):** machine-readable but not one uniform schema. Includes 12 snapshot bundles (116 snapshot objects), 11 service-resource exports, three record-oriented assurance/export/security files, and two small analytics/export-job reports. Record arrays identify systems, resource IDs, types, subjects, results, and timestamps in varying shapes. Service-resource exports contain eight service families: account, analytics, backup, export, integration, search, security, and support.
- **SQL (24):** readable SQLite-compatible snapshots with primary, read, regional, reporting, and failover data. Some use normalized service-specific tables; others use generic `resource_id`, `origin_system`, `collection_name`, `record_json`, and `updated_at` tables. Replica exports include multiple snapshots/tables that must be compared rather than assumed identical. The search-primary export and account failover export have their own schemas.
- **Logs (26):** text logs with several incompatible layouts (key/value, pipe-delimited, bracketed level/service/trace, and simple service-event lines). Timestamps and identifiers are embedded in free text, and many files include unrelated operational events. Treat lines as evidence claims and filter by time and corroborating identifiers.
- **PDFs (4):** text extraction succeeds. They are business documents: a customer/order history statement, a legal retention register, a signed security/compliance record extract, and a support delivery-correction attachment. Their page counts are 2, 2, 1, and 2 respectively.
- **Screenshots (11):** all are RGB PNGs, 1500–1800 pixels wide and 920–1200 pixels high. They show account administration, search, connector, analytics, export, support, backup, security audit, deleted-account reference, object storage, and marketing screens. They were visually inspected; this workspace has no installed OCR engine. Automated OCR accuracy and extraction are therefore unverified.
- **Text (1):** a 46-line account-service shift-handover record with timestamped resource/system/status entries.

## Ambiguities and evaluation pitfalls

1. Manifest membership is not a case/user join. Establish links from file contents and corroborating identifiers; resource IDs recur in activity and evidence, while activity resource IDs are not unique.
2. The global activity stream records `SUCCESS`, `FAILED`, and `PARTIAL` results, but those are activity claims, not proof of current state. Evidence includes unrelated users and decoy records.
3. Captured files can contain internal event timestamps, snapshot timestamps, export timestamps, and later metadata timestamps. Use the timestamp that actually describes the observation and honor the request cutoff.
4. Current identity snapshots do not suffice for 100 requests whose supplied email only matches an audited historical email.
5. Request emails include a repeated value and can be historical; screenshots/logs may show case changes or similar addresses. A naive name/substring match can join the wrong person.
6. Shared support conversations, legal holds, retention periods, analytics attribution, and account tombstones require applying the supplied policy condition, not a category-only delete rule.
7. Replica snapshots may disagree with primary data. Checking a primary only can miss a copy or a path that can recreate it.
8. The sample has no `NOT_APPLICABLE` case and is not a complete intent-classification test set.

## Not implemented / not established

No prediction code, evidence parser, OCR pipeline, automated evaluation suite, or model/agent configuration existed at inspection time. Evidence classification above documents file structure and observed content types; it is not a generated list of case-to-evidence truth. Hidden canonical answers and organizer-only data were not inspected.
