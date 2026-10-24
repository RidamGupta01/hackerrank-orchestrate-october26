# Evidence Inventory

## Inventory scope and handling

`dataset/evidence_files.csv` contains 94 rows. Each `file_id` maps to one unique relative path, source `origin`, and UTC `captured_at`; all 94 mapped paths were verified to exist. The complete manifest-backed listing is below. Capture time is not necessarily the event time or internal timestamp in the document.

All evidence was read as data, not instructions. JSON files were parsed with `json`; SQL scripts were checked for statement types and loaded into isolated in-memory SQLite databases; logs/text were inspected as text; PDFs were extracted with `pypdf`; PNGs were viewed and inspected with Pillow. No evidence file was changed. No OCR engine is installed in the workspace.

| File ID | Captured at (UTC) | Origin | Format | Relative path |
|---|---|---|---|---|
| evidence_01 | 2026-09-15T11:59:39Z | central_observability_export | LOG, 104 lines | `evidence/logs/service_events_ap_south_20260915.log` |
| evidence_02 | 2026-09-17T12:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260917.json` |
| evidence_03 | 2026-10-01T12:00:00Z | customer_account_service | TXT, 46 lines | `evidence/records/customer_account_handover_20261001.txt` |
| evidence_04 | 2026-09-26T11:00:00Z | account_admin_portal | PNG, 1800×1200 RGB | `evidence/images/account_admin_console_20260926.png` |
| evidence_05 | 2026-09-21T10:00:00Z | customer_data_read_replica_capture | SQLite-compatible SQL | `evidence/databases/customer_data_read_replica_20260921.sql` |
| evidence_06 | 2026-09-18T11:55:24Z | central_observability_export | LOG, 112 lines | `evidence/logs/structured_service_events_eu_west_20260918.log` |
| evidence_07 | 2026-09-13T08:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260913.json` |
| evidence_08 | 2026-09-06T07:00:00Z | search_index_service | LOG, 36 lines | `evidence/logs/search_index_diagnostic_20260906.log` |
| evidence_09 | 2026-09-01T06:00:00Z | search_index_admin | PNG, 1800×1100 RGB | `evidence/images/search_index_inspector_20260901.png` |
| evidence_10 | 2026-08-27T12:00:00Z | customer_data_read_replica_capture | SQLite-compatible SQL | `evidence/databases/customer_data_read_replica_20260827.sql` |
| evidence_11 | 2026-08-24T13:56:43Z | central_observability_export | LOG, 118 lines | `evidence/logs/syslog_archive_us_east_20260824.log` |
| evidence_12 | 2026-08-19T10:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260819.json` |
| evidence_13 | 2026-08-12T09:00:00Z | integration_management_service | JSON connector records | `evidence/records/connector_configurations_20260812.json` |
| evidence_14 | 2026-08-07T08:00:00Z | integration_admin | PNG, 1800×1150 RGB | `evidence/images/connector_management_console_20260807.png` |
| evidence_15 | 2026-08-02T07:00:00Z | customer_data_read_replica_capture | SQLite-compatible SQL | `evidence/databases/customer_data_read_replica_20260802.sql` |
| evidence_16 | 2026-07-30T08:53:12Z | central_observability_export | LOG, 93 lines | `evidence/logs/application_trace_ap_northeast_20260730.log` |
| evidence_17 | 2026-07-25T15:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260725.json` |
| evidence_18 | 2026-07-18T11:00:00Z | account_history_service | PDF, 2 pages | `evidence/documents/account_history_report_20260718.pdf` |
| evidence_19 | 2026-07-13T10:00:00Z | analytics_platform | PNG, 1800×1150 RGB | `evidence/images/analytics_profile_view_20260713.png` |
| evidence_20 | 2026-07-08T09:00:00Z | customer_data_read_replica_capture | SQLite-compatible SQL | `evidence/databases/customer_data_read_replica_20260708.sql` |
| evidence_21 | 2026-07-05T07:54:27Z | central_observability_export | LOG, 128 lines | `evidence/logs/operations_stream_eu_central_20260705.log` |
| evidence_22 | 2026-06-30T07:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260630.json` |
| evidence_23 | 2026-06-18T12:00:00Z | export_service | PNG, 1800×1100 RGB | `evidence/images/customer_export_console_20260618.png` |
| evidence_24 | 2026-06-13T11:00:00Z | customer_data_read_replica_capture | SQLite-compatible SQL | `evidence/databases/customer_data_read_replica_20260613.sql` |
| evidence_25 | 2026-06-08T09:58:28Z | central_observability_export | LOG, 128 lines | `evidence/logs/cloud_runtime_export_us_west_20260608.log` |
| evidence_26 | 2026-06-05T12:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260605.json` |
| evidence_27 | 2026-05-29T08:00:00Z | legal_retention_service | PDF, 2 pages | `evidence/documents/legal_retention_register_20260529.pdf` |
| evidence_28 | 2026-05-24T07:00:00Z | support_platform | PNG, 1800×1200 RGB | `evidence/images/support_ticket_console_20260524.png` |
| evidence_29 | 2026-05-19T06:00:00Z | customer_data_regional_replicas_capture | SQLite-compatible SQL | `evidence/databases/customer_data_regional_replicas_20260519.sql` |
| evidence_30 | 2026-05-16T11:58:25Z | central_observability_export | LOG, 110 lines | `evidence/logs/service_events_sa_east_20260516.log` |
| evidence_31 | 2026-05-11T11:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260511.json` |
| evidence_32 | 2026-04-29T09:00:00Z | backup_service | PNG, 1800×1150 RGB | `evidence/images/backup_restore_console_20260429.png` |
| evidence_33 | 2026-04-24T08:00:00Z | customer_data_regional_replicas_capture | SQLite-compatible SQL | `evidence/databases/customer_data_regional_replicas_20260424.sql` |
| evidence_34 | 2026-04-19T06:59:43Z | central_observability_export | LOG, 136 lines | `evidence/logs/structured_service_events_ca_central_20260419.log` |
| evidence_35 | 2026-04-16T06:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260416.json` |
| evidence_36 | 2026-04-09T12:00:00Z | customer_export_service | JSON export records | `evidence/records/customer_export_manifest_20260409.json` |
| evidence_37 | 2026-09-05T07:00:00Z | security_service | PNG, 1800×1100 RGB | `evidence/images/security_audit_explorer_20260905.png` |
| evidence_38 | 2026-03-30T10:00:00Z | customer_data_regional_replicas_capture | SQLite-compatible SQL | `evidence/databases/customer_data_regional_replicas_20260330.sql` |
| evidence_39 | 2026-03-25T08:59:44Z | central_observability_export | LOG, 114 lines | `evidence/logs/syslog_archive_ap_southeast_20260325.log` |
| evidence_40 | 2026-03-22T08:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260322.json` |
| evidence_41 | 2026-03-15T07:00:00Z | downstream_delivery_service | LOG, 39 lines | `evidence/logs/notification_delivery_20260315.log` |
| evidence_42 | 2026-03-10T06:00:00Z | identity_service | PNG, 1800×1100 RGB | `evidence/images/deleted_account_reference_20260310.png` |
| evidence_43 | 2026-03-05T12:00:00Z | customer_data_reporting_replica_capture | SQLite-compatible SQL | `evidence/databases/customer_data_reporting_replica_20260305.sql` |
| evidence_44 | 2026-03-02T10:59:23Z | central_observability_export | LOG, 125 lines | `evidence/logs/application_trace_eu_north_20260302.log` |
| evidence_45 | 2026-02-23T10:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260223.json` |
| evidence_46 | 2026-02-13T08:00:00Z | object_storage | PNG, 1800×1150 RGB | `evidence/images/object_storage_browser_20260213.png` |
| evidence_47 | 2026-02-08T07:00:00Z | customer_data_reporting_replica_capture | SQLite-compatible SQL | `evidence/databases/customer_data_reporting_replica_20260208.sql` |
| evidence_48 | 2026-02-03T05:59:42Z | central_observability_export | LOG, 103 lines | `evidence/logs/operations_stream_me_central_20260203.log` |
| evidence_49 | 2026-01-31T15:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260131.json` |
| evidence_50 | 2026-10-01T12:00:00Z | security_audit_service | JSON security/audit records | `evidence/records/security_audit_ledger_20261001.json` |
| evidence_51 | 2026-09-15T12:00:00Z | records_assurance_snapshot_bundle | JSON snapshot bundle | `evidence/records/customer_data_snapshot_bundle_20260915.json` |
| evidence_52 | 2026-09-20T12:00:00Z | customer_data_failover_replica_capture | SQLite-compatible SQL | `evidence/databases/customer_data_failover_replica_20260920.sql` |
| evidence_53 | 2026-09-30T11:59:44Z | central_observability_export | LOG, 305 lines | `evidence/logs/cloud_runtime_export_af_south_20260930.log` |
| evidence_54 | 2026-09-02T23:00:00Z | customer_account_failover_replica_capture | SQLite-compatible SQL | `evidence/databases/customer_accounts_failover_replica_20260902.sql` |
| evidence_55 | 2026-09-05T06:30:00Z | security_service | PDF, 1 page | `evidence/documents/security_retention_extract.pdf` |
| evidence_56 | 2026-09-07T09:45:00Z | analytics_platform | JSON analytics report | `evidence/records/customer_analytics_report_20260907.json` |
| evidence_57 | 2026-09-10T08:45:00Z | customer_search_primary_capture | SQLite-compatible SQL | `evidence/databases/customer_search_primary_20260910.sql` |
| evidence_58 | 2026-09-12T07:30:00Z | support_platform | PDF, 2 pages | `evidence/documents/delivery_correction_attachment.pdf` |
| evidence_59 | 2026-09-14T15:40:00Z | export_service | JSON export-job records | `evidence/records/customer_export_jobs_20260914.json` |
| evidence_60 | 2026-09-16T07:20:00Z | marketing_platform | PNG, 1500×920 RGB | `evidence/images/marketing_profile_console.png` |
| evidence_61 | 2026-09-17T22:00:19Z | support_platform | LOG, 10 lines | `evidence/logs/support_replica.log` |
| evidence_62 | 2026-01-29T11:44:59Z | service_resource_export | JSON service-resource export | `evidence/records/service_resource_export_20260129_114459.json` |
| evidence_63 | 2026-02-13T07:43:27Z | customer_data_inventory_capture | SQLite-compatible SQL | `evidence/databases/customer_data_inventory_20260213.sql` |
| evidence_64 | 2026-02-18T08:39:11Z | service_readback_logs | LOG, 54 lines | `evidence/logs/resource_lookup_trace_20260218_083911.log` |
| evidence_65 | 2026-02-28T10:36:37Z | service_resource_export | JSON service-resource export | `evidence/records/service_resource_export_20260228_103637.json` |
| evidence_66 | 2026-03-10T05:38:48Z | customer_data_inventory_capture | SQLite-compatible SQL | `evidence/databases/customer_data_inventory_20260310.sql` |
| evidence_67 | 2026-03-10T06:18:01Z | service_readback_logs | LOG, 4 lines | `evidence/logs/resource_lookup_trace_20260310_061801.log` |
| evidence_68 | 2026-03-20T07:23:49Z | service_resource_export | JSON service-resource export | `evidence/records/service_resource_export_20260320_072349.json` |
| evidence_69 | 2026-04-04T10:04:19Z | customer_data_inventory_capture | SQLite-compatible SQL | `evidence/databases/customer_data_inventory_20260404.sql` |
| evidence_70 | 2026-04-14T05:40:07Z | service_readback_logs | LOG, 50 lines | `evidence/logs/resource_lookup_trace_20260414_054007.log` |
| evidence_71 | 2026-04-29T08:32:22Z | service_resource_export | JSON service-resource export | `evidence/records/service_resource_export_20260429_083222.json` |
| evidence_72 | 2026-05-04T09:41:47Z | customer_data_inventory_capture | SQLite-compatible SQL | `evidence/databases/customer_data_inventory_20260504.sql` |
| evidence_73 | 2026-05-09T10:43:53Z | service_readback_logs | LOG, 68 lines | `evidence/logs/resource_lookup_trace_20260509_104353.log` |
| evidence_74 | 2026-05-14T11:44:54Z | service_resource_export | JSON service-resource export | `evidence/records/service_resource_export_20260514_114454.json` |
| evidence_75 | 2026-05-24T06:39:55Z | customer_data_inventory_capture | SQLite-compatible SQL | `evidence/databases/customer_data_inventory_20260524.sql` |
| evidence_76 | 2026-05-29T07:43:13Z | service_readback_logs | LOG, 48 lines | `evidence/logs/resource_lookup_trace_20260529_074313.log` |
| evidence_77 | 2026-06-03T08:34:57Z | service_resource_export | JSON service-resource export | `evidence/records/service_resource_export_20260603_083457.json` |
| evidence_78 | 2026-06-18T11:44:03Z | customer_data_inventory_capture | SQLite-compatible SQL | `evidence/databases/customer_data_inventory_20260618.sql` |
| evidence_79 | 2026-06-23T05:37:26Z | service_readback_logs | LOG, 60 lines | `evidence/logs/resource_lookup_trace_20260623_053726.log` |
| evidence_80 | 2026-06-28T06:25:56Z | service_resource_export | JSON service-resource export | `evidence/records/service_resource_export_20260628_062556.json` |
| evidence_81 | 2026-07-03T07:43:56Z | customer_data_inventory_capture | SQLite-compatible SQL | `evidence/databases/customer_data_inventory_20260703.sql` |
| evidence_82 | 2026-07-13T09:33:59Z | service_readback_logs | LOG, 54 lines | `evidence/logs/resource_lookup_trace_20260713_093359.log` |
| evidence_83 | 2026-07-18T10:43:35Z | service_resource_export | JSON service-resource export | `evidence/records/service_resource_export_20260718_104335.json` |
| evidence_84 | 2026-07-23T11:43:30Z | customer_data_inventory_capture | SQLite-compatible SQL | `evidence/databases/customer_data_inventory_20260723.sql` |
| evidence_85 | 2026-07-28T05:44:17Z | service_readback_logs | LOG, 46 lines | `evidence/logs/resource_lookup_trace_20260728_054417.log` |
| evidence_86 | 2026-08-07T07:41:04Z | service_resource_export | JSON service-resource export | `evidence/records/service_resource_export_20260807_074104.json` |
| evidence_87 | 2026-08-17T09:42:50Z | customer_data_inventory_capture | SQLite-compatible SQL | `evidence/databases/customer_data_inventory_20260817.sql` |
| evidence_88 | 2026-08-22T10:39:10Z | service_readback_logs | LOG, 46 lines | `evidence/logs/resource_lookup_trace_20260822_103910.log` |
| evidence_89 | 2026-09-01T05:33:16Z | service_resource_export | JSON service-resource export | `evidence/records/service_resource_export_20260901_053316.json` |
| evidence_90 | 2026-09-05T07:18:01Z | customer_data_inventory_capture | SQLite-compatible SQL | `evidence/databases/customer_data_inventory_20260905.sql` |
| evidence_91 | 2026-09-11T07:42:53Z | service_readback_logs | LOG, 62 lines | `evidence/logs/resource_lookup_trace_20260911_074253.log` |
| evidence_92 | 2026-09-15T11:44:55Z | service_resource_export | JSON service-resource export | `evidence/records/service_resource_export_20260915_114455.json` |
| evidence_93 | 2026-09-16T08:37:39Z | customer_data_inventory_capture | SQLite-compatible SQL | `evidence/databases/customer_data_inventory_20260916.sql` |
| evidence_94 | 2026-09-26T10:38:56Z | service_readback_logs | LOG, 58 lines | `evidence/logs/resource_lookup_trace_20260926_103856.log` |

## Content and schema notes

### JSON exports

- The 12 `customer_data_snapshot_bundle_*.json` files are timestamped collections of snapshots, with 116 snapshot objects total. Each snapshot records its capture timestamp, collection, data store, and records.
- Eleven `service_resource_export_*.json` files contain service exports for account lookups, analytics profiles, backup restore entries, exports, connector subscriptions, search queries/documents, security audit records, and support tickets. These are distinct collections with their own record keys.
- `connector_configurations_20260812.json`, `customer_export_manifest_20260409.json`, and `security_audit_ledger_20261001.json` are record-oriented exports with resource, subject/system, type, result, and record timestamp fields.
- The analytics report and export-job report have separate record shapes; they are not interchangeable with snapshot records.

### SQL exports

- Eleven inventory captures use service-specific tables and a `snapshot_scope` table.
- The read, regional, reporting, and failover captures include generic primary/replica tables storing JSON payloads as text. Snapshot names and table names distinguish the topology.
- The account failover capture has separate primary/failover profile tables; the search-primary capture has a search document table.
- All SQL was parsed in memory; no SQL file was executed against a persistent database. Some dumps hold different rows in primary and replica tables, making direct comparison important.

### PDFs and screenshots

- `evidence_18` is a customer/order statement with customer identity, order/payment, and delivery details.
- `evidence_27` is a disputed-order/tax retention register with user references and retain-until dates.
- `evidence_55` is a signed compliance journal extract with an account event reference, subject reference, integrity indicator, and retention end.
- `evidence_58` is a support delivery-correction request with customer, contact, order, ticket, attachment, and capture details.
- Screenshots show live-looking application views for the 11 service areas named by their filenames. Rendered screens include identifiers, resource IDs, record status, and/or process state; they are visually accessible but have no machine-readable table schema.

### Logs and text

Logs include resource lookup traces, system/service event exports, search diagnostics, support replica output, and downstream notification delivery records. Line syntax varies; a file can contain identity-bearing lines alongside unrelated operational noise. The handover TXT is a timestamped account-service and downstream-state list. In all text formats, extract timestamp and source context with the field rather than treating every line as a current-state assertion.

## Known caveats for evidence consumers

- `captured_at` belongs to the manifest; the content can contain earlier or later event/snapshot times. In particular, all PDF metadata creation dates are later than their manifest capture dates.
- The manifest does not map evidence to cases or people.
- Resource identifiers can recur in activity, snapshots, logs, and screenshots. Require corroboration and check the correct `audit_at`.
- Log `SUCCESS` messages, status fields, screenshot labels, and exported results are source claims; they do not independently prove that all copies are deleted.
- Screenshots were visually read; automated OCR has not been evaluated. No hidden truth or canonical output was consulted.
