import csv
import unittest
from datetime import datetime, timezone
from pathlib import Path

from src.activity_analyzer import ActivityAnalyzer, ProcessState
from src.evidence_models import (
    EvidenceIdentifier,
    EvidenceObservation,
    RecordState,
    TemporalBasis,
)
from src.identity_resolver import IdentityResolver

PROJECT_DIR = Path(__file__).resolve().parents[1]
DATASET_DIR = PROJECT_DIR / "dataset"


def activity(
    activity_id: str,
    event_time: str,
    event_type: str,
    resource_id: str,
    *,
    result: str = "SUCCESS",
    target: str = "integration_service",
    details: str = "operation logged",
) -> dict[str, str]:
    return {
        "activity_id": activity_id,
        "event_time": event_time,
        "event_type": event_type,
        "source_system": "deletion_worker",
        "target_system": target,
        "resource_id": resource_id,
        "reported_result": result,
        "details": details,
    }


def evidence(
    resource_id: str,
    *,
    evidence_id: str = "evidence_test",
    observed_at: str = "2026-01-02T00:00:00Z",
    captured_at: str = "2026-01-02T00:00:00Z",
    data_category: str | None = None,
    attributes: dict[str, object] | None = None,
    location: str = "table:records/row:1",
) -> EvidenceObservation:
    observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    captured = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    return EvidenceObservation(
        system_id="integration_service",
        resource_id=resource_id,
        data_category=data_category,
        observed_at=observed,
        captured_at=captured,
        identifiers_found=(EvidenceIdentifier("email", "subject@example.test"),),
        source_evidence_id=evidence_id,
        source_location=location,
        state=RecordState.PRESENT,
        temporal_basis=TemporalBasis.HISTORICAL,
        attributes=attributes or {},
    )


def load_rules() -> list[dict[str, str]]:
    with (DATASET_DIR / "deletion_rules.csv").open(
        encoding="utf-8-sig", newline=""
    ) as stream:
        return list(csv.DictReader(stream))


class ActivityAnalyzerTests(unittest.TestCase):
    def test_activity_stream_loads_and_unlinked_rows_are_not_attributed(self) -> None:
        analyzer = ActivityAnalyzer.from_csv(
            DATASET_DIR / "system_activity.csv",
            rules_path=DATASET_DIR / "deletion_rules.csv",
        )
        report = analyzer.analyze(
            [EvidenceIdentifier("email", "not-in-the-activity-stream@example.test")],
            "2026-10-01T12:00:00Z",
        )
        self.assertEqual(report.events, ())
        self.assertEqual(report.processes, ())

    def test_exact_identifier_association_and_event_time_order(self) -> None:
        analyzer = ActivityAnalyzer(
            [
                activity(
                    "activity_later",
                    "2026-01-04T00:00:00Z",
                    "SYNC_RECORD",
                    "analytics_9",
                    result="SUCCESS",
                    details="Sync completed for subject@example.test",
                ),
                activity(
                    "activity_earlier",
                    "2026-01-02T00:00:00Z",
                    "DELETE_RECORD",
                    "profile_1",
                    result="SUCCESS",
                    details="Submitted unrelatedsubject@example.test",
                ),
                activity(
                    "activity_delete_attempt",
                    "2026-01-02T01:00:00Z",
                    "DELETE_RECORD",
                    "profile_2",
                    result="SUCCESS",
                    details="Deletion worker submitted profile_2 for subject@example.test.",
                ),
                activity(
                    "activity_middle",
                    "2026-01-03T00:00:00Z",
                    "CREATE_EXPORT",
                    "export_2",
                    result="PARTIAL",
                    target="object_store",
                    details="Export queued for SUBJECT@example.test",
                ),
            ]
        )
        report = analyzer.analyze(
            [EvidenceIdentifier("email", "subject@example.test")],
            "2026-01-03T12:00:00Z",
        )

        self.assertEqual(
            [event.activity_id for event in report.events],
            ["activity_delete_attempt", "activity_middle", "activity_later"],
        )
        self.assertEqual(
            [event.temporal_basis for event in report.events],
            [
                TemporalBasis.HISTORICAL,
                TemporalBasis.HISTORICAL,
                TemporalBasis.AFTER_AUDIT,
            ],
        )
        self.assertTrue(all(event.result_is_claim for event in report.events))
        self.assertEqual(report.events[0].execution_stage, "OPERATION_ATTEMPT")
        self.assertEqual(report.events[0].reported_result, "SUCCESS")
        self.assertEqual(report.events[1].reported_result, "PARTIAL")
        self.assertEqual(report.events[1].event_kind, "EXPORT")

    def test_evidence_resource_mapping_correlates_otherwise_unkeyed_activity(self) -> None:
        analyzer = ActivityAnalyzer(
            [
                activity(
                    "activity_sync",
                    "2026-01-03T00:00:00Z",
                    "SYNC_RECORD",
                    "analytics_71",
                    details="Customer profile synchronization processed analytics_71.",
                )
            ]
        )
        report = analyzer.analyze(
            [EvidenceIdentifier("email", "subject@example.test")],
            "2026-01-04T00:00:00Z",
            evidence=[evidence("analytics_71", evidence_id="evidence_link")],
        )

        self.assertEqual(len(report.events), 1)
        self.assertEqual(
            report.events[0].association_basis,
            ("evidence_resource_identifier_correlation",),
        )
        self.assertEqual(report.events[0].corroborating_file_ids, ("evidence_link",))

    def test_explicit_activity_identity_link_is_retained_as_an_unverified_claim(self) -> None:
        analyzer = ActivityAnalyzer(
            [
                activity(
                    "activity_link",
                    "2026-01-02T00:00:00Z",
                    "LINK_RESOURCE_IDENTITY",
                    "analytics_72",
                    target="analytics_platform",
                    details="Catalog linked analytics_72 to subject@example.test and user_88.",
                ),
                activity(
                    "activity_sync",
                    "2026-01-03T00:00:00Z",
                    "SYNC_RECORD",
                    "analytics_72",
                    target="analytics_platform",
                    details="Customer synchronization processed analytics_72.",
                ),
            ]
        )
        report = analyzer.analyze(
            [
                EvidenceIdentifier("email", "subject@example.test"),
                EvidenceIdentifier("user_id", "user_88"),
            ],
            "2026-01-04T00:00:00Z",
        )
        sync = next(event for event in report.events if event.event_type == "SYNC_RECORD")
        self.assertEqual(sync.association_basis, ("activity_identity_link_claim",))
        self.assertEqual(sync.association_activity_ids, ("activity_link",))
        self.assertTrue(sync.result_is_claim)

    def test_process_must_be_explicitly_enabled_in_evidence_to_be_active(self) -> None:
        analyzer = ActivityAnalyzer(
            [
                activity(
                    "activity_flow_check",
                    "2026-01-03T00:00:00Z",
                    "CHECK_DATA_FLOW",
                    "data_flow_18",
                    details=(
                        "Connector status check reports data flow remains enabled "
                        "for subject@example.test."
                    ),
                )
            ]
        )
        report = analyzer.analyze(
            [EvidenceIdentifier("email", "subject@example.test")],
            "2026-01-04T00:00:00Z",
            evidence=[
                evidence(
                    "data_flow_18",
                    captured_at="2026-01-04T00:00:00Z",
                    attributes={"enabled": True},
                    data_category="connector_subscriptions",
                )
            ],
        )

        process = report.processes[0]
        self.assertEqual(process.state, ProcessState.ACTIVE)
        self.assertTrue(process.can_recreate_data)
        self.assertTrue(process.observed_can_recreate_data)
        self.assertEqual(process.state_temporal_basis, TemporalBasis.AT_AUDIT)
        self.assertEqual(process.state_basis, "case_linked_evidence_snapshot")
        self.assertEqual(process.latest_activity_claim, ProcessState.ACTIVE.value)

    def test_unverified_flow_claim_is_not_treated_as_active(self) -> None:
        analyzer = ActivityAnalyzer(
            [
                activity(
                    "activity_flow_check",
                    "2026-01-03T00:00:00Z",
                    "CHECK_DATA_FLOW",
                    "data_flow_18",
                    details=(
                        "Connector status check confirmed data flow remains enabled "
                        "for subject@example.test."
                    ),
                )
            ]
        )
        process = analyzer.analyze(
            [EvidenceIdentifier("email", "subject@example.test")],
            "2026-01-04T00:00:00Z",
        ).processes[0]
        self.assertEqual(process.state, ProcessState.UNKNOWN)
        self.assertIsNone(process.can_recreate_data)
        self.assertEqual(process.state_basis, "activity_claim_only")
        self.assertEqual(process.latest_activity_claim, ProcessState.ACTIVE.value)

    def test_historical_active_flow_is_not_projected_to_audit_time(self) -> None:
        analyzer = ActivityAnalyzer(
            [
                activity(
                    "activity_flow_check",
                    "2026-01-03T00:00:00Z",
                    "CHECK_DATA_FLOW",
                    "data_flow_18",
                    details=(
                        "Connector status check reports data flow remains enabled "
                        "for subject@example.test."
                    ),
                )
            ]
        )
        process = analyzer.analyze(
            [EvidenceIdentifier("email", "subject@example.test")],
            "2026-01-04T00:00:00Z",
            evidence=[
                evidence(
                    "data_flow_18",
                    attributes={"enabled": True},
                    data_category="connector_subscriptions",
                )
            ],
        ).processes[0]
        self.assertEqual(process.state, ProcessState.ACTIVE)
        self.assertEqual(process.state_temporal_basis, TemporalBasis.HISTORICAL)
        self.assertIsNone(process.can_recreate_data)
        self.assertTrue(process.observed_can_recreate_data)

    def test_failed_flow_check_does_not_report_a_process_state_claim(self) -> None:
        analyzer = ActivityAnalyzer(
            [
                activity(
                    "activity_failed_check",
                    "2026-01-03T00:00:00Z",
                    "CHECK_DATA_FLOW",
                    "data_flow_18",
                    result="FAILED",
                    details=(
                        "Connector status check reports data flow remains enabled "
                        "for subject@example.test."
                    ),
                )
            ]
        )
        process = analyzer.analyze(
            [EvidenceIdentifier("email", "subject@example.test")],
            "2026-01-04T00:00:00Z",
        ).processes[0]
        self.assertEqual(process.state, ProcessState.UNKNOWN)
        self.assertIsNone(process.latest_activity_claim)

    def test_disabled_flow_and_restore_block_are_evidence_based(self) -> None:
        rules = load_rules()
        analyzer = ActivityAnalyzer(
            [
                activity(
                    "activity_disable",
                    "2026-01-03T00:00:00Z",
                    "DISABLE_DATA_FLOW",
                    "data_flow_22",
                ),
                activity(
                    "activity_block",
                    "2026-01-03T00:01:00Z",
                    "BLOCK_RESTORE",
                    "backup_22",
                    target="backup_service",
                ),
            ],
            policy_rules=rules,
        )
        report = analyzer.analyze(
            [EvidenceIdentifier("email", "subject@example.test")],
            "2026-01-04T00:00:00Z",
            evidence=[
                evidence(
                    "data_flow_22",
                    evidence_id="evidence_flow",
                    captured_at="2026-01-04T00:00:00Z",
                    attributes={"enabled": False},
                    data_category="connector_subscriptions",
                ),
                evidence(
                    "backup_22",
                    evidence_id="evidence_backup",
                    captured_at="2026-01-04T00:00:00Z",
                    attributes={"restore_allowed": False},
                    data_category="BACKUP_ARCHIVE",
                ),
            ],
        )

        by_resource = {process.resource_id: process for process in report.processes}
        self.assertEqual(by_resource["data_flow_22"].state, ProcessState.DISABLED)
        self.assertFalse(by_resource["data_flow_22"].can_recreate_data)
        self.assertEqual(by_resource["data_flow_22"].state_temporal_basis, TemporalBasis.AT_AUDIT)
        self.assertEqual(by_resource["backup_22"].state, ProcessState.BLOCKED)
        self.assertFalse(by_resource["backup_22"].can_recreate_data)
        self.assertEqual(by_resource["backup_22"].policy_action, "RETAIN")
        self.assertEqual(by_resource["backup_22"].policy_rule_id, "rule_14")

    def test_later_state_evidence_cannot_override_cutoff(self) -> None:
        analyzer = ActivityAnalyzer(
            [
                activity(
                    "activity_flow",
                    "2026-01-03T00:00:00Z",
                    "CHECK_DATA_FLOW",
                    "data_flow_19",
                    details="Flow check reports status.",
                )
            ]
        )
        process = analyzer.analyze(
            [EvidenceIdentifier("email", "subject@example.test")],
            "2026-01-04T00:00:00Z",
            evidence=[
                evidence(
                    "data_flow_19",
                    captured_at="2026-01-05T00:00:00Z",
                    observed_at="2026-01-05T00:00:00Z",
                    attributes={"enabled": False},
                )
            ],
        ).processes[0]
        self.assertEqual(process.state, ProcessState.UNKNOWN)
        self.assertIsNone(process.can_recreate_data)
        self.assertEqual(process.state_basis, "no_cutoff_eligible_evidence")
        self.assertEqual(process.source_evidence_ids, ())
        self.assertEqual(
            process.excluded_after_audit_evidence_ids,
            ("evidence_test",),
        )

    def test_restore_access_claim_is_not_proof_of_restore_or_backup_deletion(self) -> None:
        analyzer = ActivityAnalyzer(
            [
                activity(
                    "activity_restore_check",
                    "2026-01-03T00:00:00Z",
                    "CHECK_RESTORE_ACCESS",
                    "backup_31",
                    target="backup_service",
                    details=(
                        "Restore-access check says backup_31 can still be restored "
                        "for subject@example.test."
                    ),
                ),
                activity(
                    "activity_restore",
                    "2026-01-03T00:02:00Z",
                    "RESTORE_BACKUP",
                    "backup_31",
                    target="backup_service",
                    details="Restore request submitted for backup_31 for subject@example.test.",
                ),
            ],
            policy_rules=load_rules(),
        )
        report = analyzer.analyze(
            [EvidenceIdentifier("email", "subject@example.test")],
            "2026-01-04T00:00:00Z",
        )
        process = report.processes[0]
        self.assertEqual(process.state, ProcessState.UNKNOWN)
        self.assertEqual(process.latest_activity_claim, ProcessState.RESTORABLE.value)
        self.assertEqual(process.policy_action, "RETAIN")
        restore_event = next(event for event in report.events if event.event_type == "RESTORE_BACKUP")
        self.assertTrue(restore_event.result_is_claim)
        self.assertIsNone(restore_event.reported_process_state)

    def test_analyze_resolution_requires_confirmed_identity(self) -> None:
        resolution = IdentityResolver([], []).resolve_email(
            "missing@example.test",
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
        )
        analyzer = ActivityAnalyzer([])
        with self.assertRaises(ValueError):
            analyzer.analyze_resolution(resolution)


if __name__ == "__main__":
    unittest.main()
