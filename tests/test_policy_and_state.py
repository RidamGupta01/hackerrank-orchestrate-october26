from __future__ import annotations

import csv
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.activity_analyzer import ActivityReport, ProcessAssessment, ProcessState
from src.evidence_models import (
    EvidenceIdentifier,
    EvidenceObservation,
    RecordState,
    TemporalBasis,
)
from src.identity_resolver import (
    IdentityRelationship,
    IdentityResolution,
    ResolutionStatus,
)
from src.policy_engine import (
    ConditionOutcome,
    PolicyAction,
    PolicyEngine,
)
from src.state_reconstructor import (
    AuditStatus,
    AuthorizationAssessment,
    ConditionStatus,
    DeletionAuthorization,
    StateReconstructor,
)


ROOT = Path(__file__).resolve().parents[1]
AUDIT_AT = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)


class PolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = PolicyEngine.from_csv(ROOT / "dataset" / "deletion_rules.csv")

    def test_policy_headers_are_resolved_semantically_not_by_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rules.csv"
            with path.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(
                    stream,
                    fieldnames=["required_action", "condition", "data_category", "rule_id"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "required_action": "DELETE",
                        "condition": "Always",
                        "data_category": "USER_PROFILE",
                        "rule_id": "fixture-rule",
                    }
                )
            decision = PolicyEngine.from_csv(path).evaluate("USER_PROFILE")
        self.assertEqual(decision.rule_id, "fixture-rule")
        self.assertEqual(decision.required_action, PolicyAction.DELETE)
        self.assertEqual(decision.condition_outcome, ConditionOutcome.APPLIES)

    def test_unknown_category_and_unknown_condition_fail_closed(self) -> None:
        unknown_category = self.engine.evaluate("UNLISTED_CATEGORY")
        self.assertTrue(unknown_category.unresolved_policy)
        self.assertEqual(unknown_category.decision, "UNRESOLVED")
        unknown_condition = PolicyEngine(
            [
                {
                    "rule_id": "x",
                    "data_category": "CUSTOM",
                    "condition": "A novel condition",
                    "required_action": "DELETE",
                }
            ]
        ).evaluate("CUSTOM")
        self.assertEqual(unknown_condition.condition_outcome, ConditionOutcome.UNRESOLVED)

    def test_conditional_rule_requires_explicit_facts(self) -> None:
        rule = self.engine.evaluate("SUPPORT_MESSAGE")
        self.assertEqual(rule.decision, "UNRESOLVED")
        false_fact = self.engine.evaluate(
            "SUPPORT_MESSAGE",
            facts={"shared_context_must_be_retained": False},
        )
        self.assertEqual(false_fact.condition_outcome, ConditionOutcome.DOES_NOT_APPLY)
        true_fact = self.engine.evaluate(
            "SUPPORT_MESSAGE",
            facts={"shared_context_must_be_retained": True},
        )
        self.assertEqual(true_fact.required_action, PolicyAction.REDACT)
        self.assertIn("email_hash", true_fact.required_identifier_removal)

    def test_verified_retention_and_tombstone_mapping(self) -> None:
        retention = self.engine.evaluate(
            "SECURITY_AUDIT_LOG",
            facts={"within_retention_period": True},
        )
        tombstone = self.engine.evaluate(
            "ACCOUNT_TOMBSTONE",
            facts={
                "account_deleted": True,
                "stable_user_id_needed_for_retained_references": True,
            },
        )
        self.assertEqual(retention.required_action, PolicyAction.RETAIN)
        self.assertTrue(retention.preserve_record)
        self.assertEqual(tombstone.permitted_identifier_types, ("user_id",))
        self.assertNotIn("user_id", tombstone.required_identifier_removal)


class StateReconstructorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = PolicyEngine.from_csv(ROOT / "dataset" / "deletion_rules.csv")
        self.reconstructor = StateReconstructor(self.engine)
        self.identity = _identity()
        self.authorization = AuthorizationAssessment(
            DeletionAuthorization.REQUESTED,
            ("request_17",),
            "Deletion request is evidenced.",
        )

    def test_deleted_record_requires_cutoff_valid_absence(self) -> None:
        result = self.reconstruct(
            (_observation("profile_17", "USER_PROFILE", RecordState.ABSENT),),
            processes=(_process("data_flow_17", ProcessState.DISABLED, "DATA_FLOW"),),
        )
        self.assertEqual(result.status, AuditStatus.COMPLETE)
        self.assertEqual(result.resources[0].state, RecordState.ABSENT)

    def test_present_deleted_record_fails_and_preserves_provenance(self) -> None:
        result = self.reconstruct(
            (_observation("profile_17", "USER_PROFILE", RecordState.PRESENT),)
        )
        self.assertEqual(result.status, AuditStatus.INCOMPLETE)
        condition = next(item for item in result.mandatory_conditions if item.condition_id.startswith("policy:"))
        self.assertEqual(condition.status, ConditionStatus.FAILED)
        self.assertEqual(condition.source_evidence_ids, ("evidence_17",))

    def test_historical_observation_does_not_establish_audit_state(self) -> None:
        observation = _observation(
            "profile_17",
            "USER_PROFILE",
            RecordState.ABSENT,
            captured_at=AUDIT_AT - timedelta(days=1),
            observed_at=AUDIT_AT - timedelta(days=1),
            temporal_basis=TemporalBasis.HISTORICAL,
        )
        result = self.reconstruct((observation,))
        self.assertEqual(result.status, AuditStatus.INCOMPLETE)
        self.assertTrue(
            any(item.status is ConditionStatus.UNRESOLVED for item in result.mandatory_conditions)
        )
        self.assertEqual(result.resources[0].state_temporal_basis, TemporalBasis.HISTORICAL)

    def test_operation_attempt_is_not_proof_of_absence(self) -> None:
        attempt = _observation(
            "profile_17",
            "USER_PROFILE",
            RecordState.ABSENT,
        )
        attempt = EvidenceObservation(
            **{
                **attempt.__dict__,
                "is_operation_attempt": True,
            }
        )
        result = self.reconstruct((attempt,))
        self.assertEqual(result.status, AuditStatus.INCOMPLETE)
        self.assertEqual(result.resources[0].state, RecordState.UNKNOWN)
        self.assertEqual(result.resources[0].source_evidence_ids, ("evidence_17",))

    def test_contradictory_cutoff_snapshots_fail(self) -> None:
        result = self.reconstruct(
            (
                _observation("profile_17", "USER_PROFILE", RecordState.PRESENT),
                _observation(
                    "profile_17",
                    "USER_PROFILE",
                    RecordState.ABSENT,
                ),
            )
        )
        self.assertEqual(result.status, AuditStatus.INCOMPLETE)
        self.assertTrue(any(item.condition_id.startswith("resource_consistency:") for item in result.mandatory_conditions))

    def test_tombstone_can_retain_stable_user_id_when_direct_fields_removed(self) -> None:
        tombstone = _observation(
            "tombstone_17",
            "ACCOUNT_TOMBSTONE",
            RecordState.REDACTED,
            identifiers=(EvidenceIdentifier("user_id", "user_17"),),
            attributes={
                "redacted_fields": ("name", "email", "phone", "email_hash"),
            },
        )
        result = self.reconstruct(
            (tombstone,),
            processes=(_process("data_flow_17", ProcessState.DISABLED, "DATA_FLOW"),),
            policy_facts={
                "account_deleted": True,
                "stable_user_id_needed_for_retained_references": True,
            },
        )
        self.assertEqual(result.status, AuditStatus.COMPLETE)

    def test_remaining_email_hash_fails_redaction(self) -> None:
        message = _observation(
            "support_17",
            "SUPPORT_MESSAGE",
            RecordState.REDACTED,
            identifiers=(
                EvidenceIdentifier("user_id", "user_17"),
                EvidenceIdentifier("email_hash", "hashvalue"),
            ),
            attributes={
                "redacted_fields": ("name", "email", "phone", "email_hash", "user_id"),
            },
        )
        result = self.reconstruct(
            (message,),
            policy_facts={"shared_context_must_be_retained": True},
        )
        # A still-linked identifier is not erased merely because a field list claims removal.
        self.assertEqual(result.status, AuditStatus.INCOMPLETE)
        self.assertTrue(any(item.status is ConditionStatus.FAILED for item in result.mandatory_conditions))

    def test_unknown_policy_mapping_is_an_unresolved_mandatory_condition(self) -> None:
        result = self.reconstruct(
            (_observation("custom_17", "UNKNOWN_CATEGORY", RecordState.PRESENT),)
        )
        self.assertEqual(result.status, AuditStatus.INCOMPLETE)
        self.assertTrue(any(item.condition_id.startswith("policy_mapping:") for item in result.mandatory_conditions))

    def test_missing_authorization_provenance_cannot_complete(self) -> None:
        result = self.reconstruct(
            (_observation("profile_17", "USER_PROFILE", RecordState.ABSENT),),
            authorization=AuthorizationAssessment(
                DeletionAuthorization.REQUESTED, (), "asserted"
            ),
        )
        self.assertEqual(result.status, AuditStatus.INCOMPLETE)
        self.assertTrue(any(item.condition_id == "deletion_authorization" for item in result.mandatory_conditions))

    def test_not_applicable_requires_evidence(self) -> None:
        result = self.reconstruct(
            (),
            authorization=AuthorizationAssessment(
                DeletionAuthorization.NOT_REQUESTED,
                ("request_18",),
                "Request text establishes no deletion request.",
            ),
        )
        self.assertEqual(result.status, AuditStatus.NOT_APPLICABLE)

    def test_active_flow_fails_but_blocked_retained_backup_is_supported(self) -> None:
        active = _process("data_flow_17", ProcessState.ACTIVE, "DATA_FLOW")
        backup = _process(
            "backup_17",
            ProcessState.BLOCKED,
            "RESTORE_PATH",
            category="BACKUP_ARCHIVE",
            rule="rule_14",
            action="RETAIN",
        )
        result = self.reconstruct((), processes=(active, backup))
        statuses = {item.condition_id: item.status for item in result.mandatory_conditions}
        self.assertEqual(statuses["recreation_prevention:data_flow_17"], ConditionStatus.FAILED)
        self.assertEqual(statuses["recreation_prevention:backup_17"], ConditionStatus.SATISFIED)
        self.assertEqual(statuses["backup_retention:backup_17"], ConditionStatus.SATISFIED)

    def test_activity_report_cutoff_must_match_identity_cutoff(self) -> None:
        with self.assertRaises(ValueError):
            self.reconstructor.reconstruct(
                self.identity,
                (),
                ActivityReport(AUDIT_AT - timedelta(seconds=1), (), ()),
                self.authorization,
            )

    def reconstruct(
        self,
        evidence: tuple[EvidenceObservation, ...],
        *,
        policy_facts: dict[str, object] | None = None,
        processes: tuple[ProcessAssessment, ...] = (),
        authorization: AuthorizationAssessment | None = None,
    ):
        return self.reconstructor.reconstruct(
            self.identity,
            evidence,
            ActivityReport(AUDIT_AT, (), processes),
            authorization or self.authorization,
            policy_facts_by_resource={
                item.resource_id: policy_facts or {}
                for item in evidence
                if policy_facts and item.resource_id
            }
            or None,
        )


def _identity() -> IdentityResolution:
    relationship = IdentityRelationship(
        "user_17",
        "user_id",
        "user_17",
        "user_identities.csv",
        "row:17",
        AUDIT_AT - timedelta(days=1),
        "CURRENT_SNAPSHOT",
    )
    return IdentityResolution(
        ResolutionStatus.CONFIRMED,
        "person@example.test",
        AUDIT_AT - timedelta(days=2),
        AUDIT_AT,
        "user_17",
        ("user_17",),
        (relationship,),
        (relationship,),
        (),
        None,
    )


def _observation(
    resource_id: str,
    category: str,
    state: RecordState,
    *,
    identifiers: tuple[EvidenceIdentifier, ...] | None = None,
    captured_at: datetime = AUDIT_AT,
    observed_at: datetime | None = None,
    temporal_basis: TemporalBasis = TemporalBasis.AT_AUDIT,
    attributes: dict[str, object] | None = None,
) -> EvidenceObservation:
    return EvidenceObservation(
        system_id="test_system",
        resource_id=resource_id,
        data_category=category,
        observed_at=observed_at or AUDIT_AT - timedelta(minutes=1),
        captured_at=captured_at,
        identifiers_found=identifiers
        if identifiers is not None
        else (EvidenceIdentifier("user_id", "user_17"),),
        source_evidence_id="evidence_17",
        source_location="row:17",
        state=state,
        temporal_basis=temporal_basis,
        attributes=attributes or {},
    )


def _process(
    resource_id: str,
    state: ProcessState,
    kind: str,
    *,
    category: str | None = None,
    rule: str | None = None,
    action: str | None = None,
) -> ProcessAssessment:
    return ProcessAssessment(
        resource_id,
        "test_system",
        kind,
        state,
        TemporalBasis.AT_AUDIT,
        AUDIT_AT,
        ("evidence_process",),
        ("activity_17",),
        category,
        rule,
        action,
        None,
        state is ProcessState.ACTIVE or state is ProcessState.RESTORABLE,
        None,
        "fixture",
        (),
        None,
        None,
    )


if __name__ == "__main__":
    unittest.main()
