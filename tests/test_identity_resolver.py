import csv
import json
import unittest
from pathlib import Path

from src.identity_resolver import IdentityResolver, ResolutionStatus


def identity(
    user_id: str = "user_01",
    email: str = "current@example.test",
    name: str = "Test User",
    phone: str = "+1 555 0100",
    email_hash: str = "hash-current",
    updated_at: str = "2026-01-01T00:00:00Z",
) -> dict[str, str]:
    return {
        "user_id": user_id,
        "name": name,
        "email": email,
        "phone": phone,
        "email_hash": email_hash,
        "updated_at": updated_at,
    }


def audit(
    audit_id: str,
    field_name: str,
    old_value: str,
    new_value: str,
    event_time: str = "2026-01-10T00:00:00Z",
    user_id: str = "user_01",
) -> dict[str, str]:
    return {
        "audit_id": audit_id,
        "user_id": user_id,
        "event_time": event_time,
        "field_name": field_name,
        "old_value": old_value,
        "new_value": new_value,
    }


class IdentityResolverTests(unittest.TestCase):
    def test_resolves_current_email_and_returns_snapshot_provenance(self) -> None:
        resolver = IdentityResolver([identity()], [])

        result = resolver.resolve_email(
            " CURRENT@example.test ",
            "2026-01-02T00:00:00Z",
            "2026-01-03T00:00:00Z",
        )

        self.assertEqual(result.status, ResolutionStatus.CONFIRMED)
        self.assertEqual(result.user_id, "user_01")
        self.assertEqual(result.candidate_user_ids, ("user_01",))
        self.assertEqual(
            result.matched_relationships[0].source_file, "user_identities.csv"
        )
        self.assertEqual(
            result.matched_relationships[0].observed_at.isoformat(),
            "2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(
            {relationship.identifier_type for relationship in result.identity_relationships},
            {"name", "email", "phone", "email_hash"},
        )

    def test_resolves_changed_email_from_explicit_audit_history(self) -> None:
        resolver = IdentityResolver(
            [identity(email="new@example.test")],
            [audit("audit_01", "email", "old@example.test", "new@example.test")],
        )

        result = resolver.resolve_email(
            "old@example.test",
            "2026-01-11T00:00:00Z",
            "2026-01-12T00:00:00Z",
        )

        self.assertEqual(result.status, ResolutionStatus.CONFIRMED)
        self.assertEqual(result.user_id, "user_01")
        matched = result.matched_relationships[0]
        self.assertEqual(matched.identifier_value, "old@example.test")
        self.assertEqual(matched.source_record_id, "audit_01")
        self.assertEqual(matched.relation_kind, "previous_value")
        self.assertEqual(matched.observed_at.isoformat(), "2026-01-10T00:00:00+00:00")
        returned_emails = {
            relationship.identifier_value
            for relationship in result.identity_relationships
            if relationship.identifier_type == "email"
        }
        self.assertEqual(returned_emails, {"old@example.test", "new@example.test"})

    def test_later_audit_change_supersedes_an_older_snapshot_value(self) -> None:
        resolver = IdentityResolver(
            [
                identity(
                    email="old@example.test",
                    updated_at="2026-01-01T00:00:00Z",
                )
            ],
            [
                audit(
                    "audit_change",
                    "email",
                    "old@example.test",
                    "new@example.test",
                    event_time="2026-01-10T00:00:00Z",
                )
            ],
        )

        result = resolver.resolve_email(
            "old@example.test",
            "2026-01-11T00:00:00Z",
            "2026-01-12T00:00:00Z",
        )

        self.assertEqual(result.status, ResolutionStatus.CONFIRMED)
        self.assertTrue(
            all(
                relationship.relation_kind != "snapshot"
                for relationship in result.matched_relationships
            )
        )

    def test_returns_multiple_historical_identifiers_with_source_timestamps(self) -> None:
        resolver = IdentityResolver(
            [
                identity(
                    email="new@example.test",
                    phone="+1 555 0102",
                    email_hash="hash-new",
                )
            ],
            [
                audit("audit_email", "email", "old@example.test", "new@example.test"),
                audit("audit_phone", "phone", "+1 555 0100", "+1 555 0102"),
                audit("audit_hash", "email_hash", "hash-old", "hash-new"),
            ],
        )

        result = resolver.resolve_email(
            "old@example.test",
            "2026-01-11T00:00:00Z",
            "2026-01-12T00:00:00Z",
        )

        observed = {
            (relationship.identifier_type, relationship.identifier_value)
            for relationship in result.identity_relationships
        }
        self.assertIn(("phone", "+1 555 0100"), observed)
        self.assertIn(("phone", "+1 555 0102"), observed)
        self.assertIn(("email_hash", "hash-old"), observed)
        self.assertIn(("email_hash", "hash-new"), observed)
        self.assertTrue(
            all(
                relationship.source_file in {"user_identities.csv", "user_audit_log.csv"}
                and relationship.observed_at <= result.audit_at
                for relationship in result.identity_relationships
            )
        )

    def test_missing_identity_is_unresolved(self) -> None:
        resolver = IdentityResolver([], [])

        result = resolver.resolve_email(
            "missing@example.test",
            "2026-01-11T00:00:00Z",
            "2026-01-12T00:00:00Z",
        )

        self.assertEqual(result.status, ResolutionStatus.UNRESOLVED)
        self.assertIsNone(result.user_id)
        self.assertEqual(result.unresolved_reason, "NO_MATCHING_IDENTITY_EVIDENCE")

    def test_email_shared_by_multiple_users_is_ambiguous_not_merged(self) -> None:
        resolver = IdentityResolver(
            [
                identity(user_id="user_01"),
                identity(user_id="user_02", name="Other User"),
            ],
            [],
        )

        result = resolver.resolve_email(
            "current@example.test",
            "2026-01-02T00:00:00Z",
            "2026-01-03T00:00:00Z",
        )

        self.assertEqual(result.status, ResolutionStatus.AMBIGUOUS)
        self.assertIsNone(result.user_id)
        self.assertEqual(result.candidate_user_ids, ("user_01", "user_02"))
        self.assertEqual(result.identity_relationships, ())

    def test_identity_first_observed_after_request_is_not_used_to_resolve(self) -> None:
        resolver = IdentityResolver(
            [
                identity(
                    email="future@example.test",
                    updated_at="2026-01-10T00:00:00Z",
                )
            ],
            [],
        )

        result = resolver.resolve_email(
            "future@example.test",
            "2026-01-05T00:00:00Z",
            "2026-01-12T00:00:00Z",
        )

        self.assertEqual(result.status, ResolutionStatus.UNRESOLVED)
        self.assertEqual(result.later_candidate_user_ids, ("user_01",))
        self.assertEqual(
            result.unresolved_reason,
            "IDENTITY_ONLY_OBSERVED_AFTER_REQUEST",
        )

    def test_future_email_audit_does_not_confirm_request_identity(self) -> None:
        resolver = IdentityResolver(
            [identity(email="current@example.test")],
            [
                audit(
                    "audit_future_email",
                    "email",
                    "future@example.test",
                    "current@example.test",
                    event_time="2026-01-10T00:00:00Z",
                )
            ],
        )

        result = resolver.resolve_email(
            "future@example.test",
            "2026-01-05T00:00:00Z",
            "2026-01-12T00:00:00Z",
        )

        self.assertEqual(result.status, ResolutionStatus.UNRESOLVED)
        self.assertEqual(result.later_candidate_user_ids, ("user_01",))

    def test_audit_cutoff_excludes_later_identity_relationships(self) -> None:
        resolver = IdentityResolver(
            [identity()],
            [
                audit(
                    "audit_future",
                    "phone",
                    "+1 555 0100",
                    "+1 555 0199",
                    event_time="2026-01-20T00:00:00Z",
                )
            ],
        )

        result = resolver.resolve_email(
            "current@example.test",
            "2026-01-02T00:00:00Z",
            "2026-01-15T00:00:00Z",
        )

        returned_phones = {
            relationship.identifier_value
            for relationship in result.identity_relationships
            if relationship.identifier_type == "phone"
        }
        self.assertEqual(returned_phones, {"+1 555 0100"})

    def test_request_mapping_and_json_compatible_result(self) -> None:
        resolver = IdentityResolver([identity()], [])

        result = resolver.resolve_request(
            {
                "email": "current@example.test",
                "requested_at": "2026-01-02T00:00:00Z",
                "audit_at": "2026-01-03T00:00:00Z",
            }
        )

        encoded = json.dumps(result.to_dict())
        self.assertEqual(json.loads(encoded)["user_id"], "user_01")

    def test_rejects_audit_timestamp_before_request_timestamp(self) -> None:
        resolver = IdentityResolver([identity()], [])

        with self.assertRaisesRegex(ValueError, "audit_at"):
            resolver.resolve_email(
                "current@example.test",
                "2026-01-03T00:00:00Z",
                "2026-01-02T00:00:00Z",
            )

    def test_loads_repository_identity_csvs_and_resolves_every_request(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        resolver = IdentityResolver.from_csv(
            repository_root / "dataset" / "user_identities.csv",
            repository_root / "dataset" / "user_audit_log.csv",
        )
        request_path = repository_root / "dataset" / "deletion_requests.csv"

        with request_path.open(encoding="utf-8-sig", newline="") as file:
            requests = list(csv.DictReader(file))

        results = [resolver.resolve_request(request) for request in requests]
        self.assertEqual(len(results), 518)
        self.assertTrue(
            all(result.status is ResolutionStatus.CONFIRMED for result in results)
        )
        self.assertEqual(
            sum(
                any(
                    relationship.relation_kind == "snapshot"
                    and relationship.identifier_type == "email"
                    for relationship in result.matched_relationships
                )
                for result in results
            ),
            418,
        )


if __name__ == "__main__":
    unittest.main()
