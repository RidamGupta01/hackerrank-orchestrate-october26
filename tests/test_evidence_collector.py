import csv
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from src.evidence_collector import EvidenceCollector
from src.evidence_models import EvidenceIdentifier, RecordState, TemporalBasis
from src.evidence_parser import parse_evidence_file
from src.identity_resolver import IdentityResolver

PROJECT_DIR = Path(__file__).resolve().parents[1]
DATASET_DIR = PROJECT_DIR / "dataset"


class EvidenceCollectorTests(unittest.TestCase):
    def test_resolution_helper_requires_confirmed_identity(self) -> None:
        unresolved = IdentityResolver([], []).resolve_email(
            "missing@example.test",
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
        )
        with self.assertRaises(ValueError):
            EvidenceCollector(DATASET_DIR).collect_for_resolution(unresolved)

    def test_finds_identifiers_across_the_supplied_manifest(self) -> None:
        collector = EvidenceCollector(DATASET_DIR)
        observations = collector.collect(
            [EvidenceIdentifier("user_id", "user_26")],
            "2026-10-01T12:00:00Z",
        )

        self.assertTrue(observations)
        self.assertTrue(
            any(
                item.resource_id == "account_5684"
                and item.source_evidence_id == "evidence_02"
                and item.state is RecordState.PRESENT
                for item in observations
            )
        )
        self.assertTrue(all(item.source_location for item in observations))
        self.assertTrue(
            all(
                item.identifiers_found
                and item.identifiers_found[0].identifier_value == "user_26"
                for item in observations
            )
        )

    def test_explicit_readback_absence_is_distinguished_from_unknown_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dataset_dir = Path(temporary)
            evidence_dir = dataset_dir / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / "lookup.log").write_text(
                "2026-01-01T00:00:00Z service=account_service "
                "event=profile_lookup_completed lookup_key=target@example.test "
                "rows=0 http_status=404 resource_id=account_404\n"
                "2026-01-01T00:01:00Z service=account_service "
                "event=profile_lookup_started lookup_key=target@example.test\n"
                "2026-01-01T00:01:30Z service=account_service "
                "event=DELETE_RECORD result=SUCCESS lookup_key=target@example.test\n"
                '{"timestamp":"2026-01-01T00:01:45Z","service":"account_service",'
                '"event":"delete_record_completed","result":"SUCCESS",'
                '"email":"target@example.test","resource_id":"account_44"}\n',
                encoding="utf-8",
            )
            self._write_manifest(
                dataset_dir,
                [("evidence_test", "evidence/lookup.log", "account_service", "2026-01-01T00:01:00Z")],
            )

            observations = EvidenceCollector(dataset_dir).collect(
                [EvidenceIdentifier("email", "target@example.test")],
                "2026-01-01T00:02:00Z",
            )

        self.assertEqual(len(observations), 4)
        self.assertEqual(observations[0].state, RecordState.ABSENT)
        self.assertFalse(observations[0].is_operation_attempt)
        self.assertEqual(observations[1].state, RecordState.UNKNOWN)
        self.assertTrue(observations[1].is_operation_attempt)
        self.assertEqual(observations[2].state, RecordState.UNKNOWN)
        self.assertTrue(observations[2].is_operation_attempt)
        self.assertEqual(observations[3].state, RecordState.UNKNOWN)
        self.assertTrue(observations[3].is_operation_attempt)

    def test_observation_time_and_audit_time_are_not_conflated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dataset_dir = Path(temporary)
            (dataset_dir / "evidence").mkdir()
            (dataset_dir / "evidence" / "record.json").write_text(
                json.dumps({
                    "records": [{
                        "system": "search_service",
                        "resource_id": "search_1",
                        "record_type": "SEARCH_INDEX_ENTRY",
                        "recorded_at": "2026-01-02T00:00:00Z",
                        "email": "target@example.test",
                    }]
                }),
                encoding="utf-8",
            )
            self._write_manifest(
                dataset_dir,
                [("evidence_json", "evidence/record.json", "json_export", "2026-01-03T00:00:00Z")],
            )
            observation = EvidenceCollector(dataset_dir).collect(
                [EvidenceIdentifier("email", "target@example.test")],
                "2026-01-03T00:00:00Z",
            )[0]

        self.assertEqual(
            observation.observed_at,
            datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        self.assertEqual(observation.temporal_basis, TemporalBasis.HISTORICAL)
        self.assertEqual(observation.state, RecordState.PRESENT)

    def test_later_captured_file_cannot_establish_state_at_earlier_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dataset_dir = Path(temporary)
            (dataset_dir / "evidence").mkdir()
            (dataset_dir / "evidence" / "record.json").write_text(
                json.dumps({
                    "records": [{
                        "system": "search_service",
                        "resource_id": "search_2",
                        "record_type": "SEARCH_INDEX_ENTRY",
                        "recorded_at": "2026-01-02T00:00:00Z",
                        "email": "target@example.test",
                    }]
                }),
                encoding="utf-8",
            )
            self._write_manifest(
                dataset_dir,
                [("evidence_later", "evidence/record.json", "json_export", "2026-01-04T00:00:00Z")],
            )
            observation = EvidenceCollector(dataset_dir).collect(
                [EvidenceIdentifier("email", "target@example.test")],
                "2026-01-03T00:00:00Z",
            )[0]

        self.assertEqual(observation.observed_at, datetime(2026, 1, 2, tzinfo=timezone.utc))
        self.assertEqual(observation.captured_at, datetime(2026, 1, 4, tzinfo=timezone.utc))
        self.assertEqual(observation.temporal_basis, TemporalBasis.AFTER_AUDIT)

    @staticmethod
    def _write_manifest(
        dataset_dir: Path,
        entries: list[tuple[str, str, str, str]],
    ) -> None:
        with (dataset_dir / "evidence_files.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["file_id", "file_path", "origin", "captured_at"])
            writer.writerows(entries)


class EvidenceParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def parse(self, filename: str):
        path = self.root / filename
        return parse_evidence_file(
            path,
            evidence_id="synthetic",
            captured_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

    def test_parses_json_lines_and_csv_records(self) -> None:
        (self.root / "records.jsonl").write_text(
            '{"system":"support_platform","resource_id":"support_9",'
            '"email":"target@example.test","observed_at":"2026-01-01T00:00:00Z"}\n',
            encoding="utf-8",
        )
        jsonl = self.parse("records.jsonl")
        self.assertEqual(jsonl[0].resource_id, "support_9")
        self.assertEqual(jsonl[0].state, RecordState.PRESENT)

        with (self.root / "records.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["system", "resource_id", "email"])
            writer.writeheader()
            writer.writerow({
                "system": "support_platform",
                "resource_id": "support_10",
                "email": "target@example.test",
            })
        csv_records = self.parse("records.csv")
        self.assertEqual(csv_records[0].resource_id, "support_10")
        self.assertEqual(csv_records[0].state, RecordState.PRESENT)

    def test_text_search_matches_confirmed_name_without_fuzzy_matching(self) -> None:
        # Use the regular collector against a minimal manifest-backed tree.
        dataset = self.root / "dataset"
        (dataset / "evidence").mkdir(parents=True)
        (dataset / "evidence" / "handover.txt").write_text(
            "Customer: Test User; request remains queued.\n"
            "Customer: Test User Extended; separate profile.\n",
            encoding="utf-8",
        )
        (dataset / "evidence_files.csv").write_text(
            "file_id,file_path,origin,captured_at\n"
            "evidence_text,evidence/handover.txt,account_service,2026-01-01T00:00:00Z\n",
            encoding="utf-8",
        )
        observations = EvidenceCollector(dataset).collect(
            [EvidenceIdentifier("name", "Test User")],
            "2026-01-01T00:00:00Z",
        )
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].source_location, "line:1")

    def test_parses_sqlite_compatible_snapshot_safely(self) -> None:
        (self.root / "snapshot.sql").write_text(
            "CREATE TABLE customer_records (resource_id TEXT, email TEXT, updated_at TEXT);"
            "INSERT INTO customer_records VALUES "
            "('profile_11', 'target@example.test', '2025-12-31T00:00:00Z');",
            encoding="utf-8",
        )
        records = self.parse("snapshot.sql")
        record = next(record for record in records if record.resource_id == "profile_11")
        self.assertEqual(record.observed_at, datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(record.attributes["updated_at"], "2025-12-31T00:00:00Z")
        self.assertEqual(record.state, RecordState.PRESENT)

    def test_rejects_sql_that_attempts_external_database_access(self) -> None:
        (self.root / "unsafe.sql").write_text(
            "ATTACH DATABASE 'other.db' AS external;",
            encoding="utf-8",
        )
        with self.assertRaises(Exception):
            self.parse("unsafe.sql")

    def test_existing_manifest_json_uses_bounded_provenance_locations(self) -> None:
        evidence_path = (
            DATASET_DIR / "evidence" / "records" /
            "customer_data_snapshot_bundle_20260917.json"
        )
        records = parse_evidence_file(
            evidence_path,
            evidence_id="evidence_02",
            captured_at=datetime(2026, 9, 17, 12, tzinfo=timezone.utc),
        )
        profile = next(record for record in records if record.resource_id == "account_5684")
        self.assertEqual(profile.system_id, "account_service")
        self.assertEqual(profile.source_location, "$.snapshots[0].records[0]")
        self.assertEqual(profile.state, RecordState.PRESENT)

    def test_image_adapter_uses_local_ocr_result_with_image_provenance(self) -> None:
        image = self.root / "screenshot.png"
        image.write_bytes(b"not-an-image")
        image_handle = MagicMock()
        image_handle.__enter__.return_value = object()
        image_handle.__exit__.return_value = False
        image_module = SimpleNamespace(open=Mock(return_value=image_handle))
        pil_module = ModuleType("PIL")
        pil_module.Image = image_module
        ocr_module = SimpleNamespace(
            image_to_string=Mock(return_value="Profile email: target@example.test")
        )
        with (
            patch.dict(
                sys.modules,
                {"PIL": pil_module, "PIL.Image": image_module, "pytesseract": ocr_module},
            ),
        ):
            records = self.parse("screenshot.png")
        self.assertTrue(records[0].source_location.startswith("image:ocr/line:"))
        self.assertEqual(records[0].identifiers[0].identifier_value, "target@example.test")

    def test_supplied_pdf_has_page_provenance(self) -> None:
        evidence_path = (
            DATASET_DIR / "evidence" / "documents" /
            "delivery_correction_attachment.pdf"
        )
        records = parse_evidence_file(
            evidence_path,
            evidence_id="evidence_58",
            captured_at=datetime(2026, 9, 12, 7, 30, tzinfo=timezone.utc),
        )
        self.assertTrue(records)
        self.assertTrue(all(record.source_location.startswith("page:") for record in records))
        self.assertTrue(any(record.identifiers for record in records))

    def test_all_manifest_sql_snapshots_parse(self) -> None:
        with (DATASET_DIR / "evidence_files.csv").open(
            encoding="utf-8-sig", newline=""
        ) as stream:
            entries = [row for row in csv.DictReader(stream) if row["file_path"].endswith(".sql")]
        self.assertEqual(len(entries), 24)
        for entry in entries:
            with self.subTest(evidence_id=entry["file_id"]):
                records = parse_evidence_file(
                    DATASET_DIR / entry["file_path"],
                    evidence_id=entry["file_id"],
                    captured_at=datetime.fromisoformat(
                        entry["captured_at"].replace("Z", "+00:00")
                    ),
                )
                self.assertIsInstance(records, tuple)


if __name__ == "__main__":
    unittest.main()
