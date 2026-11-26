"""Tier 1/2 Tests: Sweep Verifier Wider Variant Set (Technique 5)
Requirements: FR-03, NFR-04
"""
import tempfile
import unittest
from pathlib import Path

from main import REMOVED_DIRECT_IDENTIFIERS, Detection, record_removed_identifier, run_sweep_verifier


class TestSweepVariants(unittest.TestCase):
    def setUp(self):
        REMOVED_DIRECT_IDENTIFIERS.clear()

    def test_sweep_catches_reverse_name_order(self):
        """Sweep verifier catches reverse name order (e.g. 'Kumar Ramesh') of removed patient."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            san_file = tmp_path / "note.txt"
            # Plant reverse name order
            san_file.write_text("Patient name written as Kumar Ramesh here", encoding="utf-8")

            # Record that "Ramesh Kumar" was removed
            record_removed_identifier(Detection("PATIENT_NAME", "Ramesh Kumar"))

            files_report = [{"input_sha256": "dummy", "output": "sanitized/note.txt", "status": "sanitized"}]
            records = [{"file": "sanitized/note.txt", "loc": "doc", "patient": None}]

            run_sweep_verifier(tmp_path, files_report, records)

            # Should be quarantined because "Kumar Ramesh" was caught as a variant of "Ramesh Kumar"
            self.assertEqual(files_report[0]["status"], "quarantined")
            self.assertIn("leak", files_report[0]["reason"])

    def test_sweep_catches_indic_digits_leak(self):
        """Sweep verifier catches phone number written in Indic digits."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            san_file = tmp_path / "data.txt"
            # Plant Indic digits for 9876543210: ९८७६५४३२१०
            san_file.write_text("Phone: ९८७६५४३२१०", encoding="utf-8")

            record_removed_identifier(Detection("PHONE", "9876543210"))

            files_report = [{"input_sha256": "dummy", "output": "sanitized/data.txt", "status": "sanitized"}]
            records = [{"file": "sanitized/data.txt", "loc": "doc", "patient": None}]

            run_sweep_verifier(tmp_path, files_report, records)

            self.assertEqual(files_report[0]["status"], "quarantined")


if __name__ == "__main__":
    unittest.main()
