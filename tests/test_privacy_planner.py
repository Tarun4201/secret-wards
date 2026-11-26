"""Tier 2 Tests: Risk-Gated Privacy Planner (Technique 4)
Requirements: FR-07, FR-10
"""
import tempfile
import unittest
from pathlib import Path

from main import PrivacyPlanner, clean_value


class TestPrivacyPlanner(unittest.TestCase):
    def test_fr10_k_anonymity_widens_age_band(self):
        """When an equivalence class has size < k, 5-yr age band is broadened to 10-yr band."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            san_dir = tmp_path / "sanitized"
            san_dir.mkdir()

            # Create a file with a 5-yr band [42-46] or [40-44]
            test_file = san_dir / "record.txt"
            test_file.write_text("Patient Record. Age: [40-44], Village: [VILLAGE]", encoding="utf-8")

            planner = PrivacyPlanner(min_k=5)
            # Only 1 record in this group (size 1 < 5)
            records = [{"file": "sanitized/record.txt", "loc": "doc", "patient": "PSN-123456"}]
            evidence = {"record.txt:doc": {"age": "42", "village": "RareVillage"}}

            planner.plan_and_generalize(san_dir, records, evidence)

            result_text = test_file.read_text(encoding="utf-8")
            # Should be broadened to 10-year band [40-49]
            self.assertIn("[40-49]", result_text)
            self.assertNotIn("[40-44]", result_text)

    def test_fr10_location_ladder_generalization(self):
        """Village and PIN are generalized following location ladder."""
        # 1. Village generalization
        val, _ = clean_value("Rampur Khurd", header="village")
        self.assertEqual(val, "[VILLAGE]")

        # 2. 6-digit PIN code retains 3-digit prefix
        val_pin, _ = clean_value("302015", header="pin")
        self.assertEqual(val_pin, "302***")

        # 3. Invalid PIN replaced with [PIN]
        val_bad_pin, _ = clean_value("12", header="pin")
        self.assertEqual(val_bad_pin, "[PIN]")


if __name__ == "__main__":
    unittest.main()
