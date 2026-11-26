"""Tier 2 Tests: Multiformat Date & Age Processing across JSON and Free-Text
Requirements: FR-01, FR-06, FR-07
"""
import json
import unittest

from main import PatientCluster, process_json, process_text


class TestMultiformatDateAge(unittest.TestCase):
    def test_fr07_json_date_shifting_and_age_banding(self):
        """JSON fields with date and age are coherently shifted and banded."""
        linker = PatientCluster()
        records = []
        raw_json = json.dumps({
            "patient_id": "P-9001",
            "age": 45,
            "admissionDate": "2023-05-10",
            "dischargeDate": "2023-05-15",
            "diagnosis": "Dengue Fever"
        })

        sanitized_json = process_json(raw_json, "test.json", records, linker)
        parsed = json.loads(sanitized_json)

        # Age must be banded containing 45 (age_band returns "45-49" without brackets)
        self.assertEqual(parsed["age"], "45-49")
        # Dates must be shifted from original 2023-05-10
        self.assertNotEqual(parsed["admissionDate"], "2023-05-10")
        self.assertNotEqual(parsed["dischargeDate"], "2023-05-15")

        # Stay duration must be preserved exactly (5 days)
        from datetime import datetime
        d1 = datetime.strptime(parsed["admissionDate"], "%Y-%m-%d")
        d2 = datetime.strptime(parsed["dischargeDate"], "%Y-%m-%d")
        self.assertEqual((d2 - d1).days, 5, "Stay duration of 5 days must be preserved exactly")

    def test_fr07_text_stay_length_preserved_after_date_shift(self):
        """Free-text notes with dates and age are shifted coherently, preserving stay duration."""
        linker = PatientCluster()
        records = []
        note_text = (
            "Patient presented with fever.\n"
            "Age: 52 yrs\n"
            "Admitted on: 12/03/2023\n"
            "Discharged on: 18/03/2023\n"
            "Rx: Paracetamol 650mg TDS"
        )

        sanitized = process_text(note_text, "note.txt", records, linker)

        # Age 52 must be banded (age_band returns "50-54" without brackets)
        self.assertIn("50-54", sanitized)
        # Original dates must not remain
        self.assertNotIn("12/03/2023", sanitized)
        self.assertNotIn("18/03/2023", sanitized)
        # Clinical prescription preserved exactly
        self.assertIn("Paracetamol 650mg TDS", sanitized)


if __name__ == "__main__":
    unittest.main()
