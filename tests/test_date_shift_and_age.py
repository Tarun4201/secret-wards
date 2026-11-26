import datetime as dt
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main


class TestDateShiftAndAge(unittest.TestCase):
    def setUp(self):
        self.original_secret = main.SECRET
        main.SECRET = b"test-seed-secret"

    def tearDown(self):
        main.SECRET = self.original_secret

    def test_fr07_stay_length_preserved(self):
        patient_key = "patient-cluster-stay-test"
        admission = dt.date(2024, 1, 10)
        discharge = dt.date(2024, 1, 19)
        original_stay_days = (discharge - admission).days  # 9 days

        shifted_admission = main.shift_date(admission, patient_key)
        shifted_discharge = main.shift_date(discharge, patient_key)
        shifted_stay_days = (shifted_discharge - shifted_admission).days

        self.assertEqual(original_stay_days, shifted_stay_days)
        self.assertEqual(shifted_stay_days, 9)

    def test_fr07_offset_never_zero(self):
        for i in range(100):
            offset = main.date_shift_days(f"patient-{i}")
            self.assertNotEqual(offset, 0, f"Offset was 0 for patient-{i}")

    def test_fr07_age_band_contains_true_age(self):
        for age in [0, 4, 5, 12, 28, 45, 60, 89, 102]:
            band = main.age_band(age)
            parts = band.split("-")
            lo = int(parts[0])
            hi = int(parts[1])
            self.assertTrue(lo <= age <= hi, f"Age {age} not in band {band}")

    def test_fr07_different_secret_changes_offset(self):
        main.SECRET = b"key-alpha"
        off1 = main.date_shift_days("patient-x")
        main.SECRET = b"key-beta"
        off2 = main.date_shift_days("patient-x")
        self.assertNotEqual(off1, off2)


if __name__ == "__main__":
    unittest.main()
