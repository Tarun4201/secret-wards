import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import clean_text


class TestRoleResolver(unittest.TestCase):
    def test_fr05_complaint_vs_care_of(self):
        # C/O fever is a complaint (must be preserved)
        txt1 = "Patient presents with C/O fever and vomiting."
        cleaned1, _ = clean_text(txt1)
        self.assertIn("C/O fever", cleaned1)
        self.assertIn("vomiting", cleaned1)

        # C/O Ramesh is a care-of relative (must be removed)
        txt2 = "Contact: C/O Ramesh (brother)"
        cleaned2, _ = clean_text(txt2)
        self.assertNotIn("Ramesh", cleaned2)
        self.assertIn("[RELATIVE_NAME]", cleaned2)

    def test_fr05_doctor_name_preserved(self):
        txt = "Dr. Rajesh Sharma attended the patient in ICU."
        cleaned, _ = clean_text(txt)
        self.assertIn("Dr. Rajesh Sharma", cleaned)

    def test_fr05_relative_name_removed(self):
        txt = "Ramesh Kumar S/o Suresh Kumar residing in village."
        cleaned, _ = clean_text(txt)
        self.assertNotIn("Suresh Kumar", cleaned)

    def test_fr05_disease_eponym_preserved(self):
        txt = "Diagnosed with Parkinson's disease and Alzheimer's."
        cleaned, _ = clean_text(txt)
        self.assertIn("Parkinson's disease", cleaned)
        self.assertIn("Alzheimer's", cleaned)

    def test_fr05_dose_not_flagged_as_phone(self):
        txt = "Rx: Tab Metformin 500mg 1-0-1 x 5 days. Dolo 650 BD."
        cleaned, dets = clean_text(txt)
        # 1-0-1 and 650 must not be flagged as PHONE or AADHAAR
        phone_dets = [d for d in dets if d.type in ('PHONE', 'AADHAAR')]
        self.assertEqual(len(phone_dets), 0)
        self.assertIn("1-0-1", cleaned)
        self.assertIn("Dolo 650 BD", cleaned)


if __name__ == "__main__":
    unittest.main()
