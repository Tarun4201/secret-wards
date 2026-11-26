"""Tier 2 & 3 Tests: Textual Indian Date Formats, Devanagari Dates, and NLEM Clinical Preservation
Requirements: FR-06, FR-07, NFR-02
"""
import datetime as dt
import re
import unittest

from main import PatientCluster, _try_shift_date_str, clean_text, process_text


class TestTextualDatesAndNLEM(unittest.TestCase):
    def test_fr07_textual_month_date_shifting_preserves_stay(self):
        """Dates formatted as '15 Jan 2024' and '22 Jan 2024' are shifted coherently, preserving stay duration."""
        linker = PatientCluster()
        records = []
        note_text = (
            "Discharge Summary\n"
            "Patient Name: Suresh Verma\n"
            "Admitted: 15 Jan 2024\n"
            "Discharged: 22 Jan 2024\n"
            "Review Date: 15-Feb-2024\n"
            "Rx: Tab Telma 40mg OD, Tab Pan-D 1-0-0"
        )
        sanitized = process_text(note_text, "discharge_note.txt", records, linker)

        # Original dates must not remain
        self.assertNotIn("15 Jan 2024", sanitized)
        self.assertNotIn("22 Jan 2024", sanitized)
        self.assertNotIn("15-Feb-2024", sanitized)

        # Find shifted admission and discharge dates in sanitized text
        m_adm = re.search(r'Admitted:\s*(\d{1,2}\s+[A-Za-z]+\s+\d{4})', sanitized)
        m_dis = re.search(r'Discharged:\s*(\d{1,2}\s+[A-Za-z]+\s+\d{4})', sanitized)

        self.assertIsNotNone(m_adm, "Shifted admission date not found")
        self.assertIsNotNone(m_dis, "Shifted discharge date not found")

        d_adm = dt.datetime.strptime(m_adm.group(1), "%d %b %Y").date()
        d_dis = dt.datetime.strptime(m_dis.group(1), "%d %b %Y").date()

        stay_days = (d_dis - d_adm).days
        self.assertEqual(stay_days, 7, "Stay duration of 7 days must be preserved exactly after textual date shift")

    def test_fr07_dot_date_shifting_preserves_stay(self):
        """Dates formatted as '10.03.2024' and '18.03.2024' are shifted coherently."""
        linker = PatientCluster()
        records = []
        note_text = (
            "Admission: 10.03.2024\n"
            "Discharge: 18.03.2024\n"
            "Diagnosis: Viral Bronchitis"
        )
        sanitized = process_text(note_text, "note_dot.txt", records, linker)

        self.assertNotIn("10.03.2024", sanitized)
        self.assertNotIn("18.03.2024", sanitized)

        m_adm = re.search(r'Admission:\s*(\d{1,2}\.\d{1,2}\.\d{4})', sanitized)
        m_dis = re.search(r'Discharge:\s*(\d{1,2}\.\d{1,2}\.\d{4})', sanitized)

        self.assertIsNotNone(m_adm)
        self.assertIsNotNone(m_dis)

        d_adm = dt.datetime.strptime(m_adm.group(1), "%d.%m.%Y").date()
        d_dis = dt.datetime.strptime(m_dis.group(1), "%d.%m.%Y").date()

        self.assertEqual((d_dis - d_adm).days, 8, "Stay duration of 8 days must be preserved exactly")

    def test_fr07_devanagari_date_shifting(self):
        """Devanagari dates '10 जनवरी 2024' and '15 जनवरी 2024' are shifted coherently."""
        linker = PatientCluster()
        records = []
        note_text = (
            "भर्ती: 10 जनवरी 2024\n"
            "छुट्टी: 15 जनवरी 2024\n"
            "दवा: पैरासिटामोल 650mg"
        )
        sanitized = process_text(note_text, "note_hindi.txt", records, linker)

        self.assertNotIn("10 जनवरी 2024", sanitized)
        self.assertNotIn("15 जनवरी 2024", sanitized)

        # Direct verification with _try_shift_date_str
        shifted_adm = _try_shift_date_str("10 जनवरी 2024", 15)
        shifted_dis = _try_shift_date_str("15 जनवरी 2024", 15)
        self.assertEqual(shifted_adm, "25 जनवरी 2024")
        self.assertEqual(shifted_dis, "30 जनवरी 2024")

    def test_fr06_nlem_and_brand_medications_preserved(self):
        """Essential Indian NLEM medications and popular brands are preserved, not redacted."""
        clinical_text = (
            "Discharge Rx:\n"
            "1. Tab Pan-D OD before breakfast\n"
            "2. Tab Telma 40mg OD\n"
            "3. Tab Combiflam SOS for pain\n"
            "4. Syp Deriphyllin 1-0-1 x 5 days\n"
            "5. Inj Ceftriaxone 1g IV BD\n"
            "6. Tab Calpol 650mg TDS\n"
            "7. Tab Montair-LC HS"
        )
        cleaned, dets = clean_text(clinical_text)

        # No medication should be detected as PII
        self.assertEqual(len(dets), 0, f"Medications mistakenly detected as PII: {[d.surface for d in dets]}")
        self.assertIn("Pan-D OD", cleaned)
        self.assertIn("Telma 40mg OD", cleaned)
        self.assertIn("Combiflam SOS", cleaned)
        self.assertIn("Deriphyllin 1-0-1", cleaned)
        self.assertIn("Ceftriaxone 1g IV BD", cleaned)
        self.assertIn("Calpol 650mg TDS", cleaned)

    def test_fr06_dosing_patterns_not_flagged_as_phone_numbers(self):
        """Complex dosing frequencies like 1-1-1-1 or 1-0-1 are not flagged as phone numbers."""
        text = "Take 1-0-1 for 5 days, then 0-0-1 x 3 days. Alternative: 1-1-1-1 if fever > 101F."
        cleaned, dets = clean_text(text)
        self.assertEqual(len(dets), 0)
        self.assertIn("1-0-1", cleaned)
        self.assertIn("0-0-1", cleaned)
        self.assertIn("1-1-1-1", cleaned)


if __name__ == "__main__":
    unittest.main()
