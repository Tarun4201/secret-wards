import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import clean_text


class TestClinicalProtection(unittest.TestCase):
    def test_fr06_medicines_and_dosages_preserved(self):
        txt = (
            "Prescription: Tab Metformin 500mg BD after meals. "
            "Inj Ceftriaxone 1g IV BD x 5 days. "
            "Syp Paracetamol 250mg/5ml SOS. "
            "Tab Atorvastatin 20mg HS."
        )
        cleaned, _ = clean_text(txt)
        self.assertIn("Metformin 500mg BD", cleaned)
        self.assertIn("Ceftriaxone 1g IV BD", cleaned)
        self.assertIn("Paracetamol 250mg/5ml SOS", cleaned)
        self.assertIn("Atorvastatin 20mg HS", cleaned)

    def test_fr06_vitals_and_labs_preserved(self):
        txt = (
            "Vitals: BP 120/80 mmHg, Pulse 72/min, SpO2 98%, Temp 98.4 F. "
            "Labs: Hb 13.5 g/dl, Platelets 2.5 lakhs/cumm, Creatinine 0.9 mg/dl, RBS 110 mg/dl."
        )
        cleaned, _ = clean_text(txt)
        self.assertIn("120/80 mmHg", cleaned)
        self.assertIn("SpO2 98%", cleaned)
        self.assertIn("Hb 13.5 g/dl", cleaned)
        self.assertIn("Creatinine 0.9 mg/dl", cleaned)


if __name__ == "__main__":
    unittest.main()
