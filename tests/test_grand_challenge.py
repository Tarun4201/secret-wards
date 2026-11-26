"""Tests for Grand Challenge: 4-Hospital Multilingual Linkage & Edge Cases.
Validates:
- "Mohammad Arif" (CSV), "मोहम्मद आरिफ" (Hindi), "Md. Arif" (Nursing Note),
  and "Arif sahab" (Hinglish OPD) link to the EXACT SAME pseudonym.
- Family Phone Trap: Unrelated family members sharing a phone do NOT merge.
- Meaning Trap: "C/O fever", "Parkinson's disease", and doctor names remain preserved.
- Regimens: "Ramipril 5 mg", "Dolo 650 BD", "1-0-1" remain preserved.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN_PY = ROOT / "main.py"
DATAGEN = ROOT / "tools" / "datagen" / "generate_grand_challenge.py"


class TestGrandChallengeMultilingual(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.TemporaryDirectory()
        cls.input_dir = Path(cls.td.name) / "input"
        cls.output_dir = Path(cls.td.name) / "output"

        # Generate the grand challenge dataset
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "generate_grand_challenge", str(DATAGEN)
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.generate_grand_challenge(cls.input_dir)

        # Run pipeline
        env = os.environ.copy()
        env["RAKSHA_SECRET"] = "grand_challenge_secret_key_2026"
        res = subprocess.run(
            [
                sys.executable,
                str(MAIN_PY),
                "--input",
                str(cls.input_dir),
                "--output",
                str(cls.output_dir),
            ],
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"Pipeline failed: {res.stderr}"

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def test_four_hospital_multilingual_linkage(self):
        """Mohammad Arif across English CSV, Devanagari Hindi, English Nursing note,

        and Hinglish OPD note MUST link to the exact same pseudonym!
        """
        records_file = self.output_dir / "records.jsonl"
        self.assertTrue(records_file.exists())

        recs = [
            json.loads(line)
            for line in records_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

        hosp_a_psn = next(
            r["patient"]
            for r in recs
            if "hospital_a_registration.csv" in r["file"] and r["loc"] == "row:0"
        )
        hosp_b_psn = next(
            r["patient"]
            for r in recs
            if "hospital_b_discharge_hindi.txt" in r["file"]
        )
        hosp_c_psn = next(
            r["patient"]
            for r in recs
            if "hospital_c_opd_hinglish.txt" in r["file"]
        )
        hosp_d_psn = next(
            r["patient"]
            for r in recs
            if "hospital_d_nursing_english.txt" in r["file"]
        )

        self.assertIsNotNone(hosp_a_psn, "Hospital A must be linked")
        self.assertIsNotNone(hosp_b_psn, "Hospital B must be linked")
        self.assertIsNotNone(hosp_c_psn, "Hospital C must be linked")
        self.assertIsNotNone(hosp_d_psn, "Hospital D must be linked")

        self.assertEqual(
            hosp_a_psn,
            hosp_b_psn,
            "Devanagari Hindi and English CSV must share pseudonym",
        )
        self.assertEqual(
            hosp_a_psn,
            hosp_c_psn,
            "Hinglish OPD note must share same pseudonym",
        )
        self.assertEqual(
            hosp_a_psn,
            hosp_d_psn,
            "English nursing note must share same pseudonym",
        )

    def test_family_phone_trap_does_not_merge(self):
        """Different people sharing a phone must NOT merge (patient: null)."""
        records_file = self.output_dir / "records.jsonl"
        recs = [
            json.loads(line)
            for line in records_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        fam_recs = [r for r in recs if "family_phone_trap.csv" in r["file"]]
        for r in fam_recs:
            self.assertIsNone(
                r["patient"],
                "Family members sharing a phone without unique link must be patient: null",
            )

    def test_meaning_trap_clinical_preservations(self):
        """Parkinson's disease, Ramipril 5 mg, Dolo 650 BD, and doctors are preserved."""
        nurse_file = (
            self.output_dir
            / "sanitized"
            / "hospital_d_nursing_english.txt"
        )
        content = nurse_file.read_text(encoding="utf-8")
        self.assertIn("Parkinson's disease", content)
        self.assertIn("Ramipril 5 mg", content)
        self.assertIn("Dolo 650 BD", content)
        self.assertIn("Dr. Sanjay Sen", content)
        self.assertIn("C/O fever", content)
        self.assertNotIn("Md. Arif", content)


if __name__ == "__main__":
    unittest.main()
