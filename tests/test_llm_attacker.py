"""Tests for LLM Red-Team Attacker and Adversary Tools.
Requirements: NFR-01, PRD Section 12.2
"""
import tempfile
import unittest
from pathlib import Path

from tools.attacker.attacker import VoterProfile
from tools.attacker.llm_attacker import AttackerCalibration, LLMAttacker, LLMClient


class TestLLMAttacker(unittest.TestCase):
    def setUp(self):
        self.client = LLMClient()
        self.attacker = LLMAttacker(self.client)
        self.voters = [
            VoterProfile(id="V1", name="Ramesh Sharma", age=55, gender="M",
                         village="Baragaon", pin="241001", phone="9876543210"),
            VoterProfile(id="V2", name="Sunita Devi", age=45, gender="F",
                         village="Shahpur", pin="241124", phone="9123456789")
        ]

    def test_llm_attacker_detects_leaks_in_unredacted_raw(self):
        """Adversarial evaluator detects raw phone numbers and target name leaks."""
        with tempfile.TemporaryDirectory() as td:
            raw_file = Path(td) / "raw_note.txt"
            raw_file.write_text(
                "Patient: Ramesh Sharma, Phone: 9876543210, Village: Baragaon.\n"
                "Canary: canary-alpha-99 embedded here.",
                encoding="utf-8"
            )

            verdicts = self.attacker.attack_file(raw_file, self.voters)
            self.assertTrue(any(v.identified for v in verdicts))
            self.assertTrue(any("canary-alpha-99" in v.canaries_found for v in verdicts))
            self.assertTrue(any("9876543210" in v.direct_leaks for v in verdicts))

    def test_llm_attacker_reports_zero_leaks_on_clean_sanitized(self):
        """Sanitized output containing only pseudonyms and generalized data reports 0 leaks."""
        with tempfile.TemporaryDirectory() as td:
            san_file = Path(td) / "sanitized_note.txt"
            san_file.write_text(
                "Patient: PSN-79HK4B\n"
                "Age: 50-54 yrs\n"
                "Admitted: 25/01/2024, Discharged: 30/01/2024\n"
                "Rx: Tab Paracetamol 650mg TDS, Tab Pan-D 1-0-0\n"
                "BP: 120/80 mmHg, SpO2: 98%",
                encoding="utf-8"
            )

            verdicts = self.attacker.attack_file(san_file, self.voters)
            # No target identified and no direct leaks
            self.assertFalse(any(v.identified for v in verdicts))
            self.assertEqual(sum(len(v.direct_leaks) for v in verdicts), 0)
            self.assertEqual(sum(len(v.canaries_found) for v in verdicts), 0)

    def test_calibration_comparison_runs(self):
        """Attacker calibration compares heuristic and LLM attackers cleanly."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "sample.txt"
            p.write_text("Patient: PSN-123456\nAge: 40-44\nDiagnosis: Fever\n", encoding="utf-8")

            calib = AttackerCalibration.compare(Path(td), self.voters)
            self.assertIn("heuristic_reid_rate", calib)
            self.assertIn("llm_reid_rate", calib)
            self.assertTrue(calib["agreement"])


if __name__ == "__main__":
    unittest.main()
