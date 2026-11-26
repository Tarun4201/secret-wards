"""Tier 2 Tests: Attacker & Benchmark Verification and Modular Isolation
Requirements: NFR-01, Section 10.4
"""
import tempfile
import unittest
from pathlib import Path

from tools.attacker.attacker import VoterProfile, VoterRegisterAttacker
from tools.benchmark.benchmark import measure_clinical_utility


class TestAttackerBenchmark(unittest.TestCase):
    def test_nfr01_main_does_not_import_tools(self):
        """main.py must NEVER import tools, attacker, or benchmark (Section 10.4)."""
        main_path = Path(__file__).resolve().parent.parent / "main.py"
        content = main_path.read_text(encoding="utf-8")
        self.assertNotIn("tools.", content)
        self.assertNotIn("from tools", content)
        self.assertNotIn("import tools", content)
        self.assertNotIn("attacker", content.lower().split("class")[0])  # no attacker import in header

    def test_attacker_detects_direct_leak_in_raw(self):
        """Attacker correctly flags direct identifier leaks in unredacted files."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "raw.txt").write_text("Patient: Suresh Patel, Phone: 9811223344", encoding="utf-8")

            targets = [
                VoterProfile(id="V1", name="Suresh Patel", age=40, gender="M", village="A", pin="110001", phone="9811223344")
            ]
            attacker = VoterRegisterAttacker(targets)
            res = attacker.attack_directory(tmp_path)

            self.assertEqual(res.direct_leaks_found, 1)
            self.assertEqual(res.reidentification_rate, 1.0)

    def test_clinical_utility_metric(self):
        """measure_clinical_utility accurately scores preserved clinical terms."""
        with tempfile.TemporaryDirectory() as tmp_in, tempfile.TemporaryDirectory() as tmp_out:
            in_p = Path(tmp_in)
            out_p = Path(tmp_out)
            (out_p / "sanitized").mkdir()

            (in_p / "note.txt").write_text("Patient prescribed Dolo 650 BD and Metformin", encoding="utf-8")
            (out_p / "sanitized" / "note.txt").write_text("Prescribed Dolo 650 BD and Metformin", encoding="utf-8")

            utility = measure_clinical_utility(in_p, out_p)
            self.assertGreaterEqual(utility, 0.95)


if __name__ == "__main__":
    unittest.main()
