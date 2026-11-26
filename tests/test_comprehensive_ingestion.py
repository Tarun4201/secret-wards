"""Tests for Comprehensive Multi-Format & Multi-Encoding Ingestion.
Requirements: FR-01, FR-02, FR-11, FR-12
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "comprehensive_test_set"
MAIN_PY = ROOT / "main.py"


class TestComprehensiveIngestion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Generate fixtures if not present
        if not FIXTURES.exists() or len(list(FIXTURES.iterdir())) < 16:
            from tools.datagen.generate_comprehensive_set import generate

            generate()

    def test_fr01_multiformat_and_quarantine_ingestion(self):
        """Pipeline ingests CSV, TSV, JSON, FHIR R4, Text (UTF-8, UTF-8 BOM, UTF-16, cp1252)

        and safely quarantines broken, truncated, empty, and unsupported files without crashing.
        """
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"
            env = os.environ.copy()
            env["RAKSHA_SECRET"] = "comprehensive_test_key_123"

            res = subprocess.run(
                [
                    sys.executable,
                    str(MAIN_PY),
                    "--input",
                    str(FIXTURES),
                    "--output",
                    str(out_dir),
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                res.returncode, 0, f"Pipeline failed with stderr: {res.stderr}"
            )

            report_file = out_dir / "report.json"
            self.assertTrue(
                report_file.exists(), "report.json must be generated"
            )

            report = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(report["counts"]["files_total"], 16)
            self.assertEqual(report["counts"]["files_sanitized"], 9)
            self.assertEqual(report["counts"]["files_quarantined"], 7)

            sanitized_outputs = {
                f["output"]
                for f in report["files"]
                if f["status"] == "sanitized"
            }
            quarantined_reasons = {
                f.get("reason")
                for f in report["files"]
                if f["status"] == "quarantined"
            }

            # 1. Encodings and valid formats must be in sanitized/
            self.assertIn("sanitized/record_utf8.csv", sanitized_outputs)
            self.assertIn("sanitized/record_utf8_bom.tsv", sanitized_outputs)
            self.assertIn("sanitized/record_utf16le.json", sanitized_outputs)
            self.assertIn("sanitized/record_utf16be.txt", sanitized_outputs)
            self.assertIn("sanitized/record_cp1252.txt", sanitized_outputs)
            self.assertIn("sanitized/fhir_r4_bundle.json", sanitized_outputs)
            self.assertIn("sanitized/hinglish_discharge.txt", sanitized_outputs)
            self.assertIn("sanitized/devanagari_summary.txt", sanitized_outputs)

            # 2. Quarantined files must carry expected audit reasons
            self.assertIn("empty_file", quarantined_reasons)
            self.assertIn("unsupported_format", quarantined_reasons)
            self.assertIn("excessive_nesting", quarantined_reasons)
            self.assertIn("format_mismatch", quarantined_reasons)
            self.assertIn("undecodable_text", quarantined_reasons)
            self.assertIn("JSONDecodeError", quarantined_reasons)


if __name__ == "__main__":
    unittest.main()
