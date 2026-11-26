import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestIntegrationContract(unittest.TestCase):
    def test_end_to_end_pipeline_contract(self):
        project_root = Path(__file__).resolve().parent.parent
        smoke_input = project_root / "tests" / "fixtures" / "smoke_test"

        self.assertTrue(smoke_input.exists(), "Smoke test fixture missing")

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "output"
            env = os.environ.copy()
            env["RAKSHA_SECRET"] = "integration-contract-secret-key"

            cmd = [
                sys.executable,
                str(project_root / "main.py"),
                "--input",
                str(smoke_input),
                "--output",
                str(out_dir),
            ]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"Pipeline failed: {res.stderr}")

            # 1. Output directory structure
            report_path = out_dir / "report.json"
            records_path = out_dir / "records.jsonl"
            sanitized_dir = out_dir / "sanitized"

            self.assertTrue(report_path.exists(), "report.json must exist")
            self.assertTrue(records_path.exists(), "records.jsonl must exist")
            self.assertTrue(sanitized_dir.exists(), "sanitized/ directory must exist")

            # 2. Validate report.json
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report.get("schema"), "raksha-report/1")
            self.assertIn("files", report)
            self.assertIn("counts", report)
            self.assertIn("timing", report)
            self.assertIn("resources", report)

            counts = report["counts"]
            required_counts = [
                "files_total",
                "files_sanitized",
                "files_quarantined",
                "records_processed",
                "identifiers_detected",
                "records_linked",
                "records_generalized",
                "records_suppressed",
                "records_quarantined",
            ]
            for c in required_counts:
                self.assertIn(c, counts)
                self.assertIsInstance(counts[c], int)

            # 3. Validate records.jsonl
            records = []
            for line in records_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self.assertIn("file", rec)
                    self.assertIn("loc", rec)
                    self.assertIn("patient", rec)
                    self.assertTrue(rec["file"].startswith("sanitized/"))
                    records.append(rec)

            self.assertEqual(len(records), counts["records_processed"])

            # 4. Zero secret leaks
            for p in out_dir.rglob("*"):
                if p.is_file():
                    content = p.read_bytes()
                    self.assertNotIn(
                        b"integration-contract-secret-key",
                        content,
                        f"Secret leaked in {p.name}",
                    )


if __name__ == "__main__":
    unittest.main()
