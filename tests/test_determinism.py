"""Tier 1 & 2 Tests: Determinism, Input Immutability, Changed-Secret Behavior
Requirements: NFR-02, NFR-05
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

MAIN_PY = str(Path(__file__).resolve().parent.parent / "main.py")
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "smoke_test"


class TestDeterminism(unittest.TestCase):
    """NFR-02: Same input + same RAKSHA_SECRET → identical output."""

    def _run_pipeline(self, input_dir, output_dir, secret):
        env = os.environ.copy()
        env["RAKSHA_SECRET"] = secret
        res = subprocess.run(
            [sys.executable, MAIN_PY, "--input", str(input_dir), "--output", str(output_dir)],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(res.returncode, 0, f"Pipeline failed: {res.stderr}")

    def _hash_tree(self, root: Path) -> dict[str, str]:
        """SHA-256 hash of every file under root."""
        hashes = {}
        for p in sorted(root.rglob("*")):
            if p.is_file():
                hashes[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
        return hashes

    def test_nfr02_same_secret_gives_identical_output(self):
        """Running twice with the same secret must produce byte-identical output."""
        with tempfile.TemporaryDirectory() as tmp:
            out1 = Path(tmp) / "run1"
            out2 = Path(tmp) / "run2"
            self._run_pipeline(FIXTURES, out1, "determinism_test_secret")
            self._run_pipeline(FIXTURES, out2, "determinism_test_secret")

            h1 = self._hash_tree(out1)
            h2 = self._hash_tree(out2)

            self.assertEqual(set(h1.keys()), set(h2.keys()), "File sets differ between runs")
            for fname in h1:
                if fname == "report.json":
                    # report.json has timing/rss which vary; compare structurally
                    r1 = json.loads((out1 / fname).read_text(encoding="utf-8"))
                    r2 = json.loads((out2 / fname).read_text(encoding="utf-8"))
                    self.assertEqual(r1["files"], r2["files"], "report files section differs")
                    self.assertEqual(r1["counts"], r2["counts"], "report counts section differs")
                    continue
                self.assertEqual(h1[fname], h2[fname], f"File {fname} differs between runs")

    def test_nfr02_different_secret_changes_pseudonyms(self):
        """Different RAKSHA_SECRET must change pseudonyms and date shifts."""
        with tempfile.TemporaryDirectory() as tmp:
            out1 = Path(tmp) / "run_a"
            out2 = Path(tmp) / "run_b"
            self._run_pipeline(FIXTURES, out1, "secret_alpha")
            self._run_pipeline(FIXTURES, out2, "secret_beta")

            rec1 = [json.loads(line) for line in (out1 / "records.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            rec2 = [json.loads(line) for line in (out2 / "records.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]

            # At least one pseudonym that is non-null should differ
            psns1 = {r["patient"] for r in rec1 if r["patient"]}
            psns2 = {r["patient"] for r in rec2 if r["patient"]}
            if psns1 and psns2:
                self.assertNotEqual(psns1, psns2, "Different secrets must produce different pseudonyms")

    def test_nfr05_input_is_read_only(self):
        """Pipeline must never modify the input directory."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Copy fixtures to a fresh input dir
            inp = tmp_path / "input_copy"
            shutil.copytree(FIXTURES, inp)

            # Hash input before run
            before = self._hash_tree(inp)

            out = tmp_path / "output"
            self._run_pipeline(inp, out, "immutability_test")

            # Hash input after run
            after = self._hash_tree(inp)

            self.assertEqual(before, after, "Input directory was modified during pipeline run!")

    def test_nfr03_secret_not_in_any_output(self):
        """RAKSHA_SECRET must never appear in any output file, report, or records."""
        secret = "super_secret_key_xyz_12345"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "output"
            self._run_pipeline(FIXTURES, out, secret)

            for p in out.rglob("*"):
                if p.is_file():
                    content = p.read_text(encoding="utf-8", errors="ignore")
                    self.assertNotIn(secret, content, f"Secret leaked in {p.name}")


if __name__ == "__main__":
    unittest.main()
