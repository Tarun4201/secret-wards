"""End-to-End Integration and Attacker Resistance Test on the 22-File Challenge Set.

Validates:
- 22 files processed, 19 sanitized, exactly 3 canary files quarantined
- report.json matches raksha-report/1 schema with honest counts
- records.jsonl conforms to locator standards
- Zero canary token leaks in any channel
- Zero direct PII leaks (names, phones, Aadhaar)
- 0.0% re-identification rate against VoterRegisterAttacker
- Exact clinical preservation (medications, doses, vitals, labs, diagnoses)
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CHALLENGE_DIR = REPO_ROOT / "tests" / "fixtures" / "challenge_set"
GROUND_TRUTH_FILE = REPO_ROOT / "tests" / "fixtures" / "challenge_ground_truth.json"

sys.path.insert(0, str(REPO_ROOT))
from tools.attacker.attacker import VoterProfile, VoterRegisterAttacker  # noqa: E402


@pytest.fixture(scope="module")
def challenge_run():
    """Run the pipeline once on the challenge set and cache the output directory."""
    with tempfile.TemporaryDirectory() as tmp:
        env = os.environ.copy()
        env["RAKSHA_SECRET"] = "challenge_test_secret_e2e_2026"
        res = subprocess.run(
            [sys.executable, str(REPO_ROOT / "main.py"), "--input", str(CHALLENGE_DIR), "--output", tmp],
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"Pipeline failed: {res.stderr}"

        # Load artifacts
        out_path = Path(tmp)
        report = json.loads((out_path / "report.json").read_text(encoding="utf-8"))
        records = [
            json.loads(line)
            for line in (out_path / "records.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        san_texts = {
            p.relative_to(out_path / "sanitized").as_posix(): p.read_text(encoding="utf-8", errors="ignore")
            for p in (out_path / "sanitized").rglob("*")
            if p.is_file()
        }

        yield {
            "res": res,
            "report": report,
            "records": records,
            "san_texts": san_texts,
            "out_dir": out_path,
        }


class TestChallengeSetE2E:
    """Comprehensive E2E test suite for the challenge fixtures."""

    def test_fr01_fr11_fr13_pipeline_counts_and_quarantine(self, challenge_run):
        rep = challenge_run["report"]
        assert rep["schema"] == "raksha-report/1"

        counts = rep["counts"]
        assert counts["files_total"] == 22
        assert counts["files_sanitized"] == 19
        assert counts["files_quarantined"] == 3
        assert counts["records_processed"] >= 60
        assert counts["identifiers_detected"] > 200

        # Verify exactly the canary files were quarantined
        quarantined = [f for f in rep["files"] if f["status"] == "quarantined"]
        assert len(quarantined) == 3
        for qf in quarantined:
            assert qf["reason"] == "canary_in_filename"
            assert qf["output"] is None

    def test_fr12_fr13_records_jsonl_locators(self, challenge_run):
        recs = challenge_run["records"]
        assert len(recs) >= 60

        for r in recs:
            assert "file" in r
            assert "loc" in r
            assert "patient" in r
            assert r["file"].startswith("sanitized/")
            # Locator format check: doc, row:N, or JSON pointer
            loc = r["loc"]
            is_valid_loc = (
                loc == "doc"
                or re.match(r"^row:\d+$", loc)
                or loc.startswith("/")
            )
            assert is_valid_loc, f"Invalid locator: {loc}"

    def test_nfr04_zero_canary_leaks(self, challenge_run):
        # Read ground truth for canary tokens
        gt = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))
        canaries = set()
        for v in gt.values():
            if isinstance(v, dict) and "canary_tokens" in v:
                canaries.update(v["canary_tokens"])

        # Also check common canary markers
        canaries.update(["canary-alpha-99", "trap-string-omega-7", "CANARY_DO_NOT_PROCESS"])

        # Check in report.json
        rep_str = json.dumps(challenge_run["report"])
        for token in canaries:
            assert token not in rep_str, f"Canary token '{token}' leaked into report.json"

        # Check in all sanitized outputs
        for fn, text in challenge_run["san_texts"].items():
            for token in canaries:
                assert token not in text, f"Canary token '{token}' leaked into sanitized/{fn}"

    def test_fr04_zero_direct_identifier_leaks(self, challenge_run):
        gt = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))

        for fn, text in challenge_run["san_texts"].items():
            info = gt.get(fn, {})
            # Check unmasked phone
            phone = info.get("phone")
            if phone:
                clean_phone = phone.replace("-", "").replace(" ", "")
                assert clean_phone not in text, f"Phone {phone} leaked into {fn}"

            # Check unmasked Aadhaar
            aadhaar = info.get("aadhaar")
            if aadhaar:
                clean_aadhaar = aadhaar.replace(" ", "")
                assert clean_aadhaar not in text, f"Aadhaar {aadhaar} leaked into {fn}"

            # Check patient name
            pname = info.get("patient_name")
            if pname and not info.get("must_quarantine"):
                # Multi-word full name should not appear as an exact match
                assert pname.lower() not in text.lower(), f"Patient name '{pname}' leaked into {fn}"

    def test_voter_register_attacker_resistance(self, challenge_run):
        gt = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))
        targets = []
        for fn, info in gt.items():
            if info.get("patient_name") and not info.get("must_quarantine"):
                targets.append(
                    VoterProfile(
                        id=fn,
                        name=info["patient_name"],
                        age=info.get("age", 40),
                        gender="M",
                        village=info.get("village", ""),
                        pin="302001",
                        phone=info.get("phone", ""),
                    )
                )

        attacker = VoterRegisterAttacker(targets)
        # Attack the sanitized texts
        res = attacker.attack_directory(challenge_run["out_dir"] / "sanitized")

        assert res.direct_leaks_found == 0, f"Attacker found {res.direct_leaks_found} direct leaks"
        assert res.uniquely_reidentified == 0, f"Attacker uniquely re-identified {res.uniquely_reidentified} patients"
        assert res.reidentification_rate == 0.0

    def test_fr06_clinical_preservation(self, challenge_run):
        gt = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))

        for fn, info in gt.items():
            if fn in challenge_run["san_texts"]:
                out_text = challenge_run["san_texts"][fn]
                for term in info.get("clinical_preserve", []):
                    assert term.lower() in out_text.lower(), (
                        f"Clinical term '{term}' was lost in sanitized/{fn}"
                    )

    def test_fr07_stay_duration_preservation(self, challenge_run):
        # textual_dates_note.txt: Admit 15 Jan 2024, Surgery 17th Jan, Discharge 22-Jan-2024 -> 7 days stay
        text = challenge_run["san_texts"].get("textual_dates_note.txt", "")
        assert text, "textual_dates_note.txt not found in sanitized output"

        # Check that dates were shifted
        assert "15 Jan 2024" not in text
        assert "22-Jan-2024" not in text

        # Parse shifted dates
        months = {
            "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
            "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12
        }
        # Admission date: \d{1,2}\s+[A-Za-z]{3,}\s+\d{4}
        admit_m = re.search(r"Date of Admission:\s*(\d{1,2})\s+([A-Za-z]{3,})\s+(\d{4})", text, re.IGNORECASE)
        disch_m = re.search(r"Date of Discharge:\s*(\d{1,2})-([A-Za-z]{3,})-(\d{4})", text, re.IGNORECASE)

        if admit_m and disch_m:
            from datetime import date
            admit_d = date(int(admit_m.group(3)), months[admit_m.group(2)[:3].lower()], int(admit_m.group(1)))
            disch_d = date(int(disch_m.group(3)), months[disch_m.group(2)[:3].lower()], int(disch_m.group(1)))
            stay_days = (disch_d - admit_d).days
            assert stay_days == 7, f"Expected 7-day stay duration preserved, got {stay_days}"
