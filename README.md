<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/pipeline-dark.svg">
  <img alt="RAKSHA Pipeline: Safe Ingestion → Detector + Veto → Cross-Script Linkage → Keyed Transform → Sweep Verifier → Output Contract" src="docs/assets/pipeline-light.svg" width="100%">
</picture>

# 🛡️ RAKSHA — Evidence-Guided Privacy Compiler

**Track 3: Secret Wards | Yugaantar DevForge Hackathon**

*Offline, CPU-only, LLM-free privacy firewall for synthetic Indian hospital records.*

[![Status](https://img.shields.io/badge/status-READY%20TO%20SUBMIT-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![Tests](https://img.shields.io/badge/tests-67%2F67%20passing-brightgreen)]()
[![Leaks](https://img.shields.io/badge/PII%20leaks-0%25-brightgreen)]()

</div>

---

## Table of Contents

- [What is RAKSHA?](#what-is-raksha)
- [Results at a Glance](#results-at-a-glance)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Offline Setup (Step-by-Step)](#offline-setup-step-by-step)
- [Running the Pipeline](#running-the-pipeline)
- [Running Tests](#running-tests)
- [Running the Attacker Benchmark](#running-the-attacker-benchmark)
- [Official Validation](#official-validation)
- [Configuration](#configuration)
- [Output Format](#output-format)
- [Dependencies](#dependencies)
- [Troubleshooting](#troubleshooting)
- [Team](#team)

---

## What is RAKSHA?

Hospitals in Yugaantar Pradesh are merging clinical records from 4 different hospital systems. These records are written in **English**, **Devanagari Hindi**, and **Hinglish** (mixed).

RAKSHA is a privacy pipeline that:

1. **Finds** all personal data (names, phones, Aadhaar, addresses, insurance IDs) across all 3 scripts.
2. **Removes** personal identifiers and replaces them with safe pseudonyms.
3. **Keeps** all medical data intact (medicines, doses, vitals, lab values, diagnoses, procedures).
4. **Links** records of the same patient across hospitals without merging different people.
5. **Verifies** every output file for any leaked personal data before release.

**Key constraints:** Runs fully offline, CPU-only, with zero LLMs or cloud APIs. Deterministic output — same input + same secret = same output every time.

---

## Results at a Glance

| Metric | Result |
|--------|--------|
| Personal data leaks | **0 / 3,230 (0.0%)** |
| Canary traps leaked | **0 / 4** |
| Medical data preserved | **4,854 / 4,855 (99.98%)** |
| Patient linkage precision | **1.00 (0 false merges)** |
| Patient linkage recall | **1.00 (F0.5: 1.00)** |
| Attacker re-identification | **0.0%** (vs 53% on raw data) |
| Unit tests | **67 / 67 passing** |
| Official contract | ✅ `CONTRACT OK` |
| Submission check | ✅ `READY TO SUBMIT` |
| Runtime (practice data) | **~4 seconds** |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        RAKSHA PIPELINE                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────────────────────────┐                       │
│  │  1. SAFE INGESTION & BOUNDED PARSERS     │                       │
│  │  ─────────────────────────────────────    │                       │
│  │  • Encoding detection (UTF-8/16, cp1252) │                       │
│  │  • Format: JSON, CSV, TSV, FHIR R4, TXT  │                       │
│  │  • Broken/unsupported → quarantine        │                       │
│  │  • Nesting depth limits, size guards      │                       │
│  └────────────────────┬─────────────────────┘                       │
│                       ▼                                              │
│  ┌──────────────────────────────────────────┐                       │
│  │  2. MULTILINGUAL PII DETECTOR            │                       │
│  │  ─────────────────────────────────────    │                       │
│  │  • 50+ regex patterns (Latin + Devanagari)│                       │
│  │  • 500+ name gazetteer (Indian names)     │                       │
│  │  • Indic digit detection (Aadhaar, phone) │                       │
│  │  • Role-first clinical veto:              │                       │
│  │    ✓ "Dolo 650" → NOT a phone number      │                       │
│  │    ✓ "C/O fever" → NOT a person name      │                       │
│  │    ✓ "Ramipril 5 mg" → protected          │                       │
│  └────────────────────┬─────────────────────┘                       │
│                       ▼                                              │
│  ┌──────────────────────────────────────────┐                       │
│  │  3. EVIDENCE GRAPH & RECORD LINKAGE      │                       │
│  │  ─────────────────────────────────────    │                       │
│  │  • Cross-script name skeleton             │                       │
│  │    (Mohammad = Mohd = मोहम्मद)             │                       │
│  │  • Multi-pass blocking on strong IDs      │                       │
│  │    (UHID, Aadhaar, ABHA, phone)           │                       │
│  │  • Phonetic fuzzy matching (Jellyfish)     │                       │
│  │  • Conflict-aware: no transitive merges   │                       │
│  │  • Weak evidence → patient: null           │                       │
│  └────────────────────┬─────────────────────┘                       │
│                       ▼                                              │
│  ┌──────────────────────────────────────────┐                       │
│  │  4. PSEUDONYMIZATION & DATE SHIFTING     │                       │
│  │  ─────────────────────────────────────    │                       │
│  │  • Keyed HMAC-SHA256 (from RAKSHA_SECRET)│                       │
│  │  • Stable pseudonyms: PSN-XXXXXX          │                       │
│  │  • Per-patient coherent date shifts       │                       │
│  │  • Age → 5-year bands (always truthful)   │                       │
│  │  • PIN codes → 3-digit prefix only        │                       │
│  └────────────────────┬─────────────────────┘                       │
│                       ▼                                              │
│  ┌──────────────────────────────────────────┐                       │
│  │  5. OUTPUT SERIALIZERS & CHANNEL CLEANING│                       │
│  │  ─────────────────────────────────────    │                       │
│  │  • sanitized/ (cleaned files)             │                       │
│  │  • report.json (audit + statistics)       │                       │
│  │  • records.jsonl (all records, linked)     │                       │
│  │  • Filenames, headers, keys cleaned       │                       │
│  └────────────────────┬─────────────────────┘                       │
│                       ▼                                              │
│  ┌──────────────────────────────────────────┐                       │
│  │  6. SWEEP VERIFIER (Final Safety Net)    │                       │
│  │  ─────────────────────────────────────    │                       │
│  │  • Re-scans all output for any leaked PII│                       │
│  │  • Checks side channels: filenames,       │                       │
│  │    metadata, JSON keys, headers           │                       │
│  │  • Leaky files → re-cleaned or quarantined│                       │
│  └──────────────────────────────────────────┘                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Rule-based, no ML** | Deterministic, offline, CPU-only. No model weights to load. |
| **Gazetteer + regex** | Covers Indian names across Latin and Devanagari without training data. |
| **Role-first clinical veto** | Prevents medical data from being wrongly flagged as PII (e.g., drug names, dosages). |
| **Evidence graph linkage** | Links patient records safely; rejects when evidence conflicts. |
| **Sweep verifier** | Final safety net — catches anything the main detector missed. |
| **Quarantine, not crash** | Broken files are quarantined with reasons; pipeline never crashes. |

---

## Project Structure

```
raksha/
├── main.py                  # Core pipeline (single file, ~2800 lines)
├── config/
│   └── policy.yaml          # Privacy policy configuration
├── requirements.txt         # Runtime dependencies (6 packages)
├── requirements-dev.txt     # Dev/test dependencies
├── Makefile                 # Shortcuts: make test, make bench
├── pyproject.toml           # Ruff linter config
├── raksha.toml              # Project metadata
│
├── docs/
│   ├── BRIEF.md             # 2-page technical brief
│   ├── DECISIONS.md          # Architecture decision log
│   └── RAKSHA_OFFICIAL_TEST_REPORT.md  # Test results report
│
├── tests/                   # 67 unit & integration tests
│   ├── test_clinical_protection.py
│   ├── test_comprehensive_ingestion.py
│   ├── test_date_shift_and_age.py
│   ├── test_determinism.py
│   ├── test_evidence_graph_linkage.py
│   ├── test_fhir.py
│   ├── test_integration_contract.py
│   ├── test_linkage.py
│   ├── test_name_skeleton.py
│   ├── test_pseudonym.py
│   ├── test_role_resolver.py
│   ├── test_safe_reader.py
│   ├── test_security_and_sweep.py
│   ├── test_semantic_column_typing.py
│   ├── test_serializers.py
│   ├── test_sweep_variants.py
│   ├── test_textual_dates_and_nlem.py
│   ├── ... and more
│   └── fixtures/             # Test data (synthetic only)
│
└── tools/                    # Benchmarking & testing utilities
    ├── attacker/             # Adversarial re-identification tester
    │   ├── attacker.py
    │   └── llm_attacker.py
    ├── benchmark/
    │   ├── benchmark.py      # Privacy vs utility benchmark
    │   └── ablation.py       # Technique ablation study
    └── datagen/              # Synthetic test data generators
```

---

## Offline Setup (Step-by-Step)

> ⚠️ **The event day has NO internet.** Follow these steps to prepare everything offline before the event.

### Pre-Event Preparation (While You Have Internet)

```powershell
cd E:\scalar_hackthon\secret-wards

python.exe -m venv .venv

.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip

pip install -r requirements.txt

pip install -r requirements-dev.txt
```

Verify installation and run tests:

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

### Pre-Download All Wheels for Offline Install

If your teammates need to install on a machine without internet:

```powershell
# Download all wheels to a folder (run this WHILE ONLINE)
mkdir offline_wheels
pip download -r requirements.txt -d offline_wheels/
pip download -r requirements-dev.txt -d offline_wheels/

# Transfer the entire project folder (including offline_wheels/) to the offline machine
```

### Offline Install (No Internet)

```powershell
cd E:\scalar_hackthon\secret-wards

python.exe -m venv .venv

.\.venv\Scripts\Activate.ps1

# Install from local wheels
pip install --no-index --find-links=offline_wheels/ -r requirements.txt

pip install --no-index --find-links=offline_wheels/ -r requirements-dev.txt

# Verify
python -c "import regex, rapidfuzz, jellyfish, phonenumbers, indic_transliteration, psutil; print('All deps OK')"
```

---

## Running the Pipeline

### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
$env:RAKSHA_SECRET = "your-team-secret-key-here"
python main.py --input C:\path\to\input --output C:\path\to\output
```

### macOS / Linux (Bash)

```bash
source .venv/bin/activate
export RAKSHA_SECRET="your-team-secret-key-here"
python main.py --input /path/to/input --output /path/to/output
```

### Example with Practice Data

```powershell
# Assuming toolkit is in a sibling directory
$env:RAKSHA_SECRET = "my-secret-2024"
python main.py --input ..\toolkit\dev\input --output .\output
```

### What Happens

1. Pipeline reads all files from `--input` directory recursively.
2. Detects and removes PII across English, Hindi, and Hinglish.
3. Links patient records across hospitals.
4. Writes sanitized output to `--output` directory.
5. Prints a summary table to stdout.

### Important Notes

- **`RAKSHA_SECRET` is mandatory.** The pipeline will fail without it.
- **Same secret = same output.** Pseudonyms and date shifts are deterministic.
- **Different secret = different pseudonyms.** You can't reverse-engineer the secret from the output.
- **Never share or log the secret.** It never appears in any output file.

---

## Running Tests

```powershell
# Activate virtual environment first
.\.venv\Scripts\Activate.ps1

# Run all 67 tests
python -m unittest discover -s tests -p "test_*.py"

# Run a specific test file
python -m unittest tests.test_clinical_protection

# Run with verbose output
python -m unittest discover -s tests -p "test_*.py" -v

# Run with pytest (if installed)
pytest tests/ -v
```

> **Note (macOS / Linux):** You can also use `make test` where GNU `make` is installed.

### Test Categories

| Test File | What It Tests |
|-----------|---------------|
| `test_clinical_protection.py` | Medicines, doses, vitals not wrongly removed |
| `test_comprehensive_ingestion.py` | CSV, TSV, JSON, FHIR, TXT parsing |
| `test_date_shift_and_age.py` | Date shifting, age banding |
| `test_determinism.py` | Same input + secret = same output |
| `test_evidence_graph_linkage.py` | Cross-hospital patient linking |
| `test_fhir.py` | FHIR R4 bundle handling |
| `test_integration_contract.py` | Output contract (sanitized/, report.json, records.jsonl) |
| `test_name_skeleton.py` | Cross-script name normalization |
| `test_pseudonym.py` | HMAC pseudonym generation |
| `test_role_resolver.py` | Doctor vs patient vs relative roles |
| `test_safe_reader.py` | Encoding detection, malformed files |
| `test_security_and_sweep.py` | Side-channel cleaning, sweep verifier |
| `test_semantic_column_typing.py` | Column-type inference |
| `test_sweep_variants.py` | Variant probes for leaked values |

---

## Running the Attacker Benchmark

Test how well the pipeline resists re-identification:

```powershell
# Run the voter-registry attacker against sanitized output
python tools/attacker/attacker.py `
    --registry ..\toolkit\dev\attacker\registry.csv `
    --sanitized .\output\sanitized `
    --records .\output\records.jsonl
```

### Run the Full Benchmark Suite

```powershell
# Privacy vs utility benchmark
python tools/benchmark/benchmark.py

# Ablation study (tests each technique's contribution)
python tools/benchmark/ablation.py
```

---

## Official Validation

Run the official toolkit checks to verify submission readiness:

```powershell
# 1. Validate output contract
python ..\toolkit\validate_output.py --input ..\toolkit\dev\input --output .\output
# Expected: "CONTRACT OK"

# 2. Check detection accuracy
python ..\toolkit\check_dev.py --output .\output --show 10
# Expected: 0 leaks, 0 canaries

# 3. Full submission check (runs pipeline 3x for determinism)
python ..\toolkit\check_submission.py --repo . --run
# Expected: "READY TO SUBMIT"
```

> **Note:** Do NOT modify the official toolkit scripts. They are the source of truth.

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `RAKSHA_SECRET` | **Yes** | Secret key for HMAC pseudonyms and date shifts. Never logged. |
| `RAKSHA_DISABLE_CLINICAL_VETO` | No | Set to `1` to disable clinical veto (for ablation testing only). |
| `RAKSHA_DISABLE_NAME_SKELETON` | No | Set to `1` to disable cross-script name normalization. |
| `RAKSHA_DISABLE_SWEEP_VERIFIER` | No | Set to `1` to disable the sweep verifier. |
| `RAKSHA_DISABLE_SEMANTIC_TYPING` | No | Set to `1` to disable semantic column typing. |
| `RAKSHA_DISABLE_NEGATIVE_EVIDENCE` | No | Set to `1` to disable negative evidence in linkage. |
| `RAKSHA_DISABLE_PRIVACY_PLANNER` | No | Set to `1` to disable the privacy planner. |

### Policy Config (`config/policy.yaml`)

```yaml
age_band_years: 5             # Width of age bands (e.g., 25-29)
date_shift_max_days: 180      # Maximum random date shift in days
min_group_size: 5             # Minimum k-anonymity group size
link_strong_threshold: 0.8   # Confidence threshold for patient linking
link_margin: 0.2              # Margin below threshold → patient: null
```

---

## Output Format

The pipeline produces exactly 3 outputs inside the `--output` directory:

```
output/
├── sanitized/          # Cleaned files (same structure as input)
│   ├── hospital_a/
│   │   ├── discharge_summary_PSN-A1B2C3.txt
│   │   └── labs_cleaned.csv
│   └── hospital_b/
│       └── bundle_cleaned.json
├── report.json         # Audit report with statistics
└── records.jsonl       # All records, one per line, with pseudonyms
```

### `report.json` Contents

- Input file SHA-256 hashes
- Number of files processed, sanitized, quarantined
- Number of records extracted
- PII types detected and counts
- Quarantine reasons for rejected files
- Runtime and memory usage

### `records.jsonl` Format

Each line is a JSON object:

```json
{
  "patient": "PSN-A1B2C3",
  "source_sha256": "abc123...",
  "hospital": "hospital_a",
  "record_type": "discharge_summary",
  "data": { "...sanitized clinical fields..." }
}
```

If patient identity is uncertain: `"patient": null`

---

## Dependencies

### Runtime (6 packages — all lightweight, CPU-only)

| Package | Version | Purpose |
|---------|---------|---------|
| `regex` | ≥ 2024.0 | Advanced regex with Unicode support |
| `rapidfuzz` | ≥ 3.0 | Fast fuzzy string matching for linkage |
| `jellyfish` | ≥ 1.0 | Phonetic algorithms (Soundex, Metaphone) |
| `phonenumbers` | ≥ 8.13 | Phone number parsing and validation |
| `indic-transliteration` | ≥ 2.3 | Devanagari ↔ Latin transliteration |
| `psutil` | ≥ 5.9 | Memory monitoring |

### Dev/Test (optional)

| Package | Purpose |
|---------|---------|
| `pytest` | Test runner |
| `pytest-cov` | Coverage reporting |
| `hypothesis` | Property-based testing |
| `scikit-learn` | Linkage evaluation metrics |
| `ruff` | Linter |
| `faker` | Synthetic data generation |

**No LLMs.** No transformers. No neural networks. No cloud APIs. Everything is rule-based, phonetic, gazetteer-driven, and algorithmic.

---

## Troubleshooting

### "RAKSHA_SECRET not set"

```bash
export RAKSHA_SECRET="your-secret"  # Linux/macOS
$env:RAKSHA_SECRET = "your-secret"  # Windows PowerShell
set RAKSHA_SECRET=your-secret       # Windows CMD
```

### "ModuleNotFoundError: No module named 'regex'"

```powershell
# Make sure your virtual environment is activated
.\.venv\Scripts\Activate.ps1   # Windows PowerShell
# source .venv/bin/activate     # macOS / Linux
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### "CONTRACT OK" but "check_dev.py" shows leaks

The practice data may have edge cases. Check which PII types are leaking and inspect the specific files. Common causes:
- New name not in the gazetteer
- Unusual identifier format
- Devanagari digits in phone/Aadhaar numbers

### Pipeline quarantines too many files

Check `report.json` for quarantine reasons. Common causes:
- Deeply nested JSON (> 50 levels)
- Empty files
- Binary files in the input
- Encoding issues (try re-saving as UTF-8)

### Tests fail on a fresh clone

```powershell
# Make sure your virtual environment is active and dev dependencies are installed
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
# Run tests
python -m unittest discover -s tests -p "test_*.py"
```

---

## Team

**Team:** Phantom Troupe 
**Track:** 3 — Secret Wards  
**Event:** Yugaantar DevForge Hackathon  
**Repository:** https://github.com/Tarun4201/secret-wards

---

## License

This project is built for the Yugaantar DevForge Hackathon (Track 3: Secret Wards).
