# Secret Wards: Evidence-Guided Privacy Compiler

**Product:** Offline, CPU-only, LLM-free privacy firewall for synthetic Indian hospital records (Yugaantar DevForge, Track 3)  
**Team:** secret-wards  
**Repository:** https://github.com/Tarun4201/secret-wards  

---

## 1. Executive Summary & USP

Hospitals in Yugaantar Pradesh merge disparate, heterogeneous clinical records across English, Devanagari Hindi, and Hinglish. Standard off-the-shelf PII redaction either drops vital medical contexts or leaks quasi-identifiers across transliterations and fragmented identities.

**USP:** An *Evidence-Guided Privacy Compiler* that tracks cross-script evidence through reading, linkage, and transformation, blocks unsafe merges on conflicting evidence, guarantees zero direct-identifier leaks, applies role-first clinical protection, and strictly preserves critical clinical values (medicines, dosages, vitals, labs with units, diagnoses, procedures, and length of stay).

---

## 2. Architecture & Pipeline

```
Heterogeneous Raw Input (CSV, TSV, Nested JSON, FHIR R4, Text notes)
   │
   ▼
1. Safe Ingestion & Bounded Parsers (encoding detection: UTF-8, UTF-16, cp1252)
   │
   ▼
2. Multilingual Hybrid Detector (Rules, Gazetteers, Transliteration, Role-First Clinical Veto)
   │
   ▼
3. Evidence Ledger & Conflict-Aware Record Linkage (Blocking, Fuzzy/Phonetic Cross-Script, No Transitive Over-merge)
   │
   ▼
4. Pseudonymization & Date Shifting (Keyed HMAC-SHA256 from RAKSHA_SECRET, Coherent per-patient shift)
   │
   ▼
5. Output Serializers & Channel Cleaning (sanitized/, report.json, records.jsonl)
   │
   ▼
6. Sweep Verification (Double-checks side channels, file names, headers, metadata)
```

---

## 3. How It Works

- **Ingestion & Format Handling:** Supports UTF-8, UTF-8 BOM, UTF-16, and cp1252 encodings. Broken, deeply nested, or unsupported formats are quarantined safely with audit reasons in `report.json` without copying raw bytes.
- **Role-First Clinical Veto:** Distinguishes relative names from clinical complaints (e.g., `"C/O Ramesh"` vs `"C/O fever"`). Protects doctor names (`"Dr. Ramesh"`) while removing patient/relative PII. Guards dosages and regimens (`"Dolo 650 BD x 5 days"`, `"1-0-1"`, `"5 mg"`) from false phone/ID detection.
- **Cross-Script Name Skeleton:** Transliterates Devanagari to Latin and normalizes phonetic variants (Mohammad, Mohd, Md., मोहम्मद) to unify patient entities across files and hospitals.
- **Linkage & Keyed Pseudonyms:** Employs multi-pass blocking across strong IDs (UHID, Aadhaar, ABHA, phone) and corroborating evidence (village, relative, age). Unambiguous matches form clusters; ambiguous records receive `patient: null` to avoid false merges. Pseudonyms (`PSN-XXXXXX`) and date shifts are derived via keyed HMAC with `RAKSHA_SECRET`.
- **Quasi-Identifier Generalization:** Ages are banded into 5-year brackets (always containing the true age), locations are generalized, and PIN codes keep 3-digit prefixes.
- **Security & Channel Hygiene:** Fully offline and CPU-only. In-memory processing prevents raw file spills to disk. All side channels (file names, headers, keys, metadata) are purged of PII.

---

## 4. Setup & Running

### Requirements
- Python 3.10+
- Dependencies listed in `requirements.txt` (lightweight, standard CPU libraries: `regex`, `rapidfuzz`, `jellyfish`, `phonenumbers`, `indic-transliteration`)
- Strictly zero LLMs or cloud AI APIs at runtime.

### Execution
```bash
# Setup
pip install -r requirements.txt

# Run firewall
RAKSHA_SECRET="your-secret-key" python main.py --input /path/to/input --output /path/to/output

# Run unit tests (52 tests across Tier 1, Tier 2, and Tier 3)
make test

# Run RAKSHA privacy vs utility benchmark
make bench
```

---

## 5. Technical Brief
For a deep dive into the 7 internal techniques, threat model, and experimental benchmark tables, see the [2-Page Technical Brief](docs/BRIEF.md).

---

## 6. Declared Models and Dependencies
- **Runtime:** `regex`, `rapidfuzz`, `jellyfish`, `phonenumbers`, `indic-transliteration`, `psutil`.
- **No LLMs:** No transformer models, no external network calls, no cloud services used during evaluation. All logic is rule-based, phonetic, gazetteer-driven, and algorithmic.
