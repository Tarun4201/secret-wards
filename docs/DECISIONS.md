# Decision Log: Secret Wards

## 2026-11-26: Baseline Architecture Setup (P0)
- **Decision:** Implemented core hybrid detection engine in standard Python with rapid execution (<0.5s on 200 files).
- **Format Contract:** Verified against `validate_output.py` and `check_submission.py` format contract with zero errors.
- **Linkage:** Multi-pass blocking on UHID/Aadhaar/ABHA/Phone and corroborating relative/village/age signals.
- **Pseudonyms:** Keyed HMAC-SHA256 with Crockford Base32 encoding (`PSN-XXXXXX`).
- **Clinical Protection:** Strict role-first clinical protection veto preventing medicine/dosage/vital redactions.
- **Sweep Verifier (Technique 5):** Added post-sanitization scan catching unredacted PII, canaries, and secret leaks.

## 2026-11-26: Quality & Linkage Enhancements (P1)
- **Decision: Evidence-Graph Linkage with Negative Evidence (Technique 3):**
  - Enforced must-not-link constraints on conflicting IDs (Aadhaar, UHID, ABHA, PAN), gender mismatches, and age gaps > 5 years.
  - Implemented family phone trap protection: identical phone numbers with non-matching patient name skeletons and no matching relative are blocked from false-merging.
  - Added candidate margin scoring: weak fragments must score >= 0.8 and beat the runner-up cluster by >= 0.2, otherwise remaining safely unlinked (`patient: null`).
- **Decision: Risk-Gated Privacy Planner (Technique 4):**
  - Implemented k-anonymity evaluation ($k=5$) across quasi-identifier equivalence classes (age band, location).
  - Escalation ladder widens 5-year age bands to 10-year bands for high-risk profiles while strictly preserving true age containment (FR-07) and clinical utility floor (>= 0.95).
  - Coherent date shifting and age banding unified across CSV, TSV, JSON collections, and free-text clinical notes.
- **Decision: RAKSHA Attacker and Benchmark Tooling (`tools/`):**
  - Created development-only voter registry attacker simulating re-identification attacks.
  - Created automated benchmark producing side-by-side Markdown comparisons across Raw, Aggressive Baseline, and RAKSHA Compiler.
  - Strict modular isolation: `main.py` never imports `tools/`, enforced by automated test.

## 2026-11-26: Advanced Formats & Multilingual Hardening (P2)
- **Decision: Semantic Column Typing (Technique 6):**
  - Implemented statistical value fingerprinting (`infer_column_type_from_values`) classifying novel/unseen column headers by digit ratio, phone formats, 12-digit Aadhaar shapes, and Indian name gazetteers.
- **Decision: Devanagari Hindi & Hinglish Full Support:**
  - Expanded `RE_DOCTOR` to recognize Hindi doctor prefixes (`डॉ.`, `डॉक्टर`, `चिकित्सक`) preventing false-positive redaction of physicians in Indic clinical records.
  - Added Hindi relation cues (`पिता का नाम`, `पति का नाम`, `माता का नाम`, `अभिभावक`) and village cues (`गाँव:`, `ग्राम:`).
  - Constrained Devanagari name regex to horizontal whitespace (`[ \t]`) preventing multiline token eating.
- **Decision: FHIR R4 Bundle Support:**
  - Extracted linkage evidence from FHIR Patient resource and preserved valid Bundle collection schema.
  - Updated resource references (`subject.reference` -> `Patient/{pseudonym}`).
