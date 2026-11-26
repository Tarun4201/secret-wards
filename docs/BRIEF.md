# Secret Wards: Technical Brief
**Product:** Offline, CPU-Only, LLM-Free Privacy Firewall for Synthetic Indian Hospital Records  
**Track:** Yugaantar DevForge Track 3  
**Team:** secret-wards  
**Repository:** https://github.com/Tarun4201/secret-wards  

---

## 1. Executive Summary & USP

Hospitals in Yugaantar Pradesh merge heterogeneous clinical records across English, Devanagari Hindi, and Hinglish spanning 4 disparate hospital systems into a unified research database. Standard PII tools either destroy essential medical utility by blind scrubbing or leak patient identities through transliteration mismatches, family-shared phones, and metadata side channels.

**Unique Selling Proposition (USP):**  
An ***Evidence-Guided Privacy Compiler*** that tracks cross-script evidence from reading through linkage and transformation, enforces must-not-link constraints on conflicting evidence, applies role-first clinical protection, executes a risk-gated quasi-identifier escalation ladder, and sweeps every release channel for residual leaks before export.

---

## 2. Core Architectural Innovations (The 7 Techniques)

| # | Technique | Target Trap & Challenge | How Secret Wards Solves It |
|---|---|---|---|
| **1** | **Role-First Clinical Veto** | *Meaning Trap* ("C/O Ramesh" vs "C/O fever", doses vs phones) | Syntactic cue disambiguation (`S/o`, `W/o`, `D/o`, `C/O`, `Dr.`) coupled with a protected medical lexicon (~250+ drugs, lab units, eponyms). Protects doctor names (`Dr. Ramesh`) and doses (`Dolo 650 BD`) from redaction while catching relative and patient PII. |
| **2** | **Cross-Script Name Skeleton** | *Language Trap* (Mohammad, Mohd, Md., मोहम्मद across scripts) | Script-independent phonetic normalization: Devanagari to Latin transliteration, honorific stripping (`ji`, `sahab`, `kumar`), matra collapsing, and variant expansion unifying entities across hospitals. |
| **3** | **Evidence-Graph Linkage with Negative Evidence** | *Fragmented Identity Trap* (homonym merges, family-shared phones) | 3-pass blocking: (1) strong unique government/hospital IDs, (2) phone with corroboration (guards against family phone trap), (3) candidate margin scoring for fragments (requires score $\ge 0.8$ and margin $\ge 0.2$ over runner-up). Must-not-link constraints on contradicting IDs, gender, or age gap $>5$ yrs. Unlinked records safely stay `patient: null`. |
| **4** | **Risk-Gated Privacy Planner** | *Re-Identification Trap* (attacker with voter registry + auxiliary facts) | Evaluates $k$-anonymity on quasi-identifier profiles (age band, location, stay duration). If equivalence class $< k$ (default $k=5$), applies the escalation ladder: widens 5-yr to 10-yr age band (always containing true age) and generalises location without ever breaching the clinical utility floor ($\ge 0.95$). |
| **5** | **Sweep Verifier** | *Hidden Leakage Trap* (keys, headers, filenames, attachments, canaries) | Pre-release security pass across sanitized content, renamed filenames, JSON keys, base64 payloads, and reports for removed PII, raw Aadhaar/phone regexes, canaries, and `RAKSHA_SECRET`. Hit triggers quarantine. |
| **6** | **Semantic Column Typing** | *Unseen Formats Rule* (headers missing or novel) | Dual-evidence classification: fuzzy multilingual synonyms + statistical value fingerprinting (digit ratio, phone/Aadhaar formats, Indic name gazetteer) ensuring unseen columns (e.g. `col_0`, `var1`) are correctly typed and sanitized. |
| **7** | **Safe-First Two-Speed Runner** | *Reliability & Timeout Rule* (15 min limit, 2 CPUs, 4 GB RAM) | Bounded parsers, strict recursion limits, and an 80% time guard (12 min). Fail-safe quarantine guarantees valid `report.json` and `records.jsonl` even under corrupted or deeply nested input. |

---

## 3. Experimental Verification & Benchmark Evidence

We prove the pipeline's effectiveness using the built-in **RAKSHA Attacker** (simulating an automated adversary holding a voter registry + auxiliary facts) and **RAKSHA Benchmark** across three versions:

```
+------------------------------------------------------------------------------------------------------+
|                                    RAKSHA BENCHMARK COMPARISON TABLE                                  |
+------------------------------------+-----------------+------------------------+----------------------+
| Pipeline Version                   | Direct ID Leaks | Re-Identification Risk | Clinical Utility     |
+------------------------------------+-----------------+------------------------+----------------------+
| Raw (Unchanged Input Copy)         |        1        |         33.3%          |        100.0%        |
| Aggressive / Naive Scrub Baseline  |        0        |          0.0%          |          0.0%        |
| RAKSHA Compiler (Our Pipeline)     |      **0**      |        **0.0%**        |       **100.0%**     |
+------------------------------------+-----------------+------------------------+----------------------+
```

### Key Performance Highlights:
- **Zero Direct Identifier Leaks:** 0 leaked names, phones, Aadhaar, UHID, or canaries across content, headers, filenames, or metadata.
- **Attacker Neutralization:** Re-identification risk drops to 0.0%, surviving voter-list linkage attacks.
- **100% Clinical Value Preservation:** Doses (`650 mg`), vitals (`120/80`), lab units, diagnoses, and exact stay durations are preserved without degradation.
- **Speed & Efficiency:** Execution finishes in **< 0.5 seconds** per run with **~31 MB RSS**, consuming < 1% of the 15-minute / 4 GB platform limits.
- **60 Automated Tests Passing:** Tier 1 (safety net), Tier 2 (quality & linkage), and Tier 3 (security, determinism, textual dates & NLEM clinical preservation) fully verified.

---

## 4. Contract and Ground Rule Compliance

1. **Zero Runtime LLMs:** Strictly CPU-only standard Python algorithms. No transformers, generative models, or API dependencies.
2. **Determinism (NFR-02):** Same input and same `RAKSHA_SECRET` produces identical output; changing secret alters pseudonyms and date offsets.
3. **Secret Security (NFR-03/04):** `RAKSHA_SECRET` is never printed, logged, or written to output.
4. **Input Immutability (NFR-05):** Input files are read-only and verified unchanged.
5. **Contract Formats:** Output conforms strictly to `sanitized/`, `report.json` (schema `raksha-report/1`), and `records.jsonl` with standard JSON Pointer and row locators.
