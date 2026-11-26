# RAKSHA Privacy vs Utility Benchmark Report

| Pipeline Version | Direct ID Leaks | Re-Identification Risk | Clinical Utility Retention | Runtime |
| :--- | :---: | :---: | :---: | :---: |
| Raw (Unchanged Copy) | 1 | 33.3% | 100.0% | <0.01s |
| Aggressive / Naive Baseline | 0 | 0.0% | 0.0% | <0.01s |
| **RAKSHA Compiler (Our Pipeline)** | 0 | 0.0% | 100.0% | 0.213s |

### Key Findings & USP Proof:
1. **Zero Direct Leaks:** RAKSHA achieves 0 direct identifier leaks across text, CSV, and JSON channels.
2. **Attacker Resistance:** Re-identification risk drops dramatically compared to raw data.
3. **Medical Data Preservation:** Clinical values (medicines, dosages, vitals, labs, stay lengths) remain preserved at ~100%, far outperforming naive redaction.
4. **Speed:** Sub-second execution comfortably under the 15-minute contest threshold.
