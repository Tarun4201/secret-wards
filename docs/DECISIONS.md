# Decision Log: Secret Wards

## 2026-11-26: Baseline Architecture Setup
- **Decision:** Implemented core hybrid detection engine in standard Python with rapid execution (<0.5s on 200 files).
- **Format Contract:** Verified against `validate_output.py` and `check_submission.py` with zero errors.
- **Linkage:** Multi-pass blocking on UHID/Aadhaar/ABHA/Phone and corroborating relative/village/age signals.
- **Pseudonyms:** Keyed HMAC-SHA256 with Crockford Base32 encoding (`PSN-XXXXXX`).
