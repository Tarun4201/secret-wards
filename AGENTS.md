# Agent Guidelines: Secret Wards

## Mission
Offline, CPU-only, LLM-free privacy firewall for synthetic Indian hospital records (Yugaantar DevForge Track 3).

## Non-Negotiable Contract & Sandbox Rules
1. **Zero LLMs or cloud AI at runtime:** No generative models or API calls permitted in `main.py` or runtime modules.
2. **Never modify or leak `RAKSHA_SECRET`:** Do not print, log, or persist the secret.
3. **No hardcoding:** Do not hardcode specific patient names or practice dataset values.
4. **Contract integrity:** Strictly adhere to the format requirements checked by `validate_output.py` and `check_submission.py`.
5. **No raw file copies:** Broken or unsupported files must be safely quarantined, never copied raw into `sanitized/`.
