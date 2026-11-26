#!/usr/bin/env python3
"""Generates comprehensive test fixtures covering:
- CSV, TSV, JSON, FHIR R4, Text Notes (English, Hindi, Hinglish)
- Encodings: UTF-8, UTF-8 BOM, UTF-16 LE, UTF-16 BE, cp1252
- Edge cases: Broken CSV, Truncated JSON, Empty File (0-byte), Unsupported formats (.pdf, .bin), Deeply nested JSON (>100 levels)
"""
import json
from pathlib import Path


def generate():
    base = Path("tests/fixtures/comprehensive_test_set")
    base.mkdir(parents=True, exist_ok=True)

    # 1. Standard CSV (UTF-8)
    csv_content = (
        "uhid,patient_name,age,gender,phone,admission_date,discharge_date,diagnosis\n"
        "UHID101,Aakash Singh,34,M,9876543210,12/01/2024,15/01/2024,Acute Gastritis\n"
    )
    (base / "record_utf8.csv").write_bytes(csv_content.encode("utf-8"))

    # 2. TSV (UTF-8 with BOM)
    tsv_content = (
        "uhid\tpatient_name\tage\tgender\tphone\tadmission_date\tdischarge_date\tdiagnosis\n"
        "UHID102\tSneha Roy\t28\tF\t9811223344\t05/02/2024\t10/02/2024\tDengue Fever\n"
    )
    (base / "record_utf8_bom.tsv").write_bytes(b"\xef\xbb\xbf" + tsv_content.encode("utf-8"))

    # 3. Nested JSON (UTF-16 LE with BOM)
    json_obj = {
        "hospital": "City Care Hospital",
        "patients": [
            {
                "patient_id": "P-501",
                "name": "Vikram Malhotra",
                "age": 52,
                "gender": "M",
                "phone": "9123456789",
                "admission": "2024-03-01",
                "discharge": "2024-03-05",
                "diagnosis": "Type 2 Diabetes Mellitus",
                "rx": "Tab Metformin 500mg BD",
            }
        ],
    }
    (base / "record_utf16le.json").write_bytes(b"\xff\xfe" + json.dumps(json_obj, indent=2).encode("utf-16-le"))

    # 4. Text Note (UTF-16 BE with BOM)
    txt_be = (
        "Discharge Note\n"
        "Patient: Rajesh Sharma, Age: 45 yrs, Phone: 9988776655\n"
        "Prescription: Tab Pan-D 40mg OD, Dolo 650 BD x 3 days\n"
        "Dr. K.K. Gupta\n"
    )
    (base / "record_utf16be.txt").write_bytes(b"\xfe\xff" + txt_be.encode("utf-16-be"))

    # 5. Text Note in cp1252 (Windows-1252 with curly quote \u2019 and en-dash \u2013)
    txt_cp1252 = (
        "Doctor\u2019s Clinical Note \u2013 Hardoi Clinic\n"
        "Patient: Sunita Devi\n"
        "Age: 60 yrs\n"
        "Phone: 9415012345\n"
        "Rx: Tab Amlodipine 5mg OD\n"
    )
    (base / "record_cp1252.txt").write_bytes(txt_cp1252.encode("cp1252"))

    # 6. FHIR R4 Bundle (UTF-8)
    fhir_bundle = {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            {
                "fullUrl": "urn:uuid:patient-1",
                "resource": {
                    "resourceType": "Patient",
                    "id": "patient-1",
                    "name": [{"use": "official", "text": "Manoj Bajpayee"}],
                    "telecom": [{"system": "phone", "value": "9711223344"}],
                    "gender": "male",
                    "birthDate": "1975-06-15",
                    "address": [{"city": "Lucknow", "postalCode": "226001"}],
                },
            },
            {
                "fullUrl": "urn:uuid:encounter-1",
                "resource": {
                    "resourceType": "Encounter",
                    "id": "encounter-1",
                    "status": "finished",
                    "subject": {"reference": "Patient/patient-1"},
                    "period": {
                        "start": "2024-04-10T09:00:00Z",
                        "end": "2024-04-14T11:00:00Z",
                    },
                },
            },
        ],
    }
    (base / "fhir_r4_bundle.json").write_text(json.dumps(fhir_bundle, indent=2), encoding="utf-8")

    # 7. Hinglish Text Note (UTF-8)
    hinglish_txt = (
        "OPD Clinical Note\n"
        "Patient: Amit Kumar, S/o Ram Prasad\n"
        "Age: 32 yrs, Phone: 9871122334\n"
        "Symptoms: Patient ko pichle 3 din se tez bukhar aur body pain tha.\n"
        "Rx: Tab Paracetamol 650mg TDS, ORS 1 packet in 1L water.\n"
        "Review after 3 days. Dr. S.K. Verma\n"
    )
    (base / "hinglish_discharge.txt").write_text(hinglish_txt, encoding="utf-8")

    # 8. Devanagari Hindi Discharge Summary (UTF-8)
    devanagari_txt = (
        "डिस्चार्ज सारांश\n"
        "रोगी का नाम: राज कुमार\n"
        "पिता का नाम: शिव चरण\n"
        "उम्र: 48 वर्ष   लिंग: पुरुष\n"
        "फ़ोन: 9812345678\n"
        "आधार: 2345 6789 0123\n"
        "गाँव: रामपुर, जिला हरदोई\n"
        "भर्ती दिनांक: 12 मार्च 2024\n"
        "छुट्टी दिनांक: 18 मार्च 2024\n"
        "जाँच: SpO2 96%, BP 130/80 mmHg\n"
        "दवा: Tab Azithromycin 500mg OD x 5 days\n"
        "चिकित्सक: डॉ. आर. के. गुप्ता\n"
    )
    (base / "devanagari_summary.txt").write_text(devanagari_txt, encoding="utf-8")

    # 9. Broken CSV (unclosed quote error)
    broken_csv = 'id,name,diagnosis\n1,"Unclosed quote in patient name,Hypertension\n2,Normal Row,Fever\n'
    (base / "broken_data.csv").write_bytes(broken_csv.encode("utf-8"))

    # 10. Truncated JSON
    truncated_json = '{\n  "hospital": "District Hospital",\n  "records": [\n    {"patient": "Deepak", "age": '
    (base / "truncated_record.json").write_bytes(truncated_json.encode("utf-8"))

    # 11. Empty File (0 bytes)
    (base / "empty_file.txt").write_bytes(b"")

    # 12. Unsupported Format - PDF
    (base / "unsupported_scan.pdf").write_bytes(
        b"%PDF-1.4\n%Fake PDF binary content\nstream\nx\x9c\xcb\nendstream\n%%EOF"
    )

    # 13. Unsupported Format - Binary BLOB
    (base / "unsupported_blob.bin").write_bytes(
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"
    )

    # 14. Deeply Nested JSON (>100 levels recursion limit)
    deep = {"level": 0}
    curr = deep
    for i in range(1, 120):
        curr["nested"] = {"level": i}
        curr = curr["nested"]
    (base / "deep_nested.json").write_text(json.dumps(deep), encoding="utf-8")

    # 15. Undecodable Binary Bytes in text file (fails utf-8, utf-16, and cp1252)
    (base / "corrupt_bytes.txt").write_bytes(b"\x81\x8d\x8f\x90\x9d\x00\xff")

    # 16. Format Mismatch: CSV file containing raw JSON
    (base / "mismatched_format.csv").write_text('{\n  "hospital": "City Care"\n}', encoding="utf-8")

    files = list(base.iterdir())
    print(f"Generated {len(files)} comprehensive multi-format fixtures in {base}")


if __name__ == "__main__":
    generate()
