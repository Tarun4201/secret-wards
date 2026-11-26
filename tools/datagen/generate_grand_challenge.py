#!/usr/bin/env python3
"""Generates the Grand Challenge Dataset embodying all 6 challenge traps:
1. Multi-lingual: English, Devanagari Hindi, and Hinglish code-switching
2. Formats: CSV (normal, shifted), TSV (BOM), cp1252 legacy, Nested JSON, FHIR R4 Bundle, Text Notes
3. Name structures: Patronymics (S/o, D/o, W/o, C/O), initials, honorifics (ji, sahab, didi),
   transliteration variants (Mohammad, Mohd, Md., मोहम्मद) linking across files!
4. Meaning Trap: "C/O Ramesh" vs "C/O fever", "Dr. Ramesh" stays, "Dolo 650 BD", "1-0-1",
   "Parkinson's disease" stays
5. Fragmented Identity & Family Phone Trap: Linked patients across 4 hospitals, plus
   unrelated people sharing a single phone to test negative evidence
6. Quasi-identifiers & Clinical Integrity: Stay length, age bands, vitals, labs, diagnoses
7. Hidden Leakage: Canaries in headers, filenames with trap tokens, base64 payloads
"""
import base64
import json
from pathlib import Path


def generate_grand_challenge(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # Cross-Hospital Linked Entity 1: Mohammad Arif (across 4 hospitals & 3 scripts!)
    # Hospital A (CSV): "Mohammad Arif", Phone: 9876543210, Aadhaar: 2345 6789 0123
    # Hospital B (Hindi): "मोहम्मद आरिफ", Dr. Mehta, Dolo 650 BD
    # Hospital C (Hinglish): "Arif sahab", Phone: 9876543210, BP 150/90
    # Hospital D (Nursing Note): "Md. Arif", C/O fever, Ramipril 5 mg
    # -------------------------------------------------------------------------

    # 1. Hospital A: Registration CSV (UTF-8)
    hosp_a_csv = (
        "mrn,patient_name,relation,age,gender,phone,aadhaar_number,abha_id,pan_card,village,pin_code,admission_date,discharge_date,diagnosis,prescription\n"
        "HOSP-A/101,Mohammad Arif,S/o Bashir Ahmed,47,M,9876543210,2345 6789 0123,arif@abdm,ABCDE1234F,Baragaon,241001,10/01/2024,19/01/2024,Dengue Fever,Tab Dolo 650 BD x 5 days\n"
        "HOSP-A/102,Suresh Kumar,S/o Ramesh Kumar,52,M,9811223344,3456 7890 1234,suresh@abdm,BCDEF2345G,Shahabad,241124,12/02/2024,16/02/2024,Essential Hypertension,Tab Amlodipine 5mg OD\n"
        "HOSP-A/103,Pooja Sharma,W/o Amit Sharma,29,F,9123456789,4567 8901 2345,pooja@abdm,CDEFG3456H,Sandila,241204,01/03/2024,05/03/2024,Acute Gastritis,Tab Pan-D 40mg 1-0-0\n"
    )
    (output_dir / "hospital_a_registration.csv").write_text(hosp_a_csv, encoding="utf-8")

    # 2. Hospital B: Devanagari Hindi Discharge Summaries (UTF-8)
    # Tests: Hindi names, relatives (पिता का नाम), physician protection (डॉ. आर. के. मेहता),
    # Meaning Trap ("C/O" equivalent: शिकायत: बुखार), doses ("1-0-1", "Dolo 650 BD"), exact 9-day stay
    hosp_b_hindi = (
        "अस्पताल डिस्चार्ज सारांश — जिला चिकित्सालय हरदोई\n"
        "--------------------------------------------------\n"
        "रोगी का नाम: मोहम्मद आरिफ\n"
        "पिता का नाम: बशीर अहमद\n"
        "उम्र: 47 वर्ष   लिंग: पुरुष\n"
        "फ़ोन: 9876543210\n"
        "आधार संख्या: 2345 6789 0123\n"
        "गाँव: बड़ागाँव, पिन: 241001\n"
        "भर्ती दिनांक: 10 जनवरी 2024\n"
        "छुट्टी दिनांक: 19 जनवरी 2024\n"
        "शिकायत: तेज बुखार 4 दिन से, सिरदर्द, जोड़ों में दर्द\n"
        "जाँच: Platelet count 45,000 /mcL, Dengue NS1 Antigen Positive, BP 120/80 mmHg\n"
        "उपचार व दवा:\n"
        "1. Tab Paracetamol 650mg TDS\n"
        "2. Tab Pan-D 1-0-0 खाने से पहले\n"
        "3. IV Fluids DNS 100 ml/hr\n"
        "परामर्श चिकित्सक: डॉ. आर. के. मेहता (वरिष्ठ फिजीशियन)\n"
    )
    (output_dir / "hospital_b_discharge_hindi.txt").write_text(hosp_b_hindi, encoding="utf-8")

    # 3. Hospital C: Hinglish OPD & Clinical Notes (UTF-8)
    # Tests: Hinglish code-switching, honorifics ("Arif sahab", "didi"),
    # Meaning Trap ("C/O Ramesh" relative vs "C/O fever"), vitals ("BP 150/90")
    hosp_c_hinglish = (
        "City Health Clinic — OPD Follow-up Note\n"
        "Date: 25/01/2024\n\n"
        "Patient: Arif sahab (Mohd Arif)\n"
        "Contact: 9876543210, Village: Baragaon\n"
        "Attendant: C/O Bashir Ahmed (Father)\n"
        "Complaints: Patient ko ab bukhar nahi hai par weakness aur bodyache persist kar rahi hai.\n"
        "O/E: Arif sahab ka BP 150/90 mmHg hai, Pulse 78 bpm, SpO2 98% on room air.\n"
        "Systemic exam: Chest clear, CVS S1 S2 heard, P/A soft non-tender.\n"
        "Advised Medications:\n"
        "- Tab Telma 40mg 1-0-0 x 14 days\n"
        "- Tab Neurobion Forte OD x 1 month\n"
        "- Follow up next week with Dr. Alok Verma.\n"
    )
    (output_dir / "hospital_c_opd_hinglish.txt").write_text(hosp_c_hinglish, encoding="utf-8")

    # 4. Hospital D: English Nursing Notes with Eponyms & Initial Variants (UTF-8)
    # Tests: "Md. Arif", disease eponym ("Parkinson's disease"), "Ramipril 5 mg", "Dolo 650 BD"
    hosp_d_nurse = (
        "St. Jude Medical Ward — Nursing Progress Notes\n"
        "===============================================\n"
        "Patient Name: Md. Arif\n"
        "UHID: SJH-99210, Age: 47, Gender: Male, Phone: 9876543210\n"
        "Chief Complaint: C/O fever and tremors.\n"
        "History: Patient has early-stage Parkinson's disease under treatment by Dr. Sanjay Sen.\n"
        "Vitals: Temp 99.2 F, BP 130/80 mmHg, PR 82/min, RR 18/min.\n"
        "Medication Charted:\n"
        " - Ramipril 5 mg OD\n"
        " - Syndopa 110mg TDS (for Parkinson's disease)\n"
        " - Dolo 650 BD as needed for fever\n"
        "Nurse In-Charge: Sister Mary\n"
    )
    (output_dir / "hospital_d_nursing_english.txt").write_text(hosp_d_nurse, encoding="utf-8")

    # 5. Hospital E: Legacy TSV with UTF-8 BOM and Shifted Column Headers
    # Tests: UTF-8 BOM, TSV delimiters, patronymics in single column ("S/o D/o W/o")
    tsv_content = (
        "Hospital_ID\tFull_Name\tPatronymic\tYears_Old\tSex\tMobile\tGovt_ID\tTown\tPostal_Index\tAdmit\tDischarge\tClinical_Impression\n"
        "TSV-001\tMeera Devi\tW/o Rajan Singh\t38\tF\t9415012345\t5678 9012 3456\tMadhoganj\t262001\t15/02/2024\t20/02/2024\tTyphoid Fever\n"
        "TSV-002\tRajan Singh\tS/o Balram Singh\t42\tM\t9415012345\t6789 0123 4567\tMadhoganj\t262001\t18/02/2024\t24/02/2024\tMalaria (P. vivax)\n"
    )
    (output_dir / "hospital_e_legacy_bom.tsv").write_bytes(b"\xef\xbb\xbf" + tsv_content.encode("utf-8"))

    # 6. Family Phone Trap CSV (Crucial: 2 different people sharing 1 phone)
    # Tests: Negative Evidence (Technique 3) must prevent false merge between husband and wife
    fam_phone_csv = (
        "id,name,relation,age,gender,phone,aadhaar,condition\n"
        "FAM-1,Deepak Sharma,S/o Prem Sharma,35,M,9898989898,7890 1234 5678,Bronchial Asthma\n"
        "FAM-2,Sunita Sharma,W/o Deepak Sharma,32,F,9898989898,8901 2345 6789,Allergic Rhinitis\n"
    )
    (output_dir / "family_phone_trap.csv").write_text(fam_phone_csv, encoding="utf-8")

    # 7. Legacy Windows CSV in cp1252 with smart quotes and en-dashes
    cp1252_data = (
        "Registration_No,Patient,Age,Gender,Phone,Notes\n"
        "REG-901,Kavita Verma,41,F,9711002233,Patient\u2019s review \u2013 BP 120/80, Rx: Calpol 500mg SOS\n"
    )
    (output_dir / "hospital_f_cp1252.csv").write_bytes(cp1252_data.encode("cp1252"))

    # 8. Nested JSON with base64 attachment
    b64_payload = base64.b64encode(
        b"Patient Name: Ananya Sen, Phone: 9811003344, Diagnosis: Urinary Tract Infection, Rx: Tab Cefixime 200mg BD"
    ).decode("ascii")

    nested_json = {
        "hospital_network": "CareNet Hospitals YP",
        "export_date": "2024-03-15",
        "patients": [
            {
                "id": "CN-551",
                "demographics": {
                    "first_name": "Ananya",
                    "last_name": "Sen",
                    "age": 27,
                    "gender": "female",
                    "contact": "9811003344",
                    "village": "Mallawan",
                    "pin": "241303"
                },
                "admission": {
                    "date": "2024-03-01",
                    "discharge": "2024-03-04",
                    "diagnosis": "Urinary Tract Infection",
                    "vitals": {"bp": "118/76", "pulse": 72}
                },
                "attachment_base64": b64_payload
            }
        ]
    }
    (output_dir / "hospital_g_nested.json").write_text(json.dumps(nested_json, indent=2), encoding="utf-8")

    # 9. FHIR R4 Bundle (JSON)
    fhir_bundle = {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            {
                "fullUrl": "urn:uuid:p-101",
                "resource": {
                    "resourceType": "Patient",
                    "id": "p-101",
                    "name": [{"use": "official", "text": "Vikram Malhotra"}],
                    "telecom": [{"system": "phone", "value": "9922334455"}],
                    "gender": "male",
                    "birthDate": "1972-08-20",
                    "address": [{"city": "Kachhauna", "postalCode": "241126"}]
                }
            },
            {
                "fullUrl": "urn:uuid:enc-101",
                "resource": {
                    "resourceType": "Encounter",
                    "id": "enc-101",
                    "status": "finished",
                    "subject": {"reference": "Patient/p-101"},
                    "period": {"start": "2024-02-10T10:00:00Z", "end": "2024-02-14T12:00:00Z"}
                }
            }
        ]
    }
    (output_dir / "hospital_h_fhir_r4.json").write_text(json.dumps(fhir_bundle, indent=2), encoding="utf-8")

    # 10. Hidden Canary in Filename & CSV Header (Must be caught and sanitized/quarantined!)
    canary_header_csv = (
        "patient_id,canary_token_x,diagnosis\n"
        "C-1,PLANTED_CANARY_VALUE_ALPHA,Fever\n"
    )
    (output_dir / "canary_planted_record.csv").write_text(canary_header_csv, encoding="utf-8")

    # 11. Truncated corrupt JSON (Must be quarantined safely with audit reason)
    (output_dir / "corrupted_truncated.json").write_text('{"records": [{"name": "Ravi", "age":', encoding="utf-8")

    files = list(output_dir.iterdir())
    print(f"Generated {len(files)} rich multi-lingual, multi-format challenge fixtures in {output_dir}")


if __name__ == "__main__":
    generate_grand_challenge(Path("grand_challenge_input"))
