#!/usr/bin/env python3
"""Synthetic Indian Hospital Records & Canary Generator.

Generates a 50-record challenge dataset spanning Hinglish clinical notes,
Devanagari discharge summaries, multi-hospital CSVs, FHIR bundles,
family-phone traps, hidden canaries, and edge-case formats.

Output: tests/fixtures/challenge_set/  (with ground_truth.json)

Usage:
    python tools/datagen/generate_fixtures.py [--output DIR]
"""
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import random
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Seed data pools (all synthetic — no real patient data)
# ---------------------------------------------------------------------------
MALE_FIRST = [
    "Ramesh", "Suresh", "Mahesh", "Rajesh", "Dinesh", "Mukesh", "Vikas",
    "Ajay", "Vijay", "Sanjay", "Ravi", "Deepak", "Ashok", "Mohammad",
    "Shahid", "Ahmed", "Yusuf", "Imran", "Jagdish", "Prakash", "Brij",
    "Kuldeep", "Harjeet", "Kishan", "Mohan", "Sohan", "Rohan", "Govind",
]
FEMALE_FIRST = [
    "Sunita", "Anita", "Kavita", "Mamta", "Geeta", "Meena", "Pooja",
    "Priya", "Rekha", "Usha", "Kamla", "Fatima", "Shabana", "Salma",
    "Zainab", "Neha", "Seema", "Reeta", "Meera", "Savita", "Lakshmi",
]
SURNAMES = [
    "Sharma", "Verma", "Gupta", "Singh", "Chauhan", "Yadav", "Pandey",
    "Tiwari", "Mishra", "Thakur", "Lodhi", "Paswan", "Nishad", "Ansari",
    "Qureshi", "Siddiqui", "Devi", "Kumar",
]
MALE_FIRST_HI = [
    "रमेश", "सुरेश", "महेश", "राजेश", "दिनेश", "मुकेश", "विकास",
    "अजय", "विजय", "संजय", "रवि", "दीपक", "अशोक", "मोहम्मद",
    "शाहिद", "अहमद", "यूसुफ़", "किशन", "मोहन",
]
FEMALE_FIRST_HI = [
    "सुनीता", "अनीता", "कविता", "ममता", "गीता", "मीना", "पूजा",
    "प्रिया", "रेखा", "उषा", "कमला", "फ़ातिमा", "शबाना", "नेहा",
]
SURNAMES_HI = [
    "शर्मा", "वर्मा", "गुप्ता", "सिंह", "चौहान", "यादव", "पाण्डेय",
    "तिवारी", "मिश्रा", "ठाकुर", "लोधी", "अंसारी", "क़ुरैशी", "देवी", "कुमार",
]
VILLAGES = [
    "Baragaon", "Shahpur", "Mohammadpur", "Rampur", "Sultanpur",
    "Noorpur", "Bilrampur", "Sandila", "Hardoi", "Pihani", "Sawan",
    "Madhoganj", "Baghaulia", "Bhawan", "Kachhauna",
]
VILLAGES_HI = [
    "बड़ागाँव", "शाहपुर", "मोहम्मदपुर", "रामपुर", "सुलतानपुर",
    "नूरपुर", "बिलरामपुर", "सण्डीला", "हरदोई", "पिहानी",
]
DOCTORS_EN = [
    "Dr. R.K. Mehta", "Dr. Sanjay Verma", "Dr. Priya Singh",
    "Dr. Amit Pandey", "Dr. Farooq Ansari", "Dr. Neelam Gupta",
]
DOCTORS_HI = [
    "डॉ. आर.के. मेहता", "डॉ. संजय वर्मा", "डॉ. प्रिया सिंह",
    "डॉ. अमित पाण्डेय", "डॉ. फ़ारूक़ अंसारी",
]
DIAGNOSES_EN = [
    "Dengue Fever", "Viral Pneumonia", "Acute Gastroenteritis",
    "Fracture Left Femur", "Cellulitis Right Leg", "Typhoid Fever",
    "Malaria (P. vivax)", "COPD Exacerbation", "Diabetic Ketoacidosis",
    "Acute MI (STEMI)", "Preeclampsia", "Snake Bite Envenomation",
]
DIAGNOSES_HI = [
    "डेंगू बुख़ार", "वायरल निमोनिया", "तीव्र आंत्रशोथ",
    "बाएँ जाँघ की हड्डी टूटना", "टाइफ़ाइड बुख़ार", "मलेरिया",
    "मधुमेह", "उच्च रक्तचाप", "साँप का काटना",
]
MEDICATIONS = [
    "Tab Paracetamol 650mg TDS", "Inj Ceftriaxone 1g IV BD",
    "Tab Pan-D OD BBF", "Tab Telma 40mg OD", "Tab Metformin 500mg BD",
    "Syp Deriphyllin 1-0-1 x 5 days", "Tab Combiflam SOS",
    "Inj Enoxaparin 40mg SC OD", "Tab Ecosprin 75mg OD",
    "Tab Atorva 20mg HS", "Nebulization Duolin + Budecort TDS",
    "Tab Ondansetron 4mg TDS", "Tab Calpol 650mg SOS",
    "ORS sachets after each loose stool", "IV NS 1L over 8 hrs",
    "Tab Azithromycin 500mg OD x 5 days",
]
HOSPITALS = [
    ("Sanjeevani Multi-Speciality Hospital", "SNJ"),
    ("Jeevan Jyoti Charitable Hospital", "JJH"),
    ("District Hospital Hardoi", "DHH"),
    ("Arogya Sadan Hospital", "ASH"),
]
CANARY_TOKENS = [
    "canary-alpha-99", "CANARY_TRACK3_BETA", "canary-delta-42",
    "RAKSHA_CANARY_X", "trap-string-omega-7",
]
PIN_CODES = [
    "241001", "241124", "241301", "241401", "241201",
    "241303", "242001", "261001", "262001", "226001",
]

RNG = random.Random(42)  # deterministic


def _phone() -> str:
    return f"{RNG.choice([6,7,8,9])}{RNG.randint(100000000, 999999999)}"


def _aadhaar() -> str:
    return f"{RNG.randint(2000, 9999)} {RNG.randint(1000, 9999)} {RNG.randint(1000, 9999)}"


def _abha() -> str:
    return f"91-{RNG.randint(1000, 9999)}-{RNG.randint(1000, 9999)}-{RNG.randint(1000, 9999)}"


def _uhid(prefix: str) -> str:
    if prefix == "SNJ":
        return f"SNJ/{RNG.randint(23, 25)}/{RNG.randint(1000, 9999)}"
    elif prefix == "JJH":
        return f"JJH-{RNG.randint(10000, 99999)}"
    elif prefix == "DHH":
        return f"DHH-IPD-{RNG.randint(2023, 2025)}-{RNG.randint(100, 999)}"
    return f"ASH/{RNG.randint(10000, 99999)}"


def _pan() -> str:
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return "".join(RNG.choices(letters, k=5)) + f"{RNG.randint(1000, 9999)}" + RNG.choice(letters)


def _insurance() -> str:
    return f"INS-{RNG.randint(100000, 999999)}"


def _date(year: int = 2024, month_range: tuple = (1, 12)) -> str:
    m = RNG.randint(*month_range)
    d = RNG.randint(1, 28)
    return f"{d:02d}/{m:02d}/{year}"


def _date_iso(year: int = 2024) -> str:
    m = RNG.randint(1, 12)
    d = RNG.randint(1, 28)
    return f"{year}-{m:02d}-{d:02d}"


def _date_textual() -> str:
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return f"{RNG.randint(1,28)} {RNG.choice(months)} {RNG.choice([2023, 2024])}"


def _date_hindi() -> str:
    months = ["जनवरी", "फ़रवरी", "मार्च", "अप्रैल", "मई", "जून",
              "जुलाई", "अगस्त", "सितंबर", "अक्टूबर", "नवंबर", "दिसंबर"]
    return f"{RNG.randint(1,28)} {RNG.choice(months)} {RNG.choice([2023, 2024])}"


def _male_name() -> tuple[str, str]:
    return RNG.choice(MALE_FIRST), RNG.choice(SURNAMES)


def _female_name() -> tuple[str, str]:
    return RNG.choice(FEMALE_FIRST), RNG.choice(SURNAMES)


def _male_name_hi() -> tuple[str, str]:
    return RNG.choice(MALE_FIRST_HI), RNG.choice(SURNAMES_HI)


def _female_name_hi() -> tuple[str, str]:
    return RNG.choice(FEMALE_FIRST_HI), RNG.choice(SURNAMES_HI)


# ---------------------------------------------------------------------------
# Ground truth accumulator
# ---------------------------------------------------------------------------
ground_truth: dict[str, dict] = {}


def gt(filename: str, **kwargs):
    """Register ground truth expectations for a file."""
    ground_truth[filename] = kwargs


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

def gen_hinglish_note_01() -> tuple[str, str]:
    fname = "hinglish_note_01.txt"
    fn, ln = _male_name()
    rfn, rln = _male_name()
    phone = _phone()
    aadhaar = _aadhaar()
    village = RNG.choice(VILLAGES)
    age = RNG.randint(25, 70)
    doc = RNG.choice(DOCTORS_EN)
    diag = RNG.choice(DIAGNOSES_EN)
    adm = "12/01/2024"
    dis = "19/01/2024"

    text = f"""DISCHARGE SUMMARY
Sanjeevani Multi-Speciality Hospital, Hardoi

Patient Name: {fn} {ln}
S/o {rfn} {rln}
Age: {age} yrs   Gender: Male
Phone: {phone}   Aadhaar: {aadhaar}
Village: {village}, Dist. Hardoi, UP
Admission Date: {adm}    Discharge Date: {dis}

Chief Complaint: C/O bukhar aur badan dard for 5 din, weakness bahut thi
Diagnosis: {diag}
Treating Doctor: {doc}

Treatment Given:
{chr(10).join(f'  {i+1}. {RNG.choice(MEDICATIONS)}' for i in range(5))}

Vitals at Discharge: BP 120/80 mmHg, Pulse 78/min, SpO2 98%, Temp 98.4°F
Hb: 12.5 g/dL, Platelet: 1.8 lakhs/cumm, Creatinine: 0.9 mg/dL

Advice on Discharge:
- Khana samay pe khaye, paani zyaada piye
- Follow up after 7 din
- If bukhar aaye toh turant aaye

Called by {rfn} {rln} (attendant)
"""
    gt(fname, patient_name=f"{fn} {ln}", relative_name=f"{rfn} {rln}",
       phone=phone, aadhaar=aadhaar, village=village, age=age,
       admit_date=adm, discharge_date=dis, stay_days=7,
       pii_types=["PATIENT_NAME", "RELATIVE_NAME", "PHONE", "AADHAAR", "VILLAGE"],
       clinical_preserve=["120/80", "12.5 g/dL", "1.8 lakhs/cumm"])
    return fname, text


def gen_hinglish_note_02() -> tuple[str, str]:
    fname = "hinglish_note_02.txt"
    fn, ln = _female_name()
    rfn, rln = _male_name()
    phone = _phone()
    uhid = _uhid("SNJ")
    age = RNG.randint(20, 45)

    text = f"""OPD SLIP — Sanjeevani Hospital
UHID: {uhid}
Date: 15 Feb 2024

Patient: {fn} {ln}
W/o {rfn} {rln}
Age/Sex: {age}/F
Mob: {phone}

C/O pet mein dard aur ulti since 2 din
Previous H/o — Thyroid ka treatment chal raha hai

O/E: Abdomen soft, tenderness in epigastric region
BP 110/70, Pulse 82/min

Rx:
1. Tab Pan-D 1-0-0 (before breakfast)
2. Syp Sucralfate 10ml 1-1-1 BBF
3. Tab Ondansetron 4mg SOS
4. USG Abdomen advised
5. Review after 3 days with reports
"""
    gt(fname, patient_name=f"{fn} {ln}", relative_name=f"{rfn} {rln}",
       phone=phone, uhid=uhid, age=age,
       pii_types=["PATIENT_NAME", "RELATIVE_NAME", "PHONE", "MRN"],
       clinical_preserve=["110/70", "Pan-D 1-0-0", "Sucralfate 10ml"])
    return fname, text


def gen_hinglish_note_03() -> tuple[str, str]:
    fname = "hinglish_note_03.txt"
    fn, ln = _male_name()
    rfn, rln = _male_name()
    phone = _phone()
    aadhaar = _aadhaar()
    age = RNG.randint(50, 80)

    text = f"""INDOOR CASE SHEET
Jeevan Jyoti Charitable Hospital, Hardoi

Rogi ka Naam: {fn} {ln}
Pita ka Naam: {rfn} {rln}
Umar: {age} sal   Ling: Purush
Phone: {phone}
Aadhaar: {aadhaar}

Shikayat: Seene mein dard aur sans phoolna since 3 din
Past History: Known case of Diabetes Mellitus since 10 yrs, taking Tab Metformin 500mg BD, Tab Glimepiride 2mg OD
Smoking history: 20 pack-years

ECG: ST elevation in V1-V4 leads — suggestive of Anterior Wall MI
Troponin I: Positive (2.4 ng/mL)

Plan: Thrombolysis done with Streptokinase
Shifted to ICU for monitoring

Dr. R.K. Mehta
Consultant Cardiologist
"""
    gt(fname, patient_name=f"{fn} {ln}", relative_name=f"{rfn} {rln}",
       phone=phone, aadhaar=aadhaar, age=age,
       pii_types=["PATIENT_NAME", "RELATIVE_NAME", "PHONE", "AADHAAR"],
       clinical_preserve=["Metformin 500mg BD", "Glimepiride 2mg OD", "Troponin I", "2.4 ng/mL", "ST elevation"])
    return fname, text


def gen_devanagari_note_01() -> tuple[str, str]:
    fname = "devanagari_discharge_01.txt"
    fn, ln = _male_name_hi()
    rfn, rln = _male_name_hi()
    phone = _phone()
    aadhaar = _aadhaar()
    village = RNG.choice(VILLAGES_HI)
    age = RNG.randint(30, 65)
    doc = RNG.choice(DOCTORS_HI)

    text = f"""डिस्चार्ज सारांश
जिला अस्पताल हरदोई

रोगी का नाम: {fn} {ln}
पिता का नाम: {rfn} {rln}
उम्र: {age} वर्ष   लिंग: पुरुष
फ़ोन: {phone}
आधार: {aadhaar}
गाँव: {village}, जिला हरदोई, उत्तर प्रदेश

भर्ती दिनांक: 10 जनवरी 2024
छुट्टी दिनांक: 17 जनवरी 2024

शिकायत: बुखार 5 दिन से, खांसी, सांस लेने में तकलीफ
जाँच: Chest X-ray — Bilateral infiltrates, SpO2 88% on room air
निदान: वायरल निमोनिया

दवा:
1. Inj Ceftriaxone 1g IV BD
2. Tab Azithromycin 500mg OD
3. Nebulization Duolin + Budecort TDS
4. Tab Paracetamol 650mg TDS
5. IV NS 1L over 8 hrs

छुट्टी पर स्थिति: स्थिर, SpO2 97% room air
सलाह: 7 दिन बाद पुनः जाँच कराएँ

चिकित्सक: {doc}
"""
    gt(fname, patient_name=f"{fn} {ln}", relative_name=f"{rfn} {rln}",
       phone=phone, aadhaar=aadhaar, village=village, age=age,
       admit_date="10 जनवरी 2024", discharge_date="17 जनवरी 2024", stay_days=7,
       pii_types=["PATIENT_NAME", "RELATIVE_NAME", "PHONE", "AADHAAR", "VILLAGE"],
       clinical_preserve=["Ceftriaxone 1g IV BD", "Azithromycin 500mg OD", "SpO2 88%", "SpO2 97%"])
    return fname, text


def gen_devanagari_note_02() -> tuple[str, str]:
    fname = "devanagari_discharge_02.txt"
    fn, ln = _female_name_hi()
    rfn, rln = _male_name_hi()
    phone = _phone()
    age = RNG.randint(20, 40)
    doc = RNG.choice(DOCTORS_HI)

    text = f"""जिला अस्पताल हरदोई — प्रसव रिकॉर्ड

रोगी का नाम: {fn} {ln}
पति का नाम: {rfn} {rln}
उम्र: {age} वर्ष   लिंग: स्त्री
मोबाइल: {phone}

भर्ती: 05 मार्च 2024
प्रसव: 06 मार्च 2024 — Normal Vaginal Delivery, Live Female Baby, 2.8 kg
छुट्टी: 08 मार्च 2024

Hb: 10.2 g/dL, Blood Group: B+ve
BP: 120/80 mmHg

दवा:
1. Tab Ferrous Sulphate + Folic Acid OD
2. Tab Calcium 500mg BD
3. Tab Paracetamol 650mg SOS

सलाह: स्तनपान कराएँ, टीकाकरण कराएँ, 6 सप्ताह बाद जाँच

डॉक्टर: {doc}
"""
    gt(fname, patient_name=f"{fn} {ln}", relative_name=f"{rfn} {rln}",
       phone=phone, age=age,
       admit_date="05 मार्च 2024", discharge_date="08 मार्च 2024", stay_days=3,
       pii_types=["PATIENT_NAME", "RELATIVE_NAME", "PHONE"],
       clinical_preserve=["Normal Vaginal Delivery", "2.8 kg", "10.2 g/dL", "120/80", "Ferrous Sulphate"])
    return fname, text


def gen_sanjeevani_csv() -> tuple[str, str]:
    fname = "sanjeevani_patients.csv"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["UHID", "Patient Name", "S/o D/o W/o", "Age", "Gender",
                "Phone", "Aadhaar No", "Village", "Pin Code",
                "Admission Date", "Discharge Date", "Diagnosis"])
    pii_names = []
    for i in range(10):
        gender = RNG.choice(["M", "F"])
        if gender == "M":
            fn, ln = _male_name()
            rfn, rln = _male_name()
            rel_prefix = "S/o"
        else:
            fn, ln = _female_name()
            rfn, rln = _male_name()
            rel_prefix = RNG.choice(["D/o", "W/o"])
        uhid = _uhid("SNJ")
        age = RNG.randint(5, 85)
        phone = _phone()
        aadhaar = _aadhaar()
        village = RNG.choice(VILLAGES)
        pin = RNG.choice(PIN_CODES)
        adm = _date(2024, (1, 6))
        dis = _date(2024, (1, 6))
        diag = RNG.choice(DIAGNOSES_EN)
        w.writerow([uhid, f"{fn} {ln}", f"{rel_prefix} {rfn} {rln}", age, gender,
                     phone, aadhaar, village, pin, adm, dis, diag])
        pii_names.append(f"{fn} {ln}")

    gt(fname, record_count=10,
       pii_types=["PATIENT_NAME", "RELATIVE_NAME", "PHONE", "AADHAAR", "VILLAGE", "PIN", "MRN"],
       sample_names=pii_names[:3])
    return fname, buf.getvalue()


def gen_jeevan_jyoti_csv() -> tuple[str, str]:
    fname = "jeevan_jyoti_patients.csv"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Reg No", "Full Name", "Father's Name", "Age", "Sex",
                "Mobile", "ABHA Number", "Address", "Date of Admission",
                "Date of Discharge", "Diagnosis", "Doctor"])
    pii_names = []
    for i in range(10):
        fn, ln = _male_name()
        rfn, rln = _male_name()
        age = RNG.randint(10, 90)
        phone = _phone()
        abha = _abha()
        addr = f"H.No. {RNG.randint(1,500)}, {RNG.choice(VILLAGES)}, Hardoi, UP {RNG.choice(PIN_CODES)}"
        adm = _date(2024)
        dis = _date(2024)
        diag = RNG.choice(DIAGNOSES_EN)
        doc = RNG.choice(DOCTORS_EN)
        w.writerow([_uhid("JJH"), f"{fn} {ln}", f"{rfn} {rln}", age, "M",
                     phone, abha, addr, adm, dis, diag, doc])
        pii_names.append(f"{fn} {ln}")

    gt(fname, record_count=10,
       pii_types=["PATIENT_NAME", "RELATIVE_NAME", "PHONE", "ABHA_NUMBER", "ADDRESS", "MRN"],
       sample_names=pii_names[:3])
    return fname, buf.getvalue()


def gen_district_hospital_tsv() -> tuple[str, str]:
    fname = "district_hospital_patients.tsv"
    buf = io.StringIO()
    w = csv.writer(buf, delimiter="\t")
    w.writerow(["UHID", "नाम", "पिता का नाम", "उम्र", "लिंग",
                "मोबाइल", "आधार", "गाँव", "पिन कोड",
                "भर्ती दिनांक", "छुट्टी दिनांक", "रोग"])
    for i in range(10):
        fn, ln = _male_name_hi()
        rfn, rln = _male_name_hi()
        age = RNG.randint(1, 90)
        phone = _phone()
        aadhaar = _aadhaar()
        village = RNG.choice(VILLAGES_HI)
        pin = RNG.choice(PIN_CODES)
        adm = _date(2024)
        dis = _date(2024)
        diag = RNG.choice(DIAGNOSES_HI)
        w.writerow([_uhid("DHH"), f"{fn} {ln}", f"{rfn} {rln}", age, "पुरुष",
                     phone, aadhaar, village, pin, adm, dis, diag])

    gt(fname, record_count=10,
       pii_types=["PATIENT_NAME", "RELATIVE_NAME", "PHONE", "AADHAAR", "VILLAGE", "PIN", "MRN"])
    return fname, buf.getvalue()


def gen_family_phone_trap() -> tuple[str, str]:
    """Two families sharing a phone number each — linkage must NOT merge across families."""
    fname = "family_phone_trap.csv"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Patient Name", "Relative Name", "Age", "Gender", "Phone",
                "Aadhaar", "Village", "Diagnosis"])

    shared_phone_1 = _phone()
    shared_phone_2 = _phone()

    # Family 1: Father and Son share phone
    w.writerow(["Ramesh Sharma", "Late Brij Mohan Sharma", "55", "M", shared_phone_1,
                _aadhaar(), "Baragaon", "Hypertension"])
    w.writerow(["Vikas Sharma", "Ramesh Sharma", "28", "M", shared_phone_1,
                _aadhaar(), "Baragaon", "Viral Fever"])

    # Family 2: different family same phone pattern
    w.writerow(["Fatima Bano", "Mohammad Yusuf", "35", "F", shared_phone_2,
                _aadhaar(), "Shahpur", "Typhoid Fever"])
    w.writerow(["Mohammad Yusuf", "Late Ahmad Ali", "60", "M", shared_phone_2,
                _aadhaar(), "Shahpur", "Diabetes Mellitus"])

    # Unrelated person with unique phone
    w.writerow(["Sunita Devi", "Ram Prasad", "42", "F", _phone(),
                _aadhaar(), "Rampur", "Anaemia"])

    gt(fname, record_count=5,
       trap_type="family_phone",
       families=[
           {"members": ["Ramesh Sharma", "Vikas Sharma"], "shared_phone": shared_phone_1},
           {"members": ["Fatima Bano", "Mohammad Yusuf"], "shared_phone": shared_phone_2},
       ],
       must_not_link_across_families=True)
    return fname, buf.getvalue()


def gen_multi_hospital_linkage() -> tuple[str, str]:
    """Same patient appearing across different hospital systems with different formats."""
    fname = "multi_hospital_linkage.json"
    patient_name = "Suresh Kumar Verma"
    relative = "Ram Prasad Verma"
    phone = _phone()
    aadhaar = _aadhaar()
    age = 45
    village = "Sandila"

    records = [
        {
            "hospital": "Sanjeevani Multi-Speciality Hospital",
            "uhid": _uhid("SNJ"),
            "patient_name": patient_name,
            "father_name": relative,
            "age": age,
            "gender": "Male",
            "phone": phone,
            "aadhaar": aadhaar,
            "village": village,
            "pin": "241204",
            "admission_date": "2024-01-10",
            "discharge_date": "2024-01-15",
            "diagnosis": "Dengue Fever",
            "treating_doctor": "Dr. R.K. Mehta"
        },
        {
            "hospital": "District Hospital Hardoi",
            "uhid": _uhid("DHH"),
            "patient_name": "Suresh K. Verma",  # abbreviated
            "s_o": relative,
            "age": age,
            "sex": "M",
            "contact_no": phone,
            "aadhar_no": aadhaar,
            "gaon": village,
            "admission": "15/03/2024",
            "discharge": "20/03/2024",
            "diagnosis": "Acute Gastroenteritis"
        },
        {
            "hospital": "Jeevan Jyoti Charitable Hospital",
            "reg_no": _uhid("JJH"),
            "naam": "सुरेश कुमार वर्मा",  # Devanagari
            "pita_ka_naam": "राम प्रसाद वर्मा",
            "umar": age,
            "ling": "पुरुष",
            "mobile": phone,
            "aadhaar": aadhaar,
            "gaon": "सण्डीला",
            "tarikh_bharti": "10/06/2024",
            "tarikh_chutti": "14/06/2024",
            "rog": "मलेरिया"
        }
    ]

    gt(fname, record_count=3,
       trap_type="cross_hospital_linkage",
       same_patient=patient_name,
       shared_identifiers={"phone": phone, "aadhaar": aadhaar},
       pii_types=["PATIENT_NAME", "RELATIVE_NAME", "PHONE", "AADHAAR", "VILLAGE", "MRN"])
    return fname, json.dumps(records, ensure_ascii=False, indent=2) + "\n"


def gen_canary_note() -> tuple[str, str]:
    fname = "canary_note.txt"
    fn, ln = _male_name()
    canary = CANARY_TOKENS[0]
    text = f"""CASE NOTE
Patient: {fn} {ln}
Reference: {canary}
Age: 55 yrs, Gender: Male

C/O fever and cough since 3 days
Rx: Tab Dolo 650 TDS, Tab Azithromycin 500mg OD x 5 days
Follow up: 1 week
"""
    gt(fname, canary_tokens=[canary], must_quarantine=True,
       patient_name=f"{fn} {ln}")
    return fname, text


def gen_canary_json() -> tuple[str, str]:
    fname = "canary_data.json"
    fn, ln = _female_name()
    canary1 = CANARY_TOKENS[1]
    canary2 = CANARY_TOKENS[2]
    # Base64-encoded canary
    b64_canary = base64.b64encode(f"Name: {fn} {ln}, Canary: {canary2}".encode()).decode()

    data = {
        "patient_name": f"{fn} {ln}",
        "age": 30,
        canary1: "hidden_marker",  # canary in key
        "notes": f"Regular follow-up. Ref: {canary2}",  # canary in value
        "attachment_data": b64_canary,  # canary in base64
        "diagnosis": "Hypothyroidism",
        "medications": ["Tab Thyronorm 50mcg OD"]
    }

    gt(fname, canary_tokens=[canary1, canary2], must_quarantine=True,
       patient_name=f"{fn} {ln}",
       has_base64_canary=True)
    return fname, json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def gen_canary_csv() -> tuple[str, str]:
    fname = "canary_header.csv"
    canary = CANARY_TOKENS[3]
    buf = io.StringIO()
    w = csv.writer(buf)
    # Canary hidden in a column header
    w.writerow(["Patient Name", "Age", "Diagnosis", canary])
    fn, ln = _male_name()
    w.writerow([f"{fn} {ln}", "40", "Malaria", "normal_value"])

    gt(fname, canary_tokens=[canary], must_quarantine=True,
       canary_location="header")
    return fname, buf.getvalue()


def gen_unseen_columns_csv() -> tuple[str, str]:
    """CSV with deliberately obscure column headers that need semantic inference."""
    fname = "unseen_columns.csv"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["fld_1", "var_x", "col_3", "field_4", "misc_5", "data_6", "info_7"])

    for i in range(8):
        fn, ln = _male_name() if i % 2 == 0 else _female_name()
        w.writerow([
            f"{fn} {ln}",          # fld_1 = name (should be inferred)
            _phone(),              # var_x = phone (should be inferred)
            RNG.randint(20, 80),   # col_3 = age
            _aadhaar(),            # field_4 = aadhaar (should be inferred)
            RNG.choice(VILLAGES),  # misc_5 = village
            RNG.choice(DIAGNOSES_EN),  # data_6 = diagnosis (safe)
            RNG.choice(MEDICATIONS),   # info_7 = medication (safe)
        ])

    gt(fname, record_count=8,
       trap_type="unseen_headers",
       inferred_pii_columns={"fld_1": "PATIENT_NAME", "var_x": "PHONE", "field_4": "AADHAAR"})
    return fname, buf.getvalue()


def gen_fhir_bundle() -> tuple[str, str]:
    fname = "fhir_patients.json"
    fn1, ln1 = _male_name()
    fn2, ln2 = _female_name()
    phone1, phone2 = _phone(), _phone()
    aadhaar1, aadhaar2 = _aadhaar(), _aadhaar()

    bundle = {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            {
                "resource": {
                    "resourceType": "Patient",
                    "id": f"P-{RNG.randint(1000,9999)}",
                    "name": [{"given": [fn1], "family": ln1}],
                    "telecom": [{"system": "phone", "value": phone1}],
                    "identifier": [{"system": "aadhaar", "value": aadhaar1}],
                    "gender": "male",
                    "birthDate": "1980-05-15",
                    "address": [{"text": f"{RNG.choice(VILLAGES)}, Hardoi, UP"}]
                }
            },
            {
                "resource": {
                    "resourceType": "Encounter",
                    "id": f"E-{RNG.randint(1000,9999)}",
                    "subject": {"reference": f"Patient/P-{RNG.randint(1000,9999)}"},
                    "period": {"start": "2024-02-10", "end": "2024-02-15"},
                    "reasonCode": [{"text": "Dengue Fever"}]
                }
            },
            {
                "resource": {
                    "resourceType": "Patient",
                    "id": f"P-{RNG.randint(1000,9999)}",
                    "name": [{"given": [fn2], "family": ln2}],
                    "telecom": [{"system": "phone", "value": phone2}],
                    "identifier": [{"system": "aadhaar", "value": aadhaar2}],
                    "gender": "female",
                    "birthDate": "1992-09-22",
                    "address": [{"text": f"{RNG.choice(VILLAGES)}, Hardoi, UP"}]
                }
            }
        ]
    }

    gt(fname, record_count=2, format="fhir_bundle",
       pii_types=["PATIENT_NAME", "PHONE", "AADHAAR", "ADDRESS", "DOB"])
    return fname, json.dumps(bundle, ensure_ascii=False, indent=2) + "\n"


def gen_masked_aadhaar_csv() -> tuple[str, str]:
    fname = "masked_aadhaar_records.csv"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Patient Name", "Age", "Gender", "Aadhaar No", "Phone", "Diagnosis"])
    for i in range(5):
        fn, ln = _male_name()
        # Masked Aadhaar: XXXX XXXX 1234
        last4 = f"{RNG.randint(1000,9999)}"
        masked = f"XXXX XXXX {last4}"
        w.writerow([f"{fn} {ln}", RNG.randint(20, 70), "M", masked, _phone(),
                     RNG.choice(DIAGNOSES_EN)])

    gt(fname, record_count=5,
       pii_types=["PATIENT_NAME", "AADHAAR_MASKED", "PHONE"])
    return fname, buf.getvalue()


def gen_base64_embedded_json() -> tuple[str, str]:
    fname = "base64_embedded.json"
    fn, ln = _male_name()
    phone = _phone()
    secret_text = f"Emergency Contact: {fn} {ln}, Phone: {phone}"
    b64 = base64.b64encode(secret_text.encode()).decode()

    data = {
        "patient_id": f"ASH/{RNG.randint(10000,99999)}",
        "age": 50,
        "diagnosis": "Snake Bite Envenomation",
        "emergency_contact_encoded": b64,
        "clinical_notes": "Patient brought in unconscious. 20-WBCT done. ASV 10 vials given IV."
    }

    gt(fname, has_base64_pii=True,
       embedded_name=f"{fn} {ln}", embedded_phone=phone,
       pii_types=["PATIENT_NAME", "PHONE", "MRN"])
    return fname, json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def gen_textual_dates_note() -> tuple[str, str]:
    fname = "textual_dates_note.txt"
    fn, ln = _male_name()
    rfn, rln = _male_name()
    phone = _phone()
    age = RNG.randint(30, 60)

    text = f"""DISCHARGE SUMMARY
Arogya Sadan Hospital, Hardoi

Patient Name: {fn} {ln}
S/o {rfn} {rln}
Age: {age} years   Gender: Male
Contact: {phone}

Date of Admission: 15 Jan 2024
Date of Surgery: 17th January 2024
Date of Discharge: 22-Jan-2024

Diagnosis: Acute Appendicitis
Procedure: Laparoscopic Appendectomy under GA
Surgeon: Dr. Amit Pandey

Post-op Recovery: Uneventful
Vitals: BP 118/76, Pulse 72/min, Temp 98.2°F

Discharge Medications:
1. Tab Combiflam 1-0-1 x 5 days
2. Tab Pan-D 1-0-0 x 7 days
3. Tab Cefixime 200mg BD x 5 days
4. Betadine dressing daily

Follow-up: Review on 29 Jan 2024 with wound check
"""
    gt(fname, patient_name=f"{fn} {ln}", relative_name=f"{rfn} {rln}",
       phone=phone, age=age,
       textual_dates=["15 Jan 2024", "17th January 2024", "22-Jan-2024", "29 Jan 2024"],
       pii_types=["PATIENT_NAME", "RELATIVE_NAME", "PHONE"],
       clinical_preserve=["Combiflam 1-0-1", "Cefixime 200mg BD", "118/76"])
    return fname, text


def gen_email_pan_insurance_csv() -> tuple[str, str]:
    fname = "insurance_records.csv"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Patient Name", "Age", "PAN", "Email", "Insurance ID",
                "Phone", "Diagnosis", "Claim Amount"])
    for i in range(5):
        fn, ln = _male_name() if i % 2 == 0 else _female_name()
        w.writerow([
            f"{fn} {ln}", RNG.randint(25, 65), _pan(),
            f"{fn.lower()}.{ln.lower()}@example.com", _insurance(),
            _phone(), RNG.choice(DIAGNOSES_EN),
            f"Rs. {RNG.randint(5000, 500000)}"
        ])

    gt(fname, record_count=5,
       pii_types=["PATIENT_NAME", "PAN", "EMAIL", "INSURANCE_ID", "PHONE"])
    return fname, buf.getvalue()


def gen_mohammad_variants_csv() -> tuple[str, str]:
    """Test cross-script name skeleton linking for Mohammad variants."""
    fname = "mohammad_variants.csv"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Patient Name", "Father Name", "Age", "Phone", "Aadhaar", "Village", "Diagnosis"])

    shared_phone = _phone()
    shared_aadhaar = _aadhaar()

    # Same person, different spellings across records
    w.writerow(["Mohammad Yusuf Ansari", "Late Mohd. Akram Ansari", "45", shared_phone,
                shared_aadhaar, "Shahpur", "Diabetes Mellitus"])
    w.writerow(["Mohd Yusuf Ansari", "Md. Akram Ansari", "45", shared_phone,
                shared_aadhaar, "Shahpur", "Hypertension"])
    w.writerow(["मोहम्मद यूसुफ़ अंसारी", "मोहम्मद अकरम अंसारी", "45", shared_phone,
                shared_aadhaar, "शाहपुर", "मधुमेह"])

    # Different person
    w.writerow(["Mohd Shahid Qureshi", "Abdul Rahman Qureshi", "30", _phone(),
                _aadhaar(), "Noorpur", "Viral Fever"])

    gt(fname, record_count=4,
       trap_type="name_skeleton_linkage",
       same_patient_variants=["Mohammad Yusuf Ansari", "Mohd Yusuf Ansari", "मोहम्मद यूसुफ़ अंसारी"],
       must_link_first_three=True, must_not_link_fourth=True)
    return fname, buf.getvalue()


def gen_deeply_nested_json() -> tuple[str, str]:
    fname = "nested_records.json"
    fn, ln = _male_name()
    phone = _phone()

    data = {
        "hospital": "Arogya Sadan Hospital",
        "department": {
            "name": "Medicine",
            "ward": {
                "number": 3,
                "bed": 12,
                "patient": {
                    "name": f"{fn} {ln}",
                    "demographics": {
                        "age": 55,
                        "gender": "Male",
                        "contact": {
                            "phone": phone,
                            "address": {
                                "village": "Pihani",
                                "district": "Hardoi",
                                "state": "UP",
                                "pin": "241403"
                            }
                        }
                    },
                    "clinical": {
                        "diagnosis": "COPD Exacerbation",
                        "vitals": {"bp": "140/90", "spo2": "91%", "pulse": "92"},
                        "medications": [
                            {"drug": "Deriphyllin", "dose": "1-0-1", "route": "PO"},
                            {"drug": "Budecort", "dose": "1mg", "route": "Nebulization"},
                            {"drug": "Salbutamol", "dose": "2 puffs", "frequency": "QID"}
                        ]
                    }
                }
            }
        }
    }

    gt(fname, patient_name=f"{fn} {ln}", phone=phone,
       pii_types=["PATIENT_NAME", "PHONE", "VILLAGE", "PIN"],
       clinical_preserve=["140/90", "91%", "Deriphyllin", "1-0-1"])
    return fname, json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def gen_canary_filename() -> tuple[str, str]:
    """File whose filename itself contains a canary token."""
    canary = CANARY_TOKENS[4]
    fname = f"report_{canary}.txt"
    text = "Clinical note: Patient stable. BP 130/85. Discharged in good condition.\n"

    gt(fname, canary_tokens=[canary], canary_location="filename",
       must_sanitize_filename=True)
    return fname, text


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------
ALL_GENERATORS = [
    gen_hinglish_note_01,
    gen_hinglish_note_02,
    gen_hinglish_note_03,
    gen_devanagari_note_01,
    gen_devanagari_note_02,
    gen_sanjeevani_csv,
    gen_jeevan_jyoti_csv,
    gen_district_hospital_tsv,
    gen_family_phone_trap,
    gen_multi_hospital_linkage,
    gen_canary_note,
    gen_canary_json,
    gen_canary_csv,
    gen_unseen_columns_csv,
    gen_fhir_bundle,
    gen_masked_aadhaar_csv,
    gen_base64_embedded_json,
    gen_textual_dates_note,
    gen_email_pan_insurance_csv,
    gen_mohammad_variants_csv,
    gen_deeply_nested_json,
    gen_canary_filename,
]


def main():
    ap = argparse.ArgumentParser(description="Generate synthetic challenge dataset")
    ap.add_argument("--output", default=str(Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "challenge_set"))
    args = ap.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    total_records = 0
    for gen_fn in ALL_GENERATORS:
        fname, content = gen_fn()
        dest = out / fname
        dest.write_text(content, encoding="utf-8", newline="")
        rc = ground_truth.get(fname, {}).get("record_count", 1)
        total_records += rc
        print(f"  ✓ {fname} ({rc} records)")

    # Write ground truth outside the input dataset folder
    gt_path = out.parent / "challenge_ground_truth.json"
    gt_path.write_text(json.dumps(ground_truth, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8", newline="")

    print(f"\nGenerated {len(ALL_GENERATORS)} files, {total_records} total records")
    print(f"Ground truth: {gt_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
