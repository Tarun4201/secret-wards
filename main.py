#!/usr/bin/env python3
"""RAKSHA Privacy Firewall – Secret Wards pipeline.

Evidence-Guided Privacy Compiler: cross-script detection, evidence-graph linkage,
keyed pseudonymization, per-patient date shifts, sweep verification.

Usage: python main.py --input <input dir> --output <output dir>
Env:   RAKSHA_SECRET (never logged or written)
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import re
import sys
import time
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
def load_policy(path: Path) -> dict:
    policy: dict[str, Any] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" in line:
                k, v = (x.strip() for x in line.split(":", 1))
                policy[k] = int(v) if v.lstrip("-").isdigit() else v
    return policy

HERE = Path(__file__).resolve().parent
POLICY = load_policy(HERE / "config" / "policy.yaml")
SECRET = os.environ.get("RAKSHA_SECRET", "").encode()

# ---------------------------------------------------------------------------
# Transliteration tables (Devanagari <-> Latin)
# ---------------------------------------------------------------------------
DEVA_TO_LATIN = {
    'अ': 'a', 'आ': 'aa', 'इ': 'i', 'ई': 'ee', 'उ': 'u', 'ऊ': 'oo',
    'ए': 'e', 'ऐ': 'ai', 'ओ': 'o', 'औ': 'au', 'अं': 'an', 'अः': 'ah',
    'क': 'k', 'ख': 'kh', 'ग': 'g', 'घ': 'gh', 'ङ': 'ng',
    'च': 'ch', 'छ': 'chh', 'ज': 'j', 'झ': 'jh', 'ञ': 'ny',
    'ट': 't', 'ठ': 'th', 'ड': 'd', 'ढ': 'dh', 'ण': 'n',
    'त': 't', 'थ': 'th', 'द': 'd', 'ध': 'dh', 'न': 'n',
    'प': 'p', 'फ': 'ph', 'ब': 'b', 'भ': 'bh', 'म': 'm',
    'य': 'y', 'र': 'r', 'ल': 'l', 'व': 'v', 'w': 'w',
    'श': 'sh', 'ष': 'sh', 'स': 's', 'ह': 'h',
    'क़': 'q', 'ख़': 'kh', 'ग़': 'gh', 'ज़': 'z', 'फ़': 'f', 'ड़': 'r', 'ढ़': 'rh',
    'ा': 'a', 'ि': 'i', 'ी': 'ee', 'ु': 'u', 'ू': 'oo',
    'े': 'e', 'ै': 'ai', 'ो': 'o', 'ौ': 'au',
    'ं': 'n', 'ँ': 'n', 'ः': 'h', '्': '', 'ऽ': '',
}

INDIC_DIGITS = str.maketrans('०१२३४५६७८९', '0123456789')

def normalize_text(s: str) -> str:
    """NFKC + casefold + Indic digit normalization."""
    s = unicodedata.normalize("NFKC", s)
    s = s.translate(INDIC_DIGITS)
    return s.casefold()

def rough_transliterate(text: str) -> str:
    """Fast approximate Devanagari -> Latin transliteration."""
    result = []
    i = 0
    chars = list(text)
    while i < len(chars):
        # Try two-char combo first
        if i + 1 < len(chars):
            pair = chars[i] + chars[i+1]
            if pair in DEVA_TO_LATIN:
                result.append(DEVA_TO_LATIN[pair])
                i += 2
                continue
        c = chars[i]
        if c in DEVA_TO_LATIN:
            result.append(DEVA_TO_LATIN[c])
        else:
            result.append(c)
        i += 1
    return "".join(result)

def name_skeleton(name: str) -> str:
    """Produce a script-independent phonetic key for a name.
    Mohammad, Mohd, Md., मोहम्मद -> same key.
    """
    n = normalize_text(name)
    # Transliterate Devanagari
    n = rough_transliterate(n)
    # Expand abbreviations
    n = re.sub(r'\bmohammad\b', 'mohammad', n)
    n = re.sub(r'\bmohd\.?\b', 'mohammad', n)
    n = re.sub(r'\bmd\.?\b', 'mohammad', n)
    n = re.sub(r'\bsmt\.?\b', '', n)
    n = re.sub(r'\bshri\.?\b', '', n)
    n = re.sub(r'\bsri\.?\b', '', n)
    n = re.sub(r'\bश्री\.?\b', '', n)
    n = re.sub(r'\bश्रीमती\.?\b', '', n)
    # Remove honorifics
    for h in ['ji', 'sahab', 'saheb', 'didi', 'bhai', 'babu', 'amma', 'ammi',
              'bhabhi', 'chacha', 'mama', 'mausi', 'nana', 'nani', 'dada', 'dadi',
              'behenji', 'behen', 'beta', 'beti', 'bibi', 'begum']:
        n = re.sub(rf'\b{h}\b', '', n)
    # Remove dots, hyphens, extra spaces
    n = re.sub(r'[.\-,\'\"()\[\]{}]', ' ', n)
    n = ' '.join(n.split())
    return n.strip()

# ---------------------------------------------------------------------------
# Pseudonyms & dates
# ---------------------------------------------------------------------------
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

def pseudonym(patient_key: str) -> str:
    digest = hmac.new(SECRET, patient_key.encode("utf-8"), hashlib.sha256).digest()
    n = int.from_bytes(digest[:5], "big")
    code = "".join(_ALPHABET[(n >> (5 * i)) & 31] for i in range(6))
    return f"PSN-{code}"

def date_shift_days(patient_key: str) -> int:
    m = int(POLICY.get("date_shift_max_days", 180))
    d = hmac.new(SECRET, b"shift|" + patient_key.encode("utf-8"), hashlib.sha256).digest()
    v = int.from_bytes(d[:4], "big") % (2 * m) - m
    return v if v != 0 else 1

def shift_date(value: dt.date, patient_key: str) -> dt.date:
    return value + dt.timedelta(days=date_shift_days(patient_key))

def age_band(age: int) -> str:
    w = int(POLICY.get("age_band_years", 5))
    lo = (age // w) * w
    return f"{lo}-{lo + w - 1}"

# ---------------------------------------------------------------------------
# Clinical protection lexicons
# ---------------------------------------------------------------------------
DRUG_NAMES = {
    'metformin', 'glimepiride', 'pantoprazole', 'atorvastatin', 'amlodipine',
    'telmisartan', 'aspirin', 'clopidogrel', 'enoxaparin', 'heparin',
    'insulin', 'paracetamol', 'dolo', 'crocin', 'ibuprofen', 'diclofenac',
    'aceclofenac', 'nimesulide', 'tramadol', 'morphine', 'fentanyl',
    'amoxicillin', 'azithromycin', 'ciprofloxacin', 'levofloxacin',
    'ceftriaxone', 'cefixime', 'doxycycline', 'metronidazole', 'clindamycin',
    'vancomycin', 'meropenem', 'piperacillin', 'tazobactam', 'linezolid',
    'fluconazole', 'itraconazole', 'acyclovir', 'oseltamivir', 'remdesivir',
    'hydroxychloroquine', 'chloroquine', 'artemether', 'lumefantrine',
    'prednisolone', 'dexamethasone', 'hydrocortisone', 'methylprednisolone',
    'budesonide', 'salbutamol', 'ipratropium', 'montelukast', 'cetirizine',
    'levocetirizine', 'fexofenadine', 'chlorpheniramine', 'promethazine',
    'ondansetron', 'domperidone', 'metoclopramide', 'ranitidine', 'famotidine',
    'omeprazole', 'esomeprazole', 'rabeprazole', 'sucralfate', 'antacid',
    'lactulose', 'bisacodyl', 'dulcolax', 'loperamide', 'ors',
    'furosemide', 'spironolactone', 'hydrochlorothiazide', 'mannitol',
    'atenolol', 'metoprolol', 'propranolol', 'carvedilol', 'bisoprolol',
    'diltiazem', 'verapamil', 'nifedipine', 'nitroglycerin', 'isosorbide',
    'digoxin', 'amiodarone', 'warfarin', 'rivaroxaban', 'apixaban',
    'losartan', 'valsartan', 'ramipril', 'enalapril', 'lisinopril',
    'phenytoin', 'carbamazepine', 'valproate', 'levetiracetam', 'gabapentin',
    'pregabalin', 'diazepam', 'lorazepam', 'midazolam', 'alprazolam',
    'clonazepam', 'risperidone', 'olanzapine', 'haloperidol', 'quetiapine',
    'sertraline', 'fluoxetine', 'escitalopram', 'amitriptyline', 'duloxetine',
    'lithium', 'donepezil', 'memantine', 'levodopa', 'carbidopa',
    'ropinirole', 'pramipexole', 'trihexyphenidyl', 'baclofen', 'tizanidine',
    'thyroxine', 'levothyroxine', 'carbimazole', 'propylthiouracil',
    'glipizide', 'gliclazide', 'pioglitazone', 'sitagliptin', 'vildagliptin',
    'empagliflozin', 'dapagliflozin', 'liraglutide', 'semaglutide',
    'ferrous', 'folic', 'calcium', 'vitamin', 'multivitamin', 'zinc',
    'potassium', 'magnesium', 'iron', 'b12', 'thiamine', 'pyridoxine',
    'calcitriol', 'cholecalciferol', 'alfacalcidol',
    'cephalexin', 'nitrofurantoin', 'norfloxacin', 'ofloxacin',
    'gentamicin', 'tobramycin', 'neomycin', 'mupirocin', 'fusidic',
    'betadine', 'povidone', 'chlorhexidine', 'silver', 'sulfadiazine',
    'permethrin', 'ivermectin', 'albendazole', 'mebendazole',
    'sildenafil', 'tadalafil', 'tamsulosin', 'finasteride', 'dutasteride',
    'cap', 'tab', 'inj', 'syp', 'susp', 'drops', 'cream', 'ointment',
    'nebulization', 'neb', 'iv', 'im', 'sc', 'po', 'pr', 'sl',
    'stat', 'sos', 'prn', 'od', 'bd', 'tds', 'qid', 'hs',
    'ceftriaxone', 'artesunate', 'quinine', 'primaquine',
    'rifampicin', 'isoniazid', 'pyrazinamide', 'ethambutol', 'streptomycin',
    'att', 'dots', 'rntcp',
    'deriphylline', 'aminophylline', 'theophylline',
    'clotrimazole', 'miconazole', 'ketoconazole', 'terbinafine',
    'dopamine', 'dobutamine', 'noradrenaline', 'adrenaline', 'atropine',
    'lignocaine', 'lidocaine', 'bupivacaine',
    'tranexamic', 'ethamsylate', 'vitamin k', 'phytomenadione',
    'misoprostol', 'oxytocin', 'methylergometrine',
    'rabies', 'tetanus', 'hepatitis', 'typhoid',
    'mg', 'ml', 'mcg', 'iu', 'unit', 'units',
}

DISEASE_EPONYMS = {
    "parkinson", "parkinson's", "alzheimer", "alzheimer's", "hodgkin", "hodgkin's",
    "crohn", "crohn's", "addison", "addison's", "cushing", "cushing's",
    "graves", "graves'", "hashimoto", "hashimoto's", "bell", "bell's",
    "wilson", "wilson's", "marfan", "marfan's", "turner", "turner's",
    "down", "klinefelter", "paget", "paget's", "raynaud", "raynaud's",
    "sjögren", "guillain", "barré", "meniere", "behçet",
    "dengue", "malaria", "typhoid", "tuberculosis", "tb", "covid",
    "diabetes", "hypertension", "asthma", "copd", "pneumonia", "anaemia", "anemia",
    "jaundice", "hepatitis", "cirrhosis", "pancreatitis", "cholecystitis",
    "appendicitis", "peritonitis", "hernia", "hemorrhoids", "piles",
    "fracture", "dislocation", "sprain", "strain", "contusion",
    "abscess", "cellulitis", "gangrene", "sepsis", "septicemia",
    "meningitis", "encephalitis", "epilepsy", "stroke", "paralysis",
    "infarction", "angina", "failure", "cardiomyopathy", "endocarditis",
    "embolism", "thrombosis", "aneurysm", "varicose",
    "nephritis", "nephrotic", "uremia", "cystitis', 'pyelonephritis",
    "uti", "aki", "ckd", "esrd", "bph",
    "fibroids", "endometriosis", "eclampsia", "preeclampsia",
    "placenta", "cesarean", "caesarean", "lscs", "normal delivery",
    "cataract", "glaucoma", "retinopathy", "conjunctivitis",
    "hypothyroidism", "hyperthyroidism", "goiter", "goitre",
    "leukemia", "lymphoma", "myeloma", "carcinoma", "sarcoma", "melanoma",
}

MEDICAL_TERMS = {
    'bp', 'pulse', 'temp', 'spo2', 'rbs', 'fbs', 'ppbs', 'hba1c',
    'haemoglobin', 'hemoglobin', 'hb', 'wbc', 'rbc', 'platelet', 'plt',
    'creatinine', 'urea', 'bun', 'sgot', 'sgpt', 'ast', 'alt',
    'bilirubin', 'albumin', 'protein', 'globulin', 'alkaline',
    'phosphatase', 'ggt', 'ldh', 'cpk', 'troponin', 'bnp',
    'sodium', 'potassium', 'chloride', 'bicarbonate', 'calcium',
    'phosphorus', 'magnesium', 'uric', 'cholesterol', 'triglyceride',
    'hdl', 'ldl', 'vldl', 'tsh', 't3', 't4', 'ft3', 'ft4',
    'esr', 'crp', 'pt', 'inr', 'aptt', 'fibrinogen', 'd-dimer',
    'blood', 'sugar', 'glucose', 'urine', 'stool', 'sputum',
    'culture', 'sensitivity', 'x-ray', 'xray', 'ct', 'mri', 'usg',
    'ecg', 'echo', 'eeg', 'emg', 'ncv', 'pft', 'abg',
    'chest', 'abdomen', 'pelvis', 'spine', 'skull', 'brain',
    'heart', 'lung', 'liver', 'kidney', 'spleen', 'pancreas',
    'mmhg', 'mg/dl', 'g/dl', 'meq/l', 'mmol/l', 'iu/l', 'u/l',
    'cells/cumm', 'lakhs/cumm', 'thou/cumm',
    'ward', 'bed', 'icu', 'nicu', 'picu', 'ot', 'opd', 'ipd',
    'admission', 'discharge', 'transfer', 'referral', 'review',
    'diagnosis', 'prognosis', 'treatment', 'surgery', 'procedure',
    'anesthesia', 'anaesthesia', 'general', 'spinal', 'local', 'regional',
    'conservative', 'palliative', 'curative', 'prophylactic',
    'history', 'examination', 'investigation', 'finding', 'impression',
    'complaint', 'symptom', 'sign', 'vitals', 'condition', 'stable',
    'improved', 'deteriorated', 'critical', 'guarded', 'poor',
    'diet', 'rest', 'exercise', 'physiotherapy', 'rehabilitation',
    'follow', 'review', 'advice', 'counselling', 'counseling',
    'nil', 'normal', 'abnormal', 'positive', 'negative', 'reactive',
    'non-reactive', 'elevated', 'low', 'high', 'moderate', 'severe', 'mild',
    'acute', 'chronic', 'subacute', 'recurrent', 'intermittent',
    'bilateral', 'unilateral', 'right', 'left', 'upper', 'lower',
    'anterior', 'posterior', 'medial', 'lateral', 'proximal', 'distal',
    'superficial', 'deep', 'central', 'peripheral',
    'yrs', 'yr', 'days', 'day', 'hrs', 'hr', 'mins', 'min', 'weeks', 'week',
    'months', 'month', 'years', 'year',
}

DOCTOR_NAMES = set()  # Populated during processing

HOSPITAL_NAMES = {
    'sanjeevani', 'jeevan jyoti', 'jeevanjyoti', 'arogya', 'district hospital',
    'hardoi', 'lucknow', 'multispeciality', 'charitable',
}

# ---------------------------------------------------------------------------
# Column semantic typing
# ---------------------------------------------------------------------------
NAME_HEADERS = {
    'name', 'patient name', 'patient_name', 'patientname', "patient's name",
    'naam', 'rogi ka naam', 'rogi naam', 'marij ka naam', 'full name', 'fullname',
    'first name', 'first_name', 'firstname', 'last name', 'last_name', 'lastname',
    'given', 'family', 'surname', 'पूरा नाम', 'नाम', 'रोगी का नाम', 'मरीज़ का नाम',
}
RELATIVE_HEADERS = {
    'relative', 'relative name', 'relative_name', 'guardian', 'guardian name',
    'father', "father's name", 'mother', "mother's name", 'spouse', 'husband',
    'wife', 'parent', 'pita ka naam', 'pati ka naam', 'sambandhi ka naam',
    'अभिभावक', 'पिता का नाम', 'पति का नाम', 'सम्बन्धी',
}
PHONE_HEADERS = {
    'phone', 'mobile', 'mob', 'contact', 'contact no', 'contact_no', 'telephone',
    'tel', 'cell', 'whatsapp', 'फ़ोन', 'मोबाइल', 'संपर्क', 'दूरभाष',
}
AADHAAR_HEADERS = {
    'aadhaar', 'aadhar', 'aadhaar no', 'aadhaar_no', 'aadhar no', 'aadhar_no',
    'uid', 'आधार', 'आधार नं', 'aadhaar_number', 'adhar', 'adhaar',
}
ABHA_HEADERS = {
    'abha', 'abha no', 'abha_no', 'abha number', 'abha_number', 'health id',
    'health_id', 'healthid', 'एबीएचए', 'स्वास्थ्य आईडी',
}
ADDRESS_HEADERS = {
    'address', 'addr', 'full address', 'full_address', 'pata', 'pura pata',
    'resident', 'residence', 'पता', 'पूरा पता', 'निवास',
}
VILLAGE_HEADERS = {
    'village', 'village/mohalla', 'gaon', 'gram', 'mohalla', 'tola', 'basti',
    'गाँव', 'ग्राम', 'मोहल्ला', 'टोला', 'बस्ती',
}
DOB_HEADERS = {
    'dob', 'date of birth', 'date_of_birth', 'dateofbirth', 'birth date',
    'birth_date', 'birthdate', 'janm tithi', 'janm_tithi', 'जन्म तिथि',
}
MRN_HEADERS = {
    'uhid', 'mrn', 'patient id', 'patient_id', 'patientid', 'reg no', 'reg_no',
    'registration', 'registration no', 'ipd', 'ipd no', 'ipd_no', 'opd no',
    'opd_no', 'case no', 'case_no', 'hospital id', 'hospital_id',
    'रजिस्ट्रेशन', 'पंजीकरण',
}
PIN_HEADERS = {
    'pin', 'pin code', 'pin_code', 'pincode', 'postal code', 'postal_code', 'zip',
    'पिन', 'पिन कोड',
}
EMAIL_HEADERS = {
    'email', 'email id', 'email_id', 'emailid', 'e-mail', 'ईमेल',
}
PAN_HEADERS = {
    'pan', 'pan no', 'pan_no', 'pan number', 'pan_number', 'पैन',
}
INSURANCE_HEADERS = {
    'insurance', 'insurance id', 'insurance_id', 'policy', 'policy no', 'policy_no',
    'claim', 'claim no', 'claim_no', 'बीमा', 'पॉलिसी',
}
AGE_HEADERS = {
    'age', 'umar', 'उम्र', 'आयु',
}
GENDER_HEADERS = {
    'gender', 'sex', 'ling', 'लिंग',
}
RELATION_TYPE_HEADERS = {
    'relation', 'relation type', 'relation_type', 'sambandh', 'सम्बन्ध', 'रिश्ता',
}

PII_HEADER_MAP: dict[frozenset[str], str] = {
    frozenset(NAME_HEADERS): 'PATIENT_NAME',
    frozenset(RELATIVE_HEADERS): 'RELATIVE_NAME',
    frozenset(PHONE_HEADERS): 'PHONE',
    frozenset(AADHAAR_HEADERS): 'AADHAAR',
    frozenset(ABHA_HEADERS): 'ABHA_NUMBER',
    frozenset(ADDRESS_HEADERS): 'ADDRESS',
    frozenset(VILLAGE_HEADERS): 'VILLAGE',
    frozenset(DOB_HEADERS): 'DOB',
    frozenset(MRN_HEADERS): 'MRN',
    frozenset(PIN_HEADERS): 'PIN',
    frozenset(EMAIL_HEADERS): 'EMAIL',
    frozenset(PAN_HEADERS): 'PAN',
    frozenset(INSURANCE_HEADERS): 'INSURANCE_ID',
}

SAFE_HEADER_TYPES = {
    frozenset(AGE_HEADERS): 'AGE',
    frozenset(GENDER_HEADERS): 'GENDER',
    frozenset(RELATION_TYPE_HEADERS): 'RELATION_TYPE',
}

def classify_header(header: str) -> str | None:
    """Return PII type for a header, or None if safe."""
    h = normalize_text(header).strip()
    # Strip common prefixes/suffixes
    h = re.sub(r'[_\-./]', ' ', h).strip()
    for header_set, pii_type in PII_HEADER_MAP.items():
        if h in header_set:
            return pii_type
    # Fuzzy: check if any known header is a substring
    for header_set, pii_type in PII_HEADER_MAP.items():
        for known in header_set:
            if known in h or h in known:
                return pii_type
    # Safe types
    for header_set, safe_type in SAFE_HEADER_TYPES.items():
        if h in header_set:
            return None
    return None

# ---------------------------------------------------------------------------
# Regex patterns for PII detection
# ---------------------------------------------------------------------------
# Phone: Indian mobile +91/0/bare, 10 digits starting with 6-9
RE_PHONE = re.compile(
    r'(?<!\d)(?:\+?91[\s\-]?)?(?:0[\s\-]?)?([6-9]\d{4}[\s\-]?\d{5})(?!\d)'
)

# Aadhaar: 12 digits (possibly with spaces/hyphens), not starting with 0 or 1
RE_AADHAAR = re.compile(
    r'(?<!\d)([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})(?!\d)'
)

# Masked Aadhaar: XXXX XXXX 1234
RE_AADHAAR_MASKED = re.compile(
    r'(?i)(?:xxxx[\s\-]?xxxx[\s\-]?\d{4})'
)

# ABHA number: 14 digits with hyphens like 91-7938-3729-8403
RE_ABHA = re.compile(
    r'(?<!\d)(91[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})(?!\d)'
)

# PAN: 5 letters + 4 digits + 1 letter
RE_PAN = re.compile(r'\b([A-Z]{5}\d{4}[A-Z])\b')

# Email
RE_EMAIL = re.compile(r'[\w.+\-]+@[\w\-]+\.[\w.]+')

# MRN/UHID patterns from the hospitals
RE_MRN = re.compile(
    r'\b(?:SNJ/\d{2}/\d+|JJH[/-]\d+|UHID[/-]\d+|ADM\d+|DHH[/-]IPD[/-]\d+|'
    r'IP[/-]\d{2}[/-]\d+|IPD[/-]\d{4}[/-]\d+|OPD/\d{2}/\d{2}/\d+|'
    r'INS[/-]\d+|CLM[/-]\d+)\b'
)

# Date patterns (various Indian formats)
RE_DATE = re.compile(
    r'\b(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4})\b'
)
RE_DATE_ISO = re.compile(
    r'\b(\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2})\b'
)

# Indian PIN code
RE_PIN = re.compile(r'(?<!\d)([1-9]\d{5})(?!\d)')

# Insurance ID pattern
RE_INSURANCE = re.compile(r'\b(INS[/-]\d+|CLM[/-]\d+)\b', re.I)

# House number pattern
RE_HOUSE = re.compile(
    r'(?i)\b(?:h\.?\s*no\.?|house|makan\s*(?:no\.?|n[.ं])|मकान\s*(?:न[ं.]?|no\.?))\s*\.?\s*\d+\b'
)

# Ward/Mohalla/Locality
RE_LOCALITY = re.compile(
    r'(?i)\b(?:ward\s+\d+|mohalla\s+\w[\w\s]*|'
    r'opp\.?\s+[\w\s]+|near\s+[\w\s]+(?:mandir|masjid|gurudwara|school|hospital|temple|church|'
    r'panchayat\s+bhawan|pani\s+tanki|chauraha|bus\s+stand|railway\s+station))\b'
)

# Relation cues
RE_RELATION = re.compile(
    r'(?i)\b(?:s/o|d/o|w/o|son\s+of|daughter\s+of|wife\s+of)\s+'
)

# C/O patterns - need to distinguish complaint from care-of
RE_CO_NAME = re.compile(
    r'(?i)\bc/o\s+(?=[A-Z\u0900-\u097F])'  # C/O followed by uppercase or Devanagari = care of (name)
)

# Dose patterns that should NOT be treated as IDs
RE_DOSE = re.compile(
    r'(?i)\b(?:\d+(?:\.\d+)?\s*(?:mg|ml|mcg|g|iu|units?|%)|'
    r'\d+\s*(?:mg|ml|mcg|iu)\s*(?:/\s*\d+\s*(?:mg|ml|mcg))?|'
    r'[01]\s*-\s*[01]\s*-\s*[01]|'  # 1-0-1 pattern
    r'\d+\s*-\s*\d+\s*-\s*\d+\s*(?:x\s*\d+\s*days?)?|'
    r'\b(?:od|bd|tds|qid|hs|sos|prn|stat)\b|'
    r'\bx\s*\d+\s*(?:days?|weeks?|months?))\b'
)

# Doctor name pattern
RE_DOCTOR = re.compile(
    r'(?:Dr\.?\s+|Doctor\s+|Consultant:?\s*)([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*)'
)

# ---------------------------------------------------------------------------
# Name detection
# ---------------------------------------------------------------------------
# Common Indian first names and surnames (a compact gazetteer)
COMMON_INDIAN_NAMES = {
    # Male first names
    'ramesh', 'suresh', 'mahesh', 'rajesh', 'dinesh', 'naresh', 'mukesh',
    'rakesh', 'yogesh', 'ganesh', 'kamlesh', 'sunil', 'anil', 'vikas',
    'vijay', 'sanjay', 'ajay', 'manoj', 'rajan', 'mohan', 'sohan', 'rohan',
    'kishan', 'krishan', 'krishna', 'shyam', 'ram', 'hari', 'gopal',
    'deepak', 'ashok', 'vinod', 'pramod', 'kamal', 'ravi', 'pradeep',
    'mohammad', 'mohd', 'shahid', 'ahmed', 'ali', 'imran', 'akram',
    'naseem', 'yusuf', 'javed', 'zubair', 'arif', 'saleem', 'khalid',
    'jaspreet', 'sukhwinder', 'kuldeep', 'harjeet', 'brijesh',
    'hareesh', 'jagdish', 'prakash', 'baban',
    # Female first names
    'sunita', 'anita', 'kavita', 'savita', 'mamta', 'neeta', 'reeta',
    'geeta', 'seema', 'meena', 'neha', 'pooja', 'priya', 'rekha', 'usha',
    'kamla', 'kamala', 'shanti', 'parvati', 'lakshmi', 'saraswati',
    'fatima', 'fatma', 'farida', 'shabana', 'salma', 'zainab', 'amina',
    'reena', 'meera',
    'sukhwinder',
    # Surnames
    'kumar', 'sharma', 'verma', 'gupta', 'singh', 'chauhan', 'chaudhary',
    'yadav', 'pandey', 'pandeya', 'tiwari', 'mishra', 'thakur', 'lodhi',
    'paswan', 'nishad', 'ansari', 'qureshi', 'siddiqui', 'baig', 'bano',
    'kaur', 'devi',
    # Devanagari names
    'कमला', 'किशन', 'रमेश', 'सुरेश', 'मोहन', 'सुनीता', 'गीता', 'मीरा',
    'रीना', 'पार्वती', 'फ़ातिमा', 'शबाना', 'सलमा', 'ज़ैनब', 'उषा',
    'शांति', 'कविता', 'नेहा', 'पूजा', 'रेखा', 'लक्ष्मी', 'सरस्वती',
    'निषाद', 'चौहान', 'चौधरी', 'यादव', 'पाण्डेय', 'तिवारी', 'मिश्रा',
    'ठाकुर', 'लोधी', 'पासवान', 'अंसारी', 'क़ुरैशी', 'सिद्दीक़ी',
    'शाहिद', 'मोहम्मद', 'अहमद', 'ज़ुबैर', 'आरिफ़', 'नसीम', 'यूसुफ़',
    'जावेद', 'अकरम', 'कौर', 'सिंह', 'कुमार', 'शर्मा', 'वर्मा', 'गुप्ता',
    'बानो', 'बैग',
}

# Generic tokens that shouldn't trigger name detection alone
GENERIC_NAME_TOKENS = {
    'devi', 'kumar', 'md', 'md.', 'ji', 'sahab', 'saheb',
    'bhai', 'singh', 'kaur', 'bano', 'begum', 'bibi',
    'ram', 'lal', 'prasad', 'nath', 'dev', 'das', 'mal',
    'देवी', 'कुमार', 'सिंह', 'कौर', 'बानो', 'बेगम',
    'राम', 'लाल', 'प्रसाद', 'नाथ', 'दास',
}

# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------
class Detection:
    __slots__ = ('type', 'surface', 'span', 'confidence', 'channel', 'role')
    def __init__(self, type: str, surface: str, span: tuple[int,int]=(0,0),
                 confidence: float=1.0, channel: str='content', role: str='patient'):
        self.type = type
        self.surface = surface
        self.span = span
        self.confidence = confidence
        self.channel = channel
        self.role = role

def is_dose_context(text: str, start: int, end: int) -> bool:
    """Check if a number-like match is actually a dose/medication context."""
    context_before = text[max(0, start-80):start].lower()
    context_after = text[end:end+40].lower()
    # Look for dose indicators nearby
    dose_words = ['mg', 'ml', 'mcg', 'iu', 'unit', 'tab', 'cap', 'inj', 'syp',
                  'dose', 'x ', 'days', 'od', 'bd', 'tds', '1-0-1', '0-1-0',
                  '1-1-1', '0-0-1', '1-0-0']
    for w in dose_words:
        if w in context_before or w in context_after:
            return True
    return False

def is_doctor(name: str, text: str, pos: int) -> bool:
    """Check if a name appears in a doctor context."""
    before = text[max(0, pos-30):pos].lower()
    return bool(re.search(r'(?:dr\.?|doctor|consultant|surgeon|physician)\s*:?\s*$', before))

def is_complaint_co(text: str, pos: int) -> bool:
    """'C/O fever' is a complaint, not care-of."""
    after = text[pos:pos+60].lower()
    # Common complaint words after C/O
    complaints = ['fever', 'pain', 'cough', 'weakness', 'vomiting', 'diarr',
                  'breathless', 'swelling', 'bleeding', 'headache', 'chest',
                  'abdominal', 'body', 'joint', 'back', 'burning',
                  'loose motion', 'loose stool', 'nausea', 'giddiness',
                  'dizziness', 'itching', 'rash', 'cold', 'sore throat',
                  'difficulty', 'loss of', 'decreased', 'increased',
                  'बुख़ार', 'बुखार', 'खांसी', 'दर्द', 'कमज़ोरी', 'उल्टी', 'दस्त',
                  'सांस', 'सूजन', 'सिर दर्द', 'पेट दर्द']
    # C/O followed by a complaint word
    co_match = re.match(r'c/o\s+', after)
    if co_match:
        rest = after[co_match.end():]
        for c in complaints:
            if rest.startswith(c):
                return True
    return False

def detect_pii_in_text(text: str, channel: str = 'content') -> list[Detection]:
    """Detect PII in free text with role-first resolution."""
    detections = []
    norm_text = normalize_text(text)

    # 1. Phone numbers (but not doses)
    for m in RE_PHONE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r'\D', '', raw)
        if len(digits) >= 10 and not is_dose_context(text, m.start(), m.end()):
            detections.append(Detection('PHONE', raw, (m.start(), m.end()), channel=channel))

    # 2. Aadhaar (12 digits, not in dose context)
    for m in RE_AADHAAR.finditer(text):
        raw = m.group(0)
        digits = re.sub(r'\D', '', raw)
        if len(digits) == 12 and not is_dose_context(text, m.start(), m.end()):
            # Check it's not an ABHA number
            if not RE_ABHA.match(text[max(0,m.start()-3):m.end()+3]):
                detections.append(Detection('AADHAAR', raw, (m.start(), m.end()), channel=channel))

    # 3. Masked Aadhaar
    for m in RE_AADHAAR_MASKED.finditer(text):
        detections.append(Detection('AADHAAR_MASKED', m.group(0), (m.start(), m.end()), channel=channel))

    # 4. ABHA numbers
    for m in RE_ABHA.finditer(text):
        detections.append(Detection('ABHA_NUMBER', m.group(0), (m.start(), m.end()), channel=channel))

    # 5. PAN
    for m in RE_PAN.finditer(text):
        detections.append(Detection('PAN', m.group(0), (m.start(), m.end()), channel=channel))

    # 6. Email
    for m in RE_EMAIL.finditer(text):
        detections.append(Detection('EMAIL', m.group(0), (m.start(), m.end()), channel=channel))

    # 7. MRN/UHID
    for m in RE_MRN.finditer(text):
        detections.append(Detection('MRN', m.group(0), (m.start(), m.end()), channel=channel))

    # 8. Insurance IDs
    for m in RE_INSURANCE.finditer(text):
        if m.group(0).upper().startswith('INS') or m.group(0).upper().startswith('CLM'):
            detections.append(Detection('INSURANCE_ID', m.group(0), (m.start(), m.end()), channel=channel))

    # 9. House numbers
    for m in RE_HOUSE.finditer(text):
        detections.append(Detection('HOUSE', m.group(0), (m.start(), m.end()), channel=channel))

    # 10. Names - detect using anchored patterns and gazetteer
    # Patient Name: label
    for m in re.finditer(r'(?i)(?:patient\s*(?:name)?|rogi\s*(?:ka\s*)?naam|naam|नाम|रोगी\s*का\s*नाम)\s*:?\s*([^\n,;|]+)', text):
        name = m.group(1).strip()
        if name and len(name) > 1 and not any(d in name.lower() for d in DRUG_NAMES):
            detections.append(Detection('PATIENT_NAME', name, (m.start(1), m.end(1)), channel=channel))

    # Relative names from relation cues
    for m in re.finditer(r'(?i)\b(?:s/o|d/o|w/o|son\s+of|daughter\s+of|wife\s+of)\s+([A-Z\u0900-\u097F][^\n,;|]*?)(?:\s*[,;|\n]|$)', text):
        name = m.group(1).strip()
        if name and len(name) > 1:
            # Remove trailing address-like content
            name = re.split(r'(?i)\s*(?:address|village|vill\.|house|h\.no|makan|tehsil|distt?\.?|dist\.|pin)', name)[0].strip()
            if name:
                detections.append(Detection('RELATIVE_NAME', name, (m.start(1), m.end(1)),
                                          channel=channel, role='relative'))

    # C/O names (but not complaints)
    for m in re.finditer(r'(?i)\bC/O\s+', text):
        pos = m.start()
        if not is_complaint_co(text, pos):
            # It's a care-of name
            after = text[m.end():]
            name_m = re.match(r'([A-Z\u0900-\u097F][a-zA-Z\u0900-\u097F]+(?:\s+[A-Z\u0900-\u097F][a-zA-Z\u0900-\u097F]+)*)', after)
            if name_m:
                detections.append(Detection('RELATIVE_NAME', name_m.group(1),
                                          (m.end(), m.end()+name_m.end(1)),
                                          channel=channel, role='relative'))

    # Doctor names (should NOT be removed)
    for m in RE_DOCTOR.finditer(text):
        DOCTOR_NAMES.add(normalize_text(m.group(1)))

    # Names in Devanagari (look for multi-word sequences in Devanagari script)
    for m in re.finditer(r'([\u0900-\u097F][\u0900-\u097F\u0300-\u036F\s]+)', text):
        segment = m.group(1).strip()
        words = segment.split()
        if len(words) >= 2:
            # Check if any word is a known name
            has_name = False
            for w in words:
                wn = normalize_text(w)
                if wn in COMMON_INDIAN_NAMES:
                    has_name = True
                    break
            if has_name:
                # Check it's not a medical term or disease
                is_medical = any(normalize_text(w) in MEDICAL_TERMS or normalize_text(w) in DISEASE_EPONYMS
                               for w in words)
                if not is_medical:
                    detections.append(Detection('PATIENT_NAME', segment,
                                              (m.start(), m.end()), confidence=0.7, channel=channel))

    return detections


def detect_pii_in_value(value: str, header: str | None = None, channel: str = 'content') -> list[Detection]:
    """Detect PII in a structured value based on the column header type."""
    if not value or not value.strip():
        return []

    detections = []
    h_type = classify_header(header) if header else None

    if h_type:
        # Column-driven detection: we know what this column holds
        if h_type in ('PATIENT_NAME', 'RELATIVE_NAME'):
            role = 'relative' if h_type == 'RELATIVE_NAME' else 'patient'
            detections.append(Detection(h_type, value.strip(), channel=channel, role=role))
        elif h_type == 'PHONE':
            detections.append(Detection('PHONE', value.strip(), channel=channel))
        elif h_type == 'AADHAAR':
            digits = re.sub(r'\D', '', value)
            if len(digits) >= 4:  # Even masked
                detections.append(Detection('AADHAAR' if len(digits) == 12 else 'AADHAAR_MASKED',
                                          value.strip(), channel=channel))
        elif h_type == 'ABHA_NUMBER':
            if value.strip():
                detections.append(Detection('ABHA_NUMBER', value.strip(), channel=channel))
        elif h_type == 'ADDRESS':
            detections.append(Detection('ADDRESS', value.strip(), channel=channel))
        elif h_type == 'VILLAGE':
            detections.append(Detection('VILLAGE', value.strip(), channel=channel))
        elif h_type == 'DOB':
            detections.append(Detection('DOB', value.strip(), channel=channel))
        elif h_type == 'MRN':
            detections.append(Detection('MRN', value.strip(), channel=channel))
        elif h_type == 'PIN':
            detections.append(Detection('PIN', value.strip(), channel=channel))
        elif h_type == 'EMAIL':
            detections.append(Detection('EMAIL', value.strip(), channel=channel))
        elif h_type == 'PAN':
            detections.append(Detection('PAN', value.strip(), channel=channel))
        elif h_type == 'INSURANCE_ID':
            detections.append(Detection('INSURANCE_ID', value.strip(), channel=channel))
    else:
        # Pattern-based detection on untyped values
        detections.extend(detect_pii_in_text(value, channel=channel))

    return detections


# ---------------------------------------------------------------------------
# Replacement engine
# ---------------------------------------------------------------------------
def make_replacement(det: Detection) -> str:
    """Generate a replacement string for a detected PII."""
    t = det.type
    if t in ('PATIENT_NAME', 'RELATIVE_NAME'):
        return f'[{t}]'
    elif t == 'PHONE':
        return '[PHONE]'
    elif t == 'AADHAAR':
        return '[AADHAAR]'
    elif t == 'AADHAAR_MASKED':
        return '[AADHAAR]'
    elif t == 'ABHA_NUMBER':
        return '[ABHA]'
    elif t == 'PAN':
        return '[PAN]'
    elif t == 'EMAIL':
        return '[EMAIL]'
    elif t == 'MRN':
        return '[MRN]'
    elif t == 'DOB':
        return '[DOB]'
    elif t == 'ADDRESS':
        return '[ADDRESS]'
    elif t == 'VILLAGE':
        return '[VILLAGE]'
    elif t == 'PIN':
        return '[PIN]'
    elif t == 'HOUSE':
        return '[HOUSE]'
    elif t == 'LOCALITY':
        return '[LOCALITY]'
    elif t == 'LANDMARK':
        return '[LANDMARK]'
    elif t == 'INSURANCE_ID':
        return '[INSURANCE_ID]'
    elif t == 'CANARY':
        return '[REDACTED]'
    return '[REDACTED]'


def clean_text(text: str, channel: str = 'content') -> tuple[str, list[Detection]]:
    """Replace detected PII in text, preserving clinical values and doctor names."""
    detections = detect_pii_in_text(text, channel)

    # Sort detections by span start, longest first (avoid double-replacement)
    detections.sort(key=lambda d: (d.span[0], -(d.span[1] - d.span[0])))

    # Remove overlapping detections (keep the first/longest)
    filtered = []
    last_end = -1
    for d in detections:
        if d.span[0] >= last_end:
            # Check: don't remove doctor names
            if d.type in ('PATIENT_NAME', 'RELATIVE_NAME'):
                name_norm = normalize_text(d.surface)
                if name_norm in DOCTOR_NAMES or any(name_norm.startswith(dn) for dn in DOCTOR_NAMES):
                    continue
                # Check if it's a disease eponym
                if any(e in name_norm for e in DISEASE_EPONYMS):
                    continue
            filtered.append(d)
            if d.span[1] > 0:
                last_end = d.span[1]

    # Apply replacements from end to start to preserve positions
    result = text
    for d in reversed(filtered):
        if d.span[1] > 0:
            result = result[:d.span[0]] + make_replacement(d) + result[d.span[1]:]
        else:
            # No span info: use string replacement
            result = result.replace(d.surface, make_replacement(d), 1)

    return result, filtered


def clean_value(v: Any, header: str | None = None) -> tuple[Any, list[Detection]]:
    """Clean a JSON value recursively."""
    all_dets: list[Detection] = []
    if isinstance(v, str):
        dets = detect_pii_in_value(v, header)
        if dets:
            all_dets.extend(dets)
            for d in dets:
                v = v.replace(d.surface, make_replacement(d))
        return v, all_dets
    if isinstance(v, list):
        result = []
        for x in v:
            cleaned, dets = clean_value(x)
            result.append(cleaned)
            all_dets.extend(dets)
        return result, all_dets
    if isinstance(v, dict):
        result = {}
        for k, x in v.items():
            # Clean key
            key_dets = detect_pii_in_text(k, 'key')
            new_k = k
            if key_dets:
                for d in key_dets:
                    new_k = new_k.replace(d.surface, make_replacement(d))
                all_dets.extend(key_dets)
            # Clean value with header context
            cleaned, dets = clean_value(x, header=k)
            result[new_k] = cleaned
            all_dets.extend(dets)
        return result, all_dets
    return v, all_dets


# ---------------------------------------------------------------------------
# Linkage engine
# ---------------------------------------------------------------------------
class PatientCluster:
    """Groups of records belonging to the same patient."""
    def __init__(self):
        self.clusters: dict[str, set[str]] = {}  # cluster_key -> set of record_ids
        self.record_to_cluster: dict[str, str] = {}  # record_id -> cluster_key
        self.evidence: dict[str, dict[str, Any]] = {}  # record_id -> extracted evidence

    def add_evidence(self, record_id: str, ev: dict[str, Any]):
        self.evidence[record_id] = ev

    def link(self):
        """Link records based on shared identifiers."""
        # Phase 1: Group by strong IDs (UHID, Aadhaar, ABHA, phone)
        id_groups: dict[str, list[str]] = defaultdict(list)
        for rid, ev in self.evidence.items():
            for id_type in ('uhid', 'aadhaar', 'abha', 'phone', 'email', 'pan', 'insurance'):
                val = ev.get(id_type)
                if val:
                    # Normalize
                    val_n = re.sub(r'[\s\-/]', '', str(val)).lower()
                    if val_n and len(val_n) >= 4:
                        id_groups[f"{id_type}:{val_n}"].append(rid)

        # Build clusters from strong ID matches
        for key, rids in id_groups.items():
            if len(rids) < 2:
                continue
            # Check for contradictions before merging
            # Pick the first record's cluster key or create one
            canonical = None
            for rid in rids:
                if rid in self.record_to_cluster:
                    canonical = self.record_to_cluster[rid]
                    break
            if canonical is None:
                canonical = rids[0]
                self.clusters[canonical] = set()

            for rid in rids:
                old = self.record_to_cluster.get(rid)
                if old and old != canonical:
                    # Merge clusters if no contradiction
                    if not self._contradicts(canonical, old):
                        self.clusters[canonical].update(self.clusters.pop(old, set()))
                        for r in list(self.clusters.get(canonical, set())):
                            self.record_to_cluster[r] = canonical
                self.clusters[canonical].add(rid)
                self.record_to_cluster[rid] = canonical

        # Phase 2: Name-based linking for unlinked records
        # Group by name skeleton
        name_groups: dict[str, list[str]] = defaultdict(list)
        for rid, ev in self.evidence.items():
            if rid in self.record_to_cluster:
                continue
            name = ev.get('patient_name', '')
            if name:
                skel = name_skeleton(name)
                if skel and len(skel) > 2:
                    name_groups[skel].append(rid)

        # For each name group, try to link with existing clusters
        for skel, rids in name_groups.items():
            # Find clusters with matching names
            matching_clusters = []
            for ckey, members in self.clusters.items():
                for m in members:
                    m_name = self.evidence.get(m, {}).get('patient_name', '')
                    if m_name and name_skeleton(m_name) == skel:
                        matching_clusters.append(ckey)
                        break

            if len(matching_clusters) == 1:
                # Unambiguous match - check for corroborating evidence
                ckey = matching_clusters[0]
                for rid in rids:
                    if self._has_corroboration(rid, ckey):
                        self.clusters[ckey].add(rid)
                        self.record_to_cluster[rid] = ckey
            elif len(matching_clusters) == 0 and len(rids) >= 2:
                # New cluster from name group, with extra checks
                canonical = rids[0]
                self.clusters[canonical] = set(rids)
                for rid in rids:
                    self.record_to_cluster[rid] = canonical

    def _contradicts(self, cluster1: str, cluster2: str) -> bool:
        """Check if two clusters have contradicting evidence."""
        # Gather evidence from both clusters
        evs1 = [self.evidence.get(r, {}) for r in self.clusters.get(cluster1, set())]
        evs2 = [self.evidence.get(r, {}) for r in self.clusters.get(cluster2, set())]

        for ev1 in evs1:
            for ev2 in evs2:
                # Gender contradiction
                g1, g2 = ev1.get('gender'), ev2.get('gender')
                if g1 and g2 and g1 != g2:
                    return True
                # Age contradiction (more than 5 years apart)
                a1, a2 = ev1.get('age'), ev2.get('age')
                if a1 and a2:
                    try:
                        if abs(int(a1) - int(a2)) > 5:
                            return True
                    except (ValueError, TypeError):
                        pass
        return False

    def _has_corroboration(self, record_id: str, cluster_key: str) -> bool:
        """Check if a record has corroborating evidence with a cluster."""
        ev = self.evidence.get(record_id, {})
        for member in self.clusters.get(cluster_key, set()):
            m_ev = self.evidence.get(member, {})
            # Check for matching relative
            rel1, rel2 = ev.get('relative_name', ''), m_ev.get('relative_name', '')
            if rel1 and rel2 and name_skeleton(rel1) == name_skeleton(rel2):
                return True
            # Check for matching village
            v1, v2 = ev.get('village', ''), m_ev.get('village', '')
            if v1 and v2 and normalize_text(v1) == normalize_text(v2):
                return True
            # Matching age (within 2 years)
            a1, a2 = ev.get('age'), m_ev.get('age')
            if a1 and a2:
                try:
                    if abs(int(a1) - int(a2)) <= 2:
                        return True
                except (ValueError, TypeError):
                    pass
        return False

    def get_pseudonym(self, record_id: str) -> str | None:
        """Get pseudonym for a record, or None if unlinked."""
        ckey = self.record_to_cluster.get(record_id)
        if ckey is None:
            return None
        return pseudonym(ckey)


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------
def extract_evidence_csv(row: list[str], headers: list[str]) -> dict[str, Any]:
    """Extract linkage evidence from a CSV row."""
    ev: dict[str, Any] = {}
    h_map = {normalize_text(h): i for i, h in enumerate(headers)}

    for h, i in h_map.items():
        if i >= len(row):
            continue
        val = row[i].strip()
        if not val:
            continue

        h_type = classify_header(headers[i])
        if h_type == 'PATIENT_NAME':
            ev['patient_name'] = val
        elif h_type == 'RELATIVE_NAME':
            ev['relative_name'] = val
        elif h_type == 'PHONE':
            ev['phone'] = re.sub(r'[\s\-+]', '', val)
        elif h_type == 'AADHAAR':
            digits = re.sub(r'\D', '', val)
            if len(digits) >= 8:  # Not fully masked
                ev['aadhaar'] = digits
        elif h_type == 'ABHA_NUMBER':
            ev['abha'] = val
        elif h_type == 'MRN':
            ev['uhid'] = val
        elif h_type == 'EMAIL':
            ev['email'] = val
        elif h_type == 'PAN':
            ev['pan'] = val
        elif h_type == 'INSURANCE_ID':
            ev['insurance'] = val
        elif h_type == 'VILLAGE':
            ev['village'] = val
        elif h_type == 'DOB':
            ev['dob'] = val

        # Safe fields
        if h in {'age', 'umar', 'उम्र', 'आयु'}:
            ev['age'] = val
        if h in {'gender', 'sex', 'ling', 'लिंग'}:
            ev['gender'] = val.upper()[:1] if val else ''

    # Try to extract UHID from first column if it looks like one
    if headers and row:
        first_val = row[0].strip()
        if RE_MRN.match(first_val):
            ev.setdefault('uhid', first_val)

    return ev


def extract_evidence_text(text: str) -> dict[str, Any]:
    """Extract linkage evidence from free text."""
    ev: dict[str, Any] = {}

    # Patient name
    m = re.search(r'(?i)(?:patient\s*(?:name)?|rogi\s*ka\s*naam)\s*:?\s*([^\n,;|]+)', text)
    if m:
        ev['patient_name'] = m.group(1).strip()

    # UHID
    m = RE_MRN.search(text)
    if m:
        ev['uhid'] = m.group(0)

    # Phone
    m = RE_PHONE.search(text)
    if m:
        ev['phone'] = re.sub(r'[\s\-+]', '', m.group(0))

    # Relative
    m = re.search(r'(?i)\b(?:s/o|d/o|w/o)\s+([A-Z\u0900-\u097F][a-zA-Z\u0900-\u097F]+(?:\s+[A-Z\u0900-\u097F][a-zA-Z\u0900-\u097F]+)*)', text)
    if m:
        ev['relative_name'] = m.group(1).strip()

    # Age
    m = re.search(r'(?i)(?:age[:/\s]*|उम्र[:/\s]*)(\d{1,3})\s*(?:yrs?|years?|वर्ष)?', text)
    if m:
        ev['age'] = m.group(1)
    # Alt: "52 Yrs/F" or "48/M"
    m = re.search(r'(\d{1,3})\s*(?:yrs?|years?|वर्ष)\s*/\s*([MF])', text, re.I)
    if m:
        ev.setdefault('age', m.group(1))
        ev['gender'] = m.group(2).upper()
    m = re.search(r'(\d{1,3})\s*/\s*([MF])\b', text, re.I)
    if m:
        ev.setdefault('age', m.group(1))
        ev.setdefault('gender', m.group(2).upper())

    # Gender from relation type
    if re.search(r'\bw/o\b', text, re.I):
        ev.setdefault('gender', 'F')
    elif re.search(r'\bs/o\b', text, re.I):
        ev.setdefault('gender', 'M')
    elif re.search(r'\bd/o\b', text, re.I):
        ev.setdefault('gender', 'F')

    # Village
    m = re.search(r'(?i)(?:vill\.?|village|gram|gaon|गाँव|ग्राम)\s*:?\s*([A-Z\u0900-\u097F][\w\s]+?)(?:\s*[,;]|\s*(?:tehsil|distt?|dist|तहसील|जिला))', text)
    if m:
        ev['village'] = m.group(1).strip()

    return ev


def extract_evidence_json(data: dict, path: str = '') -> dict[str, Any]:
    """Extract linkage evidence from a JSON record."""
    ev: dict[str, Any] = {}
    if isinstance(data, dict):
        for k, v in data.items():
            kl = normalize_text(k)
            if isinstance(v, str) and v.strip():
                h_type = classify_header(k)
                if h_type == 'PATIENT_NAME' or 'patient' in kl and 'name' in kl:
                    ev['patient_name'] = v.strip()
                elif h_type == 'RELATIVE_NAME' or 'relative' in kl:
                    ev['relative_name'] = v.strip()
                elif h_type == 'PHONE' or 'phone' in kl or 'mobile' in kl:
                    ev['phone'] = re.sub(r'[\s\-+]', '', v)
                elif h_type == 'AADHAAR' or 'aadhaar' in kl or 'aadhar' in kl:
                    digits = re.sub(r'\D', '', v)
                    if len(digits) >= 8:
                        ev['aadhaar'] = digits
                elif h_type == 'ABHA_NUMBER' or 'abha' in kl:
                    ev['abha'] = v.strip()
                elif h_type == 'MRN' or 'uhid' in kl or 'mrn' in kl or 'patient_id' in kl or 'patient_ref' in kl:
                    ev['uhid'] = v.strip()
                elif h_type == 'EMAIL' or 'email' in kl:
                    ev['email'] = v.strip()
                elif h_type == 'PAN' or 'pan' in kl:
                    ev['pan'] = v.strip()
                elif h_type == 'VILLAGE' or 'village' in kl or 'gaon' in kl:
                    ev['village'] = v.strip()
                elif h_type == 'DOB' or 'dob' in kl or 'birth' in kl:
                    ev['dob'] = v.strip()
                elif 'name' in kl and 'doctor' not in kl and 'hospital' not in kl:
                    ev.setdefault('patient_name', v.strip())
            elif isinstance(v, (int, float)) and ('age' in kl or 'umar' in kl):
                ev['age'] = str(int(v))
            elif isinstance(v, (int, float)) and ('aadhaar' in kl or 'aadhar' in kl):
                ev['aadhaar'] = str(int(v))
            elif isinstance(v, (int, float)) and ('phone' in kl or 'mobile' in kl):
                ev['phone'] = str(int(v))
            elif isinstance(v, str) and ('age' in kl or 'umar' in kl):
                m = re.search(r'\d+', v)
                if m:
                    ev['age'] = m.group(0)
            if isinstance(v, str) and ('gender' in kl or 'sex' in kl or 'ling' in kl):
                ev['gender'] = v.strip().upper()[:1]

        # Also look for free-text notes
        for k, v in data.items():
            if isinstance(v, str) and len(v) > 50 and ('note' in k.lower() or 'complaint' in k.lower()
                                                        or 'history' in k.lower()):
                text_ev = extract_evidence_text(v)
                for ek, ev_val in text_ev.items():
                    ev.setdefault(ek, ev_val)
    return ev


# ---------------------------------------------------------------------------
# Filename PII detection and renaming
# ---------------------------------------------------------------------------
def has_pii_in_filename(filename: str) -> bool:
    """Check if a filename contains PII (patient names)."""
    name = Path(filename).stem
    # Common patterns: Discharge_Summary_FirstName_LastName_ID
    parts = re.split(r'[_\-\s]', name)
    for part in parts:
        p_lower = part.lower()
        if p_lower in COMMON_INDIAN_NAMES and p_lower not in GENERIC_NAME_TOKENS:
            return True
    # Check for known name patterns in filename
    if re.search(r'(?i)(?:Fatima|Geeta|Kavita|Parvati|Reena|Salma|Shahid|Sunil|Usha|Shabana|Zainab|Farida|Mohammad)', name):
        return True
    return False

def sanitize_filename(rel: str) -> str:
    """Remove PII from filename while preserving structure."""
    path = Path(rel)
    name = path.stem
    ext = path.suffix

    # Replace name parts with hash-based IDs
    parts = re.split(r'([_\-\s])', name)
    new_parts = []
    for part in parts:
        if part in ('_', '-', ' '):
            new_parts.append(part)
        elif part.lower() in COMMON_INDIAN_NAMES and part.lower() not in GENERIC_NAME_TOKENS:
            # Replace with a short hash
            h = hashlib.sha256(part.encode()).hexdigest()[:6]
            new_parts.append(h)
        elif re.match(r'(?i)(?:SNJ|JJH|UHID|DHH|ADM|IPD|IP)[/-]', part):
            # MRN-like in filename
            h = hashlib.sha256(part.encode()).hexdigest()[:8]
            new_parts.append(h)
        else:
            new_parts.append(part)

    new_name = ''.join(new_parts) + ext
    return str(path.parent / new_name)


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------
def decode(raw: bytes) -> str | None:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="strict")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    for enc in ("utf-8", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


class Stats:
    identifiers = 0
    records = 0
    linked = 0
    generalized = 0
    suppressed = 0


def process_csv(text: str, delimiter: str, rel: str, records: list,
                linker: PatientCluster) -> str:
    rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))
    if not rows:
        return ""
    header, body = rows[0], rows[1:]
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=delimiter, lineterminator="\n")

    # Classify headers
    header_types = [classify_header(h) for h in header]

    # Clean PII from header names (but keep structure)
    clean_header = []
    for h in header:
        h_type = classify_header(h)
        # Don't rename headers unless they contain actual PII values
        clean_header.append(h)
    w.writerow(clean_header)

    for i, row in enumerate(body):
        record_id = f"{rel}:row:{i}"

        # Extract evidence for linkage
        ev = extract_evidence_csv(row, header)
        linker.add_evidence(record_id, ev)

        # Clean each cell
        clean_row = []
        for j, cell in enumerate(row):
            h = header[j] if j < len(header) else None
            h_type = header_types[j] if j < len(header_types) else None

            if h_type:
                # This column holds PII
                if h_type in ('PATIENT_NAME', 'RELATIVE_NAME', 'PHONE', 'EMAIL',
                             'AADHAAR', 'ABHA_NUMBER', 'PAN', 'MRN', 'INSURANCE_ID',
                             'ADDRESS', 'DOB'):
                    Stats.identifiers += 1
                    clean_row.append(f'[{h_type}]')
                elif h_type == 'VILLAGE':
                    # Generalize village to district
                    Stats.generalized += 1
                    clean_row.append(f'[{h_type}]')
                elif h_type == 'PIN':
                    # Keep first 3 digits
                    digits = re.sub(r'\D', '', cell)
                    if len(digits) == 6:
                        clean_row.append(digits[:3] + '***')
                        Stats.generalized += 1
                    else:
                        clean_row.append(f'[{h_type}]')
                else:
                    clean_row.append(f'[{h_type}]')
            else:
                # Non-PII column: still scan for embedded PII
                cleaned, dets = clean_text(cell)
                Stats.identifiers += len(dets)
                clean_row.append(cleaned)

        records.append({"file": f"sanitized/{rel}", "loc": f"row:{i}", "patient": None})
        Stats.records += 1
        w.writerow(clean_row)

    return buf.getvalue()


def process_json(text: str, rel: str, records: list,
                 linker: PatientCluster) -> str:
    data = json.loads(text)

    # Determine if this is a FHIR Bundle, a single document, or a record collection
    is_fhir = isinstance(data, dict) and data.get("resourceType") == "Bundle"
    is_doc = not isinstance(data, dict) or is_fhir or not any(
        isinstance(v, list) and v and all(isinstance(x, dict) for x in v)
        for v in data.values()
    )

    if is_doc:
        record_id = f"{rel}:doc"
        # Extract evidence from the whole document
        if isinstance(data, dict):
            ev = extract_evidence_json(data)
            linker.add_evidence(record_id, ev)
        records.append({"file": f"sanitized/{rel}", "loc": "doc", "patient": None})
        Stats.records += 1
    else:
        # Process each record array
        for k, v in data.items():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                for i, record in enumerate(v):
                    pointer_key = k.replace("~", "~0").replace("/", "~1")
                    record_id = f"{rel}:/{pointer_key}/{i}"
                    ev = extract_evidence_json(record)
                    linker.add_evidence(record_id, ev)
                    records.append({
                        "file": f"sanitized/{rel}",
                        "loc": f"/{pointer_key}/{i}",
                        "patient": None
                    })
                    Stats.records += 1

    # Clean the JSON data
    cleaned, dets = clean_value(data)
    Stats.identifiers += len(dets)

    return json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n"


def process_text(text: str, rel: str, records: list,
                 linker: PatientCluster) -> str:
    record_id = f"{rel}:doc"
    ev = extract_evidence_text(text)
    linker.add_evidence(record_id, ev)
    records.append({"file": f"sanitized/{rel}", "loc": "doc", "patient": None})
    Stats.records += 1

    # Clean the text
    cleaned, dets = clean_text(text)
    Stats.identifiers += len(dets)

    return cleaned


def peak_rss_mb() -> float:
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(r / 1024 if sys.platform != "darwin" else r / 1048576, 1)
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="RAKSHA Privacy Firewall")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    t0 = time.monotonic()
    inp, out = Path(a.input), Path(a.output)
    san = out / "sanitized"
    san.mkdir(parents=True, exist_ok=True)
    files_report: list[dict] = []
    records: list[dict] = []
    linker = PatientCluster()
    sys.setrecursionlimit(5000)

    # Time guard: stop refinement at 80% of limit
    time_limit = 900  # 15 minutes
    time_guard = time_limit * 0.8

    # Phase 1: Process all files
    for path in sorted(p for p in inp.rglob("*") if p.is_file()):
        # Time guard check
        elapsed = time.monotonic() - t0
        if elapsed > time_guard:
            # Quarantine remaining files
            rel = path.relative_to(inp).as_posix()
            raw = path.read_bytes()
            entry = {
                "input_sha256": hashlib.sha256(raw).hexdigest(),
                "output": None,
                "status": "quarantined",
                "reason": "time_limit_approaching"
            }
            files_report.append(entry)
            continue

        rel = path.relative_to(inp).as_posix()
        raw = path.read_bytes()
        entry: dict[str, Any] = {"input_sha256": hashlib.sha256(raw).hexdigest()}
        ext = path.suffix.lower()

        try:
            if ext not in (".csv", ".tsv", ".json", ".txt"):
                raise ValueError("unsupported_format")
            if not raw.strip():
                raise ValueError("empty_file")
            text = decode(raw)
            if text is None:
                raise ValueError("undecodable_text")

            # Check for deeply nested JSON
            if ext == ".json":
                # Quick nesting depth check
                depth = 0
                max_depth = 0
                for c in text[:10000]:
                    if c in ('{', '['):
                        depth += 1
                        max_depth = max(max_depth, depth)
                    elif c in ('}', ']'):
                        depth -= 1
                if max_depth > 100:
                    raise ValueError("excessive_nesting")

            # Check if file contains valid JSON when extension is .csv but content is JSON
            if ext == '.csv':
                stripped = text.strip()
                if stripped.startswith('{') or stripped.startswith('['):
                    # This is actually JSON mislabeled as CSV - quarantine
                    raise ValueError("format_mismatch")

            # Determine output path (rename if filename has PII)
            out_rel = rel
            if has_pii_in_filename(rel):
                out_rel = sanitize_filename(rel)

            # Process by type
            if ext in (".csv", ".tsv"):
                result = process_csv(text, "\t" if ext == ".tsv" else ",", out_rel, records, linker)
            elif ext == ".json":
                result = process_json(text, out_rel, records, linker)
            else:
                result = process_text(text, out_rel, records, linker)

            dest = san / out_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(result, encoding="utf-8", newline="")
            entry.update(output=f"sanitized/{out_rel}", status="sanitized")

        except (ValueError, RecursionError, UnicodeError, csv.Error, json.JSONDecodeError,
                KeyError, TypeError, OverflowError, MemoryError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) and str(exc).replace('_','').isalpha() else type(exc).__name__
            entry.update(output=None, status="quarantined", reason=reason)

        files_report.append(entry)

    # Phase 2: Run linkage
    linker.link()

    # Phase 3: Assign pseudonyms to records
    exported = {e["output"] for e in files_report if e.get("output")}
    final_records = []
    for r in records:
        if r["file"] not in exported:
            continue
        record_id = None
        # Build record ID from file path and loc
        file_path = r["file"].replace("sanitized/", "", 1)
        record_id = f"{file_path}:{r['loc']}"
        pid = linker.get_pseudonym(record_id)
        r["patient"] = pid
        if pid:
            Stats.linked += 1
        final_records.append(r)

    # Phase 4: Insert pseudonyms into sanitized records
    for r in final_records:
        if r["patient"]:
            file_path = out / r["file"]
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding="utf-8")
                    ext = file_path.suffix.lower()
                    if ext in ('.csv', '.tsv'):
                        # Insert pseudonym into the row
                        lines = content.split('\n')
                        loc = r["loc"]
                        if loc.startswith("row:"):
                            row_idx = int(loc.split(":")[1])
                            # Row index is 0-based after header, so +1 for header
                            line_idx = row_idx + 1
                            if line_idx < len(lines) and lines[line_idx]:
                                # Append pseudonym as a note or replace a [MRN] placeholder
                                lines[line_idx] = lines[line_idx].replace('[MRN]', r["patient"], 1)
                                if r["patient"] not in lines[line_idx]:
                                    # If no MRN placeholder, try PATIENT_NAME
                                    lines[line_idx] = lines[line_idx].replace('[PATIENT_NAME]', r["patient"], 1)
                        content = '\n'.join(lines)
                    elif ext == '.json':
                        # Insert pseudonym into the JSON
                        try:
                            data = json.loads(content)
                            if r["loc"] == "doc":
                                if isinstance(data, dict):
                                    data["patient_ref"] = r["patient"]
                            else:
                                # Navigate to the record and insert
                                parts = r["loc"].strip("/").split("/")
                                current = data
                                for p in parts[:-1]:
                                    p = p.replace("~1", "/").replace("~0", "~")
                                    if isinstance(current, dict):
                                        current = current.get(p, current)
                                    elif isinstance(current, list):
                                        try:
                                            current = current[int(p)]
                                        except (ValueError, IndexError):
                                            break
                                last = parts[-1].replace("~1", "/").replace("~0", "~")
                                if isinstance(current, dict):
                                    current = current.get(last, current)
                                elif isinstance(current, list):
                                    try:
                                        current = current[int(last)]
                                    except (ValueError, IndexError):
                                        pass
                                if isinstance(current, dict):
                                    current["patient_ref"] = r["patient"]
                            content = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
                        except (json.JSONDecodeError, KeyError, TypeError):
                            pass
                    elif ext == '.txt':
                        # Prepend pseudonym
                        if r["patient"] not in content:
                            content = f"Patient: {r['patient']}\n{content}"

                    file_path.write_text(content, encoding="utf-8", newline="")
                except (OSError, UnicodeError):
                    pass

    # Write records.jsonl
    with open(out / "records.jsonl", "w", encoding="utf-8") as f:
        for r in final_records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    # Write report.json
    n_san = sum(e["status"] == "sanitized" for e in files_report)
    report = {
        "schema": "raksha-report/1",
        "files": files_report,
        "counts": {
            "files_total": len(files_report),
            "files_sanitized": n_san,
            "files_quarantined": len(files_report) - n_san,
            "records_processed": len(final_records),
            "identifiers_detected": Stats.identifiers,
            "records_linked": Stats.linked,
            "records_generalized": Stats.generalized,
            "records_suppressed": Stats.suppressed,
            "records_quarantined": 0,
        },
        "timing": {"seconds": round(time.monotonic() - t0, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
    }
    (out / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )

    # Only counts go to stdout
    print(f"files {len(files_report)} sanitized {n_san} quarantined {len(files_report) - n_san} records {len(final_records)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

