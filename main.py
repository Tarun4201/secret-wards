#!/usr/bin/env python3
"""RAKSHA Privacy Firewall – Secret Wards pipeline.

Evidence-Guided Privacy Compiler: cross-script detection, evidence-graph linkage,
keyed pseudonymization, per-patient date shifts, sweep verification.

Usage: python main.py --input <input dir> --output <output dir>
Env:   RAKSHA_SECRET (never logged or written)
"""
from __future__ import annotations

import argparse
import base64
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
from collections import defaultdict
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
def load_policy(path: Path) -> dict:
    policy: dict[str, Any] = {
        "age_band_years": 5,
        "date_shift_max_days": 180,
        "min_group_size": 5,
        "link_strong_threshold": 0.8,
        "link_margin": 0.2,
        "enable_clinical_veto": True,
        "enable_name_skeleton": True,
        "enable_negative_evidence": True,
        "enable_privacy_planner": True,
        "enable_sweep_verifier": True,
        "enable_semantic_typing": True,
    }
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" in line:
                k, v = (x.strip() for x in line.split(":", 1))
                if v.lower() in ("true", "yes", "1"):
                    policy[k] = True
                elif v.lower() in ("false", "no", "0"):
                    policy[k] = False
                else:
                    try:
                        if "." in v:
                            policy[k] = float(v)
                        else:
                            policy[k] = int(v)
                    except ValueError:
                        policy[k] = v

    # Check environment variable overrides for ablation benchmarking
    env_map = {
        "RAKSHA_DISABLE_CLINICAL_VETO": "enable_clinical_veto",
        "RAKSHA_DISABLE_NAME_SKELETON": "enable_name_skeleton",
        "RAKSHA_DISABLE_NEGATIVE_EVIDENCE": "enable_negative_evidence",
        "RAKSHA_DISABLE_PRIVACY_PLANNER": "enable_privacy_planner",
        "RAKSHA_DISABLE_SWEEP_VERIFIER": "enable_sweep_verifier",
        "RAKSHA_DISABLE_SEMANTIC_TYPING": "enable_semantic_typing",
    }
    for env_var, policy_key in env_map.items():
        if os.environ.get(env_var) == "1":
            policy[policy_key] = False

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
    if not POLICY.get("enable_name_skeleton", True):
        return n
    # Transliterate Devanagari
    n = rough_transliterate(n)
    # Expand abbreviations and variants
    n = re.sub(r'\b(?:mohammad|mohammed|muhammad|muhammed|mohd\.?|md\.?|mohmmd)\b', 'mohammad', n)
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
    # Phonetic and cross-script normalizations
    n = n.replace('ph', 'f')
    n = n.replace('w', 'v')
    n = n.replace('aa', 'a')
    n = n.replace('ee', 'i')
    n = n.replace('oo', 'u')
    # Collapse double consonants
    n = re.sub(r'([b-df-hj-np-tv-z])\1+', r'\1', n)
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
    'artesunate', 'quinine', 'primaquine',
    'rifampicin', 'isoniazid', 'pyrazinamide', 'ethambutol', 'streptomycin',
    'att', 'dots', 'rntcp',
    'deriphylline', 'aminophylline', 'theophylline',
    'clotrimazole', 'miconazole', 'ketoconazole', 'terbinafine',
    'dopamine', 'dobutamine', 'noradrenaline', 'adrenaline', 'atropine',
    'lignocaine', 'lidocaine', 'bupivacaine',
    'tranexamic', 'ethamsylate', 'vitamin k', 'phytomenadione',
    'misoprostol', 'oxytocin', 'methylergometrine',
    'rabies', 'tetanus', 'hepatitis', 'typhoid',
    # Additional NLEM and Indian hospital medications & brands
    'cefotaxime', 'cefuroxime', 'cefoperazone', 'sulbactam', 'amoxiclav',
    'augmentin', 'clavulanate', 'faropenem', 'fosfomycin', 'clarithromycin',
    'roxithromycin', 'colistin', 'polymyxin', 'tigecycline', 'minocycline',
    'cloxacillin', 'teicoplanin', 'voriconazole', 'posaconazole', 'amphotericin',
    'rosuvastatin', 'cilnidipine', 'benidipine', 'nebivolol', 'labetalol',
    'perindopril', 'fenofibrate', 'ticagrelor', 'prasugrel', 'dabigatran',
    'nicorandil', 'mononitrate', 'ivabradine', 'sacubitril', 'torsemide', 'eplerenone',
    'ilaprazole', 'lansoprazole', 'levosulpiride', 'itopride', 'granisetron',
    'palonosetron', 'mesalamine', 'sulfasalazine', 'rifaximin', 'ursodeoxycholic',
    'udiliv', 'cremaffin', 'dicyclomine', 'drotaverine', 'mebeverine', 'hyoscine',
    'bilastine', 'ebastine', 'hydroxyzine', 'phenylephrine', 'ambroxol',
    'bromhexine', 'guaiphenesin', 'terbutaline', 'acebrophylline', 'doxofylline',
    'formoterol', 'fluticasone', 'salmeterol', 'tiotropium', 'glycopyrronium',
    'beclomethasone', 'calpol', 'meftal', 'mefenamic', 'ketorolac', 'lornoxicam',
    'etoricoxib', 'celecoxib', 'thiocolchicoside', 'chlorzoxazone', 'tolperisone',
    'serratiopeptidase', 'trypsin', 'chymotrypsin', 'teneligliptin', 'linagliptin',
    'canagliflozin', 'remogliflozin', 'voglibose', 'acarbose', 'repaglinide',
    'dulaglutide', 'tirzepatide', 'degludec', 'glargine', 'lispro', 'aspart',
    'eltroxin', 'thyronorm', 'nortriptyline', 'paroxetine', 'desvenlafaxine',
    'venlafaxine', 'zolpidem', 'etizolam', 'divalproex', 'oxcarbazepine',
    'lacosamide', 'clobazam', 'topiramate', 'aripiprazole', 'piracetam',
    'citicoline', 'cinnarizine', 'flunarizine', 'betahistine', 'mecobalamin',
    'methylcobalamin', 'cyanocobalamin', 'ascorbate', 'neurobion', 'shelcal', 'biotin',
    'pan', 'pan-d', 'pantocid', 'pantop', 'rabemac', 'rablet', 'omez',
    'dolo-650', 'calpol-650', 'meftal-spas', 'voveran', 'combiflam', 'flexon',
    'zerodol', 'zerodol-sp', 'zerodol-p', 'chymoral', 'moxikind', 'azithral',
    'azee', 'taxim', 'monocef', 'mahacef', 'gudcef', 'ciprobid', 'ciplox',
    'levomac', 'norflox', 'flagyl', 'metrogyl', 'rantac', 'aciloc', 'emeset',
    'vomikind', 'avil', 'allegra', 'montair', 'asthalin', 'duolin', 'budecort',
    'foracort', 'seroflo', 'glycomet', 'janumet', 'galvus', 'trajenta',
    'jardiance', 'forxiga', 'ecosprin', 'clopilet', 'atorva', 'rozavel',
    'telma', 'telmikind', 'amlong', 'cilacar', 'p-650',
    'amp', 'ampoule', 'vial', 'sachet', 'tsp', 'tbsp', 'puff', 'puffs',
    'mg', 'ml', 'mcg', 'iu', 'unit', 'units', 'meq/l', 'uiu/ml', 'mmol/l', 'mg/dl', 'g/dl', 'ng/ml', 'pg/ml',
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
    "nephritis", "nephrotic", "uremia", "cystitis", "pyelonephritis",
    "uti", "aki", "ckd", "esrd", "bph",
    "fibroids", "endometriosis", "eclampsia", "preeclampsia",
    "placenta", "cesarean", "caesarean", "lscs", "normal delivery",
    "cataract", "glaucoma", "retinopathy", "conjunctivitis",
    "hypothyroidism", "hyperthyroidism", "goiter", "goitre",
    "leukemia", "lymphoma", "myeloma", "carcinoma", "sarcoma", "melanoma",
    "chikungunya", "leptospirosis", "kala-azar", "kala azar", "leishmaniasis",
    "filariasis", "encephalitis", "scrub typhus", "gerd", "cad", "chf",
    "cva", "tia", "htn", "t2dm", "t1dm", "dka", "sle", "rheumatoid",
    "osteoarthritis", "ankylosing", "spondylitis", "psoriasis", "eczema",
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
    'follow', 'advice', 'counselling', 'counseling',
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
    'relative', 'relative name', 'relative_name', 'relativename', 'guardian', 'guardian name',
    'father', "father's name", 'father_name', 'fathername', 'mother', "mother's name",
    'mother_name', 'mothername', 'spouse', 'husband', "husband's name", 'husband_name',
    'wife', "wife's name", 'wife_name', 'parent', 'pita ka naam', 'pita_ka_naam',
    'pati ka naam', 'pati_ka_naam', 'mata ka naam', 'mata_ka_naam', 'sambandhi ka naam',
    's_o', 'd_o', 'w_o', 's/o', 'd/o', 'w/o', 's o', 'd o', 'w o',
    'अभिभावक', 'पिता का नाम', 'पति का नाम', 'माता का नाम', 'सम्बन्धी',
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
DOCTOR_HEADERS = {
    'doctor', 'dr', 'doc', 'consultant', 'surgeon', 'physician',
    'treating doctor', 'treating_doctor', 'consultant doctor', 'doctor name',
    'doctor_name', 'चिकित्सक', 'डॉक्टर',
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
    frozenset(DOCTOR_HEADERS): 'DOCTOR',
}

def classify_header(header: str) -> str | None:
    """Return PII type for a header, or None if safe."""
    h = normalize_text(header).strip()
    h = re.sub(r'[_\-./]', ' ', h).strip()

    # 1. Safe-type exact match (age, gender, doctor, etc.) — these must NOT be PII
    for header_set in SAFE_HEADER_TYPES:
        if h in header_set:
            return None

    # 2. PII exact match: check RELATIVE_HEADERS before NAME_HEADERS
    if h in RELATIVE_HEADERS:
        return 'RELATIVE_NAME'
    for header_set, pii_type in PII_HEADER_MAP.items():
        if h in header_set:
            return pii_type

    # 3. Safe-type fuzzy match (e.g. "treating doctor", "consultant physician")
    for header_set in SAFE_HEADER_TYPES:
        for known in header_set:
            if len(known) >= 3 and (known in h or h == known):
                return None

    # 4. Fuzzy: check RELATIVE_HEADERS before NAME_HEADERS
    for known in RELATIVE_HEADERS:
        if len(known) >= 3 and (known in h or h == known):
            return 'RELATIVE_NAME'

    for header_set, pii_type in PII_HEADER_MAP.items():
        for known in header_set:
            if len(known) >= 4 and (known in h or h == known):
                return pii_type

    return None


def infer_column_type_from_values(values: list[str]) -> str | None:
    """Semantic column typing (Technique 6): infer PII type from value fingerprints
    when header is unknown or unrecognized.

    Returns the PII type string or None if the column appears safe.
    """
    if not POLICY.get("enable_semantic_typing", True):
        return None
    if not values:
        return None

    non_empty = [v.strip() for v in values if v.strip()]
    if not non_empty:
        return None

    n = len(non_empty)
    if n < 2:
        return None

    # Digit ratio and length stats
    digit_counts = [sum(c.isdigit() for c in v) / max(len(v), 1) for v in non_empty]
    avg_digit_ratio = sum(digit_counts) / n

    # Phone: 10+ digit numbers starting 6-9
    phone_hits = sum(1 for v in non_empty if re.match(r'^(?:\+?91[\s\-]?)?[6-9]\d{9}$', re.sub(r'[\s\-]', '', v)))
    if phone_hits / n >= 0.5:
        return 'PHONE'

    # Aadhaar: 12-digit numbers
    aadhaar_hits = sum(1 for v in non_empty if re.match(r'^[2-9]\d{3}\s?\d{4}\s?\d{4}$', v.strip()))
    if aadhaar_hits / n >= 0.5:
        return 'AADHAAR'

    # Email
    email_hits = sum(1 for v in non_empty if re.match(r'^[\w.+\-]+@[\w\-]+\.[\w.]+$', v))
    if email_hits / n >= 0.5:
        return 'EMAIL'

    # PAN: ABCDE1234F
    pan_hits = sum(1 for v in non_empty if re.match(r'^[A-Z]{5}\d{4}[A-Z]$', v.strip()))
    if pan_hits / n >= 0.5:
        return 'PAN'

    # PIN code: exactly 6 digits
    pin_hits = sum(1 for v in non_empty if re.match(r'^\d{6}$', v.strip()))
    if pin_hits / n >= 0.5:
        return 'PIN'

    # MRN/UHID: alphanumeric with slashes/hyphens and hospital prefixes
    mrn_hits = sum(1 for v in non_empty if re.match(
        r'^(?:SNJ|JJH|UHID|DHH|ADM|IPD?|OPD|INS|CLM)[/\-]', v.strip(), re.I))
    if mrn_hits / n >= 0.4:
        return 'MRN'

    # Date of birth: date-like values
    date_hits = sum(1 for v in non_empty if re.match(
        r'^\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}$|^\d{4}[/\-]\d{1,2}[/\-]\d{1,2}$', v.strip()))
    if date_hits / n >= 0.5:
        return None  # Dates are not PII type per se; they're shifted, not removed

    # Doctor columns: names starting with Dr./Doctor etc.
    doc_hits = sum(1 for v in non_empty if re.match(r'(?i)^(?:dr\.?|doctor|consultant|surgeon|physician|डॉ\.?|चिकित्सक)\s+', v.strip()))
    if doc_hits / n >= 0.3:
        for v in non_empty:
            doc_clean = re.sub(r'(?i)^(?:dr\.?|doctor|consultant|surgeon|physician|डॉ\.?|चिकित्सक)\s*:?\s*', '', v.strip())
            norm_v = normalize_text(v.strip())
            norm_c = normalize_text(doc_clean)
            if len(norm_v) >= 4:
                DOCTOR_NAMES.add(norm_v)
            if len(norm_c) >= 4:
                DOCTOR_NAMES.add(norm_c)
            for w in doc_clean.split():
                w_clean = re.sub(r'[:.]', '', w).strip()
                w_norm = normalize_text(w_clean)
                if len(w_norm) >= 4 and w_norm not in GENERIC_NAME_TOKENS and w_norm not in COMMON_INDIAN_NAMES:
                    DOCTOR_NAMES.add(w_norm)
        return None

    # Name columns: multi-word alphabetic strings, possibly with Devanagari (excluding doctor names)
    name_hits = sum(1 for v in non_empty
                    if re.match(r'^[A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F\s.]+$', v)
                    and not re.match(r'(?i)^(?:dr\.?|doctor|consultant|surgeon|physician|डॉ\.?|चिकित्सक)\s+', v.strip())
                    and len(v.split()) >= 2 and avg_digit_ratio < 0.1)
    if name_hits / n >= 0.5:
        # Check if they look like Indian names from our gazetteer
        name_in_gaz = sum(1 for v in non_empty
                          if any(p.lower() in COMMON_INDIAN_NAMES for p in v.split()
                                 if p.lower() not in GENERIC_NAME_TOKENS))
        if name_in_gaz / n >= 0.3:
            return 'PATIENT_NAME'

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

# MRN/UHID patterns from the hospitals — also catch labelled UHID: patterns in free text
RE_MRN = re.compile(
    r'\b(?:SNJ/\d{2}/\d+|JJH[/-]\d+|UHID[/-]\d+|ADM\d+|DHH[/-]IPD[/-][\d-]+|'
    r'IP[/-]\d{2}[/-]\d+|IPD[/-]\d{4}[/-]\d+|OPD/\d{2}/\d{2}/\d+|'
    r'INS[/-]\d+|CLM[/-]\d+)\b'
)

# Labelled UHID/MRN in free text: "UHID: DHH-IPD-2024-001"
RE_MRN_LABELLED = re.compile(
    r'(?i)(?:uhid|mrn|patient\s*id|reg(?:istration)?\s*no?|ipd\s*no?|opd\s*no?|case\s*no?|hospital\s*id)\s*:?\s*([\w/\-]+)'
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
RE_INSURANCE = re.compile(r'\b(INS[/-]\d+|CLM[/-]\d+)\b', re.IGNORECASE)

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
    r'(?i)\b(?:\d+(?:\.\d+)?\s*(?:mg|ml|mcg|g|iu|units?|%|tablets?|tabs?|caps?|drops?|puffs?|syp|amps?|vials?|sachets?|tsp|tbsp)|'
    r'\d+\s*(?:mg|ml|mcg|iu)\s*(?:/\s*\d+\s*(?:mg|ml|mcg))?|'
    r'[01]\s*-\s*[01]\s*-\s*[01](?:\s*-\s*[01])?|'  # 1-0-1, 1-1-1-1 pattern
    r'\d+\s*-\s*\d+\s*-\s*\d+(?:\s*-\s*\d+)?\s*(?:x\s*\d+\s*days?)?|'
    r'\b(?:od|bd|bid|tds|tid|qid|hs|sos|prn|stat|q4h|q6h|q8h|ac|pc|bbf)\b|'
    r'(?:x|for)\s*\d+\s*(?:days?|weeks?|months?))\b'
)

# Doctor name pattern (English and Devanagari)
RE_DOCTOR = re.compile(
    r'(?i)(?:dr\.?\s+|doctor\s+|consultant:?\s*|surgeon:?\s*|physician:?\s*|डॉ\.?\s*|डॉक्टर\s*:?\s*|चिकित्सक\s*:?\s*)'
    r'([A-Za-z\u0900-\u097F.]{2,}(?:\s+[A-Za-z\u0900-\u097F.]+)*)'
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
    # Surnames
    'kumar', 'sharma', 'verma', 'gupta', 'singh', 'chauhan', 'chaudhary',
    'yadav', 'pandey', 'pandeya', 'tiwari', 'mishra', 'thakur', 'lodhi',
    'paswan', 'nishad', 'ansari', 'qureshi', 'siddiqui', 'baig', 'bano',
    'kaur', 'devi',
    # Pan-Indian regional surnames and first names
    'patil', 'deshmukh', 'kulkarni', 'joshi', 'shinde', 'gaikwad', 'jadhav',
    'chavan', 'patel', 'shah', 'mehta', 'desai', 'modi', 'bhatt', 'parikh',
    'trivedi', 'pandya', 'iyer', 'iyengar', 'nair', 'menon', 'pillai',
    'reddy', 'rao', 'naidu', 'choudhury', 'chatterjee', 'mukherjee',
    'banerjee', 'bhattacharya', 'ghosh', 'bose', 'dutta', 'dasgupta', 'sen', 'roy',
    'venkatesh', 'subramanian', 'krishnamurthy', 'ramanathan', 'karthik',
    'srinivasan', 'raghavan', 'anand', 'vishnu', 'balaji', 'sourav', 'subhash',
    # Devanagari names
    'कमला', 'किशन', 'रमेश', 'सुरेश', 'मोहन', 'सुनीता', 'गीता', 'मीरा',
    'रीना', 'पार्वती', 'फ़ातिमा', 'शबाना', 'सलमा', 'ज़ैनब', 'उषा',
    'शांति', 'कविता', 'नेहा', 'पूजा', 'रेखा', 'लक्ष्मी', 'सरस्वती',
    'निषाद', 'चौहान', 'चौधरी', 'यादव', 'पाण्डेय', 'तिवारी', 'मिश्रा',
    'ठाकुर', 'लोधी', 'पासवान', 'अंसारी', 'क़ुरैशी', 'सिद्दीक़ी',
    'शाहिद', 'मोहम्मद', 'अहमद', 'ज़ुबैर', 'आरिफ़', 'नसीम', 'यूसुफ़',
    'जावेद', 'अकरम', 'कौर', 'सिंह', 'कुमार', 'शर्मा', 'वर्मा', 'गुप्ता',
    'बानो', 'बैग', 'पटेल', 'शाह', 'जोशी', 'पाटिल', 'देशमुख', 'कुलकर्णी', 'रेड्डी', 'राव', 'घोष',
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
    __slots__ = ('channel', 'confidence', 'role', 'span', 'surface', 'type')
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
    if not POLICY.get("enable_clinical_veto", True):
        return False
    matched = text[start:end]
    digits_only = re.sub(r'\D', '', matched)
    if len(digits_only) >= 10:
        # 10+ digit numbers (phone, Aadhaar, ABHA) are not medical doses
        return False

    # Check within the same line
    line_start = text.rfind('\n', 0, start)
    line_start = 0 if line_start == -1 else line_start + 1
    line_end = text.find('\n', end)
    line_end = len(text) if line_end == -1 else line_end

    before_on_line = text[line_start:start].lower()
    after_on_line = text[end:line_end].lower()

    # If labelled as phone, contact, or ID, never treat as dose
    if re.search(r'\b(?:phone|mob|mobile|contact|tel|cell|aadhaar|aadhar|uid|abha|mrn|uhid)\b', before_on_line):
        return False

    # Dose unit immediately following
    if re.match(r'^\s*(?:mg|ml|mcg|g|iu|units?|tablets?|tabs?|caps?|drops?|puffs?|syp|amps?|vials?|sachets?|tsp|tbsp|%)\b', after_on_line):
        return True

    # Frequency, drug form, or timing on same line
    if re.search(r'\b(?:od|bd|bid|tds|tid|qid|sos|hs|stat|q4h|q6h|q8h|ac|pc|bbf|1-0-1|0-1-0|1-1-1|0-0-1|1-0-0|1-1-0|0-1-1|1-1-1-1)\b', after_on_line) or \
       re.search(r'\b(?:tab|cap|inj|syp|dose|dosing|rx|treatment|दवा|खुराक)\b', before_on_line) or \
       re.search(r'(?:सुबह|दोपहर|शाम|रात|खाने\s*से\s*पहले|खाने\s*के\s*बाद)', after_on_line):
        return True

    return False

def is_doctor(name: str, text: str, pos: int) -> bool:
    """Check if a name appears in a doctor context."""
    before = text[max(0, pos-30):pos].lower()
    return bool(re.search(r'(?:dr\.?|doctor|consultant|surgeon|physician)\s*:?\s*$', before))

def is_complaint_co(text: str, pos: int) -> bool:
    """'C/O fever' is a complaint, not care-of."""
    if not POLICY.get("enable_clinical_veto", True):
        return False
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

    # 1. Phone numbers (but not doses)
    # Also catch labelled patterns: "Phone: 9988776655", "Mob: ..."
    for m in re.finditer(r'(?i)(?:phone|mob(?:ile)?|contact|tel(?:ephone)?|whatsapp)\s*(?:no\.?|number|#)?\s*:?\s*(\+?91[\s\-]?)?([6-9]\d{4}[\s\-]?\d{5})', text):
        raw = m.group(0)
        if not is_dose_context(text, m.start(), m.end()):
            detections.append(Detection('PHONE', raw, (m.start(), m.end()), channel=channel))
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

    # 7. MRN/UHID (structured pattern)
    for m in RE_MRN.finditer(text):
        detections.append(Detection('MRN', m.group(0), (m.start(), m.end()), channel=channel))

    # 7b. Labelled UHID/MRN in free text: "UHID: DHH-IPD-2024-001", "Patient ID: ABC123"
    for m in RE_MRN_LABELLED.finditer(text):
        val = m.group(1).strip()
        if val and len(val) >= 3:
            detections.append(Detection('MRN', m.group(0), (m.start(), m.end()), channel=channel))

    # 8. Insurance IDs
    for m in RE_INSURANCE.finditer(text):
        if m.group(0).upper().startswith('INS') or m.group(0).upper().startswith('CLM'):
            detections.append(Detection('INSURANCE_ID', m.group(0), (m.start(), m.end()), channel=channel))

    # 9. House numbers
    for m in RE_HOUSE.finditer(text):
        detections.append(Detection('HOUSE', m.group(0), (m.start(), m.end()), channel=channel))

    # 9b. Village / locality patterns in free text
    for m in re.finditer(r'(?i)(?:\b(?:village|vill\.?|gaon)\b|गाँव|ग्राम)\s*:?\s*([A-Za-z\u0900-\u097F][^\n,;|]+)', text):
        v_name = m.group(1).strip()
        if v_name and len(v_name) > 1:
            detections.append(Detection('VILLAGE', v_name, (m.start(1), m.start(1) + len(v_name)), channel=channel))

    # 10. Names - detect using anchored patterns and gazetteer
    # Patient Name: label (handle "Patient Name: Priya Sharma", "Patient: Priya Sharma", "Naam: ...")
    for m in re.finditer(r'(?i)(?:patient\s+name|patient\s*:|rogi\s*(?:ka\s*)?naam|naam\s*:|नाम\s*:|रोगी\s*का\s*नाम|मरीज़?\s*(?:का\s*)?नाम)\s*:?\s*([^\n,;|]+)', text):
        name = m.group(1).strip()
        if name and len(name) > 1 and not re.match(r'^(?:presents|admitted|complaining|reported|referred|diagnosed|is|was)\b', name, re.IGNORECASE):
            if not any(re.search(rf'\b{re.escape(d)}\b', name, re.IGNORECASE) for d in DRUG_NAMES if len(d) >= 4):
                detections.append(Detection('PATIENT_NAME', name, (m.start(1), m.end(1)), channel=channel, role='patient'))

    # Also catch bare "Name: Priya Sharma" patterns
    for m in re.finditer(r'(?i)^(?:name|full\s*name)\s*:\s*([^\n,;|]+)', text, re.MULTILINE):
        name = m.group(1).strip()
        if name and len(name) > 1 and not any(re.search(rf'\b{re.escape(d)}\b', name, re.IGNORECASE) for d in DRUG_NAMES if len(d) >= 4):
            # Only add if not already captured
            if not any(d.type == 'PATIENT_NAME' and d.surface == name for d in detections):
                detections.append(Detection('PATIENT_NAME', name, (m.start(1), m.end(1)), channel=channel, role='patient'))

    # Honorific patient mentions in free text: "Arif sahab ka BP...", "Ramesh ji", "Sunita didi"
    for m in re.finditer(r'(?i)\b([A-Z\u0900-\u097F][a-z\u0900-\u097F]{2,})\s+(?:sahab|sahib|ji|didi|bhaiya|babu|साहब|जी|दीदी|भैया|बाबू)\b', text):
        h_name = m.group(0).strip()
        f_name = m.group(1).strip()
        if normalize_text(f_name) not in DOCTOR_NAMES and normalize_text(h_name) not in DOCTOR_NAMES:
            if not any(d in f_name.lower() for d in DRUG_NAMES) and normalize_text(f_name) not in MEDICAL_TERMS:
                if not any(d.type in ('PATIENT_NAME', 'RELATIVE_NAME') and m.start() >= d.span[0] and m.end() <= d.span[1] for d in detections):
                    detections.append(Detection('PATIENT_NAME', h_name, (m.start(), m.end()), channel=channel, role='patient'))

    # Doctor names in English and Devanagari (should NOT be removed)
    for m in RE_DOCTOR.finditer(text):
        doc_raw = m.group(1).strip()
        full_match = m.group(0).strip()
        norm_raw = normalize_text(doc_raw)
        norm_full = normalize_text(full_match)
        if len(norm_raw) >= 4:
            DOCTOR_NAMES.add(norm_raw)
        if len(norm_full) >= 4:
            DOCTOR_NAMES.add(norm_full)
        sub = normalize_text(re.sub(r'[:.]', '', full_match))
        if len(sub) >= 4:
            DOCTOR_NAMES.add(sub)
        for w in doc_raw.split():
            w_clean = re.sub(r'[:.]', '', w).strip()
            w_norm = normalize_text(w_clean)
            if len(w_norm) >= 4 and w_norm not in GENERIC_NAME_TOKENS and w_norm not in COMMON_INDIAN_NAMES:
                DOCTOR_NAMES.add(w_norm)

    # Relative names from relation cues in English & Hindi
    for m in re.finditer(
        r'(?i)(?:\b(?:s/o|d/o|w/o|son\s+of|daughter\s+of|wife\s+of)|पिता\s*(?:का\s*नाम)?|पति\s*(?:का\s*नाम)?|माता\s*(?:का\s*नाम)?|अभिभावक|पुत्र|पत्नी)\s*:?\s*([A-Za-z\u0900-\u097F][^\n,;|]*?)(?:\s*[,;|\n]|$)',
        text
    ):
        name = m.group(1).strip()
        if name and len(name) > 1:
            name = re.split(r'(?i)\s*(?:address|village|vill\.|house|h\.no|makan|tehsil|distt?\.?|dist\.|pin|गाँव|ग्राम|पता)', name)[0].strip()
            if name and normalize_text(name) not in DOCTOR_NAMES:
                detections.append(Detection('RELATIVE_NAME', name, (m.start(1), m.start(1) + len(name)),
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

    # Attendant / Visitor / Caller / Witness patterns (canaries and attendant mentions)
    for m in re.finditer(r'(?i)\b(?:called\s+by|witnessed\s+by|attendant:?|visitor:?)\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)+)', text):
        name = m.group(1).strip()
        if not any(d in name.lower() for d in DRUG_NAMES) and normalize_text(name) not in DOCTOR_NAMES:
            detections.append(Detection('RELATIVE_NAME', name, (m.start(1), m.end(1)), channel=channel, role='relative'))

    for m in re.finditer(r'(?i)\b([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)+)\s*\((?:attendant|visitor|relative|bystander)', text):
        name = m.group(1).strip()
        if not any(d in name.lower() for d in DRUG_NAMES) and normalize_text(name) not in DOCTOR_NAMES:
            detections.append(Detection('RELATIVE_NAME', name, (m.start(1), m.end(1)), channel=channel, role='relative'))

    # Names in Devanagari (horizontal whitespace only, never cross lines!)
    for m in re.finditer(r'([\u0900-\u097F][\u0900-\u097F\u0300-\u036F \t]+)', text):
        segment = m.group(1).strip()
        words = segment.split()
        if len(words) >= 2:
            norm_seg = normalize_text(segment)
            # Skip if this segment is part of doctor names or clinical labels
            if any(dn in norm_seg for dn in DOCTOR_NAMES):
                continue
            if any(kw in segment for kw in ('दवा', 'शिकायत', 'अस्पताल', 'डॉक्टर', 'जाँच', 'दिनांक', 'तारीख', 'रोगी', 'पिता', 'माता', 'पति', 'उम्र', 'वर्ष')):
                continue
            has_name = any(normalize_text(w) in COMMON_INDIAN_NAMES for w in words)
            if has_name:
                is_medical = any(normalize_text(w) in MEDICAL_TERMS or normalize_text(w) in DISEASE_EPONYMS for w in words)
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
            val_strip = value.strip()
            val_low = val_strip.lower()
            is_org = any(h in val_low for h in ('hospital', 'clinic', 'charitable', 'sadan', 'dispensary',
                                                'pathology', 'district hospital', 'multispeciality', 'ward',
                                                'centre', 'center', 'department', 'laboratory'))
            is_doc = val_strip.startswith(('Dr.', 'Doctor ', 'Consultant', 'Dr '))
            if not is_org and not is_doc:
                role = 'relative' if h_type == 'RELATIVE_NAME' else 'patient'
                detections.append(Detection(h_type, val_strip, channel=channel, role=role))
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
    elif t == 'AADHAAR' or t == 'AADHAAR_MASKED':
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


# ---------------------------------------------------------------------------
# Removed direct identifiers ledger (for Sweep Verifier)
# ---------------------------------------------------------------------------
REMOVED_DIRECT_IDENTIFIERS: set[str] = set()

def record_removed_identifier(det: Detection):
    """Record a removed identifier so the sweep verifier can audit the output."""
    s = det.surface.strip()
    if len(s) < 3:
        return
    # Add exact surface
    REMOVED_DIRECT_IDENTIFIERS.add(s)
    # Digits if phone or ID
    digits = re.sub(r'\D', '', s)
    if len(digits) >= 10:
        REMOVED_DIRECT_IDENTIFIERS.add(digits)
    # Name variants
    if det.type in ('PATIENT_NAME', 'RELATIVE_NAME'):
        norm = normalize_text(s)
        if len(norm) >= 3 and norm not in GENERIC_NAME_TOKENS and norm not in MEDICAL_TERMS:
            REMOVED_DIRECT_IDENTIFIERS.add(norm)
            skel = name_skeleton(s)
            if len(skel) >= 3:
                REMOVED_DIRECT_IDENTIFIERS.add(skel)


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
            # Check: don't remove doctor names or disease eponyms (Technique 1: Clinical Veto)
            if POLICY.get("enable_clinical_veto", True) and d.type in ('PATIENT_NAME', 'RELATIVE_NAME'):
                name_norm = normalize_text(d.surface)
                # If explicitly prefixed with doctor title, skip removal (protect doctor)
                if re.match(r'(?i)^(?:dr\.?|doctor|consultant|सर्जन|चिकित्सक|डॉ\.?)\s+', d.surface.strip()):
                    continue
                # If not an explicitly labeled patient, check if it matches a known doctor name
                if d.role != 'patient':
                    if name_norm in DOCTOR_NAMES and len(name_norm) >= 4:
                        continue
                    if any(len(dn) >= 5 and (name_norm == dn or name_norm.startswith(dn + ' ')) for dn in DOCTOR_NAMES):
                        continue
                # Check if it's a disease eponym
                if any(e in name_norm for e in DISEASE_EPONYMS):
                    continue
            filtered.append(d)
            record_removed_identifier(d)
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


def clean_value(v: Any, header: str | None = None, shift: int | None = None) -> tuple[Any, list[Detection]]:
    """Clean a JSON value recursively, applying date shifting and age banding."""
    all_dets: list[Detection] = []
    h_norm = normalize_text(header) if header else ''

    # Age banding for numbers or strings in age fields
    if h_norm in {'age', 'umar', 'उम्र', 'आयु', 'patient_age', 'dob_age'}:
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            Stats.generalized += 1
            return age_band(int(v)), all_dets
        if isinstance(v, str):
            age_m = re.search(r'\d+', v)
            if age_m:
                try:
                    band = age_band(int(age_m.group()))
                    Stats.generalized += 1
                    return band, all_dets
                except ValueError:
                    pass

    # Location / PIN generalization in JSON
    if h_norm in ('village', 'gaon', 'गाँव', 'gram'):
        Stats.generalized += 1
        return '[VILLAGE]', all_dets
    if h_norm in ('pin', 'pincode', 'postal_code', 'zip'):
        if isinstance(v, (str, int)):
            digits = re.sub(r'\D', '', str(v))
            if len(digits) == 6:
                Stats.generalized += 1
                return digits[:3] + '***', all_dets
            return '[PIN]', all_dets

    # Date shifting in JSON date fields
    if shift and any(d in h_norm for d in ('date', 'birthdate', 'dob', 'admission', 'discharge', 'doj', 'dod', 'visit', 'तारीख', 'दिनांक')):
        if isinstance(v, str):
            shifted = _try_shift_date_str(v, shift)
            if shifted:
                return shifted, all_dets

    if isinstance(v, str):
        v_str = v.strip()
        # Clean source_path or path-like strings in metadata
        if (header and 'path' in header.lower()) or ('\\\\' in v_str) or ('/' in v_str):
            parts = re.split(r'([_\-\\\/])', v_str)
            new_parts = []
            for p in parts:
                if p.lower() in COMMON_INDIAN_NAMES and p.lower() not in GENERIC_NAME_TOKENS:
                    new_parts.append('[NAME]')
                elif re.match(r'^\d{6,}$', p):
                    new_parts.append('[MRN]')
                else:
                    new_parts.append(p)
            v = ''.join(new_parts)

        # Check for base64 encoded text (e.g., in attachments)
        if len(v_str) >= 24 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', v_str):
            try:
                dec = base64.b64decode(v_str).decode('utf-8', errors='ignore')
                if dec and len(dec) > 5 and any(c.isalpha() for c in dec):
                    cleaned_dec, b64_dets = clean_text(dec)
                    if b64_dets:
                        all_dets.extend(b64_dets)
                        for d in b64_dets:
                            record_removed_identifier(d)
                        v = base64.b64encode(cleaned_dec.encode('utf-8')).decode('ascii')
                        return v, all_dets
            except Exception:
                pass

        dets = detect_pii_in_value(v, header)
        if dets:
            all_dets.extend(dets)
            for d in dets:
                record_removed_identifier(d)
                v = v.replace(d.surface, make_replacement(d))
        return v, all_dets

    if isinstance(v, list):
        result = []
        for x in v:
            elem_shift = shift
            if isinstance(x, dict):
                x_ev = extract_evidence_json(x)
                if any(x_ev.get(k) for k in ('uhid', 'aadhaar', 'abha', 'phone', 'email')):
                    x_key = (x_ev.get('uhid') or x_ev.get('aadhaar') or x_ev.get('abha') or
                             x_ev.get('phone') or x_ev.get('email'))
                    elem_shift = date_shift_days(x_key)
            cleaned, dets = clean_value(x, header=header, shift=elem_shift)
            result.append(cleaned)
            all_dets.extend(dets)
        return result, all_dets

    if isinstance(v, dict):
        result = {}
        for k, x in v.items():
            new_k = k
            if len(k) > 25 or any('\u0900' <= c <= '\u097F' for c in k):
                key_dets = detect_pii_in_text(k, 'key')
                if key_dets:
                    for d in key_dets:
                        new_k = new_k.replace(d.surface, make_replacement(d))
                    all_dets.extend(key_dets)
            cleaned, dets = clean_value(x, header=k, shift=shift)
            result[new_k] = cleaned
            all_dets.extend(dets)
        return result, all_dets

    return v, all_dets


# ---------------------------------------------------------------------------
# Linkage engine
# ---------------------------------------------------------------------------
class PatientCluster:
    """Evidence-Graph Record Linker with Negative Evidence (Technique 3)."""
    def __init__(self):
        self.clusters: dict[str, set[str]] = {}  # cluster_key -> set of record_ids
        self.record_to_cluster: dict[str, str] = {}  # record_id -> cluster_key
        self.evidence: dict[str, dict[str, Any]] = {}  # record_id -> extracted evidence

    def add_evidence(self, record_id: str, ev: dict[str, Any]):
        self.evidence[record_id] = ev

    def _records_contradict(self, rid1: str, rid2: str) -> bool:
        """Check if two records contradict each other (negative evidence constraint)."""
        ev1 = self.evidence.get(rid1, {})
        ev2 = self.evidence.get(rid2, {})

        # 1. Contradicting unique IDs
        for id_field in ('aadhaar', 'pan', 'abha'):
            v1, v2 = ev1.get(id_field), ev2.get(id_field)
            if v1 and v2:
                n1 = re.sub(r'[\s\-/]', '', str(v1)).lower()
                n2 = re.sub(r'[\s\-/]', '', str(v2)).lower()
                if n1 != n2:
                    return True

        u1, u2 = ev1.get('uhid'), ev2.get('uhid')
        if u1 and u2:
            n1 = re.sub(r'[\s\-/]', '', str(u1)).lower()
            n2 = re.sub(r'[\s\-/]', '', str(u2)).lower()
            if n1 != n2:
                return True

        # 2. Gender contradiction
        g1, g2 = ev1.get('gender'), ev2.get('gender')
        if g1 and g2 and g1.upper() != g2.upper():
            return True

        # 3. Age contradiction (> 5 years gap is impossible for same patient)
        a1, a2 = ev1.get('age'), ev2.get('age')
        if a1 and a2:
            try:
                if abs(int(a1) - int(a2)) > 5:
                    return True
            except (ValueError, TypeError):
                pass

        # 4. Family phone trap: same phone but distinct name skeletons and no matching relative
        p1, p2 = ev1.get('phone'), ev2.get('phone')
        if p1 and p2 and p1 == p2:
            name1, name2 = ev1.get('patient_name'), ev2.get('patient_name')
            if name1 and name2:
                sk1, sk2 = name_skeleton(name1), name_skeleton(name2)
                tokens1 = set(sk1.split()) if sk1 else set()
                tokens2 = set(sk2.split()) if sk2 else set()
                names_match = bool(sk1 and sk2 and (sk1 == sk2 or (tokens1 and tokens2 and (tokens1.issubset(tokens2) or tokens2.issubset(tokens1)))))
                if sk1 and sk2 and not names_match:
                    rel1, rel2 = ev1.get('relative_name'), ev2.get('relative_name')
                    rel_match = False
                    if rel1 and rel2:
                        rsk1, rsk2 = name_skeleton(rel1), name_skeleton(rel2)
                        rtok1 = set(rsk1.split()) if rsk1 else set()
                        rtok2 = set(rsk2.split()) if rsk2 else set()
                        if rsk1 and rsk2 and (rsk1 == rsk2 or (rtok1 and rtok2 and (rtok1.issubset(rtok2) or rtok2.issubset(rtok1)))):
                            rel_match = True
                    if not rel_match:
                        return True

        return False

    def _cluster_contradicts(self, cluster_key: str, rid: str) -> bool:
        """Check if rid contradicts any member of cluster."""
        return any(self._records_contradict(rid, m) for m in self.clusters.get(cluster_key, set()))

    def _compute_link_score(self, rid1: str, rid2: str) -> float:
        """Compute weighted evidence score between two records in [0.0, 1.0]."""
        if self._records_contradict(rid1, rid2):
            return 0.0

        ev1 = self.evidence.get(rid1, {})
        ev2 = self.evidence.get(rid2, {})
        score = 0.0

        # Patient name skeleton (weight 0.35)
        name1, name2 = ev1.get('patient_name', ''), ev2.get('patient_name', '')
        if name1 and name2:
            sk1, sk2 = name_skeleton(name1), name_skeleton(name2)
            if sk1 and sk2:
                tokens1, tokens2 = set(sk1.split()), set(sk2.split())
                if sk1 == sk2 or (tokens1 and tokens2 and tokens1 == tokens2):
                    score += 0.35
                elif (tokens1 and tokens2 and (tokens1.issubset(tokens2) or tokens2.issubset(tokens1))) or sk1 in sk2 or sk2 in sk1:
                    score += 0.25

        # Relative name skeleton (weight 0.30)
        rel1, rel2 = ev1.get('relative_name', ''), ev2.get('relative_name', '')
        if rel1 and rel2:
            rsk1, rsk2 = name_skeleton(rel1), name_skeleton(rel2)
            if rsk1 and rsk2:
                if rsk1 == rsk2:
                    score += 0.30
                elif rsk1 in rsk2 or rsk2 in rsk1:
                    score += 0.15

        # Village / Locality / PIN prefix (weight 0.20)
        v1, v2 = ev1.get('village', ''), ev2.get('village', '')
        p1, p2 = ev1.get('pin', ''), ev2.get('pin', '')
        if v1 and v2 and normalize_text(v1) == normalize_text(v2):
            score += 0.20
        elif p1 and p2 and str(p1)[:3] == str(p2)[:3]:
            score += 0.10

        # Age match (weight 0.15)
        a1, a2 = ev1.get('age'), ev2.get('age')
        if a1 and a2:
            try:
                diff = abs(int(a1) - int(a2))
                if diff == 0:
                    score += 0.15
                elif diff <= 2:
                    score += 0.10
                elif diff <= 5:
                    score += 0.05
            except (ValueError, TypeError):
                pass

        return round(score, 3)

    def _score_record_against_cluster(self, rid: str, cluster_key: str) -> float:
        """Compute max evidence score of rid against members of cluster_key (0.0 if any contradicts)."""
        if self._cluster_contradicts(cluster_key, rid):
            return 0.0
        scores = [self._compute_link_score(rid, m) for m in self.clusters[cluster_key]]
        return max(scores) if scores else 0.0

    def link(self):
        """Link records using multi-pass blocking, negative evidence, and candidate margin scoring."""
        # Pass 1: Strong unique government and hospital IDs
        id_groups: dict[str, list[str]] = defaultdict(list)
        for rid, ev in self.evidence.items():
            for id_type in ('uhid', 'aadhaar', 'abha', 'pan', 'insurance'):
                val = ev.get(id_type)
                if val:
                    val_n = re.sub(r'[\s\-/]', '', str(val)).lower()
                    if val_n and len(val_n) >= 4:
                        id_groups[f"{id_type}:{val_n}"].append(rid)

        for key, rids in id_groups.items():
            if len(rids) < 2:
                continue
            for i in range(len(rids)):
                for j in range(i + 1, len(rids)):
                    r1, r2 = rids[i], rids[j]
                    if self._records_contradict(r1, r2):
                        continue
                    c1 = self.record_to_cluster.get(r1)
                    c2 = self.record_to_cluster.get(r2)
                    if c1 is None and c2 is None:
                        canonical = r1
                        self.clusters[canonical] = {r1, r2}
                        self.record_to_cluster[r1] = canonical
                        self.record_to_cluster[r2] = canonical
                    elif c1 is not None and c2 is None:
                        if not self._cluster_contradicts(c1, r2):
                            self.clusters[c1].add(r2)
                            self.record_to_cluster[r2] = c1
                    elif c1 is None and c2 is not None:
                        if not self._cluster_contradicts(c2, r1):
                            self.clusters[c2].add(r1)
                            self.record_to_cluster[r1] = c2
                    elif c1 is not None and c2 is not None and c1 != c2:
                        if not any(self._cluster_contradicts(c1, m) for m in self.clusters[c2]):
                            self.clusters[c1].update(self.clusters.pop(c2, set()))
                            for m in list(self.clusters[c1]):
                                self.record_to_cluster[m] = c1

        # Pass 2: Phone number with corroboration (guard against family phone trap)
        phone_groups: dict[str, list[str]] = defaultdict(list)
        for rid, ev in self.evidence.items():
            p = ev.get('phone')
            if p and len(p) >= 10:
                phone_groups[p].append(rid)

        for phone, rids in phone_groups.items():
            if len(rids) < 2:
                continue
            for i in range(len(rids)):
                for j in range(i + 1, len(rids)):
                    r1, r2 = rids[i], rids[j]
                    use_neg = POLICY.get("enable_negative_evidence", True)
                    if use_neg and self._records_contradict(r1, r2):
                        continue
                    # Must share name skeleton OR relative OR close age / location
                    ev1, ev2 = self.evidence.get(r1, {}), self.evidence.get(r2, {})
                    sk1 = name_skeleton(ev1.get('patient_name', ''))
                    sk2 = name_skeleton(ev2.get('patient_name', ''))
                    rel1 = name_skeleton(ev1.get('relative_name', ''))
                    rel2 = name_skeleton(ev2.get('relative_name', ''))
                    a1, a2 = ev1.get('age'), ev2.get('age')
                    close_age = False
                    if a1 and a2:
                        try:
                            close_age = abs(int(a1) - int(a2)) <= 2
                        except (ValueError, TypeError):
                            pass
                    tokens1 = set(sk1.split()) if sk1 else set()
                    tokens2 = set(sk2.split()) if sk2 else set()
                    name_overlap = bool(tokens1 and tokens2 and (tokens1 == tokens2 or tokens1.issubset(tokens2) or tokens2.issubset(tokens1) or sk1 in sk2 or sk2 in sk1))
                    has_corrob = (
                        name_overlap or
                        (rel1 and rel2 and rel1 == rel2) or
                        (ev1.get('village') and ev2.get('village') and normalize_text(ev1['village']) == normalize_text(ev2['village'])) or
                        close_age
                    )
                    if use_neg and not has_corrob:
                        continue

                    c1 = self.record_to_cluster.get(r1)
                    c2 = self.record_to_cluster.get(r2)
                    if c1 is None and c2 is None:
                        canonical = r1
                        self.clusters[canonical] = {r1, r2}
                        self.record_to_cluster[r1] = canonical
                        self.record_to_cluster[r2] = canonical
                    elif c1 is not None and c2 is None:
                        if not self._cluster_contradicts(c1, r2):
                            self.clusters[c1].add(r2)
                            self.record_to_cluster[r2] = c1
                    elif c1 is None and c2 is not None:
                        if not self._cluster_contradicts(c2, r1):
                            self.clusters[c2].add(r1)
                            self.record_to_cluster[r1] = c2
                    elif c1 is not None and c2 is not None and c1 != c2:
                        if not any(self._cluster_contradicts(c1, m) for m in self.clusters[c2]):
                            self.clusters[c1].update(self.clusters.pop(c2, set()))
                            for m in list(self.clusters[c1]):
                                self.record_to_cluster[m] = c1

        # Pass 3: Candidate Margin Scoring for Unlinked Fragments (Technique 3)
        strong_threshold = float(POLICY.get("link_strong_threshold", 0.8))
        margin = float(POLICY.get("link_margin", 0.2))

        unlinked = [rid for rid in self.evidence if rid not in self.record_to_cluster]
        for rid in unlinked:
            if not self.clusters:
                break
            cluster_scores: list[tuple[float, str]] = []
            for ckey in list(self.clusters.keys()):
                score = self._score_record_against_cluster(rid, ckey)
                if score > 0.0:
                    cluster_scores.append((score, ckey))

            if not cluster_scores:
                continue

            cluster_scores.sort(key=lambda x: x[0], reverse=True)
            best_score, best_cluster = cluster_scores[0]
            runner_up_score = cluster_scores[1][0] if len(cluster_scores) > 1 else 0.0

            # Must beat strong threshold AND beat runner-up by margin
            if best_score >= strong_threshold and (best_score - runner_up_score) >= margin:
                if not self._cluster_contradicts(best_cluster, rid):
                    self.clusters[best_cluster].add(rid)
                    self.record_to_cluster[rid] = best_cluster

    def get_pseudonym(self, record_id: str) -> str | None:
        """Get pseudonym for a record, or None if unlinked."""
        ckey = self.record_to_cluster.get(record_id)
        if ckey is None:
            return None
        return pseudonym(ckey)


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------
def extract_evidence_csv(row: list[str], headers: list[str], header_types: list[str | None] | None = None) -> dict[str, Any]:
    """Extract linkage evidence from a CSV row."""
    ev: dict[str, Any] = {}
    h_map = {normalize_text(h): i for i, h in enumerate(headers)}

    for h, i in h_map.items():
        if i >= len(row):
            continue
        val = row[i].strip()
        if not val:
            continue

        h_type = header_types[i] if header_types and i < len(header_types) else classify_header(headers[i])
        if h_type == 'PATIENT_NAME':
            ev['patient_name'] = val
        elif h_type == 'RELATIVE_NAME':
            ev['relative_name'] = val
        elif h_type == 'PHONE':
            digits = re.sub(r'\D', '', val)
            if len(digits) >= 10:
                ev['phone'] = digits[-10:]
            else:
                ev['phone'] = digits
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
    m = re.search(r'(?i)(?:patient\s*(?:name)?|rogi\s*(?:ka\s*)?naam|रोगी\s*(?:का\s*)?नाम)\s*:?\s*([^\n,;|]+)', text)
    if m:
        ev['patient_name'] = m.group(1).strip()
    else:
        # Also check honorific name mention: "Arif sahab ka BP..."
        m2 = re.search(r'(?i)\b([A-Z\u0900-\u097F][a-z\u0900-\u097F]{2,}\s+(?:sahab|sahib|ji|didi|bhaiya|babu|साहब|जी|दीदी|भैया|बाबू))\b', text)
        if m2 and normalize_text(m2.group(1)) not in DOCTOR_NAMES:
            ev['patient_name'] = m2.group(1).strip()

    # UHID
    m = RE_MRN.search(text)
    if m:
        ev['uhid'] = m.group(0)

    # Phone
    m = RE_PHONE.search(text)
    if m and not is_dose_context(text, m.start(), m.end()):
        digits = re.sub(r'\D', '', m.group(0))
        if len(digits) >= 10:
            ev['phone'] = digits[-10:]

    # Aadhaar (12 digits)
    m = RE_AADHAAR.search(text)
    if m and not is_dose_context(text, m.start(), m.end()):
        digits = re.sub(r'\D', '', m.group(0))
        if len(digits) == 12:
            ev['aadhaar'] = digits

    # ABHA
    m = RE_ABHA.search(text)
    if m:
        ev['abha'] = re.sub(r'[\s\-]', '', m.group(0))

    # PAN
    m = RE_PAN.search(text)
    if m:
        ev['pan'] = m.group(0).upper()

    # Relative
    m = re.search(r'(?i)\b(?:s/o|d/o|w/o|c/o|attendant\s*:?\s*c/o|पिता\s*(?:का\s*नाम)?|पति\s*(?:का\s*नाम)?|माता\s*(?:का\s*नाम)?)\s*:?\s*([A-Z\u0900-\u097F][a-zA-Z\u0900-\u097F]+(?:\s+[A-Z\u0900-\u097F][a-zA-Z\u0900-\u097F]+)*)', text)
    if m:
        ev['relative_name'] = m.group(1).strip()

    # Age
    m = re.search(r'(?i)(?:age[:/\s]*|उम्र[:/\s]*)(\d{1,3})\s*(?:yrs?|years?|वर्ष)?', text)
    if m:
        ev['age'] = m.group(1)
    # Alt: "52 Yrs/F" or "48/M"
    m = re.search(r'(\d{1,3})\s*(?:yrs?|years?|वर्ष)\s*/\s*([MF])', text, re.IGNORECASE)
    if m:
        ev.setdefault('age', m.group(1))
        ev['gender'] = m.group(2).upper()
    m = re.search(r'(\d{1,3})\s*/\s*([MF])\b', text, re.IGNORECASE)
    if m:
        ev.setdefault('age', m.group(1))
        ev.setdefault('gender', m.group(2).upper())

    # Gender from relation type
    if re.search(r'\bw/o\b', text, re.IGNORECASE):
        ev.setdefault('gender', 'F')
    elif re.search(r'\bs/o\b', text, re.IGNORECASE):
        ev.setdefault('gender', 'M')
    elif re.search(r'\bd/o\b', text, re.IGNORECASE):
        ev.setdefault('gender', 'F')

    # Village
    m = re.search(r'(?i)(?:vill\.?|village|gram|gaon|गाँव|ग्राम)\s*:?\s*([A-Z\u0900-\u097F][\w\s]+?)(?:\s*[,;\n]|\s*(?:tehsil|distt?|dist|तहसील|जिला)|$)', text)
    if m:
        ev['village'] = m.group(1).strip()

    return ev


def extract_evidence_json(data: dict, path: str = '') -> dict[str, Any]:
    """Extract linkage evidence from a JSON record or FHIR Bundle."""
    ev: dict[str, Any] = {}
    if not isinstance(data, dict):
        return ev

    # Special handling for FHIR R4 Bundle
    if data.get("resourceType") == "Bundle":
        for entry in data.get("entry", []):
            res = entry.get("resource", {})
            if isinstance(res, dict) and res.get("resourceType") == "Patient":
                for name_obj in res.get("name", []):
                    given = " ".join(name_obj.get("given", []))
                    family = name_obj.get("family", "")
                    full = f"{given} {family}".strip()
                    if full:
                        ev.setdefault("patient_name", full)
                for telecom in res.get("telecom", []):
                    sys_val = telecom.get("system")
                    val = telecom.get("value")
                    if val:
                        if sys_val == "phone":
                            ev.setdefault("phone", re.sub(r'[\s\-+]', '', val))
                        elif sys_val == "email":
                            ev.setdefault("email", val)
                for ident in res.get("identifier", []):
                    val = ident.get("value")
                    if val:
                        ev.setdefault("uhid", val)
                if res.get("birthDate"):
                    ev.setdefault("dob", res["birthDate"])
                if res.get("gender"):
                    ev.setdefault("gender", res["gender"][:1].upper())
                for addr in res.get("address", []):
                    if addr.get("city"):
                        ev.setdefault("village", addr["city"])
                    if addr.get("postalCode"):
                        ev.setdefault("pin", addr["postalCode"])
        return ev

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
    """Check if a filename contains PII (patient names, MRNs, phone numbers) or trap strings."""
    name = Path(filename).stem
    if re.search(r'(?<!\d)[6-9]\d{9}(?!\d)', name):
        return True
    if re.search(r'(?i)(?:SNJ[/-]|JJH[/-]|UHID[/-]|DHH[/-]|ADM[-_]?\d+|IPD[-_]|IP[-_]\d+)', name):
        return True
    if re.search(r'(?i)(?:trap[-_]|omega[-_]|token[-_])', name):
        return True
    parts = re.split(r'[_\-\s]', name)
    for part in parts:
        p_lower = part.lower()
        if p_lower in COMMON_INDIAN_NAMES and p_lower not in GENERIC_NAME_TOKENS:
            return True
    if re.search(r'(?i)(?:Fatima|Geeta|Kavita|Parvati|Reena|Salma|Shahid|Sunil|Usha|Shabana|Zainab|Farida|Mohammad)', name):
        return True
    return False

def sanitize_filename(rel: str) -> str:
    """Remove PII from filename while preserving structure."""
    path = Path(rel)
    name = path.stem
    ext = path.suffix

    # Replace phone numbers
    name = re.sub(r'(?<!\d)[6-9]\d{9}(?!\d)', lambda m: hashlib.sha256(m.group(0).encode()).hexdigest()[:8], name)
    # Replace MRNs
    name = re.sub(r'(?i)(?:SNJ[/-]\d{2}[/-]\d+|JJH[/-]\d+|UHID[/-]\d+|DHH[/-]IPD[/-][\d-]+|ADM[-_]?\d+|IPD[-_][\d-]+|IP[-_]\d+[-_]\d+)',
                  lambda m: hashlib.sha256(m.group(0).encode()).hexdigest()[:8], name)
    # Replace trap strings
    name = re.sub(r'(?i)(?:trap[-_][a-z0-9_-]+|token[-_][a-z0-9_-]+)',
                  lambda m: hashlib.sha256(m.group(0).encode()).hexdigest()[:8], name)

    # Replace name parts with short hash
    parts = re.split(r'([_\-\s])', name)
    new_parts = []
    for part in parts:
        if part in ('_', '-', ' '):
            new_parts.append(part)
        elif part.lower() in COMMON_INDIAN_NAMES and part.lower() not in GENERIC_NAME_TOKENS:
            h = hashlib.sha256(part.encode()).hexdigest()[:6]
            new_parts.append(h)
        else:
            new_parts.append(part)

    new_name = ''.join(new_parts) + ext
    if path.parent == Path('.') or str(path.parent) == '.':
        return new_name
    return str((path.parent / new_name).as_posix())


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------
def decode(raw: bytes) -> str | None:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="strict")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    # Check UTF-16 without BOM if null bytes present
    if b"\x00" in raw:
        nulls_even = sum(1 for i in range(0, min(len(raw), 100), 2) if raw[i] == 0)
        nulls_odd = sum(1 for i in range(1, min(len(raw), 100), 2) if raw[i] == 0)
        enc_order = ("utf-16-be", "utf-16-le") if nulls_even > nulls_odd else ("utf-16-le", "utf-16-be")
        for enc in enc_order:
            try:
                decoded = raw.decode(enc)
                if "\x00" not in decoded:
                    return decoded
            except UnicodeError:
                pass
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


# ---------------------------------------------------------------------------
# Date string shifting helper
# ---------------------------------------------------------------------------
_DATE_FMTS = [
    ('%d/%m/%Y', re.compile(r'^\d{1,2}/\d{1,2}/\d{4}$')),
    ('%d-%m-%Y', re.compile(r'^\d{1,2}-\d{1,2}-\d{4}$')),
    ('%d.%m.%Y', re.compile(r'^\d{1,2}\.\d{1,2}\.\d{4}$')),
    ('%Y-%m-%d', re.compile(r'^\d{4}-\d{1,2}-\d{1,2}$')),
    ('%Y/%m/%d', re.compile(r'^\d{4}/\d{1,2}/\d{1,2}$')),
    ('%Y.%m.%d', re.compile(r'^\d{4}\.\d{1,2}\.\d{1,2}$')),
    ('%d/%m/%y', re.compile(r'^\d{1,2}/\d{1,2}/\d{2}$')),
    ('%d-%m-%y', re.compile(r'^\d{1,2}-\d{1,2}-\d{2}$')),
    ('%d.%m.%y', re.compile(r'^\d{1,2}\.\d{1,2}\.\d{2}$')),
]

_MONTH_NAMES_EN = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
_MONTH_FULL_EN = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
_MONTH_HINDI = ['जनवरी', 'फ़रवरी', 'मार्च', 'अप्रैल', 'मई', 'जून', 'जुलाई', 'अगस्त', 'सितंबर', 'अक्टूबर', 'नवंबर', 'दिसंबर']

_MONTH_LOOKUP = {
    'jan': 1, 'january': 1, 'जनवरी': 1,
    'feb': 2, 'february': 2, 'फ़रवरी': 2, 'फरवरी': 2,
    'mar': 3, 'march': 3, 'मार्च': 3,
    'apr': 4, 'april': 4, 'अप्रैल': 4,
    'may': 5, 'मई': 5,
    'jun': 6, 'june': 6, 'जून': 6,
    'jul': 7, 'july': 7, 'जुलाई': 7,
    'aug': 8, 'august': 8, 'अगस्त': 8,
    'sep': 9, 'september': 9, 'sept': 9, 'सितंबर': 9, 'सितम्बर': 9,
    'oct': 10, 'october': 10, 'अक्टूबर': 10,
    'nov': 11, 'november': 11, 'नवंबर': 11, 'नवम्बर': 11,
    'dec': 12, 'december': 12, 'दिसंबर': 12, 'दिसम्बर': 12,
}

_ORDINAL_SUFFIXES = {1: 'st', 2: 'nd', 3: 'rd', 21: 'st', 22: 'nd', 23: 'rd', 31: 'st'}

def _get_ordinal(day: int) -> str:
    return _ORDINAL_SUFFIXES.get(day, 'th')

def _try_shift_date_str(value: str, offset_days: int) -> str | None:
    """Try to parse value as a date and return it shifted by offset_days. Returns None if not a date."""
    v = value.strip()
    if not v:
        return None

    v_norm = v.translate(INDIC_DIGITS)

    # 1. Standard numeric formats
    for fmt, pattern in _DATE_FMTS:
        if pattern.match(v_norm):
            try:
                d = dt.datetime.strptime(v_norm, fmt).date()
                shifted = d + dt.timedelta(days=offset_days)
                return shifted.strftime(fmt)
            except ValueError:
                continue

    # 2. Textual Day-Month-Year (e.g. 15 Jan 2024, 15-Jan-2024, 15th January 2024, 15 जनवरी 2024)
    m_dmy = re.match(
        r'^(\d{1,2})(?:st|nd|rd|th)?([ \-\.])([A-Za-z\u0900-\u097F]+)\2((?:19|20)\d{2}|\d{2})$',
        v_norm
    )
    if m_dmy:
        day = int(m_dmy.group(1))
        sep = m_dmy.group(2)
        month_token = m_dmy.group(3)
        month_num = _MONTH_LOOKUP.get(month_token.lower())
        year_token = m_dmy.group(4)
        year = int(year_token) if len(year_token) == 4 else (2000 + int(year_token) if int(year_token) < 50 else 1900 + int(year_token))
        if month_num:
            try:
                d = dt.date(year, month_num, day) + dt.timedelta(days=offset_days)
                if any('\u0900' <= c <= '\u097F' for c in month_token):
                    new_month = _MONTH_HINDI[d.month - 1]
                elif len(month_token) <= 4:
                    new_month = _MONTH_NAMES_EN[d.month - 1]
                    if month_token.isupper():
                        new_month = new_month.upper()
                    elif month_token.islower():
                        new_month = new_month.lower()
                else:
                    new_month = _MONTH_FULL_EN[d.month - 1]
                    if month_token.isupper():
                        new_month = new_month.upper()
                    elif month_token.islower():
                        new_month = new_month.lower()

                has_ordinal = any(s in v_norm.lower() for s in ('st', 'nd', 'rd', 'th'))
                if has_ordinal:
                    new_day_str = f"{d.day}{_get_ordinal(d.day)}"
                elif len(m_dmy.group(1)) == 2:
                    new_day_str = f"{d.day:02d}"
                else:
                    new_day_str = f"{d.day}"

                new_year_str = f"{d.year}" if len(year_token) == 4 else f"{d.year % 100:02d}"
                return f"{new_day_str}{sep}{new_month}{sep}{new_year_str}"
            except ValueError:
                pass

    # 3. Textual Month-Day-Year (e.g. Jan 15, 2024 or January 15 2024)
    m_mdy = re.match(
        r'^([A-Za-z\u0900-\u097F]+)[ \t]+(\d{1,2})(?:st|nd|rd|th)?(,?)[ \t]+((?:19|20)\d{2}|\d{2})$',
        v_norm
    )
    if m_mdy:
        month_token = m_mdy.group(1)
        day = int(m_mdy.group(2))
        comma = m_mdy.group(3)
        year_token = m_mdy.group(4)
        month_num = _MONTH_LOOKUP.get(month_token.lower())
        year = int(year_token) if len(year_token) == 4 else (2000 + int(year_token) if int(year_token) < 50 else 1900 + int(year_token))
        if month_num:
            try:
                d = dt.date(year, month_num, day) + dt.timedelta(days=offset_days)
                if any('\u0900' <= c <= '\u097F' for c in month_token):
                    new_month = _MONTH_HINDI[d.month - 1]
                elif len(month_token) <= 4:
                    new_month = _MONTH_NAMES_EN[d.month - 1]
                    if month_token.isupper():
                        new_month = new_month.upper()
                    elif month_token.islower():
                        new_month = new_month.lower()
                else:
                    new_month = _MONTH_FULL_EN[d.month - 1]
                    if month_token.isupper():
                        new_month = new_month.upper()
                    elif month_token.islower():
                        new_month = new_month.lower()

                has_ordinal = any(s in v_norm.lower() for s in ('st', 'nd', 'rd', 'th'))
                if has_ordinal:
                    new_day_str = f"{d.day}{_get_ordinal(d.day)}"
                elif len(m_mdy.group(2)) == 2:
                    new_day_str = f"{d.day:02d}"
                else:
                    new_day_str = f"{d.day}"

                new_year_str = f"{d.year}" if len(year_token) == 4 else f"{d.year % 100:02d}"
                return f"{new_month} {new_day_str}{comma} {new_year_str}"
            except ValueError:
                pass

    return None


def process_csv(text: str, delimiter: str, rel: str, records: list,
                linker: PatientCluster) -> str:
    rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))
    if not rows:
        return ""
    header, body = rows[0], rows[1:]
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=delimiter, lineterminator="\n")

    # Classify headers with semantic value typing fallback (Technique 6)
    header_types = []
    for j, h in enumerate(header):
        htype = classify_header(h)
        if htype is None and body:
            col_values = [r[j] for r in body if j < len(r)]
            htype = infer_column_type_from_values(col_values)
        header_types.append(htype)

    # Clean PII from header names (but keep structure)
    clean_header = []
    for h in header:
        clean_header.append(h)
    w.writerow(clean_header)

    for i, row in enumerate(body):
        record_id = f"{rel}:row:{i}"

        # Extract evidence for linkage
        ev = extract_evidence_csv(row, header, header_types)
        linker.add_evidence(record_id, ev)

        # Derive a per-row patient key for date shifting (may be refined after linkage)
        # Use the strongest available ID; fallback to record_id
        patient_key = (
            ev.get('uhid') or ev.get('aadhaar') or ev.get('abha') or
            ev.get('phone') or ev.get('email') or record_id
        )
        shift = date_shift_days(patient_key)

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
                    if cell and len(cell.strip()) >= 3:
                        record_removed_identifier(Detection(h_type, cell.strip()))
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
                # Non-PII column: check for dates and age to transform
                h_norm = normalize_text(h) if h else ''

                # Date columns: shift coherently
                if h and any(d in h_norm for d in ('date', 'admission', 'discharge', 'doj', 'dod', 'visit', 'तारीख', 'दिनांक')):
                    shifted = _try_shift_date_str(cell, shift)
                    if shifted:
                        clean_row.append(shifted)
                        continue

                # Age columns: replace with band
                if h and h_norm in {'age', 'umar', 'उम्र', 'आयु'}:
                    age_m = re.search(r'\d+', cell)
                    if age_m:
                        try:
                            band = age_band(int(age_m.group()))
                            clean_row.append(band)
                            Stats.generalized += 1
                            continue
                        except ValueError:
                            pass

                # Otherwise scan for embedded PII
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

    doc_shift = None
    if is_doc:
        record_id = f"{rel}:doc"
        # Extract evidence from the whole document
        if isinstance(data, dict):
            ev = extract_evidence_json(data)
            linker.add_evidence(record_id, ev)
            patient_key = (
                ev.get('uhid') or ev.get('aadhaar') or ev.get('abha') or
                ev.get('phone') or ev.get('email') or record_id
            )
            doc_shift = date_shift_days(patient_key)
        else:
            doc_shift = date_shift_days(record_id)
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

    # Clean the JSON data with coherent date shifting & age banding
    cleaned, dets = clean_value(data, shift=doc_shift)
    Stats.identifiers += len(dets)

    return json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n"


def process_text(text: str, rel: str, records: list,
                 linker: PatientCluster) -> str:
    record_id = f"{rel}:doc"
    ev = extract_evidence_text(text)
    linker.add_evidence(record_id, ev)
    records.append({"file": f"sanitized/{rel}", "loc": "doc", "patient": None})
    Stats.records += 1

    patient_key = (
        ev.get('uhid') or ev.get('aadhaar') or ev.get('abha') or
        ev.get('phone') or ev.get('email') or record_id
    )
    shift = date_shift_days(patient_key)

    # 1. Band age in free text: e.g. "Age: 45 yrs", "Age: 45", "Age-45", "उम्र: 45"
    def _replace_age(m):
        prefix = m.group(1)
        age_str = m.group(2)
        suffix = m.group(3) or ''
        try:
            val = int(age_str)
            Stats.generalized += 1
            return f"{prefix}{age_band(val)}{suffix}"
        except ValueError:
            return m.group(0)

    text = re.sub(
        r'(?i)\b((?:age|umar|उम्र|आयु)\s*[:=\-]?\s*)(\d{1,3})(\s*(?:yrs|years|yr|साल|वर्ष)?)',
        _replace_age,
        text
    )

    # 2. Coherent date shifting in text (preserves stay length intervals)
    def _shift_date_match(m):
        raw_date = m.group(0)
        shifted = _try_shift_date_str(raw_date, shift)
        return shifted if shifted else raw_date

    re_free_text_date = re.compile(
        r'\b(?:'
        r'\d{1,2}[/.\-]\d{1,2}[/.\-](?:19|20)?\d{2}|'
        r'(?:19|20)\d{2}[/.\-]\d{1,2}[/.\-]\d{1,2}|'
        r'\d{1,2}(?:st|nd|rd|th)?[\s\-]+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?|जनवरी|फ़रवरी|फरवरी|मार्च|अप्रैल|मई|जून|जुलाई|अगस्त|सितंबर|सितम्बर|अक्टूबर|नवंबर|नवम्बर|दिसंबर|दिसम्बर)[\s\-]+(?:19|20)?\d{2}|'
        r'(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?,?\s+(?:19|20)?\d{2}'
        r')\b',
        re.IGNORECASE
    )

    text = re_free_text_date.sub(_shift_date_match, text)

    # 3. Clean remaining PII from the text
    cleaned, dets = clean_text(text)
    Stats.identifiers += len(dets)

    return cleaned


def peak_rss_mb() -> float:
    try:
        import os

        import psutil
        p = psutil.Process(os.getpid())
        return round(p.memory_info().rss / 1_048_576, 1)
    except Exception:
        pass
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(r / 1024 if sys.platform != "darwin" else r / 1048576, 1)
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# Risk-Gated Privacy Planner (Technique 4)
# ---------------------------------------------------------------------------
class PrivacyPlanner:
    """Measures re-identification risk (k-anonymity) on release candidate
    and applies the escalation ladder to quasi-identifiers.
    """
    def __init__(self, min_k: int = 5):
        self.min_k = min_k

    def plan_and_generalize(self, san_dir: Path, final_records: list[dict], evidence_map: dict[str, dict]) -> None:
        """Measure quasi-identifier profile frequencies and apply ladder rules if group size < min_k."""
        if not POLICY.get("enable_privacy_planner", True):
            return
        qi_profiles: dict[tuple, list[dict]] = defaultdict(list)
        for r in final_records:
            file_rel = r["file"].replace("sanitized/", "", 1)
            loc = r["loc"]
            rec_id = f"{file_rel}:{loc}"
            ev = evidence_map.get(rec_id, {})
            age = ev.get('age')
            raw_age_band = age_band(int(age)) if age and str(age).isdigit() else '[AGE]'
            loc_qi = ev.get('village') or (str(ev.get('pin'))[:3] + '***' if ev.get('pin') else '[LOC]')
            qi_key = (raw_age_band, loc_qi)
            qi_profiles[qi_key].append(r)

        # Check k-anonymity and widen age bands per file in a single pass
        files_to_widen: set[str] = set()
        for qi_key, recs in qi_profiles.items():
            if len(recs) < self.min_k:
                for r in recs:
                    files_to_widen.add(r["file"].replace("sanitized/", "", 1))

        for file_rel in files_to_widen:
            file_path = san_dir / file_rel
            if not file_path.exists():
                continue
            try:
                content = file_path.read_text(encoding="utf-8")
                # Replace 5-year band like [40-44] with 10-year [40-49]
                def _widen(m):
                    lo = int(m.group(1))
                    lo_10 = (lo // 10) * 10
                    hi_10 = lo_10 + 9
                    Stats.generalized += 1
                    return f"[{lo_10}-{hi_10}]"

                new_content = re.sub(r'\[(\d{1,3})-(\d{1,3})\]', _widen, content)
                if new_content != content:
                    file_path.write_text(new_content, encoding="utf-8", newline="")
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Sweep Verifier (Technique 5)
# ---------------------------------------------------------------------------
def _quarantine_file(entry: dict, file_path: Path, reason: str, quarantined_set: set):
    try:
        if file_path.exists():
            file_path.unlink()
    except Exception:
        pass
    if entry.get("output"):
        quarantined_set.add(entry["output"])
    entry["output"] = None
    entry["status"] = "quarantined"
    entry["reason"] = reason


def run_sweep_verifier(san_dir: Path, files_report: list[dict], records: list[dict]) -> None:
    """Sweep verifier: check all sanitized outputs for leaks before release."""
    if not POLICY.get("enable_sweep_verifier", True):
        return
    secret_str = SECRET.decode('utf-8', errors='ignore') if SECRET else ""
    safe_veto = (
        MEDICAL_TERMS | DISEASE_EPONYMS | DRUG_NAMES | GENERIC_NAME_TOKENS |
        COMMON_INDIAN_NAMES | HOSPITAL_NAMES | DOCTOR_NAMES |
        {'[patient_name]', '[relative_name]', '[phone]', '[aadhaar]', '[mrn]', '[email]',
         '[village]', '[pin]', '[pan]', '[abha]', '[dob]', '[address]', '[house]',
         '[locality]', '[landmark]', '[insurance_id]', '[redacted]'}
    )
    hosp_words = {'hospital', 'clinic', 'charitable', 'sadan', 'dispensary', 'pathology', 'district', 'multispeciality', 'seva', 'ward'}

    probe_values = set()
    for v in REMOVED_DIRECT_IDENTIFIERS:
        v_low = v.lower().strip()
        if len(v_low) < 4 or v_low in safe_veto or any(hw in v_low for hw in hosp_words):
            continue
        if v_low in DOCTOR_NAMES or any(v_low.startswith(pfx) for pfx in ('dr.', 'dr ', 'doctor ', 'consultant', 'सर्जन', 'डॉ.', 'चिकित्सक')):
            continue
        # Only probe for direct identifiers with digits (phone, aadhaar, mrn), full multi-word names, or canaries
        if any(c.isdigit() for c in v_low) or len(v_low.split()) >= 2 or 'canary' in v_low:
            probe_values.add(v_low)
            # Technique 5: wider variant set (reverse name order, Devanagari transliteration, Indic digits)
            parts = v_low.split()
            if len(parts) == 2:
                probe_values.add(f"{parts[1]} {parts[0]}")
            if any('\u0900' <= c <= '\u097F' for c in v_low):
                lat = rough_transliterate(v_low)
                if lat and lat not in safe_veto and len(lat) >= 4:
                    probe_values.add(lat)
            if any(c.isdigit() for c in v_low):
                indic_v = v_low.translate(str.maketrans('0123456789', '०१२३४५६७८९'))
                probe_values.add(indic_v)

    re_canary = re.compile(r'(?i)\b(?:[a-z0-9_-]*canary[a-z0-9_-]*)\b')
    re_aadhaar_raw = re.compile(r'(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)')
    re_phone_raw = re.compile(r'(?<!\d)(?:\+?91[\s\-]?)?[6-9]\d{9}(?!\d)')

    quarantined_outputs: set[str] = set()

    for entry in files_report:
        if entry.get("status") != "sanitized" or not entry.get("output"):
            continue
        rel = entry["output"].replace("sanitized/", "", 1)
        target_file = san_dir / rel
        if not target_file.exists():
            continue

        filename_lower = target_file.name.lower()
        if secret_str and len(secret_str) >= 4 and secret_str in filename_lower:
            _quarantine_file(entry, target_file, "secret_leaked_in_filename", quarantined_outputs)
            continue
        if re_canary.search(filename_lower):
            _quarantine_file(entry, target_file, "canary_in_filename", quarantined_outputs)
            continue

        try:
            content = target_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            _quarantine_file(entry, target_file, "unreadable_sanitized_file", quarantined_outputs)
            continue

        if secret_str and len(secret_str) >= 4 and secret_str in content:
            _quarantine_file(entry, target_file, "secret_leaked_in_content", quarantined_outputs)
            continue

        if re_canary.search(content):
            _quarantine_file(entry, target_file, "canary_leak_detected", quarantined_outputs)
            continue

        # Check raw numbers
        content_lines = content.splitlines()
        leak_found = False
        for line in content_lines:
            for m in re_phone_raw.finditer(line):
                if not is_dose_context(line, m.start(), m.end()):
                    leak_found = True
                    break
            if leak_found:
                break

            for m in re_aadhaar_raw.finditer(line):
                val = re.sub(r'\D', '', m.group(0))
                if val in probe_values:
                    leak_found = True
                    break
            if leak_found:
                break

        if leak_found:
            _quarantine_file(entry, target_file, "identifier_leak_detected", quarantined_outputs)
            continue

        # Check probe values (names, sensitive tokens)
        content_norm = normalize_text(content)
        for pv in probe_values:
            if pv.isascii() and pv.isalpha():
                if re.search(rf'\b{re.escape(pv)}\b', content_norm):
                    leak_found = True
                    break
            elif pv in content_norm:
                leak_found = True
                break

        if leak_found:
            _quarantine_file(entry, target_file, "sweep_verifier_leak_detected", quarantined_outputs)

    if quarantined_outputs:
        records[:] = [r for r in records if r["file"] not in quarantined_outputs]


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

    # Phase 4: Insert pseudonyms into sanitized records (batched per file to eliminate redundant disk I/O)
    records_by_file: dict[str, list[dict]] = defaultdict(list)
    for r in final_records:
        if r.get("patient"):
            records_by_file[r["file"]].append(r)

    for file_rel, file_recs in records_by_file.items():
        file_path = out / file_rel
        if not file_path.exists():
            continue
        try:
            content = file_path.read_text(encoding="utf-8")
            ext = file_path.suffix.lower()

            if ext in ('.csv', '.tsv'):
                lines = content.split('\n')
                for r in file_recs:
                    loc = r["loc"]
                    if loc.startswith("row:"):
                        try:
                            row_idx = int(loc.split(":")[1])
                            line_idx = row_idx + 1  # 0-based data row after header
                            if line_idx < len(lines) and lines[line_idx]:
                                lines[line_idx] = lines[line_idx].replace('[MRN]', r["patient"], 1)
                                if r["patient"] not in lines[line_idx]:
                                    lines[line_idx] = lines[line_idx].replace('[PATIENT_NAME]', r["patient"], 1)
                        except (ValueError, IndexError):
                            pass
                content = '\n'.join(lines)

            elif ext == '.json':
                try:
                    data = json.loads(content)
                    for r in file_recs:
                        if r["loc"] == "doc":
                            if isinstance(data, dict):
                                if data.get("resourceType") == "Bundle":
                                    for entry in data.get("entry", []):
                                        res = entry.get("resource", {})
                                        if isinstance(res, dict):
                                            if res.get("resourceType") == "Patient":
                                                res["id"] = r["patient"]
                                            elif "subject" in res and isinstance(res["subject"], dict):
                                                res["subject"]["reference"] = f"Patient/{r['patient']}"
                                else:
                                    data["patient_ref"] = r["patient"]
                        else:
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
                for r in file_recs:
                    if r["patient"] not in content:
                        content = f"Patient: {r['patient']}\n{content}"

            file_path.write_text(content, encoding="utf-8", newline="")
        except (OSError, UnicodeError):
            pass

    # Phase 4b: Risk-Gated Privacy Planner (Technique 4)
    planner = PrivacyPlanner(min_k=int(POLICY.get("min_group_size", 5)))
    planner.plan_and_generalize(san, final_records, linker.evidence)

    # Phase 5: Sweep Verifier (Technique 5)
    run_sweep_verifier(san, files_report, final_records)

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

