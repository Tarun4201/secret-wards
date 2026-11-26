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
import difflib
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
    'ऋ': 'ri', 'ए': 'e', 'ऐ': 'ai', 'ओ': 'o', 'औ': 'au', 'अं': 'an', 'अः': 'ah',
    'ऑ': 'o', 'ऍ': 'e',
    'क': 'k', 'ख': 'kh', 'ग': 'g', 'घ': 'gh', 'ङ': 'ng',
    'च': 'ch', 'छ': 'chh', 'ज': 'j', 'झ': 'jh', 'ञ': 'ny',
    'ट': 't', 'ठ': 'th', 'ड': 'd', 'ढ': 'dh', 'ण': 'n',
    'त': 't', 'थ': 'th', 'द': 'd', 'ध': 'dh', 'न': 'n',
    'प': 'p', 'फ': 'ph', 'ब': 'b', 'भ': 'bh', 'म': 'm',
    'य': 'y', 'र': 'r', 'ल': 'l', 'व': 'v', 'w': 'w',
    'श': 'sh', 'ष': 'sh', 'स': 's', 'ह': 'h',
    'क़': 'q', 'ख़': 'kh', 'ग़': 'gh', 'ज़': 'z', 'फ़': 'f', 'ड़': 'r', 'ढ़': 'rh',
    'ा': 'a', 'ि': 'i', 'ी': 'ee', 'ु': 'u', 'ू': 'oo', 'ृ': 'ri', 'ॄ': 'ri',
    'े': 'e', 'ै': 'ai', 'ो': 'o', 'ौ': 'au', 'ॉ': 'o', 'ॅ': 'e',
    'ं': 'n', 'ँ': 'n', 'ः': 'h', '्': '', 'ऽ': '',
}

_DEVA_CONSONANTS = {
    'क': 'k', 'ख': 'kh', 'ग': 'g', 'घ': 'gh', 'ङ': 'ng',
    'च': 'ch', 'छ': 'chh', 'ज': 'j', 'झ': 'jh', 'ञ': 'ny',
    'ट': 't', 'ठ': 'th', 'ड': 'd', 'ढ': 'dh', 'ण': 'n',
    'त': 't', 'थ': 'th', 'द': 'd', 'ध': 'dh', 'न': 'n',
    'प': 'p', 'फ': 'ph', 'ब': 'b', 'भ': 'bh', 'म': 'm',
    'य': 'y', 'र': 'r', 'ल': 'l', 'व': 'v',
    'श': 'sh', 'ष': 'sh', 'स': 's', 'ह': 'h',
    'क़': 'q', 'ख़': 'kh', 'ग़': 'gh', 'ज़': 'z', 'फ़': 'f', 'ड़': 'r', 'ढ़': 'rh',
    'क\u093c': 'q', 'ख\u093c': 'kh', 'ग\u093c': 'gh', 'ज\u093c': 'z',
    'फ\u093c': 'f', 'ड\u093c': 'r', 'ढ\u093c': 'rh',
}
_DEVA_MATRAS = {
    'ा': 'a', 'ि': 'i', 'ी': 'ee', 'ु': 'u', 'ू': 'oo', 'ृ': 'ri', 'ॄ': 'ri',
    'े': 'e', 'ै': 'ai', 'ो': 'o', 'ौ': 'au', 'ॉ': 'o', 'ॅ': 'e',
}

INDIC_DIGITS = str.maketrans('०१२३४५६७८९', '0123456789')

def normalize_text(s: str) -> str:
    """NFKC + casefold + Indic digit normalization."""
    s = unicodedata.normalize("NFKC", s)
    s = s.translate(INDIC_DIGITS)
    return s.casefold()

def _is_deva_letter(ch: str) -> bool:
    return '\u0900' <= ch <= '\u097F'

def rough_transliterate(text: str) -> str:
    """Schwa-aware approximate Devanagari -> Latin transliteration."""
    result = []
    i = 0
    chars = list(text)
    n = len(chars)
    while i < n:
        # Handle common 3-char conjuncts: क्ष, त्र, ज्ञ, श्र
        if i + 2 < n and chars[i + 1] == '\u094d':
            tri = chars[i] + chars[i + 1] + chars[i + 2]
            conj_map = {'क्ष': 'ksh', 'त्र': 'tr', 'ज्ञ': 'gy', 'श्र': 'shr'}
            if tri in conj_map:
                result.append(conj_map[tri])
                i += 3
                # Check if matra/halant follows conjunct
                if i < n and chars[i] in _DEVA_MATRAS:
                    result.append(_DEVA_MATRAS[chars[i]])
                    i += 1
                elif i < n and chars[i] == '\u094d':
                    i += 1
                elif i < n and _is_deva_letter(chars[i]) and chars[i] not in ('ं', 'ँ', 'ः'):
                    result.append('a')
                continue

        # Check consonant (possibly with nukta \u093c)
        c_key = None
        step = 1
        if i + 1 < n and chars[i + 1] == '\u093c' and (chars[i] + '\u093c') in _DEVA_CONSONANTS:
            c_key = chars[i] + '\u093c'
            step = 2
        elif chars[i] in _DEVA_CONSONANTS:
            c_key = chars[i]
            step = 1

        if c_key is not None:
            result.append(_DEVA_CONSONANTS[c_key])
            nxt_idx = i + step
            if nxt_idx < n and chars[nxt_idx] == '\u094d':
                # Virama suppresses inherent 'a'
                i = nxt_idx + 1
            elif nxt_idx < n and chars[nxt_idx] in _DEVA_MATRAS:
                result.append(_DEVA_MATRAS[chars[nxt_idx]])
                i = nxt_idx + 1
            else:
                # Inherent 'a' unless bare consonant at word-final position
                at_word_end = (nxt_idx >= n) or (not _is_deva_letter(chars[nxt_idx]))
                followed_by_mark_end = (
                    nxt_idx < n and chars[nxt_idx] in ('ं', 'ँ', 'ः')
                    and (nxt_idx + 1 >= n or not _is_deva_letter(chars[nxt_idx + 1]))
                )
                prev_was_reph = (i >= 2 and chars[i - 1] == '\u094d' and chars[i - 2] == 'र')
                prev_was_halant = (i > 0 and chars[i - 1] == '\u094d' and not prev_was_reph)
                if not at_word_end and not followed_by_mark_end:
                    result.append('a')
                elif prev_was_halant:
                    result.append('a')
                i = nxt_idx
            continue

        # Try remaining 2-char combos or single char from DEVA_TO_LATIN
        if i + 1 < n and (chars[i] + chars[i + 1]) in DEVA_TO_LATIN:
            result.append(DEVA_TO_LATIN[chars[i] + chars[i + 1]])
            i += 2
            continue
        c = chars[i]
        if c in DEVA_TO_LATIN:
            result.append(DEVA_TO_LATIN[c])
        elif c != '\u093c':
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
    # Remove punctuation before word-level normalization
    n = re.sub(r'[.\-,\'\"()\[\]{}]', ' ', n)
    n = ' '.join(n.split())
    # Expand abbreviations and variants
    n = re.sub(r'\b(?:mohammad|mohammed|muhammad|muhammed|mohd|md|mohmmd)\b', 'mohammad', n)
    for h in ['smt', 'shri', 'sri', 'श्री', 'श्रीमती',
              'ji', 'sahab', 'saheb', 'didi', 'bhai', 'babu', 'amma', 'ammi',
              'bhabhi', 'chacha', 'chachu', 'mama', 'mamaji', 'mausi', 'nana',
              'nani', 'dada', 'dadi', 'behenji', 'behen', 'bhaiya', 'bhaiyya',
              'beta', 'beti', 'bibi', 'begum', 'papa']:
        n = re.sub(rf'\b{re.escape(h)}\b', '', n)
    # Phonetic and cross-script normalizations
    n = re.sub(r'qu(?=[ie])', 'k', n)
    n = n.replace('q', 'k')
    n = n.replace('ph', 'f')
    n = n.replace('w', 'v')
    n = n.replace('ou', 'au')
    n = n.replace('aa', 'a')
    n = n.replace('ee', 'i')
    n = n.replace('oo', 'u')
    n = n.replace('ei', 'i')
    n = re.sub(r'(?:ey|eya)\b', 'e', n)
    n = re.sub(r'([a-z]{3,})y\b', r'\1i', n)
    # Collapse double consonants
    n = re.sub(r'([b-df-hj-np-tv-z])\1+', r'\1', n)
    n = ' '.join(n.split())
    return n.strip()

def _schwa_key(tok: str) -> str:
    """Strip medial 'a' schwa vowels while preserving initial and final chars."""
    if len(tok) <= 3:
        return tok
    return tok[0] + tok[1:-1].replace('a', '') + tok[-1]

def _consonant_key(tok: str) -> str:
    """Consonant skeleton normalizing dental th/dh and sibilant sh/s for Indic spelling variation."""
    t = tok.replace('sh', 's').replace('th', 't').replace('dh', 'd')
    return re.sub(r'[aeiou]', '', t)

def _tokens_match(a: str, b: str) -> bool:
    """Match two phonetic skeleton tokens across transliteration and schwa variants."""
    if not a or not b:
        return False
    if a == b:
        return True
    if len(a) < 4 or len(b) < 4:
        return False
    if a[0] != b[0]:
        return False
    if (a[-1] in 'aeiou') != (b[-1] in 'aeiou'):
        return False
    if _schwa_key(a) == _schwa_key(b):
        return True
    if _consonant_key(a) == _consonant_key(b):
        return difflib.SequenceMatcher(None, a, b).ratio() >= 0.80
    return False

def _match_name_pair(name1: str, name2: str) -> str:
    """Compare two names across scripts, word orders, and phonetic variants.
    Returns: 'full', 'first', 'partial', or 'none'.
    """
    sk1 = name_skeleton(name1)
    sk2 = name_skeleton(name2)
    if not sk1 or not sk2:
        return 'none'
    toks1 = [t for t in sk1.split() if len(t) >= 2]
    toks2 = [t for t in sk2.split() if len(t) >= 2]
    if not toks1 or not toks2:
        return 'none'
    # Never let a standalone generic token (e.g. "Devi") match anything
    if len(toks1) == 1 and toks1[0] in GENERIC_NAME_TOKENS:
        return 'none'
    if len(toks2) == 1 and toks2[0] in GENERIC_NAME_TOKENS:
        return 'none'

    # Order-independent bipartite greedy matching using phonetic equivalence
    shorter, longer = (toks1, toks2) if len(toks1) <= len(toks2) else (toks2, toks1)
    used = set()
    matched_tokens = []
    for t in shorter:
        # Prefer exact match first, then phonetic match
        idx = next((j for j, u in enumerate(longer) if j not in used and u == t), None)
        if idx is None:
            idx = next((j for j, u in enumerate(longer) if j not in used and _tokens_match(t, u)), None)
        if idx is not None:
            used.add(idx)
            matched_tokens.append(t)

    non_gen_matches = [t for t in matched_tokens if t not in GENERIC_NAME_TOKENS and len(t) >= 3]
    if not non_gen_matches:
        return 'none'

    if len(matched_tokens) == len(shorter) and len(matched_tokens) == len(longer):
        if len(shorter) >= 2 or (len(shorter) == 1 and len(shorter[0]) >= 4):
            return 'full'
    if len(matched_tokens) == len(shorter) and len(shorter) == 1 and len(longer) >= 2:
        # Check if the single non-generic token matches the first (given) name of longer
        if _tokens_match(shorter[0], longer[0]):
            return 'first'
        return 'partial'
    if len(matched_tokens) == len(shorter) and len(shorter) >= 2:
        return 'partial'
    return 'none'

def _location_match(loc1: str, loc2: str) -> bool:
    """Cross-script village/location match."""
    return _match_name_pair(loc1, loc2) == 'full'

def _normalize_gender(val: str) -> str:
    """Normalize English/Hindi gender strings to 'M', 'F', or ''."""
    if not val:
        return ''
    v = normalize_text(str(val)).strip()
    if v in ('m', 'male', 'man', 'boy', 'पुरुष', 'purush', 'लड़का') or v.startswith(('male', 'पुरुष')):
        return 'M'
    if v in ('f', 'female', 'woman', 'girl', 'महिला', 'स्त्री', 'mahila', 'लड़की') or v.startswith(('female', 'महिल')):
        return 'F'
    if v and v[0] in ('m', 'f'):
        return v[0].upper()
    return ''

def _normalize_age(val: Any) -> int | None:
    """Extract numeric age from strings like '47 वर्ष' or '51'."""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        a = int(val)
        return a if 0 <= a <= 125 else None
    s = normalize_text(str(val))
    m = re.search(r'\b(\d{1,3})\b', s)
    if not m:
        return None
    a = int(m.group(1))
    return a if 0 <= a <= 125 else None

def _parse_dob(val: str) -> tuple[int, frozenset[tuple[int, int]]] | None:
    """Parse DOB into (year, {(month, day), ...}) tolerating DMY/MDY ambiguity."""
    if not val:
        return None
    s = normalize_text(str(val)).strip()
    m = re.match(r'^(\d{4})[/\-.](\d{1,2})[/\-.](\d{1,2})$', s)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if 1900 <= y <= 2030 and 1 <= mo <= 12 and 1 <= d <= 31:
            return (y, frozenset({(mo, d)}))
        return None
    m = re.match(r'^(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})$', s)
    if m:
        p1, p2, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if not (1900 <= y <= 2030):
            return None
        opts = set()
        if 1 <= p2 <= 12 and 1 <= p1 <= 31:
            opts.add((p2, p1))  # DD/MM/YYYY
        if 1 <= p1 <= 12 and 1 <= p2 <= 31:
            opts.add((p1, p2))  # MM/DD/YYYY
        if opts:
            return (y, frozenset(opts))
    return None

def _dobs_compatible(dob1: str, dob2: str) -> bool | None:
    """Return True if parsed DOBs match, False if they conflict, None if inconclusive."""
    p1 = _parse_dob(dob1)
    p2 = _parse_dob(dob2)
    if not p1 or not p2:
        return None
    if p1[0] != p2[0]:
        return False
    return bool(p1[1] & p2[1])

def _mrn_kind_ns(val: str) -> tuple[str, str]:
    """Classify an MRN into (kind, namespace).
    kind: 'encounter' (IPD/ADM) or 'uhid' (patient UHID).
    """
    v = re.sub(r'\s+', '', str(val)).upper()
    if re.match(r'^(?:DHH[/-]?IPD|IPD|IP|ADM)[/\-\d]', v):
        return ('encounter', re.match(r'^([A-Z]+)', v).group(1))
    m = re.match(r'^([A-Z]+)', v)
    ns = m.group(1) if m else ''
    return ('uhid', ns)

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
    'first', 'last', 'local', 'local name', 'local_name', 'fname', 'lname',
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
    'resident', 'residence', 'line', 'address line', 'address_line', 'addr_line', 'street',
    'पता', 'पूरा पता', 'निवास',
}
VILLAGE_HEADERS = {
    'village', 'village/mohalla', 'village mohalla', 'village_mohalla', 'gaon', 'gram', 'mohalla', 'tola', 'basti',
    'city', 'shahar', 'गाँव', 'ग्राम', 'मोहल्ला', 'टोला', 'बस्ती', 'शहर',
}
DOB_HEADERS = {
    'dob', 'date of birth', 'date_of_birth', 'dateofbirth', 'birth date',
    'birth_date', 'birthdate', 'janm tithi', 'janm_tithi', 'जन्म तिथि',
    'dob mm dd yyyy', 'dob dd mm yyyy', 'dob yyyy mm dd',
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
    'claim', 'claim no', 'claim_no', 'pmjay', 'pmjay id', 'pmjay_id', 'pmjay no', 'pmjay_no',
    'बीमा', 'पॉलिसी',
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

    # 2. PII exact match: DOB before generic date exclusion; check RELATIVE_HEADERS before NAME_HEADERS
    if any(pfx in h for pfx in ('dob', 'date of birth', 'birth date', 'janm tithi', 'जन्म तिथि')):
        return 'DOB'
    # Clinical/event dates (e.g. Registration Date, collected_on, reported_on, registered_on) are NOT MRN or RELATIVE_NAME
    if any(w in h.split() for w in ('date', 'tithi', 'tarikh', 'तारीख', 'दिनांक', 'registered', 'collected', 'reported')) or h.endswith(' on'):
        return None
    if 'pmjay' in h:
        return 'INSURANCE_ID'
    if h in RELATIVE_HEADERS:
        return 'RELATIVE_NAME'
    for header_set, pii_type in PII_HEADER_MAP.items():
        if h in header_set:
            return pii_type

    # 3. Safe-type fuzzy match (e.g. "treating doctor", "consultant physician")
    for header_set in SAFE_HEADER_TYPES:
        for known in header_set:
            if len(known) >= 3 and re.search(rf'(?:^| ){re.escape(known)}(?: |$)', h):
                return None

    # 4. Fuzzy: check RELATIVE_HEADERS before NAME_HEADERS, using word boundaries for short keys
    for known in RELATIVE_HEADERS:
        if re.search(rf'(?:^| ){re.escape(known)}(?: |$)', h) or (len(known) >= 6 and ' ' not in known and known in h):
            return 'RELATIVE_NAME'

    for header_set, pii_type in PII_HEADER_MAP.items():
        for known in header_set:
            if re.search(rf'(?:^| ){re.escape(known)}(?: |$)', h) or (len(known) >= 5 and ' ' not in known and known in h):
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
RE_PHONE_INDIC = re.compile(
    r'(?<![०-९])(?:\+?९१[\s\-]?)?(?:०[\s\-]?)?([६-९][०-९]{4}[\s\-]?[०-९]{5})(?![०-९])'
)

# Aadhaar: 12 digits (possibly with spaces/hyphens), not starting with 0 or 1
RE_AADHAAR = re.compile(
    r'(?<!\d)([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})(?!\d)'
)
RE_AADHAAR_INDIC = re.compile(
    r'(?<![०-९])([२-९][०-९]{3}[\s\-]?[०-९]{4}[\s\-]?[०-९]{4})(?![०-९])'
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
    r'\b(?:SNJ[/-]\d{2}[/-]\d+|JJH[/-]\d+|UHID[/-]\d+|ADM\d+|DHH\d{4}-\d+|DHH[/-]IPD[/-][\d-]+|DHH[/-][\d-]+|'
    r'IP[/-]\d{2}[/-]\d+|IPD[/-]\d{4}[/-]\d+|OPD/\d{2}/\d{2}/\d+|'
    r'INS[/-]\d+|CLM[/-]\d+)\b'
)

# Labelled UHID/MRN in free text: "UHID: DHH-IPD-2024-001"
RE_MRN_LABELLED = re.compile(
    r'(?i)(?:uhid|mrn|patient\s*id|reg(?:istration)?\s*no?|ipd\s*no?|opd\s*no?|case\s*no?|hospital\s*id|'
    r'पंजीकरण\s*(?:सं\.?|संख्या)?|आईपीडी\s*(?:सं\.?|संख्या)?|ओपीडी\s*(?:सं\.?|संख्या)?)\s*:?\s*([\w/\-]+)'
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
RE_PIN_INDIC = re.compile(r'(?<![०-९])([१-९][०-९]{5})(?![०-९])')

# Insurance ID pattern
RE_INSURANCE = re.compile(r'\b(INS[/-]\d+|CLM[/-]\d+|PMJAY[/-][A-Z0-9/-]+|POL[/-]\d+[/-]\d+)\b', re.IGNORECASE)

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
    'hareesh', 'harish', 'harpreet', 'jagdish', 'prakash', 'baban',
    # Female first names
    'sunita', 'anita', 'kavita', 'savita', 'mamta', 'neeta', 'reeta',
    'geeta', 'seema', 'meena', 'neha', 'pooja', 'priya', 'rekha', 'usha',
    'kamla', 'kamala', 'shanti', 'shanthi', 'parvati', 'parvathi', 'lakshmi', 'saraswati',
    'fatima', 'fatma', 'farida', 'shabana', 'salma', 'zainab', 'zenab', 'amina',
    'reena', 'meera', 'asha', 'sarita', 'pushpa', 'swati', 'poonam', 'ayesha', 'saroj', 'rukhsana',
    # Surnames
    'kumar', 'sharma', 'verma', 'gupta', 'singh', 'chauhan', 'chaudhary',
    'yadav', 'pandey', 'pandeya', 'tiwari', 'mishra', 'thakur', 'lodhi',
    'paswan', 'nishad', 'ansari', 'qureshi', 'siddiqui', 'baig', 'bano',
    'kaur', 'devi', 'rajput', 'khatoon', 'khatun', 'malik', 'khan',
    # Pan-Indian regional surnames and first names
    'patil', 'deshmukh', 'kulkarni', 'joshi', 'shinde', 'gaikwad', 'jadhav',
    'chavan', 'patel', 'shah', 'mehta', 'desai', 'modi', 'bhatt', 'parikh',
    'trivedi', 'pandya', 'iyer', 'iyengar', 'nair', 'menon', 'pillai',
    'reddy', 'rao', 'naidu', 'choudhury', 'chatterjee', 'mukherjee',
    'banerjee', 'bhattacharya', 'ghosh', 'bose', 'dutta', 'dasgupta', 'sen', 'roy',
    'venkatesh', 'subramanian', 'krishnamurthy', 'ramanathan', 'karthik',
    'srinivasan', 'raghavan', 'anand', 'vishnu', 'balaji', 'sourav', 'subhash',
    'brajesh', 'sukhvinder', 'irfan',
    # Devanagari names
    'कमला', 'किशन', 'रमेश', 'सुरेश', 'मोहन', 'सुनीता', 'गीता', 'मीरा',
    'रीना', 'पार्वती', 'फ़ातिमा', 'शबाना', 'सलमा', 'ज़ैनब', 'उषा',
    'शांति', 'कविता', 'नेहा', 'पूजा', 'रेखा', 'लक्ष्मी', 'सरस्वती',
    'निषाद', 'चौहान', 'चौधरी', 'यादव', 'पाण्डेय', 'तिवारी', 'मिश्रा',
    'ठाकुर', 'लोधी', 'पासवान', 'अंसारी', 'क़ुरैशी', 'सिद्दीक़ी',
    'शाहिद', 'मोहम्मद', 'अहमद', 'ज़ुबैर', 'आरिफ़', 'नसीम', 'यूसुफ़',
    'जावेद', 'अकरम', 'कौर', 'सिंह', 'कुमार', 'शर्मा', 'वर्मा', 'गुप्ता',
    'बानो', 'बैग', 'पटेल', 'शाह', 'जोशी', 'पाटिल', 'देशमुख', 'कुलकर्णी', 'रेड्डी', 'राव', 'घोष',
    'आशा', 'राजपूत', 'खातून', 'मलिक', 'खान', 'सरिता', 'पुष्पा', 'हरीश',
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
    # Also catch labelled patterns: "Phone: 9988776655", "Mob: ...", "मोबाइल: ७८८८०२३९२३"
    for m in re.finditer(r'(?i)(?:phone|mob(?:ile)?|contact|tel(?:ephone)?|whatsapp)\s*(?:no\.?|number|#)?\s*:?\s*(\+?91[\s\-]?)?([6-9]\d{4}[\s\-]?\d{5})', text):
        raw = m.group(0)
        if not is_dose_context(text, m.start(), m.end()):
            detections.append(Detection('PHONE', raw, (m.start(), m.end()), channel=channel))
    for m in re.finditer(r'(?i)(?:मोबाइल|फ़ोन|फोन)\s*(?:सं\.?|नंबर)?\s*:?\s*([०-९\s\-]{10,12})', text):
        raw = m.group(1).strip()
        indic_digits = re.sub(r'[^०-९]', '', raw)
        if len(indic_digits) >= 10:
            detections.append(Detection('PHONE', raw, (m.start(1), m.end(1)), channel=channel))
    for m in RE_PHONE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r'\D', '', raw)
        if len(digits) >= 10 and not is_dose_context(text, m.start(), m.end()):
            detections.append(Detection('PHONE', raw, (m.start(), m.end()), channel=channel))
    for m in RE_PHONE_INDIC.finditer(text):
        detections.append(Detection('PHONE', m.group(0), (m.start(), m.end()), channel=channel))

    # 2. Aadhaar (12 digits, not in dose context)
    for m in RE_AADHAAR.finditer(text):
        raw = m.group(0)
        digits = re.sub(r'\D', '', raw)
        if len(digits) == 12 and not is_dose_context(text, m.start(), m.end()):
            # Check it's not an ABHA number
            if not RE_ABHA.match(text[max(0,m.start()-3):m.end()+3]):
                detections.append(Detection('AADHAAR', raw, (m.start(), m.end()), channel=channel))
    for m in RE_AADHAAR_INDIC.finditer(text):
        detections.append(Detection('AADHAAR', m.group(0), (m.start(), m.end()), channel=channel))

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
        detections.append(Detection('INSURANCE_ID', m.group(0), (m.start(), m.end()), channel=channel))

    # 9. House numbers
    for m in RE_HOUSE.finditer(text):
        detections.append(Detection('HOUSE', m.group(0), (m.start(), m.end()), channel=channel))

    # 9b. Village / locality patterns in free text
    for m in re.finditer(r'(?i)\b(?:village|vill\.?|gaon|gram|गाँव|ग्राम)\s*:?\s*([A-Za-z\u0900-\u097F][^\n,;|]+)', text):
        v_name = m.group(1).strip()
        if v_name and len(v_name) > 1:
            detections.append(Detection('VILLAGE', v_name, (m.start(1), m.start(1) + len(v_name)), channel=channel))

    for m in RE_PIN_INDIC.finditer(text):
        detections.append(Detection('PIN', m.group(0), (m.start(), m.end()), channel=channel))

    # 10. Names - detect using anchored patterns and gazetteer
    # Patient Name: label (handle "Patient Name: Priya Sharma", "Patient: Priya Sharma", "Naam: ...")
    for m in re.finditer(r'(?i)(?:patient\s+name|patient\s*:|rogi\s*(?:ka\s*)?naam|naam\s*:|नाम\s*:|रोगी\s*का\s*नाम|मरीज़?\s*(?:का\s*)?नाम)\s*:?\s*([^\n,;|]+)', text):
        raw_val = m.group(1)
        split_m = re.split(r'(?i)\s{2,}|\t|\b(?:age|sex|dob|uhid|mrn|ipd|opd|ward|bed|umar)\b', raw_val)
        name = split_m[0].strip()
        if name and len(name) > 1 and not re.match(r'^(?:presents|admitted|complaining|reported|referred|diagnosed|is|was)\b', name, re.IGNORECASE):
            if not any(re.search(rf'\b{re.escape(d)}\b', name, re.IGNORECASE) for d in DRUG_NAMES if len(d) >= 4):
                end_pos = m.start(1) + len(split_m[0])
                detections.append(Detection('PATIENT_NAME', name, (m.start(1), end_pos), channel=channel, role='patient'))

    # Also catch bare "Name: Priya Sharma" patterns
    for m in re.finditer(r'(?i)^(?:name|full\s*name)\s*:\s*([^\n,;|]+)', text, re.MULTILINE):
        raw_val = m.group(1)
        split_m = re.split(r'(?i)\s{2,}|\t|\b(?:age|sex|dob|uhid|mrn|ipd|opd|ward|bed|umar)\b', raw_val)
        name = split_m[0].strip()
        if name and len(name) > 1 and not any(re.search(rf'\b{re.escape(d)}\b', name, re.IGNORECASE) for d in DRUG_NAMES if len(d) >= 4):
            if not any(d.type == 'PATIENT_NAME' and d.surface == name for d in detections):
                end_pos = m.start(1) + len(split_m[0])
                detections.append(Detection('PATIENT_NAME', name, (m.start(1), end_pos), channel=channel, role='patient'))

    # Patient before relation cue: "Asha, W/o Kamal" or "Zainab, W/o Salim"
    for m in re.finditer(r'(?i)\b([A-Z\u0900-\u097F][a-z\u0900-\u097F]+(?:\s+[A-Z\u0900-\u097F][a-z\u0900-\u097F]+)?)\s*,\s*(?:[sSwWdD]/[oO]|son\s+of|wife\s+of|daughter\s+of)', text):
        pname = m.group(1).strip()
        pnorm = normalize_text(pname)
        if pnorm not in DOCTOR_NAMES and pnorm not in MEDICAL_TERMS:
            detections.append(Detection('PATIENT_NAME', pname, (m.start(1), m.end(1)), channel=channel, role='patient'))

    # WhatsApp sender: [11/09/26, 8:13 pm] Ajay Bhaiya: <attachment...>
    for m in re.finditer(r'\[\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4},\s*[^\]]+\]\s*([A-Za-z\u0900-\u097F]+(?:\s+[A-Za-z\u0900-\u097F]+)*)\s*:', text):
        sender = m.group(1).strip()
        if sender and normalize_text(sender) not in DOCTOR_NAMES:
            detections.append(Detection('RELATIVE_NAME', sender, (m.start(1), m.end(1)), channel=channel, role='relative'))

    # WhatsApp Report of: Report of Reena behenji  65 Y / F
    for m in re.finditer(r'(?i)\b(?:report\s+of|patient\s+report\s+for)\s+([A-Za-z\u0900-\u097F]+(?:\s+[A-Za-z\u0900-\u097F]+)*?)(?=\s+\d{1,3}\s*[Yy]|\s*[,;|\n]|$)', text):
        pname = m.group(1).strip()
        if pname and normalize_text(pname) not in DOCTOR_NAMES and normalize_text(pname) not in MEDICAL_TERMS:
            detections.append(Detection('PATIENT_NAME', pname, (m.start(1), m.start(1) + len(pname)), channel=channel, role='patient'))

    # Sample received from <Name>'s attendant
    for m in re.finditer(r'(?i)\b(?:sample\s+received\s+from|received\s+from)\s+([A-Z\u0900-\u097F][a-z\u0900-\u097F]+)(?:\'s)?(?:\s+attendant)?', text):
        pname = m.group(1).strip()
        if pname and normalize_text(pname) not in DOCTOR_NAMES and normalize_text(pname) not in MEDICAL_TERMS:
            detections.append(Detection('PATIENT_NAME', pname, (m.start(1), m.start(1) + len(pname)), channel=channel, role='patient'))

    # Honorific patient mentions in free text: "Arif sahab ka BP...", "Ramesh ji", "Sunita didi", "Mahesh bhai"
    for m in re.finditer(
        r'(?i)\b([A-Z\u0900-\u097F][a-z\u0900-\u097F]{2,})\s+(?:sahab|sahib|ji|didi|bhaiya|babu|bhai|behen|behenji|amma|chachu|chacha|mama|mamaji|tauji|fufa|fufaji|mausa|mausi|bhabhi|kaka|kakaji|साहब|जी|दीदी|भैया|बाबू|भाई|बहन|बहनजी|अम्मा|चाचू|चाचा|मामा|मामाजी|ताऊजी|फूफा|मौसी|भाभी|काका)\b',
        text
    ):
        h_name = m.group(0).strip()
        f_name = m.group(1).strip()
        f_norm = normalize_text(f_name)
        if f_norm not in DOCTOR_NAMES and normalize_text(h_name) not in DOCTOR_NAMES:
            if not any(re.search(rf'\b{re.escape(d)}\b', f_name, re.IGNORECASE) for d in DRUG_NAMES if len(d) >= 4) and f_norm not in MEDICAL_TERMS:
                if not any(d.type in ('PATIENT_NAME', 'RELATIVE_NAME') and m.start() >= d.span[0] and m.end() <= d.span[1] for d in detections):
                    role = 'relative' if any(k in h_name.lower() for k in ('chachu', 'chacha', 'mama', 'mamaji', 'tauji', 'fufa', 'fufaji', 'mausa', 'mausi', 'bhabhi', 'चाचू', 'चाचा', 'मामा', 'मामाजी')) else 'patient'
                    det_type = 'RELATIVE_NAME' if role == 'relative' else 'PATIENT_NAME'
                    detections.append(Detection(det_type, h_name, (m.start(), m.end()), channel=channel, role=role))

    # Free text DOB
    for m in re.finditer(r'(?i)\b(?:dob|date\s+of\s+birth|birth\s*date|जन्म\s*तिथि)\s*[:=\-]?\s*(\d{1,2}[/.\-]\d{1,2}[/.\-](?:19|20)?\d{2})\b', text):
        detections.append(Detection('DOB', m.group(1), (m.start(1), m.end(1)), channel=channel))

    # Hinglish possessive patient mentions & Hindi complaint cues: "Dinesh ka BP", "Fatima ka sugar", "Asha ki report", "हरीश पांडे को 8 दिन से बुखार"
    for m in re.finditer(r'(?i)\b([A-Z\u0900-\u097F][a-z\u0900-\u097F]{2,}(?:[ \t]+[A-Z\u0900-\u097F][a-z\u0900-\u097F]+)?)\s+(?:ka|ki|ke|ko|का|की|के|को)\b', text):
        f_name = m.group(1).strip()
        f_norm = normalize_text(f_name)
        if any(w in COMMON_INDIAN_NAMES for w in f_norm.split()) and f_norm not in DOCTOR_NAMES and f_norm not in MEDICAL_TERMS:
            if not any(d.type in ('PATIENT_NAME', 'RELATIVE_NAME') and m.start(1) >= d.span[0] and m.end(1) <= d.span[1] for d in detections):
                detections.append(Detection('PATIENT_NAME', f_name, (m.start(1), m.end(1)), channel=channel, role='patient'))

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
        r'(?i)(?:\b(?:s/o|d/o|w/o|son\s+of|daughter\s+of|wife\s+of)|पिता\s*(?:का\s*नाम)?|पति\s*(?:का\s*नाम)?|माता\s*(?:का\s*नाम)?|अभिभावक|पुत्र|पत्नी)\s*:?\s*([A-Za-z\u0900-\u097F][^\n,;|]*?)(?:\s*[,;|\n\)]|$)',
        text
    ):
        name = m.group(1).strip()
        if name and len(name) > 1:
            name = re.split(r'(?i)\s*(?:address|village|vill\.|house|h\.no|makan|tehsil|distt?\.?|dist\.|pin|गाँव|ग्राम|पता|[\),;\n\.])', name)[0].strip()
            if name and normalize_text(name) not in DOCTOR_NAMES:
                detections.append(Detection('RELATIVE_NAME', name, (m.start(1), m.start(1) + len(name)),
                                          channel=channel, role='relative'))

    # C/O names (negative lookbehind avoids matching K/C/O or H/C/O)
    for m in re.finditer(r'(?i)(?<![kKhH]/)(?<!/)\bC/O\s+', text):
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
    for m in re.finditer(r'(?i)\b(?:called\s+by|witnessed\s+by|attendant:?|visitor:?)[ \t]*(?:\([sSwWdD]/[oO][ \t]+)?([A-Z][a-zA-Z.]+(?:[ \t]+[A-Z][a-zA-Z.]+)*)', text):
        name = m.group(1).strip()
        if not any(re.search(rf'\b{re.escape(d)}\b', name, re.IGNORECASE) for d in DRUG_NAMES if len(d) >= 4) and normalize_text(name) not in DOCTOR_NAMES:
            detections.append(Detection('RELATIVE_NAME', name, (m.start(1), m.end(1)), channel=channel, role='relative'))

    for m in re.finditer(r'(?i)\b([A-Z][a-zA-Z.]+(?:[ \t]+[A-Z][a-zA-Z.]+)*)[ \t]*\((?:attendant|visitor|relative|bystander)', text):
        name = m.group(1).strip()
        if not any(re.search(rf'\b{re.escape(d)}\b', name, re.IGNORECASE) for d in DRUG_NAMES if len(d) >= 4) and normalize_text(name) not in DOCTOR_NAMES:
            detections.append(Detection('RELATIVE_NAME', name, (m.start(1), m.end(1)), channel=channel, role='relative'))

    # Multi-word Latin names in text (e.g. Mohd. Shahid, Brajesh Yadav, Shanthi Chaudhary, Fatma Khatun) - horizontal whitespace only!
    for m in re.finditer(r'\b([A-Z][a-zA-Z.]+(?:[ \t]+[A-Z][a-zA-Z.]+){1,2})\b', text):
        cand = m.group(1).strip()
        words = cand.split()
        norm_words = [normalize_text(w) for w in words]
        if any(w in MEDICAL_TERMS or w in DISEASE_EPONYMS or w in DOCTOR_NAMES or w in HOSPITAL_NAMES for w in norm_words):
            continue
        if any(re.search(rf'\b{re.escape(d)}\b', cand, re.IGNORECASE) for d in DRUG_NAMES if len(d) >= 4):
            continue
        non_generic_names = [w for w in norm_words if w in COMMON_INDIAN_NAMES and w not in GENERIC_NAME_TOKENS]
        if non_generic_names:
            start_pos = m.start(1)
            pre = text[max(0, start_pos - 15):start_pos].lower()
            if any(dr in pre for dr in ('dr.', 'dr ', 'doctor', 'consultant', 'hospital', 'clinic')):
                continue
            if not any(d.type in ('PATIENT_NAME', 'RELATIVE_NAME') and m.start(1) >= d.span[0] and m.end(1) <= d.span[1] for d in detections):
                detections.append(Detection('PATIENT_NAME', cand, (m.start(1), m.end(1)), confidence=0.75, channel=channel))

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

    # Free-text Locality & Address patterns
    for m in re.finditer(r'(?i)\bWard\s+\d+\b', text):
        line_start = text.rfind('\n', 0, m.start())
        line_start = 0 if line_start == -1 else line_start + 1
        line_end = text.find('\n', m.end())
        line_end = len(text) if line_end == -1 else line_end
        line_txt = text[line_start:line_end].lower()
        if any(k in line_txt for k in ('address', 'mohalla', 'h.no', 'house', 'pata', 'पता', 'निवास')):
            detections.append(Detection('LOCALITY', m.group(0), (m.start(), m.end()), channel=channel))

    for m in re.finditer(r'(?i)\b(?:mohalla|मोहल्ला)\s+([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F\s]+?)(?=\s*[,;|\n]|$)', text):
        loc = m.group(0).strip()
        detections.append(Detection('LOCALITY', loc, (m.start(), m.start() + len(loc)), channel=channel))

    for m in re.finditer(r'(?i)\b(?:near|behind|opp\.?)\s+([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F\s]+?)(?=\s*[,;|\n]|$)', text):
        lm = m.group(0).strip()
        detections.append(Detection('LANDMARK', lm, (m.start(), m.start() + len(lm)), channel=channel))

    for m in re.finditer(r'([\u0900-\u097F\s]+?)\s*(?:के\s*पास|के\s*पीछे|के\s*सामने)', text):
        lm = m.group(0).strip()
        if len(lm) > 4:
            detections.append(Detection('LANDMARK', lm, (m.start(), m.start() + len(lm)), channel=channel))

    for m in re.finditer(r'\b([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F]+(?:\s+(?:Kalan|Khurd|कलां|खुर्द)))\b', text):
        v_name = m.group(0).strip()
        detections.append(Detection('VILLAGE', v_name, (m.start(), m.end()), channel=channel))

    for m in re.finditer(r'(?i)\b([A-Za-z\u0900-\u097F]{3,})(?:,\s*(?:Tehsil|तहसील))\b', text):
        cand = m.group(1).strip()
        if normalize_text(cand) not in ('ward', 'mohalla', 'house', 'distt', 'district'):
            detections.append(Detection('VILLAGE', cand, (m.start(1), m.end(1)), channel=channel))

    if channel == 'header':
        for m in re.finditer(r'\b([A-Z][a-zA-Z]+)\b', text):
            cand = m.group(1).strip()
            cand_low = cand.lower()
            if cand_low in COMMON_INDIAN_NAMES and cand_low not in MEDICAL_TERMS and cand_low not in DRUG_NAMES:
                detections.append(Detection('PATIENT_NAME', cand, (m.start(), m.end()), channel=channel, role='patient'))

    for m in RE_PIN.finditer(text):
        line_start = text.rfind('\n', 0, m.start())
        line_start = 0 if line_start == -1 else line_start + 1
        line_end = text.find('\n', m.end())
        line_end = len(text) if line_end == -1 else line_end
        line_txt = text[line_start:line_end].lower()
        if any(kw in line_txt for kw in ('address', 'pin', 'pincode', 'dist', 'distt', 'tehsil', 'ward', 'mohalla', 'bareli', 'hardoi', 'lucknow', '-')):
            if not is_dose_context(text, m.start(), m.end()):
                detections.append(Detection('PIN', m.group(1), (m.start(1), m.end(1)), channel=channel))

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
    if len(s) < 3 or '[' in s or ']' in s or det.type in ('DOB', 'DATE', 'AGE', 'GENDER', 'PIN', 'HOUSE', 'LOCALITY', 'LANDMARK', 'VILLAGE'):
        return
    if re.search(r'\b\d{1,4}[/-]\d{1,2}[/-]\d{1,4}\b', s) or ('t' in s.lower() and ':' in s) or ('/' in s and ':' in s):
        return
    # Add exact surface
    REMOVED_DIRECT_IDENTIFIERS.add(s)
    # Digits if phone or ID
    digits = re.sub(r'\D', '', s)
    if len(digits) >= 10 and not any(k in s.lower() for k in ('date', 'time', 't', 'utc', 'z')):
        REMOVED_DIRECT_IDENTIFIERS.add(digits)
    # Name variants
    if det.type in ('PATIENT_NAME', 'RELATIVE_NAME'):
        norm = normalize_text(s)
        if len(norm) >= 3 and norm not in GENERIC_NAME_TOKENS and norm not in MEDICAL_TERMS:
            REMOVED_DIRECT_IDENTIFIERS.add(norm)
            skel = name_skeleton(s)
            if len(skel) >= 3 and skel not in GENERIC_NAME_TOKENS:
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

    # Numbers (integers / floats)
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        # Age banding
        if h_norm in {'age', 'umar', 'उम्र', 'आयु', 'patient_age', 'dob_age'}:
            Stats.generalized += 1
            return age_band(int(v)), all_dets
        # PIN code generalization
        if h_norm in ('pin', 'pincode', 'postal_code', 'postalcode', 'zip'):
            digits = str(int(v))
            if len(digits) == 6:
                Stats.generalized += 1
                return digits[:3] + '***', all_dets
            return '[PIN]', all_dets
        # Identifiers stored as integers (e.g. Aadhaar, phone, MRN)
        v_str = str(int(v))
        h_type = classify_header(header) if header else None
        if h_type == 'AADHAAR' or (len(v_str) == 12 and h_norm in ('aadhar_no', 'aadhaar', 'uid')):
            d = Detection('AADHAAR', v_str, channel='content')
            record_removed_identifier(d)
            all_dets.append(d)
            return '[AADHAAR]', all_dets
        if h_type == 'PHONE' or (len(v_str) == 10 and h_norm in ('mobile', 'phone', 'contact')):
            d = Detection('PHONE', v_str, channel='content')
            record_removed_identifier(d)
            all_dets.append(d)
            return '[PHONE]', all_dets
        if h_type == 'MRN':
            d = Detection('MRN', v_str, channel='content')
            record_removed_identifier(d)
            all_dets.append(d)
            return '[MRN]', all_dets
        return v, all_dets

    # Location / PIN generalization in JSON
    if h_norm in ('village', 'gaon', 'गाँव', 'gram'):
        Stats.generalized += 1
        return '[VILLAGE]', all_dets
    if h_norm in ('pin', 'pincode', 'postal_code', 'postalcode', 'zip'):
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
        # Protect clinical panel names or test names when header == 'name'
        if h_norm == 'name':
            v_low = v_str.lower()
            if v_low in ('routine', 'complete blood count', 'lipid profile', 'lft', 'kft', 'cbc') or v_low in MEDICAL_TERMS:
                return v, all_dets

        # FHIR HTML narrative in 'div'
        if h_norm == 'div':
            cleaned_div, div_dets = clean_text(v)
            if div_dets:
                all_dets.extend(div_dets)
                return cleaned_div, all_dets

        # FHIR display: if not doctor and not hospital, clean patient name
        if h_norm == 'display':
            if not v_str.startswith(('Dr.', 'Doctor ', 'Dr ', 'dr.')):
                is_org = any(h in v_str.lower() for h in ('hospital', 'clinic', 'charitable', 'sadan', 'pathology', 'ward', 'department'))
                if not is_org and not any(m in v_str.lower() for m in MEDICAL_TERMS):
                    words = v_str.split()
                    if 1 <= len(words) <= 4 and any(w.lower() in COMMON_INDIAN_NAMES for w in words):
                        d = Detection('PATIENT_NAME', v_str, channel='content', role='patient')
                        record_removed_identifier(d)
                        all_dets.append(d)
                        return '[PATIENT_NAME]', all_dets

        # FHIR text in HumanName
        if h_norm == 'text' and not v_str.startswith('{') and not v_str.startswith('<'):
            if not v_str.startswith(('Dr.', 'Doctor ', 'Dr ')) and not any(m in v_str.lower() for m in MEDICAL_TERMS):
                words = v_str.split()
                if 1 <= len(words) <= 4 and any(w.lower() in COMMON_INDIAN_NAMES for w in words):
                    d = Detection('PATIENT_NAME', v_str, channel='content', role='patient')
                    record_removed_identifier(d)
                    all_dets.append(d)
                    return '[PATIENT_NAME]', all_dets

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
        # FHIR extension context detection
        url_val = str(v.get('url', '')).lower()
        is_mother_ext = 'mother' in url_val
        is_father_ext = 'father' in url_val or 'guardian' in url_val

        for k, x in v.items():
            new_k = k
            # Clean PII from keys (e.g. "by_name": {"Jaspreet Singh": ...})
            if any('\u0900' <= c <= '\u097F' for c in k) or any(w.lower() in COMMON_INDIAN_NAMES for w in k.split()):
                key_dets = detect_pii_in_text(k, 'key')
                if key_dets:
                    for d in key_dets:
                        new_k = new_k.replace(d.surface, make_replacement(d))
                    all_dets.extend(key_dets)
            elif len(k) > 25:
                key_dets = detect_pii_in_text(k, 'key')
                if key_dets:
                    for d in key_dets:
                        new_k = new_k.replace(d.surface, make_replacement(d))
                    all_dets.extend(key_dets)

            elem_header = k
            if is_mother_ext or is_father_ext:
                if k in ('valueString', 'valuestring', 'value'):
                    elem_header = 'relative_name'
            elif h_norm in ('guardian', 'relative', 'attendant', 'contact') and k in ('name', 'first', 'last', 'local'):
                elem_header = 'relative_name'
            elif h_norm in ('name', 'patient', 'patient_name') and k in ('first', 'last', 'local'):
                elem_header = 'patient_name'

            cleaned, dets = clean_value(x, header=elem_header, shift=shift)
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

    @staticmethod
    def _candidate_names(ev: dict[str, Any]) -> list[str]:
        return [n for n in (ev.get('patient_name', ''), ev.get('patient_name_alt', '')) if n]

    @staticmethod
    def _candidate_rels(ev: dict[str, Any]) -> list[str]:
        return [r for r in (ev.get('relative_name', ''), ev.get('relative_name_alt', '')) if r]

    @staticmethod
    def _best_name_match(names1: list[str], names2: list[str]) -> str:
        order = {'none': 0, 'partial': 1, 'first': 2, 'full': 3}
        best = 'none'
        for n1 in names1:
            for n2 in names2:
                res = _match_name_pair(n1, n2)
                if order[res] > order[best]:
                    best = res
                    if best == 'full':
                        return 'full'
        return best

    @staticmethod
    def _record_mrns(ev: dict[str, Any]) -> list[str]:
        mrns = []
        if ev.get('mrns'):
            mrns.extend(ev['mrns'])
        if ev.get('uhid'):
            mrns.append(str(ev['uhid']))
        # Preserve unique normalized order
        seen = set()
        out = []
        for m in mrns:
            nm = re.sub(r'[\s\-/]', '', str(m)).lower()
            if nm and nm not in seen:
                seen.add(nm)
                out.append(str(m))
        return out

    def _shares_any_mrn(self, ev1: dict[str, Any], ev2: dict[str, Any]) -> bool:
        m1 = {re.sub(r'[\s\-/]', '', m).lower() for m in self._record_mrns(ev1)}
        m2 = {re.sub(r'[\s\-/]', '', m).lower() for m in self._record_mrns(ev2)}
        return bool(m1 & m2)

    def _hard_contradict(self, rid1: str, rid2: str) -> bool:
        """Check strict pairwise contradictions (national IDs, gender, DOB, age, uncorroborated family phone)."""
        ev1 = self.evidence.get(rid1, {})
        ev2 = self.evidence.get(rid2, {})

        # 1. Contradicting global unique IDs (Aadhaar, PAN, ABHA)
        has_shared_global = False
        for id_field in ('aadhaar', 'pan', 'abha'):
            v1, v2 = ev1.get(id_field), ev2.get(id_field)
            if v1 and v2:
                n1 = re.sub(r'[\s\-/]', '', str(v1)).lower()
                n2 = re.sub(r'[\s\-/]', '', str(v2)).lower()
                if n1 != n2:
                    return True
                has_shared_global = True

        # 2. Gender contradiction (normalized across scripts)
        g1 = _normalize_gender(ev1.get('gender', ''))
        g2 = _normalize_gender(ev2.get('gender', ''))
        if g1 and g2 and g1 != g2:
            return True

        # 3. DOB contradiction
        d1, d2 = ev1.get('dob', ''), ev2.get('dob', '')
        dob_compat = _dobs_compatible(d1, d2) if (d1 and d2) else None
        if dob_compat is False:
            return True

        # 4. Age contradiction (> 5 years gap is impossible for same patient)
        a1 = _normalize_age(ev1.get('age'))
        a2 = _normalize_age(ev2.get('age'))
        if a1 is not None and a2 is not None and abs(a1 - a2) > 5:
            return True

        # 4b. Cross-check DOB birth year against reported age
        for dob_val, age_val in ((d1, a2), (d2, a1)):
            if dob_val and age_val is not None:
                parsed = _parse_dob(dob_val)
                if parsed:
                    byear = parsed[0]
                    min_plausible = (2020 - byear) - 3
                    max_plausible = (2027 - byear) + 3
                    if age_val < min_plausible or age_val > max_plausible:
                        return True

        # 5. Family phone trap: same phone without shared national/MRN ID, distinct names, no relative match
        p1, p2 = ev1.get('phone'), ev2.get('phone')
        if p1 and p2 and p1 == p2 and not has_shared_global and not self._shares_any_mrn(ev1, ev2):
            names1 = self._candidate_names(ev1)
            names2 = self._candidate_names(ev2)
            if names1 and names2:
                nm = self._best_name_match(names1, names2)
                if nm == 'none':
                    rels1 = self._candidate_rels(ev1)
                    rels2 = self._candidate_rels(ev2)
                    rm = self._best_name_match(rels1, rels2) if (rels1 and rels2) else 'none'
                    if rm == 'none':
                        return True

        return False

    def _sets_uhid_conflict(self, rids1: set[str], rids2: set[str]) -> bool:
        """Check whether two record sets have conflicting same-hospital UHIDs without strong corroboration."""
        uhids1: dict[str, set[str]] = {}
        uhids2: dict[str, set[str]] = {}
        globals1: dict[str, set[str]] = defaultdict(set)
        globals2: dict[str, set[str]] = defaultdict(set)
        phones1, phones2 = set(), set()
        names1, names2, rels1, rels2, vills1, vills2, dobs1, dobs2 = [], [], [], [], [], [], [], []

        for rset, uhids, globs, phones, names, rels, vills, dobs in (
            (rids1, uhids1, globals1, phones1, names1, rels1, vills1, dobs1),
            (rids2, uhids2, globals2, phones2, names2, rels2, vills2, dobs2),
        ):
            for rid in rset:
                ev = self.evidence.get(rid, {})
                for m in self._record_mrns(ev):
                    kind, ns = _mrn_kind_ns(m)
                    if kind == 'uhid' and ns:
                        uhids.setdefault(ns, set()).add(re.sub(r'[\s\-/]', '', m).lower())
                for gf in ('aadhaar', 'pan', 'abha', 'insurance', 'email'):
                    gv = ev.get(gf)
                    if gv:
                        globs[gf].add(re.sub(r'[\s\-/]', '', str(gv)).lower())
                if ev.get('phone'):
                    phones.add(ev['phone'])
                names.extend(self._candidate_names(ev))
                rels.extend(self._candidate_rels(ev))
                if ev.get('village'):
                    vills.append(ev['village'])
                if ev.get('dob'):
                    dobs.append(ev['dob'])

        shared_ns = set(uhids1) & set(uhids2)
        if not shared_ns:
            return False
        for ns in shared_ns:
            if not (uhids1[ns] & uhids2[ns]):
                # Different UHIDs in the same hospital namespace: require shared global ID OR strong phone+corrob
                for gf in ('aadhaar', 'pan', 'abha', 'insurance', 'email'):
                    if globals1[gf] & globals2[gf]:
                        return False
                if phones1 & phones2:
                    nm = self._best_name_match(names1, names2)
                    rm = self._best_name_match(rels1, rels2)
                    vm = any(_location_match(v1, v2) for v1 in vills1 for v2 in vills2)
                    dm = any(_dobs_compatible(d1, d2) is True for d1 in dobs1 for d2 in dobs2)
                    if nm == 'full' and (dm or rm != 'none' or vm):
                        return False
                return True
        return False

    def _records_contradict(self, rid1: str, rid2: str) -> bool:
        """Check if two records contradict each other (negative evidence constraint)."""
        return self._hard_contradict(rid1, rid2) or self._sets_uhid_conflict({rid1}, {rid2})

    def _cluster_contradicts(self, cluster_key: str, rid: str) -> bool:
        """Check if rid contradicts cluster (hard contradiction with any member or same-NS UHID conflict)."""
        members = self.clusters.get(cluster_key, set())
        if any(self._hard_contradict(rid, m) for m in members):
            return True
        return self._sets_uhid_conflict(members, {rid})

    def _clusters_contradict(self, c1: str, c2: str) -> bool:
        """Check if two clusters contradict each other."""
        m1 = self.clusters.get(c1, set())
        m2 = self.clusters.get(c2, set())
        if any(self._hard_contradict(r1, r2) for r1 in m1 for r2 in m2):
            return True
        return self._sets_uhid_conflict(m1, m2)

    def _build_cluster_profile(self, cluster_key: str) -> dict[str, Any]:
        """Pool validated identifying evidence across all records in a cluster."""
        names: list[str] = []
        relatives: list[str] = []
        villages: list[str] = []
        pins: list[str] = []
        ages: list[int] = []
        dobs: list[str] = []
        genders: set[str] = set()

        for m in self.clusters.get(cluster_key, set()):
            ev = self.evidence.get(m, {})
            for n in self._candidate_names(ev):
                if n not in names:
                    names.append(n)
            for r in self._candidate_rels(ev):
                if r not in relatives:
                    relatives.append(r)
            v = ev.get('village', '')
            if v and v not in villages:
                villages.append(v)
            p = ev.get('pin', '')
            if p and str(p) not in pins:
                pins.append(str(p))
            a = _normalize_age(ev.get('age'))
            if a is not None:
                ages.append(a)
            d = ev.get('dob', '')
            if d and d not in dobs:
                dobs.append(d)
            g = _normalize_gender(ev.get('gender', ''))
            if g:
                genders.add(g)

        return {
            'names': names,
            'relatives': relatives,
            'villages': villages,
            'pins': pins,
            'ages': ages,
            'dobs': dobs,
            'genders': genders,
        }

    def _score_against_profile(self, ev: dict[str, Any], prof: dict[str, Any]) -> float:
        """Compute weighted evidence score between an unlinked record and a cluster profile."""
        ev_names = self._candidate_names(ev)
        if not ev_names or not prof['names']:
            return 0.0

        name_match = self._best_name_match(ev_names, prof['names'])
        if name_match == 'none':
            return 0.0

        score = 0.0
        # Patient name score
        best_tok_count = max(len(name_skeleton(n).split()) for n in ev_names)
        if name_match == 'full':
            name_pts = 0.45 if best_tok_count >= 2 else 0.35
        elif name_match == 'first':
            name_pts = 0.30
        else:
            name_pts = 0.25
        score += name_pts

        # Relative name score
        ev_rels = self._candidate_rels(ev)
        rel_pts = 0.0
        if ev_rels and prof['relatives']:
            rel_match = self._best_name_match(ev_rels, prof['relatives'])
            if rel_match in ('full', 'first', 'partial'):
                rel_pts = 0.35
        score += rel_pts

        # Village / Location / PIN prefix
        v1 = ev.get('village', '')
        p1 = ev.get('pin', '')
        vill_match = bool(v1 and any(_location_match(v1, v2) for v2 in prof['villages']))
        pin_match = bool(p1 and any(str(p1)[:3] == str(p2)[:3] for p2 in prof['pins']))
        if vill_match:
            score += 0.25
        elif pin_match:
            score += 0.10

        # DOB / Age score
        dob1 = ev.get('dob', '')
        age1 = _normalize_age(ev.get('age'))
        dob_match = bool(dob1 and any(_dobs_compatible(dob1, d2) is True for d2 in prof['dobs']))
        if dob_match:
            score += 0.25
        elif age1 is not None:
            diffs = [abs(age1 - a2) for a2 in prof['ages']]
            if not diffs and prof['dobs']:
                # Infer approximate age from birth year if age not directly recorded
                for d2 in prof['dobs']:
                    parsed = _parse_dob(d2)
                    if parsed:
                        by = parsed[0]
                        diffs.extend([abs(age1 - (2025 - by)), abs(age1 - (2026 - by))])
            if diffs:
                min_diff = min(diffs)
                if min_diff == 0:
                    score += 0.18
                elif min_diff <= 2:
                    score += 0.14
                elif min_diff <= 3:
                    score += 0.10
                elif min_diff <= 5:
                    score += 0.05

        # Gender corroboration only when paired with name + at least one other clue
        g1 = _normalize_gender(ev.get('gender', ''))
        if g1 and g1 in prof['genders'] and name_pts >= 0.30 and (rel_pts > 0 or vill_match or dob_match):
            score += 0.15

        return round(min(1.0, score), 3)

    def _compute_link_score(self, rid1: str, rid2: str) -> float:
        """Compute weighted evidence score between two records in [0.0, 1.0]."""
        if self._records_contradict(rid1, rid2):
            return 0.0
        ev1 = self.evidence.get(rid1, {})
        ev2 = self.evidence.get(rid2, {})
        prof2 = {
            'names': self._candidate_names(ev2),
            'relatives': self._candidate_rels(ev2),
            'villages': [ev2['village']] if ev2.get('village') else [],
            'pins': [str(ev2['pin'])] if ev2.get('pin') else [],
            'ages': [a] if (a := _normalize_age(ev2.get('age'))) is not None else [],
            'dobs': [ev2['dob']] if ev2.get('dob') else [],
            'genders': {g} if (g := _normalize_gender(ev2.get('gender', ''))) else set(),
        }
        return self._score_against_profile(ev1, prof2)

    def _score_record_against_cluster(self, rid: str, cluster_key: str) -> float:
        """Compute evidence score of rid against pooled cluster profile (0.0 if any member contradicts)."""
        if self._cluster_contradicts(cluster_key, rid):
            return 0.0
        ev = self.evidence.get(rid, {})
        prof = self._build_cluster_profile(cluster_key)
        return self._score_against_profile(ev, prof)

    def _merge_pair(self, r1: str, r2: str) -> None:
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
            if not self._clusters_contradict(c1, c2):
                self.clusters[c1].update(self.clusters.pop(c2, set()))
                for m in list(self.clusters[c1]):
                    self.record_to_cluster[m] = c1

    def link(self):
        """Link records using multi-pass blocking, negative evidence, and candidate margin scoring."""
        # Pass 1: Strong unique government, hospital UHIDs, encounter IPD/ADM IDs, and personal email
        id_groups: dict[str, list[str]] = defaultdict(list)
        for rid, ev in self.evidence.items():
            for val in self._record_mrns(ev):
                val_n = re.sub(r'[\s\-/]', '', str(val)).lower()
                if val_n and len(val_n) >= 4:
                    id_groups[f"mrn:{val_n}"].append(rid)
            for id_type in ('aadhaar', 'abha', 'pan', 'insurance', 'email'):
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
                    self._merge_pair(r1, r2)

        # Pass 2: Phone number with corroboration (guard against family phone trap)
        phone_groups: dict[str, list[str]] = defaultdict(list)
        for rid, ev in self.evidence.items():
            p = ev.get('phone')
            if p and len(p) >= 10:
                phone_groups[p].append(rid)

        use_neg = POLICY.get("enable_negative_evidence", True)
        for phone, rids in phone_groups.items():
            if len(rids) < 2:
                continue
            for i in range(len(rids)):
                for j in range(i + 1, len(rids)):
                    r1, r2 = rids[i], rids[j]
                    if use_neg and self._records_contradict(r1, r2):
                        continue
                    ev1, ev2 = self.evidence.get(r1, {}), self.evidence.get(r2, {})
                    name_overlap = self._best_name_match(self._candidate_names(ev1), self._candidate_names(ev2)) != 'none'
                    rel_overlap = self._best_name_match(self._candidate_rels(ev1), self._candidate_rels(ev2)) != 'none'
                    v1, v2 = ev1.get('village', ''), ev2.get('village', '')
                    vill_overlap = bool(v1 and v2 and _location_match(v1, v2))
                    dob_overlap = bool(ev1.get('dob') and ev2.get('dob') and _dobs_compatible(ev1['dob'], ev2['dob']) is True)
                    a1, a2 = _normalize_age(ev1.get('age')), _normalize_age(ev2.get('age'))
                    close_age = (a1 is not None and a2 is not None and abs(a1 - a2) <= 3)
                    has_corrob = name_overlap or rel_overlap or vill_overlap or dob_overlap or close_age
                    if use_neg and not has_corrob:
                        continue
                    self._merge_pair(r1, r2)

        # Pass 3: Candidate Margin Scoring for Unlinked Fragments (Technique 3)
        strong_threshold = float(POLICY.get("link_strong_threshold", 0.8))
        margin = float(POLICY.get("link_margin", 0.2))

        unlinked = [rid for rid in self.evidence if rid not in self.record_to_cluster]
        cluster_profiles = {ckey: self._build_cluster_profile(ckey) for ckey in self.clusters}
        for rid in unlinked:
            if not self.clusters:
                break
            ev = self.evidence.get(rid, {})
            cluster_scores: list[tuple[float, str]] = []
            for ckey, prof in cluster_profiles.items():
                if self._cluster_contradicts(ckey, rid):
                    continue
                score = self._score_against_profile(ev, prof)
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
                    cluster_profiles[best_cluster] = self._build_cluster_profile(best_cluster)

    def get_pseudonym(self, record_id: str) -> str | None:
        """Get pseudonym for a record, or None if unlinked."""
        ckey = self.record_to_cluster.get(record_id)
        if ckey is None:
            return None
        return pseudonym(ckey)


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------
def _add_mrn_to_ev(ev: dict[str, Any], val: str) -> None:
    """Record an MRN/UHID/IPD into ev['mrns'] and prefer hospital UHID in ev['uhid']."""
    v = str(val).strip()
    if not v or len(re.sub(r'[\s\-/]', '', v)) < 4:
        return
    # Never record dates as MRNs
    if re.match(r'^\d{1,4}[/\-.]\d{1,2}[/\-.]\d{1,4}$', v):
        return
    mrns = ev.setdefault('mrns', [])
    if v not in mrns:
        mrns.append(v)
    kind, _ = _mrn_kind_ns(v)
    if 'uhid' not in ev or (kind == 'uhid' and _mrn_kind_ns(ev['uhid'])[0] == 'encounter'):
        ev['uhid'] = v


def extract_evidence_csv(row: list[str], headers: list[str], header_types: list[str | None] | None = None) -> dict[str, Any]:
    """Extract linkage evidence from a CSV row."""
    ev: dict[str, Any] = {}
    h_map = {normalize_text(h): i for i, h in enumerate(headers)}
    first_name = ''
    last_name = ''
    local_name = ''
    generic_name = ''

    for h, i in h_map.items():
        if i >= len(row):
            continue
        val = row[i].strip()
        if not val:
            continue

        h_clean = re.sub(r'[_\-./]', ' ', h).strip()
        h_type = header_types[i] if header_types and i < len(header_types) else classify_header(headers[i])
        if h_type == 'PATIENT_NAME':
            if h_clean in ('first name', 'firstname', 'first', 'fname', 'given'):
                first_name = val
            elif h_clean in ('last name', 'lastname', 'last', 'lname', 'family', 'surname'):
                last_name = val
            elif h_clean in ('local name', 'local'):
                local_name = val
            else:
                generic_name = val
        elif h_type == 'RELATIVE_NAME':
            ev['relative_name'] = val
        elif h_type == 'PHONE':
            digits = re.sub(r'\D', '', normalize_text(val))
            if len(digits) >= 10:
                ev['phone'] = digits[-10:]
            elif digits:
                ev['phone'] = digits
        elif h_type == 'AADHAAR':
            digits = re.sub(r'\D', '', normalize_text(val))
            if len(digits) == 12:  # Full 12 digits only (exclude masked XXXX...1234)
                ev['aadhaar'] = digits
        elif h_type == 'ABHA_NUMBER':
            ev['abha'] = normalize_text(val)
        elif h_type == 'MRN':
            _add_mrn_to_ev(ev, val)
        elif h_type == 'EMAIL':
            ev['email'] = val
        elif h_type == 'PAN':
            ev['pan'] = val
        elif h_type == 'INSURANCE_ID':
            ev['insurance'] = val
        elif h_type == 'VILLAGE':
            ev['village'] = val
        elif h_type == 'PIN':
            pin_digits = re.sub(r'\D', '', normalize_text(val))
            if len(pin_digits) == 6:
                ev['pin'] = pin_digits
        elif h_type == 'DOB':
            ev['dob'] = normalize_text(val)

        if h_clean in {'age', 'umar', 'उम्र', 'आयु'}:
            age_num = _normalize_age(val)
            if age_num is not None:
                ev['age'] = str(age_num)
        elif h_clean in {'age sex', 'age gender'}:
            m_as = re.match(r'^(\d{1,3})\s*/\s*([MFmf])$', normalize_text(val))
            if m_as:
                ev['age'] = m_as.group(1)
                ev['gender'] = m_as.group(2).upper()
        if h_clean in {'gender', 'sex', 'ling', 'लिंग'}:
            g = _normalize_gender(val)
            if g:
                ev['gender'] = g

    if generic_name:
        ev['patient_name'] = generic_name
    elif first_name or last_name:
        ev['patient_name'] = f"{first_name} {last_name}".strip()
    if local_name:
        if 'patient_name' not in ev:
            ev['patient_name'] = local_name
        elif normalize_text(local_name) != normalize_text(ev['patient_name']):
            ev['patient_name_alt'] = local_name

    # Extract UHID from first column if it looks like an MRN
    if headers and row:
        first_val = row[0].strip()
        if RE_MRN.match(first_val):
            _add_mrn_to_ev(ev, first_val)

    return ev


def extract_evidence_text(text: str) -> dict[str, Any]:
    """Extract linkage evidence from free text."""
    ev: dict[str, Any] = {}
    text_norm = text.translate(INDIC_DIGITS)

    # 1. Explicit patient name cues
    m = re.search(
        r'(?i)(?:patient\s+name|patient\s*:|rogi\s*(?:ka\s*)?naam|रोगी\s*(?:का\s*)?नाम|मरीज़?\s*(?:का\s*)?नाम)\s*:?[ \t]*([^\n,;|]+)',
        text
    )
    if not m:
        m = re.search(r'(?im)^(?:name|full\s*name|naam|नाम)\s*:[ \t]*([^\n,;|]+)', text)
    if m:
        raw_val = m.group(1)
        cand = re.split(r'(?i)[ \t]{2,}|\t|\b(?:age|sex|dob|uhid|mrn|ipd|opd|ward|bed|umar)\b|(?:आयु|उम्र)\s*:', raw_val)[0].strip()
        if cand and len(cand) > 1 and not re.match(r'^(?:presents|admitted|complaining|reported|referred|diagnosed|is|was|ne)\b', cand, re.I):
            ev['patient_name'] = cand

    if 'patient_name' not in ev:
        # WhatsApp "Report of <Name>  48 Y / F" before looking at sender line
        m_rep = re.search(
            r'(?i)\b(?:report\s+of|patient\s+report\s+for)[ \t]+([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F \t]{1,40}?)(?=[ \t]+\d{1,3}[ \t]*[Yy]|[ \t]*[,;|\n]|$)',
            text
        )
        if m_rep:
            cand = m_rep.group(1).strip()
            if cand and normalize_text(cand) not in DOCTOR_NAMES and normalize_text(cand) not in MEDICAL_TERMS:
                ev['patient_name'] = cand

    if 'patient_name' not in ev:
        # Nursing notes: "14:00 - Shanthi Chaudhary - K/C/O ..."
        m_kco = re.search(r'(?m)^[ \t]*(?:\d{1,2}:\d{2}[ \t]*-[ \t]*)([A-Z][a-zA-Z.]+(?:[ \t]+[A-Z][a-zA-Z.]+){1,2})[ \t]*-[ \t]*[kKhH]/[cC]/[oO]\b', text)
        if m_kco:
            cand = m_kco.group(1).strip()
            if cand and normalize_text(cand) not in DOCTOR_NAMES and normalize_text(cand) not in MEDICAL_TERMS:
                ev['patient_name'] = cand

    if 'patient_name' not in ev:
        # Patient before relation cue at line start: "Asha, W/o Kamal, ..."
        m_rel_pfx = re.search(
            r'(?im)^[ \t]*([A-Z\u0900-\u097F][A-Za-z\u0900-\u097F.]{1,30}(?:[ \t]+[A-Za-z\u0900-\u097F.]+){0,2})[ \t]*,?[ \t]+(?:s/o|d/o|w/o|son\s+of|daughter\s+of|wife\s+of)\b',
            text
        )
        if m_rel_pfx:
            cand = m_rel_pfx.group(1).strip()
            if cand and normalize_text(cand) not in DOCTOR_NAMES and normalize_text(cand) not in MEDICAL_TERMS:
                ev['patient_name'] = cand

    if 'patient_name' not in ev:
        # Honorific mention fallback (exclude WhatsApp sender bracket lines "[date] Name:")
        non_wa_lines = "\n".join(line for line in text.splitlines() if not re.match(r'^\[\d{1,2}[/\-]\d{1,2}', line.strip()))
        m2 = re.search(
            r'(?i)\b([A-Z\u0900-\u097F][a-z\u0900-\u097F]{2,}[ \t]+(?:sahab|sahib|ji|didi|bhaiya|babu|behenji|behen|amma|साहब|जी|दीदी|भैया|बाबू|बहनजी))\b',
            non_wa_lines
        )
        if m2 and normalize_text(m2.group(1)) not in DOCTOR_NAMES:
            ev['patient_name'] = m2.group(1).strip()

    # 2. Extract ALL MRNs / UHIDs / IPD IDs
    for m in RE_MRN.finditer(text_norm):
        _add_mrn_to_ev(ev, m.group(0))
    for m in RE_MRN_LABELLED.finditer(text_norm):
        val = m.group(1).strip()
        if len(val) >= 4 and not re.match(r'^\d{1,4}[/\-.]\d{1,2}[/\-.]\d{1,4}$', val):
            _add_mrn_to_ev(ev, val)

    # 3. Phone (supports both ASCII and Indic digits via text_norm)
    for m in RE_PHONE.finditer(text_norm):
        if not is_dose_context(text_norm, m.start(), m.end()):
            digits = re.sub(r'\D', '', m.group(0))
            if len(digits) >= 10:
                ev['phone'] = digits[-10:]
                break

    # 4. ABHA FIRST, then Aadhaar excluding ABHA span overlaps (prevents last 12 digits of ABHA masquerading as Aadhaar)
    abha_spans: list[tuple[int, int]] = []
    for m in RE_ABHA.finditer(text_norm):
        abha_spans.append((m.start(), m.end()))
        ev.setdefault('abha', re.sub(r'[\s\-]', '', m.group(0)))

    for m in RE_AADHAAR.finditer(text_norm):
        if any(not (m.end() <= s or m.start() >= e) for s, e in abha_spans):
            continue
        if not is_dose_context(text_norm, m.start(), m.end()):
            digits = re.sub(r'\D', '', m.group(0))
            if len(digits) == 12:
                ev.setdefault('aadhaar', digits)
                break

    # 5. PAN
    m = RE_PAN.search(text)
    if m:
        ev['pan'] = m.group(0).upper()

    # 6. Relative name (exclude K/C/O, H/C/O, and clinical C/O complaints; horizontal whitespace only)
    rel_m = re.search(
        r'(?i)(?:(?<![kKhH]/)(?<!/)\b(?:s/o|d/o|w/o|c/o|attendant[ \t]*(?:\([sSwWdD]/[oO])?)|पिता\s*(?:का\s*नाम)?|पति\s*(?:का\s*नाम)?|माता\s*(?:का\s*नाम)?)[ \t]*:?[ \t]*([^\n,;|)]+)',
        text
    )
    if rel_m:
        cue_start = rel_m.start()
        if not is_complaint_co(text, cue_start):
            cand_rel = rel_m.group(1).strip()
            cand_rel = re.sub(r'^(?:\([sSwWdD]/[oO]\s*|\b[sSwWdD]/[oO]\s+)', '', cand_rel).strip()
            cand_rel = re.split(r'(?i)[ \t]+(?:address|village|vill\.|house|h\.no|makan|tehsil|distt?\.?|dist\.|pin|पता|पंजीकरण|गाँव|ग्राम)\b|[ \t]{2,}', cand_rel)[0].strip()
            rel_low = normalize_text(cand_rel)
            first_is_proper = bool(cand_rel) and (cand_rel[0].isupper() or _is_deva_letter(cand_rel[0]))
            if cand_rel and len(cand_rel) >= 2 and first_is_proper and not any(w in rel_low for w in ('fever', 'pain', 'disease', 'typhoid', 'diabetes', 'tuberculosis', 'dengue', 'chronic', 'infection', 'informed', 'complaint', 'burning', 'micturition', 'giddiness', 'headache', 'बुखार', 'दर्द', 'दिन से')):
                ev['relative_name'] = cand_rel

    # WhatsApp sender can also serve as fallback relative clue
    wa_m = re.search(r'\[\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4},[^\]]+\][ \t]*([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F \t]{1,35}?):', text)
    if wa_m and 'relative_name' not in ev:
        ev['relative_name'] = wa_m.group(1).strip()

    # 7. Age & Gender
    m = re.search(r'(?i)\b(?:age|umar|उम्र|आयु)[ \t]*[:=/\-][ \t]*(\d{1,3})', text_norm)
    if not m:
        m = re.search(r'(?i)\b(?:age|umar|उम्र|आयु)[ \t]+(\d{1,3})[ \t]*(?:yrs?|yr|years?|वर्ष|/)\b', text_norm)
    if m:
        a = _normalize_age(m.group(1))
        if a is not None:
            ev['age'] = str(a)

    m = re.search(r'(?i)(\d{1,3})[ \t]*(?:yrs?|yr|years?|y|वर्ष)?[ \t]*/[ \t]*(M|F|महिला|पुरुष)\b', text_norm)
    if m:
        a = _normalize_age(m.group(1))
        if a is not None:
            ev.setdefault('age', str(a))
        g = _normalize_gender(m.group(2))
        if g:
            ev['gender'] = g

    if 'gender' not in ev:
        if re.search(r'\b[wWdD]/[oO]\b', text):
            ev['gender'] = 'F'
        elif re.search(r'\b[sS]/[oO]\b', text):
            ev['gender'] = 'M'

    # 8. DOB
    m = re.search(r'(?i)\b(?:dob|date\s+of\s+birth|birth\s*date|जन्म\s*तिथि)[ \t]*[:=\-]?[ \t]*(\d{1,4}[/.\-]\d{1,2}[/.\-]\d{1,4})\b', text_norm)
    if m:
        ev['dob'] = m.group(1).strip()

    # 9. Village (avoid Python \w Devanagari matra bug by matching explicit Latin/Devanagari chars)
    m = re.search(
        r'(?i)(?:vill\.?|village|gram|gaon|गाँव|ग्राम)[ \t]*:?[ \t]*([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F0-9.\- \t]{1,40}?)(?=[ \t]*(?:[,;\n|]|\b(?:tehsil|distt?|dist)\b|तहसील|जिला|-)|$)',
        text
    )
    if m:
        ev['village'] = m.group(1).strip()

    # 10. PIN
    m = re.search(r'(?i)(?:pin(?:code)?|पिन|\-)[ \t]*:?[ \t]*([1-9]\d{5})\b', text_norm)
    if m:
        ev['pin'] = m.group(1)

    return ev


def extract_evidence_json(data: dict, path: str = '') -> dict[str, Any]:
    """Extract linkage evidence from a JSON record, nested patient object, or FHIR Bundle."""
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
                    full = f"{given} {family}".strip() or name_obj.get("text", "").strip()
                    if full:
                        ev.setdefault("patient_name", full)
                for telecom in res.get("telecom", []):
                    sys_val = telecom.get("system")
                    val = telecom.get("value")
                    if val:
                        if sys_val == "phone":
                            digits = re.sub(r'\D', '', normalize_text(str(val)))
                            if len(digits) >= 10:
                                ev.setdefault("phone", digits[-10:])
                        elif sys_val == "email":
                            ev.setdefault("email", val)
                for ident in res.get("identifier", []):
                    val = ident.get("value")
                    if val:
                        s_val = normalize_text(str(val))
                        digits = re.sub(r'\D', '', s_val)
                        if RE_ABHA.match(s_val):
                            ev.setdefault("abha", digits)
                        elif len(digits) == 12 and digits[0] in '23456789' and '-' not in s_val and 'jjh' not in s_val.lower():
                            ev.setdefault("aadhaar", digits)
                        else:
                            _add_mrn_to_ev(ev, str(val))
                if res.get("birthDate"):
                    ev.setdefault("dob", str(res["birthDate"]))
                if res.get("gender"):
                    g = _normalize_gender(str(res["gender"]))
                    if g:
                        ev.setdefault("gender", g)
                for addr in res.get("address", []):
                    if isinstance(addr, dict):
                        if addr.get("city"):
                            ev.setdefault("village", addr["city"])
                        if addr.get("postalCode"):
                            ev.setdefault("pin", str(addr["postalCode"]))
                for ext in res.get("extension", []):
                    if isinstance(ext, dict):
                        url_v = str(ext.get("url", "")).lower()
                        val_s = ext.get("valueString")
                        if val_s and any(w in url_v for w in ("mother", "father", "guardian", "relative")):
                            ev.setdefault("relative_name", str(val_s).strip())
        return ev

    # Recurse cleanly on nested dict objects (e.g. dhh_patients.json, lab/report_*.json)
    first_part = ''
    last_part = ''
    local_part = ''
    for k, v in data.items():
        kl = normalize_text(k)
        kl_clean = re.sub(r'[_\-./]', ' ', kl).strip()

        if isinstance(v, dict):
            sub_url = str(v.get('url', '')).lower()
            if kl_clean in ('name', 'patient name', 'patientname'):
                fn = str(v.get('first') or v.get('given') or '').strip()
                ln = str(v.get('last') or v.get('family') or '').strip()
                loc_n = str(v.get('local') or '').strip()
                full = f"{fn} {ln}".strip()
                if full:
                    ev.setdefault('patient_name', full)
                if loc_n:
                    if 'patient_name' not in ev:
                        ev['patient_name'] = loc_n
                    elif normalize_text(loc_n) != normalize_text(ev['patient_name']):
                        ev.setdefault('patient_name_alt', loc_n)
            elif kl_clean in ('guardian', 'relative', 'attendant', 'contact person') or any(w in sub_url for w in ('mother', 'father', 'guardian')):
                rel_n = v.get('name') or v.get('valueString') or v.get('value')
                if isinstance(rel_n, str) and rel_n.strip():
                    ev.setdefault('relative_name', rel_n.strip())
            else:
                sub_ev = extract_evidence_json(v)
                for ek, eval_v in sub_ev.items():
                    if ek == 'mrns':
                        for m_item in eval_v:
                            _add_mrn_to_ev(ev, m_item)
                    else:
                        ev.setdefault(ek, eval_v)
            continue

        h_type = classify_header(k)
        if isinstance(v, str) and v.strip():
            vs = v.strip()
            if h_type == 'PATIENT_NAME' or ('patient' in kl and 'name' in kl):
                if kl_clean in ('first', 'first name', 'firstname', 'given'):
                    first_part = vs
                elif kl_clean in ('last', 'last name', 'lastname', 'family', 'surname'):
                    last_part = vs
                elif kl_clean in ('local', 'local name'):
                    local_part = vs
                else:
                    ev.setdefault('patient_name', vs)
            elif h_type == 'RELATIVE_NAME' or 'relative' in kl:
                ev.setdefault('relative_name', vs)
            elif h_type == 'PHONE' or 'phone' in kl or 'mobile' in kl:
                digits = re.sub(r'\D', '', normalize_text(vs))
                if len(digits) >= 10:
                    ev.setdefault('phone', digits[-10:])
            elif h_type == 'AADHAAR' or 'aadhaar' in kl or 'aadhar' in kl:
                digits = re.sub(r'\D', '', normalize_text(vs))
                if len(digits) == 12:
                    ev.setdefault('aadhaar', digits)
            elif h_type == 'ABHA_NUMBER' or 'abha' in kl:
                ev.setdefault('abha', normalize_text(vs))
            elif h_type == 'MRN' or any(t in kl for t in ('uhid', 'mrn', 'patient_id', 'patient_ref', 'ipd')):
                _add_mrn_to_ev(ev, vs)
            elif h_type == 'EMAIL' or 'email' in kl:
                ev.setdefault('email', vs)
            elif h_type == 'PAN' or kl_clean == 'pan' or 'pan no' in kl_clean:
                ev.setdefault('pan', vs)
            elif h_type == 'INSURANCE_ID':
                ev.setdefault('insurance', vs)
            elif h_type == 'VILLAGE' or any(t in kl_clean for t in ('village', 'gaon', 'city', 'gram')):
                ev.setdefault('village', vs)
            elif h_type == 'PIN' or kl_clean in ('pin', 'pincode', 'postal code', 'zip'):
                pin_d = re.sub(r'\D', '', normalize_text(vs))
                if len(pin_d) == 6:
                    ev.setdefault('pin', pin_d)
            elif h_type == 'DOB' or 'dob' in kl or 'birth' in kl:
                ev.setdefault('dob', normalize_text(vs))
            elif kl_clean == 'age sex' or kl_clean == 'sex':
                g = _normalize_gender(vs)
                if g:
                    ev.setdefault('gender', g)
            elif 'name' in kl and not any(bad in kl for bad in ('doctor', 'hospital', 'lab', 'test', 'drug', 'panel')):
                ev.setdefault('patient_name', vs)
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            if any(t in kl for t in ('age', 'umar')):
                a = _normalize_age(v)
                if a is not None:
                    ev.setdefault('age', str(a))
            elif 'aadhaar' in kl or 'aadhar' in kl:
                d = str(int(v))
                if len(d) == 12:
                    ev.setdefault('aadhaar', d)
            elif 'phone' in kl or 'mobile' in kl:
                d = str(int(v))
                if len(d) >= 10:
                    ev.setdefault('phone', d[-10:])
            elif kl_clean in ('pin', 'pincode', 'postal code', 'zip'):
                d = str(int(v))
                if len(d) == 6:
                    ev.setdefault('pin', d)
        if isinstance(v, str) and v.strip():
            if any(t in kl_clean.split() for t in ('age', 'umar')):
                a = _normalize_age(v)
                if a is not None:
                    ev.setdefault('age', str(a))
            if any(t in kl_clean.split() for t in ('gender', 'sex', 'ling')):
                g = _normalize_gender(v)
                if g:
                    ev.setdefault('gender', g)

        # Free-text notes/remarks fallback
        if isinstance(v, str) and len(v) > 25 and any(t in kl for t in ('note', 'complaint', 'history', 'remark')):
            text_ev = extract_evidence_text(v)
            for ek, ev_val in text_ev.items():
                if ek == 'mrns':
                    for m_item in ev_val:
                        _add_mrn_to_ev(ev, m_item)
                else:
                    ev.setdefault(ek, ev_val)

    if first_part or last_part:
        ev.setdefault('patient_name', f"{first_part} {last_part}".strip())
    if local_part:
        if 'patient_name' not in ev:
            ev['patient_name'] = local_part
        elif normalize_text(local_part) != normalize_text(ev['patient_name']):
            ev.setdefault('patient_name_alt', local_part)

    return ev


# ---------------------------------------------------------------------------
# Filename PII detection and renaming
# ---------------------------------------------------------------------------
def has_pii_in_filename(filename: str) -> bool:
    """Check if a filename contains PII (patient names, MRNs, phone numbers) or trap strings."""
    name = Path(filename).stem
    if re.search(r'(?<!\d)[6-9]\d{9}(?!\d)', name):
        return True
    if re.search(r'(?i)(?:SNJ[-/_]|JJH[-/_]|UHID[-/_]|DHH[-/_]|ADM[-_]?\d+|IPD[-_]|IP[-_]\d+)', name):
        return True
    if re.search(r'(?i)(?:trap[-_]|omega[-_]|token[-_])', name):
        return True
    parts = re.split(r'[_\-\s]', name)
    for part in parts:
        p_lower = part.lower()
        if p_lower in COMMON_INDIAN_NAMES:
            return True
    if re.search(r'(?i)(?:Fatima|Geeta|Kavita|Parvati|Reena|Salma|Shahid|Sunil|Usha|Shabana|Zainab|Farida|Mohammad|Asha|Aneeta|Anita)', name):
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
    name = re.sub(r'(?i)(?:SNJ[-/_]\d{2}[-/_]\d+|JJH[-/_]\d+|UHID[-/_]\d+|DHH[-/_]IPD[-/_][\d-]+|DHH[-/_][\d-]+|ADM[-_]?\d+|IPD[-_][\d-]+|IP[-_]\d+[-_]\d+)',
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
        elif part.lower() in COMMON_INDIAN_NAMES:
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
    ('%m/%d/%Y', re.compile(r'^\d{1,2}/\d{1,2}/\d{4}$')),
    ('%m-%d-%Y', re.compile(r'^\d{1,2}-\d{1,2}-\d{4}$')),
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
        cleaned_h, h_dets = clean_text(h, 'header')
        clean_header.append(cleaned_h)
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
    has_single_subject = isinstance(data, dict) and any(
        isinstance(data.get(k), dict) for k in ("patient", "subject", "demographics")
    )
    has_record_array = isinstance(data, dict) and any(
        isinstance(v, list) and v and all(isinstance(x, dict) for x in v)
        and (
            k.lower() in ("patients", "visits", "records", "results", "entries", "rows", "cases")
            or any(
                ik in x
                for x in v[:3]
                for ik in ("patient_ref", "uhid", "patient_id", "visit_id", "patient_name")
            )
        )
        for k, v in data.items()
    )
    is_doc = not isinstance(data, dict) or is_fhir or has_single_subject or not has_record_array

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
        if '[' in v_low or ']' in v_low:
            continue
        if re.search(r'\b\d{1,4}[/-]\d{1,2}[/-]\d{1,4}\b', v_low) or ('t' in v_low and ':' in v_low) or ('/' in v_low and ':' in v_low):
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
            elif re.search(r'^\d+$', pv):
                if re.search(rf'(?<!\d){re.escape(pv)}(?!\d)', content):
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

