#!/usr/bin/env python3
"""Generates 50,000 synthetic Indian hospital records across 50 files

for high-volume stress testing.
"""
import random
from pathlib import Path

FIRST_NAMES = [
    "Aarav",
    "Aditi",
    "Amit",
    "Ananya",
    "Arjun",
    "Deepak",
    "Divya",
    "Kavita",
    "Manoj",
    "Meera",
    "Mohit",
    "Neha",
    "Pooja",
    "Priya",
    "Rahul",
    "Rajesh",
    "Ravi",
    "Rekha",
    "Ritu",
    "Rohit",
    "Sanjay",
    "Shikha",
    "Sneha",
    "Sunita",
    "Suresh",
    "Swati",
    "Vikas",
    "Vikram",
    "Vivek",
    "Zoya",
]

LAST_NAMES = [
    "Agarwal",
    "Bose",
    "Chauhan",
    "Das",
    "Gupta",
    "Jha",
    "Joshi",
    "Khan",
    "Kumar",
    "Malhotra",
    "Mehta",
    "Mishra",
    "Mukherjee",
    "Nair",
    "Pandey",
    "Patel",
    "Reddy",
    "Roy",
    "Saxena",
    "Sen",
    "Sharma",
    "Singh",
    "Srivastava",
    "Tiwari",
    "Tripathi",
    "Varma",
    "Verma",
    "Yadav",
]

VILLAGES = [
    "Baragaon",
    "Bhawan",
    "Balamau",
    "Kachhauna",
    "Madhoganj",
    "Mallawan",
    "Pihani",
    "Sandila",
    "Shahabad",
    "Tandiyawan",
    "Hardoi",
    "Bilgram",
]

DIAGNOSES = [
    "Type 2 Diabetes Mellitus",
    "Essential Hypertension",
    "Acute Gastritis",
    "Typhoid Fever",
    "Malaria (P. vivax)",
    "Dengue Fever",
    "Bronchial Asthma",
    "Urinary Tract Infection",
    "Chronic Kidney Disease",
    "Acute Appendicitis",
]

MEDICINES = [
    "Tab Metformin 500mg BD",
    "Tab Amlodipine 5mg OD",
    "Tab Pantoprazole 40mg OD",
    "Tab Paracetamol 650mg TDS",
    "Tab Azithromycin 500mg OD x 5 days",
    "Tab Pan-D 1-0-0",
    "Tab Telma 40mg OD",
    "Tab Combiflam 1-0-1",
    "Syp Cefixime 100mg BD",
    "Inj Ceftriaxone 1g IV BD",
]


def generate_batch(output_dir: Path, num_files: int = 50, rows_per_file: int = 1000):
    output_dir.mkdir(parents=True, exist_ok=True)
    random.seed(42)

    total_records = 0
    for f_idx in range(num_files):
        filename = output_dir / f"hospital_batch_{f_idx + 1:02d}.csv"
        lines = [
            "uhid,patient_name,relative_name,age,gender,phone,aadhaar,village,pin_code,admission_date,discharge_date,diagnosis,prescription"
        ]

        for r_idx in range(rows_per_file):
            pid = (f_idx * rows_per_file + r_idx) % 15000  # Creates natural cross-file repeat patients
            fn = FIRST_NAMES[pid % len(FIRST_NAMES)]
            ln = LAST_NAMES[(pid // len(FIRST_NAMES)) % len(LAST_NAMES)]
            name = f"{fn} {ln}"
            rel_type = random.choice(["S/o", "D/o", "W/o"])
            rel_name = f"{rel_type} {random.choice(FIRST_NAMES)} {ln}"
            age = 18 + (pid % 65)
            gender = "M" if (pid % 2 == 0) else "F"
            phone = f"98{pid % 100000000:08d}"
            aadhaar = f"2{pid % 100000000000:011d}"
            aadhaar_fmt = f"{aadhaar[:4]} {aadhaar[4:8]} {aadhaar[8:12]}"
            village = random.choice(VILLAGES)
            pin = f"241{100 + (pid % 899):03d}"
            adm = f"{1 + (pid % 25):02d}/{1 + (pid % 11):02d}/2024"
            dis = f"{5 + (pid % 25):02d}/{1 + (pid % 11):02d}/2024"
            diag = random.choice(DIAGNOSES)
            rx = random.choice(MEDICINES)

            lines.append(
                f"HOSP/{pid:06d},{name},{rel_name},{age},{gender},{phone},{aadhaar_fmt},{village},{pin},{adm},{dis},{diag},{rx}"
            )
            total_records += 1

        filename.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(
        f"Generated {total_records} records across {num_files} files in {output_dir}"
    )


if __name__ == "__main__":
    generate_batch(Path("stress_50k_input"), num_files=50, rows_per_file=1000)
