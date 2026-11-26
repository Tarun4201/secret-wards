"""RAKSHA Voter Registry Attacker

Evaluates re-identification risk against sanitized health records using an external
auxiliary voter list / population registry.
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class VoterProfile:
    id: str
    name: str
    age: int
    gender: str
    village: str
    pin: str
    phone: str
    relative_name: str = ""


@dataclass
class AttackResult:
    total_targets: int
    uniquely_reidentified: int
    ambiguous_matches: int
    direct_leaks_found: int
    reidentification_rate: float
    direct_leak_rate: float


class VoterRegisterAttacker:
    """Attacker model holding voter registry records and attacking sanitized outputs."""

    def __init__(self, voter_registry: list[VoterProfile] | None = None):
        self.registry: list[VoterProfile] = voter_registry or []

    def load_registry_csv(self, path: Path) -> None:
        """Load voter registry targets from a CSV file."""
        self.registry = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                self.registry.append(
                    VoterProfile(
                        id=row.get("id", f"VOTER_{i}"),
                        name=row.get("name", "").strip(),
                        age=int(row.get("age", 0)) if row.get("age", "").isdigit() else 0,
                        gender=row.get("gender", "").strip().upper(),
                        village=row.get("village", "").strip(),
                        pin=row.get("pin", "").strip(),
                        phone=row.get("phone", "").strip(),
                        relative_name=row.get("relative_name", "").strip(),
                    )
                )

    def attack_directory(self, san_dir: Path) -> AttackResult:
        """Attack all sanitized files in a directory."""
        if not self.registry:
            return AttackResult(0, 0, 0, 0, 0.0, 0.0)

        # 1. Read all sanitized files content
        san_texts: list[tuple[str, str]] = []  # (filename, text)
        for p in san_dir.rglob("*"):
            if p.is_file():
                try:
                    san_texts.append((p.name, p.read_text(encoding="utf-8", errors="ignore")))
                except Exception:
                    pass

        uniquely_identified = 0
        ambiguous = 0
        direct_leaks = 0

        # Precompile patterns for fast lookup
        for target in self.registry:
            target_direct_leak = False

            # Check direct identifier leaks (Full name, Phone number)
            target_name_lower = target.name.lower()
            name_parts = [p for p in target_name_lower.split() if len(p) > 2]
            target_phone = target.phone.replace("-", "").replace(" ", "")

            for fname, text in san_texts:
                text_lower = text.lower()

                # Check phone leak
                if len(target_phone) >= 10 and target_phone in text:
                    target_direct_leak = True
                    break

                # Check full name leak (multi-word match)
                if len(name_parts) >= 2 and all(part in text_lower for part in name_parts):
                    target_direct_leak = True
                    break

            if target_direct_leak:
                direct_leaks += 1
                uniquely_identified += 1
                continue

            # Check quasi-identifier matching:
            # An attacker tries to match (Age in age-band, Location/PIN prefix, Gender)
            candidate_matches = 0
            for fname, text in san_texts:
                # Find age bands in text: e.g. [40-44], [40-49]
                age_bands = re.findall(r'\[(\d{1,3})-(\d{1,3})\]', text)
                age_matched = False
                for lo, hi in age_bands:
                    if int(lo) <= target.age <= int(hi):
                        age_matched = True
                        break

                # Location match
                loc_matched = False
                if target.pin and len(target.pin) >= 3:
                    pin_prefix = target.pin[:3]
                    if pin_prefix in text:
                        loc_matched = True
                if target.village and target.village.lower() in text.lower():
                    loc_matched = True

                if age_matched and loc_matched:
                    candidate_matches += 1

            if candidate_matches == 1:
                uniquely_identified += 1
            elif candidate_matches > 1:
                ambiguous += 1

        total = len(self.registry)
        reid_rate = round(uniquely_identified / total, 4) if total > 0 else 0.0
        leak_rate = round(direct_leaks / total, 4) if total > 0 else 0.0

        return AttackResult(
            total_targets=total,
            uniquely_reidentified=uniquely_identified,
            ambiguous_matches=ambiguous,
            direct_leaks_found=direct_leaks,
            reidentification_rate=reid_rate,
            direct_leak_rate=leak_rate,
        )
