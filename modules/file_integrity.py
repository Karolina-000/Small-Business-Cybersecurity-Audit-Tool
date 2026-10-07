"""
file_integrity.py
------------------
ფაილების მთლიანობის (integrity) კონტროლი SHA-256 ჰეშირების გამოყენებით.

ლოგიკა:
  1. პირველი გაშვებისას იქმნება "baseline" — ყველა სამიზნე ფაილის
     SHA-256 ჰეში ინახება baseline_hashes.json ფაილში.
  2. შემდეგ გაშვებებზე ხდება მიმდინარე ჰეშების შედარება baseline-თან.
     თუ განსხვავებაა — ფაილი შეცვლილია (Finding).
     თუ ფაილი გაქრა — ეს ცალკე Finding-ია (Medium/High რისკი).
     თუ ახალი ფაილი გამოჩნდა სამიზნე საქაღალდეში — საინფორმაციო Finding.
"""

import hashlib
import json
import os

from .risk_assessment import Finding
import config


class FileIntegrityChecker:
    def __init__(self, targets=None, baseline_path=None):
        self.targets = targets or config.FILE_INTEGRITY_TARGETS
        self.baseline_path = baseline_path or config.BASELINE_HASH_FILE

    @staticmethod
    def _sha256_of_file(filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _collect_files(self) -> list[str]:
        """მხარს უჭერს ცალკეულ ფაილებსაც და საქაღალდეებსაც (რეკურსიულად)."""
        all_files = []
        for target in self.targets:
            if os.path.isfile(target):
                all_files.append(target)
            elif os.path.isdir(target):
                for root, _, files in os.walk(target):
                    for name in files:
                        all_files.append(os.path.join(root, name))
        return all_files

    def _load_baseline(self) -> dict:
        if os.path.exists(self.baseline_path):
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _save_baseline(self, hashes: dict):
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(hashes, f, indent=2, ensure_ascii=False)

    def build_baseline(self) -> dict:
        """ქმნის ან განაახლებს baseline-ს — გამოიყენეთ პირველი გაშვებისას."""
        files = self._collect_files()
        hashes = {}
        for filepath in files:
            try:
                hashes[filepath] = self._sha256_of_file(filepath)
            except (PermissionError, FileNotFoundError):
                continue
        self._save_baseline(hashes)
        return hashes

    def check(self) -> list[Finding]:
        findings: list[Finding] = []
        baseline = self._load_baseline()

        if not baseline:
            findings.append(Finding(
                category="File Integrity",
                title="Baseline არ არსებობს",
                description=(
                    "ფაილების მთლიანობის შესამოწმებლად საჭიროა თავდაპირველი baseline. "
                    "გაუშვით build_baseline() პირველად, სანდო მდგომარეობაში მყოფ სისტემაზე."
                ),
                risk_level="Low",
                recommendation="გაუშვით `FileIntegrityChecker().build_baseline()` პირველი კონფიგურაციისას.",
            ))
            return findings

        current_files = self._collect_files()
        current_hashes = {}
        for filepath in current_files:
            try:
                current_hashes[filepath] = self._sha256_of_file(filepath)
            except (PermissionError, FileNotFoundError):
                continue

        baseline_files = set(baseline.keys())
        current_files_set = set(current_hashes.keys())

        # 1) შეცვლილი ფაილები
        for filepath in baseline_files & current_files_set:
            if baseline[filepath] != current_hashes[filepath]:
                findings.append(Finding(
                    category="File Integrity",
                    title=f"ფაილი შეცვლილია: {filepath}",
                    description=(
                        "SHA-256 ჰეში არ ემთხვევა baseline-ს — ფაილის შემცველობა შეიცვალა."
                    ),
                    risk_level="High",
                    recommendation=(
                        "გადაამოწმეთ ცვლილება ავტორიზებული პროცესის ლოგებთან. "
                        "საეჭვო შემთხვევაში ჩაატარეთ malware სკანირება."
                    ),
                    evidence=f"baseline_hash={baseline[filepath][:16]}..., "
                             f"current_hash={current_hashes[filepath][:16]}...",
                ))

        # 2) წაშლილი/გაქრობილი ფაილები
        for filepath in baseline_files - current_files_set:
            findings.append(Finding(
                category="File Integrity",
                title=f"ფაილი აღარ არსებობს: {filepath}",
                description="ფაილი, რომელიც baseline-ში იყო, ამჟამად ვერ მოიძებნა.",
                risk_level="Medium",
                recommendation="დაადასტურეთ, გამიზნულად წაიშალა თუ არა ეს ფაილი.",
            ))

        # 3) ახალი ფაილები (საინფორმაციო)
        for filepath in current_files_set - baseline_files:
            findings.append(Finding(
                category="File Integrity",
                title=f"ახალი ფაილი აღმოჩენილია: {filepath}",
                description="ეს ფაილი baseline-ის შექმნის დროს არ არსებობდა.",
                risk_level="Low",
                recommendation="დარწმუნდით, რომ ფაილი ლეგიტიმურია და საჭიროების შემთხვევაში დაამატეთ baseline-ს.",
            ))

        return findings
