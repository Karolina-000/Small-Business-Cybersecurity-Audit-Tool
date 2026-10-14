"""
file_integrity.py
------------------
ფაილების მთლიანობის (integrity) კონტროლი SHA-256 ჰეშირების გამოყენებით.

ლოგიკა:
  1. პირველი გაშვებისას იქმნება "baseline": ყველა სამიზნე ფაილის
     SHA-256 ჰეში ინახება baseline_hashes.json ფაილში
     (ბრძანება: python main.py --build-baseline).
  2. შემდეგ გაშვებებზე ხდება მიმდინარე ჰეშების შედარება baseline-თან.
     თუ განსხვავებაა: ფაილი შეცვლილია (Finding).
     თუ ფაილი გაქრა: ეს ცალკე Finding-ია (Medium რისკი).
     თუ ახალი ფაილი გამოჩნდა სამიზნე საქაღალდეში: საინფორმაციო Finding.
  3. თუ დაყენებულია გარემოს ცვლადი (config.BASELINE_KEY_ENV), baseline HMAC-ით
     ხელმოწერილია და მისი ხელით შეცვლა აღმოჩნდება.
"""

import hashlib
import hmac
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

    @staticmethod
    def _resolve(target: str) -> str:
        # ფარდობითი ბილიკი პროექტის საქაღალდიდან ითვლება და არა მიმდინარე (CWD) საქაღალდიდან,
        # თორემ სხვა ადგილიდან გაშვებისას ყველა ფაილი "წაშლილი" და "ახალი" გამოჩნდებოდა.
        return os.path.abspath(os.path.join(config.BASE_DIR, target))

    def _collect_files(self) -> list[str]:
        """მხარს უჭერს ცალკეულ ფაილებსაც და საქაღალდეებსაც (რეკურსიულად)."""
        all_files = []
        for target in self.targets:
            path = self._resolve(target)
            if os.path.isfile(path):
                all_files.append(path)
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for name in files:
                        all_files.append(os.path.join(root, name))
        return all_files

    def _hash_files(self, files: list[str]):
        """აბრუნებს (ჰეშები, ფაილები, რომელთა წაკითხვაც ვერ მოხერხდა)."""
        hashes, unreadable = {}, []
        for filepath in files:
            try:
                hashes[filepath] = self._sha256_of_file(filepath)
            except OSError:  # PermissionError, FileNotFoundError და სხვა
                unreadable.append(filepath)
        return hashes, unreadable

    # -----------------------------------------------------------
    # baseline-ის შენახვა/ჩატვირთვა (არასავალდებულო HMAC ხელმოწერით)
    # -----------------------------------------------------------
    @staticmethod
    def _key():
        key = os.environ.get(config.BASELINE_KEY_ENV, "")
        return key.encode("utf-8") if key else None

    @staticmethod
    def _sign(hashes: dict, key: bytes) -> str:
        payload = json.dumps(hashes, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    def _save_baseline(self, hashes: dict):
        data = {"hashes": hashes}
        key = self._key()
        if key:
            data["hmac"] = self._sign(hashes, key)
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _load_baseline(self):
        """
        აბრუნებს (hashes, problem).
          hashes  = None, თუ baseline-ის ფაილი საერთოდ არ არსებობს
          problem = None | "corrupt" (ვერ იკითხება) | "tampered" (ხელმოწერა არასწორია)
        """
        if not os.path.exists(self.baseline_path):
            return None, None
        try:
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {}, "corrupt"
        if not isinstance(data, dict):
            return {}, "corrupt"

        # ახალი ფორმატი: {"hashes": {...}, "hmac": "..."}; ძველი: პირდაპირ {ბილიკი: ჰეში}
        if isinstance(data.get("hashes"), dict):
            hashes, signature = data["hashes"], data.get("hmac")
        else:
            hashes, signature = data, None

        key = self._key()
        if key and not (signature and hmac.compare_digest(signature, self._sign(hashes, key))):
            return hashes, "tampered"
        return hashes, None

    def build_baseline(self) -> dict:
        """ქმნის ან განაახლებს baseline-ს. გამოიყენეთ პირველი გაშვებისას."""
        hashes, _unreadable = self._hash_files(self._collect_files())
        self._save_baseline(hashes)
        return hashes

    def check(self) -> list[Finding]:
        findings: list[Finding] = []
        baseline, problem = self._load_baseline()

        if baseline is None:
            findings.append(Finding(
                category="File Integrity",
                title="Baseline არ არსებობს",
                description=(
                    "ფაილების მთლიანობის შესამოწმებლად საჭიროა თავდაპირველი baseline. "
                    "შექმენით ის პირველად, სანდო მდგომარეობაში მყოფ სისტემაზე."
                ),
                risk_level="Low",
                recommendation="გაუშვით `python main.py --build-baseline` პირველი კონფიგურაციისას.",
            ))
            return findings

        if problem == "corrupt":
            findings.append(Finding(
                category="File Integrity",
                title="Baseline ფაილი დაზიანებულია ან ვერ იკითხება",
                description="baseline_hashes.json ვერ ჩაიტვირთა, ამიტომ შედარება შეუძლებელია.",
                risk_level="Medium",
                recommendation="თუ ფაილი თქვენ არ შეგიცვლიათ, გამოიძიეთ; შემდეგ თავიდან შექმენით baseline.",
            ))
            return findings

        if problem == "tampered":
            findings.append(Finding(
                category="File Integrity",
                title="Baseline-ის ხელმოწერა არასწორია",
                description=(
                    "baseline_hashes.json შეცვლილია სანდო გარემოს გარეთ ან გასაღები არ ემთხვევა. "
                    "შედარება არასანდოა და არ შესრულდა."
                ),
                risk_level="High",
                recommendation="გამოიძიეთ, ვინ შეცვალა baseline; სანდო სისტემაზე თავიდან შექმენით ის.",
            ))
            return findings

        if not baseline:
            findings.append(Finding(
                category="File Integrity",
                title="Baseline ცარიელია",
                description="baseline არსებობს, მაგრამ ერთი ფაილიც არ შეიცავს (სამიზნე ფაილები ვერ მოიძებნა).",
                risk_level="Low",
                recommendation="შეამოწმეთ FILE_INTEGRITY_TARGETS config.py-ში და თავიდან შექმენით baseline.",
            ))
            return findings

        current_files = self._collect_files()
        current_hashes, unreadable = self._hash_files(current_files)

        # 0) ფაილები, რომელთა წაკითხვაც ვერ მოხერხდა (ადრე ჩუმად გამოიტოვებოდა)
        for filepath in unreadable:
            findings.append(Finding(
                category="File Integrity",
                title=f"ფაილის წაკითხვა ვერ მოხერხდა: {filepath}",
                description="უფლებების ან წვდომის პრობლემის გამო მთლიანობა ვერ შემოწმდა.",
                risk_level="Medium",
                recommendation="გაუშვით ადმინისტრატორის უფლებებით ან გადაამოწმეთ ფაილის წვდომის პარამეტრები.",
            ))

        baseline_files = set(baseline.keys())
        existing_files = set(current_files)              # არსებული ფაილები (წაკითხვადიც და არაწაკითხვადიც)
        readable_files = set(current_hashes.keys())

        # 1) შეცვლილი ფაილები
        for filepath in baseline_files & readable_files:
            if baseline[filepath] != current_hashes[filepath]:
                findings.append(Finding(
                    category="File Integrity",
                    title=f"ფაილი შეცვლილია: {filepath}",
                    description=(
                        "SHA-256 ჰეში არ ემთხვევა baseline-ს: ფაილის შემცველობა შეიცვალა."
                    ),
                    risk_level="High",
                    recommendation=(
                        "გადაამოწმეთ ცვლილება ავტორიზებული პროცესის ლოგებთან. "
                        "საეჭვო შემთხვევაში ჩაატარეთ malware სკანირება."
                    ),
                    evidence=f"baseline_hash={baseline[filepath][:16]}..., "
                             f"current_hash={current_hashes[filepath][:16]}...",
                ))

        # 2) წაშლილი/გაქრობილი ფაილები (წაუკითხავი ფაილი არ ითვლება წაშლილად)
        for filepath in baseline_files - existing_files:
            findings.append(Finding(
                category="File Integrity",
                title=f"ფაილი აღარ არსებობს: {filepath}",
                description="ფაილი, რომელიც baseline-ში იყო, ამჟამად ვერ მოიძებნა.",
                risk_level="Medium",
                recommendation="დაადასტურეთ, გამიზნულად წაიშალა თუ არა ეს ფაილი.",
            ))

        # 3) ახალი ფაილები (საინფორმაციო)
        for filepath in readable_files - baseline_files:
            findings.append(Finding(
                category="File Integrity",
                title=f"ახალი ფაილი აღმოჩენილია: {filepath}",
                description="ეს ფაილი baseline-ის შექმნის დროს არ არსებობდა.",
                risk_level="Low",
                recommendation="დარწმუნდით, რომ ფაილი ლეგიტიმურია და საჭიროების შემთხვევაში განაახლეთ baseline.",
            ))

        return findings
