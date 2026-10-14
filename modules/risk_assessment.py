"""
risk_assessment.py
-------------------
საერთო "Finding" (ნაპოვნი პრობლემა) მოდელი და risk-ის დათვლის ლოგიკა.
ყველა სხვა მოდული (network_scanner, log_analyzer, file_integrity,
website_checker) ამ კლასის ობიექტებს აგენერირებს, რომ report_generator-მა
ერთნაირად შეძლოს მათი დამუშავება.
"""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Finding:
    """ერთი კონკრეტული პრობლემა/დაკვირვება აუდიტში."""
    category: str          # მაგ: "Network", "Windows Logs", "File Integrity", "Website"
    title: str             # მოკლე სათაური
    description: str       # დეტალური აღწერა
    risk_level: str        # "Low" | "Medium" | "High"
    recommendation: str    # რეკომენდაცია გამოსწორებისთვის
    evidence: str = ""     # დამატებითი მტკიცებულება (log line, port, url და ა.შ.)
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    note: str = ""                 # განმარტება, თუ რისკი კონტექსტის გამო შეიცვალა
    original_risk_level: str = ""  # თავდაპირველი რისკი (თუ შეიცვალა)
    port: int | None = None        # ქსელის Finding-ებისთვის: პორტის ნომერი (ახსნის სწორი შესაბამისობისთვის)

    def to_dict(self):
        return {
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "risk_level": self.risk_level,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "note": self.note,
            "original_risk_level": self.original_risk_level,
            "port": self.port,
        }


# საერთო ქულა 0-100 სკალაზეა. თითოეულ დონეს აქვს ქულა თითო Finding-ზე და ზედა ზღვარი,
# რომ 40 უწყინარმა Low Finding-მა ერთ რეალურ პრობლემას არ გადააჭარბოს.
SCORE_POINTS = {"High": 25, "Medium": 9, "Low": 1}
SCORE_CAPS = {"High": 100, "Medium": 45, "Low": 10}

LOCAL_NOTE = "ეს თქვენი კომპიუტერის შიდა შემოწმებაა და გარედან არ ჩანს, ამიტომ რისკი დაბალია."


def adjust_for_context(finding: Finding) -> Finding:
    """
    ასწორებს რისკს რეალური კონტექსტის მიხედვით (ადრე ეს მხოლოდ ანგარიშში ხდებოდა,
    ამიტომ კონსოლი და ანგარიში ერთმანეთს ეწინააღმდეგებოდა). ახლა ერთადერთი ადგილია,
    სადაც რისკი იცვლება, და ქულაც, ვერდიქტიც და ანგარიშიც ერთსა და იმავეს იყენებს.
    """
    text = f"{finding.title} {finding.description} {finding.evidence}".lower()
    category = finding.category.lower()
    is_local = "127.0.0.1" in text or "localhost" in text

    if is_local and "network" in category:
        finding.original_risk_level = finding.original_risk_level or finding.risk_level
        finding.risk_level = "Low"
        finding.note = LOCAL_NOTE
    elif "file" in category and finding.risk_level == "High":
        finding.original_risk_level = finding.original_risk_level or finding.risk_level
        finding.risk_level = "Medium"
    return finding


class RiskAssessor:
    """
    აგროვებს ყველა Finding-ს სხვადასხვა მოდულიდან და ითვლის:
      - საერთო რისკის ქულას
      - რისკის დონეების განაწილებას (რამდენი Low/Medium/High)
      - საბოლოო ვერდიქტს ბიზნესისთვის
    """

    def __init__(self):
        self.findings: list[Finding] = []

    def add(self, finding: Finding):
        self.findings.append(adjust_for_context(finding))

    def add_many(self, findings: list[Finding]):
        for finding in findings:
            self.add(finding)

    def summary_counts(self) -> dict:
        counts = {"Low": 0, "Medium": 0, "High": 0}
        for f in self.findings:
            counts[f.risk_level] = counts.get(f.risk_level, 0) + 1
        return counts

    def total_score(self) -> int:
        """რისკის ქულა 0-100. თითო დონის წვლილი შეზღუდულია (იხ. SCORE_CAPS)."""
        counts = self.summary_counts()
        total = sum(
            min(counts[level] * SCORE_POINTS[level], SCORE_CAPS[level])
            for level in SCORE_POINTS
        )
        return min(100, total)

    def overall_verdict(self) -> str:
        """
        ვერდიქტი ქულაზეა დამოკიდებული და არა იმაზე, არის თუ არა ერთი High მაინც.
        (კონტექსტს, მაგ. localhost, adjust_for_context უკვე ითვალისწინებს.)
        ზღვრები შეგიძლიათ საკუთარი მეთოდოლოგიის მიხედვით შეცვალოთ.
        """
        score = self.total_score()
        if score >= 50:
            return "კრიტიკული — საჭიროებს დაუყოვნებელ ჩარევას"
        if score >= 25:
            return "მომატებული რისკი — რეკომენდებულია მალე გამოსწორება"
        if score > 0:
            return "დამაკმაყოფილებელი — მცირე გაუმჯობესებები საჭიროა"
        return "კარგი — მნიშვნელოვანი პრობლემები არ აღმოჩენილა"

    def findings_by_category(self) -> dict:
        grouped = {}
        for f in self.findings:
            grouped.setdefault(f.category, []).append(f)
        return grouped
