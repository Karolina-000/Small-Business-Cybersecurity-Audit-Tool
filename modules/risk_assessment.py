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

    def to_dict(self):
        return {
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "risk_level": self.risk_level,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


# რისკის დონეებს ვანიჭებთ რიცხვით წონას საერთო ქულის დასათვლელად
RISK_WEIGHT = {"Low": 1, "Medium": 3, "High": 5}


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
        self.findings.append(finding)

    def add_many(self, findings: list[Finding]):
        self.findings.extend(findings)

    def summary_counts(self) -> dict:
        counts = {"Low": 0, "Medium": 0, "High": 0}
        for f in self.findings:
            counts[f.risk_level] = counts.get(f.risk_level, 0) + 1
        return counts

    def total_score(self) -> int:
        return sum(RISK_WEIGHT.get(f.risk_level, 0) for f in self.findings)

    def overall_verdict(self) -> str:
        """
        მარტივი ევრისტიკა საბოლოო ვერდიქტისთვის.
        შეგიძლიათ ეს ზღვრები საკუთარი მეთოდოლოგიის მიხედვით შეცვალოთ.
        """
        counts = self.summary_counts()
        if counts["High"] > 0:
            return "კრიტიკული — საჭიროებს დაუყოვნებელ ჩარევას"
        if counts["Medium"] >= 3:
            return "მომატებული რისკი — რეკომენდებულია მალე გამოსწორება"
        if counts["Medium"] > 0 or counts["Low"] > 0:
            return "დამაკმაყოფილებელი — მცირე გაუმჯობესებები საჭიროა"
        return "კარგი — მნიშვნელოვანი პრობლემები არ აღმოჩენილა"

    def findings_by_category(self) -> dict:
        grouped = {}
        for f in self.findings:
            grouped.setdefault(f.category, []).append(f)
        return grouped
