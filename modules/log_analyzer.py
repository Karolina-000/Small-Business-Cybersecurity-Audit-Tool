"""
log_analyzer.py
----------------
Windows Security Event Log-ის ანალიზი pywin32-ის მეშვეობით.

მოთხოვნები სისტემაში:
  - Windows OS
  - pip install pywin32
  - გაშვება ადმინისტრატორის უფლებებით (Security ლოგზე წვდომისთვის)

თუ სკრიპტი გაშვებულია არა-Windows სისტემაზე (მაგ. ტესტირებისთვის Linux/Mac-ზე),
მოდული ავტომატურად გადადის "დემო რეჟიმზე" და აჩვენებს სავარჯიშო მონაცემებს,
რომ დანარჩენი პროგრამის ტესტირება შესაძლებელი იყოს.
"""

import platform
from collections import defaultdict
from datetime import datetime, timedelta

from .risk_assessment import Finding
import config

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import win32evtlog
    import win32evtlogutil
    import win32security


class WindowsLogAnalyzer:
    def __init__(self, server="localhost", log_type="Security"):
        self.server = server
        self.log_type = log_type

    def analyze(self) -> list[Finding]:
        if not IS_WINDOWS:
            return self._demo_mode()

        findings: list[Finding] = []
        events = self._read_events()

        findings.extend(self._check_failed_logins(events))
        findings.extend(self._check_specific_event_ids(events))

        return findings

    # -----------------------------------------------------------
    # რეალური Windows წაკითხვა
    # -----------------------------------------------------------
    def _read_events(self):
        handle = win32evtlog.OpenEventLog(self.server, self.log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = []
        while True:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break
            events.extend(records)
            if len(events) > 5000:  # უსაფრთხო ლიმიტი დიდი ლოგებისთვის
                break
        win32evtlog.CloseEventLog(handle)
        return events

    def _check_failed_logins(self, events) -> list[Finding]:
        findings = []
        failed_by_source = defaultdict(list)

        for ev in events:
            if ev.EventID & 0xFFFF != 4625:  # წარუმატებელი შესვლა
                continue
            source_ip = "უცნობი IP"
            try:
                data = ev.StringInserts
                if data and len(data) > 19:
                    source_ip = data[19]
            except Exception:
                pass
            failed_by_source[source_ip].append(ev.TimeGenerated)

        for source_ip, timestamps in failed_by_source.items():
            timestamps.sort()
            # ვამოწმებთ, ხომ არ მოხდა threshold-ზე მეტი მცდელობა time window-ში
            for i in range(len(timestamps)):
                window_end = timestamps[i] + timedelta(minutes=config.FAILED_LOGIN_WINDOW_MIN)
                count_in_window = sum(1 for t in timestamps if timestamps[i] <= t <= window_end)
                if count_in_window >= config.FAILED_LOGIN_THRESHOLD:
                    findings.append(Finding(
                        category="Windows Logs",
                        title=f"შესაძლო Brute-Force შეტევა — {source_ip}",
                        description=(
                            f"{count_in_window} წარუმატებელი შესვლის მცდელობა "
                            f"{config.FAILED_LOGIN_WINDOW_MIN} წუთში წყაროდან {source_ip}."
                        ),
                        risk_level="High",
                        recommendation=(
                            "დაბლოკეთ წყარო IP firewall-ზე, ჩართეთ account lockout policy "
                            "და გამოიყენეთ Multi-Factor Authentication (MFA)."
                        ),
                        evidence=f"source_ip={source_ip}, attempts={count_in_window}",
                    ))
                    break  # ერთი finding საკმარისია ამ წყაროსთვის

        return findings

    def _check_specific_event_ids(self, events) -> list[Finding]:
        findings = []
        for ev in events:
            event_id = ev.EventID & 0xFFFF
            if event_id not in config.WINDOWS_EVENT_IDS:
                continue

            description = config.WINDOWS_EVENT_IDS[event_id]
            risk = "High" if event_id in (4720, 4732, 1102) else "Medium"

            findings.append(Finding(
                category="Windows Logs",
                title=f"Event ID {event_id}: {description}",
                description=f"დაფიქსირდა {ev.TimeGenerated.Format()} დროს.",
                risk_level=risk,
                recommendation=(
                    "გადაამოწმეთ, არის თუ არა ეს ქმედება ავტორიზებული ადმინისტრატორის მიერ."
                ),
                evidence=f"event_id={event_id}, time={ev.TimeGenerated.Format()}",
            ))

        return findings

    # -----------------------------------------------------------
    # დემო რეჟიმი (არა-Windows გარემოსთვის, ტესტირება/პრეზენტაცია)
    # -----------------------------------------------------------
    def _demo_mode(self) -> list[Finding]:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return [
            Finding(
                category="Windows Logs",
                title="[DEMO] შესაძლო Brute-Force შეტევა — 203.0.113.45",
                description="7 წარუმატებელი შესვლის მცდელობა 10 წუთში (სადემონსტრაციო მონაცემი).",
                risk_level="High",
                recommendation="დაბლოკეთ წყარო IP, ჩართეთ MFA და account lockout policy.",
                evidence="DEMO MODE — გაშვებულია არა-Windows გარემოში",
            ),
            Finding(
                category="Windows Logs",
                title="[DEMO] Event ID 4720: ახალი მომხმარებლის ანგარიში შეიქმნა",
                description=f"დაფიქსირდა {now} (სადემონსტრაციო მონაცემი).",
                risk_level="Medium",
                recommendation="გადაამოწმეთ, ავტორიზებული ადმინისტრატორის მიერ შეიქმნა თუ არა.",
                evidence="DEMO MODE",
            ),
        ]
