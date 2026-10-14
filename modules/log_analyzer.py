"""
log_analyzer.py
----------------
Windows Security Event Log-ის ანალიზი pywin32-ის მეშვეობით.

მოთხოვნები სისტემაში:
  - Windows OS
  - pip install pywin32
  - გაშვება ადმინისტრატორის უფლებებით (Security ლოგზე წვდომისთვის)

არა-Windows სისტემაზე მოდული გამოტოვებულია (შეცდომის შეტყობინებით).
სადემონსტრაციო (ყალბი) მონაცემები მხოლოდ მაშინ ბრუნდება, როცა პირდაპირ
მოთხოვნილია ალამით: python main.py --demo
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
    def __init__(self, server="localhost", log_type="Security", demo=False):
        self.server = server
        self.log_type = log_type
        self.demo = demo  # True მხოლოდ --demo ალმით: აბრუნებს სადემონსტრაციო (ყალბ) მონაცემებს

    def analyze(self) -> list[Finding]:
        # დემო მონაცემები მხოლოდ მაშინ, როცა მომხმარებელმა პირდაპირ მოითხოვა.
        # ადრე არა-Windows სისტემაზე ყალბი brute-force რეალურ ანგარიშში ხვდებოდა.
        if self.demo:
            return self._demo_mode()
        if not IS_WINDOWS:
            raise RuntimeError(
                "Windows Event Log მხოლოდ Windows-ზეა ხელმისაწვდომი. "
                "მოდული გამოტოვებულია (სადემონსტრაციოდ გამოიყენეთ --demo)."
            )

        findings: list[Finding] = []
        # მხოლოდ ბოლო N დღის მოვლენები (წინააღმდეგ შემთხვევაში წლების წინანდელი
        # მოვლენაც "ახალ" Finding-ად ჩაითვლებოდა)
        cutoff = datetime.now() - timedelta(days=config.LOG_LOOKBACK_DAYS)
        events = [ev for ev in self._read_events() if self._event_time(ev) >= cutoff]

        findings.extend(self._check_failed_logins(events))
        findings.extend(self._check_specific_event_ids(events))

        return findings

    @staticmethod
    def _event_time(ev) -> datetime:
        """აქცევს ლოგის დროს ჩვეულებრივ datetime-ად (სხვადასხვა pywin32 ვერსიაში ტიპი განსხვავდება)."""
        t = ev.TimeGenerated
        return datetime(t.year, t.month, t.day, t.hour, t.minute, t.second)

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
            # 4625-ს (წარუმატებელი შესვლა) ცალკე Finding აღარ ვუკეთებთ: ის ერთიანად
            # მუშავდება _check_failed_logins-ში, თორემ 200 მცდელობა = 200 Finding იქნებოდა
            if event_id == 4625 or event_id not in config.WINDOWS_EVENT_IDS:
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
