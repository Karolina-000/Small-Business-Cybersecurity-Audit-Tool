"""
network_scanner.py
-------------------
ახორციელებს ქსელის/ჰოსტების სკანირებას Nmap-ის მეშვეობით (python-nmap
ბიბლიოთეკა) და აგენერირებს Finding-ებს ღია პორტებზე.

მოთხოვნები სისტემაში:
  - დაინსტალირებული Nmap (https://nmap.org/download.html)
  - pip install python-nmap

⚠️ მნიშვნელოვანი: სკანირება ჩაატარეთ მხოლოდ იმ ქსელზე/მოწყობილობებზე,
რომელთა სკანირების ნებართვაც გაქვთ. არაავტორიზებული სკანირება
შეიძლება იყოს კანონდარღვევა.
"""

import nmap

from .risk_assessment import Finding
import config


class NetworkScanner:
    def __init__(self, targets=None, arguments=None):
        self.targets = targets or config.NETWORK_TARGETS
        self.arguments = arguments or config.NMAP_ARGUMENTS
        self.scanner = nmap.PortScanner()

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        for target in self.targets:
            try:
                self.scanner.scan(hosts=target, arguments=self.arguments)
            except Exception as e:
                findings.append(Finding(
                    category="Network",
                    title=f"სკანირება ვერ შესრულდა: {target}",
                    description=f"Nmap-ის შეცდომა: {e}",
                    risk_level="Low",
                    recommendation="შეამოწმეთ Nmap-ის ინსტალაცია და სამიზნის ხელმისაწვდომობა.",
                ))
                continue

            for host in self.scanner.all_hosts():
                host_info = self.scanner[host]
                state = host_info.state()

                for proto in host_info.all_protocols():
                    ports = host_info[proto].keys()
                    for port in sorted(ports):
                        port_data = host_info[proto][port]
                        if port_data.get("state") != "open":
                            continue

                        service = port_data.get("name", "უცნობი სერვისი")
                        product = port_data.get("product", "")
                        version = port_data.get("version", "")
                        service_str = f"{service} {product} {version}".strip()

                        findings.append(self._evaluate_port(host, port, proto, service_str))

        return findings

    def _evaluate_port(self, host, port, proto, service_str) -> Finding:
        if port in config.HIGH_RISK_PORTS:
            risk = "High"
            reason = config.HIGH_RISK_PORTS[port]
            recommendation = (
                f"დახურეთ ან შეზღუდეთ პორტი {port}/{proto} firewall-ის დონეზე, "
                f"თუ ის აუცილებელი არ არის ბიზნეს პროცესისთვის. "
                f"საჭიროების შემთხვევაში გამოიყენეთ VPN ან IP whitelisting."
            )
        elif port in config.MEDIUM_RISK_PORTS:
            risk = "Medium"
            reason = config.MEDIUM_RISK_PORTS[port]
            recommendation = (
                f"დარწმუნდით, რომ {port}/{proto} სერვისზე გამოყენებულია ძლიერი "
                f"ავთენტიფიკაცია და უახლესი, დაპატჩული ვერსია."
            )
        else:
            risk = "Low"
            reason = "სტანდარტული/ნაკლებად სარისკო სერვისი"
            recommendation = "პერიოდულად აკონტროლეთ, რომ სერვისი განახლებული იყოს."

        return Finding(
            category="Network",
            title=f"ღია პორტი {port}/{proto} ჰოსტზე {host}",
            description=f"სერვისი: {service_str or 'უცნობი'}. მიზეზი: {reason}",
            risk_level=risk,
            recommendation=recommendation,
            evidence=f"host={host}, port={port}/{proto}, service={service_str}",
        )
