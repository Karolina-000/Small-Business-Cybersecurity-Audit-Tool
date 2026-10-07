"""
website_checker.py
-------------------
ვებსაიტის საბაზისო უსაფრთხოების შემოწმება:
  - HTTPS-ის გამოყენება (HTTP -> HTTPS გადამისამართება)
  - მნიშვნელოვანი Security Headers-ის არსებობა
  - SSL სერტიფიკატის ვადის გასვლის თარიღი

მოთხოვნები: pip install requests

⚠️ შეამოწმეთ მხოლოდ საკუთარი ან წერილობით ავტორიზებული საიტები.
"""

import socket
import ssl
from datetime import datetime

import requests

from .risk_assessment import Finding
import config


class WebsiteChecker:
    def __init__(self, targets=None, timeout=10):
        self.targets = targets or config.WEBSITE_TARGETS
        self.timeout = timeout

    def check_all(self) -> list[Finding]:
        findings: list[Finding] = []
        for url in self.targets:
            findings.extend(self._check_single(url))
        return findings

    def _check_single(self, url: str) -> list[Finding]:
        findings = []

        findings.extend(self._check_https_redirect(url))
        findings.extend(self._check_headers(url))
        findings.extend(self._check_ssl_expiry(url))

        return findings

    # -----------------------------------------------------------
    def _check_https_redirect(self, url: str) -> list[Finding]:
        findings = []
        if url.startswith("https://"):
            http_version = url.replace("https://", "http://", 1)
            try:
                resp = requests.get(http_version, timeout=self.timeout, allow_redirects=False)
                if resp.status_code not in (301, 302, 307, 308) or "https://" not in resp.headers.get("Location", ""):
                    findings.append(Finding(
                        category="Website",
                        title=f"HTTP → HTTPS გადამისამართება არასწორია: {url}",
                        description="საიტი არ ახორციელებს სავალდებულო გადამისამართებას HTTPS-ზე.",
                        risk_level="Medium",
                        recommendation="დააკონფიგურირეთ სერვერზე 301 რედირექტი HTTP-დან HTTPS-ზე.",
                    ))
            except requests.RequestException:
                pass  # HTTP შეიძლება საერთოდ დახურული იყოს, რაც კარგია
        else:
            findings.append(Finding(
                category="Website",
                title=f"საიტი არ იყენებს HTTPS-ს: {url}",
                description="მონაცემები გადაიცემა დაუშიფრავად.",
                risk_level="High",
                recommendation="დააყენეთ SSL/TLS სერტიფიკატი (მაგ. Let's Encrypt) და გადაიყვანეთ საიტი HTTPS-ზე.",
            ))
        return findings

    # -----------------------------------------------------------
    def _check_headers(self, url: str) -> list[Finding]:
        findings = []
        try:
            resp = requests.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            findings.append(Finding(
                category="Website",
                title=f"საიტთან დაკავშირება ვერ მოხერხდა: {url}",
                description=f"შეცდომა: {e}",
                risk_level="Low",
                recommendation="შეამოწმეთ URL-ის სისწორე და სერვერის ხელმისაწვდომობა.",
            ))
            return findings

        for header in config.REQUIRED_SECURITY_HEADERS:
            if header not in resp.headers:
                findings.append(Finding(
                    category="Website",
                    title=f"აკლია Security Header: {header}",
                    description=f"{url} პასუხში არ არის '{header}' header.",
                    risk_level="Medium",
                    recommendation=f"დაამატეთ '{header}' header ვებ-სერვერის ან აპლიკაციის კონფიგურაციაში.",
                    evidence=f"url={url}",
                ))
        return findings

    # -----------------------------------------------------------
    def _check_ssl_expiry(self, url: str) -> list[Finding]:
        findings = []
        if not url.startswith("https://"):
            return findings

        hostname = url.replace("https://", "").split("/")[0]
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            expire_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.now()).days

            if days_left < 0:
                findings.append(Finding(
                    category="Website",
                    title=f"SSL სერტიფიკატის ვადა გასულია: {hostname}",
                    description=f"სერტიფიკატი ამოიწურა {expire_date.date()}-ს.",
                    risk_level="High",
                    recommendation="დაუყოვნებლივ განაახლეთ SSL სერტიფიკატი.",
                ))
            elif days_left <= config.SSL_EXPIRY_WARNING_DAYS:
                findings.append(Finding(
                    category="Website",
                    title=f"SSL სერტიფიკატის ვადა მალე იწურება: {hostname}",
                    description=f"დარჩენილია {days_left} დღე (ამოწურვა: {expire_date.date()}).",
                    risk_level="Medium",
                    recommendation="დაგეგმეთ სერტიფიკატის განახლება ვადის ამოწურვამდე.",
                ))
        except Exception as e:
            findings.append(Finding(
                category="Website",
                title=f"SSL სერტიფიკატის შემოწმება ვერ მოხერხდა: {hostname}",
                description=f"შეცდომა: {e}",
                risk_level="Low",
                recommendation="ხელით გადაამოწმეთ სერტიფიკატის სტატუსი ბრაუზერში.",
            ))
        return findings
