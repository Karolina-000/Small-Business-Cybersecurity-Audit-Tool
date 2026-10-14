"""
main.py
-------
Small Business Cybersecurity Audit Tool — მთავარი გამშვები ფაილი.

გაშვება:
    python main.py                 # სრული აუდიტი
    python main.py --skip-network  # ქსელის სკანირების გარეშე
    python main.py --build-baseline  # ფაილების baseline-ის შექმნა/განახლება
    python main.py --demo          # ლოგების სადემონსტრაციო (ყალბი) მონაცემებით (ტესტირებისთვის)

⚠️ გაუშვით მხოლოდ იმ სისტემებზე/ქსელებზე, რომელთა შემოწმების
წერილობითი ავტორიზაციაც გაქვთ.
"""

import argparse
import logging
import os
import sys

import config
from modules.risk_assessment import RiskAssessor
from modules.network_scanner import NetworkScanner
from modules.log_analyzer import WindowsLogAnalyzer
from modules.file_integrity import FileIntegrityChecker
from modules.website_checker import WebsiteChecker
from modules.report_generator import generate_html_report

log = logging.getLogger("audit")


def run_audit(skip_network=False, skip_logs=False, skip_files=False, skip_website=False, demo=False):
    print(f"=== კიბერუსაფრთხოების აუდიტი: {config.COMPANY_NAME} ===")
    print(f"დაწყების დრო: {config.AUDIT_DATE}\n")

    assessor = RiskAssessor()
    failed = []  # რომელი ეტაპები ვერ შესრულდა (რომ ვერდიქტი არასრული სურათით არ მოტყუებდეს)

    # 1) ქსელის სკანირება
    if not skip_network:
        print("[1/4] ქსელის სკანირება (Nmap)...")
        try:
            net_findings = NetworkScanner().scan()
            assessor.add_many(net_findings)
            print(f"      ნაპოვნია {len(net_findings)} Finding.")
        except Exception as e:
            print(f"      ⚠ ქსელის სკანირება ვერ შესრულდა: {e}")
            log.exception("Network scan failed")  # სრული შეცდომა audit.log-ში
            failed.append("ქსელის სკანირება")
    else:
        print("[1/4] ქსელის სკანირება გამოტოვებულია.")

    # 2) Windows Security ლოგები
    if not skip_logs:
        print("[2/4] Windows Security ლოგების ანალიზი...")
        try:
            if demo:
                print("      ⚠ DEMO რეჟიმი: ლოგების მონაცემები სადემონსტრაციოა (ყალბი)!")
            log_findings = WindowsLogAnalyzer(demo=demo).analyze()
            assessor.add_many(log_findings)
            print(f"      ნაპოვნია {len(log_findings)} Finding.")
        except Exception as e:
            print(f"      ⚠ ლოგების ანალიზი ვერ შესრულდა: {e}")
            log.exception("Log analysis failed")  # სრული შეცდომა audit.log-ში
            failed.append("ლოგების ანალიზი")
    else:
        print("[2/4] Windows ლოგების ანალიზი გამოტოვებულია.")

    # 3) ფაილების მთლიანობა
    if not skip_files:
        print("[3/4] ფაილების მთლიანობის შემოწმება (SHA-256)...")
        try:
            file_findings = FileIntegrityChecker().check()
            assessor.add_many(file_findings)
            print(f"      ნაპოვნია {len(file_findings)} Finding.")
        except Exception as e:
            print(f"      ⚠ ფაილების შემოწმება ვერ შესრულდა: {e}")
            log.exception("File integrity check failed")  # სრული შეცდომა audit.log-ში
            failed.append("ფაილების მთლიანობა")
    else:
        print("[3/4] ფაილების მთლიანობის შემოწმება გამოტოვებულია.")

    # 4) ვებსაიტის შემოწმება
    if not skip_website:
        print("[4/4] ვებსაიტის საბაზისო უსაფრთხოების შემოწმება...")
        try:
            web_findings = WebsiteChecker().check_all()
            assessor.add_many(web_findings)
            print(f"      ნაპოვნია {len(web_findings)} Finding.")
        except Exception as e:
            print(f"      ⚠ ვებსაიტის შემოწმება ვერ შესრულდა: {e}")
            log.exception("Website check failed")  # სრული შეცდომა audit.log-ში
            failed.append("ვებსაიტის შემოწმება")
    else:
        print("[4/4] ვებსაიტის შემოწმება გამოტოვებულია.")

    # ანგარიშის გენერაცია
    print("\nანგარიშის გენერირება...")
    report_path = generate_html_report(assessor)
    print(f"✅ ანგარიში მზადაა: {report_path}")

    # კონსოლში მოკლე შეჯამება
    counts = assessor.summary_counts()
    print("\n--- შეჯამება ---")
    print(f"სულ Findings: {len(assessor.findings)}")
    print(f"  High:   {counts['High']}")
    print(f"  Medium: {counts['Medium']}")
    print(f"  Low:    {counts['Low']}")
    print(f"რისკის ქულა: {assessor.total_score()}/100")
    print(f"ვერდიქტი: {assessor.overall_verdict()}")
    if failed:
        print(f"⚠ ყურადღება: ვერ შესრულდა: {', '.join(failed)}. ვერდიქტი არასრულია (დეტალები: audit.log).")

    return assessor, report_path


def main():
    parser = argparse.ArgumentParser(description="Small Business Cybersecurity Audit Tool")
    parser.add_argument("--skip-network", action="store_true", help="გამოტოვე Nmap სკანირება")
    parser.add_argument("--skip-logs", action="store_true", help="გამოტოვე Windows ლოგების ანალიზი")
    parser.add_argument("--skip-files", action="store_true", help="გამოტოვე ფაილების მთლიანობის შემოწმება")
    parser.add_argument("--skip-website", action="store_true", help="გამოტოვე ვებსაიტის შემოწმება")
    parser.add_argument("--demo", action="store_true", help="ლოგების სადემონსტრაციო (ყალბი) მონაცემები (ტესტირებისთვის)")
    parser.add_argument("--build-baseline", action="store_true", help="შექმენი ფაილების baseline და გამოდი")
    args = parser.parse_args()

    # შეცდომების სრული ტექსტი (traceback) იწერება audit.log-ში, კონსოლში მხოლოდ მოკლე შეტყობინებაა
    logging.basicConfig(
        filename=os.path.join(config.BASE_DIR, "audit.log"),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        encoding="utf-8",
    )

    if args.build_baseline:
        print("ფაილების baseline-ის შექმნა...")
        FileIntegrityChecker().build_baseline()
        print("✅ Baseline შენახულია.")
        sys.exit(0)

    run_audit(
        skip_network=args.skip_network,
        skip_logs=args.skip_logs,
        skip_files=args.skip_files,
        skip_website=args.skip_website,
        demo=args.demo,
    )


if __name__ == "__main__":
    main()
