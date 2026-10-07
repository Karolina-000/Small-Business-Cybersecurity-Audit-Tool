"""
report_generator.py
--------------------
გენერირებს საბოლოო HTML ანგარიშს RiskAssessor-ის შედეგების მიხედვით.
HTML არჩეულია, რადგან ბრაუზერში ლამაზად იხსნება და PDF-ადაც
შეიძლება მისი გადაქცევა (Print -> Save as PDF), დამატებითი
ბიბლიოთეკების გარეშე.
"""

import os
from datetime import datetime

import config

RISK_COLORS = {
    "High": "#dc2626",
    "Medium": "#d97706",
    "Low": "#16a34a",
}


def _findings_html(findings) -> str:
    if not findings:
        return "<p class='muted'>ამ კატეგორიაში პრობლემები არ აღმოჩენილა.</p>"

    rows = []
    # High -> Medium -> Low თანმიმდევრობით
    order = {"High": 0, "Medium": 1, "Low": 2}
    for f in sorted(findings, key=lambda x: order.get(x.risk_level, 3)):
        color = RISK_COLORS.get(f.risk_level, "#6b7280")
        rows.append(f"""
        <div class="finding">
            <div class="finding-header">
                <span class="badge" style="background:{color}">{f.risk_level}</span>
                <span class="finding-title">{f.title}</span>
            </div>
            <p class="finding-desc">{f.description}</p>
            <p class="finding-rec"><strong>რეკომენდაცია:</strong> {f.recommendation}</p>
            {f"<p class='finding-evidence'>Evidence: {f.evidence}</p>" if f.evidence else ""}
        </div>""")
    return "\n".join(rows)


def generate_html_report(risk_assessor, output_path=None) -> str:
    counts = risk_assessor.summary_counts()
    total = len(risk_assessor.findings)
    score = risk_assessor.total_score()
    verdict = risk_assessor.overall_verdict()
    grouped = risk_assessor.findings_by_category()

    output_path = output_path or os.path.join(
        config.REPORTS_DIR,
        f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    )

    categories_html = "\n".join(
        f"""
        <section class="category">
            <h2>{category} <span class="count">({len(items)})</span></h2>
            {_findings_html(items)}
        </section>"""
        for category, items in grouped.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="ka">
<head>
<meta charset="UTF-8">
<title>კიბერუსაფრთხოების აუდიტის ანგარიში — {config.COMPANY_NAME}</title>
<style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#f4f6f8; color:#1f2937; margin:0; padding:0; }}
    .container {{ max-width: 900px; margin: 0 auto; padding: 32px 24px 64px; }}
    header {{ background:#111827; color:#fff; padding:32px 24px; }}
    header h1 {{ margin:0 0 8px; font-size:24px; }}
    header p {{ margin:2px 0; color:#9ca3af; font-size:14px; }}
    .summary {{ display:flex; gap:16px; margin:24px 0; flex-wrap:wrap; }}
    .summary-card {{ flex:1; min-width:140px; background:#fff; border-radius:10px; padding:16px 20px; box-shadow:0 1px 3px rgba(0,0,0,.08); text-align:center; }}
    .summary-card .num {{ font-size:28px; font-weight:700; }}
    .summary-card .label {{ font-size:13px; color:#6b7280; margin-top:4px; }}
    .verdict {{ background:#fff; border-left:5px solid #2563eb; border-radius:6px; padding:16px 20px; margin-bottom:24px; font-size:15px; }}
    .category {{ background:#fff; border-radius:10px; padding:20px 24px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
    .category h2 {{ margin-top:0; font-size:18px; border-bottom:1px solid #e5e7eb; padding-bottom:10px; }}
    .count {{ color:#9ca3af; font-weight:400; font-size:14px; }}
    .finding {{ padding:14px 0; border-bottom:1px solid #f3f4f6; }}
    .finding:last-child {{ border-bottom:none; }}
    .finding-header {{ display:flex; align-items:center; gap:10px; margin-bottom:6px; }}
    .badge {{ color:#fff; font-size:12px; font-weight:600; padding:3px 10px; border-radius:12px; }}
    .finding-title {{ font-weight:600; }}
    .finding-desc {{ margin:4px 0; color:#374151; font-size:14px; }}
    .finding-rec {{ margin:4px 0; font-size:14px; color:#1f2937; background:#f0f9ff; padding:8px 12px; border-radius:6px; }}
    .finding-evidence {{ font-size:12px; color:#9ca3af; font-family:monospace; }}
    .muted {{ color:#9ca3af; font-style:italic; }}
    footer {{ text-align:center; color:#9ca3af; font-size:12px; margin-top:40px; }}
</style>
</head>
<body>
<header>
    <h1>🛡️ კიბერუსაფრთხოების საბაზისო აუდიტი</h1>
    <p><strong>კომპანია:</strong> {config.COMPANY_NAME}</p>
    <p><strong>თარიღი:</strong> {config.AUDIT_DATE}</p>
</header>
<div class="container">

    <div class="summary">
        <div class="summary-card"><div class="num">{total}</div><div class="label">სულ ნაპოვნი</div></div>
        <div class="summary-card"><div class="num" style="color:{RISK_COLORS['High']}">{counts['High']}</div><div class="label">High</div></div>
        <div class="summary-card"><div class="num" style="color:{RISK_COLORS['Medium']}">{counts['Medium']}</div><div class="label">Medium</div></div>
        <div class="summary-card"><div class="num" style="color:{RISK_COLORS['Low']}">{counts['Low']}</div><div class="label">Low</div></div>
        <div class="summary-card"><div class="num">{score}</div><div class="label">რისკის ქულა</div></div>
    </div>

    <div class="verdict">
        <strong>საბოლოო შეფასება:</strong> {verdict}
    </div>

    {categories_html if grouped else "<p class='muted'>Findings არ არის.</p>"}

    <footer>ანგარიში გენერირებულია ავტომატურად Small Business Cybersecurity Audit Tool-ის მიერ.</footer>
</div>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
