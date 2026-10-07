"""
modules/report_generator.py
---------------------------
სრულეკრანიანი მუქი dashboard-სტილის HTML ანგარიში.

განლაგება:
  - გვერდითი ზოლი (ნავიგაცია)
  - 4 სტატისტიკის ბარათი
  - დასკვნა + ნაბიჯები | დონათი | კატეგორიები
  - აღმოჩენების ცხრილი (დაკლიკებით იშლება დეტალები)
"""

import math
import os
import time
from html import escape

import config

REPORTS_DIR = "reports"

# სიმძიმე: (ფერი, ეტიკეტი, რიგითობა, მნიშვნელობა უბრალო ენით)
SEVERITY = {
    "High":   ("#f08a5d", "მნიშვნელოვანი", 0, "რეალური რისკია, ღირს სწრაფად გამოსწორება"),
    "Medium": ("#f2c46b", "საყურადღებო", 1, "გასაუმჯობესებელია, მაგრამ გადაუდებელი არ არის"),
    "Low":    ("#4fa3e0", "საინფორმაციო", 2, "ინფორმაციისთვისაა, საფრთხე არ არის"),
}
ORDER = ("High", "Medium", "Low")

# უბრალო ენით ახსნები (გასაღები = სიტყვა სათაურში ან აღწერაში)
EXPLANATIONS = {
    "135": "ეს Windows-ის შიდა სერვისია, რომლითაც პროგრამები ერთმანეთს უკავშირდებიან. ჩვეულებრივ ნორმალურია, მთავარია, რომ ინტერნეტიდან ხელმისაწვდომი არ იყოს.",
    "445": "ეს პორტი ფაილების გაზიარებისთვისაა. ინტერნეტიდან ღია რომ იყოს, რისკი იქნებოდა, ხოლო შიდა ქსელში ეს ჩვეულებრივი მდგომარეობაა.",
    "SMB": "ეს სერვისი ფაილების გაზიარებისთვისაა. შიდა ქსელში ნორმალურია, ინტერნეტიდან კი ღია არ უნდა იყოს.",
    "3389": "ეს პორტი კომპიუტერთან დისტანციურ წვდომას იძლევა. თუ ღიაა, უნდა იყოს პაროლითა და დამატებითი დაცვით დაცული.",
    "RDP": "დისტანციური წვდომა კომპიუტერზე. კარგად დაცული უნდა იყოს.",
    "Brute": "ვიღაც ბევრჯერ ცდის სხვადასხვა პაროლს სისტემაში შესასვლელად.",
    "4720": "კომპიუტერზე ახალი მომხმარებელი დაემატა. თუ ეს თქვენ გააკეთეთ, ყველაფერი რიგზეა.",
    "4625": "სისტემაში შესვლა ვერ მოხერხდა (მაგ. პაროლი შეცდომით შეიყვანეს).",
    "Content-Security-Policy": "ეს დაცვა ხელს უშლის საიტზე უცხო კოდის გაშვებას.",
    "Security Header": "ეს საიტის დამატებითი დამცავი პარამეტრია, რომელიც ბრაუზერს ეუბნება, როგორ დაიცვას ვიზიტორი.",
    "HTTPS": "HTTPS იცავს ვიზიტორის მონაცემებს გადაცემისას.",
    "SSL": "სერტიფიკატი ადასტურებს, რომ საიტი ნამდვილია. ვადაგასულ სერტიფიკატზე ბრაუზერი გაფრთხილებას აჩვენებს.",
    "შეიცვალა": "ფაილი შეიცვალა ბოლო შემოწმების შემდეგ. თუ ცვლილება თქვენ გააკეთეთ, ყველაფერი რიგზეა. თუ არა, ღირს გადამოწმება.",
    "შეცვლილია": "ფაილი შეიცვალა ბოლო შემოწმების შემდეგ. თუ ცვლილება თქვენ გააკეთეთ, ყველაფერი რიგზეა. თუ არა, ღირს გადამოწმება.",
    "წაიშალა": "ფაილი გაქრა ბოლო შემოწმების შემდეგ.",
}

LOCAL_NOTE = "ეს თქვენი კომპიუტერის შიდა შემოწმებაა და გარედან არ ჩანს, ამიტომ რისკი დაბალია."


# ---------- მონაცემების მომზადება ----------

def _get(obj, *names, default=""):
    """კითხულობს ველს Finding-იდან (სხვადასხვა შესაძლო სახელით)."""
    for name in names:
        value = obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)
        if value not in (None, ""):
            return getattr(value, "value", value)
    return default


def _explain(title, description):
    text = f"{title} {description}".lower()
    for keyword, explanation in EXPLANATIONS.items():
        if keyword.lower() in text:
            return explanation
    return ""


def _adjust_severity(severity, category, text):
    """ასწორებს სიმძიმეს რეალური რისკის მიხედვით. აბრუნებს (სიმძიმე, შენიშვნა)."""
    lowered = text.lower()
    is_local = "127.0.0.1" in lowered or "localhost" in lowered
    if is_local and "network" in category.lower():
        return "Low", LOCAL_NOTE
    if "file" in category.lower() and severity == "High":
        return "Medium", ""
    return severity, ""


def _prepare(finding):
    severity = str(_get(finding, "severity", "level", "risk_level", "risk", default="Low")).capitalize()
    if severity not in SEVERITY:
        severity = "Low"
    category = str(_get(finding, "category", "module", "source", default="სხვა"))
    title = str(_get(finding, "title", "name"))
    description = str(_get(finding, "description", "details"))
    evidence = str(_get(finding, "evidence"))

    severity, note = _adjust_severity(severity, category, f"{title} {description} {evidence}")

    return {
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "explanation": _explain(title, description),
        "note": note,
        "recommendation": str(_get(finding, "recommendation", "fix", "advice")),
        "evidence": evidence,
    }


def _overall(counts):
    """საერთო დასკვნა: (სათაური, შეტყობინება)."""
    if counts["High"] > 0:
        return "საჭიროა ყურადღება", \
            f"ნაპოვნია {counts['High']} მნიშვნელოვანი საკითხი. უმეტესობა მარტივად გამოსწორდება. დაიწყეთ ქვემოთ მოცემული ნაბიჯებით."
    if counts["Medium"] > 0:
        return "საერთო სურათი კარგია", \
            "სერიოზული პრობლემა არ აღმოჩნდა. რამდენიმე რამ გასაუმჯობესებელია."
    return "ყველაფერი რიგზეა", \
        "მნიშვნელოვანი პრობლემა არ აღმოჩნდა. ქვემოთ მხოლოდ ინფორმაციული შენიშვნებია."


# ---------- HTML ნაწილები ----------

def _stat_card(key, count, total):
    color, label = SEVERITY[key][0], SEVERITY[key][1]
    percent = round(count / total * 100) if total else 0
    return f"""<div class="card stat">
      <div class="stat-label"><span class="dot" style="background:{color}"></span>{label}</div>
      <div class="stat-num">{count}</div>
      <div class="bar"><span style="width:{percent}%;background:{color}"></span></div>
    </div>"""


def _total_card(total, categories):
    return f"""<div class="card stat">
      <div class="stat-label"><span class="dot" style="background:#1e9bff"></span>სულ აღმოჩენა</div>
      <div class="stat-num">{total}</div>
      <div class="stat-foot">{categories} კატეგორიაში</div>
    </div>"""


def _guide():
    """მინიშნება: რას ნიშნავს თითო დონე."""
    rows = "".join(
        f'<div class="guide-row"><span class="dot" style="background:{SEVERITY[k][0]}"></span>'
        f'<span><b>{SEVERITY[k][1]}</b> — {SEVERITY[k][3]}</span></div>'
        for k in ORDER
    )
    return f'<div class="guide"><h2>როგორ წავიკითხოთ</h2>{rows}</div>'


def _steps(items):
    """პირველი ნაბიჯები: მხოლოდ მნიშვნელოვანი და საყურადღებო საკითხებიდან."""
    top = [f for f in items if f["severity"] != "Low" and f["recommendation"]][:3]
    if not top:
        return '<p class="muted">სასწრაფო ნაბიჯები არ არის საჭირო. 🌿</p>'
    rows = "".join(
        f'<li><span class="num">{i}</span><span>{escape(f["recommendation"])}</span></li>'
        for i, f in enumerate(top, 1)
    )
    return f'<ol class="steps">{rows}</ol>'


def _donut(counts, total):
    """SVG დონათ-დიაგრამა. ცენტრში საერთო რაოდენობაა."""
    radius = 70
    circumference = 2 * math.pi * radius
    gap = 4 if sum(1 for v in counts.values() if v) > 1 else 0
    circles, offset = [], 0.0

    if total == 0:
        circles.append(f'<circle cx="100" cy="100" r="{radius}" fill="none" stroke="#242b38" stroke-width="22"/>')
    else:
        for key in ORDER:
            if not counts[key]:
                continue
            length = circumference * counts[key] / total
            dash = max(length - gap, 1)
            circles.append(
                f'<circle cx="100" cy="100" r="{radius}" fill="none" stroke="{SEVERITY[key][0]}" '
                f'stroke-width="22" stroke-linecap="round" '
                f'stroke-dasharray="{dash:.2f} {circumference - dash:.2f}" stroke-dashoffset="{-offset:.2f}"/>'
            )
            offset += length

    legend = "".join(
        f'<div class="legend-row"><span class="dot" style="background:{SEVERITY[k][0]}"></span>'
        f'<span>{SEVERITY[k][1]}</span><b>{counts[k]}</b></div>'
        for k in ORDER
    )
    return f"""<div class="donut-wrap">
      <svg viewBox="0 0 200 200" class="donut">
        <g transform="rotate(-90 100 100)">{''.join(circles)}</g>
        <text x="100" y="104" text-anchor="middle" class="donut-num">{total}</text>
        <text x="100" y="126" text-anchor="middle" class="donut-sub">აღმოჩენა</text>
      </svg>
      <div class="legend">{legend}</div>
    </div>"""


def _category_groups(items):
    """კატეგორიები: რაოდენობა და ყველაზე მძიმე დონე."""
    groups = {}
    for f in items:
        g = groups.setdefault(f["category"], {"count": 0, "worst": "Low"})
        g["count"] += 1
        if SEVERITY[f["severity"]][2] < SEVERITY[g["worst"]][2]:
            g["worst"] = f["severity"]
    return groups


def _categories(groups, total):
    if not groups:
        return '<p class="muted">მონაცემები არ არის.</p>'
    rows = ""
    for name, g in sorted(groups.items(), key=lambda kv: -kv[1]["count"]):
        color = SEVERITY[g["worst"]][0]
        percent = round(g["count"] / total * 100) if total else 0
        rows += f"""<div class="cat-row">
          <div class="cat-head"><span>{escape(name)}</span><b>{g['count']}</b></div>
          <div class="bar"><span style="width:{percent}%;background:{color}"></span></div>
        </div>"""
    return rows


def _row(f):
    color, label = SEVERITY[f["severity"]][0], SEVERITY[f["severity"]][1]
    body = []
    if f["description"]:
        body.append(f'<p>{escape(f["description"])}</p>')
    if f["note"]:
        body.append(f'<p class="note">🏠 {escape(f["note"])}</p>')
    if f["explanation"]:
        body.append(f'<p class="explain">💡 <b>რას ნიშნავს ეს?</b> {escape(f["explanation"])}</p>')
    if f["recommendation"]:
        body.append(f'<p class="todo">✅ <b>რა გააკეთოთ:</b> {escape(f["recommendation"])}</p>')
    if f["evidence"]:
        body.append(f'<code>{escape(f["evidence"])}</code>')
    return f"""<details class="row">
      <summary>
        <span class="pill" style="color:{color};background:{color}22">{label}</span>
        <span class="row-title">{escape(f["title"])}</span>
        <span class="chip">{escape(f["category"])}</span>
        <span class="chev">›</span>
      </summary>
      <div class="row-body">{''.join(body)}</div>
    </details>"""


CSS = """
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font-family:'Segoe UI',Arial,sans-serif;color:#e6e9ef;line-height:1.5;min-height:100vh;
background:#0a0d13 radial-gradient(1100px 600px at 90% -10%,#12343a 0%,transparent 60%) no-repeat fixed}
.app{display:flex;min-height:100vh}
.side{position:sticky;top:0;height:100vh;width:78px;flex:none;display:flex;flex-direction:column;align-items:center;gap:14px;
padding:24px 0;background:#0d1118;border-right:1px solid #1a212d}
.side a{width:44px;height:44px;border-radius:14px;background:#141a24;display:flex;align-items:center;justify-content:center;
font-size:19px;text-decoration:none;transition:.15s}
.side a:hover,.side a.on{background:#1e9bff}
.logo{font-size:26px;margin-bottom:10px}
.main{flex:1;min-width:0;padding:30px clamp(18px,3vw,52px) 56px}
.inner{max-width:1760px;margin:0 auto}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:24px}
h1{font-size:clamp(26px,2.2vw,34px);font-weight:600;margin:0}
.meta{background:#131822;border:1px solid #1e2531;border-radius:999px;padding:9px 18px;font-size:13px;color:#9aa3b2}
.card{background:#11151d;border:1px solid #1c2330;border-radius:20px;padding:22px 26px}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:18px;margin-bottom:18px}
.grid3{display:grid;grid-template-columns:1.7fr 1fr 1.1fr;gap:18px;margin-bottom:18px}
.stat-label{display:flex;align-items:center;gap:8px;font-size:14px;color:#9aa3b2}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;flex:none}
.stat-num{font-size:clamp(38px,3.2vw,52px);font-weight:600;margin:6px 0 12px}
.stat-foot{font-size:13px;color:#7d8798;margin-top:6px}
.bar{height:6px;background:#1b2230;border-radius:6px;overflow:hidden}
.bar span{display:block;height:100%;border-radius:6px}
h2{font-size:16px;font-weight:600;margin:0 0 10px}
.headline{font-size:clamp(22px,1.9vw,28px);font-weight:600;margin:0 0 6px}
.muted{color:#9aa3b2;font-size:14px;margin:0}
.col{display:flex;flex-direction:column}
.steps{list-style:none;padding:0;margin:8px 0 0}
.steps li{display:flex;gap:12px;align-items:flex-start;padding:13px 15px;margin-bottom:8px;background:#161b25;border-radius:12px;font-size:14px}
.steps .num{flex:none;width:24px;height:24px;border-radius:50%;background:#1e9bff;color:#fff;font-size:12px;font-weight:600;display:flex;align-items:center;justify-content:center}
.guide{margin-top:auto;padding-top:20px}
.guide-row{display:flex;gap:10px;align-items:center;font-size:13px;color:#9aa3b2;padding:6px 0}
.guide-row b{color:#e6e9ef;font-weight:600}
.donut-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:18px;flex:1}
.donut{width:min(210px,100%);height:auto}
.donut-num{fill:#e6e9ef;font-size:34px;font-weight:600}
.donut-sub{fill:#9aa3b2;font-size:11px}
.legend{width:100%}
.legend-row{display:flex;align-items:center;gap:8px;font-size:13px;color:#9aa3b2;padding:4px 0}
.legend-row b{margin-left:auto;color:#e6e9ef}
.cat-row{margin-bottom:18px}
.cat-head{display:flex;justify-content:space-between;font-size:14px;margin-bottom:8px}
.list{padding:10px 26px 16px}
.row{border-top:1px solid #1c2330}
.row summary{display:flex;align-items:center;gap:14px;padding:16px 0;cursor:pointer;list-style:none}
.row summary::-webkit-details-marker{display:none}
.pill{font-size:12px;font-weight:600;padding:5px 13px;border-radius:999px;white-space:nowrap}
.row-title{flex:1;font-size:14px;font-weight:500;word-break:break-word}
.chip{font-size:12px;color:#9aa3b2;background:#161b25;padding:5px 11px;border-radius:8px;white-space:nowrap}
.chev{color:#6b7587;font-size:20px;transition:transform .15s}
.row[open] .chev{transform:rotate(90deg)}
.row-body{padding:0 0 18px}
.row-body p{margin:8px 0;font-size:14px;color:#c4cad6}
.note{background:#12261f;padding:10px 14px;border-radius:10px}
.explain{background:#2a2414;padding:10px 14px;border-radius:10px}
.todo{background:#10253a;padding:10px 14px;border-radius:10px}
code{display:block;margin-top:8px;font-size:12px;color:#7d8798;word-break:break-all}
footer{text-align:center;color:#5d6678;font-size:12px;margin-top:34px}
@media(max-width:1200px){.grid4{grid-template-columns:repeat(2,1fr)}.grid3{grid-template-columns:1fr 1fr}.grid3>.col:first-child{grid-column:1/-1}}
@media(max-width:760px){.side{display:none}.grid4,.grid3{grid-template-columns:1fr}.row summary{flex-wrap:wrap}}
"""


# ---------- მთავარი ფუნქცია ----------

def generate_html_report(assessor):
    items = [_prepare(f) for f in assessor.findings]
    items.sort(key=lambda f: SEVERITY[f["severity"]][2])

    counts = {k: 0 for k in ORDER}
    for f in items:
        counts[f["severity"]] += 1
    total = len(items)
    groups = _category_groups(items)

    headline, message = _overall(counts)
    stats = "".join(_stat_card(k, counts[k], total) for k in ORDER) + _total_card(total, len(groups))
    rows = "".join(_row(f) for f in items) or '<p class="muted" style="padding:16px 0">პრობლემა არ მოიძებნა 🌿</p>'

    company = escape(str(config.COMPANY_NAME))
    date = escape(str(config.AUDIT_DATE))

    html = f"""<!DOCTYPE html>
<html lang="ka">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>უსაფრთხოების ანგარიში: {company}</title>
<style>{CSS}</style>
</head>
<body>
<div class="app">
  <nav class="side">
    <div class="logo">🛡️</div>
    <a href="#overview" class="on" title="მიმოხილვა">🏠</a>
    <a href="#findings" title="აღმოჩენები">📋</a>
  </nav>

  <div class="main"><div class="inner">
    <div class="top" id="overview">
      <h1>Overview</h1>
      <div class="meta">{company} &middot; {date}</div>
    </div>

    <div class="grid4">{stats}</div>

    <div class="grid3" id="steps">
      <div class="card col">
        <p class="headline">{headline}</p>
        <p class="muted">{message}</p>
        <h2 style="margin-top:22px">რეკომენდებული პირველი ნაბიჯები</h2>
        {_steps(items)}
        {_guide()}
      </div>
      <div class="card col">
        <h2>აღმოჩენების განაწილება</h2>
        {_donut(counts, total)}
      </div>
      <div class="card col">
        <h2>კატეგორიების მიხედვით</h2>
        {_categories(groups, total)}
      </div>
    </div>

    <div class="card list" id="findings">
      <h2 style="padding-top:12px">ყველა აღმოჩენა</h2>
      {rows}
    </div>

    <footer>შექმნილია Small Business Cybersecurity Audit Tool-ით</footer>
  </div></div>
</div>
</body>
</html>"""

    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"audit_report_{time.strftime('%Y%m%d_%H%M%S')}.html")
    with open(path, "w", encoding="utf-8") as file:
        file.write(html)
    return path