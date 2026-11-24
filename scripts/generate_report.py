#!/usr/bin/env python3
"""generate_report.py - merge scanner output + manual results into a full 30-item report.

Inputs : references/catalog.json, one or more findings-*.json (from scan_web.py /
         scan_code.py), and optionally manual.json written by Claude/the tester.
Outputs: report.md, report.html, results.xlsx (all in --outdir).

manual.json format (list):
  [{"catalog_id": 2, "status": "fail|warn|pass|not_tested", "severity": "high",
    "title": "...", "evidence": "...", "location": "...", "recommendation": "..."}]

Final status per catalog item: FAIL > WARN > PASS > NOT_TESTED.
A PASS from automation alone on a 'semi'/'manual' item is shown as
"PASS (partial)" because scripts cannot prove authorization logic is correct.

Usage:
  python generate_report.py --findings findings-web.json findings-code.json \
      [--manual manual.json] [--lang en|ar|both] [--target "Acme app"] [--outdir report] [--fail-on high]
"""
import argparse
import html
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.path.join(HERE, "..", "references", "catalog.json")
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
ST_ORDER = {"fail": 3, "warn": 2, "pass": 1, "info": 0, "not_tested": -1}

L = {
    "en": {"title": "Web App Security Test Report", "target": "Target", "date": "Date", "summary": "Summary",
           "overall": "Overall risk", "coverage": "Coverage matrix (all 30 checks)", "findings": "Findings",
           "id": "#", "name": "Check", "status": "Status", "sev": "Severity", "how": "How tested", "evidence": "Evidence",
           "fix": "Fix", "loc": "Location", "risk": "Risk", "fail": "FAIL", "warn": "WARN", "pass": "PASS",
           "pass_partial": "PASS (partial)", "not_tested": "NOT TESTED", "auto": "automated", "semi": "needs accounts/manual steps",
           "manual": "manual review", "next": "Items still needing manual testing", "owasp": "OWASP",
           "disclaimer": "Automated checks are indicative, not proof of security. A PASS means nothing was found by these probes."},
    "ar": {"title": "تقرير اختبار أمان تطبيق الويب", "target": "الهدف", "date": "التاريخ", "summary": "الملخص",
           "overall": "مستوى الخطورة الكلي", "coverage": "مصفوفة التغطية (جميع الفحوصات الـ30)", "findings": "النتائج",
           "id": "#", "name": "الفحص", "status": "الحالة", "sev": "الخطورة", "how": "طريقة الفحص", "evidence": "الدليل",
           "fix": "المعالجة", "loc": "الموقع", "risk": "الخطر", "fail": "فشل", "warn": "تحذير", "pass": "نجاح",
           "pass_partial": "نجاح (جزئي)", "not_tested": "لم يُختبر", "auto": "آلي", "semi": "يتطلب حسابات/خطوات يدوية",
           "manual": "مراجعة يدوية", "next": "بنود تحتاج اختبارًا يدويًا", "owasp": "OWASP",
           "disclaimer": "الفحوصات الآلية استرشادية وليست دليلًا على الأمان. «نجاح» يعني أن هذه الاختبارات لم تجد شيئًا."},
}


def load_catalog():
    with open(CATALOG, encoding="utf-8") as f:
        return {c["id"]: c for c in json.load(f)}


def load_findings(paths, manual):
    out = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        out.extend(data["findings"] if isinstance(data, dict) else data)
    if manual:
        with open(manual, encoding="utf-8") as f:
            for m in json.load(f):
                m.setdefault("source", "manual")
                m.setdefault("severity", "info")
                out.append(m)
    return out


def aggregate(cat, findings):
    per = defaultdict(list)
    for f in findings:
        per[int(f["catalog_id"])].append(f)
    rows = []
    for cid, c in cat.items():
        fs = per.get(cid, [])
        best = max((ST_ORDER.get(f["status"], -1) for f in fs), default=-1)
        status = {3: "fail", 2: "warn", 1: "pass", 0: "pass", -1: "not_tested"}[best] if fs else "not_tested"
        real = [f for f in fs if f["status"] != "not_tested"]
        if not real:
            status = "not_tested"
        manual_pass = any(f["source"] == "manual" and f["status"] == "pass" for f in fs)
        partial = status == "pass" and c["mode"] != "auto" and not manual_pass
        sev = max((f.get("severity", "info") for f in fs if f["status"] in ("fail", "warn")), key=lambda s: SEV_ORDER.get(s, 0), default=None)
        rows.append({"cat": c, "status": status, "partial": partial, "severity": sev or "-",
                     "sources": sorted({f["source"] for f in real}), "items": fs})
    return rows


def overall(rows):
    sevs = [r["severity"] for r in rows if r["status"] == "fail"]
    if "critical" in sevs:
        return "CRITICAL"
    if "high" in sevs:
        return "HIGH"
    if sevs or any(r["status"] == "warn" for r in rows):
        return "MEDIUM"
    return "LOW (within tested scope)"


def lab(t, r):
    if r["status"] == "pass":
        return t["pass_partial"] if r["partial"] else t["pass"]
    return t[r["status"]]


def name(c, lang):
    return c["name_ar"] if lang == "ar" else c["name_en"]


def build_md(rows, meta, lang):
    t = L[lang]
    n = {s: sum(1 for r in rows if r["status"] == s) for s in ("fail", "warn", "pass", "not_tested")}
    o = [f"# {t['title']}", "", f"- **{t['target']}:** {meta['target']}", f"- **{t['date']}:** {meta['date']}",
         f"- **{t['overall']}:** {overall(rows)}", "",
         f"## {t['summary']}", "",
         f"| {t['fail']} | {t['warn']} | {t['pass']} | {t['not_tested']} |", "|---|---|---|---|",
         f"| {n['fail']} | {n['warn']} | {n['pass']} | {n['not_tested']} |", "",
         f"_{t['disclaimer']}_", "", f"## {t['coverage']}", "",
         f"| {t['id']} | {t['name']} | {t['status']} | {t['sev']} | {t['how']} | {t['owasp']} |", "|---|---|---|---|---|---|"]
    for r in rows:
        c = r["cat"]
        o.append(f"| {c['id']} | {name(c, lang)} | {lab(t, r)} | {r['severity']} | {t[c['mode']]} | {c['owasp']} |")
    o += ["", f"## {t['findings']}", ""]
    bad = [r for r in rows if r["status"] in ("fail", "warn")]
    bad.sort(key=lambda r: (-ST_ORDER[r["status"]], -SEV_ORDER.get(r["severity"], 0), r["cat"]["id"]))
    for r in bad:
        c = r["cat"]
        o += [f"### #{c['id']} {name(c, lang)} - {lab(t, r)} ({r['severity']})", "",
              f"**{t['risk']}:** {c['risk_ar'] if lang == 'ar' else c['risk_en']}", ""]
        seen = set()
        for f in sorted((x for x in r["items"] if x["status"] in ("fail", "warn")), key=lambda x: -SEV_ORDER.get(x.get("severity", "info"), 0)):
            k = (f["title"], f.get("location"))
            if k in seen:
                continue
            seen.add(k)
            o.append(f"- **{f['title']}** [{f.get('severity', '')}]  ")
            if f.get("location"):
                o.append(f"  {t['loc']}: `{f['location']}`  ")
            if f.get("evidence"):
                o.append(f"  {t['evidence']}: `{str(f['evidence']).replace(chr(10), ' ')[:200]}`  ")
            if f.get("recommendation"):
                o.append(f"  {t['fix']}: {f['recommendation']}")
        o.append("")
        o.append(f"**{t['fix']} (general):** {c['prevention_ar'] if lang == 'ar' else c['prevention_en']}")
        o.append("")
    todo = [r for r in rows if r["status"] == "not_tested" or r["partial"]]
    if todo:
        o += [f"## {t['next']}", ""]
        for r in todo:
            c = r["cat"]
            o.append(f"- #{c['id']} {name(c, lang)} - {c['test_ar'] if lang == 'ar' else c['test_en']}")
        o.append("")
    return "\n".join(o)


def build_html(rows, meta, lang):
    t = L[lang]
    rtl = ' dir="rtl"' if lang == "ar" else ""
    css = ("body{font-family:system-ui,Segoe UI,Tahoma,Arial,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1b1f23}"
           "table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #d0d7de;padding:.45rem .6rem;text-align:start;vertical-align:top;font-size:.9rem}"
           "th{background:#f6f8fa}.fail{background:#ffebe9;color:#82071e;font-weight:600}.warn{background:#fff8c5;color:#7d4e00;font-weight:600}"
           ".pass{background:#dafbe1;color:#116329;font-weight:600}.not_tested{background:#eaeef2;color:#57606a}.card{border:1px solid #d0d7de;border-radius:8px;padding:.8rem 1rem;margin:.8rem 0}"
           "code{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px;word-break:break-all}.k{display:inline-block;margin-inline-end:1rem}")
    n = {s: sum(1 for r in rows if r["status"] == s) for s in ("fail", "warn", "pass", "not_tested")}
    h = [f"<!doctype html><html lang='{lang}'{rtl}><meta charset='utf-8'><title>{html.escape(t['title'])}</title><style>{css}</style><body>",
         f"<h1>{t['title']}</h1><p><b>{t['target']}:</b> {html.escape(meta['target'])} &nbsp; <b>{t['date']}:</b> {meta['date']} &nbsp; <b>{t['overall']}:</b> {overall(rows)}</p>",
         "<p>" + "".join(f"<span class='k {s}'>&nbsp;{t[s]}: {n[s]}&nbsp;</span>" for s in n) + "</p>",
         f"<p><i>{t['disclaimer']}</i></p><h2>{t['coverage']}</h2><table><tr><th>{t['id']}</th><th>{t['name']}</th><th>{t['status']}</th><th>{t['sev']}</th><th>{t['how']}</th><th>{t['owasp']}</th></tr>"]
    for r in rows:
        c = r["cat"]
        h.append(f"<tr><td>{c['id']}</td><td>{html.escape(name(c, lang))}</td><td class='{r['status']}'>{lab(t, r)}</td><td>{r['severity']}</td><td>{t[c['mode']]}</td><td>{c['owasp']}</td></tr>")
    h.append(f"</table><h2>{t['findings']}</h2>")
    bad = sorted((r for r in rows if r["status"] in ("fail", "warn")), key=lambda r: (-ST_ORDER[r["status"]], -SEV_ORDER.get(r["severity"], 0), r["cat"]["id"]))
    for r in bad:
        c = r["cat"]
        h.append(f"<div class='card'><h3>#{c['id']} {html.escape(name(c, lang))} <span class='{r['status']}'>&nbsp;{lab(t, r)} / {r['severity']}&nbsp;</span></h3>")
        h.append(f"<p><b>{t['risk']}:</b> {html.escape(c['risk_ar'] if lang == 'ar' else c['risk_en'])}</p><ul>")
        seen = set()
        for f in r["items"]:
            if f["status"] not in ("fail", "warn"):
                continue
            k = (f["title"], f.get("location"))
            if k in seen:
                continue
            seen.add(k)
            h.append(f"<li><b>{html.escape(f['title'])}</b> [{f.get('severity', '')}]<br>"
                     + (f"{t['loc']}: <code>{html.escape(str(f.get('location')))}</code><br>" if f.get("location") else "")
                     + (f"{t['evidence']}: <code>{html.escape(str(f.get('evidence'))[:200])}</code><br>" if f.get("evidence") else "")
                     + (f"{t['fix']}: {html.escape(f.get('recommendation', ''))}" if f.get("recommendation") else "") + "</li>")
        h.append(f"</ul><p><b>{t['fix']} (general):</b> {html.escape(c['prevention_ar'] if lang == 'ar' else c['prevention_en'])}</p></div>")
    todo = [r for r in rows if r["status"] == "not_tested" or r["partial"]]
    if todo:
        h.append(f"<h2>{t['next']}</h2><ul>")
        for r in todo:
            c = r["cat"]
            h.append(f"<li>#{c['id']} {html.escape(name(c, lang))} - {html.escape(c['test_ar'] if lang == 'ar' else c['test_en'])}</li>")
        h.append("</ul>")
    h.append("</body></html>")
    return "".join(h)


def build_xlsx(rows, meta, path):
    try:
        import openpyxl
        from openpyxl.styles import Alignment, Font, PatternFill
    except ImportError:
        print("openpyxl missing: skipping xlsx", file=sys.stderr)
        return
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Coverage"
    hdr = ["#", "Check (EN)", "الفحص (AR)", "Status", "Severity", "Mode", "OWASP", "Sources", "Risk (AR)", "Prevention (AR)", "How to test (AR)"]
    ws.append(hdr)
    fills = {"fail": "FFC7CE", "warn": "FFEB9C", "pass": "C6EFCE", "not_tested": "E7E6E6"}
    for r in rows:
        c = r["cat"]
        ws.append([c["id"], c["name_en"], c["name_ar"], lab(L["en"], r), r["severity"], c["mode"], c["owasp"], ", ".join(r["sources"]),
                   c["risk_ar"], c["prevention_ar"], c["test_ar"]])
        ws.cell(ws.max_row, 4).fill = PatternFill("solid", fgColor=fills[r["status"]])
    for cell in ws[1]:
        cell.font = Font(bold=True)
        cell.fill = PatternFill("solid", fgColor="D9E1F2")
    for col, w in zip("ABCDEFGHIJK", (5, 38, 38, 16, 10, 10, 11, 20, 50, 50, 50)):
        ws.column_dimensions[col].width = w
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "A2"
    ws2 = wb.create_sheet("Findings")
    ws2.append(["#", "Check", "Status", "Severity", "Title", "Location", "Evidence", "Recommendation", "Source"])
    for r in rows:
        for f in r["items"]:
            if f["status"] in ("fail", "warn"):
                ws2.append([r["cat"]["id"], r["cat"]["name_en"], f["status"], f.get("severity"), f["title"], f.get("location"),
                            f.get("evidence"), f.get("recommendation"), f.get("source")])
    for cell in ws2[1]:
        cell.font = Font(bold=True)
        cell.fill = PatternFill("solid", fgColor="D9E1F2")
    for col, w in zip("ABCDEFGHI", (5, 34, 8, 10, 50, 36, 50, 50, 12)):
        ws2.column_dimensions[col].width = w
    ws2.freeze_panes = "A2"
    ws3 = wb.create_sheet("Meta")
    ws3.append(["Target", meta["target"]])
    ws3.append(["Date", meta["date"]])
    ws3.append(["Overall risk", overall(rows)])
    wb.save(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", nargs="*", default=[])
    ap.add_argument("--manual", default="")
    ap.add_argument("--lang", choices=["en", "ar", "both"], default="en")
    ap.add_argument("--target", default="(unspecified)")
    ap.add_argument("--outdir", default="report")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="none",
                    help="exit 1 if any FAIL at or above this severity (for CI)")
    a = ap.parse_args()
    cat = load_catalog()
    rows = aggregate(cat, load_findings(a.findings, a.manual))
    meta = {"target": a.target, "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
    os.makedirs(a.outdir, exist_ok=True)
    langs = ["en", "ar"] if a.lang == "both" else [a.lang]
    for lg in langs:
        sfx = "" if len(langs) == 1 else f".{lg}"
        with open(os.path.join(a.outdir, f"report{sfx}.md"), "w", encoding="utf-8") as f:
            f.write(build_md(rows, meta, lg))
        with open(os.path.join(a.outdir, f"report{sfx}.html"), "w", encoding="utf-8") as f:
            f.write(build_html(rows, meta, lg))
    build_xlsx(rows, meta, os.path.join(a.outdir, "results.xlsx"))
    with open(os.path.join(a.outdir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump({"target": a.target, "overall": overall(rows),
                   "counts": {s: sum(1 for r in rows if r["status"] == s) for s in ("fail", "warn", "pass", "not_tested")},
                   "items": [{"id": r["cat"]["id"], "status": r["status"], "partial": r["partial"], "severity": r["severity"]} for r in rows]},
                  f, indent=2)
    n = {s: sum(1 for r in rows if r["status"] == s) for s in ("fail", "warn", "pass", "not_tested")}
    print(f"report written to {a.outdir}/  overall={overall(rows)}  {n}")
    if a.fail_on != "none":
        thr = SEV_ORDER[a.fail_on]
        if any(r["status"] == "fail" and SEV_ORDER.get(r["severity"], 0) >= thr for r in rows):
            sys.exit(1)


if __name__ == "__main__":
    main()
