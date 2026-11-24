#!/usr/bin/env python3
"""Rebuild references/catalog.json from the source Excel checklist.

Arabic columns come from the spreadsheet; English text, OWASP mapping,
default severity and automation mode are maintained in META below.

Usage: python scripts/_build_catalog.py assets/source-checklist.xlsx references/catalog.json
"""
import json
import sys

import openpyxl

# id: (name_en, risk_en, prevention_en, test_en, owasp, severity, mode)
# mode: auto   = scan_web.py / scan_code.py can detect it
#       semi   = needs two accounts, an authenticated session or a scoped input
#       manual = human or code review required
META = {
1: ("Broken Access Control", "A regular user reaches another user's or an admin's data, pages or actions", "Enforce authorization on the server for every request, not only in the UI; use explicit roles and permissions", "Open other users' links/API URLs, change IDs in the URL, try admin pages with a normal account", "A01:2021", "critical", "semi"),
2: ("IDOR: Direct access to user objects", "View, edit or delete another user's data by changing a record number in the URL or request", "Bind each record to its owner and verify ownership on the server", "Change id=5 to id=6 (or order_id / file_id) and try to reach another user's data", "A01:2021", "high", "semi"),
3: ("SQL Injection", "Read, modify or delete data, or log in without authorization", "Prepared statements or an ORM with bound parameters; never build SQL from raw strings", "Send a single quote and boolean-style test strings in search/login fields and watch for DB errors or illogical results", "A03:2021", "critical", "auto"),
4: ("XSS: Script injection into the page", "Code runs in the victim's browser: session theft, page defacement, forged actions", "Output encoding, HTML sanitisation, Content-Security-Policy", "Submit a harmless marker with HTML characters in notes/names and check whether it is rendered as text or interpreted as markup", "A03:2021", "high", "auto"),
5: ("CSRF: Cross-site request forgery", "A sensitive action (change email/password, delete data) is performed on the user's behalf without their knowledge", "CSRF token on every sensitive form/request, SameSite cookies, Origin/Referer checks", "Replay a sensitive request from a foreign origin or test page without the token", "A01:2021", "high", "semi"),
6: ("Weak authentication and login", "Account takeover, password guessing, stolen sessions", "Strong passwords, login throttling, MFA, secure session management", "Try common passwords, repeated attempts, and reuse of password-reset links", "A07:2021", "high", "semi"),
7: ("Weak session management", "Attacker keeps access after logout or password change", "Invalidate sessions on logout and password change; secure cookies (HttpOnly, Secure, SameSite)", "Log out then replay the same cookie/session ID; test access after a password change", "A07:2021", "high", "auto"),
8: ("Exposed passwords or secrets in code", "Leaked API keys, DB passwords, signing keys", "Environment variables or a secret manager; never commit .env or keys to Git", "Search the repo and public files for password, API_KEY, secret, .env files", "A02:2021", "critical", "auto"),
9: ("Weak or missing encryption", "Interception of data, passwords or sessions on the network", "Force HTTPS, hash passwords with bcrypt/Argon2, encrypt sensitive data", "Check whether the site works over HTTP and whether passwords/tokens travel in URLs or logs", "A02:2021", "high", "auto"),
10: ("Insecure file upload", "Malicious file upload, server-side code execution, access to unauthorized files", "Validate file type, content and size; store outside the executable path; rename files", "Try uploading .php/.exe or double-extension files such as image.php.jpg", "A04:2021", "critical", "semi"),
11: ("Path traversal", "Read sensitive server files such as .env or system files", "Block ../, pin paths to a fixed folder, validate file names", "Try ../ sequences (plain and URL-encoded) in file download/view parameters", "A01:2021", "high", "semi"),
12: ("SSRF: Server-side request forgery", "Server reaches internal services, private network or cloud metadata", "Allow-list destinations, block internal IP ranges, validate URLs", "Give URL-import fields internal addresses (localhost, link-local metadata IP)", "A10:2021", "high", "semi"),
13: ("Input validation errors", "Invalid data, system errors, injection flaws", "Validate on server and client; allow-lists instead of block-lists", "Send very long, negative, empty, special-character or unexpected JSON values", "A03:2021", "medium", "semi"),
14: ("Unsafe error handling", "Disclosure of file paths, library versions, SQL queries, server details", "Generic user-facing errors; details go to secured logs only", "Send malformed input and watch for stack traces, SQL or file paths in responses", "A05:2021", "medium", "auto"),
15: ("Security misconfiguration", "Open admin pages, disabled protections, server info disclosure, default accounts", "Harden configuration, remove test pages, disable directory listing, change default credentials", "Probe /admin, /debug, /api/docs, /backup, .git, .env", "A05:2021", "high", "auto"),
16: ("Outdated libraries with known vulnerabilities", "Exploitation of known flaws in frameworks, plugins or libraries", "Update libraries, scan dependencies, remove unused ones", "Run SCA tools: npm audit, pip-audit, dependency-check", "A06:2021", "high", "auto"),
17: ("Unreviewed AI-generated code", "Wrong logic, missing permission checks, unsafe data handling, duplicated code", "Human code review, unit and integration tests, static analysis", "Manually review permission, payment, file and API logic; run SAST and unit tests", "A04:2021", "high", "manual"),
18: ("Data leakage in logs", "Passwords, session tokens or personal data written to logs", "Never log sensitive fields; classify logs; restrict log access", "Search logs for passwords, tokens, card numbers, personal data", "A09:2021", "medium", "auto"),
19: ("No logging or monitoring", "Attacks, breaches or abnormal use go undetected", "Log logins, permission changes, uploads and repeated failures", "Check whether failed logins and unauthorized access attempts are recorded", "A09:2021", "medium", "manual"),
20: ("Misconfigured CORS", "External sites read user data or perform requests", "Allow-list exact origins; never combine * with credentials", "Send a request from a foreign origin to the API and inspect CORS headers", "A05:2021", "high", "auto"),
21: ("No rate limiting", "Brute force, system flooding, API abuse", "Limit requests per user/IP; delay or temporarily block", "Send many repeated requests and see whether throttling or blocking appears", "A04:2021", "medium", "auto"),
22: ("Business logic flaws", "Bypass payment steps, change price, reuse coupons, perform actions out of order", "Enforce business rules on the server, never trust the UI", "Alter price, quantity or order status in DevTools; reuse a coupon; skip a step", "A04:2021", "high", "manual"),
23: ("Insecure direct object references in the API", "Access data or perform actions through the API without verification", "Verify token, permission and ownership on every endpoint", "Call the API with another account, without a token, or with a disallowed method", "A01:2021", "high", "semi"),
24: ("Unprotected GraphQL or API", "Complex queries, data exposure, resource exhaustion", "Limit depth and complexity, check permissions, disable introspection in production", "Try nested queries, sensitive fields, and queries without a token", "A05:2021", "medium", "auto"),
25: ("Weak dependency and component management", "Known vulnerabilities or malicious code inside a package", "Use official sources, pin versions, scan dependencies", "Inspect package-lock.json / requirements.txt for unpinned or known-vulnerable versions", "A06:2021", "medium", "auto"),
26: ("No environment separation", "Production reaches test data, or real keys live in a test environment", "Separate databases, keys and domains for Dev/Staging/Production", "Check for real data or production keys in the test environment", "A05:2021", "high", "manual"),
27: ("No backup or recovery plan", "Data loss or inability to recover after an incident", "Encrypted off-site backups with periodic restore tests", "Restore a backup in an isolated environment", "A04:2021", "medium", "manual"),
28: ("Permissions not reviewed on role change", "Old privileges persist after a user changes job", "Review permissions periodically and remove unused ones", "Change a user's role and verify old privileges are revoked immediately", "A01:2021", "high", "semi"),
29: ("Weak protection of files and downloads", "Unauthorized access to files, reports or documents", "Tie each file to a permission and owner; use signed, expiring links", "Open a file link without logging in, or with a changed file number", "A01:2021", "high", "semi"),
30: ("No update integrity verification", "Malicious code injected or unauthorized changes deployed", "Digital signatures, hash checks, restrict who can deploy", "Check whether code/file/update can be pushed without review or permission", "A08:2021", "high", "manual"),
}


def main(src, dst):
    ws = openpyxl.load_workbook(src).active
    rows = [r for r in ws.iter_rows(min_row=2, values_only=True) if r[0]]
    out = []
    for n, name_ar, risk_ar, prev_ar, test_ar in rows:
        n = int(n)
        en = META[n]
        out.append({
            "id": n,
            "name_ar": name_ar, "name_en": en[0],
            "risk_ar": risk_ar, "risk_en": en[1],
            "prevention_ar": prev_ar, "prevention_en": en[2],
            "test_ar": test_ar, "test_en": en[3],
            "owasp": en[4], "default_severity": en[5], "mode": en[6],
        })
    assert len(out) == 30, len(out)
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"wrote {len(out)} items -> {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
