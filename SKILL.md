---
name: webapp-security-tester
description: Security-test any AI-built or AI-powered web app, API or repo against a 30-item vulnerability checklist (access control, IDOR, SQLi, XSS, CSRF, auth/session, secrets, crypto, uploads, traversal, SSRF, error leakage, misconfig, outdated deps, unreviewed AI code, logging, CORS, rate limits, business logic, GraphQL, backups, role changes, downloads, update integrity). Runs safe scanners on a live URL and source code, guides manual two-account tests, and writes a full bilingual (English/Arabic) report in md, html and xlsx. Use whenever the user asks to test, audit, pen-test, security-review or harden a web app or API, asks if an app is safe to launch, finds bugs in a vibe-coded app, or mentions OWASP, IDOR, XSS, CORS, rate limiting or leaked keys - even without saying skill. Arabic triggers - اختبار أمان تطبيق، فحص ثغرات، تدقيق أمني.
---

# Web App Security Tester (30-check AI Web App suite)

Test any web app - especially apps written or assisted by AI - against 30 well-known weaknesses, collect evidence, and deliver a report the owner can act on. The checklist comes from the user's "AI Web App Test" spreadsheet; `references/catalog.json` holds all 30 items in Arabic and English with risk, prevention, test method, OWASP mapping, default severity, and whether automation can cover it (`auto` / `semi` / `manual`).

Why this matters: AI-generated apps tend to look finished while skipping the unglamorous server-side work (ownership checks, rate limits, secret handling, error hygiene). Most of these 30 bugs live exactly there, so the goal is evidence per item, not a vague "looks fine".

## Step 0 - Authorization gate (never skip)

Security testing against systems the user does not control is illegal and harmful. Before touching any URL:

1. Ask (once, briefly) to confirm the user owns the target or has written permission, and which environment it is (prefer staging/dev; production only with care).
2. Agree the scope: base URL(s), whether authenticated testing is allowed, whether load-style checks (rate-limit burst) are OK, and the test accounts to use.
3. If the user cannot confirm, switch to source-only mode (`scan_code.py` on code they provide) and say why.

`scan_web.py` enforces this by requiring `--authorized` for any non-localhost target. Do not bypass it, and never aim tools at third-party sites, even "just to demo".

Keep every probe non-destructive: no real exploitation, no data deletion, no credential guessing, no uploading of executable payloads, no traversal reads of real system files, no denial-of-service. Where a check needs one of those (items 6, 10, 11, 12), describe the safe variant in `references/playbooks.md` and ask the user to run or approve it in a sandbox.

## Step 1 - Intake (ask only what you lack)

Collect: target URL(s); repo path or upload (if any); stack (Flask/Django/Next/Express/Laravel...); has login? two test accounts (user A, user B) and an admin account?; has file upload / payments / API / GraphQL?; report language (English, Arabic, or both - default to the language the user writes in); environment.

If the user gave a URL only, run the web scan and tell them what the code scan and two-account tests would add. If they gave code only, run the code scan and list which web checks remain. Do not stall on questions - run what you can, then ask for the rest.

## Step 2 - Run the automated layers

Scripts use only the Python standard library. Paths below are relative to this skill folder; adjust to where the skill is installed (e.g. `/mnt/skills/user/webapp-security-tester/`). Write outputs to a working folder, not inside the skill.

```bash
# Live app (passive checks + opt-in safe active probes)
python scripts/scan_web.py --url https://staging.example.com --authorized \
    --active --burst 40 --out work/findings-web.json
#   optional: --header "Authorization: Bearer <test-user-token>"  --cookie "sid=..."
#             --param-url "https://staging.example.com/search?q=x"  --login-path /login

# Source repo
python scripts/scan_code.py --path ./app --out work/findings-code.json
```

What each covers:

| Script | Catalog items it can evidence |
|---|---|
| `scan_web.py` | 9 HTTPS/HSTS/password-in-URL, 15 headers + exposed paths (.env, .git, backups, admin, docs), 14 error leakage, 20 CORS, 7 cookie flags, 5 CSRF-token heuristic, 4 reflected-input canary, 3 SQL-error canary, 21 rate-limit burst, 24 GraphQL introspection, 23/1 unauthenticated API reads, 8 secrets exposed over HTTP |
| `scan_code.py` | 8 secrets/.env, 9 weak hash/TLS off, 3 SQL concatenation, 4 raw HTML sinks, 13 eval/shell/deserialization, 6 JWT verify off, 7 cookie flags in code, 15 debug/default creds, 20 CORS wildcard, 5 CSRF disabled, 11/12 request-controlled paths and URLs, 10 upload handlers, 29 static serving of private dirs, 18 secrets in logs, 17 AI placeholder code + no tests, 2 id-routes without auth, 16/25 dependency pinning + `pip-audit`/`npm audit` if available, 19 logging presence, 26/27/30 env files, backup docs, CI integrity |

Read the JSON, not just the console summary. Treat every hit as a lead: open the flagged file/URL, confirm it is real, and discard false positives (note them in the report rather than silently dropping them). A "pass" only means these probes found nothing.

If the sandbox has no network, say so, run the code scan, and give the user the exact `scan_web.py` command to run locally.

## Step 3 - Manual / two-account layer (the part scripts cannot do)

Items 1, 2, 5, 6, 10, 11, 12, 22, 23, 28, 29 and the "manual" ones (17, 19, 22, 26, 27, 30) need judgment or multiple identities. Read `references/playbooks.md` for the step-by-step safe procedure per item, then either:
- run the steps yourself if you have a browser/HTTP tool and the user approved, or
- hand the user a short, ordered checklist for just the items still open, and ask them to report what happened.

IDOR/access control is the highest-yield area for AI-built apps: with user A's and user B's tokens, request each object endpoint as the wrong user, as an anonymous user, and with a non-admin role against admin routes. Compare status codes and bodies, not just the UI.

For apps that embed an LLM (chatbots, agents, RAG, AI-generated content), also run the extras in `references/ai-app-extras.md` (prompt injection, API-key exposure in the front end, unrendered-output XSS, cost abuse, tool permissions). They are reported as a supplement, outside the 30-item score.

Record manual results in `work/manual.json`:

```json
[{"catalog_id": 2, "status": "fail", "severity": "high",
  "title": "User B can read user A's invoice via /api/invoices/41",
  "evidence": "GET /api/invoices/41 with B's token -> 200, A's data",
  "location": "GET /api/invoices/{id}",
  "recommendation": "Filter by owner_id = current_user.id in the query."}]
```

`status` is `fail`, `warn`, `pass` or `not_tested`. A manual `pass` upgrades an item from "PASS (partial)" to a full PASS.

## Step 4 - Report

```bash
python scripts/generate_report.py --findings work/findings-web.json work/findings-code.json \
    --manual work/manual.json --lang both --target "My App (staging)" --outdir work/report
```

Outputs `report.md`, `report.html`, `results.xlsx` (coverage matrix + findings, Arabic columns included), and `summary.json`. For CI gating add `--fail-on high`.

Every one of the 30 items appears in the coverage matrix as FAIL / WARN / PASS / PASS (partial) / NOT TESTED, so nothing is silently skipped. Present the files, then reply in chat with:

1. Overall risk and counts.
2. The top findings first (critical -> high), one line each with where and the fix.
3. What was not tested and what is needed (accounts, repo, approval).
4. A suggested fix order: secrets and access control first, then injection, then config and hygiene.

Keep the chat answer short; the report carries the detail. If the user wrote in Arabic, answer in Arabic and use `--lang ar` or `both`.

## Step 5 - Fix and retest (when asked)

Offer concrete fixes in the user's stack (parameterized query, ownership filter, CSP header, rate limiter, cookie flags). After fixes, rerun the same commands and show before/after counts. A finding is closed only when the retest evidence changes, not when the code looks right.

## Severity guidance

- critical: secrets in repo/exposed `.env`, SQL injection, unauthenticated admin/data access, file upload to executable path.
- high: IDOR/BAC, stored/reflected XSS, CORS with credentials, JWT verification off, SSRF, path traversal, missing auth on APIs.
- medium: missing rate limits, weak cookies, verbose errors, CSRF gaps, outdated deps without known exploit.
- low/info: missing hardening headers, version banners, documentation endpoints.
Adjust up when the app handles payments, health, or personal data; explain any adjustment in the finding.

## Reporting principles

- Evidence over opinion: every FAIL carries the request, response snippet, or file:line.
- Mask secrets in all output (first few characters only) and tell the user to rotate anything real.
- Be honest about coverage: automated PASS is not proof. State what was and was not tested.
- Do not publish exploit write-ups beyond what the owner needs to reproduce and fix.

## Maintaining the checklist

To add or edit checks, edit `META` in `scripts/_build_catalog.py` (and the Excel in `assets/source-checklist.xlsx`), then run `python scripts/_build_catalog.py assets/source-checklist.xlsx references/catalog.json`.

## Files

- `references/catalog.json` - the 30 checks, bilingual, with OWASP mapping and automation mode
- `references/playbooks.md` - safe step-by-step procedure for each of the 30 checks (read in Step 3)
- `references/ai-app-extras.md` - LLM/AI-specific checks beyond the 30
- `scripts/scan_web.py`, `scripts/scan_code.py`, `scripts/generate_report.py`
- `assets/source-checklist.xlsx` - the original spreadsheet; `tests/` - local demo target to validate the scanners
