# webapp-security-tester

A Claude skill that tests any web app - especially AI-built or AI-powered ones - against a **30-item bug and vulnerability checklist** (access control, IDOR, SQLi, XSS, CSRF, auth/session, secrets, crypto, uploads, traversal, SSRF, validation, error leakage, misconfiguration, outdated dependencies, unreviewed AI code, logging, CORS, rate limiting, business logic, GraphQL/API, environments, backups, role changes, file downloads, update integrity).

It combines:

1. **Authorization gate** - never tests targets you do not own or have permission to test.
2. **Automated scanners** (Python standard library only) - `scan_web.py` for live apps, `scan_code.py` for repos.
3. **Guided manual playbooks** - safe two-account procedures for the checks scripts cannot decide.
4. **Bilingual report** (English / Arabic): Markdown, HTML and Excel with all 30 items marked FAIL / WARN / PASS / PASS (partial) / NOT TESTED.

## Install

**Claude.ai / Claude app:** download `webapp-security-tester.skill` from Releases (or zip this folder so `SKILL.md` is at the top of the archive) and add it under *Settings -> Capabilities -> Skills*.

**Claude Code:**
```bash
git clone https://github.com/Abdelrhman-Eltayyar/webapp-security-tester ~/.claude/skills/webapp-security-tester
```

## Use

Just ask: *"Test my app https://staging.example.com for security bugs and give me a report in Arabic and English"* or *"Audit this repo before launch."* Claude will confirm authorization, run what it can, guide you through the rest, and produce the report.

Run the scripts yourself:
```bash
python scripts/scan_web.py  --url https://staging.example.com --authorized --active --out findings-web.json
python scripts/scan_code.py --path ./app --out findings-code.json
python scripts/generate_report.py --findings findings-web.json findings-code.json --lang both --target "My app" --outdir report
# CI gate:  add  --fail-on high
```

## Coverage

| Mode | Items |
|---|---|
| automated (13) | 3, 4, 7, 8, 9, 14, 15, 16, 18, 20, 21, 24, 25 |
| needs accounts / manual steps (11) | 1, 2, 5, 6, 10, 11, 12, 13, 23, 28, 29 |
| manual review (6) | 17, 19, 22, 26, 27, 30 |

Scripts also give partial evidence for several "needs accounts" items (e.g. 1, 2, 5, 10, 11, 12, 13, 23, 29), shown as `PASS (partial)` rather than a clean pass.

## Safety

Non-destructive by design: no brute force, no real exploit payloads, no file traversal reads, no DoS. `scan_web.py` refuses non-local targets unless `--authorized` is passed. Use only on systems you own or are permitted to test. Automated results are indicative, not proof of security.

## Develop

```bash
python tests/vulnerable_app.py 8099 &                      # deliberately weak local target
python scripts/scan_web.py --url http://127.0.0.1:8099 --active --out /tmp/fw.json
python scripts/scan_code.py --path tests/sample_repo --no-tools --out /tmp/fc.json
python tests/check_expectations.py /tmp/fw.json /tmp/fc.json
```
Edit checks in `scripts/_build_catalog.py`, then rebuild `references/catalog.json`. The source spreadsheet is in `assets/source-checklist.xlsx`.

## License

MIT

## Contribute
See [CONTRIBUTING.md](CONTRIBUTING.md) to contribute.
