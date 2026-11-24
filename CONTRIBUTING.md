# Contributing to webapp-security-tester

Thanks for helping improve this skill. / شكرًا لمساهمتك في تطوير هذه المهارة.

## Ways to contribute

- **Report a false positive or a missed detection:** open an Issue with the scanner command you ran, the (masked) output, and what you expected.
- **Suggest a new check:** open an Issue first, describing the weakness, how to test it safely, and its OWASP category.
- **Improve a playbook, a rule, or the translations (Arabic/English).**
- **Fix a bug or add a detection** through a Pull Request (steps below).

## Ground rules

1. **Non-destructive only.** No brute force, no real exploit payloads, no file-traversal reads of real system files, no denial-of-service, no data extraction. Detect by harmless markers, error signatures, headers, and behavior differences.
2. **Authorization first.** The skill must keep refusing non-local targets unless `--authorized` is passed. Do not weaken this.
3. **Standard library only** in `scripts/` (Python 3.9+). The only optional dependency is `openpyxl`, for the Excel report.
4. **No real secrets or real targets** anywhere in the repo, including tests and examples. Test values must be obviously fake.
5. **Keep reports honest.** A PASS from automation never means "secure". Items scripts cannot fully decide must stay marked `PASS (partial)`.
6. **Bilingual by default.** New checks need Arabic and English text.

## Project layout

| Path | Purpose |
|---|---|
| `SKILL.md` | Instructions Claude follows (keep under ~500 lines) |
| `references/catalog.json` | The 30 checks (generated, do not edit by hand) |
| `references/playbooks.md` | Safe manual procedure per check |
| `references/ai-app-extras.md` | Extra checks for apps that embed an LLM |
| `scripts/scan_web.py` | Live-app scanner |
| `scripts/scan_code.py` | Source-code scanner |
| `scripts/generate_report.py` | Report builder (md, html, xlsx) |
| `scripts/_build_catalog.py` | Builds `catalog.json` from the Excel checklist |
| `assets/source-checklist.xlsx` | Original Arabic checklist |
| `tests/` | Deliberately weak local demo target and sample repo |

## Adding or changing a check

1. Edit the `META` table in `scripts/_build_catalog.py` (English text, OWASP category, default severity, mode) and the matching row in `assets/source-checklist.xlsx` (Arabic text).
2. Rebuild the catalog:
   ```bash
   python scripts/_build_catalog.py assets/source-checklist.xlsx references/catalog.json
   ```
3. Add detection:
   - Live behavior: a new `check_*` function in `scripts/scan_web.py`, registered in `main()`.
   - Source patterns: a new tuple in `RULES` in `scripts/scan_code.py`.
4. Add a safe manual procedure for the check in `references/playbooks.md`, using the same layout as the existing entries.
5. Add the matching weakness to `tests/vulnerable_app.py` or `tests/sample_repo/`, and list the expected detection in `tests/check_expectations.py`.

## Testing your change

```bash
python tests/vulnerable_app.py 8099 &
python scripts/scan_web.py --url http://127.0.0.1:8099 --active --burst 20 --out /tmp/fw.json
python scripts/scan_code.py --path tests/sample_repo --no-tools --out /tmp/fc.json
python tests/check_expectations.py /tmp/fw.json /tmp/fc.json
python scripts/generate_report.py --findings /tmp/fw.json /tmp/fc.json --lang both --outdir /tmp/rep
```

The same steps run automatically in GitHub Actions on every push and Pull Request.

## Pull Request checklist

- [ ] Change is non-destructive and respects the ground rules above
- [ ] `catalog.json` was rebuilt if checks changed
- [ ] Tests updated and passing
- [ ] Arabic and English text provided for new content
- [ ] No real secrets, domains, or personal data included

## Reporting a security problem in this project

If you find a vulnerability in the scripts themselves, do not open a public Issue. Use **Security -> Report a vulnerability** on the repository page (private advisory), or contact the maintainer directly.

## License

By contributing, you agree that your contributions are licensed under the MIT License.

---

## ملخص بالعربية

- **المساهمات المرحّب بها:** الإبلاغ عن نتيجة خاطئة أو فحص لم يُكتشف، اقتراح فحص جديد، تحسين الشرح أو الترجمة، أو إرسال Pull Request.
- **القواعد:** فحوصات آمنة وغير تدميرية فقط، بدون تخمين كلمات مرور أو استغلال حقيقي. أبقِ شرط `--authorized`. استخدم مكتبات بايثون القياسية فقط. لا تضع أسرارًا أو نطاقات حقيقية في الملفات. اكتب أي محتوى جديد بالعربية والإنجليزية.
- **إضافة فحص جديد:** عدّل `_build_catalog.py` وملف الإكسل، أعد بناء `catalog.json`، أضف الكشف في `scan_web.py` أو `scan_code.py`، أضف إجراء الاختبار اليدوي في `playbooks.md`، ثم أضف حالة اختبار في مجلد `tests`.
- **الثغرات في الأداة نفسها:** أبلغ عنها بشكل خاص عبر Security ثم Report a vulnerability، وليس في Issue علني.
