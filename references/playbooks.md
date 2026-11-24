# Playbooks: safe procedure for each of the 30 checks

Use these in Step 3 for items the scripts cannot fully decide. Every procedure is non-destructive by design: test data, your own accounts, small bounded probes, evidence over exploitation. Stop and report when you have enough evidence; never escalate to data extraction.

## Contents

1. Broken Access Control
2. IDOR: Direct access to user objects
3. SQL Injection
4. XSS: Script injection into the page
5. CSRF: Cross-site request forgery
6. Weak authentication and login
7. Weak session management
8. Exposed passwords or secrets in code
9. Weak or missing encryption
10. Insecure file upload
11. Path traversal
12. SSRF: Server-side request forgery
13. Input validation errors
14. Unsafe error handling
15. Security misconfiguration
16. Outdated libraries with known vulnerabilities
17. Unreviewed AI-generated code
18. Data leakage in logs
19. No logging or monitoring
20. Misconfigured CORS
21. No rate limiting
22. Business logic flaws
23. Insecure direct object references in the API
24. Unprotected GraphQL or API
25. Weak dependency and component management
26. No environment separation
27. No backup or recovery plan
28. Permissions not reviewed on role change
29. Weak protection of files and downloads
30. No update integrity verification

Statuses to record in `manual.json`: `fail`, `warn`, `pass`, `not_tested`.

## 1. Broken Access Control  /  كسر التحكم في الوصول / Broken Access Control

- **OWASP:** A01:2021 | **Default severity:** critical | **Coverage:** semi
- **Risk:** A regular user reaches another user's or an admin's data, pages or actions
- **Prevention:** Enforce authorization on the server for every request, not only in the UI; use explicit roles and permissions
- **Test idea (source checklist):** Open other users' links/API URLs, change IDs in the URL, try admin pages with a normal account

**Setup:** Accounts: anonymous, user A, admin.

**Steps:**
1. List every admin/internal route from the UI, JS bundles, sitemap and API docs.
2. Request each as anonymous, then as user A. Compare status and body with the admin result.
3. Try the same action with GET/POST/PUT/DELETE to catch method-specific gaps.
4. Confirm the block happens server-side: hide the button in DevTools is not a test; call the endpoint directly.

**Pass looks like:** 401/403 for every unauthorized call, no data in body.  
**Fail looks like:** 200 with data, or action succeeds, for a lower role.  
**Safety:** Use test data only; do not run destructive actions (DELETE) on real records.

## 2. IDOR: Direct access to user objects  /  IDOR: الوصول المباشر لكائنات المستخدمين

- **OWASP:** A01:2021 | **Default severity:** high | **Coverage:** semi
- **Risk:** View, edit or delete another user's data by changing a record number in the URL or request
- **Prevention:** Bind each record to its owner and verify ownership on the server
- **Test idea (source checklist):** Change id=5 to id=6 (or order_id / file_id) and try to reach another user's data

**Setup:** Two users with one object each (A owns 5, B owns 6).

**Steps:**
1. Log in as A, capture requests that carry an id (URL, body, header, cookie).
2. Replay with B's object id while still authenticated as A.
3. Repeat for read, update and delete on every object type: orders, invoices, files, messages, profiles.
4. Try UUIDs too: guessability is not authorization.

**Pass looks like:** 403/404 and no foreign data.  
**Fail looks like:** A can read or change B's object.  
**Safety:** Replay reads freely; for update/delete use throwaway records you created.

## 3. SQL Injection  /  SQL Injection / حقن قواعد البيانات

- **OWASP:** A03:2021 | **Default severity:** critical | **Coverage:** auto
- **Risk:** Read, modify or delete data, or log in without authorization
- **Prevention:** Prepared statements or an ORM with bound parameters; never build SQL from raw strings
- **Test idea (source checklist):** Send a single quote and boolean-style test strings in search/login fields and watch for DB errors or illogical results

**Setup:** Search, login, filter and sort fields; API query params.

**Steps:**
1. Send a single quote in each field and compare with a normal value.
2. Look for DB error text, 500 vs 400, or timing and result-count anomalies.
3. Check the code (scan_code.py) for string-built SQL; confirm with the ORM/driver docs.
4. If a real injection is suspected, stop and report; do not dump data.

**Pass looks like:** Same handling as any other text; no DB error; parameterized queries in code.  
**Fail looks like:** SQL error echoed, 500 only on quote, or logic changes with boolean-style input.  
**Safety:** Never run UNION/dump/stacked queries. Error or behaviour difference is enough evidence.

## 4. XSS: Script injection into the page  /  XSS: حقن سكربتات في الصفحة

- **OWASP:** A03:2021 | **Default severity:** high | **Coverage:** auto
- **Risk:** Code runs in the victim's browser: session theft, page defacement, forged actions
- **Prevention:** Output encoding, HTML sanitisation, Content-Security-Policy
- **Test idea (source checklist):** Submit a harmless marker with HTML characters in notes/names and check whether it is rendered as text or interpreted as markup

**Setup:** Every field whose value is later displayed: names, notes, comments, profile, search, error pages, chat.

**Steps:**
1. Submit a harmless marker such as zqXSS<i>x</i> and view it everywhere it appears.
2. Inspect the DOM: encoded (&lt;i&gt;) is safe, an actual <i> element is not.
3. Check CSP header and any innerHTML/dangerouslySetInnerHTML usage.
4. For AI chat/markdown output, test whether HTML in model output is rendered.

**Pass looks like:** Marker shown as literal text.  
**Fail looks like:** Marker becomes markup, or attributes/script contexts are breakable.  
**Safety:** Use inert markers; avoid payloads that exfiltrate cookies. alert() on your own test account is enough.

## 5. CSRF: Cross-site request forgery  /  CSRF: تزوير طلب عبر الموقع

- **OWASP:** A01:2021 | **Default severity:** high | **Coverage:** semi
- **Risk:** A sensitive action (change email/password, delete data) is performed on the user's behalf without their knowledge
- **Prevention:** CSRF token on every sensitive form/request, SameSite cookies, Origin/Referer checks
- **Test idea (source checklist):** Replay a sensitive request from a foreign origin or test page without the token

**Setup:** One logged-in test account.

**Steps:**
1. Find state-changing requests (email/password change, delete, transfer).
2. Check for an anti-CSRF token and for SameSite on the session cookie.
3. Replay the request without the token and with a foreign Origin/Referer header.
4. Confirm JSON endpoints reject form content types if they rely on SameSite only.

**Pass looks like:** Request rejected without a valid token/Origin.  
**Fail looks like:** Request succeeds with no token and foreign Origin.  
**Safety:** Test with your own account on non-critical actions (e.g. display name).

## 6. Weak authentication and login  /  ضعف المصادقة وتسجيل الدخول

- **OWASP:** A07:2021 | **Default severity:** high | **Coverage:** semi
- **Risk:** Account takeover, password guessing, stolen sessions
- **Prevention:** Strong passwords, login throttling, MFA, secure session management
- **Test idea (source checklist):** Try common passwords, repeated attempts, and reuse of password-reset links

**Setup:** Test account; staging only.

**Steps:**
1. Check password policy: minimum length, common passwords accepted?
2. Check lockout/throttling with a handful (<=10) of wrong attempts on your own test account.
3. Check reset flow: token single-use, expiry, not reusable after use, same response for unknown emails.
4. Check MFA availability for admin accounts, default/seed credentials, and session fixation.

**Pass looks like:** Throttling or lockout appears; reset links die after use; no user enumeration.  
**Fail looks like:** Unlimited attempts, reusable/predictable reset links, weak passwords accepted, default admin login.  
**Safety:** Do not run credential lists or brute force. Ten attempts on your own account is sufficient.

## 7. Weak session management  /  ضعف إدارة الجلسات

- **OWASP:** A07:2021 | **Default severity:** high | **Coverage:** auto
- **Risk:** Attacker keeps access after logout or password change
- **Prevention:** Invalidate sessions on logout and password change; secure cookies (HttpOnly, Secure, SameSite)
- **Test idea (source checklist):** Log out then replay the same cookie/session ID; test access after a password change

**Setup:** One logged-in test account.

**Steps:**
1. Copy the session cookie/token, log out, then replay it against an authenticated endpoint.
2. Change the password in session 1, then check whether session 2 still works.
3. Inspect cookie flags (HttpOnly, Secure, SameSite) and token lifetime; JWT: check exp and signature validation.
4. Check session ID changes after login (fixation).

**Pass looks like:** Old cookie/token is rejected (401).  
**Fail looks like:** Old cookie/token still works after logout or password change.  
**Safety:** Own account only.

## 8. Exposed passwords or secrets in code  /  كلمات مرور أو أسرار مكشوفة في الكود

- **OWASP:** A02:2021 | **Default severity:** critical | **Coverage:** auto
- **Risk:** Leaked API keys, DB passwords, signing keys
- **Prevention:** Environment variables or a secret manager; never commit .env or keys to Git
- **Test idea (source checklist):** Search the repo and public files for password, API_KEY, secret, .env files

**Setup:** Repo access plus public site.

**Steps:**
1. Run scan_code.py; review every secret-type hit and .env presence.
2. Search git history: git log -p -S 'API_KEY' (secrets removed later are still exposed).
3. Check front-end bundles and source maps for keys (browser DevTools > Sources/Network).
4. If a real secret is found: rotate first, then clean history.

**Pass looks like:** No secrets in code, history, bundles or public files.  
**Fail looks like:** Any live key/password in repo, history, bundle or public URL.  
**Safety:** Never paste a real secret into chat or the report; mask it.

## 9. Weak or missing encryption  /  تشفير ضعيف أو غياب التشفير

- **OWASP:** A02:2021 | **Default severity:** high | **Coverage:** auto
- **Risk:** Interception of data, passwords or sessions on the network
- **Prevention:** Force HTTPS, hash passwords with bcrypt/Argon2, encrypt sensitive data
- **Test idea (source checklist):** Check whether the site works over HTTP and whether passwords/tokens travel in URLs or logs

**Setup:** Public URL.

**Steps:**
1. Open http:// version: does it redirect to https://? Is HSTS present?
2. Verify TLS config with a standard tool (e.g. SSL Labs/testssl.sh) for old protocols.
3. Confirm passwords are hashed with bcrypt/Argon2 (code/DB schema review, not by reading real hashes).
4. Check tokens/passwords never appear in URLs, referrers or logs.

**Pass looks like:** HTTPS only, HSTS, modern TLS, strong password hashing.  
**Fail looks like:** HTTP serves content, MD5/SHA1/plain passwords, secrets in URLs.  
**Safety:** Do not dump or crack real password hashes.

## 10. Insecure file upload  /  رفع ملفات غير آمن

- **OWASP:** A04:2021 | **Default severity:** critical | **Coverage:** semi
- **Risk:** Malicious file upload, server-side code execution, access to unauthorized files
- **Prevention:** Validate file type, content and size; store outside the executable path; rename files
- **Test idea (source checklist):** Try uploading .php/.exe or double-extension files such as image.php.jpg

**Setup:** Upload feature on staging, account A.

**Steps:**
1. Upload a harmless file with a wrong extension/mime (text file named x.php.jpg, or .html) and check validation.
2. Check the stored name, storage location (outside web root?), served Content-Type, and size limit.
3. Check that uploaded HTML/SVG cannot run script when opened (serve as attachment or from a sandbox domain).
4. Check that another user cannot fetch the file by guessing the URL.

**Pass looks like:** Rejected, renamed, stored outside web root, served as download.  
**Fail looks like:** Executable/script type accepted and reachable at a predictable URL, or SVG/HTML runs script.  
**Safety:** Use inert files only. Never upload real webshells or malware, even to staging.

## 11. Path traversal  /  Path Traversal: تجاوز مسارات الملفات

- **OWASP:** A01:2021 | **Default severity:** high | **Coverage:** semi
- **Risk:** Read sensitive server files such as .env or system files
- **Prevention:** Block ../, pin paths to a fixed folder, validate file names
- **Test idea (source checklist):** Try ../ sequences (plain and URL-encoded) in file download/view parameters

**Setup:** Any endpoint taking a file name/path.

**Steps:**
1. Find parameters like file=, path=, name=, download=, template=.
2. Request a file that exists in your own test uploads using ../ to climb into a sibling test folder you created.
3. Try URL-encoded variants (..%2f) against that same sibling file.
4. Review code: is the final path resolved and checked to be inside the base directory?

**Pass looks like:** Request rejected or normalized to the base directory.  
**Fail looks like:** Sibling-folder test file is returned.  
**Safety:** Prove it with a canary file you placed yourself; never read /etc/passwd or real .env files.

## 12. SSRF: Server-side request forgery  /  SSRF: تزوير طلب من الخادم

- **OWASP:** A10:2021 | **Default severity:** high | **Coverage:** semi
- **Risk:** Server reaches internal services, private network or cloud metadata
- **Prevention:** Allow-list destinations, block internal IP ranges, validate URLs
- **Test idea (source checklist):** Give URL-import fields internal addresses (localhost, link-local metadata IP)

**Setup:** Any feature that fetches a URL (import, webhook, avatar-from-URL, link preview).

**Steps:**
1. Give it a URL you control (a request-bin) to confirm server-side fetching.
2. Check whether it accepts localhost, private ranges and redirects to them (use your own internal test service on staging).
3. Review code for URL allow-list, DNS-resolution check after redirect, and response-size/time limits.

**Pass looks like:** Internal/private targets refused; allow-list enforced.  
**Fail looks like:** Server fetches your internal test service or follows redirects to it.  
**Safety:** Never target cloud metadata or third-party internal systems; use a service you own.

## 13. Input validation errors  /  خطأ في التحقق من المدخلات

- **OWASP:** A03:2021 | **Default severity:** medium | **Coverage:** semi
- **Risk:** Invalid data, system errors, injection flaws
- **Prevention:** Validate on server and client; allow-lists instead of block-lists
- **Test idea (source checklist):** Send very long, negative, empty, special-character or unexpected JSON values

**Setup:** All forms and API bodies.

**Steps:**
1. Send empty, very long (10k chars), negative, zero, decimal, boolean-as-string, nested JSON, unexpected types, unicode/RTL and special characters.
2. Send extra/mass-assignment fields (role, is_admin, price, owner_id) in create/update requests.
3. Check the server validates, not just the UI.

**Pass looks like:** 4xx with a clean message, extra fields ignored.  
**Fail looks like:** 500s, accepted impossible values, privilege fields accepted.  
**Safety:** Use your own records.

## 14. Unsafe error handling  /  معالجة أخطاء غير آمنة

- **OWASP:** A05:2021 | **Default severity:** medium | **Coverage:** auto
- **Risk:** Disclosure of file paths, library versions, SQL queries, server details
- **Prevention:** Generic user-facing errors; details go to secured logs only
- **Test idea (source checklist):** Send malformed input and watch for stack traces, SQL or file paths in responses

**Setup:** Public URL.

**Steps:**
1. Request a random 404 path, a malformed JSON body, an over-long query and invalid types.
2. Look for stack traces, SQL, file paths, framework debug pages and version numbers.
3. Confirm production has debug off.

**Pass looks like:** Generic error page/JSON with no internals.  
**Fail looks like:** Trace, SQL, paths or debug console shown.  
**Safety:** Read-only probes.

## 15. Security misconfiguration  /  إعدادات أمنية خاطئة

- **OWASP:** A05:2021 | **Default severity:** high | **Coverage:** auto
- **Risk:** Open admin pages, disabled protections, server info disclosure, default accounts
- **Prevention:** Harden configuration, remove test pages, disable directory listing, change default credentials
- **Test idea (source checklist):** Probe /admin, /debug, /api/docs, /backup, .git, .env

**Setup:** Public URL.

**Steps:**
1. Run scan_web.py exposed-path check; manually try /admin, /debug, /api/docs, /backup, /.git/, /.env.
2. Check default accounts and sample data, directory listing, open cloud buckets and verbose headers.
3. Review production config: debug off, test routes removed.

**Pass looks like:** Nothing sensitive reachable without auth.  
**Fail looks like:** Any sensitive path/file/doc reachable.  
**Safety:** Do not download full .git history from a site you do not own; reading HEAD is enough.

## 16. Outdated libraries with known vulnerabilities  /  مكتبات أو حزم قديمة فيها ثغرات

- **OWASP:** A06:2021 | **Default severity:** high | **Coverage:** auto
- **Risk:** Exploitation of known flaws in frameworks, plugins or libraries
- **Prevention:** Update libraries, scan dependencies, remove unused ones
- **Test idea (source checklist):** Run SCA tools: npm audit, pip-audit, dependency-check

**Setup:** Repo.

**Steps:**
1. Run pip-audit / npm audit / osv-scanner / dependency-check.
2. Review each high/critical advisory: is the vulnerable function reachable?
3. Plan upgrades and remove unused packages.

**Pass looks like:** No known high/critical issues or documented exceptions.  
**Fail looks like:** Known-exploited or high/critical advisories unresolved.  
**Safety:** Needs network for the advisory DB.

## 17. Unreviewed AI-generated code  /  كود AI غير مُراجَع

- **OWASP:** A04:2021 | **Default severity:** high | **Coverage:** manual
- **Risk:** Wrong logic, missing permission checks, unsafe data handling, duplicated code
- **Prevention:** Human code review, unit and integration tests, static analysis
- **Test idea (source checklist):** Manually review permission, payment, file and API logic; run SAST and unit tests

**Setup:** Repo.

**Steps:**
1. Manually review auth middleware, ownership checks, payment/price logic, file handling and every API route.
2. Run SAST (Semgrep/CodeQL/Bandit) and the test suite; look for placeholder comments like 'in production, add auth'.
3. Check for duplicated or contradictory code paths, unused dangerous endpoints, and missing tests for permissions.

**Pass looks like:** Reviewed by a human, tests cover permissions, SAST clean or triaged.  
**Fail looks like:** Placeholder security, no tests, unreviewed AI output in auth/payment paths.  
**Safety:** Review is read-only.

## 18. Data leakage in logs  /  تسريب بيانات في Logs

- **OWASP:** A09:2021 | **Default severity:** medium | **Coverage:** auto
- **Risk:** Passwords, session tokens or personal data written to logs
- **Prevention:** Never log sensitive fields; classify logs; restrict log access
- **Test idea (source checklist):** Search logs for passwords, tokens, card numbers, personal data

**Setup:** Log access.

**Steps:**
1. Trigger a login with a test password and a request with a test token.
2. Search application, proxy and error-tracker logs for those values and for emails/card numbers.
3. Check log retention and who can read them.

**Pass looks like:** Sensitive values redacted or absent.  
**Fail looks like:** Passwords/tokens/PII appear in logs.  
**Safety:** Use test credentials only.

## 19. No logging or monitoring  /  غياب السجلات والمراقبة

- **OWASP:** A09:2021 | **Default severity:** medium | **Coverage:** manual
- **Risk:** Attacks, breaches or abnormal use go undetected
- **Prevention:** Log logins, permission changes, uploads and repeated failures
- **Test idea (source checklist):** Check whether failed logins and unauthorized access attempts are recorded

**Setup:** Log access.

**Steps:**
1. Produce failed logins, a 403, an upload, a role change and a burst of 429/401s.
2. Verify each is logged with user, IP, time and result, and that alerts exist for repeated failures.

**Pass looks like:** Events recorded and alertable.  
**Fail looks like:** No trace of security events.  
**Safety:** Own test traffic.

## 20. Misconfigured CORS  /  CORS خاطئ

- **OWASP:** A05:2021 | **Default severity:** high | **Coverage:** auto
- **Risk:** External sites read user data or perform requests
- **Prevention:** Allow-list exact origins; never combine * with credentials
- **Test idea (source checklist):** Send a request from a foreign origin to the API and inspect CORS headers

**Setup:** Public API.

**Steps:**
1. Send requests with Origin: https://evil.example and Origin: null.
2. Inspect Access-Control-Allow-Origin and -Credentials; reflection plus credentials is a fail.
3. Check preflight handling for sensitive methods.

**Pass looks like:** Only exact trusted origins allowed.  
**Fail looks like:** Arbitrary origin reflected, or * with credentials.  
**Safety:** Header inspection only.

## 21. No rate limiting  /  Rate Limiting غير موجود

- **OWASP:** A04:2021 | **Default severity:** medium | **Coverage:** auto
- **Risk:** Brute force, system flooding, API abuse
- **Prevention:** Limit requests per user/IP; delay or temporarily block
- **Test idea (source checklist):** Send many repeated requests and see whether throttling or blocking appears

**Setup:** Staging; login, reset, OTP, search, AI/expensive endpoints.

**Steps:**
1. Send a bounded burst (e.g. 30-50 requests) and watch for 429, Retry-After or X-RateLimit headers.
2. For login/OTP, test limits with your own account and a few wrong attempts only.
3. Check per-IP and per-account limits and cost-heavy endpoints.

**Pass looks like:** Throttling or blocking appears.  
**Fail looks like:** No limit at all on sensitive endpoints.  
**Safety:** Keep bursts small; never degrade a production service.

## 22. Business logic flaws  /  Business Logic Flaws

- **OWASP:** A04:2021 | **Default severity:** high | **Coverage:** manual
- **Risk:** Bypass payment steps, change price, reuse coupons, perform actions out of order
- **Prevention:** Enforce business rules on the server, never trust the UI
- **Test idea (source checklist):** Alter price, quantity or order status in DevTools; reuse a coupon; skip a step

**Setup:** Checkout/booking/workflow with test data.

**Steps:**
1. Map the intended step order, then call later steps directly or out of order.
2. Change price, quantity, discount, currency or status in the request; reuse a coupon or voucher; race two identical requests.
3. Check negative quantities, rounding and limits.

**Pass looks like:** Server recomputes price/state and rejects out-of-order steps.  
**Fail looks like:** Tampered values or skipped steps are accepted.  
**Safety:** Test data and sandbox payments only.

## 23. Insecure direct object references in the API  /  Insecure Direct Object References في API

- **OWASP:** A01:2021 | **Default severity:** high | **Coverage:** semi
- **Risk:** Access data or perform actions through the API without verification
- **Prevention:** Verify token, permission and ownership on every endpoint
- **Test idea (source checklist):** Call the API with another account, without a token, or with a disallowed method

**Setup:** Tokens for A, B, and no token.

**Steps:**
1. List every API route from docs/JS/proxy history.
2. Call each with no token, A's token on B's objects, and a disallowed HTTP method.
3. Check that object-level (not only route-level) authorization exists.

**Pass looks like:** 401/403 where expected.  
**Fail looks like:** Data returned or action done without proper rights.  
**Safety:** Prefer read calls; throwaway records for writes.

## 24. Unprotected GraphQL or API  /  GraphQL أو API غير محمية

- **OWASP:** A05:2021 | **Default severity:** medium | **Coverage:** auto
- **Risk:** Complex queries, data exposure, resource exhaustion
- **Prevention:** Limit depth and complexity, check permissions, disable introspection in production
- **Test idea (source checklist):** Try nested queries, sensitive fields, and queries without a token

**Setup:** GraphQL/API endpoint.

**Steps:**
1. Send an introspection query unauthenticated; check if it should be enabled.
2. Send nested queries and aliases to test depth/complexity limits (small bounds).
3. Query sensitive fields and other users' objects.

**Pass looks like:** Introspection off in prod, depth limits, auth on resolvers.  
**Fail looks like:** Schema exposed, unlimited depth, resolvers without auth.  
**Safety:** No resource-exhaustion queries.

## 25. Weak dependency and component management  /  ضعف في إدارة التبعيات والمكونات

- **OWASP:** A06:2021 | **Default severity:** medium | **Coverage:** auto
- **Risk:** Known vulnerabilities or malicious code inside a package
- **Prevention:** Use official sources, pin versions, scan dependencies
- **Test idea (source checklist):** Inspect package-lock.json / requirements.txt for unpinned or known-vulnerable versions

**Setup:** Repo.

**Steps:**
1. Check lockfiles committed, versions pinned, official registry used.
2. Look for typosquatted names, git/http dependencies, and install scripts that fetch code.
3. Generate an SBOM and compare to advisories.

**Pass looks like:** Pinned, verified, minimal dependencies.  
**Fail looks like:** Unpinned/unusual sources or malicious-looking packages.  
**Safety:** Read-only.

## 26. No environment separation  /  عدم فصل البيئات

- **OWASP:** A05:2021 | **Default severity:** high | **Coverage:** manual
- **Risk:** Production reaches test data, or real keys live in a test environment
- **Prevention:** Separate databases, keys and domains for Dev/Staging/Production
- **Test idea (source checklist):** Check for real data or production keys in the test environment

**Setup:** Environment configs.

**Steps:**
1. Compare Dev/Staging/Prod: databases, API keys, domains, storage buckets.
2. Look for production data or keys in staging and for staging services reachable from prod.
3. Check that CI uses separate secrets per environment.

**Pass looks like:** Separate credentials and data.  
**Fail looks like:** Shared DB/keys or real customer data in staging.  
**Safety:** Review config, not data contents.

## 27. No backup or recovery plan  /  عدم وجود نسخ احتياطي أو خطة استرجاع

- **OWASP:** A04:2021 | **Default severity:** medium | **Coverage:** manual
- **Risk:** Data loss or inability to recover after an incident
- **Prevention:** Encrypted off-site backups with periodic restore tests
- **Test idea (source checklist):** Restore a backup in an isolated environment

**Setup:** Ops access.

**Steps:**
1. Ask for backup schedule, encryption, off-site copy and last restore test date.
2. Restore the latest backup into an isolated environment and verify integrity and RPO/RTO.

**Pass looks like:** Recent successful restore test.  
**Fail looks like:** No backups or never tested.  
**Safety:** Restore only into isolation.

## 28. Permissions not reviewed on role change  /  عدم مراجعة الصلاحيات عند تغيير الدور

- **OWASP:** A01:2021 | **Default severity:** high | **Coverage:** semi
- **Risk:** Old privileges persist after a user changes job
- **Prevention:** Review permissions periodically and remove unused ones
- **Test idea (source checklist):** Change a user's role and verify old privileges are revoked immediately

**Setup:** Admin + a test user.

**Steps:**
1. Change the test user's role (or remove them from a group).
2. Immediately retry privileged actions with the old session and a fresh login.
3. Check scheduled permission reviews and stale accounts.

**Pass looks like:** Old privileges revoked at once.  
**Fail looks like:** Old role still works until token expiry or forever.  
**Safety:** Test account only.

## 29. Weak protection of files and downloads  /  ضعف في حماية الملفات والتنزيلات

- **OWASP:** A01:2021 | **Default severity:** high | **Coverage:** semi
- **Risk:** Unauthorized access to files, reports or documents
- **Prevention:** Tie each file to a permission and owner; use signed, expiring links
- **Test idea (source checklist):** Open a file link without logging in, or with a changed file number

**Setup:** Files/reports owned by A.

**Steps:**
1. Copy a download URL; open it logged out and as B.
2. Change the file id/name; check signed-URL expiry and reuse.
3. Check that private files are not under a public static folder.

**Pass looks like:** Access denied or link expired.  
**Fail looks like:** Anyone with/without the link can fetch.  
**Safety:** Test files only.

## 30. No update integrity verification  /  عدم التحقق من سلامة التحديثات

- **OWASP:** A08:2021 | **Default severity:** high | **Coverage:** manual
- **Risk:** Malicious code injected or unauthorized changes deployed
- **Prevention:** Digital signatures, hash checks, restrict who can deploy
- **Test idea (source checklist):** Check whether code/file/update can be pushed without review or permission

**Setup:** Repo/CI/deploy access.

**Steps:**
1. Review who can push/merge/deploy, branch protection, required reviews, signed commits/artifacts.
2. Check update/plugin mechanisms verify signatures or hashes; check CI actions are pinned to SHAs.
3. Try (on a fork/test branch) whether code can ship without review.

**Pass looks like:** Reviews + signature/hash verification enforced.  
**Fail looks like:** Direct push to main/deploy, unsigned updates.  
**Safety:** Use a test branch.
