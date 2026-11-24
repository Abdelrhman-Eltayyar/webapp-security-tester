#!/usr/bin/env python3
"""scan_web.py - safe, low-impact black-box checks for a web app / API.

Standard library only. Covers the catalog items that can be detected without
exploiting anything: transport security, headers, cookies, exposed paths,
error leakage, CORS, rate limiting, reflected-input and SQL-error canaries,
GraphQL introspection, unauthenticated API reads, and CSRF-token heuristics.

It NEVER sends destructive payloads, never brute-forces credentials, never
uploads files and never tries to read files via traversal. Canary strings are
harmless markers; "active" probes are opt-in.

You must pass --authorized to confirm you own the target or have written
permission to test it (localhost is exempt).

Usage:
  python scan_web.py --url https://staging.example.com --authorized \
      [--active] [--burst 40] [--max-requests 300] [--header "Authorization: Bearer X"] \
      [--cookie "sid=abc"] --out findings-web.json
"""
import argparse
import hashlib
import json
import random
import re
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

UA = "webapp-security-tester/1.0 (authorized-assessment)"
MAX_BODY = 300_000


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Budget:
    def __init__(self, n):
        self.left = n

    def spend(self):
        if self.left <= 0:
            raise RuntimeError("request budget exhausted (--max-requests)")
        self.left -= 1


class Client:
    def __init__(self, base, headers, timeout, budget):
        self.base = base.rstrip("/")
        self.headers = headers
        self.timeout = timeout
        self.budget = budget
        self.opener = urllib.request.build_opener(NoRedirect)
        self.all_set_cookies = []

    def url(self, path):
        if path.startswith("http"):
            return path
        return self.base + (path if path.startswith("/") else "/" + path)

    def req(self, path, method="GET", headers=None, data=None):
        self.budget.spend()
        h = {"User-Agent": UA, **self.headers, **(headers or {})}
        if isinstance(data, (dict, list)):
            data = json.dumps(data).encode()
            h.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            data = data.encode()
        r = urllib.request.Request(self.url(path), data=data, headers=h, method=method)
        try:
            resp = self.opener.open(r, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            resp = e
        except Exception as e:  # network error
            return {"status": 0, "headers": {}, "raw_headers": [], "body": "", "error": str(e)}
        try:
            body = resp.read(MAX_BODY).decode("utf-8", "replace")
        except Exception:
            body = ""
        raw = list(resp.headers.items())
        hd = {}
        for k, v in raw:
            hd.setdefault(k.lower(), v)
        sc = resp.headers.get_all("Set-Cookie") or []
        self.all_set_cookies.extend(sc)
        return {"status": resp.status if hasattr(resp, "status") else resp.code,
                "headers": hd, "raw_headers": raw, "body": body, "error": None,
                "set_cookie": sc}


findings = []
tested = set()


_seen = set()


def add(cid, status, severity, title, evidence="", location="", rec=""):
    key = (cid, status, title, location)
    if key in _seen:
        return
    _seen.add(key)
    findings.append({"catalog_id": cid, "status": status, "severity": severity,
                     "title": title, "evidence": evidence[:600], "location": location,
                     "recommendation": rec, "source": "scan_web"})


def mark(*ids):
    tested.update(ids)


# ---------------------------------------------------------------- checks

def check_transport(c, base):
    mark(9)
    p = urllib.parse.urlparse(base)
    local = p.hostname in ("localhost", "127.0.0.1", "::1")
    if p.scheme == "http" and not local:
        add(9, "fail", "high", "Site is served over plain HTTP", base, base,
            "Serve everything over HTTPS and redirect HTTP to HTTPS.")
    elif p.scheme == "https":
        r = c.req("/")
        if "strict-transport-security" not in r["headers"]:
            add(9, "warn", "medium", "HSTS header missing", "No Strict-Transport-Security header", base,
                "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.")
        else:
            add(9, "pass", "info", "HSTS present", r["headers"]["strict-transport-security"], base)
        # does plain http redirect to https?
        try:
            http_url = "http://" + p.netloc + "/"
            c.budget.spend()
            rr = c.opener.open(urllib.request.Request(http_url, headers={"User-Agent": UA}), timeout=c.timeout)
            code, loc = rr.status, rr.headers.get("Location", "")
        except urllib.error.HTTPError as e:
            code, loc = e.code, e.headers.get("Location", "")
        except Exception:
            code, loc = 0, ""
        if code == 200:
            add(9, "fail", "high", "HTTP version of the site answers 200 without redirecting to HTTPS", http_url, http_url,
                "Redirect all HTTP traffic to HTTPS (301) and enable HSTS.")
        elif code in (301, 302, 307, 308) and loc.startswith("https://"):
            add(9, "pass", "info", "HTTP redirects to HTTPS", loc, http_url)
    elif local:
        add(9, "info", "info", "Local target over HTTP: transport check skipped", base, base)


def check_headers(c, base):
    mark(15, 20, 4, 14)
    r = c.req("/")
    h = r["headers"]
    if r["status"] == 0:
        add(15, "warn", "info", "Target not reachable", r["error"] or "", base)
        return r
    want = [
        ("content-security-policy", 4, "medium", "Content-Security-Policy missing",
         "Add a restrictive CSP (default-src 'self'; no 'unsafe-inline' where possible)."),
        ("x-content-type-options", 15, "low", "X-Content-Type-Options missing",
         "Send X-Content-Type-Options: nosniff."),
        ("referrer-policy", 15, "low", "Referrer-Policy missing",
         "Send Referrer-Policy: strict-origin-when-cross-origin."),
    ]
    for hdr, cid, sev, title, rec in want:
        if hdr not in h:
            add(cid, "warn", sev, title, f"Header {hdr} absent", base, rec)
        else:
            add(cid, "pass", "info", f"{hdr} present", h[hdr][:200], base)
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        add(15, "warn", "low", "Clickjacking protection missing", "No X-Frame-Options / frame-ancestors", base,
            "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.")
    for hdr in ("server", "x-powered-by", "x-aspnet-version"):
        v = h.get(hdr, "")
        if re.search(r"\d+\.\d+", v):
            add(14, "warn", "low", f"Version disclosure in {hdr} header", f"{hdr}: {v}", base,
                "Strip or genericize version banners.")
    if "index of /" in r["body"].lower():
        add(15, "fail", "medium", "Directory listing enabled on the root", "'Index of /' in body", base,
            "Disable directory listing.")
    return r


def check_cookies(c, base):
    mark(7)
    seen = set()
    for sc in c.all_set_cookies:
        name = sc.split("=", 1)[0].strip()
        if name in seen:
            continue
        seen.add(name)
        low = sc.lower()
        problems = []
        if "httponly" not in low:
            problems.append("HttpOnly")
        if "secure" not in low and base.startswith("https"):
            problems.append("Secure")
        if "samesite" not in low:
            problems.append("SameSite")
        if problems:
            add(7, "warn" if name.lower() not in ("session", "sid", "sessionid", "phpsessid", "jsessionid", "connect.sid", "token") else "fail",
                "medium", f"Cookie '{name}' lacks {', '.join(problems)}", sc[:200], base,
                "Set HttpOnly; Secure; SameSite=Lax (or Strict) on session cookies.")
        else:
            add(7, "pass", "info", f"Cookie '{name}' has secure flags", "", base)
    if not seen:
        add(7, "info", "info", "No cookies set on the landing page (session checks need an authenticated flow)", "", base)


EXPOSED = [
    # path, catalog id, severity, validator(kind), title
    ("/.env", 8, "critical", "env", "Environment file exposed"),
    ("/.git/HEAD", 8, "critical", "git", "Git repository exposed"),
    ("/.git/config", 8, "critical", "gitcfg", "Git config exposed"),
    ("/.DS_Store", 15, "low", "bin", ".DS_Store exposed"),
    ("/backup.zip", 15, "high", "bin", "Backup archive exposed"),
    ("/backup.sql", 15, "high", "sql", "SQL backup exposed"),
    ("/db.sqlite3", 15, "high", "bin", "SQLite database exposed"),
    ("/config.json", 15, "medium", "json", "config.json exposed"),
    ("/package.json", 25, "low", "json", "package.json publicly readable"),
    ("/requirements.txt", 25, "low", "text", "requirements.txt publicly readable"),
    ("/phpinfo.php", 15, "high", "phpinfo", "phpinfo() exposed"),
    ("/server-status", 15, "medium", "apache", "Apache server-status exposed"),
    ("/actuator/env", 15, "high", "json", "Spring actuator env exposed"),
    ("/actuator", 15, "medium", "json", "Spring actuator exposed"),
    ("/debug", 15, "high", "any", "Debug endpoint reachable"),
    ("/admin", 1, "medium", "any", "Admin path reachable without auth (verify it requires login)"),
    ("/api/docs", 15, "low", "any", "API docs reachable (confirm intended for production)"),
    ("/docs", 15, "low", "any", "API docs reachable (confirm intended for production)"),
    ("/swagger.json", 15, "low", "json", "Swagger spec reachable"),
    ("/openapi.json", 15, "low", "json", "OpenAPI spec reachable"),
    ("/swagger-ui/", 15, "low", "any", "Swagger UI reachable"),
]


def validate(kind, body, ctype):
    b = body.lstrip()
    if kind == "env":
        return bool(re.search(r"^[A-Z0-9_]{3,}\s*=", body, re.M))
    if kind == "git":
        return b.startswith("ref:")
    if kind == "gitcfg":
        return "[core]" in body
    if kind == "sql":
        return bool(re.search(r"(CREATE TABLE|INSERT INTO|DROP TABLE)", body, re.I))
    if kind == "json":
        return b.startswith("{") or b.startswith("[")
    if kind == "phpinfo":
        return "PHP Version" in body
    if kind == "apache":
        return "Apache Server Status" in body
    if kind == "text":
        return bool(re.search(r"^[A-Za-z0-9_.-]+(==|>=|~=)", body, re.M))
    if kind == "bin":
        return "text/html" not in ctype
    return True


def check_exposed(c, base):
    mark(15, 8, 24, 25, 1)
    junk = "/" + "".join(random.choices(string.ascii_lowercase, k=14))
    base404 = c.req(junk)
    base_hash = hashlib.md5(base404["body"].encode()).hexdigest()
    base_len = len(base404["body"])
    hits = 0
    for path, cid, sev, kind, title in EXPOSED:
        r = c.req(path)
        if r["status"] != 200:
            continue
        # skip SPA/catch-all that serves the same page for any URL
        if hashlib.md5(r["body"].encode()).hexdigest() == base_hash or (base404["status"] == 200 and abs(len(r["body"]) - base_len) < 40):
            continue
        ctype = r["headers"].get("content-type", "")
        if not validate(kind, r["body"], ctype):
            continue
        hits += 1
        st = "fail" if sev in ("critical", "high") else "warn"
        add(cid, st, sev, title, f"GET {path} -> 200, {len(r['body'])} bytes", c.url(path),
            "Remove the file/route from the public web root or require authentication; rotate any secret that was exposed.")
    if hits == 0:
        add(15, "pass", "info", "No common sensitive paths exposed", f"{len(EXPOSED)} paths probed", base)
        add(8, "pass", "info", "No .env/.git exposure found over HTTP", "", base)


def check_errors(c, base):
    mark(14, 13)
    sigs = [r"Traceback \(most recent call last\)", r"at [\w.$]+\([\w]+\.java:\d+\)", r"SQLSTATE\[", r"ORA-\d{4,5}",
            r"You have an error in your SQL syntax", r"mysqli?_", r"psycopg2\.", r"Microsoft OLE DB", r"System\.\w+Exception",
            r"Werkzeug Debugger", r"DEBUG = True", r"/var/www/", r"C:\\\\(Users|inetpub)", r"node_modules/", r"at Object\.<anonymous>",
            r"Whitelabel Error Page", r"Stack trace:", r"Fatal error:", r"Django.*DEBUG"]
    probes = [("/" + "".join(random.choices(string.ascii_lowercase, k=10)), "GET", None, None),
              ("/?id=%", "GET", None, None),
              ("/?q=" + "A" * 3000, "GET", None, None),
              ("/api/" + "".join(random.choices(string.ascii_lowercase, k=8)), "POST", "{bad json", {"Content-Type": "application/json"})]
    leaked = False
    for path, m, data, hd in probes:
        r = c.req(path, m, hd, data)
        for s in sigs:
            mt = re.search(s, r["body"], re.I)
            if mt:
                leaked = True
                add(14, "fail", "medium", "Error response leaks internals", f"{m} {path[:60]} -> {r['status']}: matched '{mt.group(0)[:80]}'",
                    c.url(path[:60]), "Return generic errors to users; log details server-side; disable debug mode in production.")
                break
    if not leaked:
        add(14, "pass", "info", "No stack traces or internals in error responses", f"{len(probes)} error probes", base)


def check_cors(c, base):
    mark(20)
    bad = False
    for origin in ("https://evil.example", "null"):
        r = c.req("/", headers={"Origin": origin})
        acao = r["headers"].get("access-control-allow-origin", "")
        acac = r["headers"].get("access-control-allow-credentials", "").lower() == "true"
        if acao == origin and acac:
            bad = True
            add(20, "fail", "high", "CORS reflects arbitrary Origin with credentials", f"Origin: {origin} -> ACAO: {acao}, ACAC: true", base,
                "Allow-list exact origins; never reflect Origin together with Allow-Credentials.")
        elif acao == "*" and acac:
            bad = True
            add(20, "fail", "high", "CORS wildcard with credentials", "ACAO: * and ACAC: true", base, "Never combine * with credentials.")
        elif acao == origin:
            bad = True
            add(20, "warn", "medium", "CORS reflects arbitrary Origin (no credentials)", f"Origin: {origin} -> ACAO: {acao}", base,
                "Replace reflection with an explicit allow-list.")
        elif acao == "*":
            add(20, "info", "info", "CORS allows any origin (*); acceptable only for fully public data", "", base)
    if not bad:
        add(20, "pass", "info", "No unsafe CORS reflection observed", "", base)


def check_graphql(c, base):
    mark(24)
    for path in ("/graphql", "/api/graphql", "/graphiql"):
        r = c.req(path, "POST", data={"query": "{__schema{queryType{name}}}"})
        if r["status"] == 200 and "__schema" in r["body"] and "queryType" in r["body"]:
            add(24, "fail", "medium", "GraphQL introspection enabled without authentication", f"POST {path} returned schema", c.url(path),
                "Disable introspection in production, require auth, and limit query depth/complexity.")
            return
        if r["status"] in (200, 400) and ("errors" in r["body"] or "data" in r["body"]) and "graph" in path:
            add(24, "info", "info", "GraphQL endpoint present (introspection appears disabled)", path, c.url(path))
            return
    add(24, "pass", "info", "No GraphQL endpoint found at common paths", "", base)


def check_unauth_api(c, base):
    mark(23, 1)
    paths = ["/api/users", "/api/user", "/api/admin", "/api/orders", "/api/me", "/api/v1/users", "/users", "/api/accounts"]
    found = False
    for p in paths:
        r = c.req(p, headers={"Authorization": ""})
        ct = r["headers"].get("content-type", "")
        if r["status"] == 200 and "json" in ct and len(r["body"]) > 20 and r["body"].strip() not in ("[]", "{}"):
            found = True
            add(23, "fail", "high", f"API returns data without authentication: {p}", f"GET {p} -> 200 JSON, {len(r['body'])} bytes", c.url(p),
                "Require a valid token and verify role/ownership on every endpoint.")
    if not found:
        add(23, "pass", "info", "Common API list endpoints require authentication or do not exist", f"{len(paths)} paths", base)


def check_rate_limit(c, base, burst, login_path):
    mark(21)
    target = login_path or "/"
    codes, limited = [], False
    t0 = time.time()
    for _ in range(burst):
        r = c.req(target)
        codes.append(r["status"])
        h = r["headers"]
        if r["status"] == 429 or "retry-after" in h or any(k.startswith("x-ratelimit") or k == "ratelimit-limit" for k in h):
            limited = True
            break
    dt = time.time() - t0
    if limited:
        add(21, "pass", "info", "Rate limiting signals observed", f"{len(codes)} requests, throttle headers/429 seen", c.url(target))
    else:
        add(21, "warn", "medium", f"No throttling observed after {len(codes)} rapid requests ({dt:.1f}s)",
            f"statuses: {sorted(set(codes))}", c.url(target),
            "Add per-IP/per-user limits (especially on login, reset, OTP and expensive endpoints). Confirm with a login-specific test.")


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.links, self._f = [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._f = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self._f)
        elif tag in ("input", "textarea", "select") and self._f is not None:
            self._f["inputs"].append({"name": a.get("name", ""), "type": (a.get("type") or "text").lower()})
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "form":
            self._f = None


def check_forms(c, base, home):
    mark(5, 9)
    pp = PageParser()
    try:
        pp.feed(home["body"])
    except Exception:
        pass
    for f in pp.forms:
        names = " ".join(i["name"].lower() for i in f["inputs"])
        has_pw = any(i["type"] == "password" for i in f["inputs"])
        if f["method"] == "post" and not re.search(r"csrf|token|authenticity|xsrf|nonce|__requestverificationtoken", names):
            add(5, "warn", "medium", "POST form without a visible CSRF token", f"action={f['action'] or '(self)'} fields={names[:100]}", base,
                "Add per-session CSRF tokens (or rely on SameSite=Strict/Lax cookies plus Origin checks) and confirm server-side validation.")
        if has_pw and f["method"] == "get":
            add(9, "fail", "high", "Password form submits via GET (credentials land in URLs and logs)", f"action={f['action']}", base,
                "Use POST over HTTPS.")
        if has_pw and f["action"].startswith("http://"):
            add(9, "fail", "high", "Password form posts to an HTTP URL", f["action"], base, "Post credentials only to HTTPS endpoints.")
    for l in pp.links:
        if re.search(r"[?&](password|passwd|token|api_?key|secret)=", l, re.I):
            add(9, "warn", "medium", "Sensitive-looking parameter in a URL", l[:120], base, "Never put secrets in URLs.")
    return pp


def params_from_page(c, base, pp, home):
    """Collect a few same-origin GET parameters to canary-test."""
    out = []
    host = urllib.parse.urlparse(base).netloc
    cands = list(pp.links) + [f["action"] + "?" + "&".join(i["name"] + "=1" for i in f["inputs"] if i["name"])
                              for f in pp.forms if f["method"] == "get"]
    for l in cands:
        u = urllib.parse.urlparse(urllib.parse.urljoin(base + "/", l))
        if u.netloc != host or not u.query:
            continue
        q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        for k, _ in q:
            out.append((u.path or "/", q, k))
    seen, uniq = set(), []
    for p, q, k in out:
        if (p, k) not in seen:
            seen.add((p, k))
            uniq.append((p, q, k))
    return uniq[:10]


def check_injection_canaries(c, base, params):
    mark(4, 3, 13)
    if not params:
        add(4, "info", "info", "No GET parameters discovered on the landing page to canary-test (give --param-url for specific pages)", "", base)
        return
    sql_sigs = [r"error in your SQL syntax", r"SQL syntax.*MySQL", r"SQLSTATE\[", r"ORA-\d{5}", r"unterminated quoted string", r"SQLite3?::", r"sqlite3\.OperationalError",
                r"Unclosed quotation mark", r"psycopg2", r"pg_query"]
    tag = "zq" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    xss_hit = sql_hit = False
    for path, q, key in params:
        def build(val):
            qq = [(k, val if k == key else v) for k, v in q]
            return path + "?" + urllib.parse.urlencode(qq)
        r = c.req(build(tag + "<i>\"'"))
        if (tag + "<i>") in r["body"]:
            xss_hit = True
            add(4, "fail", "high", f"Reflected input is not HTML-encoded (parameter '{key}')", f"marker with <i> echoed raw at {path}", c.url(path),
                "HTML-encode output by context, sanitize rich text, and add a CSP.")
        base_r = c.req(build("1"))
        r2 = c.req(build("1'"))
        for s in sql_sigs:
            if re.search(s, r2["body"], re.I) and not re.search(s, base_r["body"], re.I):
                sql_hit = True
                add(3, "fail", "critical", f"Database error triggered by a single quote (parameter '{key}')", f"matched /{s}/ at {path}", c.url(path),
                    "Use parameterized queries / ORM bindings; never concatenate user input into SQL.")
                break
        if r2["status"] >= 500 and base_r["status"] < 500:
            add(13, "warn", "medium", f"Server error (5xx) on unexpected input (parameter '{key}')", f"{r2['status']} at {path}", c.url(path),
                "Validate and reject malformed input with a 4xx response.")
    if not xss_hit:
        add(4, "pass", "info", "No unencoded reflection found in discovered parameters", f"{len(params)} parameters", base)
    if not sql_hit:
        add(3, "pass", "info", "No SQL error signatures from single-quote probes", f"{len(params)} parameters", base)


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True)
    ap.add_argument("--authorized", action="store_true", help="confirm you own the target or have written permission")
    ap.add_argument("--active", action="store_true", help="also run rate-limit burst and canary injection probes")
    ap.add_argument("--burst", type=int, default=40, help="requests in the rate-limit burst (max 150)")
    ap.add_argument("--login-path", default="", help="path to burst for the rate-limit check (default /)")
    ap.add_argument("--param-url", action="append", default=[], help="extra page URLs (with query strings) to canary-test; repeatable")
    ap.add_argument("--header", action="append", default=[], help="extra header 'Name: value'; repeatable")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--max-requests", type=int, default=300)
    ap.add_argument("--out", default="findings-web.json")
    a = ap.parse_args()

    u = urllib.parse.urlparse(a.url)
    if u.scheme not in ("http", "https") or not u.hostname:
        sys.exit("Provide a full URL, e.g. https://staging.example.com")
    local = u.hostname in ("localhost", "127.0.0.1", "::1")
    if not a.authorized and not local:
        sys.exit("Refusing to scan: pass --authorized to confirm you own this target or have written permission.")

    headers = {}
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if a.cookie:
        headers["Cookie"] = a.cookie

    base = f"{u.scheme}://{u.netloc}"
    c = Client(base, headers, a.timeout, Budget(a.max_requests))
    steps = [("transport", lambda: check_transport(c, base))]
    home = {}

    def hdrs():
        home.update(check_headers(c, base))
    steps += [("headers", hdrs), ("exposed paths", lambda: check_exposed(c, base)),
              ("error handling", lambda: check_errors(c, base)), ("cors", lambda: check_cors(c, base)),
              ("graphql", lambda: check_graphql(c, base)), ("unauth api", lambda: check_unauth_api(c, base))]
    pp_holder = {}

    def forms():
        pp_holder["pp"] = check_forms(c, base, home or c.req("/"))
    steps.append(("forms", forms))
    if a.active:
        steps.append(("rate limit", lambda: check_rate_limit(c, base, min(a.burst, 150), a.login_path)))

        def canaries():
            params = params_from_page(c, base, pp_holder.get("pp") or PageParser(), home)
            for pu in a.param_url:
                pr = urllib.parse.urlparse(pu)
                q = urllib.parse.parse_qsl(pr.query, keep_blank_values=True)
                for k, _ in q:
                    params.append((pr.path or "/", q, k))
            check_injection_canaries(c, base, params[:20])
        steps.append(("canary injection", canaries))
    steps.append(("cookies", lambda: check_cookies(c, base)))

    for name, fn in steps:
        try:
            fn()
        except RuntimeError as e:
            print(f"[!] {e}", file=sys.stderr)
            break
        except Exception as e:  # keep scanning
            print(f"[!] step '{name}' failed: {e}", file=sys.stderr)
    if not a.active:
        add(21, "not_tested", "info", "Rate limiting not tested (run with --active)", "", base)
        add(3, "not_tested", "info", "SQL error canaries not run (run with --active)", "", base)

    out = {"tool": "scan_web", "target": base, "active": a.active,
           "requests_used": a.max_requests - c.budget.left,
           "tested_catalog_ids": sorted(tested), "findings": findings}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    n = {s: sum(1 for x in findings if x["status"] == s) for s in ("fail", "warn", "pass", "info", "not_tested")}
    print(f"scan_web done: {out['requests_used']} requests -> {a.out}  {n}")


if __name__ == "__main__":
    main()
