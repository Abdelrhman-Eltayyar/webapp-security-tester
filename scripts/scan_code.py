#!/usr/bin/env python3
"""scan_code.py - lightweight static review of a web-app repository.

Standard library only. Finds secrets, risky patterns and supply-chain smells
and maps every hit to the 30-item catalog (references/catalog.json). It is a
fast first pass, not a replacement for a real SAST tool: expect false
positives, and always confirm in context.

Optional: if `pip-audit`, `npm` or `semgrep` are installed (and the network is
allowed) they are run and summarised.

Usage:
  python scan_code.py --path ./my-app --out findings-code.json [--no-tools]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "dist", "build", "__pycache__", "vendor",
             ".next", ".nuxt", "coverage", ".idea", ".vscode", "site-packages", ".tox", "target"}
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".java", ".go", ".cs", ".html", ".htm", ".vue",
            ".svelte", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".md", ".txt",
            ".properties", ".xml", ".gradle", ".tf"}
MAX_SIZE = 1_000_000
PER_RULE_CAP = 15

PLACEHOLDER = re.compile(r"(your[_-]?|example|changeme|change_me|xxxx|<.+>|\$\{|process\.env|os\.environ|getenv|"
                         r"placeholder|dummy|sample|test(?:ing)?[_-]?(?:key|pass)|\*{3,}|secret_key_here)", re.I)

# (id, severity, title, regex, file_ext_filter or None, recommendation)
RULES = [
    # --- secrets (8)
    (8, "critical", "AWS access key id", r"\bAKIA[0-9A-Z]{16}\b", None, "Remove from code, rotate the key, load from env/secret manager."),
    (8, "critical", "Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", None, "Remove, rotate and store in a secret manager."),
    (8, "critical", "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", None, "Revoke the token and use CI secrets."),
    (8, "critical", "Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", None, "Revoke and rotate."),
    (8, "critical", "Stripe live key", r"\b[sr]k_live_[A-Za-z0-9]{16,}\b", None, "Revoke and rotate; keep keys server-side in env."),
    (8, "critical", "Anthropic/OpenAI-style API key", r"\bsk-(?:ant-)?[A-Za-z0-9_-]{24,}\b", None, "Revoke, rotate, load from env."),
    (8, "critical", "Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", None, "Restrict/rotate the key; keep it out of source."),
    (8, "high", "Hard-coded credential assignment",
     r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|jwt[_-]?secret)\b\s*[:=]\s*['\"][^'\"\s]{6,}['\"]",
     None, "Move to environment variables or a secret manager; rotate if real."),
    (8, "high", "Credentials inside a connection string", r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^/\s:@]+:[^/\s@]{3,}@", None,
     "Use env vars for DSNs; rotate the password."),
    # --- crypto / transport (9)
    (9, "high", "Weak hash (MD5/SHA1) - never use for passwords", r"(?i)\b(?:hashlib\.(?:md5|sha1)|md5\(|sha1\(|createHash\(['\"](?:md5|sha1)['\"]\))", None,
     "Hash passwords with bcrypt/Argon2/scrypt."),
    (9, "high", "TLS verification disabled", r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0))", None,
     "Never disable certificate verification outside local dev."),
    (9, "medium", "Hard-coded plain http:// endpoint", r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|schemas\.|www\.w3\.org|example\.)[a-z0-9.-]+\.[a-z]{2,}", {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".java", ".go", ".cs", ".yml", ".yaml", ".json"},
     "Use https:// for every external endpoint."),
    # --- injection (3, 4, 13)
    (3, "high", "SQL built from strings (concatenation / f-string / template)",
     r"(?i)(?:execute|query|raw|prepare)\s*\(\s*(?:f['\"]|`|['\"][^'\"]*(?:select|insert|update|delete)\b[^'\"]*['\"]\s*(?:\+|%|\.format))[^)]*(?:select|insert|update|delete)\b[^)]*(?:\{|\$\{|\+|%s|%\s*\()",
     {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".java", ".go", ".cs"}, "Use parameterized queries / ORM bindings."),
    (3, "high", "SQL keyword + string interpolation on one line",
     r"(?i)['\"`]\s*(?:select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\s[^'\"`]*['\"`]\s*(?:\+|\.format\()|f['\"](?:select|insert|update|delete)\s[^'\"]*\{",
     {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".java", ".go", ".cs"}, "Use parameterized queries / ORM bindings."),
    (4, "high", "Raw HTML sink (XSS risk)", r"(?i)(\.innerHTML\s*=|\.outerHTML\s*=|dangerouslySetInnerHTML|document\.write\(|v-html=|\|\s*safe\b|mark_safe\(|\{\{\{|Html\.Raw\(|\$\(.+\)\.html\()",
     None, "Encode output or sanitize with a vetted library (e.g. DOMPurify); add CSP."),
    (13, "high", "Dynamic code execution (eval/exec/Function)", r"(?<![\w.])(?:eval|exec)\s*\(|new\s+Function\s*\(|setTimeout\(\s*['\"]", {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb"},
     "Remove dynamic evaluation of input; use safe parsers."),
    (13, "high", "Shell command execution", r"(?i)(shell\s*=\s*True|os\.system\(|child_process\.exec\(|\bpopen\(|Runtime\.getRuntime\(\)\.exec|shell_exec\(|passthru\()", {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb", ".java"},
     "Avoid shells; pass argument arrays and validate input against an allow-list."),
    (13, "high", "Unsafe deserialization", r"(?i)(pickle\.loads?\(|yaml\.load\((?!.*SafeLoader)|marshal\.loads\(|unserialize\(|ObjectInputStream)", {".py", ".php", ".java", ".rb"},
     "Use JSON or safe loaders; never deserialize untrusted data."),
    # --- auth/session (6, 7)
    (6, "high", "JWT verification disabled or 'none' algorithm", r"(?i)(verify_signature['\"]?\s*:\s*False|verify\s*=\s*False.*jwt|algorithms?\s*=\s*\[?['\"]none['\"]|jwt\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true)", None,
     "Always verify signature and expiry; pin allowed algorithms."),
    (7, "medium", "Cookie / session flags disabled", r"(?i)(httponly\s*[:=]\s*(?:false|0)|secure\s*[:=]\s*(?:false|0)|SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|samesite\s*[:=]\s*['\"]?none)", None,
     "Set HttpOnly, Secure and SameSite=Lax/Strict on session cookies."),
    (7, "medium", "Very long / non-expiring session or token lifetime", r"(?i)(expires?_?in|maxAge|max_age|PERMANENT_SESSION_LIFETIME)\s*[:=]\s*[^\n]*?(\b\d{9,}\b|365\s*\*|never)", None,
     "Use short-lived tokens with refresh and server-side revocation."),
    # --- config (15), CORS (20), CSRF (5)
    (15, "high", "Debug mode enabled", r"(?i)(\bDEBUG\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1|NODE_ENV\s*=\s*['\"]?development|display_errors\s*=\s*(?:On|1))", None,
     "Disable debug in production builds and configs."),
    (15, "medium", "Wildcard allowed hosts / trusted hosts", r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]", {".py"}, "List exact hostnames."),
    (15, "high", "Default credentials", r"(?i)(admin\s*[:/]\s*admin\b|admin\s*[:/]\s*password\b|root\s*[:/]\s*root\b|user(name)?\s*[:=]\s*['\"]admin['\"][^\n]{0,40}pass(word)?\s*[:=]\s*['\"](admin|password|123456|1234|changeme)['\"])", None,
     "Remove default accounts; force a unique strong password at install."),
    (20, "high", "CORS wildcard / permissive origin", r"(?i)(Access-Control-Allow-Origin['\"]?\s*[:,=]\s*['\"]?\*|origin\s*:\s*['\"]\*['\"]|origin\s*:\s*true\b|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allow_origins\s*=\s*\[\s*['\"]\*['\"]|\bCORS\(\s*app\s*\))", None,
     "Allow-list exact origins; never combine * with credentials."),
    (5, "high", "CSRF protection explicitly disabled", r"(?i)(@csrf_exempt|csrf\(\)\.disable|csrf\s*:\s*false|WTF_CSRF_ENABLED\s*=\s*False|\.csrf\(\)\s*\.disable|skip_before_action\s*:verify_authenticity_token|csrf\.exempt)", None,
     "Keep CSRF protection on for state-changing browser requests."),
    (24, "medium", "GraphQL introspection / playground enabled", r"(?i)(introspection\s*[:=]\s*(?:true|True)|playground\s*[:=]\s*(?:true|True)|graphiql\s*[:=]\s*(?:true|True))", None,
     "Disable introspection and playground in production."),
    # --- files (10, 11, 12, 29)
    (11, "high", "File path built from request data", r"(?i)(?:open|send_file|sendFile|readFile(?:Sync)?|createReadStream|file_get_contents|include|require)\s*\([^)\n]*(?:request\.|req\.(?:query|params|body)|\$_(?:GET|POST|REQUEST))", {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb"},
     "Resolve against a fixed base dir, reject '..', allow-list file names."),
    (12, "high", "Outbound HTTP request to a URL from request data", r"(?i)(?:requests\.(?:get|post)|urlopen|fetch|axios\.(?:get|post)|http\.get|curl_exec|file_get_contents)\s*\([^)\n]*(?:request\.|req\.(?:query|params|body)|\$_(?:GET|POST|REQUEST))", {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb"},
     "Allow-list destinations; block private/link-local ranges after DNS resolution."),
    (10, "medium", "File-upload handler - verify validation", r"(?i)(request\.files|multer\s*\(|\$_FILES|IFormFile|upload\.single|upload\.array|FileField\()", {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".cs", ".rb"},
     "Check type by content (magic bytes), size limit, random file name, storage outside web root, no execute permission."),
    (29, "medium", "Uploads / private folder served statically", r"(?i)(express\.static\(['\"][^'\"]*(?:upload|private|files|reports|download)[^'\"]*['\"]|send_from_directory\([^)]*upload|StaticFiles\([^)]*(?:upload|files))", None,
     "Serve private files through an authorization check or signed, expiring URLs."),
    # --- logging (18)
    (18, "medium", "Sensitive value written to logs", r"(?i)(?:print|console\.(?:log|info|debug)|logger?\.\w+|logging\.\w+|log\.\w+|Log\.\w+|error_log)\s*\([^)\n]*(?:password|passwd|secret|token|authorization|api[_-]?key|card[_-]?number|cvv|ssn)", None,
     "Redact sensitive fields before logging."),
    # --- AI-code smells (17)
    (17, "medium", "AI/placeholder code marker", r"(?i)(in a real (?:app|application|world)|for (?:demo|demonstration|illustration) purposes|not for production|simplified (?:version|for)|placeholder (?:auth|logic|check)|todo:?\s*(?:add|implement)?\s*(?:auth|security|validation|permission)|fixme:?\s*(?:auth|security)|as an ai|insecure[, ]+but)", None,
     "Replace placeholders with real implementations and review by a human."),
    (17, "medium", "Authorization decided on client-supplied role/flag", r"(?i)(req\.(?:body|query)\.(?:is_?admin|role|admin)|request\.(?:json|form|args)(?:\.get\()?\[?['\"](?:is_?admin|role)['\"]|localStorage\.(?:getItem|setItem)\(['\"](?:role|isAdmin|is_admin)['\"])", None,
     "Derive roles from the server-side session/token, never from client input."),
]

ROUTE_ID = re.compile(r"(?i)(?:@\w+\.(?:route|get|put|patch|delete|post)\(|\b(?:app|router)\.(?:get|put|patch|delete|post)\(|path\()\s*['\"]([^'\"]*(?:<(?:int:|uuid:|str:)?\w*id\w*>|:\w*id\b|\{\w*id\w*\})[^'\"]*)['\"]")
AUTH_HINT = re.compile(r"(?i)(login_required|requires_auth|authenticate|authorize|permission|isAuthenticated|verifyToken|jwt_required|@auth|current_user|req\.user|request\.user|Depends\(get_current|\[Authorize\]|can\?|policy)")

findings = []
tested = set()
rule_counts = {}


def add(cid, status, sev, title, evidence="", location="", rec=""):
    findings.append({"catalog_id": cid, "status": status, "severity": sev, "title": title,
                     "evidence": evidence[:300], "location": location, "recommendation": rec, "source": "scan_code"})


def mask(s):
    s = s.strip()
    return (s[:6] + "…[masked]") if len(s) > 10 else "[masked]"


def walk(root):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            p = os.path.join(dp, f)
            ext = os.path.splitext(f)[1].lower()
            if f.startswith(".env") or ext in CODE_EXT or f in ("Dockerfile", "Makefile", "Gemfile", "Procfile"):
                try:
                    if os.path.getsize(p) <= MAX_SIZE:
                        yield p, ext if not f.startswith(".env") else ".env"
                except OSError:
                    pass


def scan_file(path, ext, root):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().splitlines()
    except Exception:
        return None
    rel = os.path.relpath(path, root)
    is_doc = ext in (".md", ".txt")
    for i, line in enumerate(lines, 1):
        if len(line) > 800:
            continue
        if ext == ".env":
            em = re.match(r"\s*(?:export\s+)?(\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE)\w*)\s*=\s*(\S{4,})", line, re.I)
            if em and not PLACEHOLDER.search(line):
                key = (8, ".env value")
                rule_counts[key] = rule_counts.get(key, 0) + 1
                if rule_counts[key] <= PER_RULE_CAP:
                    add(8, "fail", "high", f"Real-looking secret value in env file ({em.group(1)})", f"{em.group(1)}={mask(em.group(2))}",
                        f"{rel}:{i}", "Keep env files out of Git; rotate this secret.")
        for cid, sev, title, rx, exts, rec in RULES:
            if exts and ext not in exts:
                continue
            if is_doc and cid not in (8,):
                continue
            m = re.search(rx, line)
            if not m:
                continue
            if cid == 8 and PLACEHOLDER.search(line):
                continue
            if cid == 8 and ext == ".env" and False:
                continue
            key = (cid, title)
            rule_counts[key] = rule_counts.get(key, 0) + 1
            if rule_counts[key] > PER_RULE_CAP:
                continue
            ev = line.strip()
            if cid == 8:
                ev = re.sub(r"(['\"])([^'\"\s]{4})[^'\"\s]*(['\"])", r"\1\2***\3", ev)
                if "PRIVATE KEY" in ev:
                    ev = "-----BEGIN … PRIVATE KEY-----"
            add(cid, "fail" if sev in ("critical", "high") else "warn", sev, title, ev, f"{rel}:{i}", rec)
    # route + id without any auth hint nearby (IDOR/BAC review hints)
    for i, line in enumerate(lines, 1):
        m = ROUTE_ID.search(line)
        if m:
            window = "\n".join(lines[max(0, i - 4): i + 12])
            if not AUTH_HINT.search(window):
                key = (2, "route-id")
                rule_counts[key] = rule_counts.get(key, 0) + 1
                if rule_counts[key] <= PER_RULE_CAP:
                    add(2, "warn", "medium", "Object-id route with no visible auth/ownership check nearby",
                        line.strip(), f"{rel}:{i}", "Verify the handler checks the caller owns/may access this record (IDOR).")
    return lines


def check_repo_files(root, all_files):
    names = {os.path.relpath(p, root): p for p, _ in all_files}
    base_names = [os.path.basename(n) for n in names]
    mark = tested.update

    # .env committed / gitignore
    env_files = [n for n in names if os.path.basename(n).startswith(".env") and not n.endswith((".example", ".sample", ".template"))]
    gi = os.path.join(root, ".gitignore")
    gi_txt = open(gi, encoding="utf-8", errors="ignore").read() if os.path.exists(gi) else ""
    mark({8, 26})
    for n in env_files:
        tracked = None
        if shutil.which("git") and os.path.isdir(os.path.join(root, ".git")):
            r = subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch", n], capture_output=True)
            tracked = (r.returncode == 0)
        if tracked is True:
            add(8, "fail", "critical", f"Env file is committed to Git: {n}", "git ls-files lists it", n,
                "git rm --cached it, add to .gitignore, rotate every secret in it, and purge history (git filter-repo).")
        elif ".env" not in gi_txt:
            add(8, "warn", "high", f"Env file present and .gitignore does not exclude .env: {n}", "", n,
                "Add .env* to .gitignore (keep only .env.example).")
        if re.search(r"(?i)\.env\.(prod|production|staging)", n):
            add(26, "warn", "high", f"Environment-specific secrets file in repo: {n}", "", n,
                "Keep per-environment secrets in the platform's secret store; separate Dev/Staging/Prod keys and databases.")
    if not env_files and gi_txt and ".env" not in gi_txt:
        add(8, "warn", "low", ".gitignore does not mention .env", "", ".gitignore", "Add .env* to .gitignore preventively.")
    if not env_files and ".env" in gi_txt:
        add(8, "pass", "info", "No .env file in repo and .gitignore excludes it", "", ".gitignore")

    # dependencies
    mark({16, 25})
    req = [n for n in names if os.path.basename(n) in ("requirements.txt",)]
    for n in req:
        unp = [l.strip() for l in open(names[n], encoding="utf-8", errors="ignore") if l.strip() and not l.startswith(("#", "-")) and "==" not in l and "@" not in l]
        if unp:
            add(25, "warn", "medium", f"{len(unp)} unpinned dependencies in {n}", ", ".join(unp[:6]), n,
                "Pin exact versions (pip-compile / uv lock) and scan with pip-audit.")
        else:
            add(25, "pass", "info", f"All dependencies pinned in {n}", "", n)
    for n in [n for n in names if os.path.basename(n) == "package.json"]:
        try:
            pj = json.load(open(names[n], encoding="utf-8"))
        except Exception:
            continue
        deps = {**pj.get("dependencies", {}), **pj.get("devDependencies", {})}
        bad = [f"{k}@{v}" for k, v in deps.items() if v in ("*", "latest", "") or v.startswith(("git", "http", "github:"))]
        if bad:
            add(25, "warn", "medium", f"Loose/unusual dependency specs in {n}", ", ".join(bad[:6]), n,
                "Pin versions, use the official registry, commit the lockfile.")
        lock_dir = os.path.dirname(n)
        has_lock = any(os.path.exists(os.path.join(root, lock_dir, lf)) for lf in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"))
        if not has_lock:
            add(25, "warn", "medium", f"No lockfile next to {n}", "", n, "Commit package-lock.json / yarn.lock / pnpm-lock.yaml.")
        scripts = pj.get("scripts", {})
        for k in ("preinstall", "postinstall", "install"):
            if k in scripts and re.search(r"(curl|wget|bash -c|eval)", scripts[k]):
                add(30, "warn", "high", f"Lifecycle script '{k}' downloads/executes code in {n}", scripts[k][:150], n,
                    "Remove remote-exec install hooks; verify integrity with hashes.")

    # tests / review signals (17)
    mark({17, 19, 27, 30})
    test_files = [n for n in names if re.search(r"(^|/)(tests?|__tests__|spec)(/|$)|(\.|_)(test|spec)\.[a-z]+$|^test_.*\.py$", n)]
    if not test_files:
        add(17, "warn", "medium", "No automated tests found", "", ".", "Add unit/integration tests, especially for auth, permissions, payments and file handling.")
    else:
        add(17, "pass", "info", f"{len(test_files)} test files found", "", ".")
    if not any(re.search(r"(?i)(semgrep|codeql|sonar|bandit|eslint-plugin-security)", open(p, encoding="utf-8", errors="ignore").read(20000))
               for p in [names[n] for n in names if n.startswith(".github/workflows") or n in ("package.json", "requirements.txt", ".pre-commit-config.yaml")]):
        add(17, "warn", "low", "No SAST tool configured in CI/package manifests", "", ".", "Add Semgrep/CodeQL/Bandit to CI.")

    # logging (19)
    all_text_sample = ""
    for n in list(names)[:400]:
        if n.endswith((".py", ".js", ".ts", ".java", ".go", ".php", ".rb", ".cs")):
            all_text_sample += open(names[n], encoding="utf-8", errors="ignore").read(6000)
    if all_text_sample:
        if not re.search(r"(?i)(import logging|from logging|winston|pino|morgan|log4j|slf4j|serilog|zap\.|logrus|structlog|loguru|Monolog|Rails\.logger)", all_text_sample):
            add(19, "warn", "medium", "No logging framework detected", "", ".", "Log auth events, permission changes, uploads and repeated failures to a central store.")
        elif not re.search(r"(?i)(login.{0,30}(fail|invalid|denied)|unauthori[sz]ed|forbidden|audit)", all_text_sample):
            add(19, "warn", "low", "Logging exists but no auth-failure/audit events detected", "", ".", "Log failed logins, access-denied and privilege changes.")
        else:
            add(19, "pass", "info", "Logging framework and security-event logging signals found", "", ".")

    # backups (27)
    if not any(re.search(r"(?i)backup|restore|disaster|runbook", n) for n in names):
        add(27, "info", "info", "No backup/restore scripts or docs found in repo (verify out-of-band)", "", ".",
            "Document and test encrypted off-site backups and a restore drill.")

    # CI/CD integrity (30)
    for n in [n for n in names if n.startswith(".github/workflows/")]:
        txt = open(names[n], encoding="utf-8", errors="ignore").read()
        for m in re.finditer(r"uses:\s*([\w./-]+)@(main|master|latest)\b", txt):
            add(30, "warn", "medium", f"GitHub Action pinned to a moving ref: {m.group(1)}@{m.group(2)}", "", n, "Pin actions to a full commit SHA.")
        if re.search(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba)?sh", txt):
            add(30, "high" if False else "warn", "high", "Pipeline pipes a remote script into a shell", "", n, "Download, verify checksum/signature, then run.")
        if "pull_request_target" in txt and "actions/checkout" in txt:
            add(30, "warn", "high", "pull_request_target with checkout (privileged PR code execution risk)", "", n, "Avoid checking out PR head in privileged workflows.")
    if not any(n.endswith("CODEOWNERS") for n in names) and os.path.isdir(os.path.join(root, ".git")):
        add(30, "info", "info", "No CODEOWNERS file (consider restricting who may approve/deploy changes)", "", ".", "Add CODEOWNERS and enforce branch protection + required reviews.")

    # Docker
    for n in [n for n in names if os.path.basename(n).startswith("Dockerfile")]:
        txt = open(names[n], encoding="utf-8", errors="ignore").read()
        if not re.search(r"(?im)^\s*USER\s+(?!root)", txt):
            add(15, "warn", "medium", f"Container runs as root: {n}", "", n, "Add a non-root USER.")
        if re.search(r"(?im)^\s*(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|KEY)\w*\s*=?\s*\S+", txt):
            add(8, "fail", "high", f"Secret baked into Docker image via ENV/ARG: {n}", "", n, "Inject secrets at runtime, not at build time.")
        if re.search(r"(?im)^\s*FROM\s+\S+:latest\b|^\s*FROM\s+[^:\s@]+\s*$", txt):
            add(30, "warn", "low", f"Base image not pinned ({n})", "", n, "Pin base images to a version or digest.")


def run_tools(root):
    notes = []
    if shutil.which("pip-audit") and os.path.exists(os.path.join(root, "requirements.txt")):
        try:
            r = subprocess.run(["pip-audit", "-r", os.path.join(root, "requirements.txt"), "-f", "json"], capture_output=True, text=True, timeout=180)
            data = json.loads(r.stdout or "{}")
            vulns = [(d["name"], d["version"], v["id"]) for d in data.get("dependencies", []) for v in d.get("vulns", [])]
            tested.add(16)
            if vulns:
                add(16, "fail", "high", f"pip-audit: {len(vulns)} known vulnerabilities", "; ".join(f"{a}=={b} {c}" for a, b, c in vulns[:8]), "requirements.txt",
                    "Upgrade the affected packages.")
            else:
                add(16, "pass", "info", "pip-audit: no known vulnerabilities", "", "requirements.txt")
        except Exception as e:
            notes.append(f"pip-audit failed: {e}")
    else:
        notes.append("pip-audit not available or no requirements.txt")
    for pj in [p for p, _, f in os.walk(root) if "package-lock.json" in f and "node_modules" not in p][:1]:
        if shutil.which("npm"):
            try:
                r = subprocess.run(["npm", "audit", "--json"], cwd=pj, capture_output=True, text=True, timeout=180)
                data = json.loads(r.stdout or "{}")
                meta = data.get("metadata", {}).get("vulnerabilities", {})
                tested.add(16)
                tot = sum(meta.get(k, 0) for k in ("critical", "high", "moderate", "low"))
                if tot:
                    add(16, "fail" if meta.get("critical", 0) or meta.get("high", 0) else "warn", "high" if meta.get("high", 0) or meta.get("critical", 0) else "medium",
                        f"npm audit: {tot} vulnerable packages", json.dumps(meta), pj, "Run npm audit fix / upgrade the flagged packages.")
                else:
                    add(16, "pass", "info", "npm audit: no known vulnerabilities", "", pj)
            except Exception as e:
                notes.append(f"npm audit failed: {e}")
    if shutil.which("semgrep"):
        try:
            r = subprocess.run(["semgrep", "--config", "auto", "--json", "--quiet", root], capture_output=True, text=True, timeout=600)
            data = json.loads(r.stdout or "{}")
            for res in data.get("results", [])[:30]:
                add(17, "warn", "medium", f"semgrep: {res.get('check_id', '').split('.')[-1]}", res.get("extra", {}).get("message", "")[:200],
                    f"{os.path.relpath(res.get('path', ''), root)}:{res.get('start', {}).get('line', '?')}", "See semgrep rule documentation.")
            tested.add(17)
        except Exception as e:
            notes.append(f"semgrep failed: {e}")
    if not tested & {16}:
        add(16, "not_tested", "info", "Dependency vulnerability audit not executed (no tool or no network). Run pip-audit / npm audit on a connected machine.", "; ".join(notes)[:250], ".")
    return notes


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--path", required=True)
    ap.add_argument("--out", default="findings-code.json")
    ap.add_argument("--no-tools", action="store_true", help="skip pip-audit/npm audit/semgrep")
    a = ap.parse_args()
    root = os.path.abspath(a.path)
    if not os.path.isdir(root):
        sys.exit(f"Not a directory: {root}")
    files = list(walk(root))
    tested.update({3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 15, 18, 20, 24, 29, 2})
    for p, ext in files:
        scan_file(p, ext, root)
    check_repo_files(root, files)
    notes = [] if a.no_tools else run_tools(root)
    if a.no_tools:
        add(16, "not_tested", "info", "Dependency audit skipped (--no-tools)", "", ".")
    # positive signals for rules that found nothing
    hit_ids = {f["catalog_id"] for f in findings if f["status"] in ("fail", "warn")}
    for cid in sorted(tested - hit_ids):
        if not any(f["catalog_id"] == cid for f in findings):
            add(cid, "pass", "info", "No matching risky patterns found by static rules", "", ".")
    out = {"tool": "scan_code", "target": root, "files_scanned": len(files), "tested_catalog_ids": sorted(tested),
           "tool_notes": notes, "findings": findings}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    n = {s: sum(1 for x in findings if x["status"] == s) for s in ("fail", "warn", "pass", "info", "not_tested")}
    print(f"scan_code done: {len(files)} files -> {a.out}  {n}")


if __name__ == "__main__":
    main()
