"""AppSec scanners (SCA via OSV, secrets, SAST, local DAST probe) and the findings registry they feed.

Every scanner works on a repo path and returns plain data; Workspace (tools.py) turns that into
SecurityFindings and the text the agents read."""
import asyncio
import json
import math
import os
import re
import shutil
import subprocess
import tomllib
from collections import Counter
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlsplit

import httpx

SKIP_DIRS = {".git", ".coven", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next", "target", ".idea"}
# Test/fixture code never ships: findings there are still reported, but LOW.
TEST_CODE = re.compile(r"(^|/)(tests?|spec|__tests__|e2e|cypress|fixtures?|mocks?)/|\.(spec|test)\.\w+$|(^|/)test_\w+\.py$|_test\.(py|go)$", re.I)
OSV_URL = "https://api.osv.dev/v1/query"
MAX_PACKAGES = 400  # ponytail: one OSV query per package; switch to /v1/querybatch past a few hundred deps
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
STATUSES = ("DETECTED", "CONFIRMED_BY_QA", "PATCHED", "VERIFIED", "FALSE_POSITIVE")


class SecurityFinding(TypedDict, total=False):
    id: str                  # COVEN-001
    title: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW
    standard: str            # "OWASP A03:2021 / CWE-89", "CVE-2024-1234"...
    file_path: str
    line_number: int
    empirical_evidence: str
    status: str              # DETECTED | CONFIRMED_BY_QA | PATCHED | VERIFIED | FALSE_POSITIVE
    fix: str
    endpoint: str            # "POST /api/users" when the finding maps to a route
    source: str              # osv | secrets | sast | semgrep | dast | reviewer
    history: list[str]


def _walk(root: Path, exts: set[str] | None = None):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            p = Path(dirpath, f)
            if (exts is None or p.suffix.lower() in exts) and p.stat().st_size < 1_000_000:
                yield p


def _lines(p: Path) -> list[str]:
    try:
        return p.read_text(encoding="utf-8").splitlines()
    except (UnicodeDecodeError, OSError):
        return []  # binary or unreadable


# ---------------------------------------------------------------- SCA (OSV.dev)

def _vkey(v: str) -> tuple:
    # ponytail: numeric tuple compare (1.10.0 > 1.9.2); pre-release tags are ignored.
    return tuple(int(n) for n in re.findall(r"\d+", v.split("-")[0].split("+")[0]))


def _norm(name: str, eco: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "PyPI" else name


def _line_of(lines: list[str], name: str) -> int:
    rx = re.compile(rf"""(^|["'\s]){re.escape(name)}(["'\s=<>~!\[]|$)""", re.I)
    return next((i for i, l in enumerate(lines, 1) if rx.search(l)), 0)


def collect_dependencies(root: Path) -> list[dict]:
    """Pinned (name, version) pairs from package.json (+ lockfile), requirements.txt and pyproject.toml."""
    deps = []
    if (pkg := root / "package.json").exists():
        data = json.loads(pkg.read_text(encoding="utf-8"))
        lock = {}
        if (lf := root / "package-lock.json").exists():
            lock = json.loads(lf.read_text(encoding="utf-8")).get("packages", {})
        lines = pkg.read_text(encoding="utf-8").splitlines()
        for name, spec in {**data.get("dependencies", {}), **data.get("devDependencies", {})}.items():
            version = lock.get(f"node_modules/{name}", {}).get("version")
            if not version and (m := re.match(r"^[\^~=v]*(\d+\.\d+\.\d+[\w.\-+]*)$", str(spec).strip())):
                version = m.group(1)
            if version:  # ranges like ">=1" or git urls have no exact version to query
                deps.append({"name": name, "version": version, "ecosystem": "npm",
                             "manifest": "package.json", "line": _line_of(lines, name)})
    if (req := root / "requirements.txt").exists():
        lines = req.read_text(encoding="utf-8").splitlines()
        for i, l in enumerate(lines, 1):
            if m := re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([\w.\-+]+)", l):
                deps.append({"name": m.group(1), "version": m.group(2), "ecosystem": "PyPI",
                             "manifest": "requirements.txt", "line": i})
    if (pp := root / "pyproject.toml").exists():
        text = pp.read_text(encoding="utf-8")
        data, lines = tomllib.loads(text), text.splitlines()
        specs = list(data.get("project", {}).get("dependencies", []))
        for name, v in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
            if isinstance(v, str) and re.match(r"^=?=?\d", v):
                specs.append(f"{name}=={v.lstrip('=')}")
        for s in specs:
            if m := re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([\w.\-+]+)", s):
                deps.append({"name": m.group(1), "version": m.group(2), "ecosystem": "PyPI",
                             "manifest": "pyproject.toml", "line": _line_of(lines, m.group(1))})
    return deps[:MAX_PACKAGES]


def _severity(vuln: dict) -> str:
    db = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    if db in SEVERITIES:
        return db
    if db == "MODERATE":
        return "MEDIUM"
    # ponytail: rough CVSS-vector bucketing instead of the full base-score formula.
    vec = next((s["score"] for s in vuln.get("severity", []) if s.get("type", "").startswith("CVSS")), "")
    if not vec:
        return "MEDIUM"
    highs = sum(f"{m}:H" in vec for m in ("C", "I", "A"))
    if "AV:N" in vec and "PR:N" in vec and highs >= 2:
        return "CRITICAL"
    return "HIGH" if highs else "MEDIUM"


def _fixed_version(vuln: dict, dep: dict) -> str | None:
    current, fixes = _vkey(dep["version"]), []
    for aff in vuln.get("affected", []):
        if _norm(aff.get("package", {}).get("name", ""), dep["ecosystem"]) != _norm(dep["name"], dep["ecosystem"]):
            continue
        for rng in aff.get("ranges", []):
            fixes += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    newer = [f for f in fixes if _vkey(f) > current]
    return min(newer, key=_vkey) if newer else None


async def scan_dependencies_osv(repo_path: str | Path) -> dict:
    """Query OSV.dev for every pinned dependency. Returns real advisories with severity and the safe version."""
    deps = collect_dependencies(Path(repo_path))
    sem, errors = asyncio.Semaphore(10), []

    async def query(client: httpx.AsyncClient, dep: dict) -> list[dict]:
        async with sem:
            try:
                r = await client.post(OSV_URL, json={"package": {"name": dep["name"], "ecosystem": dep["ecosystem"]},
                                                     "version": dep["version"]})
                r.raise_for_status()
            except httpx.HTTPError as e:
                errors.append(f"{dep['name']}: {type(e).__name__}")
                return []
        out = []
        for v in r.json().get("vulns", []):
            ids = [v["id"], *v.get("aliases", [])]
            out.append({**dep, "id": v["id"], "cve": next((i for i in ids if i.startswith("CVE-")), v["id"]),
                        "severity": _severity(v), "summary": (v.get("summary") or v.get("details", ""))[:300],
                        "fixed": _fixed_version(v, dep)})
        return out

    async with httpx.AsyncClient(timeout=20) as client:
        results = await asyncio.gather(*(query(client, d) for d in deps))
    return {"scanned": len(deps), "vulnerabilities": dedupe_advisories([v for r in results for v in r]), "errors": errors}


def dedupe_advisories(vulns: list[dict]) -> list[dict]:
    """OSV lists one CVE under several databases (PYSEC + GHSA): keep one per package+CVE, worst severity,
    and the highest fixed version so upgrading clears every advisory."""
    best: dict[tuple, dict] = {}
    for v in vulns:
        key = (v["ecosystem"], v["name"].lower(), v["cve"])
        if (old := best.get(key)) is None:
            best[key] = v
            continue
        fixed = max((f for f in (old["fixed"], v["fixed"]) if f), key=_vkey, default=None)
        worst = min((old, v), key=lambda x: SEVERITIES.index(x["severity"]))
        best[key] = {**worst, "fixed": fixed, "summary": max(old["summary"], v["summary"], key=len)}
    return list(best.values())


# ---------------------------------------------------------------- secrets

SECRET_RULES = [  # (type, severity, regex; group 1 = the secret value)
    ("AWS Access Key ID", "CRITICAL", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("AWS Secret Access Key", "CRITICAL", re.compile(r"aws_?secret_?access_?key\w*\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", re.I)),
    ("Stripe live key", "CRITICAL", re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})")),
    ("Stripe test key", "LOW", re.compile(r"\b((?:sk|rk)_test_[0-9a-zA-Z]{20,})")),
    ("Telegram bot token", "CRITICAL", re.compile(r"\b(\d{8,10}:AA[A-Za-z0-9_-]{30,})")),
    ("OpenRouter API key", "CRITICAL", re.compile(r"\b(sk-or-v1-[A-Za-z0-9]{32,})")),
    ("Anthropic API key", "CRITICAL", re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})")),
    ("OpenAI API key", "CRITICAL", re.compile(r"\b(sk-(?!or-|ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,})")),
    ("Google API key", "CRITICAL", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})")),
    ("GitHub token", "CRITICAL", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("Slack token", "CRITICAL", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})")),
    ("Private key", "CRITICAL", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)")),
    ("JWT secret", "HIGH", re.compile(r"jwt_?(?:secret|key|signing_?key)\w*\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]", re.I)),
    ("JSON Web Token", "MEDIUM", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")),
    ("DB URL with credentials", "CRITICAL",
     re.compile(r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:@\s/'\"]+:[^@\s'\"]+@[^\s'\"/]+)")),
]
GENERIC = re.compile(r"(?:secret|token|api_?key|password|passwd|pwd|private_?key|client_?secret)\w*['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]", re.I)
# .env style: KEY=value, unquoted
ENV_ASSIGN = re.compile(r"^\s*(?:export\s+)?\w*(?:SECRET|TOKEN|API_?KEY|PASSWORD|PASSWD|PRIVATE_?KEY)\w*\s*=\s*([^\s'\"]{8,})(?:\s+#.*)?\s*$", re.I)
HIGH_ENTROPY = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{32,})['\"]")
PLACEHOLDER = re.compile(r"your|example|changeme|change_me|placeholder|xxxx|<|\$\{|process\.env|environ|getenv|dummy|sample|redacted|"
                         r"\*\*\*|\.\.\.|…|tu_|_tu_|aqu[ií]|ejemplo|cambiar", re.I)  # English + Spanish placeholders
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "uv.lock", "Cargo.lock"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf",
              ".exe", ".dll", ".so", ".pyc", ".map", ".svg", ".lock", ".mp4", ".mp3"}


def shannon_entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


PEM_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)


def redact(text: str) -> str:
    """File text → text safe for the LLM: private keys become a line marker, rule-matched secrets are masked.
    Line count is preserved so line numbers stay valid."""
    def key(m: re.Match) -> str:
        line = text.count("\n", 0, m.start()) + 1
        return f"[REDACTED_PRIVATE_KEY_DETECTED at line {line}]" + "\n" * m.group().count("\n")
    text = PEM_KEY.sub(key, text)
    for _, _, rx in SECRET_RULES:
        text = rx.sub(lambda m: m.group().replace(m.group(1), mask(m.group(1))) if m.group(1) else m.group(), text)
    return text


def mask(value: str) -> str:
    """Never hand the raw secret to the LLM or the UI: keep 4 chars of prefix and the length."""
    if m := re.match(r"^(\w[\w+]*://[^:]+:)([^@]+)(@.*)$", value):  # DB URL: hide only the password
        return f"{m.group(1)}****{m.group(3)}"
    return f"{value[:4]}{'*' * 8} ({len(value)} chars)" if len(value) > 8 else "*" * 8


def scan_secrets_and_entropy(repo_path: str | Path) -> list[dict]:
    """Regex for known credential formats + Shannon entropy for generic ones. Values come back masked."""
    root, hits = Path(repo_path).resolve(), []
    for p in _walk(root):
        if p.name in SKIP_FILES or p.suffix.lower() in BINARY_EXT or p.name.endswith(".min.js"):
            continue
        rel = p.relative_to(root).as_posix()
        for i, line in enumerate(_lines(p), 1):
            if len(line) > 2000 or "integrity" in line:
                continue
            found = False
            for kind, sev, rx in SECRET_RULES:
                for m in rx.finditer(line):
                    value = m.group(1)
                    if kind == "DB URL with credentials" and re.search(r"@(localhost|127\.0\.0\.1|db|postgres|mysql)\b", value):
                        sev = "MEDIUM"  # dev compose default; still worth rotating
                    hits.append({"file": rel, "line": i, "type": kind, "severity": sev, "masked": mask(value)})
                    found = True
            if found:
                continue
            # ponytail: generic credentials need a digit — cuts word-only placeholders, misses all-letter passwords
            if ((m := GENERIC.search(line) or ENV_ASSIGN.match(line)) and not PLACEHOLDER.search(m.group(1))
                    and re.search(r"\d", m.group(1)) and shannon_entropy(m.group(1)) >= 3.0):
                hits.append({"file": rel, "line": i, "type": "Hardcoded credential", "severity": "HIGH",
                             "masked": mask(m.group(1)), "entropy": round(shannon_entropy(m.group(1)), 2)})
            elif (m := HIGH_ENTROPY.search(line)) and not PLACEHOLDER.search(m.group(1)) and shannon_entropy(m.group(1)) >= 4.5:
                hits.append({"file": rel, "line": i, "type": "High-entropy string", "severity": "MEDIUM",
                             "masked": mask(m.group(1)), "entropy": round(shannon_entropy(m.group(1)), 2)})
    # A secret in a git-ignored file (a local .env) never reaches the repo: still reported, but LOW.
    for f in _git_ignored(root, {h["file"] for h in hits}):
        for h in hits:
            if h["file"] == f:
                h.update(severity="LOW", ignored=True)
    for h in hits:
        if TEST_CODE.search(h["file"]):
            h.update(severity="LOW", test_code=True)
    return hits


def _git_ignored(root: Path, files: set[str]) -> set[str]:
    if not files or not (root / ".git").exists() or not (git := shutil.which("git")):
        return set()
    try:
        # paths as args: `--stdin` drops matches on Git for Windows depending on input order
        r = subprocess.run([git, "check-ignore", "--", *sorted(files)[:500]], cwd=root, capture_output=True,
                           text=True, encoding="utf-8", timeout=20)
    except subprocess.TimeoutExpired:
        return set()
    return {l.strip() for l in r.stdout.splitlines() if l.strip()}


# ---------------------------------------------------------------- SAST + route map

PY, JS = {".py"}, {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SQL = r"(?:SELECT\b.*\bFROM|INSERT\s+INTO|UPDATE\b.*\bSET|DELETE\s+FROM)\b"
STATIC_RULES = [  # (rule, title, severity, standard, extensions, regex)
    ("eval-js", "eval()/new Function() con código dinámico", "HIGH", "OWASP A03:2021 / CWE-95", JS,
     re.compile(r"(?:(?<![\w.$])eval|\bnew\s+Function)\s*\((?!(?:\s*\"\"\s*,?)*\s*\))")),  # all-literal args = constant code
    ("eval-py", "eval()/exec() con código dinámico", "HIGH", "OWASP A03:2021 / CWE-95", PY,
     re.compile(r"(?<![\w.])(?:eval|exec)\s*\(")),
    ("react-dangerously-set-inner-html", "dangerouslySetInnerHTML (posible XSS)", "MEDIUM", "OWASP A03:2021 / CWE-79", JS,
     re.compile(r"dangerouslySetInnerHTML")),
    ("sql-fstring", "SQL construido con f-string", "CRITICAL", "OWASP A03:2021 / CWE-89", PY,
     re.compile(rf"""\bf(["']{{1,3}})[^\n]*?{SQL}[^\n]*?\{{[^}}]+\}}""", re.I)),
    ("sql-format", "SQL construido con % / .format()", "CRITICAL", "OWASP A03:2021 / CWE-89", PY,
     re.compile(rf"""["'][^"'\n]*{SQL}[^"'\n]*["']\s*(?:%\s*[\w(]|\.format\()""", re.I)),
    ("sql-template-literal", "SQL construido con template literal", "CRITICAL", "OWASP A03:2021 / CWE-89", JS,
     re.compile(rf"(?<![\w$])`[^`]*{SQL}[^`]*\$\{{", re.I)),
    ("sql-concat", "SQL construido concatenando strings", "CRITICAL", "OWASP A03:2021 / CWE-89", JS | PY,
     re.compile(rf"""["'][^"'\n]*{SQL}[^"'\n]*["']\s*\+\s*\w""", re.I)),
]
CODE_ONLY = {"eval-js", "eval-py", "react-dangerously-set-inner-html"}  # never match inside string literals
STRING_LITERAL = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""")


def _blank(m: re.Match) -> str:  # a template literal with ${...} is dynamic: keep a non-literal stand-in
    return "x" if m.group(1) == "`" and "${" in m.group(0) else '""'

CORS_RULES = [  # (extensions, wildcard-origin regex, credentials regex)
    (JS, re.compile(r"origin\s*:\s*(?:true|['\"]\*['\"])"), re.compile(r"credentials\s*:\s*true")),
    (PY, re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]"), re.compile(r"allow_credentials\s*=\s*True")),
]
AUTH_HINT = re.compile(r"(?:auth|login_required|requireUser|protect|verify_?token|jwt|passport|guard|current_?user|session|"
                       r"permission|Security\(|clerk|getToken|isAdmin|denyAll)", re.I)  # grouped: it is spliced into other regexes
EXPRESS_USE = re.compile(r"""\.use\(\s*(?:(['"`])([^'"`]*)\1\s*,)?(.*)""")
# app.use() covers a whole scope, so it needs a real gate name, not a fragment (frameguard, updateAuthenticatedUsers)
AUTH_GATE = re.compile(r"\b(?:isAuth\w*|isLoggedIn|ensureLoggedIn|(?:require|ensure|check)(?:Auth|Login|User|Session|Jwt|Admin)\w*|"
                       r"authenticate|auth(?:Middleware|Guard|orize)?|passport\.authenticate|verify(?:Token|Jwt)|expressjwt|"
                       r"jwt|denyAll|isAdmin|protect|clerkMiddleware)\s*\(", re.I)
PUBLIC_ROUTE = re.compile(r"login|logout|register|signup|sign-up|signin|auth|health|status|webhook|callback|public|csrf", re.I)
EXPRESS_ROUTE = re.compile(r"""\b(?:app|router|server|api)\.(get|post|put|patch|delete|all)\(\s*(['"`])([^'"`]+)\2\s*,(.*)""")
PY_ROUTE = re.compile(r"""^\s*@\w+\.(get|post|put|patch|delete|route|api_route)\(\s*['"]([^'"]*)['"](.*)""")
NEXT_HANDLER = re.compile(r"export\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE)\b")


EXPRESS_CHAIN = re.compile(r"""\.route\(\s*(['"`])([^'"`]+)\1\s*\)""")
CHAIN_CALL = re.compile(r"\.(get|post|put|patch|delete|all)\((.*?)\)\s*(?=\.\w+\(|$)")
REST_RESOURCE = re.compile(r"\b(?:finale|epilogue)\.resource\(\s*\{[^}]*?endpoints\s*:\s*\[([^\]]*)\]", re.S)


def _rest_resources(text: str) -> list[tuple[str, str, int]]:
    """CRUD routes generated by finale-rest / epilogue: endpoints ['/api/Users', '/api/Users/:id'].
    Template endpoints (`/api/${name}s`) are expanded with the `name: 'User'` literals found in the same file."""
    # ponytail: values for ${var} come from any `var: '...'` in the file, not from real data flow
    out = []
    for m in REST_RESOURCE.finditer(text):
        line = text[:m.start()].count("\n") + 1
        for ep in re.findall(r"""['"`]([^'"`]+)['"`]""", m.group(1)):
            paths = [ep]
            for var in set(re.findall(r"\$\{(\w+)\}", ep)):
                vals = re.findall(rf"""\b{var}\s*:\s*['"]([^'"]+)['"]""", text)
                paths = [p.replace(f"${{{var}}}", v) for p in paths for v in vals]
            for p in paths:
                item = re.search(r"/:\w+$", p)
                out += [(meth, p, line) for meth in (("GET", "PUT", "DELETE") if item else ("GET", "POST"))]
    return out


def map_api_routes(repo_path: str | Path) -> list[dict]:
    """Express / FastAPI / Flask / Next.js routes with a best-effort 'auth' flag (middleware or auth calls)."""
    root, routes = Path(repo_path).resolve(), []
    for p in _walk(root, PY | JS):
        rel, lines = p.relative_to(root).as_posix(), _lines(p)
        text = "\n".join(lines)
        if p.suffix == ".py":
            # router-level dependencies (APIRouter(dependencies=[Depends(auth)])) cover every route in the file
            file_auth = bool(re.search(r"(APIRouter|FastAPI)\([^)]*dependencies\s*=\s*\[[^\]]*" + AUTH_HINT.pattern, text, re.I))
            for i, line in enumerate(lines, 1):
                if not (m := PY_ROUTE.match(line)):
                    continue
                method = m.group(1).upper()
                if method in ("ROUTE", "API_ROUTE"):
                    ms = re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", m.group(3), re.I)
                    method = ",".join(x.upper() for x in ms) or "GET"
                # decorators above + signature below until the body starts
                j = i
                while j < len(lines) and not re.match(r"\s*(async\s+)?def\b.*:\s*(#.*)?$", lines[j - 1]):
                    j += 1
                window = "\n".join(lines[max(i - 4, 0):min(j + 1, len(lines))])
                routes.append({"method": method, "path": m.group(2) or "/", "file": rel, "line": i,
                               "auth": file_auth or bool(AUTH_HINT.search(window))})
        else:
            parts = p.relative_to(root).parts
            if p.stem == "route" and "app" in parts:  # Next.js app router
                seg = [s for s in parts[parts.index("app") + 1:-1] if not s.startswith("(")]
                path, file_auth = "/" + "/".join(seg), bool(AUTH_HINT.search(text))
                routes += [{"method": m.group(1), "path": path, "file": rel, "line": text[:m.start()].count("\n") + 1,
                            "auth": file_auth} for m in NEXT_HANDLER.finditer(text)]
                continue
            if "pages" in parts and "api" in parts and parts.index("api") == parts.index("pages") + 1:
                path = "/api/" + "/".join([*parts[parts.index("api") + 1:-1], p.stem]).removesuffix("/index").removesuffix("index")
                routes.append({"method": "ANY", "path": path.rstrip("/") or "/api", "file": rel, "line": 1,
                               "auth": bool(AUTH_HINT.search(text))})
                continue
            # auth scopes: app.use(auth) covers everything, app.use('/prefix', auth) only that prefix,
            # app.get('/x', auth) also covers later handlers registered for the same method+path
            # ponytail: ignores registration order and multi-line .use() calls
            prefixes, guarded, found, chain = [], set(), [], None
            for i, line in enumerate(lines, 1):
                if line.lstrip().startswith(("//", "*", "/*")):
                    continue
                # app.route('/x').get(auth).put(...) — the chain may continue on the following lines
                if c := EXPRESS_CHAIN.search(line):
                    chain, rest = c.group(2), line[c.end():]
                elif chain and line.lstrip().startswith("."):
                    rest = line
                else:
                    chain = None
                if chain:
                    for cm in CHAIN_CALL.finditer(rest):
                        found.append((cm.group(1).upper(), chain, i))
                        if AUTH_HINT.search(cm.group(2)):
                            guarded.add((cm.group(1).upper(), chain))
                    continue
                if m := EXPRESS_ROUTE.search(line):
                    found.append((m.group(1).upper(), m.group(3), i))
                    if AUTH_HINT.search(m.group(4)):
                        guarded.add((m.group(1).upper(), m.group(3)))
                elif (u := EXPRESS_USE.search(line)) and AUTH_GATE.search(u.group(3)):
                    prefixes.append((u.group(2) or "").rstrip("/"))
            seen = {(m, p) for m, p, _ in found}
            for method, path, i in _rest_resources(text):
                if (method, path) not in seen:
                    seen.add((method, path))
                    found.append((method, path, i))
            for method, path, i in found:
                auth = (method, path) in guarded or any(path == pre or path.startswith(pre + "/") for pre in prefixes)
                routes.append({"method": method, "path": path, "file": rel, "line": i, "auth": auth})
    return routes


def _semgrep(root: Path) -> list[dict] | None:
    if not (exe := shutil.which("semgrep")):
        return None
    try:
        r = subprocess.run([exe, "scan", "--config", "p/default", "--json", "--quiet", "--metrics=off"],
                           cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        results = json.loads(r.stdout)["results"]
    except (subprocess.TimeoutExpired, ValueError, KeyError):
        return None  # fall back to the native rules
    out = []
    for res in results:
        meta = res.get("extra", {}).get("metadata", {})
        owasp = (meta.get("owasp") or [""])
        cwe = re.findall(r"CWE-\d+", " ".join(meta.get("cwe") or []))
        standard = " / ".join(x for x in [(owasp[0] if isinstance(owasp, list) else owasp).split(" - ")[0], cwe[0] if cwe else ""] if x)
        out.append({"rule": res["check_id"].split(".")[-1], "title": res["extra"].get("message", "")[:160],
                    "severity": {"ERROR": "HIGH", "WARNING": "MEDIUM"}.get(res["extra"].get("severity"), "LOW"),
                    "standard": standard or "CWE", "file": res["path"], "line": res["start"]["line"],
                    "snippet": res["extra"].get("lines", "").strip()[:160]})
    return out


def run_static_ast_rules(repo_path: str | Path) -> dict:
    """semgrep (JSON) when installed, else native rules. Route-level missing-auth checks run either way."""
    root = Path(repo_path).resolve()
    findings, engine = _semgrep(root), "semgrep"
    if findings is None:
        engine, findings = "native", []
        for p in _walk(root, PY | JS):
            rel, lines, ext = p.relative_to(root).as_posix(), _lines(p), p.suffix.lower()
            for i, line in enumerate(lines, 1):
                if line.lstrip().startswith(("#", "//", "*")):
                    continue
                code = re.sub(r"\s(#|//).*$", "", STRING_LITERAL.sub(_blank, line))  # no strings, no trailing comments
                for rule, title, sev, std, exts, rx in STATIC_RULES:
                    if ext in exts and rx.search(code if rule in CODE_ONLY else line):
                        findings.append({"rule": rule, "title": title, "standard": std,
                                         "severity": "LOW" if TEST_CODE.search(rel) else sev,
                                         "file": rel, "line": i, "snippet": line.strip()[:160]})
            text = "\n".join(lines)
            for exts, origin, creds in CORS_RULES:
                if ext in exts and (m := origin.search(text)) and creds.search(text):
                    i = text[:m.start()].count("\n") + 1
                    findings.append({"rule": "cors-wildcard-credentials", "title": "CORS con origen comodín y credenciales",
                                     "severity": "HIGH", "standard": "OWASP A05:2021 / CWE-942", "file": rel, "line": i,
                                     "snippet": lines[i - 1].strip()[:160]})
    routes = map_api_routes(root)
    for r in routes:
        mutating = r["method"] in ("ANY", "ALL") or any(x in r["method"] for x in ("POST", "PUT", "PATCH", "DELETE"))
        admin = re.search(r"admin", r["path"], re.I)
        if r["auth"] or PUBLIC_ROUTE.search(r["path"]) or not (mutating or admin):
            continue
        findings.append({"rule": "endpoint-without-auth", "title": f"Endpoint sin middleware de autenticación: {r['method']} {r['path']}",
                         "severity": "HIGH" if admin else "MEDIUM", "standard": "OWASP A01:2021 / CWE-306",
                         "file": r["file"], "line": r["line"], "snippet": "", "endpoint": f"{r['method']} {r['path']}"})
    return {"engine": engine, "findings": findings, "routes": routes}


# ---------------------------------------------------------------- DAST probe (localhost only)

LOCAL_HOSTS = {"localhost", "127.0.0.1"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}  # PUT/PATCH/DELETE could mutate data on a passing auth gate
PROBE_ORIGIN = "https://coven-probe.invalid"


def _local_url(base_url: str, endpoint: str) -> str:
    """Join and validate: http(s), host exactly localhost/127.0.0.1, no credentials, endpoint is a plain path."""
    base = urlsplit(base_url.strip())
    if base.scheme not in ("http", "https") or base.hostname not in LOCAL_HOSTS or "@" in base.netloc:
        raise ValueError("solo se permiten URLs http(s)://localhost o http(s)://127.0.0.1")
    _ = base.port  # raises on a malformed port
    if not endpoint.startswith("/") or endpoint.startswith("//") or "\\" in endpoint or re.search(r"[\s\x00-\x1f]", endpoint):
        raise ValueError("el endpoint debe ser una ruta que empiece por '/'")
    url = f"{base.scheme}://{base.netloc}{endpoint}"
    final = urlsplit(url)
    if final.hostname not in LOCAL_HOSTS or final.netloc != base.netloc:
        raise ValueError("la URL final no es local")
    return url


async def verify_endpoint_security(base_url: str, endpoint: str, method: str = "GET") -> dict:
    """Security headers + auth gate (no credentials, then an invalid bearer token) against a local dev server."""
    method = (method or "GET").upper()
    if method not in SAFE_METHODS:
        raise ValueError(f"método {method} no permitido; usa {', '.join(sorted(SAFE_METHODS))}")
    url = _local_url(base_url, endpoint)
    traces = []
    # trust_env=False: a system proxy must not see (or redirect) these requests; no redirects are followed.
    async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
        for label, headers in (("sin credenciales", {}), ("token inválido", {"Authorization": "Bearer coven.invalid.token"})):
            r = await client.request(method, url, headers={"Origin": PROBE_ORIGIN, **headers})
            traces.append({"request": f"{method} {url} ({label})", "status": r.status_code,
                           "headers": {k: v for k, v in r.headers.items() if k.lower() in (
                               "content-security-policy", "x-content-type-options", "strict-transport-security",
                               "x-frame-options", "access-control-allow-origin", "access-control-allow-credentials",
                               "location", "www-authenticate", "set-cookie")},
                           "body": r.text[:300]})
    h = {k.lower(): v for k, v in traces[0]["headers"].items()}
    acao = h.get("access-control-allow-origin")
    checks = {
        "Content-Security-Policy": "content-security-policy" in h,
        "X-Content-Type-Options": h.get("x-content-type-options", "").lower() == "nosniff",
        "Strict-Transport-Security": "strict-transport-security" in h,
        "X-Frame-Options": "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", ""),
        "Access-Control-Allow-Origin": acao not in ("*", PROBE_ORIGIN),
    }
    codes = [t["status"] for t in traces]
    if all(c in (401, 403) for c in codes):
        gate = "PASS"
    elif any(200 <= c < 300 for c in codes):
        gate = "FAIL"
    elif any(c >= 500 for c in codes):
        gate = "ERROR"
    else:
        gate = "INCONCLUSIVE"  # 3xx / 404 / 405: nothing to conclude about auth
    return {"url": url, "method": method, "auth_gate": gate, "headers": checks,
            "missing_headers": [k for k, ok in checks.items() if not ok],
            "acao": acao, "https": url.startswith("https"), "traces": traces}


# ---------------------------------------------------------------- findings registry

# who may move a finding to which status
STATUS_PERMISSIONS = {"QARunner": {"CONFIRMED_BY_QA", "FALSE_POSITIVE", "VERIFIED"}, "Fixer": {"PATCHED"}}


MISSING_AUTH = re.compile(r"CWE-(?:306|862|287)\b")


def route_matches(pattern: str, method: str, path: str) -> bool:
    """'POST /users/:id' matches ('POST', '/users/42'); also {id} and [id] params."""
    pm, _, pp = pattern.partition(" ")
    if pm not in ("ANY", "ALL") and method not in pm.split(","):
        return False
    rx = re.sub(r":\w+|\{[^}]+\}|\[[^\]]+\]", "[^/]+", re.escape(pp).replace(r"\:", ":").replace(r"\{", "{")
                .replace(r"\}", "}").replace(r"\[", "[").replace(r"\]", "]"))
    return re.fullmatch(rx.rstrip("/") or "/", path.split("?")[0].rstrip("/") or "/") is not None


class FindingRegistry:
    """Deduplicated SecurityFindings keyed by what was found (scanner+location), numbered COVEN-NNN."""

    def __init__(self):
        self.items: dict[str, SecurityFinding] = {}

    def add(self, key: str, status: str = "DETECTED", **fields) -> SecurityFinding:
        if key in self.items:
            return self.items[key]
        f: SecurityFinding = {"id": f"COVEN-{len(self.items) + 1:03d}", "status": status, "line_number": 0,
                              "file_path": "", "empirical_evidence": "", "history": [f"{fields.get('source', '?')}: {status}"], **fields}
        self.items[key] = f
        return f

    def get(self, fid: str) -> SecurityFinding:
        f = next((f for f in self.items.values() if f["id"] == fid.strip().upper()), None)
        if not f:
            raise ValueError(f"no existe el hallazgo {fid}")
        return f

    def set_status(self, fid: str, status: str, evidence: str, agent: str) -> SecurityFinding:
        f, status = self.get(fid), status.strip().upper()
        if status not in STATUSES:
            raise ValueError(f"estado inválido; usa {', '.join(STATUSES)}")
        if status not in STATUS_PERMISSIONS.get(agent, set()):
            raise ValueError(f"{agent} no puede marcar hallazgos como {status}")
        if not evidence.strip():
            raise ValueError("aporta la evidencia empírica del cambio de estado")
        if status == "VERIFIED" and f["status"] != "PATCHED":
            raise ValueError("solo un hallazgo PATCHED puede pasar a VERIFIED")
        self._move(f, status, f"{agent}: {evidence.strip()[:600]}")
        return f

    def _move(self, f: SecurityFinding, status: str, note: str):
        f["status"] = status
        f["empirical_evidence"] = (f["empirical_evidence"] + f"\n[{status}] {note}").strip()[-4000:]
        f["history"].append(f"{status} ← {note[:160]}")

    def apply_probe(self, method: str, endpoint: str, result: dict) -> list[SecurityFinding]:
        """Deterministic status changes from a verify_endpoint_security result."""
        trace = "; ".join(f"{t['request']} -> {t['status']}" for t in result["traces"])
        touched = []
        if result["auth_gate"] in ("PASS", "FAIL"):
            for f in self.items.values():
                # an anonymous probe only proves/disproves missing auth — not IDOR, input validation, etc.
                if (not f.get("endpoint") or not route_matches(f["endpoint"], method, endpoint)
                        or not MISSING_AUTH.search(f.get("standard") or "")):
                    continue
                if result["auth_gate"] == "FAIL" and f["status"] in ("DETECTED", "PATCHED", "VERIFIED"):
                    self._move(f, "CONFIRMED_BY_QA", f"QARunner: auth gate abierto — {trace}")
                elif result["auth_gate"] == "PASS" and f["status"] in ("DETECTED", "PATCHED"):
                    self._move(f, "VERIFIED" if f["status"] == "PATCHED" else "FALSE_POSITIVE", f"QARunner: 401/403 — {trace}")
                touched.append(f)
            if result["auth_gate"] == "FAIL" and not touched:
                touched.append(self.add(f"dast:auth:{method} {endpoint}", status="CONFIRMED_BY_QA", source="dast",
                                        title=f"Endpoint accesible sin autenticación: {method} {endpoint}", severity="HIGH",
                                        standard="OWASP A01:2021 / CWE-306", endpoint=f"{method} {endpoint}",
                                        empirical_evidence=trace))
        origin = urlsplit(result["url"])._replace(path="", query="").geturl()
        key = f"dast:headers:{origin}"
        missing = [h for h in result["missing_headers"] if h != "Strict-Transport-Security" or result["https"]]
        if missing:
            touched.append(self.add(key, status="CONFIRMED_BY_QA", source="dast", severity="MEDIUM",
                                    title=f"Cabeceras de seguridad ausentes en {origin}", standard="OWASP A05:2021 / CWE-693",
                                    empirical_evidence=f"Faltan: {', '.join(missing)} — {trace}"))
        elif key in self.items and self.items[key]["status"] == "PATCHED":
            self._move(self.items[key], "VERIFIED", f"QARunner: cabeceras presentes — {trace}")
            touched.append(self.items[key])
        return touched
