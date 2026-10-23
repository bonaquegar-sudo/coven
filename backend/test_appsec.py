"""AppSec checks: secrets masking, SAST rules, route map, localhost-only DAST, finding lifecycle, live OSV.
Run: python test_appsec.py   (the OSV part is skipped when offline)"""
import asyncio
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app import appsec_tools as appsec
from app.tools import Workspace

AWS, STRIPE, DB_PASS = "AKIA" + "Z7Q4K2M9X3B5N8C1", "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc", "S3cr3tP4ss!x"
FILES = {
    "config.py": f'AWS_KEY = "{AWS}"\nSTRIPE = "{STRIPE}"\nDB = "postgres://admin:{DB_PASS}@prod.db.internal:5432/app"\n'
                 'api_token = "your-token-here"\n',
    "api.py": 'from fastapi import FastAPI, Depends\napp = FastAPI()\n'
              'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n'
              '@app.post("/items")\ndef create(item: dict):\n    db.execute(f"SELECT * FROM items WHERE id = {item[\'id\']}")\n'
              '    return eval(item["expr"])\n'
              '@app.delete("/items/{id}")\ndef remove(id: int, user=Depends(get_current_user)):\n    pass\n'
              'model.eval()\n',
    "server.js": "const app = express();\napp.use(cors({ origin: '*', credentials: true }));\n"
                 "app.post('/api/open', async (req, res) => {\n  db.query(`SELECT * FROM users WHERE id = ${req.body.id}`);\n});\n"
                 "app.post('/api/safe', requireAuth, (req, res) => {});\napp.post('/api/login', (req, res) => {});\n"
                 "const q = sql`SELECT * FROM t WHERE id = ${id}`;\n",
    "View.jsx": "export const V = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;\n",
    "node_modules/pkg/leak.js": f'const k = "{AWS}";\n',
}

with tempfile.TemporaryDirectory() as d:
    for rel, text in FILES.items():
        Path(d, rel).parent.mkdir(parents=True, exist_ok=True)
        Path(d, rel).write_text(text, encoding="utf-8")

    # secrets: found, masked, node_modules ignored, placeholders skipped
    hits = appsec.scan_secrets_and_entropy(d)
    types = {(h["file"], h["type"]) for h in hits}
    assert ("config.py", "AWS Access Key ID") in types and ("config.py", "Stripe live key") in types, types
    assert ("config.py", "DB URL with credentials") in types, types
    assert not any(h["file"].startswith("node_modules") for h in hits)
    assert not any("your-token" in h["masked"] for h in hits)
    blob = repr(hits)
    assert AWS not in blob and STRIPE not in blob and DB_PASS not in blob, "secret leaked unmasked"

    # SAST native rules + routes
    sast = appsec.run_static_ast_rules(d)
    assert sast["engine"] in ("native", "semgrep")
    rules = {(f["rule"], f["file"]) for f in sast["findings"]}
    if sast["engine"] == "native":
        for expected in [("sql-fstring", "api.py"), ("eval-py", "api.py"), ("sql-template-literal", "server.js"),
                         ("react-dangerously-set-inner-html", "View.jsx"), ("cors-wildcard-credentials", "server.js"),
                         ("cors-wildcard-credentials", "api.py")]:
            assert expected in rules, (expected, rules)
        assert not any(f["file"] == "api.py" and f["line"] == 13 for f in sast["findings"]), "model.eval() flagged"
        assert not any(f["file"] == "server.js" and f["line"] == 8 for f in sast["findings"]), "tagged sql`` flagged"
    unauth = {f["endpoint"] for f in sast["findings"] if f["rule"] == "endpoint-without-auth"}
    assert unauth == {"POST /api/open", "POST /items"}, unauth  # /api/safe has middleware, /api/login is public, DELETE has Depends

    # DAST: strict localhost-only validation
    bad = [("http://example.com", "/"), ("http://127.0.0.1.evil.com", "/"), ("http://user@localhost", "/"),
           ("ftp://localhost", "/"), ("http://localhost", "//evil.com/x"), ("http://localhost", "evil"),
           ("http://[::ffff:8.8.8.8]", "/"), ("http://0.0.0.0", "/")]
    for base, ep in bad:
        try:
            asyncio.run(appsec.verify_endpoint_security(base, ep, "GET"))
            raise AssertionError(f"accepted {base}{ep}")
        except ValueError:
            pass
    try:
        asyncio.run(appsec.verify_endpoint_security("http://localhost", "/", "DELETE"))
        raise AssertionError("DELETE accepted")
    except ValueError:
        pass

    # local server: /api/open answers 200 to anyone until "patched", then 401 with security headers
    patched = threading.Event()

    class H(BaseHTTPRequestHandler):
        def _reply(self):
            if patched.is_set():
                self.send_response(401)
                for k, v in {"Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff",
                             "X-Frame-Options": "DENY"}.items():
                    self.send_header(k, v)
            else:
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
        do_GET = do_POST = _reply

        def log_message(self, *_):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"

    async def lifecycle():
        ws = Workspace(d)
        await ws.call("run_sast", {})
        open_f = next(f for f in ws.findings.items.values() if f.get("endpoint") == "POST /api/open")
        assert open_f["status"] == "DETECTED"
        out = await ws.call("verify_endpoint_security", {"base_url": base, "endpoint": "/api/open", "method": "POST"}, "QARunner")
        assert "auth gate FAIL" in out and "HTTP 200" in out, out
        assert open_f["status"] == "CONFIRMED_BY_QA"
        headers_f = next(f for f in ws.findings.items.values() if f["title"].startswith("Cabeceras"))
        assert "Content-Security-Policy" in headers_f["empirical_evidence"]

        assert "ERROR" in await ws.call("set_finding_status", {"id": open_f["id"], "status": "VERIFIED", "evidence": "x"}, "Fixer")
        assert "ERROR" in await ws.call("set_finding_status", {"id": open_f["id"], "status": "PATCHED", "evidence": "x", "agent": "Fixer"}, "Reviewer")
        for f in (open_f, headers_f):
            assert (await ws.call("set_finding_status", {"id": f["id"], "status": "PATCHED", "evidence": "middleware añadido"}, "Fixer")).endswith("PATCHED")

        patched.set()
        out = await ws.call("verify_endpoint_security", {"base_url": base, "endpoint": "/api/open", "method": "POST"}, "QARunner")
        assert "auth gate PASS" in out, out
        assert open_f["status"] == "VERIFIED" and headers_f["status"] == "VERIFIED", (open_f["status"], headers_f["status"])
        assert [f["id"] for f in ws.findings.items.values()] == [f"COVEN-{i:03d}" for i in range(1, len(ws.findings.items) + 1)]

        await ws.call("run_sast", {})  # re-scan does not duplicate
        assert sum(f.get("endpoint") == "POST /api/open" for f in ws.findings.items.values()) == 1

        out = await ws.call("scan_secrets", {})
        assert AWS not in out and STRIPE not in out and DB_PASS not in out

    asyncio.run(lifecycle())
    srv.shutdown()

    assert appsec.route_matches("GET /users/:id", "GET", "/users/42")
    assert appsec.route_matches("ANY /api/x/[id]", "POST", "/api/x/1")
    assert not appsec.route_matches("POST /users/{id}", "GET", "/users/1")

    # SCA: version picking (offline) and a live OSV query
    vuln = {"affected": [{"package": {"name": "Jinja2"}, "ranges": [{"events": [
        {"introduced": "0"}, {"fixed": "2.10.1"}, {"introduced": "3.0"}, {"fixed": "3.1.5"}]}]}]}
    assert appsec._fixed_version(vuln, {"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"}) == "2.10.1"
    assert appsec._fixed_version(vuln, {"name": "jinja2", "version": "3.1.0", "ecosystem": "PyPI"}) == "3.1.5"
    Path(d, "requirements.txt").write_text("fastapi>=0.1\njinja2==2.10\n")
    Path(d, "package.json").write_text('{"dependencies": {"lodash": "4.17.15", "react": "^18.2.0", "x": "git+https://a/b"}}')
    deps = {(x["name"], x["version"], x["line"]) for x in appsec.collect_dependencies(Path(d))}
    assert deps == {("jinja2", "2.10", 2), ("lodash", "4.17.15", 1), ("react", "18.2.0", 1)}, deps
    osv = asyncio.run(appsec.scan_dependencies_osv(d))
    if osv["errors"]:
        print("OSV live check skipped (offline):", osv["errors"][:2])
    else:
        by_pkg = {v["name"] for v in osv["vulnerabilities"]}
        assert {"jinja2", "lodash"} <= by_pkg, by_pkg
        assert all(v["severity"] in appsec.SEVERITIES for v in osv["vulnerabilities"])
        assert any(v["cve"].startswith("CVE-") and v["fixed"] for v in osv["vulnerabilities"])
        print(f"OSV live: {len(osv['vulnerabilities'])} advisories for {osv['scanned']} deps")
# regressions from a real repo: unquoted .env tokens, git-ignored downgrade, eval inside a regex string, PYSEC+GHSA dupes
import subprocess  # noqa: E402

TG, OR = "1234567890:AA" + "Fk3j_x9QmZ2vB7nR4tY8wP1sL6dH0cG5eK", "sk-or-v1-" + "ab12" * 16
with tempfile.TemporaryDirectory() as d:
    Path(d, ".env").write_text(f"TELEGRAM_TOKEN={TG}\nOPENROUTER_API_KEY={OR}\nDB_PASSWORD=Xq7!pL2#vR9z\nLOG_LEVEL=INFO\n")
    Path(d, "deploy.sh").write_text(f"export GITHUB_TOKEN=ghp_{'a1B2' * 9}\n")
    Path(d, ".gitignore").write_text(".env\n")
    Path(d, "security.py").write_text("PATTERNS = [r'eval\\s*\\(', \"exec(\"]\nresult = eval(user_input)\n"
                                      "    r'eval\\s*\\(',  # eval() calls\n")
    Path(d, "README.md").write_text("TELEGRAM_TOKEN=tu_token_de_telegram_aqui\nOPENROUTER_API_KEY=sk-or-v1-tu_api_key\n")
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    hits = {(h["file"], h["type"]): h for h in appsec.scan_secrets_and_entropy(d)}
    assert hits[(".env", "Telegram bot token")]["severity"] == "LOW" and hits[(".env", "Telegram bot token")]["ignored"]
    assert (".env", "OpenRouter API key") in hits and (".env", "Hardcoded credential") in hits, hits.keys()
    assert hits[("deploy.sh", "GitHub token")]["severity"] == "CRITICAL" and not hits[("deploy.sh", "GitHub token")].get("ignored")
    assert not any("LOG_LEVEL" in str(h) for h in hits.values()) and TG not in repr(hits) and OR not in repr(hits)
    assert not any(f == "README.md" for f, _ in hits), "Spanish placeholders flagged"
    if (sast := appsec.run_static_ast_rules(d))["engine"] == "native":
        assert [f["line"] for f in sast["findings"] if f["rule"] == "eval-py"] == [2], sast["findings"]

# regressions from Juice Shop: test code downgraded, constant new Function() not flagged, template ${} still dynamic
with tempfile.TemporaryDirectory() as d:
    Path(d, "test").mkdir()
    Path(d, "test", "login.spec.ts").write_text(f"const token = '{OR}'\neval(input)\n")
    Path(d, "xml.ts").write_text("const imp = new Function('s', 'return import(s)')\neval(`${code}`)\neval(userInput)\n")
    hits = appsec.scan_secrets_and_entropy(d)
    assert hits and all(h["severity"] == "LOW" and h["test_code"] for h in hits), hits
    sast = appsec.run_static_ast_rules(d)
    if sast["engine"] == "native":
        ev = sorted((f["file"], f["line"], f["severity"]) for f in sast["findings"] if f["rule"] == "eval-js")
        assert ev == [("test/login.spec.ts", 2, "LOW"), ("xml.ts", 2, "HIGH"), ("xml.ts", 3, "HIGH")], ev
    Path(d, "server.ts").write_text("app.use(session({ secret: s }))\napp.use('/rest/basket', security.isAuthorized())\n"
                                    "app.get('/rest/basket/:id', basket())\napp.get('/api/Deliverys', delivery())\n"
                                    "app.get('/api/Users', security.isAuthorized())\napp.get('/api/Users', list())\n"
                                    "app.post('/api/Users', verify.registerAdminChallenge())\n")
    auth = {(r["method"], r["path"], r["line"]): r["auth"] for r in appsec.map_api_routes(d) if r["file"] == "server.ts"}
    assert auth == {("GET", "/rest/basket/:id", 3): True, ("GET", "/api/Deliverys", 4): False, ("GET", "/api/Users", 5): True,
                    ("GET", "/api/Users", 6): True, ("POST", "/api/Users", 7): False}, auth

# app.route() chains and finale/epilogue generated CRUD (template endpoints expanded from `name:` literals)
with tempfile.TemporaryDirectory() as d:
    Path(d, "server.ts").write_text(
        "app.route('/api/Users/:id')\n  .get(security.isAuthorized())\n  .put(security.denyAll())\n"
        "app.route('/api/Hints/:id').get(security.denyAll())\n"
        "app.post('/api/Products', security.isAuthorized())\n"
        "const models = [{ name: 'User', model: U }, { name: 'Product', model: P }]\n"
        "for (const { name, model } of models) {\n"
        "  finale.resource({\n    model,\n    endpoints: [`/api/${name}s`, `/api/${name}s/:id`]\n  })\n}\n")
    auth = {(r["method"], r["path"]): r["auth"] for r in appsec.map_api_routes(d)}
    assert auth[("GET", "/api/Users/:id")] and auth[("PUT", "/api/Users/:id")] and auth[("GET", "/api/Hints/:id")]
    assert not auth[("DELETE", "/api/Users/:id")] and not auth[("PUT", "/api/Products/:id")] and auth[("POST", "/api/Products")]
    assert not auth[("GET", "/api/Users")] and ("POST", "/api/Users") in auth and len(auth) == 11, auth

# an anonymous 401 disproves missing auth, never an IDOR on the same endpoint
reg = appsec.FindingRegistry()
idor = reg.add("idor", title="IDOR", severity="HIGH", standard="OWASP A01:2021 / CWE-639", endpoint="GET /rest/basket/:id")
noauth = reg.add("na", title="sin auth", severity="HIGH", standard="OWASP A01:2021 / CWE-306", endpoint="GET /rest/basket/:id")
reg.apply_probe("GET", "/rest/basket/1", {"auth_gate": "PASS", "traces": [], "url": "http://127.0.0.1:3000/rest/basket/1",
                                          "missing_headers": [], "https": False})
assert reg.get(idor["id"])["status"] == "DETECTED" and reg.get(noauth["id"])["status"] == "FALSE_POSITIVE"

dup = [{"ecosystem": "PyPI", "name": "requests", "cve": "CVE-2024-47081", "severity": s, "fixed": f, "summary": x}
       for s, f, x in [("MEDIUM", "2.32.4", "short"), ("HIGH", "2.32.3", "a longer summary")]]
merged = appsec.dedupe_advisories(dup + [{**dup[0], "cve": "CVE-2024-35195"}])
assert len(merged) == 2 and merged[0]["severity"] == "HIGH" and merged[0]["fixed"] == "2.32.4" and merged[0]["summary"] == "a longer summary"
# private keys never reach the LLM: one marker at the key's first line, line count preserved
pem = "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDN\nabcd\n-----END RSA PRIVATE KEY-----"
src = f"a = 1\nkey = '''{pem}'''\nb = 2\ninline = '{pem.replace(chr(10), chr(92) + 'r' + chr(92) + 'n')}'\naws = 'AKIAABCDEFGHIJKLMNOP'"
red = appsec.redact(src)
assert "MIICXAIBAAKBgQDN" not in red and "AKIAABCDEFGHIJKLMNOP" not in red, red
assert red.count("\n") == src.count("\n") and "[REDACTED_PRIVATE_KEY_DETECTED at line 2]" in red
assert "[REDACTED_PRIVATE_KEY_DETECTED at line 7]" in red, red
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "k.py").write_text(src, encoding="utf-8")
    ws = Workspace(d)
    assert "MIICXAIBAAKBgQDN" not in ws.read_file("k.py") and "7: inline = '[REDACTED" in ws.read_file("k.py")
    assert "MIICXAIBAAKBgQDN" not in ws.search_code("inline|MIIC")
# agent autonomy: free commands and scripts inside the project, guardrails for the dangerous ones
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "mod.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    ws = Workspace(d)
    run = lambda tool, **a: asyncio.run(ws.call(tool, a))
    assert run("run_command", command="python -I mod.py").startswith("exit code 0")
    assert run("run_command", command="python --version").startswith("exit code 0")
    out = run("run_code", language="python", code="import sys; sys.path.insert(0, '.')\nfrom mod import add\nassert add(2, 3) == 5\nprint('ok')")
    assert out.startswith("exit code 0") and "ok" in out, out
    assert "exit code 1" in run("run_code", language="python", code="raise SystemExit(1)")
    assert not list((Path(d) / ".coven").glob("*")), "scripts are cleaned up"
    for bad in ["rm -rf .", "del mod.py", "powershell -c dir", "git push origin main", "curl http://example.com",
                "python -c print(1)", "python ../outside.py", "python C:/Windows/win.ini", "node x.js http://evil.example",
                "npm install", "npm i jsonwebtoken@9", "pip install requests", "python -m pip install x", "yarn add x"]:
        assert run("run_command", command=bad).startswith("ERROR"), bad
    assert run("run_code", language="python", code="import urllib.request\nurllib.request.urlopen('https://evil.example')").startswith("ERROR")
    assert run("run_code", language="ruby", code="puts 1").startswith("ERROR")
    assert not run("run_command", command="node x.js http://127.0.0.1:3002/api").startswith("ERROR: red")
print("appsec OK")
