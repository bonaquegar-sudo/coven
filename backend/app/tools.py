"""Sandboxed file/test tools the agents call. Every path is confined to the project root."""
import asyncio
import difflib
import fnmatch
import inspect
import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from . import appsec_tools as appsec
from .appsec_tools import SKIP_DIRS, FindingRegistry

MAX_OUT = 12_000
# ponytail: subprocess with a command allowlist, not a container. Running a repo's tests runs its code;
# move to the docker SDK when Coven analyses repos you don't trust.
TEST_COMMANDS = [
    ["pytest"], ["python", "-m", "pytest"], ["npm", "test"], ["npm", "run", "test"], ["npm", "run", "lint"],
    ["npx", "vitest", "run"], ["npx", "jest"], ["npx", "tsc", "--noEmit"], ["npx", "eslint"], ["ruff", "check"],
]

# name -> (description, {param: description}, required params)
SPECS = {
    "list_directory": ("Árbol de directorios (ignora node_modules, .git, etc.).",
                       {"path": "Ruta relativa al proyecto, '.' por defecto"}, []),
    "read_file": ("Lee un archivo de texto con números de línea (200 líneas por defecto; pide solo el rango que necesites).",
                  {"path": "Ruta relativa", "start_line": "Primera línea (1 por defecto)",
                   "end_line": "Última línea (máx. 400 por lectura)"}, ["path"]),
    "find_files": ("Busca archivos por patrón glob sobre la ruta relativa, ej. '*.py' o 'src/**/*.ts'.",
                   {"pattern": "Patrón glob"}, ["pattern"]),
    "search_code": ("Busca una regex en el código. Devuelve archivo:línea: texto.",
                    {"query": "Expresión regular", "glob": "Filtro de archivos, ej. '*.ts'"}, ["query"]),
    "write_file": ("Crea o sobrescribe un archivo completo.",
                   {"path": "Ruta relativa", "content": "Contenido completo"}, ["path", "content"]),
    "apply_patch": ("Reemplaza un fragmento exacto (debe aparecer una sola vez) por otro.",
                    {"path": "Ruta relativa", "old": "Texto exacto actual", "new": "Texto nuevo"}, ["path", "old", "new"]),
    "get_git_diff": ("Diff unificado de todos los cambios hechos en esta sesión.", {}, []),
    "run_tests": ("Ejecuta un test runner/linter permitido: " + ", ".join(" ".join(c) for c in TEST_COMMANDS),
                  {"command": "Comando, ej. 'npx vitest run' o 'pytest -q'"}, ["command"]),
    # AppSec
    "scan_dependencies_osv": ("SCA: consulta OSV.dev con cada dependencia fijada (package.json, requirements.txt, "
                              "pyproject.toml). Devuelve CVEs reales, severidad y versión segura.", {}, []),
    "scan_secrets": ("Busca secretos (AWS, Stripe, JWT, URLs de BD con credenciales) y cadenas de alta entropía. "
                     "Los valores vienen enmascarados.", {}, []),
    "run_sast": ("SAST: semgrep si está instalado, si no reglas nativas (eval, dangerouslySetInnerHTML, SQL con "
                 "f-string/template literal, CORS * con credenciales, endpoints sin auth).", {}, []),
    "map_api_routes": ("Mapa de rutas API (Express, FastAPI, Flask, Next.js) con indicador de auth.", {}, []),
    "verify_endpoint_security": ("Prueba de integración local (auth_middleware_check + verify_schema de cabeceras): "
                                 "petición sin credenciales y con token inválido; lo correcto es 401/403. Solo localhost/127.0.0.1.",
                                 {"base_url": "ej. http://localhost:3000", "endpoint": "ruta, ej. /api/users",
                                  "method": "GET, HEAD, OPTIONS o POST"}, ["base_url", "endpoint"]),
    "report_finding": ("Registra un hallazgo de seguridad confirmado leyendo el código.",
                       {"title": "Título", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "standard": "OWASP / CWE / CVE",
                        "file_path": "Ruta relativa", "line_number": "Línea", "evidence": "Evidencia (código citado)",
                        "fix": "Corrección propuesta", "endpoint": "Opcional: 'METHOD /ruta' afectada"},
                       ["title", "severity", "standard", "file_path", "evidence"]),
    "set_finding_status": ("Cambia el estado de un hallazgo COVEN-NNN aportando evidencia empírica.",
                           {"id": "COVEN-001", "status": "CONFIRMED_BY_QA|FALSE_POSITIVE|VERIFIED (QARunner) o PATCHED (Fixer)",
                            "evidence": "Evidencia: traza HTTP, salida de tests, diff..."}, ["id", "status", "evidence"]),
    "list_findings": ("Lista los hallazgos de seguridad registrados con su estado.", {}, []),
}


# manifest dependency -> stack label shown in the UI
JS_STACK = {"next": "Next.js", "react": "React", "vue": "Vue", "svelte": "Svelte", "@angular/core": "Angular",
            "express": "Express", "@nestjs/core": "NestJS", "prisma": "Prisma", "tailwindcss": "Tailwind"}
PY_STACK = {"fastapi": "FastAPI", "django": "Django", "flask": "Flask", "sqlalchemy": "SQLAlchemy", "langgraph": "LangGraph"}


def detect_stack(root: Path) -> list[str]:
    """Cheap stack fingerprint from manifest files at the project root."""
    stack = []
    if (pkg := root / "package.json").exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        stack += [label for dep, label in JS_STACK.items() if dep in deps and not (dep == "react" and "next" in deps)]
        stack.append("TypeScript" if "typescript" in deps or (root / "tsconfig.json").exists() else "JavaScript")
    py = " ".join(f.read_text(encoding="utf-8", errors="ignore").lower()
                  for f in (root / "requirements.txt", root / "pyproject.toml") if f.exists())
    if py or any(root.glob("*.py")):
        stack += ["Python"] + [label for dep, label in PY_STACK.items() if dep in py]
    for name, label in (("go.mod", "Go"), ("Cargo.toml", "Rust"), ("Dockerfile", "Docker"), ("docker-compose.yml", "Docker")):
        if (root / name).exists() and label not in stack:
            stack.append(label)
    return stack


def docker_status() -> str:
    """'ready' if the Docker daemon answers, 'stopped' if installed but down, 'missing' otherwise."""
    if not (exe := shutil.which("docker")):
        return "missing"
    try:
        r = subprocess.run([exe, "info", "--format", "{{.ServerVersion}}"], capture_output=True, timeout=4)
    except subprocess.TimeoutExpired:
        return "stopped"
    return "ready" if r.returncode == 0 else "stopped"


def tool_schemas(names: list[str]) -> list[dict]:
    """OpenAI-style function schemas (LiteLLM translates them per provider)."""
    return [{"type": "function", "function": {
        "name": n, "description": SPECS[n][0],
        "parameters": {"type": "object", "required": SPECS[n][2],
                       "properties": {p: {"type": "string", "description": d} for p, d in SPECS[n][1].items()}},
    }} for n in names]


class Workspace:
    def __init__(self, root: str):
        self.root = Path(root).expanduser().resolve()
        if not self.root.is_dir():
            raise ValueError(f"No existe el directorio: {root}")
        self.originals: dict[str, str | None] = {}  # rel path -> content before Coven touched it (None = new file)
        self.findings = FindingRegistry()
        self.routes: list[dict] = []  # last map_api_routes result

    async def call(self, name: str, args: dict, agent: str = "") -> str:
        if name not in SPECS:
            return f"ERROR: herramienta desconocida {name}"
        if name == "set_finding_status":
            args = {**args, "agent": agent}  # who is asking comes from the graph, never from the model
        fn = getattr(self, name)
        try:
            out = await fn(**args) if inspect.iscoroutinefunction(fn) else await asyncio.to_thread(fn, **args)
            return str(out)[:MAX_OUT]
        except Exception as e:  # tool errors go back to the model, not up the stack
            return f"ERROR: {e}"

    def _path(self, rel: str) -> Path:
        p = (self.root / rel).resolve()
        if not p.is_relative_to(self.root):
            raise ValueError("ruta fuera del proyecto")
        return p

    def _files(self):
        for dirpath, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                yield Path(dirpath, f)

    def _rel(self, p: Path) -> str:
        return p.relative_to(self.root).as_posix()

    def list_directory(self, path: str = ".", depth: int = 3) -> str:
        base, lines = self._path(path), []

        def walk(d: Path, level: int):
            for c in sorted(d.iterdir(), key=lambda c: (c.is_file(), c.name)):
                if c.name in SKIP_DIRS:
                    continue
                lines.append("  " * level + c.name + ("/" if c.is_dir() else ""))
                if c.is_dir() and level + 1 < depth:
                    walk(c, level + 1)
        walk(base, 0)
        return "\n".join(lines[:500]) or "(vacío)"

    def read_file(self, path: str, start_line: str | int = 1, end_line: str | int = 0) -> str:
        start = max(int(start_line or 1), 1)
        end = min(int(end_line or start + 199), start + 399)
        text = appsec.redact(self._path(path).read_text(encoding="utf-8", errors="replace")).splitlines()
        chunk = text[start - 1:end]
        more = f"\n... ({len(text)} líneas en total)" if end < len(text) else ""
        return "\n".join(f"{i}: {l}" for i, l in enumerate(chunk, start)) + more

    def find_files(self, pattern: str) -> str:
        hits = [r for p in self._files() if fnmatch.fnmatch(r := self._rel(p), pattern) or fnmatch.fnmatch(p.name, pattern)]
        return "\n".join(hits[:200]) or "(sin resultados)"

    def search_code(self, query: str, glob: str = "*") -> str:
        rx, hits = re.compile(query), []
        for p in self._files():
            if not fnmatch.fnmatch(p.name, glob) or p.stat().st_size > 1_000_000:
                continue
            try:
                for i, line in enumerate(appsec.redact(p.read_text(encoding="utf-8")).splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{self._rel(p)}:{i}: {line.strip()[:200]}")
            except UnicodeDecodeError:
                continue  # binary
            if len(hits) >= 100:
                break
        return "\n".join(hits) or "(sin resultados)"

    def write_file(self, path: str, content: str) -> str:
        p = self._path(path)
        rel = self._rel(p)
        if rel not in self.originals:
            self.originals[rel] = p.read_text(encoding="utf-8") if p.exists() else None
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return f"OK: {rel} escrito"

    def apply_patch(self, path: str, old: str, new: str) -> str:
        text = self._path(path).read_text(encoding="utf-8")
        if (n := text.count(old)) != 1:
            raise ValueError(f"'old' aparece {n} veces; debe ser exacto y único")
        return self.write_file(path, text.replace(old, new))

    def get_git_diff(self) -> str:
        # Diff against our own snapshots: works without git and only shows Coven's changes.
        out = []
        for rel, before in self.originals.items():
            p = self.root / rel
            after = p.read_text(encoding="utf-8") if p.exists() else ""
            out += difflib.unified_diff((before or "").splitlines(True), after.splitlines(True),
                                        f"a/{rel}" if before is not None else "/dev/null", f"b/{rel}")
        return appsec.redact("".join(out)) or "(sin cambios)"

    def revert(self, rel: str) -> None:
        before = self.originals.pop(rel)
        p = self._path(rel)
        if before is None:
            p.unlink(missing_ok=True)
        else:
            p.write_text(before, encoding="utf-8")

    def run_tests(self, command: str) -> str:
        argv = shlex.split(command)
        if not any(argv[:len(c)] == c for c in TEST_COMMANDS):
            raise ValueError("comando no permitido")
        exe = shutil.which(argv[0])  # resolves npx.cmd etc. on Windows without shell=True
        if not exe:
            raise ValueError(f"{argv[0]} no está instalado")
        try:
            r = subprocess.run([exe, *argv[1:]], cwd=self.root, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=300)
        except subprocess.TimeoutExpired:
            return "TIMEOUT tras 300s"
        out = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", r.stdout + r.stderr)  # strip ANSI colours
        return f"exit code {r.returncode}\n{out[-MAX_OUT:]}"

    # ---- AppSec: run a scanner, register what it found, return text for the model.
    # The first line of each result is the one-line summary shown in the UI.

    async def scan_dependencies_osv(self) -> str:
        r = await appsec.scan_dependencies_osv(self.root)
        groups: dict[tuple, list] = {}
        for v in r["vulnerabilities"]:
            f = self.findings.add(f"osv:{v['ecosystem']}:{v['name']}:{v['id']}", source="osv",
                                  title=f"{v['name']}@{v['version']} vulnerable ({v['id']})", severity=v["severity"],
                                  standard=v["cve"], file_path=v["manifest"], line_number=v["line"],
                                  empirical_evidence=f"OSV {v['id']}: {v['summary']}",
                                  fix=f"Actualizar {v['name']} a {v['fixed']}" if v["fixed"] else "Sin versión corregida publicada")
            groups.setdefault((v["ecosystem"], v["name"], v["version"], v["manifest"], v["line"]), []).append((f["id"], v))
        # one line per package (the per-CVE detail lives in the registry/UI): far fewer tokens, same decisions
        rows = []
        for (eco, name, ver, manifest, line), items in groups.items():
            worst = min(items, key=lambda x: appsec.SEVERITIES.index(x[1]["severity"]))[1]
            fixes = [v["fixed"] for _, v in items if v["fixed"]]
            rows.append(f"{','.join(i for i, _ in items)} [{worst['severity']}] {eco} {name}@{ver} "
                        f"-> {max(fixes, key=appsec._vkey) if fixes else 'sin fix'} ({manifest}:{line}) "
                        f"{len(items)} avisos: {', '.join(v['cve'] for _, v in items)[:160]} — {worst['summary'][:90]}")
        head = f"{len(r['vulnerabilities'])} vulnerabilidades en {r['scanned']} dependencias fijadas (OSV.dev)"
        errors = f"\nErrores de red: {', '.join(r['errors'][:10])}" if r["errors"] else ""
        return "\n".join([head, *rows]) + errors

    def scan_secrets(self) -> str:
        hits = appsec.scan_secrets_and_entropy(self.root)
        rows = []
        for h in hits:
            f = self.findings.add(f"secret:{h['file']}:{h['line']}:{h['type']}", source="secrets",
                                  title=f"Secreto expuesto: {h['type']}", severity=h["severity"],
                                  standard="OWASP A07:2021 / CWE-798", file_path=h["file"], line_number=h["line"],
                                  empirical_evidence=f"Valor (enmascarado): {h['masked']}"
                                                     + (f", entropía {h['entropy']}" if "entropy" in h else "")
                                                     + (". Archivo ignorado por git: no llega al repo, pero rota la "
                                                        "credencial si se compartió" if h.get("ignored") else "")
                                                     + (". Código de test: no llega a producción" if h.get("test_code") else ""),
                                  fix="Mover a variables de entorno / gestor de secretos y rotar la credencial")
            if h["severity"] != "LOW":
                rows.append(f"{f['id']} [{h['severity']}] {h['type']} en {h['file']}:{h['line']} -> {h['masked']}")
        low = len(hits) - len(rows)
        return "\n".join([f"{len(hits)} posibles secretos", *rows]
                         + ([f"+{low} LOW (código de test o ignorados por git): en el registro, no listados"] if low else []))

    def run_sast(self) -> str:
        r = appsec.run_static_ast_rules(self.root)
        rows = []
        for h in r["findings"]:
            f = self.findings.add(f"sast:{h['rule']}:{h['file']}:{h['line']}", source="semgrep" if r["engine"] == "semgrep" else "sast",
                                  title=h["title"], severity=h["severity"], standard=h["standard"], file_path=h["file"],
                                  line_number=h["line"], empirical_evidence=h["snippet"] and f"`{h['snippet']}`",
                                  **({"endpoint": h["endpoint"]} if h.get("endpoint") else {}))
            if h["severity"] != "LOW":
                rows.append(f"{f['id']} [{h['severity']}] {h['standard']} {h['title']} ({h['file']}:{h['line']})"
                            + (f"\n    {h['snippet']}" if h["snippet"] else ""))
        low = len(r["findings"]) - len(rows)
        return "\n".join([f"{len(r['findings'])} hallazgos SAST (motor: {r['engine']})", *rows]
                         + ([f"+{low} LOW (código de test): en el registro, no listados"] if low else []))

    def map_api_routes(self) -> str:
        self.routes = appsec.map_api_routes(self.root)
        # routes with auth are listed only as a count: the model needs the unprotected ones
        open_ = [r for r in self.routes if not r["auth"]]
        rows = [f"{r['method']:7} {r['path']:40} SIN AUTH {r['file']}:{r['line']}" for r in open_[:120]]
        return "\n".join([f"{len(self.routes)} rutas API detectadas ({len(self.routes) - len(open_)} con auth, no listadas)",
                          *rows] + ([f"+{len(open_) - 120} rutas sin auth más"] if len(open_) > 120 else []))

    async def verify_endpoint_security(self, base_url: str, endpoint: str, method: str = "GET") -> str:
        r = await appsec.verify_endpoint_security(base_url, endpoint, method)
        touched = self.findings.apply_probe(r["method"], endpoint, r)
        lines = [f"{r['method']} {endpoint}: auth gate {r['auth_gate']}, cabeceras ausentes: {len(r['missing_headers'])}"]
        for t in r["traces"]:
            lines.append(f"> {t['request']}\n< HTTP {t['status']}\n" + "\n".join(f"< {k}: {v}" for k, v in t["headers"].items())
                         + (f"\n< body: {t['body'][:200]}" if t["body"] else ""))
        lines.append("Cabeceras: " + ", ".join(f"{k} {'OK' if ok else 'FALTA'}" for k, ok in r["headers"].items()))
        lines += [f"{f['id']} -> {f['status']}" for f in touched]
        return "\n".join(lines)

    def report_finding(self, title: str, severity: str, standard: str, file_path: str, evidence: str,
                       line_number: str | int = 0, fix: str = "", endpoint: str = "") -> str:
        severity = severity.strip().upper()
        if severity not in appsec.SEVERITIES:
            raise ValueError(f"severidad inválida; usa {', '.join(appsec.SEVERITIES)}")
        line = int(line_number or 0)
        if not self._path(file_path).is_file():
            raise ValueError(f"no existe {file_path}")
        f = self.findings.add(f"reviewer:{file_path}:{line}:{title.lower()}", source="reviewer", title=title,
                              severity=severity, standard=standard, file_path=file_path, line_number=line,
                              empirical_evidence=evidence, fix=fix, **({"endpoint": endpoint.strip()} if endpoint.strip() else {}))
        return f"{f['id']} registrado [{f['severity']}] {f['title']}"

    def set_finding_status(self, id: str, status: str, evidence: str, agent: str) -> str:
        f = self.findings.set_status(id, status, evidence, agent)
        return f"{f['id']} -> {f['status']}"

    def list_findings(self) -> str:
        items = list(self.findings.items.values())
        shown = [f for f in items if f["severity"] != "LOW" and f["status"] != "FALSE_POSITIVE"]
        return "\n".join([f"{len(items)} hallazgos ({len(items) - len(shown)} LOW o descartados, no listados)", *(
            f"{f['id']} [{f['severity']}][{f['status']}] {f['title']} — {f['file_path']}:{f['line_number']} ({f['standard']})"
            + (f" endpoint {f['endpoint']}" if f.get("endpoint") else "") for f in shown)])
