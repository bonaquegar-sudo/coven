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
import time
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
# run_command guardrails: no shells (they would bypass every check below), deletion, privilege or system tools
BLOCKED_EXES = {"rm", "rmdir", "del", "erase", "rd", "format", "mkfs", "dd", "shutdown", "reboot", "sudo", "su", "runas",
                "cmd", "powershell", "pwsh", "bash", "sh", "zsh", "wsl", "reg", "regedit", "diskpart", "takeown", "icacls",
                "chmod", "chown", "kill", "taskkill", "curl", "wget", "ssh", "scp", "nc", "ncat", "netsh", "schtasks"}
BLOCKED_SUBCOMMANDS = ("git push", "git reset", "git clean", "git checkout", "git restore", "git rebase", "git remote",
                       "git config", "npm publish", "npm adduser", "npm login", "npm token", "pip uninstall",
                       "npm uninstall", "yarn publish", "pnpm publish", "python -c", "node -e", "node --eval")

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
    "run_command": ("Ejecuta cualquier comando de desarrollo en la raíz del proyecto (sin shell: nada de pipes ni &&), p. ej. "
                    "'npm install', 'node scripts/check.js', 'python -m pip list', 'git log -5'. Sin borrados, sin git push/reset, "
                    "rutas solo dentro del proyecto, red solo a localhost. Devuelve exit code y salida.",
                    {"command": "Comando completo", "timeout": "Segundos, máx. 300 (120 por defecto)"}, ["command"]),
    "run_code": ("Ejecuta un script corto de diagnóstico (regression_test, diagnostic_input) en Python o Node con cwd en la "
                 "raíz del proyecto, p. ej. para importar un módulo y comprobar una función parcheada. Red solo a localhost.",
                 {"language": "python o node", "code": "Código completo del script", "timeout": "Segundos, máx. 120 (60 por defecto)"},
                 ["language", "code"]),
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
        self.findings = FindingRegistry(self.root / ".coven" / "accepted.json")
        self.routes: list[dict] = []  # last map_api_routes result

    # ---- git: diff-only scans and publishing Coven's changes. Plain subprocess, never through the agents' tools.

    def _git(self, *args: str, check: bool = True) -> str:
        r = subprocess.run(["git", *args], cwd=self.root, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=120, stdin=subprocess.DEVNULL)
        if check and r.returncode:
            raise ValueError(f"git {args[0]}: {(r.stderr or r.stdout).strip()[:400]}")
        return r.stdout.strip()

    def changed_files(self, base: str = "") -> set[str]:
        """Files changed vs base (default: the merge-base with main/master) plus uncommitted and untracked ones."""
        if not base:
            for ref in ("origin/main", "origin/master", "main", "master"):
                if self._git("rev-parse", "--verify", "--quiet", ref, check=False):
                    base = self._git("merge-base", "HEAD", ref, check=False)
                    break
        files = set(self._git("diff", "--name-only", base or "HEAD").splitlines()) if base or self._git(
            "rev-parse", "--verify", "--quiet", "HEAD", check=False) else set()
        files |= set(self._git("ls-files", "--others", "--exclude-standard").splitlines())
        return {f for f in files if f}

    def limit_to_changes(self, base: str = "") -> set[str]:
        self.findings.only = self.changed_files(base)
        return self.findings.only

    def git_publish(self, title: str, body: str) -> str:
        """New branch with only Coven's changes, commit, push (never force, never the current branch) and a PR via gh."""
        files = [rel for rel in self.originals if (self.root / rel).exists() or self.originals[rel] is not None]
        if not files:
            raise ValueError("no hay cambios de Coven que publicar")
        self._git("rev-parse", "--git-dir")
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40] or "fix"
        branch = f"coven/{slug}-{time.strftime('%Y%m%d-%H%M%S')}"
        # the developer stays on the new branch: the working tree keeps exactly what they reviewed in the Diff panel
        self._git("switch", "-c", branch)
        self._git("add", "--", *files)
        identity = [] if self._git("config", "user.email", check=False) else ["-c", "user.name=Coven", "-c", "user.email=coven@localhost"]
        self._git(*identity, "commit", "-m", title, "-m", body)
        self.originals.clear()  # committed: nothing left to accept/revert
        remote = self._git("remote", check=False).splitlines()
        if not remote:
            return f"Rama {branch} creada con el commit (sin remoto configurado: no se ha subido)."
        self._git("push", "-u", remote[0], branch)
        gh = shutil.which("gh")
        if gh:
            r = subprocess.run([gh, "pr", "create", "--head", branch, "--title", title, "--body", body], cwd=self.root,
                               capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            if r.returncode == 0:
                return f"PR abierta: {r.stdout.strip().splitlines()[-1]} (rama {branch})"
            return f"Rama {branch} subida; no se pudo abrir la PR con gh: {(r.stderr or r.stdout).strip()[:300]}"
        return f"Rama {branch} subida a {remote[0]}. Instala gh para abrir la PR automáticamente."

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
        return self._exec(argv, 300)

    def run_command(self, command: str, timeout: str | int = 120) -> str:
        argv = shlex.split(command.replace(chr(92), "/"))  # forward slashes: posix quoting without eating Windows paths
        if not argv:
            raise ValueError("comando vacío")
        exe = Path(argv[0]).stem.lower()
        if exe in BLOCKED_EXES or any(" ".join([exe, *argv[1:3]]).lower().startswith(b) for b in BLOCKED_SUBCOMMANDS):
            raise ValueError(f"'{' '.join(argv[:2])}' no está permitido (destructivo, shell o publicación)")
        for a in argv[1:]:
            self._check_arg(a.strip("'\""))
        return self._exec(argv, min(int(timeout or 120), 300))

    def run_code(self, language: str, code: str, timeout: str | int = 60) -> str:
        lang = language.strip().lower()
        if lang not in ("python", "node"):
            raise ValueError("language debe ser python o node")
        for url in re.findall(r"https?://[^\s'\"`)]+", code):
            self._check_arg(url)
        scratch = self.root / ".coven"
        scratch.mkdir(exist_ok=True)
        script = scratch / f"diag_{os.getpid()}_{abs(hash(code)) % 10**8}.{'py' if lang == 'python' else 'js'}"
        script.write_text(code, encoding="utf-8")
        try:
            return self._exec(["python", "-I", str(script)] if lang == "python" else ["node", str(script)],
                              min(int(timeout or 60), 120))
        finally:
            script.unlink(missing_ok=True)

    def _check_arg(self, arg: str) -> None:
        """Agent commands stay in the project and only talk to localhost."""
        if re.match(r"^[a-z]+://", arg, re.I):
            host = re.match(r"^[a-z]+://(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)", arg, re.I)
            if not host or host.group(1).strip("[]").lower() not in appsec.LOCAL_HOSTS | {"::1"}:
                raise ValueError(f"red solo a localhost: {arg[:80]}")
        elif Path(arg).is_absolute() or re.match(r"^[A-Za-z]:[\\/]", arg) or ".." in Path(arg).parts:
            if not (self.root / arg).resolve().is_relative_to(self.root):
                raise ValueError(f"ruta fuera del proyecto: {arg[:80]}")

    def _exec(self, argv: list[str], timeout: int) -> str:
        exe = shutil.which(argv[0])  # resolves npx.cmd etc. on Windows without shell=True
        if not exe:
            raise ValueError(f"{argv[0]} no está instalado")
        # no credentials from Coven's own environment reach agent-run processes
        env = {k: v for k, v in os.environ.items() if not re.search(r"KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL", k, re.I)}
        try:
            r = subprocess.run([exe, *argv[1:]], cwd=self.root, capture_output=True, text=True, env=env,
                               encoding="utf-8", errors="replace", timeout=timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return f"TIMEOUT tras {timeout}s"
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
            if not f:
                continue  # diff-only scan and this manifest did not change
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
            if f and h["severity"] != "LOW":
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
            if f and h["severity"] != "LOW":
                rows.append(f"{f['id']} [{h['severity']}] {h['standard']} {h['title']} ({h['file']}:{h['line']})"
                            + (f"\n    {h['snippet']}" if h["snippet"] else ""))
        low = len(r["findings"]) - len(rows)
        return "\n".join([f"{len(r['findings'])} hallazgos SAST (motor: {r['engine']})", *rows]
                         + ([f"+{low} LOW (código de test): en el registro, no listados"] if low else []))

    def map_api_routes(self) -> str:
        only = self.findings.only
        self.routes = [r for r in appsec.map_api_routes(self.root) if only is None or r["file"] in only]
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
        if not f:
            return f"{file_path} no ha cambiado: fuera del alcance de este escaneo (solo cambios)"
        return f"{f['id']} registrado [{f['severity']}] {f['title']}"

    def set_finding_status(self, id: str, status: str, evidence: str, agent: str) -> str:
        f = self.findings.set_status(id, status, evidence, agent)
        return f"{f['id']} -> {f['status']}"

    def list_findings(self) -> str:
        items = list(self.findings.items.values())
        shown = [f for f in items if f["severity"] != "LOW" and f["status"] not in ("FALSE_POSITIVE", appsec.ACCEPTED)]
        return "\n".join([f"{len(items)} hallazgos ({len(items) - len(shown)} LOW o descartados, no listados)", *(
            f"{f['id']} [{f['severity']}][{f['status']}] {f['title']} — {f['file_path']}:{f['line_number']} ({f['standard']})"
            + (f" endpoint {f['endpoint']}" if f.get("endpoint") else "") for f in shown)])
