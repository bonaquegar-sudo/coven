"""Plan/questions, Fixer approval, publish to a git remote, accepted risks, diff-only scans, confidence/compliance, CI CLI.
Run: python test_features.py   (fake LLM, local bare git remote: no network except OSV)"""
import subprocess
import sys
import time
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

import app.graph as graph
from app import appsec_tools as appsec
from app.cli import main as cli
from app.main import app
from app.tools import Workspace
from test_smoke import Reply, call, run

AWS = "AKIAABCDEFGHIJKLMNOP"


async def fake_chat(cfg, messages, tools=None):
    system, last = messages[0]["content"], messages[-1]
    if "Fase de planificación" in system:
        if "Ya tienes las respuestas" in system:
            return Reply(content="ROUTE: CodeScout, Fixer\nPUBLICAR: sí\n## Plan\n1. Mapa\n2. Corregir", tool_calls=None)
        return Reply(content="PREGUNTAS\n1. ¿Solo auditar o también corregir? (auditar / corregir)", tool_calls=None)
    if last["role"] != "tool" and "Eres Fixer" in system:
        return call("apply_patch", path="app.py", old="x = 1", new="x = 2")
    return Reply(content="ok", tool_calls=None)


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


graph.chat = fake_chat
client = TestClient(app)
with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as remote:
    repo = Path(d)
    git(remote, "init", "--bare", "-q")
    git(d, "init", "-q", "-b", "main")
    git(d, "config", "user.email", "dev@example.com")
    git(d, "config", "user.name", "Dev")
    (repo / "app.py").write_text("x = 1\n")
    (repo / "config.py").write_text(f"KEY = '{AWS}'\n")
    git(d, "add", ".")
    git(d, "commit", "-qm", "init")
    git(d, "remote", "add", "origin", remote)

    with client.websocket_connect("/ws/session") as ws:
        start = {"type": "start", "project_path": d, "llm": {"provider": "anthropic", "api_key": "k"},
                 "plan": True, "approve_fixes": True}
        # 1) questions first, nobody else runs
        ev = run(ws, {**start, "request": "Haz una auditoría, arregla lo que encuentres y súbelo a GitHub"})
        msgs = [e for e in ev if e["type"] == "message"]
        assert [m["author"] for m in msgs] == ["user", "TechLead", "TechLead"] and msgs[-1]["kind"] == "questions", msgs
        # 2) answer -> plan -> CodeScout -> approval gate (secret in config.py is a candidate)
        ev = run(ws, {"type": "user_message", "content": "corregir"})
        msgs = [e for e in ev if e["type"] == "message"]
        assert [(m["author"], m.get("kind")) for m in msgs] == [("user", None), ("TechLead", "plan"), ("CodeScout", None),
                                                                 ("TechLead", "approval")], msgs
        assert "rama nueva" in msgs[1]["content"] and "COVEN-" in msgs[-1]["content"]
        assert (repo / "app.py").read_text() == "x = 1\n", "no code touched before approval"
        # 3) approve -> Fixer patches -> QARunner re-verifies -> final report + branch pushed
        ev = run(ws, {"type": "user_message", "content": "aprobar"})
        msgs = [e for e in ev if e["type"] == "message"]
        assert [m["author"] for m in msgs] == ["user", "TechLead", "Fixer", "QARunner", "TechLead"], msgs
        final = msgs[-1]
        assert final.get("final") and "**GitHub:**" in final["content"] and "coven/" in final["content"], final["content"]
        branch = git(d, "rev-parse", "--abbrev-ref", "HEAD")
        assert branch.startswith("coven/") and git(remote, "branch", "--list", branch), branch
        assert git(d, "log", "-1", "--format=%an") == "Dev" and git(d, "status", "--porcelain") == ""
        assert git(d, "show", "--stat", "--format=", "HEAD").count("|") == 1  # only Coven's file

        # 4) accept a risk from the UI; it stays accepted in a later scan of the project
        w0 = Workspace(d)
        w0.scan_secrets()
        fid = next(f["id"] for f in w0.findings.items.values() if f["file_path"] == "config.py")
        ws.send_json({"type": "accept_risk", "id": fid, "reason": "clave de ejemplo para tests"})
        assert any(f["status"] == "ACCEPTED_RISK" for f in ws.receive_json()["findings"])

    w1 = Workspace(d)
    w1.scan_secrets()
    f = next(f for f in w1.findings.items.values() if f["file_path"] == "config.py")
    assert f["status"] == "ACCEPTED_RISK" and f["accepted_reason"] == "clave de ejemplo para tests"
    assert "COVEN" not in w1.list_findings().split("\n", 1)[-1]
    w1.findings.reopen(f["id"])
    assert Workspace(d).findings.accepted == {}

    # skip: answering "saltar" drops Fixer and nothing is patched
    git(d, "switch", "-q", "main")
    with client.websocket_connect("/ws/session") as ws:
        run(ws, {**start, "request": "audita y corrige"})
        run(ws, {"type": "user_message", "content": "corregir"})
        ev = run(ws, {"type": "user_message", "content": "saltar"})
        assert "Fixer" not in [e.get("author") for e in ev if e["type"] == "message"]
        assert (repo / "app.py").read_text() == "x = 1\n"

    # diff-only: only the uncommitted file produces findings
    (repo / "new.py").write_text(f"TOKEN = '{AWS}'\n")
    w2 = Workspace(d)
    assert "new.py" in w2.limit_to_changes("HEAD")
    w2.scan_secrets()
    assert [f["file_path"] for f in w2.findings.items.values()] == ["new.py"]

    # CI CLI: blocking finding -> exit 1; only low-confidence noise or nothing changed -> 0
    assert cli([d, "--out", str(repo / ".coven" / "r.md")]) == 1
    assert "## Hallazgos abiertos" in (repo / ".coven" / "r.md").read_text(encoding="utf-8")
    (repo / "new.py").unlink()
    assert cli([d, "--diff-base", "HEAD"]) == 0

    # push refused: back on the original branch, change uncommitted and still reviewable, no leftover branch
    git(d, "switch", "-q", "main")
    git(d, "remote", "set-url", "origin", str(repo / "no-such-remote"))
    w3 = Workspace(d)
    w3.apply_patch("app.py", "x = 1", "x = 3")
    try:
        w3.git_publish("t", "b")
        raise AssertionError("publish should fail")
    except ValueError as e:
        assert "push" in str(e)
    assert git(d, "rev-parse", "--abbrev-ref", "HEAD") == "main" and not git(d, "branch", "--list", "coven/t-*")
    assert "app.py" in git(d, "status", "--porcelain") and "app.py" in w3.originals

# "no lo subas" never publishes, even when the request mentions GitHub
assert not graph.wants_publish("Audita y corrige. No lo subas a GitHub, deja los cambios en local.")
assert not graph.wants_publish("sin subir nada, solo audita")
assert graph.wants_publish("arregla y súbelo a GitHub") and graph.wants_publish("corrige y abre una PR")

# confidence and compliance mapping
assert appsec.confidence({"source": "osv"}) == "alta" and appsec.confidence({"source": "sast"}) == "baja"
assert appsec.confidence({"source": "sast", "status": "CONFIRMED_BY_QA"}) == "alta"
assert appsec.compliance({"standard": "OWASP A03:2021 / CWE-89"})[2] == "PCI DSS 6.2.4"
assert appsec.compliance({"standard": "CWE-798", "source": "secrets"})[1] == "ISO 27001 A.5.17"
assert appsec.compliance({"source": "osv", "standard": "CVE-2024-1"})[1] == "ISO 27001 A.8.8"
assert appsec.compliance({"standard": "CWE-639"})[0].startswith("ASVS V4")
assert appsec.fingerprint("sast:eval:src/a.ts:42") == "sast:eval:src/a.ts"
# packaged backend: a timed-out command is killed with its whole tree (wrappers like Git for Windows' cmd\git.exe)
if sys.platform == "win32":
    import server  # noqa: F401  applies the win32 Popen patches
    _t = time.time()
    try:
        subprocess.run([sys.executable, "-c", f"import subprocess; subprocess.run([r'{sys.executable}', '-c', 'import time; time.sleep(60)'])"],
                       capture_output=True, timeout=2)
    except subprocess.TimeoutExpired:
        pass
    assert time.time() - _t < 15, "timeout left the grandchild holding the pipes"
print("features OK")
