"""End-to-end check with a fake LLM: scan pipeline, @Fixer patch -> QARunner, revert, sandboxing.
Run: python test_smoke.py"""
import asyncio
import json
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.graph as graph
from app.main import app
from app.tools import Workspace


class Reply(SimpleNamespace):
    def model_dump(self, **_):
        return {"role": "assistant", "content": self.content, "tool_calls": [
            {"id": t.id, "type": "function", "function": {"name": t.function.name, "arguments": t.function.arguments}}
            for t in self.tool_calls or []]}


def call(name, **args):
    return Reply(content=None, tool_calls=[SimpleNamespace(id="t1", function=SimpleNamespace(name=name, arguments=json.dumps(args)))])


NUDGED = []  # Fixer patched without set_finding_status -> the graph reminds it once


async def fake_chat(cfg, messages, tools=None):
    system, last = messages[0]["content"], messages[-1]
    if "no has marcado" in str(last.get("content")):
        NUDGED.append(1)
    if "Decide qué agentes" in system:
        return Reply(content="ROUTE: none\nHola", tool_calls=None)
    if last["role"] != "tool":
        if "Eres CodeScout" in system:
            return call("list_directory", path=".")
        if "Eres Fixer" in system:
            return call("apply_patch", path="app.py", old="x = 1", new="x = 2")
        if "Eres QARunner" in system:
            return call("read_file", path="../../etc/passwd")
    if "Eres Reviewer" in system:
        return Reply(content="Reporte OWASP", tool_calls=None)
    return Reply(content=f"ok: {last['content'][:40]}", tool_calls=None)


def run(ws, payload):
    ws.send_json(payload)
    events = []
    while (e := ws.receive_json())["type"] != "done":
        assert e["type"] != "error", e
        events.append(e)
    return events


graph.chat = fake_chat
with tempfile.TemporaryDirectory() as d:
    Path(d, "app.py").write_text("x = 1\n")
    client = TestClient(app).__enter__()  # one event loop for every socket, as under uvicorn (sessions outlive sockets)
    with client.websocket_connect("/ws/session") as ws:
        ev = run(ws, {"type": "start", "project_path": d, "llm": {"provider": "anthropic", "api_key": "k"}})
        authors = [e["author"] for e in ev if e["type"] == "message"]
        assert authors == ["TechLead", "CodeScout", "Reviewer", "QARunner", "Fixer", "QARunner", "TechLead"], authors  # Fixer patched -> QA re-verifies
        assert sum(e["type"] == "channel_created" for e in ev) == 5
        assert len(NUDGED) == 1, NUDGED
        tools = [(e["agent"], e["tool"], e["status"]) for e in ev if e["type"] == "tool_execution"]
        assert ("CodeScout", "scan_dependencies_osv", "done") in tools and ("Reviewer", "run_sast", "done") in tools, tools
        assert next(e for e in ev if e["type"] == "security_findings")["findings"] == []  # app.py has nothing to report
        assert next(e for e in ev if e.get("author") == "Reviewer")["channel"] == "auditoria"

        ev = run(ws, {"type": "user_message", "content": "@Fixer cambia x"})
        authors = [e["author"] for e in ev if e["type"] == "message"]
        assert authors == ["user", "TechLead", "Fixer", "QARunner", "TechLead"], authors
        assert "+x = 2" in next(e for e in ev if e["type"] == "diff")["diff"]
        assert Path(d, "app.py").read_text() == "x = 2\n"

        ev = run(ws, {"type": "user_message", "content": "¿qué tal?"})
        assert [e["author"] for e in ev if e["type"] == "message"] == ["user", "TechLead"]

        ws.send_json({"type": "revert", "path": "app.py"})
        assert ws.receive_json()["diff"] == "(sin cambios)"
        assert Path(d, "app.py").read_text() == "x = 1\n"

        run(ws, {"type": "user_message", "content": "@Fixer cambia x"})
        ws.send_json({"type": "accept", "path": "app.py"})
        assert ws.receive_json()["diff"] == "(sin cambios)"
        assert Path(d, "app.py").read_text() == "x = 2\n"

    # start with a request: no scan, TechLead routes straight to the named agent
    with client.websocket_connect("/ws/session") as ws:
        ev = run(ws, {"type": "start", "project_path": d, "llm": {"provider": "anthropic", "api_key": "k"},
                      "request": "@Reviewer audita"})
        assert [e["author"] for e in ev if e["type"] == "message"] == ["user", "TechLead", "TechLead", "Reviewer", "TechLead"]

    Path(d, "package.json").write_text('{"dependencies": {"next": "1", "react": "1"}, "devDependencies": {"typescript": "5"}}')
    assert client.get("/project", params={"path": d}).json()["stack"] == ["Next.js", "TypeScript", "Python"]
    # dropped connection: the team keeps working and a new socket resumes without gaps or duplicates
    with client.websocket_connect("/ws/session") as ws:
        ws.send_json({"type": "start", "project_path": d, "llm": {"provider": "anthropic", "api_key": "k"}})
        sid = ws.receive_json()["id"]
        first = [ws.receive_json() for _ in range(3)]
    with client.websocket_connect("/ws/session") as ws:
        ws.send_json({"type": "resume", "id": sid, "since": first[-1]["seq"] + 1})
        rest = []
        while (e := ws.receive_json())["type"] != "done":
            rest.append(e)
    seqs = [e["seq"] for e in first + rest]
    assert seqs == list(range(len(seqs))), seqs
    assert [e["author"] for e in first + rest if e["type"] == "message"][-1] == "TechLead"

    # cancel: stops a run stuck on a slow model right away and the session keeps accepting messages
    async def slow_chat(cfg, messages, tools=None):
        await asyncio.sleep(60)
    graph.chat = slow_chat
    with client.websocket_connect("/ws/session") as ws:
        ws.send_json({"type": "start", "project_path": d, "llm": {"provider": "anthropic", "api_key": "k"}, "request": "audita"})
        while ws.receive_json()["type"] != "message":
            pass
        t = time.time()
        ws.send_json({"type": "cancel"})
        ev = []
        while (e := ws.receive_json())["type"] != "done":
            ev.append(e)
        assert time.time() - t < 5 and "cancelada" in ev[-1]["content"], ev
        graph.chat = fake_chat
        ev = run(ws, {"type": "user_message", "content": "¿qué tal?"})
        msgs = [e for e in ev if e["type"] == "message"]
        assert msgs[0]["author"] == "user" and msgs[-1]["content"] == "Hola", msgs  # a cut-off start may repeat its intro

    assert client.get("/project", params={"path": d + "/nope"}).status_code == 404
    assert client.get("/health").json()["sandbox"] in ("ready", "stopped", "missing")

    w = Workspace(d)
    assert asyncio.run(w.call("read_file", {"path": "../outside.txt"})).startswith("ERROR: ruta fuera")
    assert asyncio.run(w.call("run_tests", {"command": "rm -rf /"})).startswith("ERROR: comando no permitido")
    assert asyncio.run(w.call("verify_endpoint_security", {"base_url": "http://example.com", "endpoint": "/"})).startswith("ERROR: solo se permiten")

    try:
        with client.websocket_connect("/ws/session", headers={"origin": "https://evil.example"}):
            raise AssertionError("foreign origin accepted")
    except Exception as e:
        assert "foreign origin" not in str(e)
print("smoke OK")
