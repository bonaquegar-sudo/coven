"""FastAPI server: one WebSocket per Coven session, streaming every agent event to the UI.

Client -> server:
  {"type": "start", "project_path": "...", "llm": {...}, "target_url"?: "...", "request"?: "...",
   "plan"?: bool, "approve_fixes"?: bool, "only_changes"?: bool, "diff_base"?: "origin/main"}
    (plan: TechLead asks questions / posts a plan first; approve_fixes: pause before Fixer's patching flow;
     only_changes: findings only in files changed per git; with a request the scan is skipped unless the plan routes it)
  {"type": "user_message", "channel": "general", "content": "@Fixer ..."}
  {"type": "revert" | "accept", "path": "src/x.ts"}
  {"type": "accept_risk", "id": "COVEN-012", "reason": "..."} | {"type": "reopen", "id": "COVEN-012"}
  {"type": "publish", "title"?: "...", "body"?: "..."}   (new branch + commit + push + PR with Coven's changes)
Server -> client:
  channel_created | message | status | security_findings | tool_execution | test_output | diff | usage | error | done
    (usage: tokens of one LLM call — input, cache_write, cache_read, output, cost — tagged with the agent)
"""
import asyncio
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from . import subscriptions
from .graph import build_graph
from .llm import PROVIDERS, LLMConfig
from .tools import Workspace, detect_stack, docker_status

# A browser page on any site can open ws://localhost; only our own UI may drive agents that touch files.
ALLOWED_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173", "tauri://localhost", "http://tauri.localhost"}

app = FastAPI(title="Coven")
app.add_middleware(CORSMiddleware, allow_origins=list(ALLOWED_ORIGINS), allow_methods=["GET"])
graph = build_graph()


def user_message(content: str, channel: str = "general") -> dict:
    return {"id": uuid.uuid4().hex, "channel": channel, "author": "user", "content": content, "ts": time.time()}


@app.get("/health")
def health():
    return {"ok": True, "sandbox": docker_status()}


@app.get("/project")
def project(path: str):
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise HTTPException(404, "No existe el directorio")
    return {"path": str(root), "name": root.name, "stack": detect_stack(root)}


@app.get("/providers")
def providers():
    subs = subscriptions.status()
    return {name: {"default_model": model, **({"subscription": True, **subs[name]} if name in subs else {})}
            for name, (_, model) in PROVIDERS.items()}


@app.websocket("/ws/session")
async def session(ws: WebSocket):
    origin = ws.headers.get("origin")
    if origin and origin not in ALLOWED_ORIGINS:
        await ws.close(code=1008)
        return
    await ws.accept()
    run_config = None
    try:
        while True:
            data = await ws.receive_json()
            kind = data.get("type")
            try:
                if kind == "start":
                    run_config = {"recursion_limit": 100, "configurable": {
                        "thread_id": uuid.uuid4().hex,
                        "llm": LLMConfig(**data.get("llm", {})),
                        "workspace": Workspace(data["project_path"]),
                    }}
                    workspace = run_config["configurable"]["workspace"]
                    if data.get("only_changes"):
                        workspace.limit_to_changes(data.get("diff_base") or "")
                    inputs = {"project_path": str(workspace.root), "target_url": data.get("target_url") or "",
                              "plan": bool(data.get("plan")), "approve_fixes": bool(data.get("approve_fixes"))}
                    if data.get("request"):
                        msg = user_message(data["request"])
                        await ws.send_json({"type": "message", **msg})
                        inputs |= {"messages": [msg], "request": data["request"], "routed": False, "turns": 0}
                elif run_config is None:
                    raise ValueError("Envía primero {'type': 'start'}")
                elif kind == "user_message":
                    msg = user_message(data["content"], data.get("channel", "general"))
                    await ws.send_json({"type": "message", **msg})
                    inputs = {"messages": [msg], "request": data["content"], "routed": False, "turns": 0}
                elif kind in ("revert", "accept"):
                    workspace = run_config["configurable"]["workspace"]
                    if kind == "revert":
                        workspace.revert(data["path"])
                    else:  # keep the change on disk, stop tracking it
                        workspace.originals.pop(data["path"], None)
                    await ws.send_json({"type": "diff", "diff": workspace.get_git_diff(), "files": list(workspace.originals)})
                    continue
                elif kind in ("accept_risk", "reopen"):
                    findings = run_config["configurable"]["workspace"].findings
                    findings.accept_risk(data["id"], data.get("reason", "")) if kind == "accept_risk" else findings.reopen(data["id"])
                    await ws.send_json({"type": "security_findings", "findings": list(findings.items.values())})
                    continue
                elif kind == "publish":
                    workspace = run_config["configurable"]["workspace"]
                    result = await asyncio.to_thread(workspace.git_publish, data.get("title") or "Coven: correcciones de seguridad",
                                                     data.get("body") or "Cambios revisados en el panel Diff de Coven.")
                    await ws.send_json({"type": "message", **user_message(f"**GitHub:** {result}") | {"author": "system"}})
                    await ws.send_json({"type": "diff", "diff": workspace.get_git_diff(), "files": list(workspace.originals)})
                    continue
                else:
                    raise ValueError(f"Tipo de mensaje desconocido: {kind}")
                # ponytail: messages sent while the team is working queue up until this run ends.
                async for event in graph.astream(inputs, run_config, stream_mode="custom"):
                    await ws.send_json(event)
            except WebSocketDisconnect:
                raise
            except Exception as e:
                await ws.send_json({"type": "error", "message": f"{type(e).__name__}: {e}"})
            await ws.send_json({"type": "done"})
    except WebSocketDisconnect:
        pass
