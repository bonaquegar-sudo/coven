"""CovenState and the 5-agent LangGraph. Nodes stream UI events through LangGraph's custom stream writer."""
import json
import operator
import re
import time
import uuid
from typing import Annotated, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import MemorySaver
from langgraph.config import get_stream_writer
from langgraph.graph import END, START, StateGraph

from .appsec_tools import SecurityFinding, _vkey
from .llm import LLMConfig, chat
from .prompts import DEFAULT_TASKS, PROMPTS, ROUTER
from .tools import Workspace, tool_schemas

CHANNELS = ["general", "arquitectura", "auditoria", "tests", "parches"]
# agent -> (channel it posts to, tools it may call)
AGENTS = {
    "CodeScout": ("arquitectura", ["list_directory", "read_file", "find_files", "scan_dependencies_osv", "scan_secrets",
                                   "map_api_routes"]),
    "Reviewer": ("auditoria", ["read_file", "search_code", "list_directory", "find_files", "run_sast", "report_finding",
                               "list_findings"]),
    "QARunner": ("tests", ["run_tests", "read_file", "list_directory", "find_files", "verify_endpoint_security",
                           "scan_dependencies_osv", "scan_secrets", "run_sast", "set_finding_status", "list_findings"]),
    "Fixer": ("parches", ["read_file", "search_code", "apply_patch", "write_file", "get_git_diff", "set_finding_status",
                          "list_findings"]),
}
# scanners each agent runs deterministically before its LLM turn; results go into its task
PRE_RUN = {"CodeScout": ["scan_dependencies_osv", "scan_secrets", "map_api_routes"], "Reviewer": ["run_sast"]}
APPSEC_TOOLS = {"scan_dependencies_osv", "scan_secrets", "run_sast", "map_api_routes", "verify_endpoint_security",
                "report_finding", "set_finding_status"}
SCAN = ["CodeScout", "Reviewer", "QARunner", "Fixer"]
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
CLOSED = {"FALSE_POSITIVE", "VERIFIED"}
MAX_TURNS = 12  # agent turns per user request; TechLead wraps up when hit
MAX_STEPS = 10  # tool-calling rounds per agent turn


class CovenState(TypedDict, total=False):
    project_path: str
    target_url: str        # optional running app the team can reference
    channels: list[str]
    messages: Annotated[list[dict], operator.add]  # every message, each tagged with its channel
    repo_map: str          # CodeScout's map
    security_findings: list[SecurityFinding]  # mirror of the workspace registry after each agent turn
    diff: str              # Fixer's current diff
    request: str | None    # latest developer message being handled
    routed: bool
    pending: list[str]     # agent queue decided by TechLead
    turns: int
    started: bool


def emit(event: dict):
    get_stream_writer()(event)


def post(channel: str, author: str, content: str) -> dict:
    msg = {"id": uuid.uuid4().hex, "channel": channel, "author": author, "content": content, "ts": time.time()}
    emit({"type": "message", **msg})
    return msg


def status(agent: str, state: str, detail: str = ""):
    emit({"type": "status", "agent": agent, "status": state, "detail": detail})


async def ask(agent: str, cfg: LLMConfig, msgs: list[dict], schemas: list[dict] | None = None):
    """chat() + one usage event per call, so the UI can show what each agent costs."""
    reply = await chat(cfg, msgs, schemas)
    if usage := getattr(reply, "usage", None):
        emit({"type": "usage", "agent": agent, **usage})
    return reply


def context(state: CovenState) -> str:
    parts = [f"Proyecto: {state['project_path']}"]
    if state.get("target_url"):
        parts.append(f"Target URL (app en ejecución, sandbox): {state['target_url']}")
    if state.get("repo_map"):
        parts.append("## Mapa técnico (CodeScout)\n" + state["repo_map"])
    if findings := state.get("security_findings"):
        # open, non-LOW first by severity; LOW/closed only counted (the full registry is in the UI and list_findings)
        open_ = sorted((f for f in findings if f["status"] not in CLOSED and f["severity"] != "LOW"),
                       key=lambda f: SEV_ORDER.get(f["severity"], 9))
        head = (f"{len(findings)} en total; {len(open_)} abiertos no-LOW"
                + (f", se muestran {min(len(open_), 60)}" if len(open_) > 60 else ""))
        parts.append(f"## Hallazgos de seguridad ({head})\n" + "\n".join(
            f"{f['id']} [{f['severity']}][{f['status']}] {f['title'][:90]} — {f['file_path']}:{f['line_number']}"
            + (f" endpoint {f['endpoint']}" if f.get("endpoint") else "") for f in open_[:60]))
    if state.get("diff") and state["diff"] != "(sin cambios)":
        parts.append(f"## Diff actual (Fixer)\n```diff\n{state['diff'][:6000]}\n```")
    recent = state.get("messages", [])[-4:]
    if recent:
        parts.append("## Conversación reciente\n" + "\n\n".join(
            f"[#{m['channel']}] {m['author']}: {m['content'][:1200]}" for m in recent))
    if state.get("request"):
        parts.append("## Petición del desarrollador\n" + state["request"])
    return "\n\n".join(parts)


async def use_tool(agent: str, tool: str, args: dict, ws: Workspace) -> str:
    """Run one tool for an agent, streaming tool_execution / security_findings / test_output events."""
    traced = tool in APPSEC_TOOLS
    call_id, t0 = uuid.uuid4().hex, time.monotonic()
    if traced:
        emit({"type": "tool_execution", "call_id": call_id, "agent": agent, "tool": tool, "args": args, "status": "running"})
    out = await ws.call(tool, args, agent)
    if traced:
        emit({"type": "tool_execution", "call_id": call_id, "agent": agent, "tool": tool, "args": args,
              "status": "error" if out.startswith("ERROR") else "done", "summary": out.split("\n", 1)[0][:200],
              "output": out[:4000], "duration_ms": round((time.monotonic() - t0) * 1000)})
        emit({"type": "security_findings", "findings": list(ws.findings.items.values())})
    if tool == "run_tests":
        emit({"type": "test_output", "agent": agent, "command": args.get("command", ""), "output": out})
    return out


async def run_agent(name: str, task: str, cfg: LLMConfig, ws: Workspace) -> str:
    """Tool-calling loop for one agent turn; returns the agent's final message."""
    tools = AGENTS[name][1]
    schemas = tool_schemas(tools)
    msgs = [{"role": "system", "content": PROMPTS[name]}, {"role": "user", "content": task}]
    try:
        for _ in range(MAX_STEPS):
            status(name, "thinking")
            reply = await ask(name, cfg, msgs, schemas)
            if not reply.tool_calls:
                return reply.content or ""
            msgs.append(reply.model_dump(exclude_none=True))
            for tc in reply.tool_calls:
                tool = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                if tool in tools:
                    status(name, "tool", f"{tool}({json.dumps(args, ensure_ascii=False)[:80]})")
                    out = await use_tool(name, tool, args, ws)
                else:
                    out = f"ERROR: {tool} no está disponible para {name}"
                msgs.append({"role": "tool", "tool_call_id": tc.id, "content": out})
        msgs.append({"role": "user", "content": "Límite de herramientas alcanzado. Publica ya tu mensaje final."})
        status(name, "thinking")
        return (await ask(name, cfg, msgs, schemas)).content or ""
    finally:
        status(name, "idle")


def inventory(ws: Workspace) -> str:
    """CodeScout's tables, built from the scanners instead of written by the model: complete, exact, zero tokens."""
    items = list(ws.findings.items.values())
    deps: dict[str, list] = {}
    for f in (f for f in items if f["source"] == "osv"):
        deps.setdefault(f["title"].split(" vulnerable")[0], []).append(f)
    rows = sorted(deps.items(), key=lambda kv: min(SEV_ORDER[f["severity"]] for f in kv[1]))
    out = ["## Dependencias vulnerables", "| Paquete | Avisos | Máx. | Corrección | Ids |", "|---|---|---|---|---|"]
    out += [f"| `{pkg}` | {len(fs)} | {min((f['severity'] for f in fs), key=SEV_ORDER.get)} | "
            f"{max((f.get('fix', '') for f in fs), key=lambda x: _vkey(x.rpartition(' a ')[2]))} | {', '.join(f['id'] for f in fs)} |" for pkg, fs in rows] or ["| — | 0 | | | |"]
    secrets = [f for f in items if f["source"] == "secrets"]
    shown = sorted((f for f in secrets if f["severity"] != "LOW"), key=lambda f: SEV_ORDER[f["severity"]])
    out += ["", "## Secretos expuestos", "| Id | Tipo | Ubicación | Sev. |", "|---|---|---|---|"]
    out += [f"| {f['id']} | {f['title'].removeprefix('Secreto expuesto: ')} | `{f['file_path']}:{f['line_number']}` | "
            f"{f['severity']} |" for f in shown[:40]] or ["| — | | | |"]
    if len(secrets) > len(shown[:40]):
        out.append(f"\n+{len(secrets) - len(shown[:40])} más (LOW: código de test o ignorados por git) en el inspector.")
    open_routes = [r for r in ws.routes if not r["auth"]]
    out += ["", f"## Rutas API sin autenticación ({len(open_routes)} de {len(ws.routes)})",
            "| Método | Ruta | Archivo |", "|---|---|---|"]
    out += [f"| {r['method']} | `{r['path']}` | `{r['file']}:{r['line']}` |" for r in open_routes[:40]] or ["| — | | |"]
    if len(open_routes) > 40:
        out.append(f"\n+{len(open_routes) - 40} rutas sin auth más (lista completa: map_api_routes).")
    return "\n".join(out)


def agent_node(name: str):
    async def node(state: CovenState, config: RunnableConfig):
        cfg, ws = config["configurable"]["llm"], config["configurable"]["workspace"]
        task = f"{state.get('request') or DEFAULT_TASKS[name]}\n\n{context(state)}"
        if PRE_RUN.get(name):
            outs = []
            for tool in PRE_RUN[name]:
                status(name, "tool", tool)
                outs.append(f"### {tool}\n{await use_tool(name, tool, {}, ws)}")
            task += "\n\n## Resultados de herramientas (ya ejecutadas por ti)\n" + "\n\n".join(outs)
        text = await run_agent(name, task, cfg, ws) or "(sin respuesta)"
        update: CovenState = {"turns": state.get("turns", 0) + 1, "pending": state.get("pending", [])[1:],
                              "security_findings": [dict(f) for f in ws.findings.items.values()]}
        if name == "CodeScout":
            update["repo_map"] = text  # the short LLM part; the tables below are already in the registry
            text += "\n\n" + inventory(ws)
        update["messages"] = [post(AGENTS[name][0], name, text)]
        if name == "Fixer":
            update["diff"] = ws.get_git_diff()
            emit({"type": "diff", "diff": update["diff"], "files": list(ws.originals)})
            if update["diff"] != "(sin cambios)" and "QARunner" not in update["pending"]:
                update["pending"] = ["QARunner", *update["pending"]]
        return update
    return node


async def lead_say(cfg: LLMConfig, instruction: str, state: CovenState) -> str:
    status("TechLead", "thinking")
    try:
        reply = await ask("TechLead", cfg, [{"role": "system", "content": PROMPTS["TechLead"] + "\n\n" + instruction},
                                 {"role": "user", "content": context(state)}])
        return reply.content or ""
    finally:
        status("TechLead", "idle")


async def techlead(state: CovenState, config: RunnableConfig):
    cfg = config["configurable"]["llm"]
    boot: CovenState = {}
    if not state.get("started"):
        for c in CHANNELS:
            emit({"type": "channel_created", "channel": c})
        plan = ("\n\nVoy directo con tu petición." if state.get("request") else
                "\n\n@CodeScout arranca el escaneo en #arquitectura; después @Reviewer audita en #auditoria, "
                "@QARunner verifica en local en #tests y @Fixer corrige lo confirmado en #parches.")
        msg = post("general", "TechLead", f"Sesión iniciada sobre `{state['project_path']}`. Canales: "
                   + ", ".join(f"#{c}" for c in CHANNELS) + "." + plan)
        boot = {"started": True, "channels": CHANNELS, "turns": 0, "messages": [msg]}
        if not state.get("request"):
            return {**boot, "pending": SCAN}
        state = {**state, "messages": [*state.get("messages", []), msg]}

    if state.get("request") and not state.get("routed"):
        names = list(dict.fromkeys(n for n in re.findall(r"@(\w+)", state["request"]) if n in AGENTS))
        if names:
            reply = "Recibido. " + ", ".join(f"@{n}" for n in names) + (", os toca." if len(names) > 1 else ", te toca.")
        else:
            text = await lead_say(cfg, ROUTER, state)
            first, _, rest = text.partition("\n")
            if first.strip().startswith("ROUTE:"):
                names = [n for n in re.findall(r"\w+", first.split(":", 1)[1]) if n in AGENTS]
            reply = rest.strip() or text
        return {**boot, "routed": True, "pending": names, "turns": 0,
                "messages": [*boot.get("messages", []), post("general", "TechLead", reply)]}

    over = state.get("turns", 0) >= MAX_TURNS
    text = await lead_say(cfg, "Redacta el resumen final para #general (estado, riesgos principales, siguiente paso)."
                          + (" Se alcanzó el límite de turnos: indica que el equipo se detuvo." if over else ""), state)
    return {"pending": [], "request": None, "messages": [post("general", "TechLead", text)]}


def next_agent(state: CovenState) -> str:
    pending = state.get("pending") or []
    return pending[0] if pending and state.get("turns", 0) < MAX_TURNS else "TechLead"


def build_graph():
    g = StateGraph(CovenState)
    g.add_node("TechLead", techlead)
    for name in AGENTS:
        g.add_node(name, agent_node(name))
        g.add_conditional_edges(name, next_agent, [*AGENTS, "TechLead"])
    g.add_edge(START, "TechLead")
    g.add_conditional_edges("TechLead", lambda s: (s.get("pending") or [END])[0], [*AGENTS, END])
    return g.compile(checkpointer=MemorySaver())  # ponytail: in-memory sessions; SqliteSaver to survive restarts
