"""CovenState and the 5-agent LangGraph. Nodes stream UI events through LangGraph's custom stream writer."""
import asyncio
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
from .prompts import DEFAULT_TASKS, FULL_SCAN, PLANNER, PLANNER_FINAL, PROMPTS, ROUTER
from .tools import Workspace, tool_schemas

CHANNELS = ["general", "arquitectura", "auditoria", "tests", "parches"]
# agent -> (channel it posts to, tools it may call)
AGENTS = {
    "CodeScout": ("arquitectura", ["list_directory", "read_file", "find_files", "scan_dependencies_osv", "scan_secrets",
                                   "map_api_routes"]),
    "Reviewer": ("auditoria", ["read_file", "search_code", "list_directory", "find_files", "run_sast", "report_finding",
                               "list_findings"]),
    "QARunner": ("tests", ["run_tests", "run_command", "run_code", "read_file", "list_directory", "find_files", "verify_endpoint_security",
                           "scan_dependencies_osv", "scan_secrets", "run_sast", "set_finding_status", "list_findings"]),
    "Fixer": ("parches", ["read_file", "search_code", "apply_patch", "write_file", "get_git_diff", "set_finding_status",
                          "run_command", "run_code",
                          "list_findings"]),
}
# scanners each agent runs deterministically before its LLM turn; results go into its task
PRE_RUN = {"CodeScout": ["scan_dependencies_osv", "scan_secrets", "map_api_routes"], "Reviewer": ["run_sast"]}
APPSEC_TOOLS = {"scan_dependencies_osv", "scan_secrets", "run_sast", "map_api_routes", "verify_endpoint_security",
                "report_finding", "set_finding_status"}
SCAN = ["CodeScout", "Reviewer", "QARunner", "Fixer"]
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
CLOSED = {"FALSE_POSITIVE", "VERIFIED", "ACCEPTED_RISK"}
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
    plan: bool             # ask questions / post a plan before the first request (the UI turns it on)
    approve_fixes: bool    # pause before Fixer's patching flow until the developer approves
    goal: str              # the first request (+ answers to TechLead's questions) the plan was made for
    awaiting: str | None   # "answers" | "fixer": the run ended waiting for the developer
    queued: list[str]      # agents to resume with after an approval
    approved: bool
    publish: bool          # branch + commit + push + PR at the end


def emit(event: dict):
    get_stream_writer()(event)


def post(channel: str, author: str, content: str, **extra) -> dict:
    msg = {"id": uuid.uuid4().hex, "channel": channel, "author": author, "content": content, "ts": time.time(), **extra}
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
    if tool in ("run_tests", "run_command", "run_code"):
        command = args.get("command") or f"{args.get('language', '')} script ({len(str(args.get('code', '')).splitlines())} líneas)"
        emit({"type": "test_output", "agent": agent, "command": command, "output": out})
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


def report(state: CovenState) -> str:
    """Final report appended to TechLead's summary: exact counts from the registry, not the model's recollection."""
    findings = state.get("security_findings") or []
    cols = ["DETECTED", "CONFIRMED_BY_QA", "PATCHED", "VERIFIED", "FALSE_POSITIVE"]
    out = ["## Informe", "| Severidad | Detectado | Confirmado | Parcheado | Verificado | Falso + |", "|---|---|---|---|---|---|"]
    for sev in SEV_ORDER:
        row = [sum(f["severity"] == sev and f["status"] == c for f in findings) for c in cols]
        if any(row):
            out.append(f"| {sev} | " + " | ".join(str(n) for n in row) + " |")
    files = re.findall(r"^\+\+\+ b/(.+)$", state.get("diff") or "", re.M)
    out.append(f"\n{len(findings)} hallazgos en total. "
               + (f"Archivos modificados por Fixer: {', '.join(f'`{f}`' for f in files)}." if files else "Sin cambios en el código."))
    return "\n".join(out)


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
        request = state.get("request")
        if name == "Fixer" and request and not re.search(r"COVEN-\d+", request):
            request += "\n\n" + DEFAULT_TASKS["Fixer"]  # no specific ids → this is the scan's patching flow
        task = f"{request or DEFAULT_TASKS[name]}\n\n{context(state)}"
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


PUBLISH_ASK = re.compile(r"pull request|\bPR\b|github|git push|\b(sube|subir|súbelo|subelo|publica|publicar)\b[^.\n]{0,40}"
                         r"\b(git|repo|repositorio|rama|remoto|cambios)\b", re.I)
YES = re.compile(r"^\s*(s[ií]|ok|vale|adelante|aprob|apruebo|dale|correcto|perfecto)\b", re.I)
SKIP = re.compile(r"^\s*(no\b|salta|saltar|cancel|omit)", re.I)
COVEN_ID = re.compile(r"COVEN-\d+", re.I)


def needs_approval(state: CovenState) -> bool:
    """Fixer's open-ended patching flow waits for a click; a request naming exact ids is already the approval."""
    return bool(state.get("approve_fixes") and not state.get("approved") and not COVEN_ID.search(state.get("request") or ""))


def fixer_candidates(state: CovenState) -> list[dict]:
    """What Fixer's patching flow will most likely take (same rule as its task), shown before approving."""
    rank = {"CONFIRMED_BY_QA": 0, "DETECTED": 1}
    items = [f for f in state.get("security_findings") or [] if f["status"] in rank and (
        f["status"] == "CONFIRMED_BY_QA" or (f["severity"] in ("CRITICAL", "HIGH") and f.get("confidence") != "baja"
                                             and (f["source"] != "osv" or "Sin versión" not in f.get("fix", ""))))]
    return sorted(items, key=lambda f: (rank[f["status"]], SEV_ORDER.get(f["severity"], 9)))[:5]


async def planning(state: CovenState, cfg: LLMConfig, final: bool = False) -> CovenState:
    """Questions first if something essential is missing, then a plan with the agent route; nobody touches code before."""
    text = await lead_say(cfg, PLANNER + (PLANNER_FINAL if final else ""), {**state, "request": state["goal"]})
    route = re.search(r"^\W*ROUTE:\s*(.*)$", text, re.M)
    if not route and not final:
        body = re.sub(r"^\W*PREGUNTAS\W*$", "", text, flags=re.M).strip()
        msg = post("general", "TechLead", "Antes de empezar necesito aclarar esto:\n\n" + body, kind="questions")
        return {"awaiting": "answers", "pending": [], "routed": True, "goal": state["goal"], "messages": [msg]}
    names = list(dict.fromkeys(n for n in re.findall(r"\w+", route.group(1)) if n in AGENTS)) if route else []
    publish = bool(PUBLISH_ASK.search(state["goal"]) or re.search(r"^\W*PUBLICAR:\W*s[ií]", text, re.M | re.I))
    body = re.sub(r"^\W*(ROUTE|PUBLICAR):.*$", "", text, flags=re.M).strip()
    msg = post("general", "TechLead", body + ("\n\nAl terminar subiré los cambios a una rama nueva y abriré la PR." if publish else ""),
               kind="plan")
    return {"awaiting": None, "routed": True, "pending": names or SCAN, "turns": 0, "goal": state["goal"],
            "request": state["goal"], "publish": publish, "approved": False, "messages": [msg]}


async def techlead(state: CovenState, config: RunnableConfig):
    cfg, ws = config["configurable"]["llm"], config["configurable"]["workspace"]
    boot: CovenState = {}
    if not state.get("started"):
        for c in CHANNELS:
            emit({"type": "channel_created", "channel": c})
        scope = (f" Alcance: solo los {len(ws.findings.only)} archivos cambiados según git."
                 if ws.findings.only is not None else "")
        plan = ("\n\nAntes de empezar preparo el plan." if state.get("plan") else
                "\n\nVoy directo con tu petición." if state.get("request") else
                "\n\n@CodeScout arranca el escaneo en #arquitectura; después @Reviewer audita en #auditoria, "
                "@QARunner verifica en local en #tests y @Fixer corrige lo confirmado en #parches.")
        msg = post("general", "TechLead", f"Sesión iniciada sobre `{state['project_path']}`. Canales: "
                   + ", ".join(f"#{c}" for c in CHANNELS) + "." + scope + plan)
        boot = {"started": True, "channels": CHANNELS, "turns": 0, "messages": [msg]}
        state = {**state, "messages": [*state.get("messages", []), msg]}
        if state.get("plan"):
            upd = await planning({**state, "goal": state.get("request") or FULL_SCAN}, cfg)
            return {**boot, **upd, "messages": [msg, *upd["messages"]]}
        if not state.get("request"):
            return {**boot, "pending": SCAN, "publish": False}
        boot["publish"] = bool(PUBLISH_ASK.search(state["request"]))

    # the run ended waiting for the developer; this message is their answer
    if state.get("awaiting") == "answers" and state.get("request"):
        return await planning({**state, "goal": f"{state['goal']}\n\nRespuestas del desarrollador:\n{state['request']}"},
                              cfg, final=True)
    if state.get("awaiting") == "fixer" and state.get("request"):
        reply, queued = state["request"].strip(), state.get("queued") or []
        if SKIP.match(reply):
            msg = post("general", "TechLead", "De acuerdo: @Fixer no tocará el código; sigo con el resto del plan.")
            return {"awaiting": None, "routed": True, "request": state.get("goal"), "approved": False,
                    "pending": [n for n in queued if n != "Fixer"], "messages": [msg]}
        notes = "" if YES.match(reply) else f"\n\nIndicaciones del desarrollador para Fixer: {reply}"
        msg = post("general", "TechLead", "Aprobado. @Fixer, adelante." + (" Ten en cuenta sus indicaciones." if notes else ""))
        return {"awaiting": None, "routed": True, "approved": True, "request": (state.get("goal") or "") + notes,
                "pending": queued, "messages": [msg]}

    pending = state.get("pending") or []
    if pending[:1] == ["Fixer"] and needs_approval(state):
        if not (cands := fixer_candidates(state)):
            return {"approved": True}  # nothing to approve: Fixer runs and says so in one line
        rows = "\n".join(f"| {f['id']} | {f['severity']} | {f['title'][:70]} | `{f.get('file_path') or f.get('endpoint', '')}` |"
                         for f in cands)
        msg = post("general", "TechLead", "**Aprobación necesaria antes de tocar código.** @Fixer va a corregir, como "
                   "máximo, estos hallazgos:\n\n| Id | Sev. | Hallazgo | Ubicación |\n|---|---|---|---|\n" + rows
                   + "\n\nResponde **aprobar**, **saltar** o escribe indicaciones para @Fixer.", kind="approval")
        return {"awaiting": "fixer", "queued": pending, "pending": [], "messages": [msg]}

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
        explicit = "Fixer" in re.findall(r"@(\w+)", state["request"])  # the developer called Fixer: that is the approval
        return {**boot, "routed": True, "pending": names, "turns": 0, "approved": explicit,
                "publish": bool(PUBLISH_ASK.search(state["request"])),
                "messages": [*boot.get("messages", []), post("general", "TechLead", reply)]}

    over = state.get("turns", 0) >= MAX_TURNS
    text = await lead_say(cfg, "Redacta el resumen final para #general (estado, riesgos principales, siguiente paso)."
                          + (" Se alcanzó el límite de turnos: indica que el equipo se detuvo." if over else ""), state)
    summary = f"{text}\n\n{report(state)}"
    if state.get("publish"):
        try:
            title = f"Coven: correcciones de seguridad ({sum(f['status'] == 'PATCHED' for f in state.get('security_findings') or [])} hallazgos)"
            result = await asyncio.to_thread(ws.git_publish, title, summary)
        except Exception as e:
            result = f"no se pudo publicar: {e}"
        emit({"type": "diff", "diff": ws.get_git_diff(), "files": list(ws.originals)})
        summary += f"\n\n**GitHub:** {result}"
    return {"pending": [], "request": None, "approved": False, "publish": False,
            "messages": [post("general", "TechLead", summary, final=True)]}


def next_agent(state: CovenState) -> str:
    pending = state.get("pending") or []
    if pending[:1] == ["Fixer"] and needs_approval(state):
        return "TechLead"  # approval gate
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
