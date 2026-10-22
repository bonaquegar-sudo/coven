"""Headless Coven for CI: scanners (and optionally the audit agents) over a repo, Markdown report, exit code.

  python -m app.cli <repo> [--diff-base origin/main] [--fail-on high] [--out coven.md]
                           [--llm anthropic --model ... ]   (API key from <PROVIDER>_API_KEY, e.g. ANTHROPIC_API_KEY)

Without --llm only the deterministic scanners run (OSV, secrets, SAST, routes): no key, no cost, same result every time.
With --llm, CodeScout, Reviewer and QARunner audit on top; Fixer never runs in CI. Accepted risks (.coven/accepted.json)
are honoured, and the exit code is 1 when an open finding at or above --fail-on is not low-confidence.
"""
import argparse
import asyncio
import os
import sys
import uuid

from .graph import SEV_ORDER, build_graph, report
from .llm import LLMConfig
from .tools import Workspace

OPEN = {"DETECTED", "CONFIRMED_BY_QA", "PATCHED"}


async def scan(ws: Workspace, llm: LLMConfig | None) -> list[dict]:
    if llm is None:
        await ws.scan_dependencies_osv()
        for tool in (ws.scan_secrets, ws.run_sast, ws.map_api_routes):
            tool()
        return list(ws.findings.items.values())
    cfg = {"recursion_limit": 100, "configurable": {"thread_id": uuid.uuid4().hex, "llm": llm, "workspace": ws}}
    state = {"project_path": str(ws.root), "request": "@CodeScout @Reviewer @QARunner audita el código (sin modificar nada).",
             "routed": False, "turns": 0, "messages": []}
    async for _ in build_graph().astream(state, cfg, stream_mode="custom"):
        pass
    return list(ws.findings.items.values())


def markdown(findings: list[dict], scope: str) -> str:
    shown = sorted((f for f in findings if f["status"] in OPEN and f["severity"] != "LOW"),
                   key=lambda f: (SEV_ORDER.get(f["severity"], 9), f.get("confidence") == "baja"))
    rows = [f"| {f['id']} | {f['severity']} | {f.get('confidence', '')} | {f['title'][:80]} | "
            f"`{f.get('file_path') or f.get('endpoint', '')}{':' + str(f['line_number']) if f.get('line_number') else ''}` | "
            f"{(f.get('compliance') or [''])[0]} |" for f in shown[:60]]
    accepted = sum(f["status"] == "ACCEPTED_RISK" for f in findings)
    return "\n".join([f"# Coven: revisión de seguridad ({scope})", "", report({"security_findings": findings}), "",
                      f"## Hallazgos abiertos ({len(shown)})", "",
                      "| Id | Sev. | Confianza | Hallazgo | Ubicación | Control |", "|---|---|---|---|---|---|",
                      *(rows or ["| — | | | | | |"])]
                     + ([f"\n+{len(shown) - 60} más."] if len(shown) > 60 else [])
                     + ([f"\n{accepted} riesgos aceptados (`.coven/accepted.json`) no se muestran."] if accepted else []))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="coven", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("repo")
    p.add_argument("--diff-base", default=None, help="solo archivos cambiados respecto a esta ref (p. ej. origin/main)")
    p.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "none"])
    p.add_argument("--out", default="", help="escribe el informe Markdown en este archivo")
    p.add_argument("--llm", default="", help="proveedor para la auditoría con agentes (sin él, solo escáneres)")
    p.add_argument("--model", default="")
    a = p.parse_args(argv)

    ws = Workspace(a.repo)
    scope = "todo el repositorio"
    if a.diff_base is not None:
        scope = f"{len(ws.limit_to_changes(a.diff_base))} archivos cambiados respecto a {a.diff_base or 'main'}"
    llm = LLMConfig(provider=a.llm, model=a.model, api_key=os.environ.get(f"{a.llm.upper().replace('-', '_')}_API_KEY")) if a.llm else None
    findings = asyncio.run(scan(ws, llm))
    md = markdown(findings, scope)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(md)
    print(md)
    limit = {"critical": 0, "high": 1, "medium": 2, "none": -1}[a.fail_on]
    blocking = [f for f in findings if f["status"] in OPEN and SEV_ORDER.get(f["severity"], 9) <= limit and f.get("confidence") != "baja"]
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
