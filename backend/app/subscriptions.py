"""Use your own subscription instead of an API key, by driving the vendor's official CLI headless.

You log in once with the vendor's tool (claude / codex login / agy); Coven never sees a token, it just
runs the CLI in an empty temp folder with its own tools off or read-only. Our tools travel as a text
protocol (<tool_call>{json}</tool_call>) because these CLIs don't expose native function calling."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

TIMEOUT = 600
# provider -> (executable, login hint, label)
CLIS = {
    "claude-sub": ("claude", "ejecuta `claude` y entra con tu cuenta Pro/Max", "Claude Pro/Max (Claude Code)"),
    "chatgpt-sub": ("codex", "instala Codex CLI y ejecuta `codex login`", "ChatGPT Plus/Pro (Codex CLI)"),
    "gemini-sub": ("agy", "ejecuta `agy` y entra con tu cuenta de Google", "Google (Antigravity CLI)"),
}

PROTOCOL = """## Herramientas disponibles
Para usar una herramienta responde ÚNICAMENTE con uno o varios bloques, sin más texto:
<tool_call>{"name": "nombre", "arguments": {"param": "valor"}}</tool_call>
Recibirás los resultados en el siguiente turno. Cuando ya tengas la respuesta final, escríbela sin ningún bloque
<tool_call>. No uses herramientas propias de tu entorno (archivos, terminal, web): solo las de esta lista.

"""
CALL = re.compile(r"<tool_call>\s*(?:```(?:json)?)?\s*(\{.*?\})\s*(?:```)?\s*</tool_call>", re.S)


class Message(SimpleNamespace):
    """Quacks like the LiteLLM message graph.py expects (content, tool_calls, model_dump)."""

    def model_dump(self, **_):
        return {"role": "assistant", "content": self.content, "tool_calls": [
            {"id": t.id, "type": "function", "function": {"name": t.function.name, "arguments": t.function.arguments}}
            for t in self.tool_calls or []]}


def status() -> dict:
    return {p: {"installed": bool(shutil.which(exe)), "login": hint, "label": label} for p, (exe, hint, label) in CLIS.items()}


def render(messages: list[dict], tools: list[dict] | None) -> list[str]:
    """Flatten a chat (system, user, assistant tool calls, tool results) into prompt blocks, one per message.
    Blocks never change once written, so the CLI's prompt cache reuses the whole prefix on the next tool round
    (one big string that grows each round is a cache miss every time)."""
    names, parts = {}, []
    for m in messages:
        role, content = m["role"], m.get("content") or ""
        if role == "system":
            spec = "".join(
                f"- {t['function']['name']}: {t['function']['description']} Parámetros: "
                + json.dumps(t["function"]["parameters"]["properties"], ensure_ascii=False) + "\n" for t in tools or [])
            parts.append(f"# Instrucciones\n{content}\n\n" + (PROTOCOL + spec if tools else ""))
        elif role == "assistant":
            calls = m.get("tool_calls") or []
            for c in calls:
                names[c["id"]] = c["function"]["name"]
            body = content + "".join(
                f'\n<tool_call>{{"name": "{c["function"]["name"]}", "arguments": {c["function"]["arguments"] or "{}"}}}</tool_call>'
                for c in calls)
            parts.append(f"# Tú (asistente)\n{body.strip()}")
        elif role == "tool":
            parts.append(f"# Resultado de {names.get(m.get('tool_call_id'), 'herramienta')}\n{content}")
        else:
            parts.append(f"# Usuario\n{content}")
    parts.append("# Tu turno\nResponde ahora siguiendo las instrucciones.")
    return parts


def parse(text: str) -> Message:
    calls = []
    for raw in CALL.findall(text):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and data.get("name"):
            calls.append(SimpleNamespace(id=f"call_{uuid.uuid4().hex[:8]}", function=SimpleNamespace(
                name=data["name"], arguments=json.dumps(data.get("arguments") or {}, ensure_ascii=False))))
    content = CALL.sub("", text).strip()
    return Message(content=(content or None) if calls else content, tool_calls=calls or None)


def _run(argv: list[str], stdin: str, cwd: str, env: dict | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, input=stdin, cwd=cwd, capture_output=True, text=True, env=env and {**os.environ, **env},
                              encoding="utf-8", errors="replace", timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{Path(argv[0]).stem} no respondió en {TIMEOUT}s")


def _fail(provider: str, detail: str):
    hint = CLIS[provider][1]
    auth = re.search(r"log ?in|auth|credential|unauthori|sign in|api key", detail, re.I)
    raise RuntimeError(f"{CLIS[provider][2]}: {detail.strip()[-400:] or 'sin salida'}" + (f" — {hint}" if auth else ""))


def complete(provider: str, model: str, blocks: list[str]) -> tuple[str, dict]:
    """Blocking: one headless turn through the vendor CLI. Run it in a thread. Returns (text, usage); usage may be {}."""
    exe = shutil.which(CLIS[provider][0])
    if not exe:
        raise RuntimeError(f"No encuentro `{CLIS[provider][0]}`: {CLIS[provider][1]}")
    prompt = "\n\n".join(blocks)
    with tempfile.TemporaryDirectory(prefix="coven-llm-") as cwd:  # nothing of the repo is reachable from here
        if provider == "claude-sub":
            argv = [exe, "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose",
                    "--tools", "", "--no-session-persistence",
                    "--setting-sources", "", "--strict-mcp-config",
                    "--system-prompt", "Eres el motor de lenguaje de Coven. Sigue las instrucciones del mensaje."]
            # headless default output cap cuts long reports with many tool calls
            line = json.dumps({"type": "user", "message": {"role": "user", "content": [
                {"type": "text", "text": b} for b in blocks]}}, ensure_ascii=False)
            r = _run(argv + (["--model", model] if model else []), line + "\n", cwd, {"CLAUDE_CODE_MAX_OUTPUT_TOKENS": "64000"})
            out = next((json.loads(raw) for raw in reversed(r.stdout.splitlines())
                        if raw.startswith("{") and '"type":"result"' in raw.replace(" ", "")), None)
            if out is None:
                _fail(provider, r.stderr or r.stdout)
            if out.get("is_error"):
                _fail(provider, str(out.get("result") or out))
            cut = {"max_tokens": "\n\n[respuesta truncada por el límite de salida: divide el trabajo en pasos más cortos]",
                   "refusal": "\n\n[respuesta cortada por el filtro de seguridad del proveedor: reformula en términos "
                              "defensivos (impacto y corrección), sin payloads ni pasos de explotación]"}
            u = out.get("usage") or {}
            usage = {"input": u.get("input_tokens", 0), "cache_write": u.get("cache_creation_input_tokens", 0),
                     "cache_read": u.get("cache_read_input_tokens", 0), "output": u.get("output_tokens", 0),
                     "cost": out.get("total_cost_usd"), "model": next(iter(out.get("modelUsage") or {}), model)}
            return (out.get("result") or "") + cut.get(out.get("stop_reason"), ""), usage
        if provider == "gemini-sub":
            argv = [exe, "--mode", "plan", "--input-format", "stream-json", "--output-format", "stream-json", "-p", ""]
            line = json.dumps({"event": "user", "message": {"role": "user", "content": prompt}}, ensure_ascii=False)
            r = _run(argv + (["--model", model] if model else []), line + "\n", cwd)
            for raw in reversed(r.stdout.splitlines()):
                if raw.startswith("{") and '"event":"result"' in raw.replace(" ", ""):
                    res = json.loads(raw)["result"]
                    if res.get("status") != "SUCCESS":
                        _fail(provider, res.get("error") or json.dumps(res))
                    return res.get("response") or "", {}
            _fail(provider, r.stderr or r.stdout)
        # chatgpt-sub — ponytail: built from Codex CLI docs, not run here (codex isn't installed on this machine)
        last = Path(cwd, "last.txt")
        argv = [exe, "exec", "--skip-git-repo-check", "--sandbox", "read-only", "--color", "never",
                "--output-last-message", str(last), *(["-m", model] if model else []), "-"]
        r = _run(argv, prompt, cwd)
        if r.returncode != 0 or not last.exists():
            _fail(provider, r.stderr or r.stdout)
        return last.read_text(encoding="utf-8"), {}
