"""Subscription providers: text tool-call protocol offline, plus an opt-in live round trip per installed CLI.
Run: python test_subscriptions.py            (offline)
     COVEN_LIVE_SUBS=1 python test_subscriptions.py   (also calls claude / agy / codex with your login)"""
import asyncio
import json
import os

from app import subscriptions as subs
from app.llm import LLMConfig, chat
from app.tools import tool_schemas

# parse: tool calls (plain and fenced), bad JSON ignored, text kept when there are no calls
m = subs.parse('Voy.\n<tool_call>{"name": "read_file", "arguments": {"path": "a.py"}}</tool_call>\n'
               '<tool_call>```json\n{"name": "list_directory", "arguments": {}}\n```</tool_call><tool_call>{oops}</tool_call>')
assert [t.function.name for t in m.tool_calls] == ["read_file", "list_directory"]
assert json.loads(m.tool_calls[0].function.arguments) == {"path": "a.py"} and m.content == "Voy."
assert subs.parse("respuesta final").tool_calls is None and subs.parse("respuesta final").content == "respuesta final"

# render: tool specs in the instructions, prior calls and their results named
dump = m.model_dump()
blocks = subs.render([{"role": "system", "content": "Eres X"}, {"role": "user", "content": "hola"}, dump,
                      {"role": "tool", "tool_call_id": dump["tool_calls"][0]["id"], "content": "1: x = 1"}],
                     tool_schemas(["read_file"]))
prompt = "\n\n".join(blocks)
# one block per message, so earlier blocks stay byte-identical (prompt cache) when the chat grows
assert len(blocks) == 5 and blocks[:4] == subs.render([{"role": "system", "content": "Eres X"}, {"role": "user", "content": "hola"}, dump,
                      {"role": "tool", "tool_call_id": dump["tool_calls"][0]["id"], "content": "1: x = 1"},
                      {"role": "user", "content": "sigue"}], tool_schemas(["read_file"]))[:4]
assert "- read_file:" in prompt and "<tool_call>" in prompt and "# Resultado de read_file\n1: x = 1" in prompt

LLMConfig(provider="claude-sub")  # no api_key needed
print("subscription CLIs:", {p: s["installed"] for p, s in subs.status().items()})


async def live(provider: str):
    cfg = LLMConfig(provider=provider)
    msgs = [{"role": "system", "content": "Eres un asistente de código. Usa read_file antes de responder."},
            {"role": "user", "content": "¿Qué valor tiene x en app.py? Responde solo el número."}]
    reply = await chat(cfg, msgs, tool_schemas(["read_file"]))
    assert reply.tool_calls and reply.tool_calls[0].function.name == "read_file", reply
    msgs += [reply.model_dump(), {"role": "tool", "tool_call_id": reply.tool_calls[0].id, "content": "1: x = 42"}]
    final = await chat(cfg, msgs, tool_schemas(["read_file"]))
    assert not final.tool_calls and "42" in final.content, final
    print(f"{provider}: tool call + final answer OK -> {final.content!r}")


if os.environ.get("COVEN_LIVE_SUBS"):
    for p, s in subs.status().items():
        if s["installed"]:
            asyncio.run(live(p))
print("subscriptions OK")
