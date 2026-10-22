"""Multi-provider LLM gateway: API keys through LiteLLM, or your own subscription through the vendor CLI."""
import asyncio
from dataclasses import dataclass

import litellm

from . import subscriptions

# provider -> (litellm model prefix, default model); "" model = the CLI's own default
PROVIDERS = {
    "openrouter": ("openrouter/", "anthropic/claude-sonnet-5-5"),
    "anthropic": ("anthropic/", "claude-sonnet-5-5"),
    "openai": ("openai/", "gpt-5"),
    "gemini": ("gemini/", "gemini-2.5-pro"),
    "ollama": ("ollama_chat/", "qwen2.5-coder:14b"),
    **{p: ("", "") for p in subscriptions.CLIS},
}
NO_KEY = {"ollama", *subscriptions.CLIS}
OLLAMA_URL = "http://localhost:11434"


@dataclass
class LLMConfig:
    provider: str
    model: str = ""
    api_key: str | None = None
    base_url: str | None = None

    def __post_init__(self):
        if self.provider not in PROVIDERS:
            raise ValueError(f"Proveedor desconocido: {self.provider}. Usa uno de {list(PROVIDERS)}")
        if self.provider not in NO_KEY and not self.api_key:
            raise ValueError(f"{self.provider} requiere api_key")
        self.model = self.model or PROVIDERS[self.provider][1]

    def __repr__(self):  # never leak the key into logs/tracebacks
        return f"LLMConfig({self.provider}/{self.model})"


async def chat(cfg: LLMConfig, messages: list[dict], tools: list[dict] | None = None):
    """One completion; returns the assistant message (content + optional tool_calls)."""
    if cfg.provider in subscriptions.CLIS:
        text = await asyncio.to_thread(subscriptions.complete, cfg.provider, cfg.model, subscriptions.render(messages, tools))
        return subscriptions.parse(text)
    resp = await litellm.acompletion(
        model=PROVIDERS[cfg.provider][0] + cfg.model,
        messages=messages,
        tools=tools or None,
        api_key=cfg.api_key,
        api_base=cfg.base_url or (OLLAMA_URL if cfg.provider == "ollama" else None),
    )
    return resp.choices[0].message
