"""Pluggable LLM backends. MockBackend — deterministic, offline. OpenAIBackend — calls any OpenAI-compatible /chat/completions endpoint with httpx. Requires OPENAI_API_KEY (or LLM_API_KEY)."""
from __future__ import annotations
import os
import httpx
from .config import BackendConfig
class BackendError(Exception):
    """Raised when the upstream LLM call fails."""
class LLMBackend:
    def complete(self, messages: list[dict], model: str, max_tokens: int | None) -> tuple[str, int]:
        raise NotImplementedError
class MockBackend(LLMBackend):
    def complete(self, messages: list[dict], model: str, max_tokens: int | None) -> tuple[str, int]:
        user_msgs = [m["content"] for m in messages if m.get("role") == "user"]
        last = user_msgs[-1] if user_msgs else ""
        reply = f"Mock reply to: {last}"
        if max_tokens is not None:
            reply = reply[: max_tokens * 4]
        return reply, max(1, len(reply) // 4)
class OpenAIBackend(LLMBackend):
    def __init__(self, cfg: BackendConfig) -> None:
        self.cfg = cfg
        self.api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY")
        if not self.api_key:
            raise BackendError("OpenAI backend selected but no OPENAI_API_KEY (or LLM_API_KEY) is set in the environment.")
    def complete(self, messages: list[dict], model: str, max_tokens: int | None) -> tuple[str, int]:
        payload: dict = {"model": model or self.cfg.model, "messages": messages}
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        try:
            resp = httpx.post(f"{self.cfg.base_url.rstrip('/')}/chat/completions", headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}, json=payload, timeout=self.cfg.timeout_seconds,)
        except httpx.HTTPError as exc:
            raise BackendError(f"Upstream LLM request failed: {exc}") from exc
        if resp.status_code != 200:
            raise BackendError(f"Upstream LLM returned HTTP {resp.status_code}: {resp.text[:500]}")
        data = resp.json()
        choice = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        return choice, int(usage.get("completion_tokens", max(1, len(choice) // 4)))
_BACKENDS: dict[str, type[LLMBackend]] = {"mock": MockBackend, "openai": OpenAIBackend,}
def get_backend(cfg: BackendConfig) -> LLMBackend:
    cls = _BACKENDS.get(cfg.name.lower())
    if cls is None:
        raise BackendError(f"Unknown backend '{cfg.name}'. Choose one of: {sorted(_BACKENDS)}")
    if cfg.name.lower() == "openai":
        return OpenAIBackend(cfg)
    return cls()
