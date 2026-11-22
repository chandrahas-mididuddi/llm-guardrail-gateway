"""Configuration loading. Policies are defined in ``config.yaml`` at the repo root so operators can tune guardrails per deployment without touching code. All fields have sane defaults, so a missing or partial file still boots."""
from __future__ import annotations
from pathlib import Path
import yaml
from pydantic import BaseModel, Field
class Policies(BaseModel):
    pii_redaction: bool = True
    pii_block_response: bool = False
    injection_detection: bool = True
    jailbreak_detection: bool = True
    toxicity_filter: bool = True
    max_prompt_tokens: int = 4000
    injection_block_threshold: int = 2
class RateLimit(BaseModel):
    requests_per_minute: int = 60
    tokens_per_minute: int = 20000
class BackendConfig(BaseModel):
    name: str = "mock"
    model: str = "mock-llm"
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: float = 30.0
class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
class GatewayConfig(BaseModel):
    policies: Policies = Field(default_factory=Policies)
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    backend: BackendConfig = Field(default_factory=BackendConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    api_keys: dict[str, str] = Field(default_factory=lambda: {"demo-key-123": "demo-user"})
    audit_log_path: str = "audit.log.jsonl"
def load_config(path: str | Path) -> GatewayConfig:
    path = Path(path)
    if not path.exists():
        return GatewayConfig()
    with path.open() as fh:
        raw = yaml.safe_load(fh) or {}
    return GatewayConfig(**raw)
