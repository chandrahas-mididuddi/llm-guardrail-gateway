"""llm-guardrail-gateway — a FastAPI gateway that enforces safety guardrails around LLM calls. Pipeline: API-key auth -> rate limit -> pre-call guardrails (PII redaction, prompt-injection / jailbreak detection) -> LLM backend -> post-call guardrails (PII scan, toxicity filter, optional JSON validation) -> structured audit log entry (no raw prompts stored, only hashes)."""
from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from . import __version__
from .audit import AuditLogger, hash_text
from .backends import BackendError, get_backend
from .config import GatewayConfig, load_config
from .guardrails import GuardrailResult, run_post_call_checks, run_pre_call_checks
from .models import ChatCompletionRequest, ChatCompletionResponse, Choice, Usage
from .rate_limit import RateLimiter
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
config: GatewayConfig = load_config(CONFIG_PATH)
audit = AuditLogger(config.audit_log_path)
limiter = RateLimiter(requests_per_minute=config.rate_limit.requests_per_minute, tokens_per_minute=config.rate_limit.tokens_per_minute,)
app = FastAPI(title="llm-guardrail-gateway", description="A production-style FastAPI gateway that enforces PII redaction, prompt-injection / jailbreak detection, rate limiting and audit logging around any LLM API.", version=__version__,)
def authenticate(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> str:
    """In-memory API-key auth. Returns the key id (owner label)."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    owner = config.api_keys.get(x_api_key)
    if owner is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return owner
@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "llm-guardrail-gateway", "version": __version__, "backend": config.backend.name, "guardrails": {"pii_redaction": config.policies.pii_redaction, "injection_detection": config.policies.injection_detection, "toxicity_filter": config.policies.toxicity_filter,},}
@app.get("/metrics")
def metrics() -> dict:
    return audit.summary()
@app.post("/v1/chat/completions", response_model=ChatCompletionResponse)
def chat_completions(request: ChatCompletionRequest, http_request: Request, owner: str = Depends(authenticate),) -> ChatCompletionResponse:
    started = time.monotonic()
    guardrails_fired: list[str] = []
    redactions = 0
    blocked_reason: str | None = None
    status = "ok"
    prompt_text = ""
    prompt_tokens = 0
    completion_tokens = 0
    try:
        if not limiter.allow(owner):
            status = "rate_limited"
            raise HTTPException(status_code=429, detail="Rate limit exceeded for this API key")
        prompt_text = "\n".join(m.content for m in request.messages)
        prompt_tokens = max(1, len(prompt_text) // 4)
        if prompt_tokens > config.policies.max_prompt_tokens:
            status = "blocked"
            blocked_reason = "max_prompt_tokens"
            guardrails_fired.append("max_prompt_tokens")
            raise HTTPException(status_code=400, detail="Prompt exceeds max_prompt_tokens")
        pre: GuardrailResult = run_pre_call_checks(prompt_text, config.policies)
        redactions = pre.redaction_count
        guardrails_fired.extend(pre.fired)
        if pre.blocked:
            status = "blocked"
            blocked_reason = pre.block_reason
            raise HTTPException(status_code=400, detail=f"Blocked by guardrail: {pre.block_reason}",)
        backend = get_backend(config.backend)
        safe_messages: list[dict] = []
        user_indices = [i for i, m in enumerate(request.messages) if m.role == "user"]
        last_user = user_indices[-1] if user_indices else None
        for i, m in enumerate(request.messages):
            if i == last_user and pre.redacted_text != prompt_text:
                from .guardrails import redact_pii
                redacted_msg, _ = redact_pii(m.content)
                safe_messages.append({"role": m.role, "content": redacted_msg})
            else:
                safe_messages.append({"role": m.role, "content": m.content})
        try:
            reply_text, completion_tokens = backend.complete(safe_messages, model=request.model, max_tokens=request.max_tokens)
        except BackendError as exc:
            status = "backend_error"
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        post = run_post_call_checks(reply_text, config.policies)
        guardrails_fired.extend(post.fired)
        redactions += post.redaction_count
        if post.blocked:
            status = "blocked"
            blocked_reason = post.block_reason
            raise HTTPException(status_code=400, detail=f"Response blocked by guardrail: {post.block_reason}",)
        reply_text = post.redacted_text
        if request.response_format is not None and request.response_format.get("type") == "json_object":
            try:
                json.loads(reply_text)
            except json.JSONDecodeError:
                status = "blocked"
                blocked_reason = "invalid_json_response"
                guardrails_fired.append("invalid_json_response")
                raise HTTPException(status_code=502, detail="Backend response is not valid JSON as requested",)
        latency_ms = int((time.monotonic() - started) * 1000)
        audit.log(owner=owner, route="/v1/chat/completions", model=request.model, prompt_hash=hash_text(prompt_text), latency_ms=latency_ms, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, guardrails_fired=guardrails_fired, redactions=redactions, status=status, blocked_reason=blocked_reason,)
        return ChatCompletionResponse(id=f"chatcmpl-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]}", created=int(time.time()), model=request.model, choices=[Choice(index=0, message={"role": "assistant", "content": reply_text})], usage=Usage(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=prompt_tokens + completion_tokens,),)
    except HTTPException:
        latency_ms = int((time.monotonic() - started) * 1000)
        audit.log(owner=owner, route="/v1/chat/completions", model=request.model, prompt_hash=hash_text(prompt_text), latency_ms=latency_ms, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, guardrails_fired=guardrails_fired, redactions=redactions, status=status, blocked_reason=blocked_reason,)
        raise
@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
def main() -> None:
    import uvicorn
    uvicorn.run("app.main:app", host=config.server.host, port=config.server.port, reload=False,)
if __name__ == "__main__":
    main()
