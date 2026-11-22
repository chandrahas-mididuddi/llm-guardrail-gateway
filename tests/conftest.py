"""Pytest fixtures: fresh TestClient with an isolated audit log and a reset rate limiter for every test."""
import pytest
from fastapi.testclient import TestClient
from app import main as app_main
from app.audit import AuditLogger
@pytest.fixture()
def client(tmp_path):
    app_main.audit = AuditLogger(tmp_path / "audit.log.jsonl")
    app_main.limiter.reset()
    with TestClient(app_main.app) as c:
        yield c
    app_main.limiter.reset()
@pytest.fixture()
def headers():
    return {"X-API-Key": "demo-key-123"}
def chat_payload(text: str, **extra):
    payload = {"model": "mock-llm", "messages": [{"role": "user", "content": text}],}
    payload.update(extra)
    return payload
