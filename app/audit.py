"""Structured audit logging (JSON lines). Every request produces one JSON line. Privacy rule: raw prompts and raw responses are NEVER written to the log. Only a SHA-256 hash of the prompt is stored."""
from __future__ import annotations
import hashlib
import json
import threading
import time
from collections import Counter
from pathlib import Path
def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
class AuditLogger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._counters: Counter[str] = Counter()
        self._total_latency_ms = 0
    def log(self, *, owner: str, route: str, model: str, prompt_hash: str, latency_ms: int, prompt_tokens: int, completion_tokens: int, guardrails_fired: list[str], redactions: int, status: str, blocked_reason: str | None = None,) -> dict:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "owner": owner, "route": route, "model": model, "prompt_sha256": prompt_hash, "latency_ms": latency_ms, "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens, "guardrails_fired": guardrails_fired, "redactions": redactions, "status": status, "blocked_reason": blocked_reason,}
        line = json.dumps(entry)
        with self._lock:
            self._counters["total_requests"] += 1
            self._counters[f"status:{status}"] += 1
            for fired in guardrails_fired:
                self._counters[f"guardrail:{fired}"] += 1
            self._counters["total_redactions"] += redactions
            self._total_latency_ms += latency_ms
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return entry
    def summary(self) -> dict:
        total = self._counters.get("total_requests", 0)
        return {"total_requests": total, "avg_latency_ms": round(self._total_latency_ms / total, 2) if total else 0, "by_status": {k.split(":", 1)[1]: v for k, v in self._counters.items() if k.startswith("status:")}, "guardrail_counts": {k.split(":", 1)[1]: v for k, v in self._counters.items() if k.startswith("guardrail:")}, "total_redactions": self._counters.get("total_redactions", 0),}
