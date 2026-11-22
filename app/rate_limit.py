"""In-memory per-API-key rate limiting (sliding window). Two independent budgets per key: requests per minute and tokens per minute."""
from __future__ import annotations
import threading
import time
from collections import deque
class RateLimiter:
    def __init__(self, requests_per_minute: int, tokens_per_minute: int) -> None:
        self.requests_per_minute = requests_per_minute
        self.tokens_per_minute = tokens_per_minute
        self._requests: dict[str, deque[float]] = {}
        self._tokens: dict[str, deque[tuple[float, int]]] = {}
        self._lock = threading.Lock()
    def _prune(self, window: deque, now: float, window_seconds: float = 60.0) -> None:
        while window and window[0] <= now - window_seconds:
            window.popleft()
    def allow(self, key: str, tokens: int = 1) -> bool:
        now = time.monotonic()
        with self._lock:
            req_window = self._requests.setdefault(key, deque())
            self._prune(req_window, now)
            if len(req_window) >= self.requests_per_minute:
                return False
            tok_window = self._tokens.setdefault(key, deque())
            while tok_window and tok_window[0][0] <= now - 60.0:
                tok_window.popleft()
            used_tokens = sum(t for _, t in tok_window)
            if used_tokens + tokens > self.tokens_per_minute:
                return False
            req_window.append(now)
            tok_window.append((now, tokens))
            return True
    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._requests.clear()
                self._tokens.clear()
            else:
                self._requests.pop(key, None)
                self._tokens.pop(key, None)
