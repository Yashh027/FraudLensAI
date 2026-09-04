"""Shared test fixtures for FraudLens AI backend tests.

The application uses a shared Redis-backed rate limiter in production. For local
unit and integration tests, we inject a safe stub so tests remain deterministic
without requiring an external Redis process.
"""

import pytest

from app import main as main_module


@pytest.fixture(autouse=True)
def _clear_rate_limiter(monkeypatch):
    """Stub the shared redis limiter for tests without a real Redis instance."""
    class FakeRedisLimiter:
        def __init__(self):
            self.calls = {}

        def check(self, client_ip):
            bucket = self.calls.setdefault(client_ip, 0)
            self.calls[client_ip] = bucket + 1
            allowed = self.calls[client_ip] <= int(main_module.RATE_LIMIT_PER_MINUTE)
            return {
                "allowed": allowed,
                "count": self.calls[client_ip],
                "limit": int(main_module.RATE_LIMIT_PER_MINUTE),
                "remaining": max(0, int(main_module.RATE_LIMIT_PER_MINUTE) - self.calls[client_ip]),
                "reset_after": 60,
                "window_seconds": 60,
            }

    monkeypatch.setattr(main_module, "redis_limiter", FakeRedisLimiter())
    yield
    monkeypatch.setattr(main_module, "redis_limiter", FakeRedisLimiter())
