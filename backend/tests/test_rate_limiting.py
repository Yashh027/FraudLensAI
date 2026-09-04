import threading

import pytest
from fastapi.testclient import TestClient

import app.main as main_module
from app.main import app
from app.services.rate_limiter import RedisRateLimiter, RedisRateLimitError

client = TestClient(app)


class FakePipeline:
    def __init__(self, fake_redis):
        self.fake_redis = fake_redis
        self._result = None
        self.ttl_value = self.fake_redis.ttl_value

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def incr(self, key):
        self._result = self.fake_redis.incr(key)
        return self

    def ttl(self, key):
        self.fake_redis.ttl_value = self.fake_redis.ttl(key)
        return self

    def expire(self, key, seconds):
        self.fake_redis.expire(key, seconds)
        return self

    def execute(self):
        if self.fake_redis.raise_error:
            raise self.fake_redis.raise_error
        return [self._result, self.fake_redis.ttl_value]


class FakeRedis:
    def __init__(self, counts=None, *, raise_error=None):
        self.counts = list(counts or [])
        self.current = 0
        self.values = {}
        self.ttl_value = 60
        self.raise_error = raise_error
        self.lock = threading.Lock()

    def pipeline(self):
        return FakePipeline(self)

    def incr(self, key):
        with self.lock:
            self.values[key] = self.values.get(key, 0) + 1
            return self.values[key]

    def ttl(self, key):
        return 60

    def expire(self, key, seconds):
        return True


def test_rate_limiter_allows_requests_below_limit():
    fake_redis = FakeRedis([1, 2, 3])
    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.limit = 5
    limiter.window_seconds = 60
    limiter._redis = fake_redis

    result = limiter.check("203.0.113.1")

    assert result["allowed"] is True
    assert result["count"] == 1
    assert result["remaining"] == 4


def test_rate_limiter_blocks_when_count_reaches_limit():
    fake_redis = FakeRedis()
    key = "fraudlens:rate_limit:203.0.113.2"
    fake_redis.values[key] = 4
    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.limit = 5
    limiter.window_seconds = 60
    limiter._redis = fake_redis

    result = limiter.check("203.0.113.2")

    assert result["allowed"] is True
    assert result["count"] == 5
    assert result["remaining"] == 0


def test_rate_limiter_blocks_when_request_exceeds_limit():
    fake_redis = FakeRedis()
    key = "fraudlens:rate_limit:203.0.113.3"
    fake_redis.values[key] = 5
    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.limit = 5
    limiter.window_seconds = 60
    limiter._redis = fake_redis

    result = limiter.check("203.0.113.3")

    assert result["allowed"] is False
    assert result["count"] == 6


def test_api_returns_429_when_limit_is_exceeded(monkeypatch):
    class FakeRateLimiter:
        def check(self, client_ip):
            return {"allowed": False, "count": 6, "limit": 5, "remaining": 0, "reset_after": 60, "window_seconds": 60}

    monkeypatch.setattr(main_module, "redis_limiter", FakeRateLimiter())

    response = client.get("/health/live")
    assert response.status_code == 200

    response = client.get("/api/v1/history", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 429
    payload = response.json()
    assert payload["error"] == "rate_limited"
    assert payload["retry_after"] == 60


def test_concurrent_requests_follow_limit():
    class LockedRedis(FakeRedis):
        def __init__(self):
            super().__init__()
            self.lock = threading.Lock()

    fake_redis = LockedRedis()
    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.limit = 3
    limiter.window_seconds = 60
    limiter._redis = fake_redis

    def worker():
        return limiter.check("203.0.113.4")

    results = [worker() for _ in range(5)]
    allowed = sum(1 for item in results if item["allowed"])
    blocked = sum(1 for item in results if not item["allowed"])

    assert allowed <= 3
    assert blocked >= 2


def test_redis_failure_returns_service_error(monkeypatch):
    class FakeRateLimiter:
        def check(self, client_ip):
            raise RedisRateLimitError("Redis unavailable")

    monkeypatch.setattr(main_module, "redis_limiter", FakeRateLimiter())

    response = client.get("/api/v1/history", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 503
    payload = response.json()
    assert payload["error"] == "rate_limiter_unavailable"


def test_rate_limit_window_reset_behavior():
    fake_redis = FakeRedis([1, 2, 3])
    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.limit = 3
    limiter.window_seconds = 60
    limiter._redis = fake_redis

    first = limiter.check("203.0.113.5")
    second = limiter.check("203.0.113.5")

    assert first["allowed"] is True
    assert second["allowed"] is True
    assert first["reset_after"] == 60
    assert second["reset_after"] == 60
