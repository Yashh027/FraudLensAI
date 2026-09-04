import os
import time
from typing import Any

from redis import Redis
from redis.exceptions import RedisError


class RedisRateLimitError(RuntimeError):
    """Raised when Redis-backed rate limiting is unavailable or misconfigured."""


class RedisRateLimiter:
    """Redis-backed sliding-window rate limiter shared across backend instances."""

    def __init__(self, redis_url: str | None = None, limit: int | None = None, window_seconds: int = 60):
        self.redis_url = redis_url or os.getenv("REDIS_URL")
        self.limit = int(limit if limit is not None else os.getenv("RATE_LIMIT_PER_MINUTE", 30))
        self.window_seconds = int(window_seconds)
        self._redis: Redis | None = None

        if not self.redis_url:
            raise RedisRateLimitError("REDIS_URL is not configured.")

        try:
            self._redis = Redis.from_url(self.redis_url, decode_responses=True)
            self._redis.ping()
        except (RedisError, ValueError, TypeError) as exc:
            raise RedisRateLimitError(f"Unable to connect to Redis at {self.redis_url}.") from exc

    @classmethod
    def from_env(cls):
        return cls(
            redis_url=os.getenv("REDIS_URL"),
            limit=int(os.getenv("RATE_LIMIT_PER_MINUTE", 30)),
            window_seconds=60,
        )

    def _key(self, client_ip: str) -> str:
        return f"fraudlens:rate_limit:{client_ip}"

    def check(self, client_ip: str) -> dict[str, Any]:
        if not client_ip:
            client_ip = "unknown"

        if self._redis is None:
            raise RedisRateLimitError("Redis client is not available.")

        key = self._key(client_ip)
        try:
            with self._redis.pipeline() as pipe:
                pipe.incr(key)
                pipe.expire(key, self.window_seconds)
                count, _ = pipe.execute()
            ttl = int(self._redis.ttl(key) or self.window_seconds)
        except RedisError as exc:
            raise RedisRateLimitError("Redis rate limiting failed during request validation.") from exc

        allowed = int(count) <= self.limit
        return {
            "allowed": allowed,
            "count": int(count),
            "limit": self.limit,
            "remaining": max(0, self.limit - int(count)),
            "reset_after": ttl,
            "window_seconds": self.window_seconds,
        }
