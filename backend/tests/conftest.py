"""Shared test fixtures for FraudLens AI backend tests.

Clears the in-memory rate limiter before each test so that integration tests
using the shared TestClient never hit the 30 req/min ceiling.
"""

import pytest
from app.main import _rate_buckets


@pytest.fixture(autouse=True)
def _clear_rate_limiter():
    """Reset the per-IP rate limiter between every test."""
    _rate_buckets.clear()
    yield
    _rate_buckets.clear()
