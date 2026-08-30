import time
from collections.abc import Callable
from typing import TypeVar

import requests

T = TypeVar("T")


def request_with_retry(request_fn: Callable[[], T], attempts: int = 2, backoff_seconds: float = 0.25) -> T:
    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            return request_fn()
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_exc = exc
            if attempt + 1 < attempts:
                time.sleep(backoff_seconds * (2 ** attempt))
    assert last_exc is not None
    raise last_exc
