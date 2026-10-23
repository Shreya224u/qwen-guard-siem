import json
from typing import Any, Optional, Dict, List, Tuple

import redis

from app.config import settings


redis_client = None

if settings.REDIS_ENABLED:
    redis_client = redis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
    )


# ---------------------------------------------------------------------------
# CACHE
# ---------------------------------------------------------------------------

def cache_set(
    key: str,
    value: Any,
    ttl_seconds: int = 60,
) -> None:
    """
    Store a JSON-serializable value in Redis with an expiry time.
    """

    if redis_client is None:
        return

    redis_client.setex(
        name=key,
        time=ttl_seconds,
        value=json.dumps(value),
    )


def cache_get(key: str) -> Optional[Any]:
    """
    Retrieve a cached value from Redis and decode it from JSON.
    """

    if redis_client is None:
        return None

    raw_value = redis_client.get(key)

    if raw_value is None:
        return None

    return json.loads(raw_value)


def cache_delete(key: str) -> None:
    """
    Delete a cached value.
    """

    if redis_client is None:
        return

    redis_client.delete(key)


# ---------------------------------------------------------------------------
# RATE LIMITING
# ---------------------------------------------------------------------------

def rate_limit_check(
    key: str,
    max_attempts: int,
    window_seconds: int,
) -> bool:
    """
    Fixed-window rate limiter using Redis.

    Uses a pipeline so INCR and EXPIRE are sent together.
    """

    if redis_client is None:
        return True

    pipe = redis_client.pipeline(transaction=True)

    pipe.incr(key)
    pipe.expire(key, window_seconds)

    current_count, _ = pipe.execute()

    return current_count <= max_attempts


# ---------------------------------------------------------------------------
# SINGLE COUNTER
# ---------------------------------------------------------------------------

def increment_and_get_count(
    key: str,
    ttl_seconds: int,
) -> int:
    """
    Increment a Redis counter and return its current value.

    Kept for compatibility with the single-log Rule Engine API.
    """

    if redis_client is None:
        return 0

    pipe = redis_client.pipeline(transaction=True)

    pipe.incr(key)
    pipe.expire(key, ttl_seconds)

    current_count, _ = pipe.execute()

    return int(current_count)


# ---------------------------------------------------------------------------
# BATCH COUNTERS
# ---------------------------------------------------------------------------

def increment_and_get_counts_batch(
    items: List[Tuple[str, int]],
) -> Dict[str, int]:
    """
    Increment many Redis counters in one pipeline.

    Args:
        items:
            List of:
                (redis_key, ttl_seconds)

    Returns:
        Dictionary:
            redis_key -> current counter value

    Example:

        increment_and_get_counts_batch(
            [
                ("corr:brute_force:10.0.0.1", 300),
                ("corr:brute_force:10.0.0.2", 300),
            ]
        )

    Instead of:

        Redis request
        Redis request
        Redis request
        ...

    the counters are sent together using a Redis pipeline.
    """

    if redis_client is None or not items:
        return {
            key: 0
            for key, _ in items
        }

    pipe = redis_client.pipeline(transaction=False)

    for key, ttl_seconds in items:
        pipe.incr(key)
        pipe.expire(key, ttl_seconds)

    results = pipe.execute()

    counts: Dict[str, int] = {}

    result_index = 0

    for key, _ in items:
        count = results[result_index]

        counts[key] = int(count)

        result_index += 2

    return counts