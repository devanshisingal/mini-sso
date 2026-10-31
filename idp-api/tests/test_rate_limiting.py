"""
Tests for SlidingWindowRateLimiter.
"""

from app.core.rate_limiter import SlidingWindowRateLimiter


def test_rate_limiter_allows_under_limit():
    limiter = SlidingWindowRateLimiter(max_attempts=3, window_seconds=60)
    key = "user:alice@example.com"

    limited, _ = limiter.is_rate_limited(key)
    assert limited is False

    # Attempt 1 failed
    limited, _ = limiter.record_failure(key)
    assert limited is False

    # Attempt 2 failed
    limited, _ = limiter.record_failure(key)
    assert limited is False

    # Attempt 3 failed -> Hit limit
    limited, retry_after = limiter.record_failure(key)
    assert limited is True
    assert retry_after > 0

    # Subsequent check is still limited
    limited, _ = limiter.is_rate_limited(key)
    assert limited is True


def test_rate_limiter_reset():
    limiter = SlidingWindowRateLimiter(max_attempts=2, window_seconds=60)
    key = "ip:192.168.1.100"

    limiter.record_failure(key)
    limiter.record_failure(key)
    limited, _ = limiter.is_rate_limited(key)
    assert limited is True

    # User successfully logs in
    limiter.reset(key)
    limited, _ = limiter.is_rate_limited(key)
    assert limited is False
