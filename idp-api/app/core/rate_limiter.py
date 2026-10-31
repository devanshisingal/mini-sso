"""
Rate Limiter using in-memory sliding window.
Protects against brute force credential stuffing on login and MFA verification.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict


class SlidingWindowRateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _cleanup_old_attempts(self, key: str, now: float) -> None:
        cutoff = now - self.window_seconds
        self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]
        if not self._attempts[key]:
            self._attempts.pop(key, None)

    def is_rate_limited(self, key: str) -> tuple[bool, int]:
        """
        Checks if key has exceeded allowed attempts.
        Returns (is_limited, retry_after_seconds).
        """
        now = time.time()
        with self._lock:
            self._cleanup_old_attempts(key, now)
            attempts = self._attempts.get(key, [])
            if len(attempts) >= self.max_attempts:
                oldest = attempts[0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                return True, retry_after
            return False, 0

    def record_failure(self, key: str) -> tuple[bool, int]:
        """
        Records a failed attempt for key.
        Returns (is_limited, retry_after_seconds).
        """
        now = time.time()
        with self._lock:
            self._cleanup_old_attempts(key, now)
            self._attempts[key].append(now)
            if len(self._attempts[key]) >= self.max_attempts:
                oldest = self._attempts[key][0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                return True, retry_after
            return False, 0

    def reset(self, key: str) -> None:
        """Clears failure history on successful authentication."""
        with self._lock:
            self._attempts.pop(key, None)


# Default global instances for different authentication vectors
login_rate_limiter = SlidingWindowRateLimiter(max_attempts=5, window_seconds=300)  # 5 fails in 5 min
mfa_rate_limiter = SlidingWindowRateLimiter(max_attempts=4, window_seconds=180)    # 4 fails in 3 min
