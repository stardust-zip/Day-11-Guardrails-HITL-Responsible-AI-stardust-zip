"""
Assignment - Rate Limiter Component
Prevents abuse by limiting requests per user in a time window.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    current_count: int
    max_requests: int
    window_seconds: int
    retry_after_seconds: float | None = None


class RateLimiter:
    """Sliding window rate limiter per user.

    Tracks request timestamps for each user and blocks when
    the number of requests exceeds the limit within the time window.

    Usage:
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        result = limiter.check("user123")
        if not result.allowed:
            print(f"Try again in {result.retry_after_seconds} seconds")
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque] = defaultdict(deque)

    def _clean_window(self, user_id: str) -> None:
        """Remove expired timestamps from user's window."""
        now = time.time()
        window = self.user_windows[user_id]
        while window and now - window[0] > self.window_seconds:
            window.popleft()

    def check(self, user_id: str) -> RateLimitResult:
        """Check if user is within rate limit.

        Args:
            user_id: Unique identifier for the user

        Returns:
            RateLimitResult with allowed status and metadata
        """
        self._clean_window(user_id)
        window = self.user_windows[user_id]

        current_count = len(window)

        if current_count >= self.max_requests:
            oldest_timestamp = window[0]
            retry_after = oldest_timestamp + self.window_seconds - time.time()
            return RateLimitResult(
                allowed=False,
                current_count=current_count,
                max_requests=self.max_requests,
                window_seconds=self.window_seconds,
                retry_after_seconds=max(0, retry_after),
            )

        window.append(time.time())
        return RateLimitResult(
            allowed=True,
            current_count=current_count + 1,
            max_requests=self.max_requests,
            window_seconds=self.window_seconds,
        )

    def reset(self, user_id: str) -> None:
        """Reset rate limit for a user (e.g., after admin action)."""
        if user_id in self.user_windows:
            del self.user_windows[user_id]

    def get_stats(self) -> dict:
        """Get current rate limiter statistics."""
        return {
            "max_requests": self.max_requests,
            "window_seconds": self.window_seconds,
            "active_users": len(self.user_windows),
        }


class RateLimitPlugin:
    """Google ADK Plugin wrapper for RateLimiter.

    Can be used as a plugin in the ADK pipeline.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.limiter = RateLimiter(max_requests, window_seconds)
        self.blocked_count = 0
        self.total_count = 0

    async def on_user_message_callback(self, *, invocation_context, user_message):
        from google.genai import types

        self.total_count += 1
        user_id = invocation_context.user_id if invocation_context else "anonymous"

        result = self.limiter.check(user_id)

        if not result.allowed:
            self.blocked_count += 1
            retry_msg = f"Rate limit exceeded. Please try again in {result.retry_after_seconds:.0f} seconds."
            return types.Content(
                role="model",
                parts=[types.Part.from_text(text=retry_msg)],
            )

        return None

    def get_stats(self) -> dict:
        return {
            **self.limiter.get_stats(),
            "blocked_count": self.blocked_count,
            "total_count": self.total_count,
            "block_rate": self.blocked_count / self.total_count
            if self.total_count > 0
            else 0,
        }


def test_rate_limiter():
    """Test RateLimiter with sample scenarios."""
    limiter = RateLimiter(max_requests=5, window_seconds=60)

    test_user = "test_user_123"
    print("Testing RateLimiter (max=5, window=60s):")
    print("=" * 50)

    for i in range(10):
        result = limiter.check(test_user)
        status = "ALLOWED" if result.allowed else "BLOCKED"
        print(
            f"Request {i + 1}: [{status}] count={result.current_count}/{result.max_requests}"
        )
        if not result.allowed:
            print(f"           Retry after: {result.retry_after_seconds:.1f}s")

    print("=" * 50)
    print(f"Stats: {limiter.get_stats()}")

    print("\nTesting different users:")
    for user in ["user_a", "user_b", "user_c"]:
        result = limiter.check(user)
        print(f"  {user}: {'ALLOWED' if result.allowed else 'BLOCKED'}")


if __name__ == "__main__":
    test_rate_limiter()
