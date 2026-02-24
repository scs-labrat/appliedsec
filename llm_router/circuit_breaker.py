"""Circuit breaker and provider health registry — Stories 12.3, 12.4.

Implements per-provider circuit breaker pattern with three states:
CLOSED (healthy), OPEN (tripped), HALF_OPEN (probing recovery).
Adds degradation level computation for provider outage playbook.
"""

from __future__ import annotations

import time
from enum import Enum

from shared.schemas.routing import LLMProvider


class CircuitBreakerState(str, Enum):
    """Three-state circuit breaker."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Per-provider circuit breaker with configurable thresholds.

    State machine:
        CLOSED  → OPEN       on ``failure_threshold`` consecutive failures
        OPEN    → HALF_OPEN  after ``recovery_timeout_seconds`` elapsed
        HALF_OPEN → CLOSED   on success (probe passed)
        HALF_OPEN → OPEN     on failure (probe failed)
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout_seconds: float = 30.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._opened_at: float = 0.0

    @property
    def state(self) -> CircuitBreakerState:
        """Current state, with automatic OPEN → HALF_OPEN promotion."""
        if (
            self._state == CircuitBreakerState.OPEN
            and time.monotonic() - self._opened_at > self.recovery_timeout_seconds
        ):
            self._state = CircuitBreakerState.HALF_OPEN
        return self._state

    @property
    def is_available(self) -> bool:
        """True when CLOSED or HALF_OPEN (probe allowed)."""
        return self.state != CircuitBreakerState.OPEN

    def record_success(self) -> None:
        """Record a successful call — reset failures or close breaker."""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed call — increment counter or re-open breaker."""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self._open()
            return
        self._failure_count += 1
        if self._failure_count >= self.failure_threshold:
            self._open()

    def _open(self) -> None:
        self._state = CircuitBreakerState.OPEN
        self._opened_at = time.monotonic()
        self._failure_count = 0


class ProviderHealthRegistry:
    """Manages per-provider circuit breakers.

    Auto-creates a :class:`CircuitBreaker` on first access for any
    :class:`LLMProvider`.
    """

    def __init__(self) -> None:
        self._breakers: dict[LLMProvider, CircuitBreaker] = {}

    def _get(self, provider: LLMProvider) -> CircuitBreaker:
        if provider not in self._breakers:
            self._breakers[provider] = CircuitBreaker()
        return self._breakers[provider]

    def is_available(self, provider: LLMProvider) -> bool:
        """Check if *provider* is considered healthy."""
        return self._get(provider).is_available

    def record_success(self, provider: LLMProvider) -> None:
        """Record a successful call to *provider*."""
        self._get(provider).record_success()

    def record_failure(self, provider: LLMProvider) -> None:
        """Record a failed call to *provider*."""
        self._get(provider).record_failure()

    def compute_degradation_level(self) -> "DegradationLevel":
        """Compute current system degradation level from provider health."""
        from llm_router.models import DegradationLevel

        primary_up = self.is_available(LLMProvider.ANTHROPIC)
        secondary_up = self.is_available(LLMProvider.OPENAI)

        if primary_up:
            return DegradationLevel.FULL_CAPABILITY
        if secondary_up:
            return DegradationLevel.SECONDARY_ACTIVE
        return DegradationLevel.DETERMINISTIC_ONLY

    def get_policy(self) -> "DegradationPolicy":
        """Return the degradation policy for the current level."""
        from llm_router.models import DEGRADATION_POLICIES

        return DEGRADATION_POLICIES[self.compute_degradation_level()]
