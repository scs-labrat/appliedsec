"""Tests for CircuitBreaker, CircuitBreakerState, and ProviderHealthRegistry — Stories 12.3, 12.4."""

from unittest.mock import patch

from llm_router.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerState,
    ProviderHealthRegistry,
)
from llm_router.models import DEGRADATION_POLICIES, DegradationLevel
from shared.schemas.routing import LLMProvider


class TestCircuitBreakerState:
    """Enum values for circuit breaker states."""

    def test_has_three_states(self):
        assert len(list(CircuitBreakerState)) == 3

    def test_state_values(self):
        assert CircuitBreakerState.CLOSED.value == "closed"
        assert CircuitBreakerState.OPEN.value == "open"
        assert CircuitBreakerState.HALF_OPEN.value == "half_open"

    def test_is_str_enum(self):
        assert isinstance(CircuitBreakerState.CLOSED, str)


class TestCircuitBreaker:
    """Circuit breaker state machine transitions."""

    def test_initial_state_is_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitBreakerState.CLOSED

    def test_is_available_when_closed(self):
        cb = CircuitBreaker()
        assert cb.is_available is True

    def test_stays_closed_below_threshold(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.is_available is True

    def test_opens_on_threshold_breach(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(5):
            cb.record_failure()
        assert cb.state == CircuitBreakerState.OPEN
        assert cb.is_available is False

    def test_not_available_when_open(self):
        cb = CircuitBreaker(failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_available is False

    def test_failure_count_resets_on_success(self):
        cb = CircuitBreaker(failure_threshold=5)
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        # After success, count resets — 4 more failures should not open
        for _ in range(4):
            cb.record_failure()
        assert cb.state == CircuitBreakerState.CLOSED

    @patch("llm_router.circuit_breaker.time.monotonic")
    def test_transitions_to_half_open_after_timeout(self, mock_time):
        mock_time.return_value = 100.0
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=30.0)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitBreakerState.OPEN

        # Before timeout
        mock_time.return_value = 129.0
        assert cb.is_available is False
        assert cb.state == CircuitBreakerState.OPEN

        # After timeout
        mock_time.return_value = 131.0
        assert cb.is_available is True
        assert cb.state == CircuitBreakerState.HALF_OPEN

    @patch("llm_router.circuit_breaker.time.monotonic")
    def test_half_open_closes_on_success(self, mock_time):
        mock_time.return_value = 100.0
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=10.0)
        cb.record_failure()
        cb.record_failure()

        mock_time.return_value = 111.0
        assert cb.is_available is True  # HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitBreakerState.CLOSED

    @patch("llm_router.circuit_breaker.time.monotonic")
    def test_half_open_reopens_on_failure(self, mock_time):
        mock_time.return_value = 100.0
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=10.0)
        cb.record_failure()
        cb.record_failure()

        mock_time.return_value = 111.0
        assert cb.state == CircuitBreakerState.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitBreakerState.OPEN

    @patch("llm_router.circuit_breaker.time.monotonic")
    def test_half_open_is_available_for_probe(self, mock_time):
        mock_time.return_value = 100.0
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout_seconds=5.0)
        cb.record_failure()

        mock_time.return_value = 106.0
        assert cb.is_available is True
        assert cb.state == CircuitBreakerState.HALF_OPEN

    @patch("llm_router.circuit_breaker.time.monotonic")
    def test_record_success_promotes_open_to_closed_without_prior_state_check(self, mock_time):
        """record_success() after recovery timeout closes breaker even if
        is_available/state was never called first."""
        mock_time.return_value = 100.0
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=10.0)
        cb.record_failure()
        cb.record_failure()
        assert cb._state == CircuitBreakerState.OPEN

        mock_time.return_value = 111.0
        # Do NOT call cb.state or cb.is_available first
        cb.record_success()
        assert cb.state == CircuitBreakerState.CLOSED

    @patch("llm_router.circuit_breaker.time.monotonic")
    def test_record_failure_promotes_open_to_half_open_then_reopens(self, mock_time):
        """record_failure() after recovery timeout re-opens breaker even if
        is_available/state was never called first."""
        mock_time.return_value = 100.0
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=10.0)
        cb.record_failure()
        cb.record_failure()
        assert cb._state == CircuitBreakerState.OPEN

        mock_time.return_value = 111.0
        # Do NOT call cb.state or cb.is_available first
        cb.record_failure()
        assert cb.state == CircuitBreakerState.OPEN

    def test_default_thresholds(self):
        cb = CircuitBreaker()
        assert cb.failure_threshold == 5
        assert cb.recovery_timeout_seconds == 30.0


class TestProviderHealthRegistry:
    """Provider health registry manages per-provider circuit breakers."""

    def test_new_provider_is_available(self):
        registry = ProviderHealthRegistry()
        assert registry.is_available(LLMProvider.ANTHROPIC) is True

    def test_auto_creates_breaker_on_access(self):
        registry = ProviderHealthRegistry()
        registry.record_failure(LLMProvider.OPENAI)
        assert registry.is_available(LLMProvider.OPENAI) is True  # 1 failure < 5

    def test_per_provider_isolation(self):
        registry = ProviderHealthRegistry()
        for _ in range(5):
            registry.record_failure(LLMProvider.ANTHROPIC)
        assert registry.is_available(LLMProvider.ANTHROPIC) is False
        assert registry.is_available(LLMProvider.OPENAI) is True

    def test_record_success_resets_failures(self):
        registry = ProviderHealthRegistry()
        for _ in range(4):
            registry.record_failure(LLMProvider.GROQ)
        registry.record_success(LLMProvider.GROQ)
        registry.record_failure(LLMProvider.GROQ)
        assert registry.is_available(LLMProvider.GROQ) is True

    @patch("llm_router.circuit_breaker.time.monotonic")
    def test_provider_opens_and_recovers(self, mock_time):
        mock_time.return_value = 100.0
        registry = ProviderHealthRegistry()
        for _ in range(5):
            registry.record_failure(LLMProvider.ANTHROPIC)
        assert registry.is_available(LLMProvider.ANTHROPIC) is False

        # Advance past recovery timeout
        mock_time.return_value = 131.0
        assert registry.is_available(LLMProvider.ANTHROPIC) is True  # HALF_OPEN
        registry.record_success(LLMProvider.ANTHROPIC)
        assert registry.is_available(LLMProvider.ANTHROPIC) is True  # CLOSED


# ---------- DegradationComputation — Story 12.4 ------------------------------

class TestDegradationComputation:
    """compute_degradation_level() and get_policy() on ProviderHealthRegistry."""

    def test_all_healthy_full_capability(self):
        registry = ProviderHealthRegistry()
        assert registry.compute_degradation_level() == DegradationLevel.FULL_CAPABILITY

    def test_primary_down_secondary_active(self):
        registry = ProviderHealthRegistry()
        for _ in range(5):
            registry.record_failure(LLMProvider.ANTHROPIC)
        assert registry.compute_degradation_level() == DegradationLevel.SECONDARY_ACTIVE

    def test_all_llm_down_deterministic_only(self):
        registry = ProviderHealthRegistry()
        for _ in range(5):
            registry.record_failure(LLMProvider.ANTHROPIC)
        for _ in range(5):
            registry.record_failure(LLMProvider.OPENAI)
        assert registry.compute_degradation_level() == DegradationLevel.DETERMINISTIC_ONLY

    @patch("llm_router.circuit_breaker.time.monotonic")
    def test_recovery_back_to_full(self, mock_time):
        mock_time.return_value = 100.0
        registry = ProviderHealthRegistry()
        for _ in range(5):
            registry.record_failure(LLMProvider.ANTHROPIC)
        assert registry.compute_degradation_level() == DegradationLevel.SECONDARY_ACTIVE

        # Recover primary
        mock_time.return_value = 131.0
        registry.record_success(LLMProvider.ANTHROPIC)
        assert registry.compute_degradation_level() == DegradationLevel.FULL_CAPABILITY

    def test_get_policy_returns_matching_policy(self):
        registry = ProviderHealthRegistry()
        policy = registry.get_policy()
        assert policy is DEGRADATION_POLICIES[DegradationLevel.FULL_CAPABILITY]

    def test_get_policy_secondary_active(self):
        registry = ProviderHealthRegistry()
        for _ in range(5):
            registry.record_failure(LLMProvider.ANTHROPIC)
        policy = registry.get_policy()
        assert policy.confidence_threshold_override == 0.95
        assert policy.extended_thinking_available is False
