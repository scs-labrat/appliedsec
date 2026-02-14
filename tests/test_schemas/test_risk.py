"""Tests for RiskState, RiskSignal, classify_risk — AC-1.1.6."""

from shared.schemas.risk import RiskSignal, RiskState, classify_risk


class TestClassifyRiskNoBaseline:
    """AC-1.1.6: None priority returns NO_BASELINE with risk_score=None."""

    def test_none_priority_returns_no_baseline(self):
        result = classify_risk(
            investigation_priority=None, data_freshness_hours=1.0
        )
        assert result.risk_state == RiskState.NO_BASELINE
        assert result.risk_score is None

    def test_no_baseline_signal_type_is_ueba(self):
        result = classify_risk(
            investigation_priority=None, data_freshness_hours=5.0
        )
        assert result.signal_type == "ueba"


class TestClassifyRiskStaleData:
    """Stale data returns UNKNOWN even if priority present."""

    def test_stale_data_returns_unknown(self):
        result = classify_risk(
            investigation_priority=5,
            data_freshness_hours=48.0,
            max_stale_hours=24.0,
        )
        assert result.risk_state == RiskState.UNKNOWN
        assert result.risk_score == 5.0

    def test_exactly_at_threshold_is_not_stale(self):
        result = classify_risk(
            investigation_priority=5,
            data_freshness_hours=24.0,
            max_stale_hours=24.0,
        )
        assert result.risk_state == RiskState.MEDIUM


class TestClassifyRiskThresholds:
    """Priority thresholds: <3 LOW, <6 MEDIUM, >=6 HIGH."""

    def test_priority_0_is_low(self):
        result = classify_risk(investigation_priority=0, data_freshness_hours=1.0)
        assert result.risk_state == RiskState.LOW

    def test_priority_2_is_low(self):
        result = classify_risk(investigation_priority=2, data_freshness_hours=1.0)
        assert result.risk_state == RiskState.LOW

    def test_priority_3_is_medium(self):
        result = classify_risk(investigation_priority=3, data_freshness_hours=1.0)
        assert result.risk_state == RiskState.MEDIUM

    def test_priority_5_is_medium(self):
        result = classify_risk(investigation_priority=5, data_freshness_hours=1.0)
        assert result.risk_state == RiskState.MEDIUM

    def test_priority_6_is_high(self):
        result = classify_risk(investigation_priority=6, data_freshness_hours=1.0)
        assert result.risk_state == RiskState.HIGH

    def test_priority_10_is_high(self):
        result = classify_risk(investigation_priority=10, data_freshness_hours=1.0)
        assert result.risk_state == RiskState.HIGH


class TestRiskSignalModel:
    def test_risk_signal_construction(self):
        sig = RiskSignal(
            entity_id="user@example.com",
            signal_type="ueba",
            risk_state=RiskState.HIGH,
            risk_score=8.0,
            data_freshness_hours=2.5,
            source="sentinel",
        )
        assert sig.entity_id == "user@example.com"
        assert sig.risk_score == 8.0
