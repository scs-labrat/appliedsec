"""Tests for Context Gateway — F7 quarantine strip fix."""

from __future__ import annotations

from context_gateway.gateway import _strip_quarantined_ids


class TestStripQuarantinedIds:
    def test_exact_match_stripped(self):
        """Exact technique ID should be stripped from text."""
        text = "Detected technique T1566 in the alert"
        result = _strip_quarantined_ids(text, ["T1566"])
        assert "T1566" not in result

    def test_substring_not_stripped(self):
        """F7: Quarantined ID embedded inside a larger word should NOT be stripped."""
        text = "Reference prefixT1566suffix in the report"
        result = _strip_quarantined_ids(text, ["T1566"])
        # Word-boundary regex should not strip T1566 when embedded in a larger token
        assert "T1566" in result

    def test_empty_quarantine_list(self):
        """No quarantined IDs → text unchanged."""
        text = "No quarantine needed"
        result = _strip_quarantined_ids(text, [])
        assert result == text
