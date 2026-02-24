"""Injection regression suite infrastructure — Story 12.10.

Provides shared fixtures, test case dataclasses, and helpers for
the red-team injection regression test suite.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from context_gateway.evidence_builder import EvidenceBlock, escape_xml_tags
from context_gateway.injection_detector import sanitise_input


@dataclass
class InjectionTestCase:
    """A single injection test case."""

    payload: str
    category: str
    description: str
    expected_detected: bool = True


@dataclass
class InjectionSuiteResult:
    """Aggregated results from running the full injection suite."""

    total: int = 0
    detected: int = 0
    bypassed: int = 0
    by_category: dict[str, dict[str, int]] = field(default_factory=dict)


def run_injection_test(test_case: InjectionTestCase) -> bool:
    """Run payload through sanitise_input and return True if detected."""
    _, detections = sanitise_input(test_case.payload)
    return len(detections) > 0


def run_evidence_isolation_test(test_case: InjectionTestCase) -> bool:
    """Check that payload is isolated inside <evidence> tags after wrapping."""
    wrapped = EvidenceBlock.wrap_evidence(
        alert_title=test_case.payload,
        alert_description="",
        entities_json="{}",
    )
    # The raw payload should NOT appear outside <evidence> tags
    # After escaping, angle brackets become &lt; &gt;, so the original
    # payload with < or > won't match. Check the escaped version is
    # contained within the evidence block structure.
    escaped = escape_xml_tags(test_case.payload)

    # Find content before <evidence> and after </evidence>
    evidence_start = wrapped.find("<evidence>")
    evidence_end = wrapped.find("</evidence>")

    if evidence_start == -1 or evidence_end == -1:
        return False  # Broken evidence structure

    before = wrapped[:evidence_start]
    after = wrapped[evidence_end + len("</evidence>"):]

    # Payload (or its escaped version) should NOT appear outside evidence
    return escaped not in before and escaped not in after


def run_combined_defense_test(test_case: InjectionTestCase) -> bool:
    """Return True if ANY defense layer catches the injection."""
    regex_detected = run_injection_test(test_case)
    evidence_isolated = run_evidence_isolation_test(test_case)
    return regex_detected or evidence_isolated


def print_suite_summary(result: InjectionSuiteResult) -> str:
    """Format per-category results for CI visibility."""
    lines = [
        f"Injection Regression Suite: {result.detected}/{result.total} detected "
        f"({result.bypassed} bypasses)",
        "",
    ]
    for category, counts in sorted(result.by_category.items()):
        total = counts.get("total", 0)
        detected = counts.get("detected", 0)
        bypassed = counts.get("bypassed", 0)
        rate = (detected / total * 100) if total > 0 else 0
        lines.append(f"  {category}: {detected}/{total} ({rate:.0f}%) — {bypassed} bypass(es)")
    return "\n".join(lines)
