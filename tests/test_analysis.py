"""Tests for structured analysis results."""

from kasa.models.analysis import AnalysisResult
from kasa.models.finding import Finding, Severity


def test_empty_analysis_result() -> None:
    result = AnalysisResult()

    assert result.total == 0
    assert result.findings == []


def test_analysis_result_counts_severity() -> None:
    findings = [
        Finding(
            id="TEST-001",
            title="Low finding",
            description="Test",
            severity=Severity.LOW,
            category="test",
        ),
        Finding(
            id="TEST-002",
            title="Medium finding",
            description="Test",
            severity=Severity.MEDIUM,
            category="test",
        ),
        Finding(
            id="TEST-003",
            title="Another low finding",
            description="Test",
            severity=Severity.LOW,
            category="test",
        ),
    ]

    result = AnalysisResult(findings=findings)

    assert result.total == 3
    assert result.severity_counts["low"] == 2
    assert result.severity_counts["medium"] == 1
    assert result.severity_counts["high"] == 0
