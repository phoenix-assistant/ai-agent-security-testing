"""Tests for Ai Agent Security Testing."""

from ai_agent_security_testing import analyze, AnalysisResult, AnalysisConfig


def test_analyze_empty():
    result = analyze()
    assert result.success is True
    assert result.summary["total"] == 0


def test_analyze_with_targets():
    config = AnalysisConfig(targets=["target1", "target2"])
    result = analyze(config)
    assert result.summary["total"] == 2
    assert result.summary["passed"] == 2


def test_result_has_issues():
    result = AnalysisResult(success=True, findings=[])
    assert result.has_issues is False


def test_result_with_critical():
    result = AnalysisResult(
        success=False,
        findings=[{"severity": "critical", "target": "x", "message": "bad", "status": "fail"}],
    )
    assert result.has_issues is True


def test_format_json():
    from ai_agent_security_testing.core import format_results
    result = AnalysisResult(success=True, findings=[], summary={"total": 0, "passed": 0, "failed": 0})
    output = format_results(result, "json")
    import json
    parsed = json.loads(output)
    assert parsed["success"] is True
