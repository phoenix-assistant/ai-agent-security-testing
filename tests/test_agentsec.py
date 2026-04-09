"""Tests for agentsec."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from dataclasses import asdict

from agentsec.models import ScanResults, TestResult
from agentsec.scanner import Scanner
from agentsec.reports import generate_json, generate_markdown, generate_html
from agentsec.attacks.base import BaseAttack
from agentsec.attacks.prompt_injection import PromptInjectionAttack
from agentsec.attacks.jailbreak import JailbreakAttack
from agentsec.attacks.data_exfiltration import DataExfiltrationAttack
from agentsec.attacks.tool_abuse import ToolAbuseAttack
from agentsec.attacks.ssrf import SSRFAttack
from agentsec.attacks.indirect_injection import IndirectInjectionAttack
from agentsec.attacks import ATTACK_REGISTRY


class TestScanResults:
    def test_perfect_score(self):
        r = ScanResults(target="http://test", model="gpt-4")
        r.tests = [TestResult(module="a", name="b", severity="critical", passed=True)]
        r.compute_score()
        assert r.score == 100

    def test_failed_critical(self):
        r = ScanResults(target="http://test", model="gpt-4")
        r.tests = [TestResult(module="a", name="b", severity="critical", passed=False)]
        r.compute_score()
        assert r.score == 75

    def test_multiple_failures(self):
        r = ScanResults(target="http://test", model="gpt-4")
        r.tests = [
            TestResult(module="a", name="b", severity="critical", passed=False),
            TestResult(module="a", name="c", severity="high", passed=False),
        ]
        r.compute_score()
        assert r.score == 60

    def test_score_floor_zero(self):
        r = ScanResults(target="http://test", model="gpt-4")
        r.tests = [TestResult(module="a", name=f"t{i}", severity="critical", passed=False) for i in range(5)]
        r.compute_score()
        assert r.score == 0

    def test_empty_tests(self):
        r = ScanResults(target="http://test", model="gpt-4")
        r.compute_score()
        assert r.score == 100


class TestBaseAttack:
    def test_check_response_match(self):
        a = PromptInjectionAttack()
        assert a._check_response("Here is my System Prompt", ["system prompt"])

    def test_check_response_no_match(self):
        a = PromptInjectionAttack()
        assert not a._check_response("I cannot help with that", ["system prompt"])


class TestReports:
    def _make_results(self):
        r = ScanResults(target="http://test", model="gpt-4", score=85)
        r.tests = [
            TestResult(module="prompt_injection", name="test1", severity="high", passed=True, details="OK"),
            TestResult(module="jailbreak", name="test2", severity="critical", passed=False, details="Failed"),
        ]
        return r

    def test_json_report(self):
        data = json.loads(generate_json(self._make_results()))
        assert data["score"] == 85
        assert len(data["tests"]) == 2

    def test_markdown_report(self):
        md = generate_markdown(self._make_results())
        assert "85/100" in md
        assert "✅ PASS" in md
        assert "❌ FAIL" in md

    def test_html_report(self):
        html = generate_html(self._make_results())
        assert "<html>" in html
        assert "85/100" in html


class TestAttackRegistry:
    def test_all_modules_registered(self):
        assert len(ATTACK_REGISTRY) == 6
        expected = {"prompt_injection", "jailbreak", "data_exfiltration", "tool_abuse", "ssrf", "indirect_injection"}
        assert set(ATTACK_REGISTRY.keys()) == expected

    def test_all_inherit_base(self):
        for cls in ATTACK_REGISTRY.values():
            assert issubclass(cls, BaseAttack)


class TestScanner:
    def test_scanner_init(self):
        s = Scanner(target="http://localhost:8080/", api_key="test", model="gpt-3.5")
        assert s.target == "http://localhost:8080"
        assert s.api_key == "test"

    @pytest.mark.asyncio
    async def test_scanner_run_with_mock(self):
        s = Scanner(target="http://test", api_key="k")
        s._chat = AsyncMock(return_value="I cannot help with that request.")
        results = await s.run()
        assert isinstance(results, ScanResults)
        assert len(results.tests) > 0
        assert all(isinstance(t, TestResult) for t in results.tests)
