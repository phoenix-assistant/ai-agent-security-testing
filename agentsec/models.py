"""Data models for agentsec."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TestResult:
    module: str
    name: str
    severity: str  # critical, high, medium, low, info
    passed: bool
    details: Optional[str] = None
    raw_response: Optional[str] = None


@dataclass
class ScanResults:
    target: str
    model: str
    tests: list[TestResult] = field(default_factory=list)
    score: int = 100

    def compute_score(self):
        if not self.tests:
            self.score = 100
            return
        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
        penalty = sum(severity_weights.get(t.severity, 0) for t in self.tests if not t.passed)
        self.score = max(0, 100 - penalty)
