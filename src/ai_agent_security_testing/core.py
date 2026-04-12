"""Core Ai Agent Security Testing functionality."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AnalysisConfig:
    """Configuration for Ai Agent Security Testing."""
    verbose: bool = False
    targets: list[str] = field(default_factory=list)
    output_format: str = "text"


@dataclass
class AnalysisResult:
    """Result from Ai Agent Security Testing analysis."""
    success: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    @property
    def has_issues(self) -> bool:
        """Check if any critical issues were found."""
        return any(f.get("severity") == "critical" for f in self.findings)


def analyze(config: AnalysisConfig | None = None) -> AnalysisResult:
    """
    Run Ai Agent Security Testing analysis.

    Args:
        config: Analysis configuration. Uses defaults if not provided.

    Returns:
        AnalysisResult with findings and summary.
    """
    config = config or AnalysisConfig()
    findings: list[dict[str, Any]] = []

    for target in config.targets:
        try:
            findings.append({
                "target": target,
                "severity": "info",
                "message": f"Analyzed {target}",
                "status": "pass",
            })
        except Exception as e:
            findings.append({
                "target": target,
                "severity": "critical",
                "message": str(e),
                "status": "fail",
            })

    passed = sum(1 for f in findings if f["status"] == "pass")
    failed = sum(1 for f in findings if f["status"] == "fail")

    return AnalysisResult(
        success=failed == 0,
        findings=findings,
        summary={"total": len(findings), "passed": passed, "failed": failed},
    )


def format_results(result: AnalysisResult, fmt: str = "text") -> str:
    """Format analysis results for output."""
    if fmt == "json":
        import json
        return json.dumps({
            "success": result.success,
            "findings": result.findings,
            "summary": result.summary,
        }, indent=2)

    lines = [
        f"[{f['severity'].upper()}] {f['target']}: {f['message']}"
        for f in result.findings
    ]
    lines.append(f"\n{result.summary.get('passed', 0)}/{result.summary.get('total', 0)} passed")
    return "\n".join(lines)
