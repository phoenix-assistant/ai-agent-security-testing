"""Report generation — JSON, Markdown, HTML."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from jinja2 import Template

if TYPE_CHECKING:
    from agentsec.scanner import ScanResults


def generate_json(results: ScanResults) -> str:
    data = {
        "target": results.target,
        "model": results.model,
        "score": results.score,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tests": [asdict(t) for t in results.tests],
    }
    return json.dumps(data, indent=2)


def generate_markdown(results: ScanResults) -> str:
    passed = sum(1 for t in results.tests if t.passed)
    failed = len(results.tests) - passed
    lines = [
        f"# AgentSec Scan Report",
        f"",
        f"**Target:** {results.target}  ",
        f"**Model:** {results.model}  ",
        f"**Score:** {results.score}/100  ",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Passed:** {passed} | **Failed:** {failed}",
        f"",
        f"## Results",
        f"",
        f"| Module | Test | Severity | Result | Details |",
        f"|--------|------|----------|--------|---------|",
    ]
    for t in results.tests:
        status = "✅ PASS" if t.passed else "❌ FAIL"
        lines.append(f"| {t.module} | {t.name} | {t.severity} | {status} | {t.details or ''} |")
    return "\n".join(lines) + "\n"


HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><title>AgentSec Report</title>
<style>
body{font-family:system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;background:#0d1117;color:#c9d1d9}
h1{color:#58a6ff}table{width:100%;border-collapse:collapse;margin:1rem 0}
th,td{padding:8px 12px;border:1px solid #30363d;text-align:left}
th{background:#161b22}.pass{color:#3fb950}.fail{color:#f85149}
.score{font-size:2rem;font-weight:bold;margin:1rem 0}
.critical{color:#f85149}.high{color:#f0883e}.medium{color:#d29922}.low{color:#58a6ff}
</style></head><body>
<h1>🛡️ AgentSec Scan Report</h1>
<p><b>Target:</b> {{ target }} | <b>Model:</b> {{ model }}</p>
<p class="score">Score: {{ score }}/100</p>
<table><tr><th>Module</th><th>Test</th><th>Severity</th><th>Result</th><th>Details</th></tr>
{% for t in tests %}
<tr><td>{{ t.module }}</td><td>{{ t.name }}</td>
<td class="{{ t.severity }}">{{ t.severity }}</td>
<td class="{{ 'pass' if t.passed else 'fail' }}">{{ '✅ PASS' if t.passed else '❌ FAIL' }}</td>
<td>{{ t.details or '' }}</td></tr>
{% endfor %}</table></body></html>"""


def generate_html(results: ScanResults) -> str:
    tmpl = Template(HTML_TEMPLATE)
    return tmpl.render(
        target=results.target, model=results.model, score=results.score,
        tests=results.tests,
    )
