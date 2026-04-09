"""CLI entry point for agentsec."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agentsec.scanner import Scanner
from agentsec.reports import generate_json, generate_markdown, generate_html

console = Console()


@click.group()
@click.version_option(package_name="agentsec")
def main():
    """AgentSec — Red-team AI agents with automated attack scenarios."""


@main.command()
@click.option("--target", "-t", required=True, help="OpenAI-compatible chat endpoint URL")
@click.option("--api-key", "-k", envvar="OPENAI_API_KEY", default="", help="API key")
@click.option("--model", "-m", default="gpt-4", help="Model to test")
@click.option("--output", "-o", default="agentsec-report", help="Output file prefix")
@click.option("--format", "fmt", type=click.Choice(["json", "md", "html", "all"]), default="all")
@click.option("--modules", help="Comma-separated attack modules (default: all)")
def scan(target: str, api_key: str, model: str, output: str, fmt: str, modules: Optional[str]):
    """Run security test suite against an AI agent endpoint."""
    scanner = Scanner(target=target, api_key=api_key, model=model)

    selected = modules.split(",") if modules else None
    results = asyncio.run(scanner.run(selected_modules=selected))

    # Display results table
    table = Table(title="AgentSec Scan Results", show_lines=True)
    table.add_column("Module", style="cyan")
    table.add_column("Test", style="white")
    table.add_column("Severity", style="yellow")
    table.add_column("Result", style="bold")
    table.add_column("Details", max_width=50)

    passed = sum(1 for r in results.tests if r.passed)
    failed = len(results.tests) - passed

    for t in results.tests:
        status = "[green]PASS[/green]" if t.passed else "[red]FAIL[/red]"
        sev_colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue", "info": "dim"}
        sev_style = sev_colors.get(t.severity, "white")
        table.add_row(t.module, t.name, f"[{sev_style}]{t.severity}[/{sev_style}]", status, t.details or "")

    console.print(table)
    console.print(f"\n[bold]Score:[/bold] {results.score}/100  |  "
                  f"[green]Passed: {passed}[/green]  |  [red]Failed: {failed}[/red]\n")

    # Generate reports
    if fmt in ("json", "all"):
        p = Path(f"{output}.json")
        p.write_text(generate_json(results))
        console.print(f"📄 JSON report: {p}")
    if fmt in ("md", "all"):
        p = Path(f"{output}.md")
        p.write_text(generate_markdown(results))
        console.print(f"📄 Markdown report: {p}")
    if fmt in ("html", "all"):
        p = Path(f"{output}.html")
        p.write_text(generate_html(results))
        console.print(f"📄 HTML report: {p}")

    sys.exit(0 if results.score >= 70 else 1)


@main.command()
@click.option("--port", "-p", default=8080, help="MCP server port")
def serve(port: int):
    """Start MCP server for Claude Desktop integration."""
    from agentsec.mcp.server import run_server
    run_server(port=port)


if __name__ == "__main__":
    main()
