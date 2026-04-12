"""CLI entry point for Ai Agent Security Testing."""

from __future__ import annotations
import argparse
import sys

from .core import analyze, AnalysisConfig, format_results


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="ai-agent-security-testing",
        description="Red-team testing infrastructure using AI agents for security assessment",
    )
    parser.add_argument("targets", nargs="*", help="Targets to analyze")
    parser.add_argument("--format", choices=["json", "text"], default="text")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--version", action="version", version="0.1.0")

    args = parser.parse_args()

    config = AnalysisConfig(
        verbose=args.verbose,
        targets=args.targets,
        output_format=args.format,
    )

    result = analyze(config)
    print(format_results(result, args.format))
    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
