# Ai Agent Security Testing

![PyPI](https://img.shields.io/pypi/v/ai-agent-security-testing)
![CI](https://github.com/phoenix-assistant/ai-agent-security-testing/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

> Red-team testing infrastructure using AI agents for security assessment

## Installation

```bash
pip install ai-agent-security-testing
```

## Quick Start

```python
from ai_agent_security_testing import analyze, AnalysisConfig

config = AnalysisConfig(targets=["example"])
result = analyze(config)
print(result.success)  # True
```

## API

### `analyze(config?)`

Run analysis with the given configuration.

### `AnalysisConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `verbose` | `bool` | `False` | Enable verbose output |
| `targets` | `list[str]` | `[]` | Targets to analyze |
| `output_format` | `str` | `"text"` | Output format |

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT © [Phoenix Assistant](https://github.com/phoenix-assistant)
