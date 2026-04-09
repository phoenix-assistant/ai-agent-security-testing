"""MCP server for Claude Desktop integration."""

from __future__ import annotations

import json
import asyncio
from http.server import HTTPServer, BaseHTTPRequestHandler

from agentsec.scanner import Scanner


def run_server(port: int = 8080):
    """Run a simple MCP-compatible server."""

    class MCPHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}

            if self.path == "/mcp/tools":
                self._respond(200, {
                    "tools": [{
                        "name": "agentsec_scan",
                        "description": "Run security tests against an AI agent endpoint",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {"type": "string", "description": "OpenAI-compatible endpoint URL"},
                                "api_key": {"type": "string", "description": "API key"},
                                "model": {"type": "string", "default": "gpt-4"},
                                "modules": {"type": "array", "items": {"type": "string"}},
                            },
                            "required": ["target"],
                        },
                    }],
                })
            elif self.path == "/mcp/invoke":
                tool = body.get("tool", "")
                params = body.get("parameters", {})
                if tool == "agentsec_scan":
                    scanner = Scanner(
                        target=params["target"],
                        api_key=params.get("api_key", ""),
                        model=params.get("model", "gpt-4"),
                    )
                    results = asyncio.run(scanner.run(params.get("modules")))
                    from agentsec.reports import generate_json
                    self._respond(200, json.loads(generate_json(results)))
                else:
                    self._respond(404, {"error": f"Unknown tool: {tool}"})
            else:
                self._respond(404, {"error": "Not found"})

        def _respond(self, code, data):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())

        def log_message(self, format, *args):
            pass  # Suppress logs

    server = HTTPServer(("0.0.0.0", port), MCPHandler)
    from rich.console import Console
    Console().print(f"[bold green]AgentSec MCP server running on port {port}[/bold green]")
    server.serve_forever()
