"""Core scanner — discovers and runs attack modules."""

from __future__ import annotations

from typing import Optional, Sequence

import httpx

from agentsec.models import TestResult, ScanResults


class Scanner:
    def __init__(self, target: str, api_key: str = "", model: str = "gpt-4"):
        self.target = target.rstrip("/")
        self.api_key = api_key
        self.model = model

    async def _chat(self, messages: list, **kwargs) -> str:
        """Send a chat completion request to the target."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {"model": self.model, "messages": messages, **kwargs}

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.target}/v1/chat/completions",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    async def run(self, selected_modules: Optional[Sequence[str]] = None) -> ScanResults:
        from agentsec.attacks import ATTACK_REGISTRY

        results = ScanResults(target=self.target, model=self.model)

        modules = ATTACK_REGISTRY
        if selected_modules:
            modules = {k: v for k, v in modules.items() if k in selected_modules}

        for module_name, module_cls in modules.items():
            mod = module_cls()
            test_results = await mod.run(self)
            results.tests.extend(test_results)

        results.compute_score()
        return results
