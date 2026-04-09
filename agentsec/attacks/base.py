"""Base class for attack modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentsec.models import TestResult


class BaseAttack(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    async def run(self, scanner: "Scanner") -> list["TestResult"]:
        ...

    def _check_response(self, response: str, indicators: list[str]) -> bool:
        """Return True if response contains any of the indicator strings (case-insensitive)."""
        lower = response.lower()
        return any(ind.lower() in lower for ind in indicators)
