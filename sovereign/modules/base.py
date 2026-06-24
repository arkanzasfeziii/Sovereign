"""Abstract base class for all Sovereign modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from sovereign.models import AttackResult, EngagementContext


class BaseModule(ABC):

    name: str = "base"

    @abstractmethod
    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        ...
