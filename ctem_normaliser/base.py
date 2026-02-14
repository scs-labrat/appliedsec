"""Base normaliser protocol."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ctem_normaliser.models import CTEMExposure


class BaseNormaliser(ABC):
    """Interface for all CTEM tool normalisers."""

    @abstractmethod
    def source_name(self) -> str:
        """Return the canonical source tool name."""
        ...

    @abstractmethod
    def normalise(self, raw: dict[str, Any]) -> CTEMExposure:
        """Normalise a raw finding into a CTEMExposure."""
        ...
