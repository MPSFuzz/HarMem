from __future__ import annotations

from typing import Dict, Any
from abc import ABC, abstractmethod

class HarnessAnalysisBackend(ABC):
    backend_name = "base"

    @abstractmethod
    def parse_code(self, code: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def extract_raw(self, code: str) -> Dict[str, Any]:
         """
        Return backend-specific raw syntax information.
        The normalization into reusable structure facts happens later.
        """
         raise NotImplementedError