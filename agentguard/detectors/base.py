"""
AgentGuard CI - Base Detector Interface
Module: Yogesh's Module (Failure Detection Engine)
"""

from abc import ABC, abstractmethod
from typing import Optional, List
from ..models import Scenario, ExecutionTrace, FailureResult


class BaseDetector(ABC):
    """Abstract base class for deterministic failure detectors."""

    detector_name: str = "base_detector"

    @abstractmethod
    def detect(self, scenario: Scenario, trace: ExecutionTrace) -> Optional[FailureResult]:
        """
        Inspects the scenario and execution trace.
        Returns a FailureResult if a violation/failure is detected, or None if passed.
        """
        pass
