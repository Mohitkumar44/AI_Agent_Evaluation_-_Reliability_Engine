"""
AgentGuard CI - Detector Registry & Coordinator
Module: Yogesh's Module (Failure Detection Engine)
"""

from typing import List, Dict, Type, Optional
from .base import BaseDetector
from .unauthorized_tool import UnauthorizedToolDetector
from .destructive_action import DestructiveActionDetector
from .tool_misuse import ToolMisuseDetector
from .tool_loop import ToolLoopDetector
from .hallucinated_success import HallucinatedSuccessDetector
from .prompt_injection import PromptInjectionDetector
from .goal_drift import GoalDriftDetector
from .instruction_conflict import InstructionConflictDetector
from .recovery_failure import RecoveryFailureDetector
from ..models import Scenario, ExecutionTrace, FailureResult


class DetectorRegistry:
    """Coordinates and executes all registered failure detectors."""

    def __init__(self, custom_detectors: Optional[List[BaseDetector]] = None):
        if custom_detectors is not None:
            self.detectors = custom_detectors
        else:
            self.detectors: List[BaseDetector] = [
                UnauthorizedToolDetector(),
                DestructiveActionDetector(),
                ToolMisuseDetector(),
                ToolLoopDetector(),
                HallucinatedSuccessDetector(),
                PromptInjectionDetector(),
                GoalDriftDetector(),
                InstructionConflictDetector(),
                RecoveryFailureDetector(),
            ]

    def register(self, detector: BaseDetector) -> None:
        self.detectors.append(detector)

    def run_all(self, scenario: Scenario, trace: ExecutionTrace) -> List[FailureResult]:
        """
        Runs all detectors against the scenario and trace.
        Returns a list of all detected failures (empty if clean pass).
        """
        failures = []
        for detector in self.detectors:
            try:
                res = detector.detect(scenario, trace)
                if res is not None:
                    failures.append(res)
            except Exception as e:
                # Fail-safe detector logging
                print(f"[AgentGuard Warning] Error in detector {detector.detector_name}: {e}")

        return failures
