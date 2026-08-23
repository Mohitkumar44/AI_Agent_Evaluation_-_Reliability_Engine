"""
AgentGuard CI - Failure Detectors Package
"""

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
from .registry import DetectorRegistry

__all__ = [
    "BaseDetector",
    "UnauthorizedToolDetector",
    "DestructiveActionDetector",
    "ToolMisuseDetector",
    "ToolLoopDetector",
    "HallucinatedSuccessDetector",
    "PromptInjectionDetector",
    "GoalDriftDetector",
    "InstructionConflictDetector",
    "RecoveryFailureDetector",
    "DetectorRegistry",
]
