"""
AgentGuard CI - Autonomous AI Agent Reliability, Safety & Failure Detection Engine
Module: Yogesh's Module (Agent Reliability, Scenarios, Failure Taxonomy & Evaluation)
"""

from .taxonomy import Severity, FailureType, FAILURE_DESCRIPTIONS
from .models import (
    Scenario,
    ExecutionTrace,
    TraceStep,
    ToolCall,
    FailureResult,
    GuardrailResult,
    Scorecard,
    ScenarioEvaluationResult,
    EvaluationSummary,
)
from .detectors import (
    BaseDetector,
    UnauthorizedToolDetector,
    DestructiveActionDetector,
    ToolMisuseDetector,
    ToolLoopDetector,
    HallucinatedSuccessDetector,
    PromptInjectionDetector,
    GoalDriftDetector,
    InstructionConflictDetector,
    RecoveryFailureDetector,
    DetectorRegistry,
)
from .guardrails import (
    BaseGuardrailRule,
    DestructiveConfirmationGuardrail,
    ToolAuthorizationGuardrail,
    ParameterLimitGuardrail,
    LoopProtectionGuardrail,
    GuardrailEngine,
)
from .scoring import ReliabilityScorer
from .regression import RegressionComparator
from .replay import DeterministicReplayer
from .evaluator import AgentGuardEvaluator
from .scenarios.benchmark_data import get_all_scenarios, get_scenario_by_id, BENCHMARK_SCENARIOS
from .scenarios.generator import ScenarioGenerator

__version__ = "1.0.0"

__all__ = [
    "Severity",
    "FailureType",
    "FAILURE_DESCRIPTIONS",
    "Scenario",
    "ExecutionTrace",
    "TraceStep",
    "ToolCall",
    "FailureResult",
    "GuardrailResult",
    "Scorecard",
    "ScenarioEvaluationResult",
    "EvaluationSummary",
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
    "BaseGuardrailRule",
    "DestructiveConfirmationGuardrail",
    "ToolAuthorizationGuardrail",
    "ParameterLimitGuardrail",
    "LoopProtectionGuardrail",
    "GuardrailEngine",
    "ReliabilityScorer",
    "RegressionComparator",
    "DeterministicReplayer",
    "AgentGuardEvaluator",
    "get_all_scenarios",
    "get_scenario_by_id",
    "BENCHMARK_SCENARIOS",
    "ScenarioGenerator",
]
