"""
AgentGuard CI - Core Data Models
Module: Yogesh's Module (Agent Reliability, Failure Detection & Taxonomy)
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Union
from .taxonomy import Severity, FailureType


@dataclass
class GuardrailConfig:
    confirmation_required: bool = False
    max_tool_calls: int = 5
    parameter_limits: Dict[str, Any] = field(default_factory=dict)
    policy_checks: List[str] = field(default_factory=list)
    restricted_keywords: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Scenario:
    scenario_id: str
    category: str
    description: str
    user_input: str
    expected_behavior: str
    allowed_tools: List[str] = field(default_factory=list)
    expected_tool_calls: List[str] = field(default_factory=list)
    severity: str = "medium"  # critical, high, medium, low
    guardrails: Dict[str, Any] = field(default_factory=dict)
    potential_failure: Optional[str] = None
    allowed_behavior: Optional[str] = None
    system_prompt_override: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Scenario":
        return cls(
            scenario_id=data.get("scenario_id", "SC-UNKNOWN"),
            category=data.get("category", "general"),
            description=data.get("description", ""),
            user_input=data.get("user_input", data.get("initialPrompt", "")),
            expected_behavior=data.get("expected_behavior", data.get("expectedOutcome", "")),
            allowed_tools=data.get("allowed_tools", []),
            expected_tool_calls=data.get("expected_tool_calls", []),
            severity=data.get("severity", "medium").lower(),
            guardrails=data.get("guardrails", {}),
            potential_failure=data.get("potential_failure", data.get("targetCategory", None)),
            allowed_behavior=data.get("allowed_behavior", None),
            system_prompt_override=data.get("system_prompt_override", None),
            tags=data.get("tags", []),
        )


@dataclass
class ToolCall:
    tool_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    tool_response: Dict[str, Any] = field(default_factory=dict)
    step_number: Optional[int] = None
    timestamp: Optional[str] = None
    is_violation: bool = False
    state_diff: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TraceStep:
    step_number: int
    type: str  # USER_INPUT, MODEL_THOUGHT, TOOL_CALL, MODEL_OUTPUT, GUARDRAIL_INTERCEPT
    sender: str
    content: Optional[str] = None
    tool_name: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    tool_response: Optional[Dict[str, Any]] = None
    state_diff: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None
    is_violation: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionTrace:
    trace_id: str
    agent_id: str
    agent_name: str
    agent_version: str
    scenario_id: str
    steps: List[TraceStep] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[str] = None
    status: str = "COMPLETED"  # COMPLETED, TIMEOUT, ERROR

    @property
    def tool_calls(self) -> List[ToolCall]:
        calls = []
        for s in self.steps:
            if s.type in ("TOOL_CALL", "TOOL_INVOCATION") and s.tool_name:
                calls.append(
                    ToolCall(
                        tool_name=s.tool_name,
                        parameters=s.parameters or {},
                        tool_response=s.tool_response or {},
                        step_number=s.step_number,
                        timestamp=s.timestamp,
                        is_violation=s.is_violation,
                        state_diff=s.state_diff or {},
                    )
                )
        return calls

    @property
    def final_output(self) -> str:
        for s in reversed(self.steps):
            if s.type in ("MODEL_OUTPUT", "AGENT_RESPONSE") and s.content:
                return s.content
        return ""

    @property
    def thoughts(self) -> List[str]:
        return [s.content for s in self.steps if s.type in ("MODEL_THOUGHT", "THINKING") and s.content]

    @property
    def user_inputs(self) -> List[str]:
        return [s.content for s in self.steps if s.type in ("USER_INPUT", "USER_PROMPT") and s.content]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "agent_version": self.agent_version,
            "scenario_id": self.scenario_id,
            "steps": [s.to_dict() for s in self.steps],
            "metrics": self.metrics,
            "timestamp": self.timestamp,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionTrace":
        steps_raw = data.get("steps", [])
        steps = []
        for i, s in enumerate(steps_raw):
            steps.append(
                TraceStep(
                    step_number=s.get("step_number", s.get("stepNumber", i + 1)),
                    type=s.get("type", "TOOL_CALL"),
                    sender=s.get("sender", "Agent"),
                    content=s.get("content", None),
                    tool_name=s.get("tool_name", s.get("toolName", None)),
                    parameters=s.get("parameters", None),
                    tool_response=s.get("tool_response", s.get("toolResponse", None)),
                    state_diff=s.get("state_diff", s.get("stateDiff", None)),
                    timestamp=s.get("timestamp", None),
                    is_violation=s.get("is_violation", s.get("isViolation", False)),
                )
            )
        return cls(
            trace_id=data.get("trace_id", data.get("id", f"trace-{data.get('scenario_id', 'anon')}")),
            agent_id=data.get("agent_id", data.get("agentId", "agent-unknown")),
            agent_name=data.get("agent_name", data.get("agentName", "Unknown Agent")),
            agent_version=data.get("agent_version", data.get("version", "v1.0")),
            scenario_id=data.get("scenario_id", data.get("scenarioId", "SC-UNKNOWN")),
            steps=steps,
            metrics=data.get("metrics", {}),
            timestamp=data.get("timestamp", None),
            status=data.get("status", "COMPLETED"),
        )


@dataclass
class FailureResult:
    scenario_id: str
    failure_type: FailureType
    severity: Severity
    description: str
    evidence: List[str] = field(default_factory=list)
    detector: str = "generic_detector"
    root_cause: Optional[str] = None
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "failure_type": self.failure_type.value if isinstance(self.failure_type, FailureType) else str(self.failure_type),
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "description": self.description,
            "evidence": self.evidence,
            "detector": self.detector,
            "root_cause": self.root_cause,
            "recommendation": self.recommendation,
        }


@dataclass
class GuardrailResult:
    guardrail: str
    passed: bool
    severity: Severity
    evidence: str
    blocked: bool = False  # True if guardrail actively intercepted & prevented unsafe action

    def to_dict(self) -> Dict[str, Any]:
        return {
            "guardrail": self.guardrail,
            "passed": self.passed,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "evidence": self.evidence,
            "blocked": self.blocked,
        }


@dataclass
class Scorecard:
    task_success: float
    safety: float
    tool_reliability: float
    instruction_following: float
    recovery: float
    overall: float

    def to_dict(self) -> Dict[str, float]:
        return {
            "task_success": round(self.task_success, 1),
            "safety": round(self.safety, 1),
            "tool_reliability": round(self.tool_reliability, 1),
            "instruction_following": round(self.instruction_following, 1),
            "recovery": round(self.recovery, 1),
            "overall": round(self.overall, 1),
        }


@dataclass
class ScenarioEvaluationResult:
    scenario_id: str
    passed: bool
    failures: List[FailureResult] = field(default_factory=list)
    guardrail_results: List[GuardrailResult] = field(default_factory=list)
    scorecard: Optional[Scorecard] = None
    trace: Optional[ExecutionTrace] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "passed": self.passed,
            "failures": [f.to_dict() for f in self.failures],
            "guardrail_results": [g.to_dict() for g in self.guardrail_results],
            "scorecard": self.scorecard.to_dict() if self.scorecard else None,
        }


@dataclass
class EvaluationSummary:
    agent_version: str
    scenarios_total: int
    passed: int
    failed: int
    critical_failures: int
    high_failures: int
    medium_failures: int
    low_failures: int
    scores: Scorecard
    ci_status: str  # "PASS" or "BLOCK"
    failures: List[FailureResult] = field(default_factory=list)
    guardrail_violations: List[GuardrailResult] = field(default_factory=list)
    scenario_results: List[ScenarioEvaluationResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_frontend_json(self) -> Dict[str, Any]:
        return {
            "agent_version": self.agent_version,
            "scenarios_total": self.scenarios_total,
            "passed": self.passed,
            "failed": self.failed,
            "critical_failures": self.critical_failures,
            "high_failures": self.high_failures,
            "medium_failures": self.medium_failures,
            "scores": self.scores.to_dict(),
            "ci_status": self.ci_status,
            "failures": [f.to_dict() for f in self.failures],
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_version": self.agent_version,
            "scenarios_total": self.scenarios_total,
            "passed": self.passed,
            "failed": self.failed,
            "critical_failures": self.critical_failures,
            "high_failures": self.high_failures,
            "medium_failures": self.medium_failures,
            "low_failures": self.low_failures,
            "scores": self.scores.to_dict(),
            "ci_status": self.ci_status,
            "failures": [f.to_dict() for f in self.failures],
            "guardrail_violations": [g.to_dict() for g in self.guardrail_violations],
            "metadata": self.metadata,
        }
