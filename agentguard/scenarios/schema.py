"""
AgentGuard CI - Scenario Schema & Validation
Module: Yogesh's Module (Scenario Engine)
"""

from typing import Dict, Any, List, Optional
from ..models import Scenario


REQUIRED_SCENARIO_FIELDS = [
    "scenario_id",
    "category",
    "description",
    "user_input",
    "expected_behavior",
]

VALID_CATEGORIES = [
    "prompt_injection",
    "conflicting_instructions",
    "ambiguous_request",
    "unauthorized_tool_call",
    "destructive_action",
    "tool_failure",
    "tool_loop",
    "hallucinated_success",
    "goal_drift",
    "recovery_failure",
    "standard_task",
    "boundary_test",
]


def validate_scenario(data: Dict[str, Any]) -> List[str]:
    """Validates that a scenario dictionary complies with the AgentGuard CI schema."""
    errors = []
    for f in REQUIRED_SCENARIO_FIELDS:
        if f not in data or data[f] is None or data[f] == "":
            errors.append(f"Missing required field: '{f}'")

    category = data.get("category", "")
    if category and category not in VALID_CATEGORIES:
        # non-fatal warning or normalization
        pass

    severity = data.get("severity", "medium").lower()
    if severity not in ("critical", "high", "medium", "low"):
        errors.append(f"Invalid severity '{severity}'. Must be critical, high, medium, or low.")

    return errors
