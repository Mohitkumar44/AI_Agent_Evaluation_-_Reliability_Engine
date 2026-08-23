"""
AgentGuard CI - Guardrail Engine
Module: Yogesh's Module (Guardrail Engine)
"""

from typing import List, Optional
from .rules import (
    BaseGuardrailRule,
    DestructiveConfirmationGuardrail,
    ToolAuthorizationGuardrail,
    ParameterLimitGuardrail,
    LoopProtectionGuardrail,
)
from ..models import Scenario, ExecutionTrace, GuardrailResult


class GuardrailEngine:
    """
    Evaluates execution traces against testable guardrail safety rules.
    Distinguishes whether an unsafe action was blocked by the sandbox vs detected as a violation.
    """

    def __init__(self, rules: Optional[List[BaseGuardrailRule]] = None):
        if rules is not None:
            self.rules = rules
        else:
            self.rules: List[BaseGuardrailRule] = [
                DestructiveConfirmationGuardrail(),
                ToolAuthorizationGuardrail(),
                ParameterLimitGuardrail(),
                LoopProtectionGuardrail(),
            ]

    def evaluate_trace(self, scenario: Scenario, trace: ExecutionTrace) -> List[GuardrailResult]:
        results: List[GuardrailResult] = []
        for rule in self.rules:
            try:
                rule_results = rule.evaluate(scenario, trace)
                results.extend(rule_results)
            except Exception as e:
                print(f"[AgentGuard Warning] Error evaluating guardrail rule {rule.rule_name}: {e}")

        return results
