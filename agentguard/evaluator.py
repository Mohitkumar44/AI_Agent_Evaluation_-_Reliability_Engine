"""
AgentGuard CI - Main Evaluation Pipeline & Orchestrator
Module: Yogesh's Module (Core Evaluation Engine)
"""

from typing import List, Dict, Any, Optional
from .models import (
    Scenario,
    ExecutionTrace,
    ScenarioEvaluationResult,
    EvaluationSummary,
    FailureResult,
    GuardrailResult,
)
from .detectors.registry import DetectorRegistry
from .guardrails.engine import GuardrailEngine
from .scoring.scorer import ReliabilityScorer
from .scenarios.benchmark_data import get_all_scenarios
from .mock_runner import TraceAdapter, MockAgentRunner


class AgentGuardEvaluator:
    """
    Main Evaluation Engine for AgentGuard CI.
    Orchestrates the entire evaluation workflow:
      Scenario + Trace -> Detectors -> Guardrails -> Scoring -> CI PASS/BLOCK.
    """

    def __init__(
        self,
        detector_registry: Optional[DetectorRegistry] = None,
        guardrail_engine: Optional[GuardrailEngine] = None,
        scorer: Optional[ReliabilityScorer] = None,
    ):
        self.registry = detector_registry or DetectorRegistry()
        self.guardrails = guardrail_engine or GuardrailEngine()
        self.scorer = scorer or ReliabilityScorer()

    def evaluate_scenario_trace(
        self,
        scenario: Scenario,
        trace: ExecutionTrace,
    ) -> ScenarioEvaluationResult:
        """Evaluates a single scenario execution trace."""
        # 1. Run all failure detectors
        failures = self.registry.run_all(scenario, trace)

        # 2. Run guardrail rules
        guardrail_results = self.guardrails.evaluate_trace(scenario, trace)

        # 3. Calculate dimension scores for this scenario
        scorecard = self.scorer.calculate_scenario_scores(
            scenario=scenario,
            failures=failures,
            guardrails=guardrail_results,
            trace=trace,
        )

        passed = len(failures) == 0 and all(g.passed for g in guardrail_results)

        return ScenarioEvaluationResult(
            scenario_id=scenario.scenario_id,
            passed=passed,
            failures=failures,
            guardrail_results=guardrail_results,
            scorecard=scorecard,
            trace=trace,
        )

    def evaluate_suite(
        self,
        agent_config: Dict[str, Any],
        scenarios: Optional[List[Scenario]] = None,
        simulate_regression: bool = False,
    ) -> EvaluationSummary:
        """
        Executes and evaluates an entire suite of scenarios against an agent.
        """
        scenario_list = scenarios or get_all_scenarios()
        agent_version = agent_config.get("version", "v1.0.0")

        scenario_results: List[ScenarioEvaluationResult] = []

        for scen in scenario_list:
            trace = MockAgentRunner.run_scenario(
                agent_config=agent_config,
                scenario=scen,
                simulate_regression=simulate_regression,
            )
            eval_res = self.evaluate_scenario_trace(scen, trace)
            scenario_results.append(eval_res)

        # Aggregate results across all scenarios and apply Hard Safety Gate
        summary = self.scorer.aggregate_evaluation(
            agent_version=agent_version,
            results=scenario_results,
        )
        return summary
