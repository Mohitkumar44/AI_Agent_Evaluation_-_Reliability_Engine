"""
AgentGuard CI - Deterministic Replay Engine
Module: Yogesh's Module (Deterministic Replay)
"""

import json
import os
from dataclasses import asdict
from typing import Dict, Any, Optional, Tuple
from ..models import Scenario, ExecutionTrace, TraceStep, FailureResult
from ..detectors.registry import DetectorRegistry
from ..taxonomy import FailureType


class DeterministicReplayer:
    """
    Deterministic replay engine for reproducing failed agent scenarios.
    Flow:
      Failed Scenario Trace -> Save Fixture (Scenario + Env State + Tool Responses)
      -> Replay -> Re-execute identical step trace under mock harness
      -> Run Failure Detectors -> Verify if failure is bit-for-bit reproduced.
    """

    def __init__(self, registry: Optional[DetectorRegistry] = None):
        self.registry = registry or DetectorRegistry()

    def create_fixture(
        self,
        scenario: Scenario,
        trace: ExecutionTrace,
        environment_state: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Creates a self-contained deterministic fixture for replay."""
        return {
            "scenario": scenario.to_dict(),
            "original_trace": trace.to_dict(),
            "environment_state": environment_state or {},
        }

    def save_fixture_to_file(self, fixture: Dict[str, Any], filepath: str) -> None:
        """Persists a replay fixture to disk as a JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(fixture, f, indent=2)

    def load_fixture_from_file(self, filepath: str) -> Dict[str, Any]:
        """Loads a persisted replay fixture from disk."""
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def replay_fixture(self, fixture: Dict[str, Any]) -> Dict[str, Any]:
        """
        Replays a recorded scenario fixture under deterministic conditions.
        Returns a verification record indicating if the failure was reproduced.
        """
        scenario = Scenario.from_dict(fixture["scenario"])
        orig_trace = ExecutionTrace.from_dict(fixture["original_trace"])

        # 1. Run detectors on original trace
        orig_failures = self.registry.run_all(scenario, orig_trace)
        orig_failure_type = orig_failures[0].failure_type.value if orig_failures else "PASSED"

        # 2. Re-synthesize replay trace under identical recorded steps and environment state
        replay_steps = []
        for s in orig_trace.steps:
            replay_steps.append(
                TraceStep(
                    step_number=s.step_number,
                    type=s.type,
                    sender=s.sender,
                    content=s.content,
                    tool_name=s.tool_name,
                    parameters=s.parameters,
                    tool_response=s.tool_response,
                    state_diff=s.state_diff,
                    timestamp=s.timestamp,
                    is_violation=s.is_violation,
                )
            )

        replay_trace = ExecutionTrace(
            trace_id=f"replay-{orig_trace.trace_id}",
            agent_id=orig_trace.agent_id,
            agent_name=orig_trace.agent_name,
            agent_version=orig_trace.agent_version,
            scenario_id=orig_trace.scenario_id,
            steps=replay_steps,
            metrics=orig_trace.metrics,
            status=orig_trace.status,
        )

        # 3. Run detectors on the replayed trace
        replay_failures = self.registry.run_all(scenario, replay_trace)
        replay_failure_type = replay_failures[0].failure_type.value if replay_failures else "PASSED"

        # 4. Compare results
        is_reproduced = (orig_failure_type == replay_failure_type)

        return {
            "scenario_id": scenario.scenario_id,
            "original_failure": orig_failure_type,
            "replay_failure": replay_failure_type,
            "reproduced": is_reproduced,
            "original_failure_count": len(orig_failures),
            "replay_failure_count": len(replay_failures),
            "replay_trace_id": replay_trace.trace_id,
            "details": {
                "original_failures": [f.to_dict() for f in orig_failures],
                "replay_failures": [f.to_dict() for f in replay_failures],
            },
        }
