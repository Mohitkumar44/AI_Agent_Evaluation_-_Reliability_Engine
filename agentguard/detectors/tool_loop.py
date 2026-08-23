"""
AgentGuard CI - Tool Loop Detector
Module: Yogesh's Module (Failure Detection Engine)
"""

import json
from typing import Optional
from .base import BaseDetector
from ..models import Scenario, ExecutionTrace, FailureResult
from ..taxonomy import FailureType, Severity, FAILURE_DESCRIPTIONS


class ToolLoopDetector(BaseDetector):
    """
    Detector 4: Tool Loop
    Detects repeated or cyclical tool calls exceeding a configured retry limit.
    """

    detector_name = "tool_loop_detector"

    def __init__(self, loop_threshold: int = 3):
        self.loop_threshold = loop_threshold

    def detect(self, scenario: Scenario, trace: ExecutionTrace) -> Optional[FailureResult]:
        configured_limit = scenario.guardrails.get("max_tool_calls", self.loop_threshold)
        tool_calls = trace.tool_calls

        if len(tool_calls) < 2:
            return None

        consecutive_count = 1
        last_signature = ""
        loop_found = False
        loop_evidence = []

        for tc in tool_calls:
            sig = f"{tc.tool_name}:{json.dumps(tc.parameters or {}, sort_keys=True)}"
            if sig == last_signature:
                consecutive_count += 1
                if consecutive_count >= configured_limit:
                    loop_found = True
                    loop_evidence.append(
                        f"Repeated tool invocation: '{tc.tool_name}' called {consecutive_count} times sequentially with identical parameters."
                    )
                    break
            else:
                consecutive_count = 1
                last_signature = sig

        # Also check total identical calls across the entire trace
        if not loop_found:
            call_counts = {}
            for tc in tool_calls:
                sig = f"{tc.tool_name}:{json.dumps(tc.parameters or {}, sort_keys=True)}"
                call_counts[sig] = call_counts.get(sig, 0) + 1
                if call_counts[sig] >= configured_limit:
                    loop_found = True
                    loop_evidence.append(
                        f"Tool signature '{tc.tool_name}' invoked {call_counts[sig]} times across execution steps."
                    )
                    break

        if loop_found:
            meta = FAILURE_DESCRIPTIONS[FailureType.TOOL_LOOP]
            return FailureResult(
                scenario_id=scenario.scenario_id,
                failure_type=FailureType.TOOL_LOOP,
                severity=Severity.HIGH,
                description=f"Tool loop detected: Agent executed {consecutive_count} consecutive identical tool calls exceeding threshold ({configured_limit}).",
                evidence=loop_evidence,
                detector=self.detector_name,
                root_cause=meta["root_cause"],
                recommendation=meta["recommendation"],
            )

        return None
