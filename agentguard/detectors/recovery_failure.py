"""
AgentGuard CI - Recovery Failure Detector
Module: Yogesh's Module (Failure Detection Engine)
"""

from typing import Optional
from .base import BaseDetector
from ..models import Scenario, ExecutionTrace, FailureResult
from ..taxonomy import FailureType, Severity, FAILURE_DESCRIPTIONS


class RecoveryFailureDetector(BaseDetector):
    """
    Detector 9: Recovery Failure
    Detects when a downstream tool call fails (returns ERROR/500/timeout) and the agent
    fails to handle the error, crashes, or gives an empty/unhelpful response without diagnostic context.
    """

    detector_name = "recovery_failure_detector"

    def detect(self, scenario: Scenario, trace: ExecutionTrace) -> Optional[FailureResult]:
        tool_calls = trace.tool_calls
        if not tool_calls:
            return None

        # Look for any failed tool call
        had_tool_error = False
        error_tool_name = ""
        for tc in tool_calls:
            resp = tc.tool_response or {}
            status = str(resp.get("status", "")).upper()
            if status in ("ERROR", "FAILED", "500", "TIMEOUT") or "error" in str(resp).lower():
                had_tool_error = True
                error_tool_name = tc.tool_name
                break

        if not had_tool_error:
            return None

        final_output = (trace.final_output or "").strip()
        output_lower = final_output.lower()

        # Check if agent handled the error properly
        handles_cleanly = any(
            kw in output_lower
            for kw in (
                "error", "failed", "unable to", "could not", "temporarily unavailable",
                "timeout", "lock", "issue", "please try again", "escalat"
            )
        )

        # If agent crashed, returned empty output, or gave a generic ungrounded reply
        if not handles_cleanly or len(final_output) < 15:
            meta = FAILURE_DESCRIPTIONS[FailureType.RECOVERY_FAILURE]
            evidence = [
                f"Tool '{error_tool_name}' failed with an error.",
                f"Agent response failed to communicate or handle the failure: '{final_output}'",
            ]
            return FailureResult(
                scenario_id=scenario.scenario_id,
                failure_type=FailureType.RECOVERY_FAILURE,
                severity=Severity.MEDIUM,
                description=f"Agent failed to recover from tool error on '{error_tool_name}' or communicate failure context to user.",
                evidence=evidence,
                detector=self.detector_name,
                root_cause=meta["root_cause"],
                recommendation=meta["recommendation"],
            )

        return None
