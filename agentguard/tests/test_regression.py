"""
AgentGuard CI - Unit Tests for Version Regression Comparison
"""

import unittest
from agentguard.models import EvaluationSummary, Scorecard, FailureResult
from agentguard.regression import RegressionComparator
from agentguard.taxonomy import FailureType, Severity


class TestRegression(unittest.TestCase):

    def test_version_regression_detects_safety_drop(self):
        v1_summary = EvaluationSummary(
            agent_version="v1.0.0",
            scenarios_total=20,
            passed=19,
            failed=1,
            critical_failures=0,
            high_failures=1,
            medium_failures=0,
            low_failures=0,
            scores=Scorecard(95, 96, 90, 92, 85, 92.5),
            ci_status="PASS",
            failures=[
                FailureResult(
                    scenario_id="SC-011",
                    failure_type=FailureType.RECOVERY_FAILURE,
                    severity=Severity.HIGH,
                    description="Minor timeout",
                )
            ],
        )

        v2_summary = EvaluationSummary(
            agent_version="v2.0.0",
            scenarios_total=20,
            passed=15,
            failed=5,
            critical_failures=2,
            high_failures=2,
            medium_failures=1,
            low_failures=0,
            scores=Scorecard(75, 60, 70, 80, 70, 70.5),
            ci_status="BLOCK",
            failures=[
                FailureResult(
                    scenario_id="SC-001",
                    failure_type=FailureType.UNSAFE_DESTRUCTIVE_ACTION,
                    severity=Severity.CRITICAL,
                    description="Destructive deletion",
                ),
                FailureResult(
                    scenario_id="SC-004",
                    failure_type=FailureType.UNAUTHORIZED_TOOL_CALL,
                    severity=Severity.CRITICAL,
                    description="Unauthorized drop",
                ),
                FailureResult(
                    scenario_id="SC-012",
                    failure_type=FailureType.TOOL_LOOP,
                    severity=Severity.HIGH,
                    description="Loop trap",
                ),
            ],
        )

        diff = RegressionComparator.compare(v1_summary, v2_summary)

        self.assertEqual(diff["v1_overall"], 92.5)
        self.assertEqual(diff["v2_overall"], 70.5)
        self.assertEqual(diff["score_delta"], -22.0)
        self.assertEqual(diff["new_critical_failures"], 2)
        self.assertTrue(diff["has_regression"])
        self.assertEqual(diff["ci_status"], "BLOCK")

        # Check new failure types detected
        new_types = [nft["type"] for nft in diff["new_failure_types"]]
        self.assertIn("UNSAFE_DESTRUCTIVE_ACTION", new_types)
        self.assertIn("UNAUTHORIZED_TOOL_CALL", new_types)


if __name__ == "__main__":
    unittest.main()
