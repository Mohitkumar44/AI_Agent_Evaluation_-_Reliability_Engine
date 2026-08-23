"""
AgentGuard CI - End-to-End Pipeline Evaluation Tests
"""

import unittest
from agentguard.evaluator import AgentGuardEvaluator
from agentguard.scenarios import get_all_scenarios
from agentguard.regression import RegressionComparator


class TestEvaluatorE2E(unittest.TestCase):

    def setUp(self):
        self.evaluator = AgentGuardEvaluator()
        self.agent_v1 = {
            "id": "agent-sre-v1",
            "name": "Cloud DevOps SRE Agent",
            "version": "v1.0.0",
            "tools": [{"name": "list_pods"}, {"name": "fetch_pod_logs"}, {"name": "delete_resource"}],
        }
        self.agent_v2 = {
            "id": "agent-sre-v2",
            "name": "Cloud DevOps SRE Agent (Regressed)",
            "version": "v2.0.0-unaligned",
            "tools": [{"name": "list_pods"}, {"name": "fetch_pod_logs"}, {"name": "delete_resource"}],
        }

    def test_full_e2e_evaluation_v1_passes(self):
        scenarios = get_all_scenarios()
        summary = self.evaluator.evaluate_suite(
            agent_config=self.agent_v1,
            scenarios=scenarios,
            simulate_regression=False,
        )

        self.assertGreater(summary.scores.overall, 85.0)
        self.assertEqual(summary.critical_failures, 0)
        self.assertEqual(summary.ci_status, "PASS")

        frontend_json = summary.to_frontend_json()
        self.assertIn("agent_version", frontend_json)
        self.assertIn("scores", frontend_json)
        self.assertIn("ci_status", frontend_json)
        self.assertEqual(frontend_json["ci_status"], "PASS")

    def test_full_e2e_evaluation_v2_blocked(self):
        scenarios = get_all_scenarios()
        summary = self.evaluator.evaluate_suite(
            agent_config=self.agent_v2,
            scenarios=scenarios,
            simulate_regression=True,
        )

        self.assertGreater(summary.critical_failures, 0)
        self.assertEqual(summary.ci_status, "BLOCK")

        frontend_json = summary.to_frontend_json()
        self.assertEqual(frontend_json["ci_status"], "BLOCK")

    def test_version_regression_workflow_e2e(self):
        scenarios = get_all_scenarios()
        v1_sum = self.evaluator.evaluate_suite(self.agent_v1, scenarios, simulate_regression=False)
        v2_sum = self.evaluator.evaluate_suite(self.agent_v2, scenarios, simulate_regression=True)

        diff = RegressionComparator.compare(v1_sum, v2_sum)

        self.assertTrue(diff["has_regression"])
        self.assertEqual(diff["ci_status"], "BLOCK")
        self.assertGreater(diff["new_critical_failures"], 0)


if __name__ == "__main__":
    unittest.main()
