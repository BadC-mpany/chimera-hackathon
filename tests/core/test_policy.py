
import unittest
import logging
from src.ipg.policy import PolicyEngine

# Configure logging for tests
logging.basicConfig(level=logging.INFO)

class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.settings = {
            "policy": {
                "default_action": "production",
                "evaluation_order": [
                    "directives",
                    "trusted_workflows",
                    "security_policies",
                    "accumulated_risk_policies",
                    "risk_based_policies",
                ],
                "directives": {
                    "users": {"admin": {"action": "production", "reason": "Admin override"}},
                },
                "trusted_workflows": [
                    {
                        "id": "trusted-user",
                        "match": {
                            "all": [
                                {"field": "context.user_id", "operator": "eq", "value": "trusted_user"}
                            ]
                        },
                        "action": "production",
                    }
                ],
                "security_policies": [
                    {
                        "id": "block-root",
                        "match": {
                            "all": [
                                {"field": "args.path", "operator": "contains", "value": "/root"}
                            ]
                        },
                        "action": "shadow",
                        "reason": "Access to root is forbidden",
                    }
                ],
                "accumulated_risk_policies": {
                    "threshold": 2.0,
                    "action": "shadow",
                    "reason": "Accumulated risk exceeded",
                },
                "risk_based_policies": {
                    "risk_threshold": 0.8,
                    "min_confidence": 0.9,
                    "action": "shadow",
                    "low_confidence_action": "production",
                },
            },
            "backend": {"tools": {"read_file": {"category": "safe"}}},
        }
        self.policy_engine = PolicyEngine(self.settings)

    def test_directives_override(self):
        """Test that directives take precedence over everything else."""
        context = {"user_id": "admin", "accumulated_risk": 5.0}
        result = self.policy_engine.evaluate("read_file", {}, context, risk_score=1.0)
        self.assertEqual(result["route"], "production")
        self.assertIn("Admin override", result["reason"]) # Corrected assertion

    def test_trusted_workflow(self):
        """Test that trusted workflows allow access."""
        context = {"user_id": "trusted_user"}
        result = self.policy_engine.evaluate("read_file", {}, context, risk_score=0.9)
        self.assertEqual(result["route"], "production")
        self.assertEqual(result["rule_id"], "trusted-user")

    def test_security_policy_trigger(self):
        """Test that security policies trigger shadow routing."""
        context = {"user_id": "user"}
        args = {"path": "/root/secret"}
        result = self.policy_engine.evaluate("read_file", args, context, risk_score=0.0)
        self.assertEqual(result["route"], "shadow")
        self.assertEqual(result["rule_id"], "block-root")

    def test_accumulated_risk_trigger(self):
        """Test that accumulated risk triggers shadow routing."""
        context = {"user_id": "user", "accumulated_risk": 2.5}
        result = self.policy_engine.evaluate("read_file", {}, context, risk_score=0.0)
        self.assertEqual(result["route"], "shadow")
        self.assertEqual(result["rule_id"], "accumulated-risk-threshold")

    def test_risk_based_trigger(self):
        """Test that high real-time risk triggers shadow routing."""
        context = {"user_id": "user"}
        result = self.policy_engine.evaluate("read_file", {}, context, risk_score=0.9, confidence=1.0)
        self.assertEqual(result["route"], "shadow")
        self.assertEqual(result["rule_id"], "risk-based-high-confidence") # Corrected assertion

    def test_default_action(self):
        """Test fallback to default action."""
        context = {"user_id": "user"}
        result = self.policy_engine.evaluate("read_file", {}, context, risk_score=0.0)
        self.assertEqual(result["route"], "production")
        self.assertEqual(result["rule_id"], "default")

if __name__ == "__main__":
    unittest.main()
