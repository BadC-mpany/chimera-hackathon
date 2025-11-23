
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
from src.ipg.interceptor import MessageInterceptor, InterceptionResult

class TestMessageInterceptor(unittest.TestCase):
    def setUp(self):
        self.settings = {
            "policy": {
                "default_action": "production",
                "risk_accumulation": {"enabled": False}
            },
            "backend": {"tools": {}}
        }
        self.interceptor = MessageInterceptor(self.settings)
        
        # Mock internal components to isolate interceptor logic
        self.interceptor.judge = AsyncMock()
        self.interceptor.policy = MagicMock()
        self.interceptor.authority = MagicMock()
        self.interceptor.memory = MagicMock()
        self.interceptor.taint_manager = MagicMock()
        self.interceptor.ifl = MagicMock()

    async def test_process_message_non_tool_call(self):
        """Test that non-tool calls are passed through."""
        msg = '{"jsonrpc": "2.0", "method": "chat", "params": {}}'
        result, route = await self.interceptor.process_message(msg)
        self.assertEqual(route, "production")
        self.assertEqual(result, msg)

    async def test_process_message_tool_call_production(self):
        """Test a safe tool call routing to production."""
        msg = '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "safe.txt"}}}'
        
        # Setup mocks
        self.interceptor.judge.evaluate_risk.return_value = MagicMock(risk_score=0.1, confidence=1.0, reason="Safe")
        self.interceptor.policy.evaluate.return_value = {"route": "production", "reason": "Policy allowed"}
        self.interceptor.authority.issue_warrant.return_value = "prod_token"
        self.interceptor.taint_manager.is_tainted.return_value = False
        self.interceptor.memory.get_accumulated_risk.return_value = 0.1

        result_str, route = await self.interceptor.process_message(msg)
        
        self.assertEqual(route, "production")
        self.assertIn("__chimera_warrant__", result_str)
        self.interceptor.authority.issue_warrant.assert_called_with(
            session_id="session_123", risk_score=0.1, route="production"
        )

    async def test_process_message_tool_call_shadow(self):
        """Test a risky tool call routing to shadow."""
        msg = '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "secret.txt"}}}'
        
        # Setup mocks
        self.interceptor.judge.evaluate_risk.return_value = MagicMock(risk_score=0.9, confidence=1.0, reason="Risky")
        self.interceptor.policy.evaluate.return_value = {"route": "shadow", "reason": "Policy blocked"}
        self.interceptor.authority.issue_warrant.return_value = "shadow_token"
        self.interceptor.taint_manager.is_tainted.return_value = False
        self.interceptor.memory.get_accumulated_risk.return_value = 0.9

        result_str, route = await self.interceptor.process_message(msg)
        
        self.assertEqual(route, "shadow")
        self.interceptor.authority.issue_warrant.assert_called_with(
            session_id="session_123", risk_score=0.9, route="shadow"
        )
        self.interceptor.ifl.log_event.assert_called_once()

if __name__ == "__main__":
    unittest.main()

