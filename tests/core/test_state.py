
import unittest
import time
from src.ipg.memory import SessionMemory
from src.ipg.taint import TaintManager, TrustLevel

class TestSessionMemory(unittest.TestCase):
    def setUp(self):
        self.settings = {
            "policy": {
                "risk_accumulation": {
                    "enabled": True,
                    "method": "additive_decay",
                    "decay_rate": 0.1,
                    "window_minutes": 60
                }
            }
        }
        self.memory = SessionMemory(self.settings)
        self.session_id = "test_session"

    def test_add_tool_call(self):
        """Test tracking tool calls."""
        self.memory.add_tool_call(self.session_id, "read_file", {"path": "test.txt"})
        history = self.memory.get_session(self.session_id).history
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["tool"], "read_file")

    def test_accumulate_risk(self):
        """Test risk accumulation."""
        self.memory.accumulate_risk(self.session_id, 0.5)
        self.assertAlmostEqual(self.memory.get_accumulated_risk(self.session_id), 0.5)
        
        # Add more risk
        self.memory.accumulate_risk(self.session_id, 0.3)
        # Should be 0.5 + 0.3 = 0.8 (ignoring tiny decay for immediate calls)
        self.assertAlmostEqual(self.memory.get_accumulated_risk(self.session_id), 0.8, delta=0.01)

    def test_taint_logic_legacy(self):
        """Test legacy taint logic in memory."""
        self.memory.add_tool_call(self.session_id, "read_file", {"path": "/external/resume.pdf"})
        self.assertIn("resume", self.memory.get_taint(self.session_id))


class TestTaintManager(unittest.TestCase):
    def setUp(self):
        self.settings = {
            "taint": {
                "untrusted_patterns": ["resume", "upload"],
                "trusted_patterns": ["/private/", "system"]
            }
        }
        self.taint_manager = TaintManager(self.settings)
        self.session_id = "taint_session"

    def test_check_source_trust(self):
        """Test pattern matching for trust levels."""
        self.assertEqual(self.taint_manager.check_source_trust("my_resume.pdf"), TrustLevel.RED)
        self.assertEqual(self.taint_manager.check_source_trust("/private/config.yaml"), TrustLevel.GREEN)
        self.assertEqual(self.taint_manager.check_source_trust("unknown.txt"), TrustLevel.GREEN) # Default safe (green)

    def test_update_taint(self):
        """Test session taint transition."""
        # Initially safe
        self.assertFalse(self.taint_manager.is_tainted(self.session_id))
        
        # Access trusted source -> Remains safe
        self.taint_manager.update_taint(self.session_id, "/private/data")
        self.assertFalse(self.taint_manager.is_tainted(self.session_id))
        
        # Access untrusted source -> Becomes tainted
        self.taint_manager.update_taint(self.session_id, "malicious_upload.exe")
        self.assertTrue(self.taint_manager.is_tainted(self.session_id))
        
        # Access trusted source again -> Remains tainted (latching)
        self.taint_manager.update_taint(self.session_id, "/private/data")
        self.assertTrue(self.taint_manager.is_tainted(self.session_id))

if __name__ == "__main__":
    unittest.main()

