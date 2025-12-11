# Copyright 2025 Badcompany
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Comprehensive per-turn logging for CHIMERA.
Captures system state, risk, raw LLM calls, tool permissions, and responses.
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class TurnLog:
    """Complete log of a single conversation turn."""
    turn_number: int
    timestamp: str
    session_id: str
    
    # System State
    user_id: str
    user_role: str
    is_tainted: bool
    taint_source: Optional[str]
    is_in_shadow: bool
    accumulated_risk: float
    
    # User Query
    user_query: str
    
    # LLM Agent Call
    agent_llm_request: Optional[Dict[str, Any]] = None
    agent_llm_response: Optional[Dict[str, Any]] = None
    
    # Tool Execution
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    
    # NSIE Judge Calls (per tool)
    judge_calls: List[Dict[str, Any]] = field(default_factory=list)
    
    # Policy Decisions (per tool)
    policy_decisions: List[Dict[str, Any]] = field(default_factory=list)
    
    # Final Response
    assistant_response: Optional[str] = None
    
    # Performance
    duration_ms: Optional[float] = None


class TurnLogger:
    """
    Centralized turn-based logger that aggregates logs from agent and IPG.
    Both components write to the same log file with structured turn data.
    """
    
    def __init__(self, log_file: Optional[Path] = None):
        self.log_file = log_file or Path("logs") / f"turns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # In-progress turn data (session_id -> turn_data)
        self.active_turns: Dict[str, TurnLog] = {}
        self.turn_counters: Dict[str, int] = {}  # session_id -> turn_number
        
        logger.info(f"TurnLogger initialized: {self.log_file}")
    
    def start_turn(self, session_id: str, user_query: str, system_state: Dict[str, Any]) -> int:
        """Start logging a new turn."""
        turn_number = self.turn_counters.get(session_id, 0) + 1
        self.turn_counters[session_id] = turn_number
        
        turn_log = TurnLog(
            turn_number=turn_number,
            timestamp=datetime.now().isoformat(),
            session_id=session_id,
            user_id=system_state.get("user_id", "unknown"),
            user_role=system_state.get("user_role", "unknown"),
            is_tainted=system_state.get("is_tainted", False),
            taint_source=system_state.get("taint_source"),
            is_in_shadow=system_state.get("is_in_shadow", False),
            accumulated_risk=system_state.get("accumulated_risk", 0.0),
            user_query=user_query
        )
        
        self.active_turns[session_id] = turn_log
        
        # Log turn header
        self._log_section(f"{'='*80}\nTURN {turn_number} START - Session: {session_id}\n{'='*80}")
        self._log_section(f"USER: {system_state.get('user_id')} (role: {system_state.get('user_role')})")
        self._log_section(f"QUERY: {user_query}")
        self._log_section(f"SYSTEM STATE:")
        self._log_json({
            "is_tainted": turn_log.is_tainted,
            "taint_source": turn_log.taint_source,
            "is_in_shadow": turn_log.is_in_shadow,
            "accumulated_risk": turn_log.accumulated_risk
        })
        
        return turn_number
    
    def log_agent_llm_request(self, session_id: str, request_data: Dict[str, Any]):
        """Log the complete LLM API request from the agent."""
        if session_id not in self.active_turns:
            logger.warning(f"No active turn for session {session_id}")
            return
        
        self.active_turns[session_id].agent_llm_request = request_data
        
        self._log_section(f"\n{'─'*80}\nAGENT LLM REQUEST\n{'─'*80}")
        self._log_json(request_data)
    
    def log_agent_llm_response(self, session_id: str, response_data: Dict[str, Any]):
        """Log the complete LLM API response to the agent."""
        if session_id not in self.active_turns:
            logger.warning(f"No active turn for session {session_id}")
            return
        
        self.active_turns[session_id].agent_llm_response = response_data
        
        self._log_section(f"\n{'─'*80}\nAGENT LLM RESPONSE\n{'─'*80}")
        self._log_json(response_data)
    
    def log_tool_call(self, session_id: str, tool_name: str, arguments: Dict[str, Any], 
                      allowed_tools: List[str], context: Dict[str, Any]):
        """Log a tool call with permissions."""
        if session_id not in self.active_turns:
            logger.warning(f"No active turn for session {session_id}")
            return
        
        tool_call_data = {
            "tool_name": tool_name,
            "arguments": arguments,
            "timestamp": datetime.now().isoformat(),
            "allowed_tools": allowed_tools,
            "context": context
        }
        
        self.active_turns[session_id].tool_calls.append(tool_call_data)
        
        self._log_section(f"\n{'─'*80}\nTOOL CALL: {tool_name}\n{'─'*80}")
        self._log_section(f"ALLOWED TOOLS: {', '.join(allowed_tools)}")
        self._log_section(f"ARGUMENTS:")
        self._log_json(arguments)
    
    def log_judge_call(self, session_id: str, tool_name: str, judge_request: Dict[str, Any], 
                       judge_response: Dict[str, Any]):
        """Log NSIE judge evaluation."""
        if session_id not in self.active_turns:
            logger.warning(f"No active turn for session {session_id}")
            return
        
        judge_data = {
            "tool_name": tool_name,
            "timestamp": datetime.now().isoformat(),
            "request": judge_request,
            "response": judge_response
        }
        
        self.active_turns[session_id].judge_calls.append(judge_data)
        
        self._log_section(f"\n{'─'*80}\nNSIE JUDGE EVALUATION: {tool_name}\n{'─'*80}")
        self._log_section("JUDGE REQUEST:")
        self._log_json(judge_request)
        self._log_section("JUDGE RESPONSE:")
        self._log_json(judge_response)
    
    def log_policy_decision(self, session_id: str, tool_name: str, policy_result: Dict[str, Any]):
        """Log policy engine decision."""
        if session_id not in self.active_turns:
            logger.warning(f"No active turn for session {session_id}")
            return
        
        policy_data = {
            "tool_name": tool_name,
            "timestamp": datetime.now().isoformat(),
            "route": policy_result.get("route"),
            "rule_id": policy_result.get("rule_id"),
            "reason": policy_result.get("reason")
        }
        
        self.active_turns[session_id].policy_decisions.append(policy_data)
        
        self._log_section(f"\n{'─'*80}\nPOLICY DECISION: {tool_name}\n{'─'*80}")
        self._log_json(policy_result)
    
    def log_tool_response(self, session_id: str, tool_name: str, response: str, 
                          routing_target: Optional[str] = None):
        """Log tool execution response."""
        if session_id not in self.active_turns:
            logger.warning(f"No active turn for session {session_id}")
            return
        
        # Add response to the most recent tool call
        if self.active_turns[session_id].tool_calls:
            self.active_turns[session_id].tool_calls[-1]["response"] = response
            self.active_turns[session_id].tool_calls[-1]["routing_target"] = routing_target
        
        self._log_section(f"\n{'─'*80}\nTOOL RESPONSE: {tool_name}\n{'─'*80}")
        if routing_target:
            self._log_section(f"ROUTED TO: {routing_target.upper()}")
        self._log_section(f"RESPONSE: {response[:500]}{'...' if len(response) > 500 else ''}")
    
    def end_turn(self, session_id: str, assistant_response: str, duration_ms: Optional[float] = None):
        """Complete and persist the turn log."""
        if session_id not in self.active_turns:
            logger.warning(f"No active turn for session {session_id}")
            return
        
        turn_log = self.active_turns[session_id]
        turn_log.assistant_response = assistant_response
        turn_log.duration_ms = duration_ms
        
        self._log_section(f"\n{'─'*80}\nASSISTANT RESPONSE\n{'─'*80}")
        self._log_section(assistant_response)
        
        if duration_ms:
            self._log_section(f"\nTURN DURATION: {duration_ms:.2f}ms")
        
        self._log_section(f"\n{'='*80}\nTURN {turn_log.turn_number} END\n{'='*80}\n")
        
        # Write complete turn to JSONL file
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(asdict(turn_log), default=str) + '\n')
        
        # Clear active turn
        del self.active_turns[session_id]
    
    def _log_section(self, message: str):
        """Write to log file."""
        logger.info(message)
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(message + '\n')
    
    def _log_json(self, data: Any):
        """Write JSON data to log file."""
        try:
            formatted = json.dumps(data, indent=2, default=str)
            logger.debug(formatted)
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(formatted + '\n')
        except Exception as e:
            error_msg = f"Failed to serialize JSON: {e}"
            logger.error(error_msg)
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"{error_msg}\n{str(data)}\n")


# Global turn logger instance
_turn_logger: Optional[TurnLogger] = None


def get_turn_logger() -> TurnLogger:
    """Get or create the global turn logger."""
    global _turn_logger
    if _turn_logger is None:
        _turn_logger = TurnLogger()
    return _turn_logger


def init_turn_logger(log_file: Optional[Path] = None) -> TurnLogger:
    """Initialize the global turn logger with a specific log file."""
    global _turn_logger
    _turn_logger = TurnLogger(log_file)
    return _turn_logger
