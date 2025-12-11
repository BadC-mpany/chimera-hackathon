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
Attack Logger - Comprehensive data collection for shadow mode interactions.

This module is ONLY activated when an agent is routed to the shadow environment.
It captures complete forensic intelligence about attacker behavior.
"""

import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AttackInteraction:
    """A single interaction in an attack session."""
    timestamp: float
    interaction_id: str
    tool_name: str
    tool_args: Dict[str, Any]
    risk_score: float
    response_preview: str  # First 500 chars of response
    accumulated_risk: float
    context_snapshot: Dict[str, Any]


@dataclass
class AttackSession:
    """Complete attack session with all interactions."""
    session_id: str
    start_time: float
    trigger_reason: str
    trigger_risk_score: float
    user_id: Optional[str]
    user_role: Optional[str]
    interactions: List[AttackInteraction]
    end_time: Optional[float] = None
    total_interactions: int = 0
    final_risk_score: float = 0.0


class AttackLogger:
    """
    Forensic data collector for shadow-mode sessions.
    
    Creates timestamped session files in attack_logs/ with complete
    attacker behavior for post-incident analysis and ML training.
    """

    def __init__(self, log_dir: Path = Path("attack_logs")):
        self.log_dir = log_dir
        self.active_sessions: Dict[str, AttackSession] = {}
        self._ensure_log_dir()

    def _ensure_log_dir(self):
        """Ensure attack_logs directory exists."""
        if not self.log_dir.exists():
            self.log_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created attack log directory: {self.log_dir}")

    def start_attack_session(
        self,
        session_id: str,
        trigger_reason: str,
        trigger_risk_score: float,
        context: Dict[str, Any]
    ):
        """
        Initialize attack session tracking.
        Called when agent is first routed to shadow environment.
        """
        if session_id in self.active_sessions:
            logger.warning(f"Attack session {session_id} already active")
            return

        session = AttackSession(
            session_id=session_id,
            start_time=time.time(),
            trigger_reason=trigger_reason,
            trigger_risk_score=trigger_risk_score,
            user_id=context.get("user_id"),
            user_role=context.get("user_role"),
            interactions=[],
        )
        self.active_sessions[session_id] = session
        
        logger.warning(f"🚨 ATTACK SESSION STARTED: {session_id} | Reason: {trigger_reason}")

    def log_interaction(
        self,
        session_id: str,
        interaction_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        risk_score: float,
        response: str,
        accumulated_risk: float,
        context: Dict[str, Any]
    ):
        """
        Log a single shadow-mode tool call interaction.
        Captures everything the attacker tried and what they received.
        """
        if session_id not in self.active_sessions:
            logger.error(f"Cannot log interaction for unknown session: {session_id}")
            return

        session = self.active_sessions[session_id]
        
        # Truncate response for preview (full response in separate file if needed)
        response_preview = response[:500] if response else ""
        
        interaction = AttackInteraction(
            timestamp=time.time(),
            interaction_id=interaction_id,
            tool_name=tool_name,
            tool_args=tool_args,
            risk_score=risk_score,
            response_preview=response_preview,
            accumulated_risk=accumulated_risk,
            context_snapshot=self._sanitize_context(context)
        )
        
        session.interactions.append(interaction)
        session.total_interactions = len(session.interactions)
        session.final_risk_score = accumulated_risk
        
        logger.info(f"🎯 Attack interaction logged: {session_id} | Tool: {tool_name} | Risk: {risk_score:.2f}")

    def end_attack_session(self, session_id: str):
        """
        Finalize attack session and write complete forensic log to disk.
        Called when session ends or timeout occurs.
        """
        if session_id not in self.active_sessions:
            logger.warning(f"Cannot end unknown attack session: {session_id}")
            return

        session = self.active_sessions[session_id]
        session.end_time = time.time()
        
        # Write complete session to timestamped file
        self._write_session_log(session)
        
        # Clean up in-memory tracking
        del self.active_sessions[session_id]
        
        duration = session.end_time - session.start_time
        logger.warning(
            f"🚨 ATTACK SESSION ENDED: {session_id} | "
            f"Duration: {duration:.1f}s | "
            f"Interactions: {session.total_interactions} | "
            f"Final Risk: {session.final_risk_score:.2f}"
        )

    def _write_session_log(self, session: AttackSession):
        """Write complete attack session to JSON file."""
        timestamp_str = time.strftime("%Y%m%d_%H%M%S", time.localtime(session.start_time))
        filename = f"attack_{session.session_id}_{timestamp_str}.json"
        filepath = self.log_dir / filename
        
        # Convert to dict for JSON serialization
        session_dict = asdict(session)
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(session_dict, f, indent=2)
            
            logger.warning(f"📝 Attack log written: {filepath}")
        except Exception as e:
            logger.error(f"Failed to write attack log {filepath}: {e}")

    def is_session_active(self, session_id: str) -> bool:
        """Check if session is being tracked as attack."""
        return session_id in self.active_sessions

    def _sanitize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive internal data from context snapshot."""
        # Keep only relevant context for forensic analysis
        return {
            "user_id": context.get("user_id"),
            "user_role": context.get("user_role"),
            "source": context.get("source"),
            "is_tainted": context.get("is_tainted"),
            "accumulated_risk": context.get("accumulated_risk"),
        }

    def get_session_summary(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get current state of active attack session."""
        if session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_id]
        return {
            "session_id": session.session_id,
            "duration": time.time() - session.start_time,
            "total_interactions": session.total_interactions,
            "final_risk_score": session.final_risk_score,
            "trigger_reason": session.trigger_reason,
        }
