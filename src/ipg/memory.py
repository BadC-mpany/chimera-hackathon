from math import exp
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.config import load_settings


@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.time)
    history: List[Dict[str, Any]] = field(default_factory=list)
    risk_history: List[Dict[str, Any]] = field(default_factory=list)
    taint_source: Optional[str] = None
    accumulated_risk: float = 0.0
    last_risk_update: float = field(default_factory=time.time)


class SessionMemory:
    """
    In-memory state store (simulating Redis) to track user actions
    and propagate taint across tool calls.
    """

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self._sessions: Dict[str, SessionState] = {}
        self.settings = settings or load_settings()
        self.risk_config = self.settings.get("policy", {}).get("risk_accumulation", {})

    def get_session(self, session_id: str) -> SessionState:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState(session_id=session_id)
        return self._sessions[session_id]

    def add_tool_call(self, session_id: str, tool_name: str, args: Dict[str, Any]):
        session = self.get_session(session_id)
        entry = {
            "tool": tool_name,
            "args": args,
            "timestamp": time.time(),
        }
        session.history.append(entry)

        # Taint Logic: If reading an external file, taint the session
        if tool_name == "read_file":
            path = args.get("path") or args.get("filename", "")
            # Heuristic: resumes or uploads are considered tainted sources
            if "resume" in path.lower() or "upload" in path.lower():
                session.taint_source = path

    def get_taint(self, session_id: str) -> Optional[str]:
        return self.get_session(session_id).taint_source

    def _apply_decay(self, session: SessionState) -> float:
        """Calculate and apply time-based decay to the accumulated risk."""
        if not self.risk_config.get("enabled", False):
            return session.accumulated_risk

        decay_rate = self.risk_config.get("decay_rate", 0.0)
        if decay_rate == 0.0:
            return session.accumulated_risk

        now = time.time()
        time_elapsed_minutes = (now - session.last_risk_update) / 60
        
        # Prune risk history outside the time window
        window_minutes = self.risk_config.get("window_minutes", 60)
        session.risk_history = [
            event for event in session.risk_history
            if (now - event["timestamp"]) / 60 <= window_minutes
        ]

        if self.risk_config.get("method") == "additive_decay":
            # Simple decay on the total score
            decay_factor = exp(-decay_rate * time_elapsed_minutes)
            session.accumulated_risk *= decay_factor
        elif self.risk_config.get("method") == "windowed_sum":
             # Recalculate risk from the pruned history
            session.accumulated_risk = sum(event["risk_score"] for event in session.risk_history)

        session.last_risk_update = now
        return session.accumulated_risk

    def accumulate_risk(self, session_id: str, risk_score: float):
        """Update the session's risk score based on the configured strategy."""
        session = self.get_session(session_id)
        now = time.time()
        
        # First, apply decay to the current score
        self._apply_decay(session)
        
        # Add the new risk event to history
        session.risk_history.append({"risk_score": risk_score, "timestamp": now})
        
        # Accumulate the new risk score
        session.accumulated_risk += risk_score
        session.last_risk_update = now

    def get_accumulated_risk(self, session_id: str) -> float:
        """Return the current accumulated risk for the session, applying decay first."""
        session = self.get_session(session_id)
        return self._apply_decay(session)

    def get_risk_history(self, session_id: str) -> List[Dict]:
        """Return the list of risk assessments for pattern analysis."""
        return self.get_session(session_id).risk_history
