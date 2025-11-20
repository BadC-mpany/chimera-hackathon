import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.time)
    history: List[Dict[str, Any]] = field(default_factory=list)
    taint_source: Optional[str] = None
    risk_accumulator: float = 0.0


class SessionMemory:
    """
    In-memory state store (simulating Redis) to track user actions
    and propagate taint across tool calls.
    """

    def __init__(self):
        self._sessions: Dict[str, SessionState] = {}

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
