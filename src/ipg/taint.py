from enum import Enum
from dataclasses import dataclass
from typing import Dict, Optional
import logging
import re

from src.config import load_settings

logger = logging.getLogger(__name__)


class TrustLevel(Enum):
    GREEN = "trusted"
    RED = "untrusted"


@dataclass
class TaintState:
    session_id: str
    status: TrustLevel = TrustLevel.GREEN
    taint_source: Optional[str] = None


class TaintManager:
    """
    Tracks data provenance and session taint status.
    If a session accesses RED (untrusted) data, the session becomes TAINTED (RED).
    Patterns are configurable per scenario via config.
    """

    def __init__(self, settings: Optional[Dict] = None):
        self._sessions: Dict[str, TaintState] = {}
        self.settings = settings or load_settings()

        # Load taint patterns from config
        taint_config = self.settings.get("taint", {})
        self.red_patterns = taint_config.get("untrusted_patterns", [
            "resume",
            "upload",
            "external",
            "/shared/",
            "attachment",
        ])
        self.green_patterns = taint_config.get("trusted_patterns", [
            "/private/",
            "/real/",
            "_conf_",
            "system",
            "internal",
        ])
        self.default_trust = taint_config.get("default_trust", "green")

        logger.info(f"TaintManager initialized: {len(self.red_patterns)} RED patterns, {len(self.green_patterns)} GREEN patterns")

    def get_session_state(self, session_id: str) -> TaintState:
        if session_id not in self._sessions:
            self._sessions[session_id] = TaintState(session_id=session_id)
        return self._sessions[session_id]

    def check_source_trust(self, source: str) -> TrustLevel:
        """
        Determines if a data source is Trusted (GREEN) or Untrusted (RED).
        Uses regex patterns from config.
        """
        source_lower = source.lower()

        # Check RED patterns first (untrusted)
        for pattern in self.red_patterns:
            if re.search(pattern, source_lower):
                return TrustLevel.RED

        # Check GREEN patterns (trusted)
        for pattern in self.green_patterns:
            if re.search(pattern, source_lower):
                return TrustLevel.GREEN

        # Default behavior (configurable)
        if self.default_trust == "red":
            return TrustLevel.RED  # Secure by default
        return TrustLevel.GREEN  # Utility by default

    def update_taint(self, session_id: str, source: str):
        """
        Updates session taint status based on the source being accessed.
        Transition is one-way: GREEN -> RED. Once RED, always RED.
        """
        state = self.get_session_state(session_id)
        trust_level = self.check_source_trust(source)

        if trust_level == TrustLevel.RED:
            if state.status == TrustLevel.GREEN:
                logger.warning(f"[TAINT] Session {session_id} TAINTED by source: {source}")
                state.status = TrustLevel.RED
                state.taint_source = source

    def is_tainted(self, session_id: str) -> bool:
        return self.get_session_state(session_id).status == TrustLevel.RED

    def get_taint_source(self, session_id: str) -> Optional[str]:
        """Returns the original source that tainted the session."""
        return self.get_session_state(session_id).taint_source
