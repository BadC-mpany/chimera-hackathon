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

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class LedgerEvent:
    event_id: str
    timestamp: float
    session_id: str
    event_type: str
    trigger: Dict[str, Any]
    action: Dict[str, Any]
    outcome: Dict[str, Any]
    accumulated_risk: Optional[float]
    risk_history_length: Optional[int]
    previous_hash: str
    hash: str = ""


class ImmutableForensicLedger:
    """
    Append-only log with cryptographic hash chaining.
    Provides tamper-proof evidence of why a Shadow Warrant was issued.
    """

    def __init__(self, log_path: Path = Path("data/forensic_ledger.jsonl")):
        self.log_path = log_path
        self.last_hash = "0" * 64
        self._ensure_log_exists()
        self._recover_last_hash()

    def _ensure_log_exists(self):
        if not self.log_path.parent.exists():
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch()

    def _recover_last_hash(self):
        """Read the last line to get the most recent hash to maintain the chain."""
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if lines:
                    last_entry = json.loads(lines[-1])
                    self.last_hash = last_entry.get("hash", self.last_hash)
        except Exception as e:
            logger.error(f"Failed to recover ledger hash: {e}")

    def _calculate_hash(self, event_data: Dict[str, Any], previous_hash: str) -> str:
        """Compute SHA-256 hash of the event data + previous hash."""
        # Sort keys to ensure deterministic hashing
        payload = json.dumps(event_data, sort_keys=True) + previous_hash
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def log_event(
        self,
        session_id: str,
        event_type: str,
        trigger: Dict[str, Any],
        action: Dict[str, Any],
        outcome: Dict[str, Any],
        accumulated_risk: Optional[float] = None,
        risk_history_length: Optional[int] = None,
    ) -> str:
        """
        Record an event to the immutable ledger.
        """
        event_id = str(uuid.uuid4())
        timestamp = time.time()

        event_core = {
            "event_id": event_id,
            "timestamp": timestamp,
            "session_id": session_id,
            "event_type": event_type,
            "trigger": trigger,
            "action": action,
            "outcome": outcome,
            "accumulated_risk": accumulated_risk,
            "risk_history_length": risk_history_length,
            "previous_hash": self.last_hash,
        }

        current_hash = self._calculate_hash(event_core, self.last_hash)

        final_event = LedgerEvent(**event_core, hash=current_hash)

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(final_event)) + "\n")

            self.last_hash = current_hash
            logger.info(f"IFL Logged: {event_type} | Hash: {current_hash[:8]}...")
            return event_id
        except Exception as e:
            logger.error(f"Critical IFL Failure: {e}")
            return ""
