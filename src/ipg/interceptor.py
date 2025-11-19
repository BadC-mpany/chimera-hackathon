import json
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
from src.dkca.authority import TokenAuthority

logger = logging.getLogger(__name__)

@dataclass
class InterceptionResult:
    """Result of the message inspection."""
    should_block: bool = False
    modified_message: Optional[Dict[str, Any]] = None
    routing_target: str = "production" # "production" or "shadow"

class MessageInterceptor:
    """
    Inspects JSON-RPC messages to detect tool calls and determine routing.
    """
    
    def __init__(self):
        # Initialize the Dual-Key Credential Authority
        try:
            self.authority = TokenAuthority()
            logger.info("DKCA initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize DKCA: {e}")
            self.authority = None

    async def process_message(self, raw_message: str) -> Tuple[str, str]:
        """
        Parses and inspects the message.
        Returns a tuple of (processed_message_str, routing_target).
        """
        try:
            message_json = json.loads(raw_message)
        except json.JSONDecodeError:
            return raw_message, "production"

        # Fast Path: Check if it's a tool call
        if message_json.get("method") != "tools/call":
            return raw_message, "production"

        # Slow Path: Deep inspection for tools/call
        tool_name = message_json.get("params", {}).get("name")
        logger.info(f"Intercepted tool call: {tool_name}")
        
        result = await self._inspect_tool_call(message_json)
        
        final_message = result.modified_message if result.modified_message else message_json
        
        # Re-serialize
        return json.dumps(final_message), result.routing_target

    async def _inspect_tool_call(self, message_json: Dict[str, Any]) -> InterceptionResult:
        """
        Performs the actual threat assessment and issues a Shadow Warrant.
        """
        tool_name = message_json.get("params", {}).get("name")
        risk_score = 0.1 # Default safe
        routing_target = "production"

        # Mock Threat Detection Logic
        if tool_name and "transfer" in tool_name:
             logger.warning(f"Flagging suspicious tool call: {tool_name}")
             risk_score = 0.95
             routing_target = "shadow"

        # Issue Warrant via DKCA
        if self.authority:
            session_id = "session_123" # TODO: Extract from context
            warrant = self.authority.issue_warrant(session_id, risk_score)
            
            # Inject Warrant into params
            if "params" not in message_json:
                message_json["params"] = {}
            
            # We modify the message in place (or copy if needed, but here dict is mutable)
            # Injecting into params so the downstream tool receives it
            message_json["params"]["__chimera_warrant__"] = warrant
            
            return InterceptionResult(
                should_block=False, 
                modified_message=message_json,
                routing_target=routing_target
            )
        else:
            logger.warning("DKCA unavailable, forwarding without warrant.")
            return InterceptionResult(should_block=False, routing_target="production")
