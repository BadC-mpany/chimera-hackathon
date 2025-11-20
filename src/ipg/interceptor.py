import json
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
from src.dkca.authority import TokenAuthority
from src.nsie.judge import ProbabilisticJudge
from src.ipg.policy import PolicyEngine

logger = logging.getLogger(__name__)


@dataclass
class InterceptionResult:
    """Result of the message inspection."""
    should_block: bool = False
    modified_message: Optional[Dict[str, Any]] = None
    routing_target: str = "production"  # "production" or "shadow"


class MessageInterceptor:
    """
    Inspects JSON-RPC messages to detect tool calls and determine routing.
    """

    def __init__(self):
        # Initialize Components
        try:
            self.authority = TokenAuthority()
            self.judge = ProbabilisticJudge()
            self.policy = PolicyEngine()
            logger.info("CHIMERA Interceptor initialized (DKCA + NSIE + Policy).")
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            self.authority = None
            self.judge = None
            self.policy = None
        self.default_session_id = "session_123"

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

    def _extract_context(self, message_json: Dict[str, Any]) -> Dict[str, Any]:
        params = message_json.get("params", {})
        meta = params.get("context") or {}
        return {
            "user_id": str(meta.get("user_id", "99")),
            "user_role": meta.get("user_role", "patient"),
            "session_id": str(meta.get("session_id", message_json.get("session_id", self.default_session_id))),
            "ip": meta.get("ip"),
            "geo": meta.get("geo"),
        }

    async def _inspect_tool_call(self, message_json: Dict[str, Any]) -> InterceptionResult:
        """
        Performs the actual threat assessment and issues a Shadow Warrant.
        """
        tool_name = message_json.get("params", {}).get("name")
        args = message_json.get("params", {}).get("arguments", {})
        context = self._extract_context(message_json)
        risk_score = 0.0
        reason = "Default Safe"
        routing_target = "production"

        # 1. Neural-Symbolic Inference (The Guardrail)
        if self.judge:
            assessment = await self.judge.evaluate_risk(tool_name, args, context)
            risk_score = assessment.risk_score
            reason = assessment.reason

            logger.info(f"NSIE Assessment: Risk={risk_score:.2f} | Reason={reason}")

        # 2. Policy Decision
        if self.policy:
            policy_result = self.policy.evaluate(tool_name, args, context, risk_score)
            routing_target = policy_result["route"]
            reason = policy_result["reason"]
            logger.info(
                "Policy decision: route=%s rule=%s reason=%s",
                routing_target,
                policy_result.get("rule_id"),
                reason,
            )
        else:
            if risk_score > 0.5:
                routing_target = "shadow"

        # 3. Issue Warrant via DKCA
        if self.authority:
            session_id = context.get("session_id", self.default_session_id)
            # Pass the AI-generated risk score to the Authority
            warrant = self.authority.issue_warrant(session_id, risk_score)

            # Inject Warrant
            if "params" not in message_json:
                message_json["params"] = {}

            message_json["params"]["__chimera_warrant__"] = warrant

            return InterceptionResult(
                should_block=False,
                modified_message=message_json,
                routing_target=routing_target
            )
        else:
            logger.warning("DKCA unavailable, forwarding without warrant.")
            return InterceptionResult(should_block=False, routing_target="production")
