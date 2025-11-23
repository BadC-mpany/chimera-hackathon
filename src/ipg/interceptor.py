import json
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple

from src.config import load_settings
from src.dkca.authority import TokenAuthority
from src.ifl.ledger import ImmutableForensicLedger
from src.ipg.memory import SessionMemory
from src.ipg.policy import PolicyEngine
from src.ipg.taint import TaintManager
from src.nsie.judge import ProbabilisticJudge

logger = logging.getLogger(__name__)

# Import logging utilities for enhanced debugging
try:
    from src.utils.logging_config import log_dict, log_separator
except ImportError:
    # Fallback if logging utilities not available
    def log_dict(logger, title, data, level="DEBUG"):
        getattr(logger, level.lower())(f"{title}: {data}")
    def log_separator(logger, message="", level="INFO"):
        getattr(logger, level.lower())(f"{'='*80}")
        if message:
            getattr(logger, level.lower())(message)


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

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or load_settings()
        self.debug = self.settings.get("agent", {}).get("debug", False)
        
        # Initialize Components
        try:
            self.authority = TokenAuthority()
            self.judge = ProbabilisticJudge(settings=self.settings)
            self.policy = PolicyEngine(settings=self.settings)
            self.ifl = ImmutableForensicLedger()
            self.memory = SessionMemory()
            self.taint_manager = TaintManager(settings=self.settings)
            logger.info("CHIMERA Interceptor initialized (DKCA + NSIE + Policy + IFL + Memory + Taint).")
            if self.debug:
                logger.debug("Debug mode enabled - verbose logging active")
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            self.authority = None
            self.judge = None
            self.policy = None
            self.ifl = None
            self.memory = None
            self.taint_manager = None
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
        session_id = str(meta.get("session_id", message_json.get("session_id", self.default_session_id)))

        # Check Taint Status
        is_tainted = False
        if self.taint_manager:
            is_tainted = self.taint_manager.is_tainted(session_id)

        # Retrieve Taint from Memory (Legacy support, moving to TaintManager)
        taint_source = None
        if self.memory:
            taint_source = self.memory.get_taint(session_id)

        return {
            "user_id": str(meta.get("user_id", "99")),
            "user_role": meta.get("user_role", "patient"),
            "session_id": session_id,
            "ip": meta.get("ip"),
            "geo": meta.get("geo"),
            # Critical: Inject the taint so the Policy Engine can see it
            "source_file": taint_source,
            "source": "external_upload" if taint_source else meta.get("source", "internal"),
            "is_tainted": is_tainted,
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
        
        if self.debug:
            log_separator(logger, f"🔍 TOOL CALL INTERCEPTION: {tool_name}", "DEBUG")
            log_dict(logger, "Tool Arguments", args, "DEBUG")
            log_dict(logger, "Initial Context", context, "DEBUG")

        # 0a. Update Memory (Legacy)
        if self.memory:
            self.memory.add_tool_call(context["session_id"], tool_name, args)
            if self.debug:
                history_len = len(self.memory.get_session(context["session_id"]).history)
                logger.debug(f"📚 Session history updated (total calls: {history_len})")

        # 0b. Update Taint Manager
        taint_changed = False
        if self.taint_manager and tool_name == "read_file":
            path = args.get("filename") or args.get("path", "")
            if path:
                was_tainted = self.taint_manager.is_tainted(context["session_id"])
                self.taint_manager.update_taint(context["session_id"], path)
                is_now_tainted = self.taint_manager.is_tainted(context["session_id"])
                
                if not was_tainted and is_now_tainted:
                    taint_changed = True
                    context["is_tainted"] = True
                    taint_source = self.taint_manager.get_taint_source(context["session_id"])
                    logger.warning(f"🔴 SESSION TAINTED by file: {taint_source}")
                    if self.debug:
                        log_dict(logger, "Taint Status", {
                            "session_id": context["session_id"],
                            "taint_source": taint_source,
                            "file_accessed": path
                        }, "WARNING")

        # 1. Neural-Symbolic Inference (The Guardrail)
        confidence = 1.0  # Default confidence
        accumulated_risk = 0.0
        event_risk_score = 0.0
        
        if self.judge:
            if self.debug:
                logger.debug("🧠 Invoking NSIE Judge...")
            
            assessment = await self.judge.evaluate_risk(tool_name, args, context)
            event_risk_score = assessment.risk_score
            confidence = assessment.confidence
            reason = assessment.reason

            logger.info(f"NSIE Assessment: Risk={event_risk_score:.2f} Confidence={confidence:.2f} | Reason={reason}")
            
            if self.debug:
                log_dict(logger, "Full NSIE Assessment", {
                    "risk_score": event_risk_score,
                    "confidence": confidence,
                    "reason": reason,
                    "violation_tags": assessment.violation_tags
                }, "DEBUG")

            # Stateful Risk Accumulation
            prev_accumulated = self.memory.get_accumulated_risk(context["session_id"])
            self.memory.accumulate_risk(context["session_id"], event_risk_score)
            accumulated_risk = self.memory.get_accumulated_risk(context["session_id"])
            
            logger.info(f"Session Risk: Event={event_risk_score:.2f}, Accumulated={accumulated_risk:.2f}")
            
            if self.debug:
                risk_history = self.memory.get_risk_history(context["session_id"])
                log_dict(logger, "Risk Accumulation Details", {
                    "previous_accumulated": prev_accumulated,
                    "new_event_risk": event_risk_score,
                    "current_accumulated": accumulated_risk,
                    "risk_history_length": len(risk_history),
                    "risk_events_in_window": [{"score": r["risk_score"], "time": r["timestamp"]} for r in risk_history[-5:]]
                }, "DEBUG")
            
            context["accumulated_risk"] = accumulated_risk

        # 2. Policy Decision
        if self.policy:
            if self.debug:
                logger.debug("⚖️  Invoking Policy Engine...")
                log_dict(logger, "Policy Input", {
                    "tool_name": tool_name,
                    "args": args,
                    "context": context,
                    "event_risk_score": event_risk_score,
                    "confidence": confidence
                }, "DEBUG")
            
            policy_result = self.policy.evaluate(tool_name, args, context, event_risk_score, confidence)
            routing_target = policy_result["route"]
            reason = policy_result["reason"]
            
            logger.info(
                "Policy decision: route=%s rule=%s reason=%s",
                routing_target,
                policy_result.get("rule_id"),
                reason,
            )
            
            if self.debug:
                log_dict(logger, "Policy Decision", policy_result, "DEBUG")
                
            # Log when shadow routing is triggered
            if routing_target == "shadow":
                logger.warning(f"⚠️  SHADOW ROUTING TRIGGERED: {reason} (rule: {policy_result.get('rule_id')})")
        else:
            if accumulated_risk > 0.8: # Fallback to accumulated risk
                routing_target = "shadow"
                logger.warning(f"⚠️  SHADOW ROUTING (fallback): Accumulated risk {accumulated_risk:.2f} > 0.8")

        # 3. Issue Warrant via DKCA
        if self.authority:
            session_id = context.get("session_id", self.default_session_id)
            
            if self.debug:
                logger.debug(f"🔐 Issuing {routing_target.upper()} warrant via DKCA...")
            
            warrant = self.authority.issue_warrant(
                session_id=session_id,
                risk_score=accumulated_risk, # Use accumulated risk for the warrant
                route=routing_target,
            )
            
            if self.debug:
                log_dict(logger, "Issued Warrant", {
                    "session_id": session_id,
                    "warrant_type": routing_target,
                    "accumulated_risk": accumulated_risk,
                    "warrant_preview": warrant[:50] + "..." if len(warrant) > 50 else warrant
                }, "DEBUG")

            # Inject Warrant
            if "params" not in message_json:
                message_json["params"] = {}

            message_json["params"]["__chimera_warrant__"] = warrant

            # 4. Log to Immutable Forensic Ledger
            if self.ifl:
                event_id = self.ifl.log_event(
                    session_id=session_id,
                    event_type="TOOL_INTERCEPTION",
                    trigger={"tool": tool_name, "args": args, "risk_score": event_risk_score},
                    action={"warrant_type": routing_target, "reason": reason},
                    outcome={"routed_to": routing_target},
                    accumulated_risk=accumulated_risk,
                    risk_history_length=len(self.memory.get_risk_history(session_id))
                )
                
                if self.debug:
                    logger.debug(f"📜 Logged to IFL with event_id: {event_id}")

            if self.debug:
                log_separator(logger, f"✅ INTERCEPTION COMPLETE: Routing to {routing_target.upper()}", "DEBUG")

            return InterceptionResult(
                should_block=False,
                modified_message=message_json,
                routing_target=routing_target
            )
        else:
            logger.warning("DKCA unavailable, forwarding without warrant.")
            return InterceptionResult(should_block=False, routing_target="production")
