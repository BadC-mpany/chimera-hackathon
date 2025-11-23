import json
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple

from src.config import load_settings
from src.dkca.authority import TokenAuthority
from src.ifl.ledger import ImmutableForensicLedger
from src.ipg.attack_logger import AttackLogger
from src.ipg.memory import SessionMemory
from src.ipg.policy import PolicyEngine
from src.ipg.taint import TaintManager
from src.nsie.judge import ProbabilisticJudge

logger = logging.getLogger(__name__)

# Import logging utilities for enhanced debugging
try:
    from src.utils.logging_config import log_dict, log_separator, log_dashboard_event
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
    routing_target: str = "production"  # "production", "shadow", or "denied"
    denial_reason: Optional[str] = None  # Reason for access denial


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
            self.attack_logger = AttackLogger()
            logger.info("CHIMERA Interceptor initialized (DKCA + NSIE + Policy + IFL + Memory + Taint + AttackLogger).")
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
            self.attack_logger = None
        self.default_session_id = "session_123"

    async def process_message(self, raw_message: str) -> Tuple[str, str]:
        """
        Parses and inspects the message.
        Returns a tuple of (processed_message_str, routing_target).
        
        If access is denied, returns an error response directly.
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

        # Handle DENIAL (permission block)
        if result.should_block:
            error_response = {
                "jsonrpc": "2.0",
                "id": message_json.get("id"),
                "error": {
                    "code": -32000,
                    "message": result.denial_reason or "Access Denied"
                }
            }
            return json.dumps(error_response), "denied"

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
        
        # ALWAYS log tool interception comprehensively (not just in debug mode)
        logger.info("="*80)
        logger.info(f"TOOL INTERCEPTION: {tool_name}")
        logger.info("="*80)
        logger.info(f"TOOL ARGUMENTS: {json.dumps(args, indent=2)}")
        logger.info(f"SESSION: {context['session_id']}")
        logger.info(f"USER: {context['user_id']} (role: {context['user_role']})")
        logger.info(f"TAINTED: {context['is_tainted']}")
        if context.get('source_file'):
            logger.info(f"TAINT SOURCE: {context['source_file']}")
        logger.info("-"*80)

        # 0a. Update Memory (Legacy)
        if self.memory:
            self.memory.add_tool_call(context["session_id"], tool_name, args)
            history_len = len(self.memory.get_session(context["session_id"]).history)
            logger.info(f"Session tool call history length: {history_len}")

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
        logger.info("-"*80)
        logger.info("POLICY EVALUATION")
        logger.info("-"*80)
        
        if self.policy:
            policy_result = self.policy.evaluate(tool_name, args, context, event_risk_score, confidence)
            routing_target = policy_result["route"]
            reason = policy_result["reason"]
            
            # ALWAYS log policy decision comprehensively
            logger.info(f"ROUTE: {routing_target.upper()}")
            logger.info(f"RULE: {policy_result.get('rule_id')}")
            logger.info(f"REASON: {reason}")
            logger.info(f"EVENT RISK: {event_risk_score:.3f}")
            logger.info(f"ACCUMULATED RISK: {accumulated_risk:.3f}")
            logger.info(f"CONFIDENCE: {confidence:.3f}")
            
            # Log the comprehensive event for the dashboard
            log_dashboard_event(
                message=f"Tool call '{tool_name}' intercepted and routed to {routing_target}.",
                data={
                    "event_type": "tool_interception",
                    "session_id": context.get("session_id"),
                    "user_id": context.get("user_id"),
                    "user_role": context.get("user_role"),
                    "tool_name": tool_name,
                    "tool_args": args,
                    "nsie_risk_score": event_risk_score,
                    "nsie_reason": assessment.reason if 'assessment' in locals() else "N/A",
                    "accumulated_risk": accumulated_risk,
                    "policy_rule_id": policy_result.get("rule_id"),
                    "policy_reason": reason,
                    "final_route": routing_target,
                    "is_tainted": context.get("is_tainted", False),
                }
            )
            
            # Handle DENY action (permission block)
            if routing_target == "deny":
                logger.warning(f"🚫 ACCESS DENIED: {reason} (rule: {policy_result.get('rule_id')})")
                logger.info("="*80 + "\n")
                
                if self.debug:
                    log_separator(logger, "❌ INTERCEPTION COMPLETE: Access Denied", "DEBUG")
                
                return InterceptionResult(
                    should_block=True,
                    routing_target="denied",
                    denial_reason=reason
                )
                
            # Log when shadow routing is triggered (ATTACK DETECTED)
            if routing_target == "shadow":
                logger.warning(f"⚠️  SHADOW ROUTING TRIGGERED: {reason} (rule: {policy_result.get('rule_id')})")
                
                # Start attack session tracking
                if self.attack_logger and not self.attack_logger.is_session_active(context["session_id"]):
                    self.attack_logger.start_attack_session(
                        session_id=context["session_id"],
                        trigger_reason=reason,
                        trigger_risk_score=event_risk_score,
                        context=context
                    )
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
            
            # 5. Log attack interaction if in shadow mode
            if routing_target == "shadow" and self.attack_logger:
                # Note: We log the interaction now, response will be captured in transport layer
                self.attack_logger.log_interaction(
                    session_id=session_id,
                    interaction_id=event_id,  # Use IFL event_id for correlation
                    tool_name=tool_name,
                    tool_args=args,
                    risk_score=event_risk_score,
                    response="[Response will be captured in transport]",  # Placeholder
                    accumulated_risk=accumulated_risk,
                    context=context
                )

            # ALWAYS log completion summary
            logger.info("="*80)
            logger.info(f"INTERCEPTION COMPLETE: {tool_name} → {routing_target.upper()}")
            logger.info(f"Warrant issued: {routing_target.upper()}")
            if routing_target == "shadow":
                logger.info("⚠️  HONEYPOT DATA WILL BE SERVED")
            logger.info("="*80 + "\n")

            return InterceptionResult(
                should_block=False,
                modified_message=message_json,
                routing_target=routing_target
            )
        else:
            logger.warning("DKCA unavailable, forwarding without warrant.")
            logger.info("="*80 + "\n")
            return InterceptionResult(should_block=False, routing_target="production")
