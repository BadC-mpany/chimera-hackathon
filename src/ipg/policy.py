import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.config import load_settings

logger = logging.getLogger(__name__)


def _deep_get(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    """Fetch nested dictionary keys using dot notation."""
    if not path:
        return default
    current: Any = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


def _compare(lhs: Any, operator: str, rhs: Any) -> bool:
    try:
        if operator == "eq":
            return lhs == rhs
        if operator == "neq":
            return lhs != rhs
        if operator == "gt":
            return float(lhs) > float(rhs)
        if operator == "gte":
            return float(lhs) >= float(rhs)
        if operator == "lt":
            return float(lhs) < float(rhs)
        if operator == "lte":
            return float(lhs) <= float(rhs)
        if operator == "contains":
            return str(rhs) in str(lhs)
        if operator == "regex":
            import re

            return bool(re.search(str(rhs), str(lhs)))
        if operator == "in":
            return lhs in rhs
        if operator == "not_in":
            return lhs not in rhs
    except Exception:
        return False
    logger.warning("Unknown operator '%s'. Defaulting to False.", operator)
    return False


@dataclass
class Condition:
    field: str
    operator: str = "eq"
    value: Optional[Any] = None
    value_from_context: Optional[str] = None

    def evaluate(self, data: Dict[str, Any], context: Dict[str, Any]) -> bool:
        lhs = _deep_get(data, self.field)
        rhs = (
            _deep_get({"context": context}, f"context.{self.value_from_context}")
            if self.value_from_context
            else self.value
        )
        return _compare(lhs, self.operator, rhs)


def _evaluate_clause(clause: Dict[str, Any], data: Dict[str, Any], context: Dict[str, Any]) -> bool:
    if "all" in clause:
        return all(
            _evaluate_clause(item, data, context)
            if isinstance(item, dict) and ("all" in item or "any" in item or "not" in item)
            else Condition(**item).evaluate(data, context)
            for item in clause["all"]
        )
    if "any" in clause:
        return any(
            _evaluate_clause(item, data, context)
            if isinstance(item, dict) and ("all" in item or "any" in item or "not" in item)
            else Condition(**item).evaluate(data, context)
            for item in clause["any"]
        )
    if "not" in clause:
        return not _evaluate_clause(clause["not"], data, context)
    # Fallback: treat clause itself as condition
    return Condition(**clause).evaluate(data, context)


@dataclass
class Rule:
    id: str
    action: str
    tools: List[str] = field(default_factory=list)
    match: Dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def applies_to(self, tool_name: str) -> bool:
        return not self.tools or tool_name in self.tools or "*" in self.tools

    def evaluate(self, tool_name: str, data: Dict[str, Any], context: Dict[str, Any]) -> bool:
        if not self.applies_to(tool_name):
            return False
        if not self.match:
            return True
        return _evaluate_clause(self.match, data, context)


def is_suspicious_query(args: Dict[str, Any]) -> bool:
    """
    A simple detector for suspicious keywords in tool arguments.
    """
    suspicious_keywords = ["password", "secret", "credit card", "ssn", "private_key", "formula"]
    args_str = json.dumps(args).lower()
    for keyword in suspicious_keywords:
        if keyword in args_str:
            logger.warning(f"[TRIGGER] Suspicious keyword '{keyword}' detected in query.")
            return True
    return False


class PolicyEngine:
    """Deterministic decision layer enforcing a structured, multi-phase policy manifest."""

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or load_settings()
        policy_cfg = self.settings.get("policy", {})

        self.default_action = policy_cfg.get("default_action", "production")
        self.evaluation_order = policy_cfg.get("evaluation_order", [
            "directives", "trusted_workflows", "security_policies", "risk_based_policies"
        ])

        # Store each policy section
        self.directives = policy_cfg.get("directives", {})
        self.trusted_workflows = [Rule(**r) for r in policy_cfg.get("trusted_workflows", [])]
        self.security_policies = [Rule(**r) for r in policy_cfg.get("security_policies", [])]
        self.risk_based_policies = policy_cfg.get("risk_based_policies", {})
        
        # Load tool categories from the backend tool definitions, not the policy file
        self.tool_categories: Dict[str, str] = {}
        backend_tools = self.settings.get("backend", {}).get("tools", {})
        for tool_name, tool_meta in backend_tools.items():
            self.tool_categories[tool_name] = tool_meta.get("category", "safe")

    def evaluate(
        self,
        tool_name: str,
        args: Dict[str, Any],
        context: Dict[str, Any],
        risk_score: float,
        confidence: float = 1.0,
    ) -> Dict[str, Any]:
        """Executes the policy manifest phases in order to determine the final routing decision."""
        # Inject additional context for rules to match against
        context['is_suspicious_query'] = is_suspicious_query(args)
        data = {
            "args": args,
            "context": context,
            "risk_score": risk_score,
            "confidence": confidence,
            "tool_category": self.tool_categories.get(tool_name, "safe")
        }

        for phase in self.evaluation_order:
            result = None
            if phase == "directives":
                result = self._evaluate_directives(context)
            elif phase == "trusted_workflows":
                result = self._evaluate_rules(tool_name, data, context, self.trusted_workflows)
            elif phase == "security_policies":
                result = self._evaluate_rules(tool_name, data, context, self.security_policies)
            elif phase == "risk_based_policies":
                result = self._evaluate_risk_based(risk_score, confidence)

            if result:
                return result

        # Fallback to default if no policies matched
        return {"route": self.default_action, "reason": "Default action", "rule_id": "default"}

    def _evaluate_directives(self, context: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Handles the 'directives' phase for manual user/role overrides."""
        user_id = context.get("user_id")
        if user_id and user_id in self.directives.get("users", {}):
            directive = self.directives["users"][user_id]
            return {
                "route": directive.get("action", self.default_action),
                "reason": directive.get("reason", f"Directive for user {user_id}"),
                "rule_id": f"directive-user-{user_id}",
            }
        
        user_role = context.get("user_role")
        if user_role and user_role in self.directives.get("roles", {}):
            directive = self.directives["roles"][user_role]
            return {
                "route": directive.get("action", self.default_action),
                "reason": directive.get("reason", f"Directive for role {user_role}"),
                "rule_id": f"directive-role-{user_role}",
            }
            
        return None

    def _evaluate_rules(self, tool_name: str, data: Dict[str, Any], context: Dict[str, Any], rules: List[Rule]) -> Optional[Dict[str, str]]:
        """Generic rule evaluation logic for a list of rules."""
        for rule in rules:
            try:
                if rule.evaluate(tool_name, data, context):
                    return {
                        "route": rule.action,
                        "reason": rule.description or f"Rule {rule.id}",
                        "rule_id": rule.id,
                    }
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.id}: {e}")
        return None

    def _evaluate_risk_based(self, risk_score: float, confidence: float) -> Optional[Dict[str, str]]:
        """Handles the 'risk_based_policies' phase using LLM scores."""
        cfg = self.risk_based_policies
        risk_threshold = cfg.get("risk_threshold", 0.8)
        min_confidence = cfg.get("min_confidence", 0.7)

        if risk_score >= risk_threshold and confidence >= min_confidence:
            return {
                "route": cfg.get("action", "shadow"),
                "reason": f"Risk {risk_score:.2f} >= {risk_threshold} and Confidence {confidence:.2f} >= {min_confidence}",
                "rule_id": "risk-based-high-confidence",
            }
        
        if risk_score >= risk_threshold and confidence < min_confidence:
            low_confidence_action = cfg.get("low_confidence_action", self.default_action)
            return {
                "route": low_confidence_action,
                "reason": f"High risk but low confidence ({confidence:.2f} < {min_confidence})",
                "rule_id": "risk-based-low-confidence-failsafe",
            }
            
        return None
