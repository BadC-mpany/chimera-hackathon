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
    priority: int = 100  # Higher = evaluated first
    override_risk: bool = False  # Ignore LLM risk score if True
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
    """
    A deterministic, rule-based engine that makes the final routing decision.
    """

    def __init__(self, settings: Dict[str, Any] = None):
        self.settings = settings or load_settings()
        policy_cfg = self.settings.get("policy", {})
        self.rules = sorted(
            policy_cfg.get("rules", []),
            key=lambda r: r.get("priority", 100),
            reverse=True,
        )
        self.defaults = policy_cfg.get("defaults", {})
        self.overrides = policy_cfg.get("overrides", {})

    def _check_overrides(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Check for manual overrides based on user ID or role."""
        user_id = context.get("user_id")
        user_role = context.get("user_role")
        if user_id and user_id in self.overrides.get("users", {}):
            return self.overrides["users"][user_id]
        if user_role and user_role in self.overrides.get("roles", {}):
            return self.overrides["roles"][user_role]
        return {}

    def evaluate(
        self,
        tool_name: str,
        args: Dict[str, Any],
        context: Dict[str, Any],
        risk_score: float,
        confidence: float = 1.0,
    ) -> Dict[str, Any]:
        """Return routing target and reason."""
        # Add the result of your trigger to the context
        context['is_suspicious_query'] = is_suspicious_query(args)

        # 1. Manual Overrides (HIGHEST PRIORITY)
        override = self._check_overrides(context)
        if override:
            return {**override, "rule_id": "override"}

        data = {"args": args, "context": context, "risk_score": risk_score}

        # 2. TAINT-AWARE ROUTING (High Priority Security)
        is_tainted = context.get("is_tainted", False)
        tool_category = self.tool_categories.get(tool_name, "safe")
        
        if is_tainted and tool_category == "sensitive":
            logger.warning(
                f"[TAINT LOCKDOWN] Tainted session attempting sensitive tool: {tool_name}"
            )
            return {
                "route": "shadow",
                "reason": f"Tainted session + sensitive tool ({tool_name})",
                "rule_id": "taint_lockdown",
            }

        # 3. PRIORITY-SORTED RULE EVALUATION
        # Sort rules by priority (highest first)
        sorted_rules = sorted(self.rules, key=lambda r: r.priority, reverse=True)
        
        for rule in sorted_rules:
            try:
                if rule.evaluate(tool_name, data, context):
                    # Check if rule overrides risk score
                    if rule.override_risk:
                        logger.info(
                            f"[POLICY] Rule {rule.id} matched with override_risk=true, "
                            f"routing to {rule.action} (ignoring risk_score={risk_score:.2f})"
                        )
                        return {
                            "route": rule.action,
                            "reason": rule.description or f"Rule {rule.id}",
                            "rule_id": rule.id,
                        }
                    else:
                        return {
                            "route": rule.action,
                            "reason": rule.description or f"Rule {rule.id}",
                            "rule_id": rule.id,
                        }
            except Exception as exc:
                logger.error("Error evaluating rule %s: %s", rule.id, exc)

        # 4. RISK THRESHOLD + CONFIDENCE CHECK
        threshold = float(self.defaults.get("risk_threshold", 0.8))
        min_confidence = float(self.defaults.get("min_confidence", 0.0))
        
        if risk_score >= threshold and confidence >= min_confidence:
            return {
                "route": "shadow",
                "reason": f"Risk={risk_score:.2f} >= {threshold}, Confidence={confidence:.2f} >= {min_confidence}",
                "rule_id": "risk_threshold",
            }
        elif risk_score >= threshold and confidence < min_confidence:
            logger.warning(
                f"[FAIL-SAFE] High risk ({risk_score:.2f}) but low confidence ({confidence:.2f}), "
                f"defaulting to PRODUCTION (benign-first)"
            )
            return {
                "route": "production",
                "reason": f"High risk but low confidence (confidence={confidence:.2f} < {min_confidence})",
                "rule_id": "low_confidence_failsafe",
            }

        # 5. DEFAULT: PRODUCTION (Benign-First Fail-Safe)
        return {
            "route": "production",
            "reason": "Risk below threshold",
            "rule_id": "default",
        }
