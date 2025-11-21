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


class PolicyEngine:
    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or load_settings()
        self.defaults: Dict[str, Any] = {
            "risk_threshold": 0.8,
            "fail_mode": "shadow",
        }
        self.rules: List[Rule] = []
        self.overrides: Dict[str, Any] = {"users": {}, "sessions": {}}
        self.tool_categories: Dict[str, str] = {}  # tool_name -> "safe" or "sensitive"
        self.reload()

    def reload(self) -> None:
        """Initialize rules/overrides from merged settings."""
        policy_data = self.settings.get("policy", {})
        self.defaults.update(policy_data.get("defaults", {}))
        self.rules = [Rule(**rule) for rule in policy_data.get("rules", [])]
        self.overrides = self.settings.get("overrides", {"users": {}, "sessions": {}})
        
        # Load tool categories
        tools_config = policy_data.get("tools", {})
        for tool_name, tool_meta in tools_config.items():
            category = tool_meta.get("category", "safe")  # Default to safe
            self.tool_categories[tool_name] = category
        
        logger.info("Policy loaded: %d rules (scenario=%s)", len(self.rules), self.settings.get("scenario", {}).get("active"))

    def _check_overrides(self, context: Dict[str, Any]) -> Optional[Dict[str, str]]:
        user_id = context.get("user_id")
        session_id = context.get("session_id")
        if user_id and user_id in self.overrides.get("users", {}):
            route = self.overrides["users"][user_id].get("force_route")
            if route:
                return {"route": route, "reason": f"Manual user override for {user_id}"}
        if session_id and session_id in self.overrides.get("sessions", {}):
            route = self.overrides["sessions"][session_id].get("force_route")
            if route:
                return {"route": route, "reason": f"Manual session override for {session_id}"}
        return None

    def evaluate(
        self,
        tool_name: str,
        args: Dict[str, Any],
        context: Dict[str, Any],
        risk_score: float,
    ) -> Dict[str, Any]:
        """Return routing target and reason."""
        override = self._check_overrides(context)
        if override:
            return {**override, "rule_id": "override"}

        data = {"args": args, "context": context, "risk_score": risk_score}

        # TAINT-AWARE ROUTING: Check if session is tainted AND tool is sensitive
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

        # Regular rule evaluation
        for rule in self.rules:
            try:
                if rule.evaluate(tool_name, data, context):
                    return {
                        "route": rule.action,
                        "reason": rule.description or f"Rule {rule.id}",
                        "rule_id": rule.id,
                    }
            except Exception as exc:
                logger.error("Error evaluating rule %s: %s", rule.id, exc)

        threshold = float(self.defaults.get("risk_threshold", 0.8))
        if risk_score >= threshold:
            return {
                "route": "shadow",
                "reason": f"Risk score {risk_score:.2f} >= threshold {threshold}",
                "rule_id": "risk_threshold",
            }

        return {
            "route": "production",
            "reason": "Risk below threshold",
            "rule_id": "default",
        }

