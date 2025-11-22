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


    # def __init__(self, settings: Optional[Dict[str, Any]] = None):
    #     self.settings = settings or load_settings()
    #     self.defaults: Dict[str, Any] = {
    #         "risk_threshold": 0.8,
    #         "fail_mode": "shadow",
    #     }
    #     self.rules: List[Rule] = []
    #     self.overrides: Dict[str, Any] = {"users": {}, "sessions": {}}
    #     self.tool_categories: Dict[str, str] = {}  # tool_name -> "safe" or "sensitive"
    #     self.reload()

    # def reload(self) -> None:
    #     """Initialize rules/overrides from merged settings."""
    #     policy_data = self.settings.get("policy", {})
    #     self.defaults.update(policy_data.get("defaults", {}))
    #     self.rules = [Rule(**rule) for rule in policy_data.get("rules", [])]
    #     self.overrides = self.settings.get("overrides", {"users": {}, "sessions": {}})
        
    #     # Load tool categories
    #     tools_config = policy_data.get("tools", {})
    #     for tool_name, tool_meta in tools_config.items():
    #         category = tool_meta.get("category", "safe")  # Default to safe
    #         self.tool_categories[tool_name] = category
        
    #     logger.info("Policy loaded: %d rules (scenario=%s)", len(self.rules), self.settings.get("scenario", {}).get("active"))

    # def _check_overrides(self, context: Dict[str, Any]) -> Optional[Dict[str, str]]:
    #     user_id = context.get("user_id")
    #     session_id = context.get("session_id")
    #     if user_id and user_id in self.overrides.get("users", {}):
    #         route = self.overrides["users"][user_id].get("force_route")
    #         if route:
    #             return {"route": route, "reason": f"Manual user override for {user_id}"}
    #     if session_id and session_id in self.overrides.get("sessions", {}):
    #         route = self.overrides["sessions"][session_id].get("force_route")
    #         if route:
    #             return {"route": route, "reason": f"Manual session override for {session_id}"}
    #     return None

    
    """
    A deterministic, rule-based engine that makes the final routing decision.
    """

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or load_settings()
        policy_cfg = self.settings.get("policy", {})

        defaults = {
            "risk_threshold": 0.8,
            "min_confidence": 0.5,
            "fail_mode": "production",
            "trusted_risk_threshold": 0.95,
            "override_priority_floor": 900,
        }
        defaults.update(policy_cfg.get("defaults", {}))
        self.defaults = defaults

        self.rules: List[Rule] = []
        for rule_cfg in policy_cfg.get("rules", []):
            self.rules.append(
                Rule(
                    id=rule_cfg.get("id", "rule"),
                    action=rule_cfg.get("action", "production"),
                    priority=int(rule_cfg.get("priority", 100)),
                    override_risk=bool(rule_cfg.get("override_risk", False)),
                    tools=rule_cfg.get("tools") or [],
                    match=rule_cfg.get("match", {}),
                    description=rule_cfg.get("description", ""),
                )
            )
        self.rules.sort(key=lambda r: r.priority, reverse=True)

        self.tool_categories: Dict[str, str] = {}
        for tool_name, tool_meta in policy_cfg.get("tools", {}).items():
            self.tool_categories[tool_name] = tool_meta.get("category", "safe")

        overrides = self.settings.get("overrides", {}) or {}
        overrides.setdefault("users", {})
        overrides.setdefault("roles", {})
        overrides.setdefault("sessions", {})
        policy_overrides = policy_cfg.get("overrides")
        if policy_overrides:
            policy_overrides.setdefault("users", {})
            policy_overrides.setdefault("roles", {})
            policy_overrides.setdefault("sessions", {})
            overrides = policy_overrides
        self.overrides = overrides

    def _check_overrides(self, context: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Check for manual overrides based on user ID or role."""
        user_id = context.get("user_id")
        user_role = context.get("user_role")

        if user_id and user_id in self.overrides.get("users", {}):
            override = self.overrides["users"][user_id]
            route = override.get("route") or override.get("action") or override.get("force_route")
            if not route:
                route = self.defaults.get("fail_mode", "production")
            reason = override.get("reason", f"Manual override for user {user_id}")
            return {"route": route, "reason": reason}

        if user_role and user_role in self.overrides.get("roles", {}):
            override = self.overrides["roles"][user_role]
            route = override.get("route") or override.get("action") or override.get("force_route")
            if not route:
                route = self.defaults.get("fail_mode", "production")
            reason = override.get("reason", f"Manual override for role {user_role}")
            return {"route": route, "reason": reason}

        return None

    def evaluate(
        self,
        tool_name: str,
        args: Dict[str, Any],
        context: Dict[str, Any],
        risk_score: float,
        confidence: float = 1.0,
    ) -> Dict[str, Any]:
        """Return routing target and reason."""
        context["is_suspicious_query"] = is_suspicious_query(args)

        override = self._check_overrides(context)
        if override:
            return {**override, "rule_id": "override"}

        data = {"args": args, "context": context, "risk_score": risk_score, "confidence": confidence}
        high_priority_floor = int(self.defaults.get("override_priority_floor", 900))
        trusted_risk_threshold = float(self.defaults.get("trusted_risk_threshold", 0.95))

        # High-priority override rules (execute before taint lockdown)
        for rule in self.rules:
            if not (rule.override_risk and rule.priority >= high_priority_floor):
                continue
            try:
                if rule.evaluate(tool_name, data, context):
                    logger.info("[POLICY] High-priority override matched: %s", rule.id)
                    return {
                        "route": rule.action,
                        "reason": rule.description or f"Rule {rule.id} (override)",
                        "rule_id": rule.id,
                    }
            except Exception as exc:
                logger.error("Error evaluating override rule %s: %s", rule.id, exc)

        # Taint lockdown for sensitive tools
        is_tainted = context.get("is_tainted", False)
        tool_category = self.tool_categories.get(tool_name, "safe")
        if is_tainted and tool_category == "sensitive":
            logger.warning("[TAINT LOCKDOWN] Tainted session attempting sensitive tool: %s", tool_name)
            return {
                "route": "shadow",
                "reason": f"Tainted session + sensitive tool ({tool_name})",
                "rule_id": "taint_lockdown",
            }

        # Remaining rules (already sorted by priority)
        for rule in self.rules:
            if rule.override_risk and rule.priority >= high_priority_floor:
                continue
            try:
                if not rule.evaluate(tool_name, data, context):
                    continue

                if rule.override_risk:
                    return {
                        "route": rule.action,
                        "reason": rule.description or f"Rule {rule.id} (override)",
                        "rule_id": rule.id,
                    }

                if rule.action == "production" and risk_score >= trusted_risk_threshold:
                    logger.info(
                        "[POLICY] Rule %s matched but risk %.2f >= trusted threshold %.2f; skipping",
                        rule.id,
                        risk_score,
                        trusted_risk_threshold,
                    )
                    continue

                return {
                    "route": rule.action,
                    "reason": rule.description or f"Rule {rule.id}",
                    "rule_id": rule.id,
                }
            except Exception as exc:
                logger.error("Error evaluating rule %s: %s", rule.id, exc)

        # Risk/confidence fallback
        threshold = float(self.defaults.get("risk_threshold", 0.8))
        min_confidence = float(self.defaults.get("min_confidence", 0.7))
        fail_mode = self.defaults.get("fail_mode", "production")

        if risk_score >= threshold and confidence >= min_confidence:
            return {
                "route": "shadow",
                "reason": f"Risk score {risk_score:.2f} >= threshold {threshold:.2f} "
                f"and confidence {confidence:.2f} >= {min_confidence:.2f}",
                "rule_id": "risk_threshold",
            }

        if risk_score >= threshold and confidence < min_confidence:
            logger.warning(
                "[FAIL-SAFE] High risk %.2f but low confidence %.2f; defaulting to %s",
                risk_score,
                confidence,
                fail_mode,
            )
            return {
                "route": fail_mode if fail_mode in ("production", "shadow") else "production",
                "reason": f"High risk but low confidence ({confidence:.2f} < {min_confidence:.2f})",
                "rule_id": "risk_threshold_low_confidence",
            }

        return {
            "route": fail_mode if fail_mode in ("production", "shadow") else "production",
            "reason": "Risk below threshold or no specific rule matched",
            "rule_id": "default",
        }
