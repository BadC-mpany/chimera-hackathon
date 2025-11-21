import json
import logging
import os
from typing import Any, Dict, List

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from src.config import load_settings

logger = logging.getLogger(__name__)


def _deep_get(container: Dict[str, Any], path: str) -> Any:
    current: Any = container
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _compare(lhs: Any, operator: str, rhs: Any) -> bool:
    try:
        if operator == "eq":
            return lhs == rhs
        if operator == "neq":
            return lhs != rhs
        if operator == "contains":
            return str(rhs) in str(lhs)
        if operator == "regex":
            import re

            return bool(re.search(str(rhs), str(lhs)))
        if operator == "gt":
            return float(lhs) > float(rhs)
        if operator == "gte":
            return float(lhs) >= float(rhs)
        if operator == "lt":
            return float(lhs) < float(rhs)
        if operator == "lte":
            return float(lhs) <= float(rhs)
    except Exception:
        return False
    return False


class RiskAssessment(BaseModel):
    risk_score: float = Field(description="A score from 0.0 (Safe) to 1.0 (High Threat)")
    confidence: float = Field(default=1.0, description="Confidence in the assessment (0.0-1.0)")
    reason: str = Field(description="The reasoning behind the risk score")
    violation_tags: List[str] = Field(default_factory=list)


class ProbabilisticJudge:
    """LLM-as-a-Judge that evaluates tool calls for malicious intent."""

    def __init__(self, settings: Dict[str, Any] = None):
        self.settings = settings or load_settings()
        nsie_cfg = self.settings.get("nsie", {})
        self.prompt_template = nsie_cfg.get("prompt_template") or (
            "You are a vigilant security AI. Return JSON with risk_score (0.0-1.0), "
            "confidence (0.0-1.0, how certain you are), reason, and violation_tags."
        )
        self.mock_rules = nsie_cfg.get("mock_rules", [])
        self.default_mock = nsie_cfg.get("default_mock", {"risk_score": 0.1, "reason": "Mock: Default safe."})

        api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("OPENROUTER_BASE_URL")
        model_name = os.getenv("GUARDRAIL_MODEL", os.getenv("OPENROUTER_MODEL", "gpt-4o-mini"))

        if not api_key:
            logger.warning("No API Key found for NSIE Judge. Falling back to MOCK mode.")
            self.llm = None
        else:
            self.llm = ChatOpenAI(
                model=model_name,
                temperature=0,
                api_key=api_key,
                base_url=base_url,
            )

    async def evaluate_risk(
        self, tool_name: str, args: Dict[str, Any], context: Dict[str, Any]
    ) -> RiskAssessment:
        if not self.llm:
            return self._mock_assessment(tool_name, args, context)

        user_prompt = f"""Analyze this tool call:
        Tool: {tool_name}
        Arguments: {json.dumps(args)}
        Context: {json.dumps(context)}
        """
        messages = [
            SystemMessage(content=self.prompt_template),
            HumanMessage(content=user_prompt),
        ]

        try:
            response = await self.llm.ainvoke(messages)
            parsed_response = json.loads(response.content)
            return RiskAssessment(**parsed_response)
        except Exception as exc:
            logger.error("Judge Evaluation Failed: %s", exc)
            return RiskAssessment(risk_score=0.9, reason=f"Guardrail Failure: {exc}", violation_tags=["LLM_ERROR"])

    def _mock_assessment(self, tool_name: str, args: Dict[str, Any], context: Dict[str, Any]) -> RiskAssessment:
        payload = {"args": args, "context": context, "tool": tool_name}
        for rule in self.mock_rules:
            tools = rule.get("tools") or []
            if tools and tool_name not in tools:
                continue
            field = rule.get("field")
            operator = rule.get("operator", "eq")
            expected = rule.get("value")
            if field and _compare(_deep_get(payload, field), operator, expected):
                return RiskAssessment(
                    risk_score=rule.get("risk_score", 0.5),
                    confidence=rule.get("confidence", 1.0),
                    reason=rule.get("reason", "Mock rule triggered."),
                    violation_tags=rule.get("tags", []),
                )

        return RiskAssessment(
            risk_score=self.default_mock.get("risk_score", 0.1),
            confidence=self.default_mock.get("confidence", 1.0),
            reason=self.default_mock.get("reason", "Mock: Default safe."),
            violation_tags=self.default_mock.get("tags", []),
        )
