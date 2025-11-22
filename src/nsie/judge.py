import json
import logging
import os
from typing import Any, Dict, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.pydantic_v1 import BaseModel, Field

from src.config import load_settings

from .llm_clients import get_llm_client

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
    """
    An LLM-as-a-judge that evaluates the potential risk of a tool call.
    """

    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or load_settings()
        nsie_cfg = self.settings.get("nsie", {})
        
        self.llm = get_llm_client()
        self.parser = JsonOutputParser(pydantic_object=RiskAssessment)

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
