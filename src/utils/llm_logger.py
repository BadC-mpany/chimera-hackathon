# Copyright 2025 Badcompany
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
LLM Call Logger - Captures complete LLM API interactions for debugging.
"""
import json
import logging
from typing import Any, Dict, List, Optional
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import BaseMessage
from langchain_core.outputs import LLMResult

logger = logging.getLogger(__name__)


class LLMCallLogger(BaseCallbackHandler):
    """
    Callback handler that logs complete LLM API calls and responses.
    Captures system prompts, tools, messages, and full responses.
    """
    
    def __init__(self, turn_logger=None):
        self.turn_logger = turn_logger
        self.session_id: Optional[str] = None
        self.current_request: Optional[Dict[str, Any]] = None
    
    def set_session(self, session_id: str):
        """Set the current session ID for logging."""
        self.session_id = session_id
    
    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[BaseMessage]],
        **kwargs: Any
    ) -> None:
        """Called when LLM starts processing."""
        try:
            # Extract model configuration
            invocation_params = kwargs.get("invocation_params", {})
            
            # Build complete request representation
            request_data = {
                "model": invocation_params.get("model", "unknown"),
                "temperature": invocation_params.get("temperature", 0),
                "base_url": invocation_params.get("base_url"),
                "messages": self._serialize_messages(messages[0] if messages else []),
                "tools": invocation_params.get("tools", []),
                "tool_choice": invocation_params.get("tool_choice"),
                "invocation_params": invocation_params
            }
            
            self.current_request = request_data
            
            # Log to turn logger if available
            if self.turn_logger and self.session_id:
                self.turn_logger.log_agent_llm_request(self.session_id, request_data)
            
            # Also log to standard logger
            logger.debug("="*80)
            logger.debug("LLM REQUEST")
            logger.debug("="*80)
            logger.debug(f"Model: {request_data['model']}")
            logger.debug(f"Temperature: {request_data['temperature']}")
            logger.debug(f"Messages: {len(request_data['messages'])}")
            for i, msg in enumerate(request_data['messages']):
                role = msg.get('role', 'unknown')
                content = msg.get('content', '')
                content_preview = content[:200] if len(content) > 200 else content
                logger.debug(f"  [{i}] {role}: {content_preview}")
            if request_data.get('tools'):
                logger.debug(f"Tools: {len(request_data['tools'])} available")
                for tool in request_data['tools']:
                    tool_name = tool.get('function', {}).get('name', 'unknown')
                    logger.debug(f"  - {tool_name}")
                    
        except Exception as e:
            logger.error(f"Error in on_chat_model_start: {e}", exc_info=True)
    
    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        """Called when LLM finishes."""
        try:
            # Extract response data
            response_data = {
                "generations": [],
                "llm_output": response.llm_output or {}
            }
            
            for generation_list in response.generations:
                for generation in generation_list:
                    gen_data = {
                        "text": generation.text if hasattr(generation, 'text') else None,
                        "message": self._serialize_message(generation.message) if hasattr(generation, 'message') else None,
                        "generation_info": generation.generation_info if hasattr(generation, 'generation_info') else None
                    }
                    response_data["generations"].append(gen_data)
            
            # Log to turn logger if available
            if self.turn_logger and self.session_id:
                self.turn_logger.log_agent_llm_response(self.session_id, response_data)
            
            # Also log to standard logger
            logger.debug("="*80)
            logger.debug("LLM RESPONSE")
            logger.debug("="*80)
            for i, gen in enumerate(response_data["generations"]):
                if gen.get("text"):
                    logger.debug(f"Generation [{i}]: {gen['text'][:200]}")
                if gen.get("message"):
                    msg = gen["message"]
                    content = msg.get("content", "")
                    logger.debug(f"Message [{i}]: {content[:200] if content else 'No content'}")
                    if msg.get("tool_calls"):
                        logger.debug(f"  Tool calls: {len(msg['tool_calls'])}")
                        for tc in msg["tool_calls"]:
                            logger.debug(f"    - {tc.get('name')}: {tc.get('args')}")
            
            logger.debug("="*80)
                    
        except Exception as e:
            logger.error(f"Error in on_llm_end: {e}", exc_info=True)
    
    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        """Called when LLM errors."""
        logger.error(f"LLM Error: {error}", exc_info=True)
        if self.turn_logger and self.session_id:
            error_data = {"error": str(error), "type": type(error).__name__}
            self.turn_logger.log_agent_llm_response(self.session_id, error_data)
    
    def _serialize_messages(self, messages: List[BaseMessage]) -> List[Dict[str, Any]]:
        """Convert LangChain messages to JSON-serializable format."""
        return [self._serialize_message(msg) for msg in messages]
    
    def _serialize_message(self, message: BaseMessage) -> Dict[str, Any]:
        """Convert a single message to dict."""
        msg_dict = {
            "role": self._get_role(message),
            "content": message.content if hasattr(message, 'content') else str(message)
        }
        
        # Add tool calls if present
        if hasattr(message, 'additional_kwargs'):
            additional = message.additional_kwargs
            if 'tool_calls' in additional:
                msg_dict['tool_calls'] = [
                    {
                        "id": tc.get("id"),
                        "type": tc.get("type"),
                        "name": tc.get("function", {}).get("name"),
                        "args": json.loads(tc.get("function", {}).get("arguments", "{}"))
                    }
                    for tc in additional['tool_calls']
                ]
        
        return msg_dict
    
    def _get_role(self, message: BaseMessage) -> str:
        """Get the role string from a message."""
        if hasattr(message, 'type'):
            role_map = {
                'human': 'user',
                'ai': 'assistant',
                'system': 'system',
                'function': 'function',
                'tool': 'tool'
            }
            return role_map.get(message.type, message.type)
        return 'unknown'
