"""
Conversation Memory Management for Multi-Turn Interactions

Implements a security-aware memory system that:
1. Maintains full conversation history (user queries, tool calls, LLM responses) in normal mode
2. Strips tool call data after shadow realm trigger to prevent exfiltration
3. Preserves conversation consistency while protecting sensitive information
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum

from src.config import load_settings

# Load debug setting
_settings = load_settings()
DEBUG_MODE = _settings.get("agent", {}).get("debug", False)


class MessageType(Enum):
    """Types of messages in conversation history"""
    USER_QUERY = "user_query"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    LLM_RESPONSE = "llm_response"


@dataclass
class ConversationMessage:
    """Single message in conversation history"""
    type: MessageType
    content: str
    timestamp: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Security flags
    contains_sensitive_data: bool = False
    from_shadow_realm: bool = False


@dataclass
class ConversationSession:
    """A complete conversation session with security-aware memory"""
    session_id: str
    created_at: float = field(default_factory=time.time)
    messages: List[ConversationMessage] = field(default_factory=list)
    
    # Security state
    is_in_shadow: bool = False
    shadow_triggered_at: Optional[float] = None
    trigger_reason: Optional[str] = None
    
    # Context tracking
    taint_source: Optional[str] = None
    risk_score: float = 0.0
    warrant_type: Optional[str] = None  # 'prime' or 'shadow'


class ConversationMemory:
    """
    Manages multi-turn conversation memory with security-aware filtering.
    
    Strategy:
    - Before shadow trigger: Store full history (user, tool, LLM)
    - After shadow trigger: Store only user queries and LLM responses
    - Tool results from shadow realm are NOT stored in history
    - Maintains conversation consistency while preventing data exfiltration
    """
    
    def __init__(self):
        self._sessions: Dict[str, ConversationSession] = {}
    
    def get_session(self, session_id: str) -> ConversationSession:
        """Get or create a conversation session"""
        if session_id not in self._sessions:
            self._sessions[session_id] = ConversationSession(session_id=session_id)
        return self._sessions[session_id]
    
    def add_user_query(self, session_id: str, query: str, metadata: Optional[Dict] = None):
        """
        Add user query to conversation history.
        Always stored, regardless of shadow state.
        """
        session = self.get_session(session_id)
        msg = ConversationMessage(
            type=MessageType.USER_QUERY,
            content=query,
            timestamp=time.time(),
            metadata=metadata or {},
            from_shadow_realm=session.is_in_shadow
        )
        session.messages.append(msg)
        if DEBUG_MODE:
            print(f"[MEMORY DEBUG] Added USER_QUERY to session {session_id}. Total messages: {len(session.messages)}")
    
    def add_tool_call(self, session_id: str, tool_name: str, args: Dict[str, Any], 
                      result: Optional[str] = None, metadata: Optional[Dict] = None):
        """
        Add tool call and result to history.
        
        Security logic:
        - If NOT in shadow: Store everything
        - If IN shadow: Only store if needed for consistency, mark as sensitive
        """
        session = self.get_session(session_id)
        
        # Check if this should trigger shadow mode (taint logic)
        if tool_name == "read_file" and not session.is_in_shadow:
            path = args.get("path") or args.get("filename", "")
            if "resume" in path.lower() or "upload" in path.lower():
                session.taint_source = path
        
        # Tool call message
        tool_call_msg = ConversationMessage(
            type=MessageType.TOOL_CALL,
            content=f"{tool_name}({args})",
            timestamp=time.time(),
            metadata={**(metadata or {}), "tool_name": tool_name, "args": args},
            contains_sensitive_data=session.is_in_shadow,
            from_shadow_realm=session.is_in_shadow
        )
        
        # Tool result message
        if result is not None:
            tool_result_msg = ConversationMessage(
                type=MessageType.TOOL_RESULT,
                content=result,
                timestamp=time.time(),
                metadata={**(metadata or {}), "tool_name": tool_name},
                contains_sensitive_data=session.is_in_shadow,
                from_shadow_realm=session.is_in_shadow
            )
        else:
            tool_result_msg = None
        
        # Add to history based on shadow state
        if not session.is_in_shadow:
            # Production: store everything
            session.messages.append(tool_call_msg)
            if tool_result_msg:
                session.messages.append(tool_result_msg)
        else:
            # Shadow: only store for immediate context, will be filtered later
            # Mark as sensitive to be excluded from LLM context
            session.messages.append(tool_call_msg)
            if tool_result_msg:
                session.messages.append(tool_result_msg)
    
    def add_llm_response(self, session_id: str, response: str, metadata: Optional[Dict] = None):
        """
        Add LLM response to history.
        Always stored, as it's already been outputted to user.
        """
        session = self.get_session(session_id)
        msg = ConversationMessage(
            type=MessageType.LLM_RESPONSE,
            content=response,
            timestamp=time.time(),
            metadata=metadata or {},
            from_shadow_realm=session.is_in_shadow
        )
        session.messages.append(msg)
        if DEBUG_MODE:
            print(f"[MEMORY DEBUG] Added LLM_RESPONSE to session {session_id}. Total messages: {len(session.messages)}")
    
    def trigger_shadow_mode(self, session_id: str, reason: str, risk_score: float = 0.0):
        """
        Trigger shadow realm for this session.
        After this point, tool data will be filtered from context.
        """
        session = self.get_session(session_id)
        if not session.is_in_shadow:
            session.is_in_shadow = True
            session.shadow_triggered_at = time.time()
            session.trigger_reason = reason
            session.risk_score = risk_score
            session.warrant_type = "shadow"
    
    def set_warrant_type(self, session_id: str, warrant_type: str):
        """Set the warrant type (prime/shadow) for this session"""
        session = self.get_session(session_id)
        session.warrant_type = warrant_type
        if warrant_type == "shadow" and not session.is_in_shadow:
            session.is_in_shadow = True
            session.shadow_triggered_at = time.time()
    
    def get_conversation_history(self, session_id: str, 
                                  include_tool_data: bool = True,
                                  max_turns: Optional[int] = None) -> List[Dict[str, str]]:
        """
        Get conversation history formatted for LLM context.
        
        Args:
            session_id: Session identifier
            include_tool_data: If False, excludes tool calls/results (for shadow mode)
            max_turns: Maximum number of turns to include (for context window management)
        
        Returns:
            List of messages formatted as {"role": "...", "content": "..."}
        """
        session = self.get_session(session_id)
        
        # Determine if we should filter tool data
        filter_tools = session.is_in_shadow and not include_tool_data
        
        formatted_messages = []
        for msg in session.messages:
            # Skip tool data if in shadow mode and filtering is enabled
            if filter_tools and msg.type in (MessageType.TOOL_CALL, MessageType.TOOL_RESULT):
                # Only skip NEW tool data from shadow realm
                # Keep tool data that was already exposed before trigger
                if msg.from_shadow_realm or msg.contains_sensitive_data:
                    continue
            
            # Map message types to LLM roles
            if msg.type == MessageType.USER_QUERY:
                formatted_messages.append({
                    "role": "user",
                    "content": msg.content
                })
            elif msg.type == MessageType.LLM_RESPONSE:
                formatted_messages.append({
                    "role": "assistant",
                    "content": msg.content
                })
            elif msg.type == MessageType.TOOL_CALL and not filter_tools:
                # Include tool calls as system messages if not filtered
                formatted_messages.append({
                    "role": "system",
                    "content": f"[Tool Call] {msg.content}"
                })
            elif msg.type == MessageType.TOOL_RESULT and not filter_tools:
                # Include tool results as system messages if not filtered
                formatted_messages.append({
                    "role": "system",
                    "content": f"[Tool Result] {msg.content[:200]}..."  # Truncate for context
                })
        
        # Limit to max_turns if specified
        if max_turns and len(formatted_messages) > max_turns * 2:
            # Keep system prompt + last N turns
            formatted_messages = formatted_messages[-(max_turns * 2):]
        
        return formatted_messages
    
    def get_session_info(self, session_id: str) -> Dict[str, Any]:
        """Get session metadata and security status"""
        session = self.get_session(session_id)
        return {
            "session_id": session.session_id,
            "created_at": session.created_at,
            "message_count": len(session.messages),
            "is_in_shadow": session.is_in_shadow,
            "shadow_triggered_at": session.shadow_triggered_at,
            "trigger_reason": session.trigger_reason,
            "taint_source": session.taint_source,
            "risk_score": session.risk_score,
            "warrant_type": session.warrant_type
        }
    
    def clear_session(self, session_id: str):
        """Clear session history (for testing or explicit user request)"""
        if session_id in self._sessions:
            del self._sessions[session_id]
    
    def get_taint(self, session_id: str) -> Optional[str]:
        """Get taint source for backward compatibility with SessionMemory"""
        return self.get_session(session_id).taint_source
