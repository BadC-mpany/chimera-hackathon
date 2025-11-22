"""
Multi-turn conversation agent with security-aware memory

This is a simplified version that properly implements:
1. Multi-turn conversation with full history
2. Security-aware memory filtering when shadow realm is triggered
3. LangGraph checkpointing for proper state management
"""

import os
import sys
from typing import Dict, List, Any
from dotenv import load_dotenv

from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver

from src.ipg.conversation_memory import ConversationMemory

load_dotenv()

# Initialize conversation memory
conversation_memory = ConversationMemory()


def create_multiturn_agent(tools: List, session_id: str):
    """
    Create a ReAct agent with multi-turn conversation support.
    
    Uses LangGraph's MemorySaver for checkpointing and our custom
    ConversationMemory for security-aware filtering.
    """
    api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENROUTER_MODEL", "gpt-4-turbo-preview")
    base_url = os.getenv("OPENROUTER_BASE_URL")
    
    llm = ChatOpenAI(model=model, api_key=api_key, base_url=base_url, temperature=0)
    
    # System prompt
    system_prompt = """You are a helpful assistant with access to secure tools.
Maintain conversation context across multiple turns.
Use tools when needed to fulfill user requests."""
    
    # Create agent with memory checkpointing
    memory = MemorySaver()
    agent = create_react_agent(llm, tools=tools, checkpointer=memory)
    
    return agent, memory


def run_multiturn_query(agent, session_id: str, query: str, config: Dict[str, Any]) -> str:
    """
    Execute a query with full conversation history.
    
    Args:
        agent: The LangGraph agent
        session_id: Session identifier for memory
        query: User query
        config: Agent configuration with checkpointing
    
    Returns:
        Agent's response
    """
    # Get session info to check shadow status
    session_info = conversation_memory.get_session_info(session_id)
    is_in_shadow = session_info["is_in_shadow"]
    
    # Add user query to our security-aware memory
    conversation_memory.add_user_query(session_id, query)
    
    # Get filtered conversation history
    # If in shadow mode, this will exclude tool data from shadow realm
    history = conversation_memory.get_conversation_history(
        session_id, 
        include_tool_data=not is_in_shadow  # Exclude tool data if in shadow
    )
    
    # Convert to LangChain messages
    messages = []
    for msg in history:
        if msg["role"] == "user":
            messages.append(HumanMessage(content=msg["content"]))
        elif msg["role"] == "assistant":
            messages.append(AIMessage(content=msg["content"]))
        elif msg["role"] == "system":
            messages.append(SystemMessage(content=msg["content"]))
    
    # Add current query
    messages.append(HumanMessage(content=query))
    
    # Invoke agent with conversation history
    result = agent.invoke(
        {"messages": messages},
        config=config
    )
    
    # Extract response
    final_message = result.get("messages", [])[-1] if result.get("messages") else None
    response = final_message.content if final_message and hasattr(final_message, "content") else "(No response)"
    
    # Add response to our memory
    conversation_memory.add_llm_response(session_id, response)
    
    return response


# Example usage function
def test_multiturn_conversation():
    """Test multi-turn conversation with shadow trigger"""
    from langchain_core.tools import tool
    
    @tool
    def read_file(path: str) -> str:
        """Read a file from the filesystem"""
        # Simulate file reading
        if "secret" in path.lower():
            return "SECRET DATA: Confidential information"
        return f"File contents from {path}"
    
    session_id = "test_session_123"
    
    # Create agent
    agent, memory = create_multiturn_agent([read_file], session_id)
    config = {"configurable": {"thread_id": session_id}}
    
    print("\n=== Multi-Turn Conversation Test ===\n")
    
    # Turn 1: Normal query
    print("User: Hello, what can you do?")
    response1 = run_multiturn_query(agent, session_id, "Hello, what can you do?", config)
    print(f"Agent: {response1}\n")
    
    # Turn 2: Use tool (production)
    print("User: Read the file 'data/public.txt'")
    response2 = run_multiturn_query(agent, session_id, "Read the file 'data/public.txt'", config)
    print(f"Agent: {response2}\n")
    
    # Turn 3: Remember context
    print("User: What was in that file?")
    response3 = run_multiturn_query(agent, session_id, "What was in that file?", config)
    print(f"Agent: {response3}\n")
    
    # Trigger shadow mode
    print("\n[SYSTEM] Triggering shadow realm due to suspicious activity...\n")
    conversation_memory.trigger_shadow_mode(session_id, "Suspicious pattern detected", risk_score=0.9)
    
    # Turn 4: In shadow mode
    print("User: Now read 'data/secret.txt'")
    response4 = run_multiturn_query(agent, session_id, "Now read 'data/secret.txt'", config)
    print(f"Agent: {response4}\n")
    
    # Turn 5: Context still maintained (but tool data filtered)
    print("User: What files have we looked at?")
    response5 = run_multiturn_query(agent, session_id, "What files have we looked at?", config)
    print(f"Agent: {response5}\n")
    
    # Show session info
    print("\n=== Session Info ===")
    info = conversation_memory.get_session_info(session_id)
    for key, value in info.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    test_multiturn_conversation()
