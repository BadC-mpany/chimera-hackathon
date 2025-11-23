#!/usr/bin/env python3
"""Quick test of conversation memory in agent context"""
import os
os.environ["CHIMERA_SCENARIO"] = "aetheria"

from src.ipg.conversation_memory import ConversationMemory

# Create memory
memory = ConversationMemory()
session_id = "test-123"

# Add first turn
memory.add_user_query(session_id, "Hello")
memory.add_llm_response(session_id, "Hi there!")

# Get history
history = memory.get_conversation_history(session_id, include_tool_data=True)
print(f"History has {len(history)} messages:")
for msg in history:
    print(f"  {msg['role']}: {msg['content']}")

# Get session info
info = memory.get_session_info(session_id)
print(f"\nSession info: {info}")

print("\nTest passed!")
