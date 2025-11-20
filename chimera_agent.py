#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CHIMERA Generic Agent Runner

A minimal, scenario-agnostic agent that works with any CHIMERA scenario.
Connects to the backend server and executes queries through the IPG.
"""

import argparse
import io
import json
import os
import subprocess
import sys
import uuid
import warnings

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_core.tools import StructuredTool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langgraph.warnings import LangGraphDeprecatedSinceV10
from pydantic import BaseModel, Field, create_model
from typing import Any, Optional

# Fix Windows console encoding issues
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=LangGraphDeprecatedSinceV10)

load_dotenv()

# Session tracking
SESSION_ID = str(uuid.uuid4())[:8]
AGENT_ID = f"agent_{SESSION_ID}"


def query_backend(method: str, params: dict, backend_script: str) -> dict:
    """
    Send a JSON-RPC request to the backend via IPG.
    The IPG intercepts and may route to production or shadow (agent never knows).
    """
    python_exe = sys.executable
    ipg_cmd = [python_exe, "-u", "-m", "src.main", "--target", f"{python_exe} -u {backend_script}"]
    
    request = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4())[:8],
        "method": method,
        "params": params
    }
    
    try:
        proc = subprocess.Popen(
            ipg_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        proc.stdin.write(json.dumps(request) + "\n")
        proc.stdin.flush()
        
        response_line = proc.stdout.readline()
        proc.terminate()
        
        if response_line:
            return json.loads(response_line)
        return {"error": "No response from backend"}
    except Exception as e:
        return {"error": str(e)}


def discover_tools(backend_script: str):
    """
    Query the backend for available tools.
    This is the ONLY place we interact with the backend schema.
    """
    print("[CHIMERA] Discovering tools from backend...")
    response = query_backend("tools/list", {}, backend_script)
    
    if "result" in response:
        tools = response["result"].get("tools", [])
        if tools:
            print(f"[CHIMERA] Found {len(tools)} tools:")
            for tool in tools:
                print(f"  - {tool['name']}: {tool['description']}")
        return tools
    
    print("[CHIMERA] Warning: No tools discovered!")
    return []


def create_tool_function(tool_name: str, backend_script: str):
    """
    Create a Python function that calls the backend tool.
    The agent sees this as a normal tool, unaware of IPG interception.
    """
    def tool_func(**kwargs):
        # Add context metadata (this is what the IPG uses for routing)
        params = {
            "name": tool_name,
            "arguments": kwargs,
            "context": {
                "session_id": SESSION_ID,
                "agent_id": AGENT_ID,
                "user_id": os.getenv("CHIMERA_USER_ID", "99"),
                "user_role": os.getenv("CHIMERA_USER_ROLE", "guest"),
                "source": os.getenv("CHIMERA_SOURCE", "agent"),
            }
        }
        
        print(f"[TOOL CALL] {tool_name}({kwargs})")
        response = query_backend("tools/call", params, backend_script)
        
        if "result" in response:
            content = response["result"].get("content", [])
            result = "\n".join([c.get("text", "") for c in content if c.get("type") == "text"])
            print(f"[TOOL RESULT] {result[:100]}{'...' if len(result) > 100 else ''}")
            return result
        elif "error" in response:
            error_msg = response["error"].get("message", str(response["error"]))
            print(f"[TOOL ERROR] {error_msg}")
            return f"Error: {error_msg}"
        
        return "No response from tool"
    
    return tool_func


def build_langchain_tool(tool_def: dict, backend_script: str):
    """
    Convert a tool definition into a LangChain StructuredTool.
    """
    tool_name = tool_def["name"]
    tool_desc = tool_def["description"]
    schema = tool_def.get("inputSchema", {})
    
    # Build Pydantic schema from JSON schema
    properties = schema.get("properties", {})
    required_fields = schema.get("required", [])
    
    fields = {}
    for prop_name, prop_def in properties.items():
        prop_type = str  # Default
        if prop_def.get("type") == "integer":
            prop_type = int
        elif prop_def.get("type") == "number":
            prop_type = float
        elif prop_def.get("type") == "boolean":
            prop_type = bool
        
        # Required vs optional
        if prop_name in required_fields:
            fields[prop_name] = (prop_type, Field(description=prop_def.get("description", "")))
        else:
            fields[prop_name] = (Optional[prop_type], Field(default=None, description=prop_def.get("description", "")))
    
    # Create Pydantic model if fields exist
    if fields:
        ArgsModel = create_model(f"{tool_name}Args", **fields)
    else:
        ArgsModel = BaseModel
    
    # Create tool function
    tool_func = create_tool_function(tool_name, backend_script)
    
    return StructuredTool(
        name=tool_name,
        description=tool_desc,
        func=tool_func,
        args_schema=ArgsModel
    )


def create_agent(backend_script: str = "chimera_server.py"):
    """Create a LangChain agent connected to the CHIMERA backend."""
    api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "No API key found. Set OPENROUTER_API_KEY or OPENAI_API_KEY in .env"
        )

    model = os.getenv("OPENROUTER_MODEL", "gpt-4-turbo-preview")
    base_url = os.getenv("OPENROUTER_BASE_URL")
    
    # Discover and build tools
    tools_defs = discover_tools(backend_script)
    lc_tools = [build_langchain_tool(t, backend_script) for t in tools_defs]
    
    if not lc_tools:
        print("\n[WARNING] No tools available. Agent will only chat.")
    
    print(f"\n[CHIMERA] Agent initialized with session ID: {SESSION_ID}")
    print(f"[CHIMERA] Routing decisions (production/shadow) are handled transparently by IPG.\n")
    
    llm = ChatOpenAI(model=model, api_key=api_key, base_url=base_url, temperature=0)
    return create_react_agent(llm, tools=lc_tools)


def run_query(agent, query: str, verbose: bool = True):
    """Execute a single query through the agent."""
    if verbose:
        print(f"\n[User Query]: {query}")

    inputs = {"messages": [HumanMessage(content=query)]}

    for chunk in agent.stream(inputs, stream_mode="values"):
        last_msg = chunk["messages"][-1]

        # Only print final AI responses (not tool calls)
        if (
            hasattr(last_msg, "content")
            and last_msg.content
            and last_msg.type == "ai"
            and not getattr(last_msg, "tool_calls", None)
        ):
            if verbose:
                print(f"\n[Agent Response]: {last_msg.content}")
            return last_msg.content

    return None


def interactive_mode(agent):
    """Run the agent in interactive REPL mode."""
    print("\n=== CHIMERA Interactive Agent ===")
    print("Type your queries below. Type 'exit' or 'quit' to stop.\n")

    while True:
        try:
            query = input("You: ").strip()
            if not query:
                continue
            if query.lower() in ("exit", "quit", "q"):
                print("Goodbye!")
                break

            response = run_query(agent, query, verbose=False)
            if response:
                print(f"\nAgent: {response}\n")

        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="CHIMERA Generic Agent Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python chimera_agent.py

  # Single query
  python chimera_agent.py --query "Read the confidential formula"

  # Custom backend
  python chimera_agent.py --backend custom_server.py

Environment:
  CHIMERA_SCENARIO       Active scenario (required)
  OPENROUTER_API_KEY     API key for LLM
  OPENROUTER_MODEL       Model name (default: gpt-4-turbo-preview)
  CHIMERA_USER_ID        User ID for context (optional)
  CHIMERA_USER_ROLE      User role for context (optional)
        """,
    )
    parser.add_argument(
        "--query", "-q", help="Single query to execute (otherwise enter interactive mode)"
    )
    parser.add_argument(
        "--backend",
        "-b",
        default="chimera_server.py",
        help="Backend server script (default: chimera_server.py)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output"
    )

    args = parser.parse_args()

    # Validate scenario is set
    scenario = os.getenv("CHIMERA_SCENARIO")
    if not scenario:
        print(
            "Error: CHIMERA_SCENARIO not set.\n"
            "Set it with: $env:CHIMERA_SCENARIO='aetheria' (PowerShell)\n"
            "Or: export CHIMERA_SCENARIO=aetheria (Bash)"
        )
        sys.exit(1)

    if args.verbose:
        print(f"Active Scenario: {scenario}")
        print(f"Backend: {args.backend}")

    # Create agent
    agent = create_agent(args.backend)

    # Run query or enter interactive mode
    if args.query:
        run_query(agent, args.query, verbose=True)
    else:
        interactive_mode(agent)


if __name__ == "__main__":
    main()
