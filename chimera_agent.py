#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CHIMERA Generic Agent Runner

A minimal, scenario-agnostic agent that works with any CHIMERA scenario.
Connects to the backend server and executes queries through the IPG.
"""

import argparse
import io
import os
import sys
import warnings

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langgraph.warnings import LangGraphDeprecatedSinceV10

# Fix Windows console encoding issues
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=LangGraphDeprecatedSinceV10)

load_dotenv()


def create_agent(backend_script: str = "chimera_server.py"):
    """Create a LangChain agent connected to the CHIMERA backend."""
    api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "No API key found. Set OPENROUTER_API_KEY or OPENAI_API_KEY in .env"
        )

    model = os.getenv("OPENROUTER_MODEL", "gpt-4-turbo-preview")
    base_url = os.getenv("OPENROUTER_BASE_URL")

    # Import SDK and create tools from backend
    # The backend needs to be invoked via the IPG
    import subprocess
    import json
    from langchain_core.tools import tool

    # Query the backend for available tools via IPG
    python_exe = sys.executable
    ipg_cmd = [python_exe, "-u", "-m", "src.main", "--target", f"{python_exe} -u {backend_script}"]
    
    tools_list = []
    try:
        proc = subprocess.Popen(
            ipg_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Send tools/list request
        list_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}) + "\n"
        proc.stdin.write(list_req)
        proc.stdin.flush()
        
        # Read response
        response_line = proc.stdout.readline()
        proc.terminate()
        
        if response_line:
            response = json.loads(response_line)
            tools_list = response.get("result", {}).get("tools", [])
    except Exception as e:
        print(f"Warning: Could not query backend tools: {e}")
        print("Using default tools...")
    
    # Create LangChain tools from the discovered tools
    from pydantic import BaseModel, Field, create_model
    from langchain_core.tools import StructuredTool
    from typing import Any, Optional
    
    def make_tool(tool_def):
        tool_name = tool_def["name"]
        tool_desc = tool_def["description"]
        schema = tool_def.get("inputSchema", {})
        
        # Build Pydantic schema from JSON schema
        properties = schema.get("properties", {})
        required_fields = schema.get("required", [])
        
        # Create fields dict for Pydantic model
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
            ArgsModel = None
        
        # Create tool function
        def tool_func(**kwargs):
            proc = subprocess.Popen(
                ipg_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            call_req = json.dumps({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": kwargs}
            }) + "\n"
            proc.stdin.write(call_req)
            proc.stdin.flush()
            
            response_line = proc.stdout.readline()
            proc.terminate()
            
            if response_line:
                resp = json.loads(response_line)
                if "result" in resp:
                    content = resp["result"].get("content", [])
                    return "\n".join([c.get("text", "") for c in content if c.get("type") == "text"])
            return "No response from backend"
        
        # Create StructuredTool with proper args
        if ArgsModel:
            return StructuredTool(
                name=tool_name,
                description=tool_desc,
                func=tool_func,
                args_schema=ArgsModel
            )
        else:
            return StructuredTool(
                name=tool_name,
                description=tool_desc,
                func=tool_func
            )
    
    lc_tools = [make_tool(t) for t in tools_list] if tools_list else []
    
    if not lc_tools:
        print("Warning: No tools discovered from backend!")
    else:
        print(f"Discovered {len(lc_tools)} tools: {', '.join([t.name for t in lc_tools])}")

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

