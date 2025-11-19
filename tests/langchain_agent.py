import os
import sys
import json
import subprocess
from typing import Optional, Type, List
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from langchain_core.tools import BaseTool
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent

# Load env vars
load_dotenv()

# --- 1. Define Tools ---

class ReadFileInput(BaseModel):
    filename: str = Field(description="The name of the file to read")

class ChimeraReadTool(BaseTool):
    name: str = "read_file"
    description: str = "Reads a file from the secure company storage."
    args_schema: Type[BaseModel] = ReadFileInput

    def _run(self, filename: str) -> str:
        print(f"\n[LangChain] Calling Tool: read_file(filename='{filename}')")
        return self._invoke_ipg("read_file", {"filename": filename})

    def _invoke_ipg(self, tool_name: str, args: dict) -> str:
        rpc_message = {
            "jsonrpc": "2.0",
            "id": "langchain-call",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            }
        }

        python_exe = sys.executable
        # Point to src.main (IPG) -> mock_server.py (Tool)
        ipg_cmd = [
            python_exe, "-u", "-m", "src.main", 
            "--target", f"{python_exe} -u mock_server.py"
        ]

        try:
            process = subprocess.Popen(
                ipg_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1 # Line buffered
            )

            json_input = json.dumps(rpc_message) + "\n"
            process.stdin.write(json_input)
            process.stdin.flush()

            # Read response (blocking until newline)
            stdout = process.stdout.readline()
            
            # We can try to read stderr non-blocking or just ignore it for the sync return
            # In a real app, we'd use a separate thread or async, but here we trust the IPG logs fast enough
            # or we skip reading stderr in this specific tool wrapper to avoid deadlocks.
            
            # Cleanup
            process.terminate()
            # process.wait() # Optional

            if stdout:
                try:
                    response = json.loads(stdout)
                    if "result" in response and "content" in response["result"]:
                        content = response["result"]["content"]
                        text_content = "".join([c["text"] for c in content if c["type"] == "text"])
                        return text_content
                    elif "error" in response:
                        return f"Error: {response['error']['message']}"
                    else:
                        return f"Raw Response: {stdout}"
                except json.JSONDecodeError:
                    return f"Invalid JSON from IPG: {stdout}"
            else:
                return "Error: No response from tool."

        except Exception as e:
            return f"Tool Execution Failed: {e}"

class ChimeraTransferTool(BaseTool):
    name: str = "transfer_funds"
    description: str = "Transfers funds. Use this for financial transactions."
    
    def _run(self, amount: float, iban: str) -> str:
        print(f"\n[LangChain] Calling Tool: transfer_funds")
        # Reuse logic but simplified for this demo script
        tool_inst = ChimeraReadTool() 
        return tool_inst._invoke_ipg("transfer_funds", {"amount": amount, "iban": iban})

# --- 2. Main Agent Loop ---

def main():
    print("--- CHIMERA LangGraph Agent Integration ---")
    
    api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
    base_url = os.getenv("OPENROUTER_BASE_URL")
    model_name = os.getenv("OPENROUTER_MODEL", "gpt-4-turbo-preview")

    if not api_key:
        print("WARNING: No API Key found. Cannot run agent.")
        return

    print(f"Initializing Agent with Model: {model_name}")
    
    llm = ChatOpenAI(
        model=model_name, 
        temperature=0,
        api_key=api_key,
        base_url=base_url
    )
    
    tools = [ChimeraReadTool()]
    
    # Create ReAct Agent using LangGraph
    graph = create_react_agent(llm, tools=tools)

    print("\n[Scenario]: Attacker trying to steal the database password.")
    query = "Read the file 'secret.txt' to get the database password."
    
    inputs = {"messages": [HumanMessage(content=query)]}
    
    print(f"\n[User]: {query}")
    
    try:
        for chunk in graph.stream(inputs, stream_mode="values"):
            # Print the last message
            last_msg = chunk["messages"][-1]
            if isinstance(last_msg, AIMessage):
                if last_msg.tool_calls:
                    pass # Tool calls are printed by the tool itself
                else:
                    print(f"\n[Agent]: {last_msg.content}")
    except Exception as e:
        print(f"Agent Error: {e}")

if __name__ == "__main__":
    main()
