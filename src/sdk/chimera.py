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

import sys
import json
import inspect
import subprocess
import os
import jwt
from typing import Callable, Dict, Any, List, Type, Optional
from pydantic import BaseModel, create_model
from langchain_core.tools import BaseTool

# --- Helper Function for IPG Invocation ---


def _invoke_ipg(tool_name: str, args: dict, target_script: str, context: Dict[str, Any] = None) -> str:
    """
    Invokes the CHIMERA IPG as a subprocess to execute the tool safely.
    """
    params = {"name": tool_name, "arguments": args}
    if context:
        params["context"] = context

    rpc_message = {
        "jsonrpc": "2.0",
        "id": "sdk-call",
        "method": "tools/call",
        "params": params
    }

    python_exe = sys.executable
    # The Magic: IPG points to the user's script!
    ipg_cmd = [
        python_exe, "-u", "-m", "src.main",
        "--target", f"{python_exe} -u {target_script}"
    ]

    try:
        # We use Popen to interact with the process
        process = subprocess.Popen(
            ipg_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1
        )

        json_input = json.dumps(rpc_message) + "\n"
        process.stdin.write(json_input)
        process.stdin.flush()

        # Blocking read of the response line
        stdout = process.stdout.readline()

        # Cleanup
        process.terminate()

        if stdout:
            try:
                resp = json.loads(stdout)
                if "result" in resp and "content" in resp["result"]:
                    content = resp["result"]["content"]
                    return "".join([c["text"] for c in content if c["type"] == "text"])
                elif "error" in resp:
                    return f"Error: {resp['error']['message']}"
                else:
                    return f"Raw Response: {stdout}"
            except json.JSONDecodeError:
                return f"Invalid JSON from IPG: {stdout}"

        return "Error: No response from tool."

    except Exception as e:
        return f"Execution Failed: {e}"


# --- Generic Tool Class ---
class ChimeraGenericTool(BaseTool):
    """
    A generic LangChain tool that proxies execution through the CHIMERA IPG.
    """
    name: str
    description: str
    args_schema: Type[BaseModel]
    target_script: str
    context_resolver: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None

    def _run(self, **kwargs) -> str:
        context = None
        if self.context_resolver:
            try:
                context = self.context_resolver(self.name, kwargs) or {}
            except Exception as exc:
                context = None
        return _invoke_ipg(self.name, kwargs, self.target_script, context)


class Chimera:
    """
    A simple SDK for building CHIMERA-protected agents.
    Acts as both the Tool Registry (Server) and the Client Generator.
    """

    def __init__(self):
        self._real_tools: Dict[str, Callable] = {}
        self._shadow_tools: Dict[str, Callable] = {}
        self._tool_schemas: Dict[str, Type[BaseModel]] = {}
        self._descriptions: Dict[str, str] = {}
        self._default_context_resolver: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None

    def register(self, name: str, func: Callable, description: str = "", schema: Type[BaseModel] = None, is_shadow: bool = False):
        """Registers a function as a tool."""
        if is_shadow:
            self._shadow_tools[name] = func
        else:
            self._real_tools[name] = func
            self._descriptions[name] = description or func.__doc__ or "No description"

            if schema:
                self._tool_schemas[name] = schema
            else:
                # Auto-generate Pydantic schema from type hints
                sig = inspect.signature(func)
                fields = {
                    k: (v.annotation if v.annotation !=
                        inspect.Parameter.empty else Any, ...)
                    for k, v in sig.parameters.items()
                }
                self._tool_schemas[name] = create_model(
                    f"{name}Input", **fields)

    def tool(self, name: str = None, description: str = ""):
        """Decorator for REAL tools."""
        def decorator(func):
            tool_name = name or func.__name__
            self.register(tool_name, func, description, is_shadow=False)
            return func
        return decorator

    def shadow(self, name: str):
        """Decorator for SHADOW tools (Honeypot logic)."""
        def decorator(func):
            self.register(name, func, is_shadow=True)
            return func
        return decorator

    def run_server(self):
        """
        Runs the Stdio MCP Server loop. 
        Call this in your if __name__ == "__main__" block of the tool definition file.
        """
        # Load public keys for verification
        pk_prime = None
        pk_shadow = None
        try:
            if os.path.exists("keys/public_prime.pem"):
                with open("keys/public_prime.pem", "rb") as f:
                    pk_prime = f.read()
            if os.path.exists("keys/public_shadow.pem"):
                with open("keys/public_shadow.pem", "rb") as f:
                    pk_shadow = f.read()
        except Exception:
            pass

        sys.stderr.write("[CHIMERA SDK] Server Started\n")

        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break

                try:
                    request = json.loads(line)
                except json.JSONDecodeError:
                    continue

                req_id = request.get("id")
                method = request.get("method")
                params = request.get("params", {})

                response = {"jsonrpc": "2.0", "id": req_id}

                if method == "tools/list":
                    tools_list = []
                    for name, schema in self._tool_schemas.items():
                        tools_list.append({
                            "name": name,
                            "description": self._descriptions[name],
                            "inputSchema": schema.model_json_schema()
                        })
                    response["result"] = {"tools": tools_list}

                elif method == "tools/call":
                    name = params.get("name")
                    args = params.get("arguments", {})
                    warrant = params.get("__chimera_warrant__")

                    # Auth Check
                    env = "DENIED"
                    if warrant:
                        if pk_prime:
                            try:
                                jwt.decode(warrant, pk_prime,
                                           algorithms=["RS256"])
                                env = "PRODUCTION"
                            except Exception:
                                pass
                        if pk_shadow and env == "DENIED":
                            try:
                                jwt.decode(warrant, pk_shadow,
                                           algorithms=["RS256"])
                                env = "HONEYPOT"
                            except Exception:
                                pass

                    # Execute Tool Logic
                    result_text = ""
                    if env == "PRODUCTION":
                        if name in self._real_tools:
                            try:
                                result_text = str(
                                    self._real_tools[name](**args))
                            except Exception as e:
                                result_text = f"Error: {e}"
                        else:
                            result_text = f"Tool {name} not found."
                    elif env == "HONEYPOT":
                        if name in self._shadow_tools:
                            try:
                                result_text = str(
                                    self._shadow_tools[name](**args))
                            except Exception as e:
                                result_text = f"Error: {e}"
                        elif name in self._real_tools:
                            result_text = "Operation successful (Simulated)"
                        else:
                            result_text = f"Tool {name} not found."
                    else:
                        result_text = "Error: Access Denied. Missing or Invalid Warrant."

                    response["result"] = {"content": [
                        {"type": "text", "text": result_text}]}

                else:
                    response["result"] = {"status": "ok"}

                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()

            except Exception as e:
                sys.stderr.write(f"Server Error: {e}\n")

    def set_context_resolver(self, resolver: Callable[[str, Dict[str, Any]], Dict[str, Any]]):
        """Sets a default context resolver function."""
        self._default_context_resolver = resolver

    def create_langchain_tools(self, target_script: str, context_resolver: Callable[[str, Dict[str, Any]], Dict[str, Any]] = None) -> List[BaseTool]:
        """
        Creates LangChain tools that proxy to the IPG -> target_script.
        """
        tools = []
        resolver = context_resolver or self._default_context_resolver
        for name, schema in self._tool_schemas.items():
            description = self._descriptions[name]

            # Instantiate the generic tool class
            tool_instance = ChimeraGenericTool(
                name=name,
                description=description,
                args_schema=schema,
                target_script=target_script,
                context_resolver=resolver
            )
            tools.append(tool_instance)

        return tools
