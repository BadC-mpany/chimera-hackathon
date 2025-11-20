import argparse
import json
import logging
import os
import sys
from typing import Any, Dict

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
except ImportError:  # FastAPI optional unless HTTP mode enabled
    FastAPI = None
    BaseModel = None

from src.vee.backend import ChimeraBackend

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("chimera.backend.server")

backend = ChimeraBackend()


def handle_json_line(line: str) -> Dict[str, Any]:
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Invalid JSON"}}

    return backend.handle_request(request)


def run_stdio_server():
    logger.info("CHIMERA backend starting in STDIO mode")
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        response = handle_json_line(line)
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


# --- FastAPI HTTP surface ----------------------------------------------------

if FastAPI:

    class MCPRequest(BaseModel):
        jsonrpc: str = "2.0"
        id: Any
        method: str
        params: Dict[str, Any] = {}

    app = FastAPI(
        title="CHIMERA Secure Backend",
        description="Production vs Honeypot data plane exposed over HTTP.",
        version="0.1.0",
    )

    @app.post("/mcp")
    async def mcp_bridge(payload: MCPRequest):
        try:
            response = backend.handle_request(payload.dict())
            return response
        except Exception as exc:  # pragma: no cover - FastAPI auto handling
            raise HTTPException(status_code=500, detail=str(exc)) from exc

else:
    app = None


def parse_args():
    parser = argparse.ArgumentParser(description="Run CHIMERA backend server.")
    parser.add_argument(
        "--mode",
        choices=["stdio", "http"],
        default=os.getenv("CHIMERA_SERVER_MODE", "stdio"),
        help="Select STDIO (MCP) or HTTP (uvicorn) mode.",
    )
    parser.add_argument("--host", default=os.getenv("CHIMERA_SERVER_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("CHIMERA_SERVER_PORT", "8000")))
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.mode == "http":
        if app is None:
            logger.error("FastAPI not installed. Install fastapi+uvicorn to run HTTP mode.")
            sys.exit(1)
        import uvicorn

        uvicorn.run("chimera_server:app", host=args.host, port=args.port, log_level="info")
    else:
        run_stdio_server()
