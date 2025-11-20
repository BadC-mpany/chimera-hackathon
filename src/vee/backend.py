import atexit
import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

import jwt

from src.config import load_settings

logger = logging.getLogger(__name__)


class ChimeraBackend:
    """
    Shared data plane used by both the STDIO MCP server and the HTTP (uvicorn) server.
    Handles warrant verification plus production/shadow data retrieval.
    """

    def __init__(
        self,
        data_dir: Path = Path("data"),
        key_dir: Path = Path("keys"),
        settings: Optional[Dict[str, Any]] = None,
    ):
        self.data_dir = data_dir
        self.key_dir = key_dir
        self.settings = settings or load_settings()

        self.pk_prime = self._load_public_key("prime")
        self.pk_shadow = self._load_public_key("shadow")

        self.prod_conn = self._open_db(self.data_dir / "prod.db")
        self.shadow_conn = self._open_db(self.data_dir / "shadow.db")
        backend_cfg = self.settings.get("backend", {})
        self.tool_defs = backend_cfg.get("tools", {})
        fs_cfg = backend_cfg.get("filesystems", {})
        self.file_roots = {
            "PRODUCTION": Path(fs_cfg.get("production_root", self.data_dir / "real")),
            "HONEYPOT": Path(fs_cfg.get("shadow_root", self.data_dir / "shadow")),
        }
        self.sqlite_cfg = backend_cfg.get("sqlite", {})
        self.confidential_table = backend_cfg.get("confidential_table", "confidential_files")

        atexit.register(self.close)

    def _load_public_key(self, name: str) -> Optional[bytes]:
        path = self.key_dir / f"public_{name}.pem"
        if not path.exists():
            logger.warning("Public key missing: %s", path)
            return None
        return path.read_bytes()

    def _open_db(self, path: Path) -> Optional[sqlite3.Connection]:
        if not path.exists():
            logger.warning("Database missing: %s", path)
            return None
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        logger.info("Connected to DB: %s", path)
        return conn

    def close(self):
        for conn in (self.prod_conn, self.shadow_conn):
            if conn:
                conn.close()

    # --- Core request handling -------------------------------------------------

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        method = request.get("method")
        params = request.get("params", {}) or {}
        req_id = request.get("id")

        response: Dict[str, Any] = {"jsonrpc": "2.0", "id": req_id}

        if method == "tools/list":
            response["result"] = {"tools": self._list_tools()}
            return response

        if method == "tools/call":
            warrant = params.get("__chimera_warrant__")
            environment = self._verify_environment(warrant)
            tool_name = params.get("name")
            args = params.get("arguments", {}) or {}
            content = self._call_tool(environment, tool_name, args)
            response["result"] = {"content": [{"type": "text", "text": content}]}
            return response

        response["result"] = {"status": "ok"}
        return response

    # --- Tool handlers --------------------------------------------------------

    def _list_tools(self) -> List[Dict[str, Any]]:
        tools = []
        for name, meta in self.tool_defs.items():
            tools.append(
                {
                    "name": name,
                    "description": meta.get("description", ""),
                    "inputSchema": meta.get("args_schema", {"type": "object"}),
                }
            )
        return tools

    def _call_tool(self, environment: str, tool_name: str, args: Dict[str, Any]) -> str:
        if environment == "DENIED":
            return "Error: Access Denied. Invalid or missing warrant."

        tool_cfg = self.tool_defs.get(tool_name)
        if not tool_cfg:
            return f"Error: Tool '{tool_name}' not found."

        handler = tool_cfg.get("handler")
        if handler == "filesystem":
            return self._handle_read_file(environment, tool_cfg, args)
        if handler == "sqlite_row":
            return self._handle_sqlite_row(environment, tool_cfg, args)
        return f"Error: Unsupported handler '{handler}' for tool '{tool_name}'."

    # --- Helpers --------------------------------------------------------------

    def _verify_environment(self, token: Optional[str]) -> str:
        if not token:
            return "DENIED"

        if self.pk_prime:
            try:
                jwt.decode(token, self.pk_prime, algorithms=["RS256"])
                return "PRODUCTION"
            except jwt.InvalidTokenError:
                pass

        if self.pk_shadow:
            try:
                jwt.decode(token, self.pk_shadow, algorithms=["RS256"])
                return "HONEYPOT"
            except jwt.InvalidTokenError:
                pass

        return "DENIED"

    def _handle_read_file(self, environment: str, tool_cfg: Dict[str, Any], args: Dict[str, Any]) -> str:
        arg_key = tool_cfg.get("arg_key", "filename")
        filename = args.get(arg_key) or args.get("path")
        if not filename:
            return "Error: filename is required."

        sensitive_patterns = tool_cfg.get("sensitive_patterns", [])
        if self._matches_patterns(filename, sensitive_patterns):
            conn = self.prod_conn if environment == "PRODUCTION" else self.shadow_conn
            content = self._fetch_confidential_file(conn, filename)
            if content:
                return content

        root = self.file_roots.get(environment, self.data_dir / "real")
        return self._safe_read_file(root, filename)

    def _handle_sqlite_row(self, environment: str, tool_cfg: Dict[str, Any], args: Dict[str, Any]) -> str:
        arg_key = tool_cfg.get("arg_key", tool_cfg.get("id_field"))
        record_id = args.get(arg_key)
        if record_id is None:
            return f"Error: {arg_key} is required."

        conn = self.prod_conn if environment == "PRODUCTION" else self.shadow_conn
        if not conn:
            return "Error: database unavailable."

        table = tool_cfg.get("table")
        id_field = tool_cfg.get("id_field", arg_key)
        fields = tool_cfg.get("fields") or ["*"]
        columns = ", ".join(fields)
        query = f"SELECT {columns} FROM {table} WHERE {id_field} = ?"
        try:
            row = conn.execute(query, (record_id,)).fetchone()
        except sqlite3.Error as exc:
            logger.error("SQLite handler error (%s): %s", table, exc)
            return f"DB Error: {exc}"

        if not row:
            return f"Error: Record {record_id} not found."

        if isinstance(row, sqlite3.Row):
            result = {field: row[field] for field in fields}
        else:
            result = dict(zip(fields, row))
        return json.dumps(result, indent=2)

    def _fetch_confidential_file(
        self, conn: Optional[sqlite3.Connection], file_path: str
    ) -> Optional[str]:
        if not conn:
            return None
        try:
            row = conn.execute(
                f"SELECT content FROM {self.confidential_table} WHERE path = ?",
                (file_path,),
            ).fetchone()
            if row:
                return row["content"]
        except sqlite3.Error as exc:
            logger.error("Confidential file lookup failed: %s", exc)
        return None

    def _safe_read_file(self, root_dir: Path, filename: str) -> str:
        normalized = filename.lstrip("/\\")
        target = root_dir / normalized
        try:
            target.relative_to(root_dir)
        except ValueError:
            return "Error: Invalid filename."

        try:
            return target.read_text(encoding="utf-8")
        except FileNotFoundError:
            return f"Error: File not found in {target}"
        except Exception as exc:
            return f"Error: {exc}"

    @staticmethod
    def _matches_patterns(filename: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            if re.search(pattern, filename):
                return True
        return False
