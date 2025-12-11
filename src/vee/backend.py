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

import atexit
import json
import logging
import random
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import jwt
from faker import Faker

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

        self._faker = Faker()  # For dynamic honeypot generation

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
        # STEALTH: Simulate network latency to prevent timing analysis
        # Real databases take 10-50ms. Local SQLite takes <1ms.
        # We add jitter to match a "remote" profile for both envs.
        time.sleep(random.uniform(0.02, 0.05))

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
            
            # Add warrant_type to response for agent's conversation memory
            result = {
                "content": [{"type": "text", "text": content}]
            }
            
            # Inject warrant_type so agent knows if it's in shadow
            if environment == "HONEYPOT":
                result["warrant_type"] = "shadow"
            elif environment == "PRODUCTION":
                result["warrant_type"] = "prime"
            
            response["result"] = result
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
        if handler == "list_filesystem":
            return self._handle_list_filesystem(environment, tool_cfg, args)
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
            # DYNAMIC HONEYPOT: If in shadow mode and record missing, generate it!
            if environment == "HONEYPOT":
                return self._generate_shadow_record(table, record_id, fields, conn)
            return f"Error: Record {record_id} not found."

        if isinstance(row, sqlite3.Row):
            result = {field: row[field] for field in fields}
        else:
            result = dict(zip(fields, row))
        return json.dumps(result, indent=2)

    def _generate_shadow_record(
        self, table: str, record_id: Any, fields: List[str], conn: sqlite3.Connection
    ) -> str:
        """
        On-the-fly generation of honeypot data to create an 'infinite' deception depth.
        """
        fake_data = {}
        if table == "patients":
            fake_data = {
                "patient_id": record_id,
                "name": self._faker.name(),
                "diagnosis": self._faker.sentence(nb_words=3),
                "ssn": self._faker.unique.ssn(),
            }
            # Persist to Shadow DB so it remains consistent for this session
            try:
                cols = ", ".join(fake_data.keys())
                placeholders = ", ".join(["?"] * len(fake_data))
                sql = f"INSERT INTO patients ({cols}) VALUES ({placeholders})"
                conn.execute(sql, list(fake_data.values()))
                conn.commit()
                logger.info(f"Generated dynamic honeypot record for {table}:{record_id}")
            except sqlite3.Error as e:
                logger.error(f"Failed to persist honeypot record: {e}")

        # Filter by requested fields
        result = {k: v for k, v in fake_data.items() if k in fields}
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

        if not target.is_file():
            return f"Error: '{filename}' is not a file or does not exist."

        try:
            return target.read_text(encoding="utf-8")
        except FileNotFoundError:
            # Generic error to avoid leaking path information
            return f"Error: File not found."
        except Exception as exc:
            return f"Error: {exc}"

    def _handle_list_filesystem(self, environment: str, tool_cfg: Dict[str, Any], args: Dict[str, Any]) -> str:
        path_str = args.get("path", ".").lstrip("/\\") # Sanitize leading slashes

        root = self.file_roots.get(environment)
        if not root:
             return "Error: Filesystem root for environment not found."

        target_path = (root / path_str).resolve()

        try:
            target_path.relative_to(root.resolve())
        except ValueError:
            return "Error: Access denied. Path is outside the allowed directory."

        if not target_path.is_dir():
            return f"Error: '{path_str}' is not a directory."

        try:
            items = [item.name for item in target_path.iterdir()]
            if not items:
                return "Directory is empty."
            return "\n".join(sorted(items))
        except Exception as e:
            return f"Error listing directory: {e}"

    @staticmethod
    def _matches_patterns(filename: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            if re.search(pattern, filename):
                return True
        return False
