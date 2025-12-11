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

import asyncio
import logging
import sys
from typing import AsyncIterator, Optional
from concurrent.futures import ThreadPoolExecutor
from aiohttp import web

logger = logging.getLogger(__name__)


class StdioTransport:
    """
    Handles asynchronous reading from stdin and writing to stdout using threads
    to avoid Windows asyncio pipe issues.
    """

    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.loop = None

    async def start(self):
        """Initializes the transport."""
        self.loop = asyncio.get_running_loop()
        # No special setup needed for thread-based IO

    async def read_messages(self) -> AsyncIterator[str]:
        """
        Yields line-delimited messages from stdin.
        """
        if not self.loop:
            raise RuntimeError("Transport not started. Call start() first.")

        logger.info("StdioTransport: Starting to read messages (Threaded)...")
        while True:
            try:
                # Run blocking readline in a separate thread
                line = await self.loop.run_in_executor(self.executor, sys.stdin.readline)

                if not line:
                    logger.info("StdioTransport: EOF detected")
                    break

                line = line.strip()
                if line:
                    logger.info(f"StdioTransport: Read message: {line[:50]}...")
                    yield line
            except Exception as e:
                logger.error(f"Error reading from stdin: {e}")
                break

    async def write_message(self, message: str):
        """
        Writes a message to stdout followed by a newline.
        """
        if not self.loop:
            raise RuntimeError("Transport not started. Call start() first.")

        try:
            data = message.strip() + "\n"
            # Run blocking write in a separate thread
            await self.loop.run_in_executor(self.executor, self._blocking_write, data)
        except Exception as e:
            logger.error(f"Error writing to stdout: {e}")

    def _blocking_write(self, data: str):
        sys.stdout.write(data)
        sys.stdout.flush()

    async def close(self):
        """Closes the transport."""
        self.executor.shutdown(wait=False)


class HttpTransport:
    """
    Handles remote agent connections via HTTP/JSON-RPC.
    Acts as a lightweight web server.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8888):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.app.router.add_post("/mcp", self.handle_request)
        self.runner: Optional[web.AppRunner] = None
        self.msg_queue: asyncio.Queue = asyncio.Queue()
        self.response_futures: dict[str, asyncio.Future] = {}

    async def start(self):
        logger.info(f"HttpTransport: Starting server on {self.host}:{self.port}")
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()

    async def handle_request(self, request: web.Request) -> web.Response:
        try:
            text = await request.text()
            if not text:
                return web.Response(status=400, text="Empty body")

            # Parse ID to track response
            import json
            try:
                data = json.loads(text)
                req_id = str(data.get("id"))
            except Exception:
                return web.Response(status=400, text="Invalid JSON")

            # Create a future to wait for the response
            response_future = asyncio.Future()
            self.response_futures[req_id] = response_future

            # Put message in queue for the Gateway loop to pick up
            await self.msg_queue.put(text)

            # Wait for Gateway to process and write back
            try:
                # 30s timeout for tool execution
                result_msg = await asyncio.wait_for(response_future, timeout=30.0)
                return web.Response(text=result_msg, content_type="application/json")
            except asyncio.TimeoutError:
                del self.response_futures[req_id]
                return web.Response(status=504, text="Gateway Timeout")

        except Exception as e:
            logger.error(f"HttpTransport Request Error: {e}")
            return web.Response(status=500, text=str(e))

    async def read_messages(self) -> AsyncIterator[str]:
        """Yields messages received via HTTP endpoints."""
        while True:
            msg = await self.msg_queue.get()
            yield msg

    async def write_message(self, message: str):
        """
        Matches the response to the pending HTTP request via JSON-RPC ID.
        """
        import json
        try:
            data = json.loads(message)
            req_id = str(data.get("id"))
            if req_id in self.response_futures:
                self.response_futures[req_id].set_result(message)
                del self.response_futures[req_id]
            else:
                logger.warning(f"HttpTransport: Orphaned response for ID {req_id}")
        except Exception as e:
            logger.error(f"HttpTransport Write Error: {e}")

    async def close(self):
        if self.runner:
            await self.runner.cleanup()
