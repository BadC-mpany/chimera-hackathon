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
import os
import shlex
import sys
from typing import Dict, Optional, Union, Any
from .transport import StdioTransport, HttpTransport
from .interceptor import MessageInterceptor
from .sanitizer import ResponseSanitizer

from src.config import load_settings

logger = logging.getLogger(__name__)


class Gateway:
    """
    Orchestrates the bi-directional flow between the Upstream Agent and the Downstream Tool.
    Supports both Stdio and HTTP transports.
    """

    def __init__(self, downstream_command: str, transport_mode: str = "stdio", settings: Optional[Dict[str, Any]] = None):
        self.downstream_command = downstream_command
        self.transport_mode = transport_mode
        self.settings = settings or load_settings()
        self.upstream: Union[StdioTransport, HttpTransport]

        if self.transport_mode == "http":
            port = int(os.getenv("CHIMERA_PORT", "8888"))
            host = os.getenv("CHIMERA_HOST", "127.0.0.1")
            self.upstream = HttpTransport(host=host, port=port)
        else:
            self.upstream = StdioTransport()

        self.interceptor = MessageInterceptor(settings=self.settings)
        self.sanitizer = ResponseSanitizer()
        self.downstream_proc: Optional[asyncio.subprocess.Process] = None

    async def start(self):
        """Starts the gateway and the two forwarding tasks."""
        logger.info(f"Starting IPG (Transport: {self.transport_mode}) with downstream target: {self.downstream_command}")

        await self.upstream.start()

        # Use create_subprocess_exec for efficiency and security
        # shlex.split is essential for correctly parsing the command string
        cmd_parts = shlex.split(self.downstream_command)
        
        # Ensure the first part of the command is the python executable if it's a python script
        if cmd_parts[0] == 'python' and '.py' in self.downstream_command:
            cmd_parts[0] = sys.executable

        self.downstream_proc = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr  # Passthrough stderr for debugging
        )

        if not self.downstream_proc.stdin or not self.downstream_proc.stdout:
            raise RuntimeError("Failed to connect pipes to downstream process")

        try:
            # Run the two forwarding tasks concurrently
            await asyncio.gather(
                self._forward_upstream_to_downstream(),
                self._forward_downstream_to_upstream()
            )
        except Exception as e:
            logger.error(f"Gateway error: {e}")
        finally:
            await self.stop()

    async def _forward_upstream_to_downstream(self):
        """Task to read from agent, intercept, and forward to the tool's stdin."""
        if not self.downstream_proc or not self.downstream_proc.stdin:
            return

        try:
            async for message in self.upstream.read_messages():
                processed_msg, routing_target = await self.interceptor.process_message(message)

                if routing_target == "denied":
                    logger.warning(f"[ACCESS DENIED] Request blocked by policy")
                    await self.upstream.write_message(processed_msg)
                    continue
                
                if routing_target == "shadow":
                    logger.warning(f"[ROUTING] Message routed to SHADOW environment.")

                input_data = processed_msg.strip() + "\n"
                self.downstream_proc.stdin.write(input_data.encode('utf-8'))
                await self.downstream_proc.stdin.drain()

        except asyncio.CancelledError:
            logger.info("Upstream forwarding task cancelled.")
        except Exception as e:
            logger.error(f"Upstream -> Downstream forwarder error: {e}", exc_info=True)
        finally:
            # Close downstream stdin to signal no more data will be sent
            if self.downstream_proc.stdin:
                self.downstream_proc.stdin.close()
                await self.downstream_proc.stdin.wait_closed()

    async def _forward_downstream_to_upstream(self):
        """Task to read from the tool's stdout, sanitize, and forward to the agent."""
        if not self.downstream_proc or not self.downstream_proc.stdout:
            return

        try:
            # This loop correctly waits for data and exits when the stream is closed.
            while not self.downstream_proc.stdout.at_eof():
                line = await self.downstream_proc.stdout.readline()
                if not line:
                    break

                msg = line.decode('utf-8').strip()
                if msg:
                    clean_msg = self.sanitizer.sanitize(msg)
                    await self.upstream.write_message(clean_msg)

        except asyncio.CancelledError:
            logger.info("Downstream forwarding task cancelled.")
        except Exception as e:
            logger.error(f"Downstream -> Upstream forwarder error: {e}", exc_info=True)

    async def stop(self):
        """Gracefully stop the gateway and its subprocess."""
        await self.upstream.close()
        if self.downstream_proc and self.downstream_proc.returncode is None:
            logger.info("Terminating downstream process...")
            try:
                self.downstream_proc.terminate()
                await asyncio.wait_for(self.downstream_proc.wait(), timeout=5.0)
                logger.info("Downstream process terminated.")
            except asyncio.TimeoutError:
                logger.warning("Downstream process did not terminate gracefully, killing.")
                self.downstream_proc.kill()
            except Exception as e:
                logger.error(f"Error stopping downstream process: {e}")
