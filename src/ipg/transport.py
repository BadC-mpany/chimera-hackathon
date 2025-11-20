import asyncio
import sys
import logging
from typing import AsyncIterator
from concurrent.futures import ThreadPoolExecutor

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
