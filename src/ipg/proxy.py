import asyncio
import logging
import sys
import shlex
from typing import Optional
from .transport import StdioTransport
from .interceptor import MessageInterceptor

logger = logging.getLogger(__name__)

class Gateway:
    """
    Orchestrates the bi-directional flow between the Upstream Agent and the Downstream Tool.
    """
    
    def __init__(self, downstream_command: str):
        self.downstream_command = downstream_command
        self.upstream = StdioTransport()
        self.interceptor = MessageInterceptor()
        self.downstream_proc: Optional[asyncio.subprocess.Process] = None

    async def start(self):
        """Starts the gateway loop."""
        logger.info(f"Starting IPG with downstream target: {self.downstream_command}")
        
        # 1. Start Upstream (Stdin/Stdout)
        await self.upstream.start()
        
        # 2. Start Downstream (Subprocess)
        # using shell=True for flexibility in the MVP command string, but exec is better for security usually
        self.downstream_proc = await asyncio.create_subprocess_shell(
            self.downstream_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr # Passthrough stderr for now
        )

        if not self.downstream_proc.stdin or not self.downstream_proc.stdout:
            raise RuntimeError("Failed to connect pipes to downstream process")

        # 3. Run loops
        try:
            await asyncio.gather(
                self._upstream_to_downstream(),
                self._downstream_to_upstream()
            )
        except Exception as e:
            logger.error(f"Gateway error: {e}")
        finally:
            await self.stop()

    async def _upstream_to_downstream(self):
        """Reads from Agent (stdin), Intercepts, writes to Tool (subprocess)."""
        try:
            async for message in self.upstream.read_messages():
                # Intercept & Inspect
                processed_msg, routing_target = await self.interceptor.process_message(message)
                
                if routing_target == "shadow":
                    logger.warning(f"[ROUTING] Message routed to SHADOW environment: {message[:50]}...")
                
                # Forward to downstream
                if self.downstream_proc and self.downstream_proc.stdin:
                    logger.info("Gateway: Writing to downstream...")
                    input_data = processed_msg.strip() + "\n"
                    self.downstream_proc.stdin.write(input_data.encode('utf-8'))
                    await self.downstream_proc.stdin.drain()
                    logger.info("Gateway: Wrote to downstream")
        except Exception as e:
            logger.error(f"Upstream -> Downstream error: {e}")

    async def _downstream_to_upstream(self):
        """Reads from Tool (subprocess), writes to Agent (stdout)."""
        try:
            if not self.downstream_proc or not self.downstream_proc.stdout:
                return
            
            logger.info("Gateway: Starting downstream listener...")
            while True:
                line = await self.downstream_proc.stdout.readline()
                if not line:
                    logger.info("Gateway: Downstream EOF")
                    break
                
                logger.info(f"Gateway: Read from downstream: {line[:20]}...")
                # Direct passthrough for now (Agent doesn't need to know response was intercepted, usually)
                # In full CHIMERA, we might sanitize this too.
                msg = line.decode('utf-8').strip()
                if msg:
                    await self.upstream.write_message(msg)
                    logger.info("Gateway: Forwarded to upstream")
        except Exception as e:
            logger.error(f"Downstream -> Upstream error: {e}")

    async def stop(self):
        """Cleanup."""
        await self.upstream.close()
        if self.downstream_proc:
            try:
                self.downstream_proc.terminate()
                await self.downstream_proc.wait()
            except Exception:
                pass

