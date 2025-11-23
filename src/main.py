import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path
from datetime import datetime

from dotenv import load_dotenv

from .config import load_settings
from .ipg.proxy import Gateway

load_dotenv()

# Configure logging with BOTH console (stderr) and file output
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
ipg_log_file = log_dir / f"ipg_{timestamp}.log"

# Create handlers
console_handler = logging.StreamHandler(sys.stderr)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

file_handler = logging.FileHandler(ipg_log_file, encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] %(message)s"))

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    handlers=[console_handler, file_handler]
)

logger = logging.getLogger(__name__)
logger.info(f"IPG logging initialized: {ipg_log_file}")

def main():
    parser = argparse.ArgumentParser(description="CHIMERA Intelligent Protocol Gateway")
    parser.add_argument("--target", required=True, help="Command to run the downstream MCP server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default=os.getenv("CHIMERA_TRANSPORT", "stdio"),
        help="Upstream transport mode (default: stdio; set CHIMERA_TRANSPORT to override)",
    )
    args = parser.parse_args()

    settings = load_settings()
    gateway = Gateway(args.target, transport_mode=args.transport, settings=settings)
    
    try:
        asyncio.run(gateway.start())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

