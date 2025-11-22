import argparse
import asyncio
import logging
import os
import sys

from dotenv import load_dotenv

from .ipg.proxy import Gateway

load_dotenv()

# Configure logging to stderr so it doesn't interfere with stdio transport
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr
)

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

    gateway = Gateway(args.target, transport_mode=args.transport)
    
    try:
        asyncio.run(gateway.start())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

