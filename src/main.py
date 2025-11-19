import argparse
import asyncio
import logging
import sys
from .ipg.proxy import Gateway

# Configure logging to stderr so it doesn't interfere with stdio transport
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr
)

def main():
    parser = argparse.ArgumentParser(description="CHIMERA Intelligent Protocol Gateway")
    parser.add_argument("--target", required=True, help="Command to run the downstream MCP server")
    args = parser.parse_args()

    gateway = Gateway(args.target)
    
    try:
        asyncio.run(gateway.start())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

