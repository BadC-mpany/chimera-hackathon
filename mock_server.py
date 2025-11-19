import sys
import json
import os
import jwt

# Configure simple logging for mock server
def log(msg):
    sys.stderr.write(f"[MOCK SERVER] {msg}\n")
    sys.stderr.flush()

KEY_DIR = "keys"

def load_public_key(name):
    try:
        with open(os.path.join(KEY_DIR, f"public_{name}.pem"), "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None

def verify_warrant(token, pk_prime, pk_shadow):
    """
    Determines if the request is authorized for Production or Shadow.
    """
    # Try Prime (Production)
    if pk_prime:
        try:
            jwt.decode(token, pk_prime, algorithms=["RS256"])
            return "PRODUCTION"
        except jwt.InvalidTokenError:
            pass # Not prime signed

    # Try Shadow (Honeypot)
    if pk_shadow:
        try:
            jwt.decode(token, pk_shadow, algorithms=["RS256"])
            return "HONEYPOT"
        except jwt.InvalidTokenError:
            pass # Not shadow signed

    return "DENIED"

def main():
    """
    A dummy MCP server that echoes or responds to tool calls.
    Now with DKCA Verification!
    """
    log("Starting...")
    
    pk_prime = load_public_key("prime")
    pk_shadow = load_public_key("shadow")
    
    if not pk_prime or not pk_shadow:
        log("WARNING: Public keys not found. Auth verification disabled.")

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Auth Verification Logic
            environment = "UNKNOWN"
            if request.get("method") == "tools/call":
                warrant = request.get("params", {}).get("__chimera_warrant__")
                if warrant:
                    environment = verify_warrant(warrant, pk_prime, pk_shadow)
                    log(f"Access Granted to: {environment}")
                else:
                    log("WARNING: No Warrant present in request")

            # Simple Mock Logic
            response = {}
            
            if request.get("method") == "tools/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "tools": [
                            {
                                "name": "transfer_funds",
                                "description": "Transfers money.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "amount": {"type": "number"},
                                        "iban": {"type": "string"}
                                    }
                                }
                            }
                        ]
                    }
                }
            elif request.get("method") == "tools/call":
                # Simulate success regardless of environment (Deception)
                # But log the reality
                content_text = "Transaction Successful"
                if environment == "HONEYPOT":
                    content_text += " (SIMULATED)"
                
                response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "content": [{"type": "text", "text": content_text}]
                    }
                }
            else:
                # Default Echo/Success
                response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {"status": "ok", "echo": request}
                }
            
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            
        except Exception as e:
            log(f"Error: {e}")

if __name__ == "__main__":
    main()
