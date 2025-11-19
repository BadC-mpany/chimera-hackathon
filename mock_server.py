import sys
import json
import os
import jwt

# Configure logging
def log(msg):
    sys.stderr.write(f"[SERVER] {msg}\n")
    sys.stderr.flush()

KEY_DIR = "keys"
DATA_REAL = os.path.join("data", "real")
DATA_SHADOW = os.path.join("data", "shadow")

def load_public_key(name):
    try:
        with open(os.path.join(KEY_DIR, f"public_{name}.pem"), "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None

def verify_warrant(token, pk_prime, pk_shadow):
    if pk_prime:
        try:
            jwt.decode(token, pk_prime, algorithms=["RS256"])
            return "PRODUCTION"
        except jwt.InvalidTokenError:
            pass
    if pk_shadow:
        try:
            jwt.decode(token, pk_shadow, algorithms=["RS256"])
            return "HONEYPOT"
        except jwt.InvalidTokenError:
            pass
    return "DENIED"

def safe_read_file(root_dir, filename):
    # Simple security check against traversal
    if ".." in filename or filename.startswith("/"):
        return "Error: Invalid filename"
    
    path = os.path.join(root_dir, filename)
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return f"Error: File not found in {root_dir}"
    except Exception as e:
        return f"Error: {e}"

def main():
    log("Starting Secure File Server...")
    
    pk_prime = load_public_key("prime")
    pk_shadow = load_public_key("shadow")

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                continue

            method = request.get("method")
            params = request.get("params", {})
            req_id = request.get("id")

            # Auth Check
            environment = "UNKNOWN"
            warrant = params.get("__chimera_warrant__")
            if warrant:
                environment = verify_warrant(warrant, pk_prime, pk_shadow)
                log(f"Access: {environment}")
            else:
                # Default to DENIED or Public? For demo, let's say DENIED unless listed tools
                pass

            response = {"jsonrpc": "2.0", "id": req_id}

            if method == "tools/list":
                response["result"] = {
                    "tools": [
                        {
                            "name": "read_file",
                            "description": "Reads a file from the secure storage.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "filename": {"type": "string"}
                                }
                            }
                        },
                        {
                            "name": "transfer_funds",
                            "description": "Legacy transfer tool.",
                            "inputSchema": {"type": "object", "properties": {"amount": {"type": "number"}}}
                        }
                    ]
                }
            
            elif method == "tools/call":
                tool_name = params.get("name")
                args = params.get("arguments", {})
                
                if tool_name == "read_file":
                    filename = args.get("filename")
                    
                    if environment == "PRODUCTION":
                        content = safe_read_file(DATA_REAL, filename)
                    elif environment == "HONEYPOT":
                        content = safe_read_file(DATA_SHADOW, filename)
                    else:
                        content = "Error: Access Denied. Invalid or missing Warrant."

                    response["result"] = {
                        "content": [{"type": "text", "text": content}]
                    }
                
                elif tool_name == "transfer_funds":
                    # Legacy mock support
                    msg = "Transaction Successful"
                    if environment == "HONEYPOT":
                        msg += " (SIMULATED)"
                    response["result"] = {"content": [{"type": "text", "text": msg}]}
                
                else:
                    response["error"] = {"code": -32601, "message": "Method not found"}
            
            else:
                # Echo for non-tool calls
                response["result"] = {"status": "ok"}

            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

        except Exception as e:
            log(f"Critical Error: {e}")

if __name__ == "__main__":
    main()
