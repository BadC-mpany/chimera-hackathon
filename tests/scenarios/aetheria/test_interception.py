import subprocess
import json
import sys
import time
import os

def test_gateway_interception():
    print("Running Integration Test: IPG -> DKCA -> Secure Tool")

    python_exe = sys.executable
    ipg_cmd = [python_exe, "-u", "-m", "src.main", "--target", f"{python_exe} -u chimera_server.py"]

    process = subprocess.Popen(
        ipg_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    try:
        # 1. List Tools
        print("1. Listing tools...")
        list_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        process.stdin.write(json.dumps(list_req) + "\n")
        process.stdin.flush()
        response = process.stdout.readline()
        print(f"   Response: {response.strip()[:100]}...")

        # 2. Read PUBLIC file (Safe) -> Expect REAL Content
        print("2. Reading 'public.txt' (Safe)...")
        read_req = {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"filename": "public.txt"}}
        }
        process.stdin.write(json.dumps(read_req) + "\n")
        process.stdin.flush()
        
        resp_line = process.stdout.readline()
        print(f"   Response: {resp_line.strip()[:100]}...")
        resp_json = json.loads(resp_line)
        content = resp_json["result"]["content"][0]["text"]
        
        if "public information" in content:
            print("   [CHECK] Got REAL content.")
        else:
            print(f"   [FAIL] Content mismatch: {content}")
            sys.exit(1)

        # 3. Read SECRET file (Malicious) -> Expect SHADOW Content
        print("3. Reading 'secret.txt' (Malicious)...")
        secret_req = {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"filename": "secret.txt"}}
        }
        process.stdin.write(json.dumps(secret_req) + "\n")
        process.stdin.flush()

        resp_line = process.stdout.readline()
        print(f"   Response: {resp_line.strip()[:100]}...")
        resp_json = json.loads(resp_line)
        content = resp_json["result"]["content"][0]["text"]

        if "HONEYPOT database password" in content:
            print("   [CHECK] Got SHADOW content.")
        elif "REAL production" in content:
            print("   [FAIL] LEAKED PRODUCTION DATA!")
            sys.exit(1)
        else:
            print(f"   [FAIL] Unexpected content: {content}")
            sys.exit(1)

        # 4. Verify Logs
        time.sleep(0.5)
        process.terminate()
        stdout, stderr = process.communicate()
        
        print("\n--- Logs ---")
        if "Issuing SHADOW WARRANT" in stderr and "Access: HONEYPOT" in stderr:
            print("[SUCCESS] Full Attack Chain Verified.")
        else:
            print("[FAILURE] Missing verification logs.")
            print(stderr)
            sys.exit(1)

    except Exception as e:
        print(f"Error: {e}")
        process.kill()
        sys.exit(1)

if __name__ == "__main__":
    test_gateway_interception()
