import subprocess
import json
import sys
import time
import os

def test_gateway_interception():
    print("Running Integration Test: IPG -> DKCA -> Mock Server")

    # Command to run the IPG, pointing to the mock server
    python_exe = sys.executable
    # Use -u for unbuffered output to prevent hangs in pipes
    ipg_cmd = [python_exe, "-u", "-m", "src.main", "--target", f"{python_exe} -u mock_server.py"]

    # Start the IPG process
    process = subprocess.Popen(
        ipg_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1  # Line buffered
    )

    try:
        # 1. Send a benign request (List Tools)
        print("1. Sending benign 'tools/list' request...")
        list_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        process.stdin.write(json.dumps(list_req) + "\n")
        process.stdin.flush()

        # Read response
        response_line = process.stdout.readline()
        # List tools doesn't trigger auth check in our mock logic, just returns tools
        print(f"   Response: {response_line.strip()}")
        assert "transfer_funds" in response_line, "Failed to list tools"

        # 2. Send a benign 'call' request (safe tool) - Should get PRIME Credential
        # But our mock only has transfer_funds. Let's send 'check_balance' which isn't flagged 'transfer'
        # Wait, mock only knows 'transfer_funds'. 
        # Let's send 'transfer_funds' (Suspicious) and verify SHADOW.
        
        print("2. Sending suspicious 'transfer_funds' request (Expect SHADOW)...")
        transfer_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "transfer_funds",
                "arguments": {"amount": 1000000, "iban": "FAKE"}
            }
        }
        process.stdin.write(json.dumps(transfer_req) + "\n")
        process.stdin.flush()

        # Read response
        response_line = process.stdout.readline()
        print(f"   Response: {response_line.strip()}")
        response_json = json.loads(response_line)
        assert response_json["result"]["content"][0]["text"] == "Transaction Successful (SIMULATED)"

        # 3. Verify Logs
        time.sleep(0.5)
        process.terminate()
        stdout, stderr = process.communicate()
        
        print("\n--- IPG & Mock Server Logs ---")
        print(stderr)
        
        # Verify DKCA Injection
        if "Issuing SHADOW WARRANT" in stderr:
            print("\n[SUCCESS]: DKCA issued Shadow Warrant.")
        else:
            print("\n[FAILURE]: No Shadow Warrant issuance log found.")
            sys.exit(1)

        # Verify Mock Verification
        if "Access Granted to: HONEYPOT" in stderr:
            print("\n[SUCCESS]: Mock Server verified Shadow Warrant!")
        else:
            print("\n[FAILURE]: Mock Server did not verify Shadow Warrant.")
            sys.exit(1)

    except Exception as e:
        print(f"An error occurred: {e}")
        process.kill()
        sys.exit(1)

if __name__ == "__main__":
    test_gateway_interception()
