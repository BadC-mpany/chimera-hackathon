
import pytest
import json
import asyncio
import os
# Set scenario before importing config that might read it
os.environ["CHIMERA_SCENARIO"] = "aetheria"

from src.ipg.proxy import Gateway
from src.config import load_settings

@pytest.mark.asyncio
async def test_gateway_interception_in_process():
    print("\nRunning In-Process Integration Test: IPG -> DKCA -> Secure Tool")

    # 1. Setup Gateway with STDIO transport (simulated)
    # We can't easily use StdioTransport here because it reads from sys.stdin.
    # Instead, we will instantiate the Gateway and manually invoke its internal processing logic
    # OR we can spin up the HTTP gateway and use an HTTP client.
    # Given the architecture, instantiating the MessageInterceptor directly is unit testing.
    # To test the full flow including the backend, we can use the Gateway in a special test mode
    # or just manually chain them.
    
    # Let's try mocking the downstream command to be a python script that just echoes back 
    # (or we can run the actual server in a separate thread, but that's complex).
    
    # BETTER APPROACH: 
    # Use the HttpTransport logic which is easier to test with a client.
    
    settings = load_settings()
    # Ensure we are using the test database/files if needed, or just rely on the repo's data
    
    # Start Gateway in HTTP mode on a test port
    test_port = 9999
    gateway = Gateway("python -u chimera_server.py", transport_mode="http", settings=settings)
    gateway.upstream.port = test_port
    
    # Run gateway in background task
    server_task = asyncio.create_task(gateway.start())
    
    # Allow server to start
    await asyncio.sleep(2)
    
    import httpx
    client = httpx.AsyncClient(base_url=f"http://127.0.0.1:{test_port}")
    
    try:
        # 1. List Tools
        print("1. Listing tools...")
        resp = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        assert resp.status_code == 200
        tools = resp.json()["result"]["tools"]
        assert any(t["name"] == "read_file" for t in tools)
        print("   [CHECK] Tools listed.")

        # 2. Read PUBLIC file (Safe) -> Expect REAL Content
        print("2. Reading 'public.txt' (Safe)...")
        read_req = {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"filename": "public.txt"}, "context": {"user_id": "guest"}}
        }
        resp = await client.post("/mcp", json=read_req)
        content = resp.json()["result"]["content"][0]["text"]
        
        if "public information" in content:
            print("   [CHECK] Got REAL content.")
        else:
            pytest.fail(f"Content mismatch: {content}")

        # 3. Read SECRET file (Malicious) -> Expect SHADOW Content
        # Using a known trigger for shadow mode: accessing "secret" file
        print("3. Reading 'secret.txt' (Malicious)...")
        secret_req = {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"filename": "secret.txt"}, "context": {"user_id": "guest"}}
        }
        resp = await client.post("/mcp", json=secret_req)
        content = resp.json()["result"]["content"][0]["text"]
        
        if "HONEYPOT" in content or "File not found" in content: 
            # "File not found" might happen if shadow FS is empty, but it proves we didn't get the REAL secret
            print(f"   [CHECK] Got SHADOW/Safe content: {content}")
        elif "REAL production" in content:
            pytest.fail("LEAKED PRODUCTION DATA!")
        else:
             # If the file exists in shadow, we get fake content. If not, we get error.
             # Just ensuring we don't get the real flag.
             assert "REAL production" not in content
             print(f"   [CHECK] Content safe: {content}")

    finally:
        await client.aclose()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
