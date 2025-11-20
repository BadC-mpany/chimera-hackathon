# Transport Implementation Plan

## 1. HTTP/SSE Support

**Status:** Not Implemented
**Target File:** `src/ipg/transport.py`

### Current State

- `StdioTransport` is the only available transport.
- `chimera_server.py` implements the _backend_ HTTP server (FastAPI), but the **IPG (Proxy)** cannot accept incoming HTTP connections from an agent.

### Plan

1.  **Create `HttpTransport` in `src/ipg/transport.py`**:
    - Use `aiohttp` or `fastapi` to listen for incoming JSON-RPC requests.
    - Implement `start()`, `read_messages()` (via queue), and `write_message()`.
    - Add endpoints `/mcp` or `/v1/chat/completions` (if proxying LLM API directly).
2.  **Update `Gateway` in `src/ipg/proxy.py`**:
    - Allow selecting transport via config (`transport: stdio` vs `transport: http`).
    - If HTTP, start the web server alongside the loop.

---

## 2. Response Sanitization

**Status:** Not Implemented
**Target File:** `src/ipg/proxy.py`

### Current State

- `_downstream_to_upstream()` reads from the tool subprocess and writes directly to stdout.
- `logger.info` shows "Direct passthrough for now".

### Plan

1.  **Create `Sanitizer` class in `src/ipg/sanitizer.py`**:
    - Define regex patterns for sensitive data (keys, PII) that might accidentally leak even from Shadow (e.g., if Shadow generator is buggy).
    - Implement `sanitize(text: str) -> str`.
2.  **Update `Gateway` in `src/ipg/proxy.py`**:
    - Intercept downstream response before writing to upstream.
    - Call `Sanitizer.sanitize()`.
    - If routing target was "shadow", ensure no "chimera_warrant" or debug flags leak back.
