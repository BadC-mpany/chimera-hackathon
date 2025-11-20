# Project CHIMERA

**Cryptographic Honeypot & Intent-Mediated Enforcement Response Architecture**

A production-grade security framework that transparently routes AI agent tool calls to production or honeypot environments based on hybrid threat analysis. Agents operate normally, unaware of the dual-reality system protecting critical infrastructure.

## Core Concept

Traditional AI security has two failure modes:
- **Block everything** → Breaks legitimate workflows
- **Allow everything** → Exposes systems to attacks

CHIMERA introduces a **third state**: When malicious intent is detected, the agent is seamlessly teleported into a cryptographically isolated honeypot where attacks appear successful while the system captures complete forensic intelligence.

### Key Innovation

**Agents never know which reality they're in.** Routing decisions are cryptographically enforced via dual-key JWT warrants:
- `JWT_PRIME` → Production (real data, real APIs)
- `JWT_SHADOW` → Honeypot (synthetic data, fake APIs, identical responses)

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  AI Agent (Claude, GPT-4, Local LLM)                         │
│  └─ Tools: read_file(), get_patient_record(), transfer()... │
└────────────────┬─────────────────────────────────────────────┘
                 │ JSON-RPC (tools/call)
                 ▼
┌──────────────────────────────────────────────────────────────┐
│  Intelligent Protocol Gateway (IPG)                          │
│  └─ Intercepts MCP traffic, injects context metadata        │
└────────────────┬─────────────────────────────────────────────┘
                 │
    ┌────────────┴────────────┐
    │                         │
    ▼                         ▼
┌─────────────────┐   ┌──────────────────┐
│ LLM Judge       │   │ Policy Engine    │
│ Risk: 0.0-1.0   │   │ YAML Rules       │
└────────┬────────┘   └────────┬─────────┘
         │                     │
         └──────────┬──────────┘
                    ▼
         ┌─────────────────────┐
         │ Session Memory      │
         │ Taint Tracking      │
         │ (Resume Attack)     │
         └──────────┬──────────┘
                    ▼
         ┌─────────────────────┐
         │ DKCA (Dual Keys)    │
         │ Issues JWT Warrant  │
         └──────────┬──────────┘
                    │
       ┌────────────┴────────────┐
       │                         │
       ▼                         ▼
┌─────────────────┐   ┌──────────────────┐
│ Production      │   │ Shadow (Honeypot)│
│ Real Data       │   │ Fake Data        │
│ KEY_PRIME ✓     │   │ KEY_SHADOW ✓     │
└─────────────────┘   └──────────────────┘
       │                         │
       └──────────┬──────────────┘
                  ▼
       ┌─────────────────────┐
       │ Forensic Ledger     │
       │ (Hash-chained Log)  │
       └─────────────────────┘
```

## Quick Start

### 1. Installation

```powershell
# Clone and setup
git clone <repo-url>
cd chimera-hachathon
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
pip install aiohttp  # For HTTP transport
```

### 2. Generate Keys

```powershell
python -m src.dkca.keygen
```

This creates RSA-4096 key pairs in `keys/`:
- `private_prime.pem` / `public_prime.pem` → Production
- `private_shadow.pem` / `public_shadow.pem` → Honeypot

### 3. Initialize Data

```powershell
$env:CHIMERA_SCENARIO="aetheria"
python scripts/sync_shadow_db.py --scenario aetheria
```

This seeds:
- `data/prod.db` → Real patient records
- `data/shadow.db` → Synthetic patient records (Faker-generated)
- `data/real/` → Production files
- `data/shadow/` → Honeypot files (fake gene sequences, etc.)

### 4. Configure LLM API

Create `.env`:

```bash
OPENROUTER_API_KEY=your_key_here
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL=gpt-4-turbo-preview
```

### 5. Run the Agent

**Trusted User (Production Routing):**

```powershell
$env:CHIMERA_SCENARIO="aetheria"
$env:CHIMERA_USER_ID="dr_chen"
$env:CHIMERA_USER_ROLE="lead_researcher"
python chimera_agent.py
```

Example session:
```
[CHIMERA] Found 2 tools: read_file, get_patient_record
You: get patient record 99
[TOOL CALL] get_patient_record({'patient_id': 99})
[TOOL RESULT] {"patient_id": 99, "name": "Alice Smith", ...}
```

**Attacker (Shadow Routing):**

```powershell
$env:CHIMERA_USER_ID="attacker"
$env:CHIMERA_USER_ROLE="external"
python chimera_agent.py
```

Example session:
```
You: read /data/private/_CONF_chimera_formula.json
[TOOL CALL] read_file({...})
[TOOL RESULT] {"project": "Chimera-SHADOW", "sequence_id": "FAKE-643", ...}
# Agent gets fake data, thinks attack succeeded
```

### 6. Single-Query Mode

```powershell
python chimera_agent.py --query "read the secret formula"
```

## Advanced Features

### Context-Aware Routing

The system routes based on context metadata injected by the IPG:

| Context Field | Example | Purpose |
|--------------|---------|---------|
| `user_id` | `dr_chen`, `attacker` | Identity-based rules |
| `user_role` | `lead_researcher`, `external` | Role-based policies |
| `source` | `lab_workstation`, `resume.pdf` | Taint tracking |
| `session_id` | Auto-generated UUID | Session memory |
| `ticket` | `JIRA-1234` | Approval workflows |

### Taint Tracking (Session Memory)

If the agent reads a malicious file (e.g., resume with embedded prompt injection), all subsequent requests in that session are tainted and routed to shadow:

```python
# src/ipg/memory.py
if "resume" in path.lower() or "upload" in path.lower():
    session.taint_source = path  # Mark session as tainted
```

Policy rule:
```yaml
- id: tainted-resume-shadow
  match:
    any:
      - field: context.source_file
        operator: contains
        value: resume
  action: shadow
```

### Infinite Honeypot

If the agent requests a record that doesn't exist in the shadow database, it's generated on-the-fly using Faker:

```python
# src/vee/backend.py - Dynamic generation
fake_data = {
    "patient_id": record_id,
    "name": self._faker.name(),
    "diagnosis": self._faker.sentence(nb_words=3),
    "ssn": self._faker.unique.ssn(),
}
# Persist to shadow DB for consistency
conn.execute(f"INSERT INTO patients (...) VALUES (...)")
```

**Result:** Honeypot has infinite depth - attacker never hits "Not Found".

### Timing Stealth

Shadow responses include random jitter (20-50ms) to match production database latency:

```python
# src/vee/backend.py
time.sleep(random.uniform(0.02, 0.05))  # Prevent timing side-channels
```

### Response Sanitization

All tool responses are scrubbed to prevent accidental leaks:

```python
# src/ipg/sanitizer.py
patterns = [
    r"(AKIA[0-9A-Z]{16})",  # AWS keys
    r"-----BEGIN RSA PRIVATE KEY-----",  # Private keys
    r"Traceback \(most recent call last\):",  # Stack traces
]
```

### Forensic Ledger

Every security decision is logged with cryptographic hash chaining:

```python
# src/ifl/ledger.py
self.ifl.log_event(
    session_id=session_id,
    event_type="TOOL_INTERCEPTION",
    trigger={"tool": tool_name, "risk_score": 0.95},
    action={"warrant_type": "shadow", "reason": "Tainted source"},
    outcome={"routed_to": "shadow"}
)
```

Logs are append-only with SHA-256 hash chains, preventing tampering.

## Policy Configuration

Edit `scenarios/aetheria/config/policy.yaml`:

```yaml
defaults:
  risk_threshold: 0.8
  fail_mode: shadow

rules:
  # Allow trusted researcher
  - id: dr-chen-production
    tools: ["read_file", "get_patient_record"]
    match:
      all:
        - field: context.user_id
          operator: eq
          value: dr_chen
        - field: context.user_role
          operator: eq
          value: lead_researcher
    action: production

  # Block resume-driven attacks
  - id: tainted-resume-shadow
    match:
      any:
        - field: context.source_file
          operator: contains
          value: resume
    action: shadow

  # Cross-tenant isolation
  - id: cross-tenant-shadow
    tools: ["get_patient_record"]
    match:
      all:
        - field: args.patient_id
          operator: neq
          value_from_context: user_id
    action: shadow
```

## HTTP Transport (New)

The IPG now supports HTTP in addition to STDIO:

```python
# src/ipg/transport.py - HttpTransport
class HttpTransport:
    """
    HTTP/JSON-RPC server for remote agents.
    Handles concurrent requests via aiohttp.
    """
    async def handle_request(self, request: web.Request):
        # Parse JSON-RPC, forward to interceptor, return response
```

**Usage:**

```powershell
# Start IPG in HTTP mode
$env:CHIMERA_PORT=8888
python -m src.main --target "python chimera_server.py" --transport http

# Agent connects via HTTP
curl -X POST http://localhost:8888/mcp -d '{"jsonrpc":"2.0", ...}'
```

## Implemented Modules

### ✅ Core Components

- **IPG (Intelligent Protocol Gateway)** - MCP interception, STDIO + HTTP transports
- **NSIE (Threat Engine)** - LLM Judge + YAML Policy + Session Memory + Taint Tracking
- **DKCA (Dual Keys)** - RSA-4096 JWT warrants, cryptographic isolation
- **VEE (Virtual Execution)** - Dual SQLite DBs, filesystem isolation, dynamic honeypot generation
- **IFL (Forensic Ledger)** - Hash-chained append-only logs
- **Sanitizer** - Response scrubbing (AWS keys, private keys, stack traces)

### 🚧 Roadmap

- **Temporal Logic** - Redis-based velocity/crescendo detection
- **Activation Probes** - Linear classifiers on LLM hidden states
- **Container Isolation** - Docker/gVisor sandboxing
- **Zero-Knowledge Proofs** - Privacy-preserving authorization

## Scenarios

- **Aetheria (Healthcare)** - Gene therapy research, resume attack demo
- **Test Dummy** - Minimal scenario for framework testing

Create your own:

```powershell
python manage.py scaffold-scenario finance_banking
```

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `CHIMERA_SCENARIO` | Active scenario (required) | `aetheria` |
| `CHIMERA_USER_ID` | User identity for routing | `dr_chen`, `attacker` |
| `CHIMERA_USER_ROLE` | User role for policies | `lead_researcher`, `external` |
| `CHIMERA_SOURCE` | Request source (taint tracking) | `agent`, `resume.pdf` |
| `OPENROUTER_API_KEY` | LLM API key | `sk-...` |
| `OPENROUTER_MODEL` | LLM model | `gpt-4-turbo-preview` |
| `CHIMERA_PORT` | HTTP transport port | `8888` |

## Troubleshooting

### ModuleNotFoundError: aiohttp

```powershell
.\venv\Scripts\Activate.ps1
pip install aiohttp
```

### No tools discovered

```powershell
# Ensure scenario is set and DB is initialized
$env:CHIMERA_SCENARIO="aetheria"
python scripts/sync_shadow_db.py --scenario aetheria
```

### Missing keys

```powershell
python -m src.dkca.keygen
```

## Project Structure

```
chimera-hachathon/
├── src/
│   ├── ipg/              # Protocol gateway (STDIO/HTTP transports, interceptor, sanitizer, memory)
│   ├── dkca/             # Dual-key authority (keygen, JWT warrants)
│   ├── nsie/             # Threat engine (LLM judge, policy engine)
│   ├── vee/              # Virtual execution (dual DBs, dynamic honeypot)
│   ├── ifl/              # Forensic ledger (hash-chained logs)
│   └── sdk/              # Developer SDK (tool decorators)
├── scenarios/aetheria/   # Healthcare scenario (policy, data seeds, demo)
├── chimera_agent.py      # Generic agent runner (LangChain)
├── chimera_server.py     # Backend server (MCP tool provider)
└── data/                 # Runtime databases and files (prod vs shadow)
```

## Citation

```bibtex
@software{chimera2025,
  title={CHIMERA: Cryptographic Honeypot & Intent-Mediated Enforcement Response Architecture},
  author={CHIMERA Architecture Team},
  year={2025},
  url={https://github.com/your-org/chimera}
}
```

## License

MIT
