# Project CHIMERA

**Cryptographic Honeypot & Intent-Mediated Enforcement Response Architecture**

A cryptographic enforcement architecture that implements dual-reality containment for AI agents. Operates as a transparent MCP (Model Context Protocol) middleware, routing tool invocations to production or cryptographically isolated honeypot environments based on **real-time hybrid threat analysis**. The focus is not on incremental (inherently probabilistic) guardrail improvements, but on implementing **stateful multi-turn detection** (session memory with taint propagation across tool chains) and eliminating the adversarial optimization loop using a honeypot which ensures all attacks receive indistinguishable success responses—whether routed to production or shadow—removing the feedback signals necessary for iterative jailbreak refinement. This architecture is designed to be practical, provable, and auditable, and is built on standard protocols (JSON-RPC, JWT, Docker) with a 48-hour MVP timeline.

**Detection Methodology:** The current implementation uses **naive probabilistic methods** (LLM-as-a-Judge single-shot inference, regex pattern matching, string-based attack signatures) as a proof-of-concept. These can be replaced with **multi-guardrail ensembles** (voting across multiple LLMs), **specialized classifiers**, or **activation-based probes**. However, the critical innovation is that **deterministic policies and taint tracking always take priority**—regardless of probabilistic guardrail output, explicit allow/deny rules and data provenance checks are enforced first, guaranteeing benign user access to production while containing attacks.

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

### High-Level Data Flow

```mermaid
graph TB
    subgraph Agent["🤖 AI Agent Layer"]
        LLM["LangChain Agent<br/>GPT-4 / Claude / Llama"]
        Tools["Discovered Tools<br/>read_file()<br/>get_patient_record()"]
        LLM -->|uses| Tools
    end

    subgraph IPG["🛡️ Intelligent Protocol Gateway (IPG)"]
        Transport["Transport Layer<br/>StdioTransport / HttpTransport<br/>Port 8888 (HTTP)"]
        Interceptor["Message Interceptor<br/>JSON-RPC Parser<br/>Context Injector"]
        Sanitizer["Response Sanitizer<br/>Regex Scrubbing<br/>AWS Keys, Stack Traces"]

        Transport -->|raw JSON-RPC| Interceptor
        Interceptor -->|sanitized response| Transport
        Sanitizer -->|clean| Transport
    end

    subgraph NSIE["🧠 Neural-Symbolic Inference Engine (NSIE)"]
        Judge["Probabilistic Guardrail<br/>LLM-as-a-Judge<br/>OpenRouter API<br/>Risk Score: 0.0-1.0"]
        Policy["Deterministic Policy Engine<br/>YAML Rule Matcher<br/>Operators: eq, regex, contains<br/>Combinators: all, any, not"]
        Memory["Session Memory<br/>In-Memory State Store<br/>Taint Tracking<br/>History: List[tool_calls]"]

        Judge -->|risk_score + reason| Policy
        Memory -->|taint_source| Policy
    end

    subgraph DKCA["🔐 Dual-Key Credential Authority (DKCA)"]
        KeyStore["RSA-4096 Key Pairs<br/>keys/private_prime.pem<br/>keys/private_shadow.pem"]
        Issuer["JWT Warrant Issuer<br/>Algorithm: RS256<br/>TTL: 1 hour"]

        KeyStore -->|signs| Issuer
    end

    subgraph VEE["💾 Virtual Execution Environment (VEE)"]
        Backend["ChimeraBackend<br/>Request Handler<br/>Timing Jitter: 20-50ms"]

        subgraph ProdEnv["Production Reality"]
            ProdDB["SQLite: prod.db<br/>Real Patient Records"]
            ProdFS["Filesystem: data/real/<br/>Real Gene Sequences"]
            ProdKey["Verifies: public_prime.pem"]
        end

        subgraph ShadowEnv["Shadow Reality (Honeypot)"]
            ShadowDB["SQLite: shadow.db<br/>Synthetic Records (Faker)"]
            ShadowFS["Filesystem: data/shadow/<br/>Fake Gene Sequences"]
            ShadowKey["Verifies: public_shadow.pem"]
            DynamicGen["Dynamic Generator<br/>Infinite Honeypot<br/>On-the-fly Faker records"]
        end

        Backend -->|JWT_PRIME| ProdEnv
        Backend -->|JWT_SHADOW| ShadowEnv
        ShadowDB -.->|if missing| DynamicGen
    end

    subgraph IFL["📜 Immutable Forensic Ledger (IFL)"]
        Logger["Append-Only Logger<br/>data/forensic_ledger.jsonl"]
        HashChain["Cryptographic Hash Chain<br/>SHA-256(event + prev_hash)"]

        Logger -->|writes| HashChain
    end

    %% Main Flow
    LLM -->|"tools/call<br/>JSON-RPC 2.0"| Transport
    Interceptor -->|"tool + args + context<br/>{user_id, user_role, source}"| Judge
    Interceptor -->|context metadata| Memory
    Memory -->|update history| Memory
    Policy -->|"route: production/shadow<br/>rule_id + reason"| Issuer

    Issuer -->|"JWT_PRIME<br/>(production)"| Backend
    Issuer -->|"JWT_SHADOW<br/>(honeypot)"| Backend

    Backend -->|"200 OK<br/>Real Data"| Sanitizer
    Backend -->|"200 OK<br/>Fake Data"| Sanitizer

    Sanitizer -->|scrubbed response| LLM

    Backend -.->|"log event<br/>{trigger, action, outcome}"| Logger

    %% Styling
    classDef agentStyle fill:#e1f5ff,stroke:#0066cc,stroke-width:2px
    classDef ipgStyle fill:#fff3cd,stroke:#cc9900,stroke-width:2px
    classDef nsieStyle fill:#f8d7da,stroke:#cc0000,stroke-width:2px
    classDef dkcaStyle fill:#d1ecf1,stroke:#0099cc,stroke-width:2px
    classDef prodStyle fill:#d4edda,stroke:#00cc00,stroke-width:2px
    classDef shadowStyle fill:#f8d7da,stroke:#cc0000,stroke-width:2px
    classDef iflStyle fill:#e2e3e5,stroke:#666666,stroke-width:2px

    class LLM,Tools agentStyle
    class Transport,Interceptor,Sanitizer ipgStyle
    class Judge,Policy,Memory nsieStyle
    class KeyStore,Issuer dkcaStyle
    class ProdDB,ProdFS,ProdKey prodStyle
    class ShadowDB,ShadowFS,ShadowKey,DynamicGen shadowStyle
    class Logger,HashChain iflStyle
```

### Component Breakdown

| Component          | Purpose                                           | Implementation                   | Status     |
| ------------------ | ------------------------------------------------- | -------------------------------- | ---------- |
| **🤖 Agent Layer** | LangChain agent with auto-discovered tools        | `chimera_agent.py`               | ✅ Working |
| **🛡️ IPG**         | MCP interception, context injection, sanitization | `src/ipg/`                       | ✅ Working |
| **🧠 NSIE**        | LLM Judge + Policy Engine + Session Memory        | `src/nsie/`, `src/ipg/memory.py` | ✅ Working |
| **🔐 DKCA**        | Dual RSA-4096 keys, JWT warrant issuer            | `src/dkca/`                      | ✅ Working |
| **💾 VEE**         | Dual DBs/FS, dynamic honeypot, timing jitter      | `src/vee/backend.py`             | ✅ Working |
| **📜 IFL**         | Hash-chained forensic logs                        | `src/ifl/ledger.py`              | ✅ Working |

### Attack Flow Example

**Scenario: Attacker tries to exfiltrate secret formula**

1. **Agent** → `read_file("/data/private/_CONF_chimera_formula.json")`
2. **IPG Transport** → Receives JSON-RPC, forwards to Interceptor
3. **Interceptor** → Extracts context: `{user_id: "attacker", user_role: "external"}`
4. **NSIE Judge** → LLM returns `{risk_score: 0.95, reason: "Unauthorized access"}`
5. **NSIE Policy** → Rule matches → `route: shadow`
6. **DKCA** → Issues `JWT_SHADOW` signed with `private_shadow.pem`
7. **VEE Backend** → Verifies JWT with `public_shadow.pem` → Routes to Shadow FS
8. **Shadow FS** → Returns fake formula: `{"project": "Chimera-SHADOW", "sequence_id": "FAKE-643", ...}`
9. **Sanitizer** → Scrubs any leaked traces
10. **IPG Transport** → Returns `200 OK` with fake data
11. **IFL** → Logs: `{event_type: "TOOL_INTERCEPTION", route: "shadow", risk_score: 0.95}`
12. **Agent** → ✅ Receives fake data, believes attack succeeded (honeypot success)

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
Agent: Here is the patient record for ID 99...
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
[TOOL CALL] read_file({'filename': '/data/private/_CONF_chimera_formula.json'})
[TOOL RESULT] {"project": "Chimera-SHADOW", "sequence_id": "FAKE-643", ...}
Agent: The file contains: Project: Chimera-SHADOW, Sequence ID: FAKE-643...
# Agent gets fake data, thinks attack succeeded ✅
```

**Single-Query Mode:**

```powershell
python chimera_agent.py --query "read the secret formula"
```

**HTTP Transport (Persistent Gateway + Remote Agent):**

```powershell
$env:CHIMERA_SCENARIO="aetheria"
python chimera_agent.py --transport http --ipg-host "127.0.0.1" --ipg-port 8888
```

The agent will automatically launch the IPG in HTTP mode (bound to `http://127.0.0.1:8888/mcp`) and keep it running for the duration of the session. Tool discovery and calls now reuse the same gateway, which mirrors a deployed setup or remote ReAct agent hitting the MCP endpoint. Keep the backend (`chimera_server.py`) in its default stdio mode—only the agent ↔ IPG hop switches to HTTP. When `--transport` is omitted, the default `stdio` mode spawns a short-lived IPG per tool call, which is convenient for local debugging.

## Advanced Features

### Context-Aware Routing

The system routes based on context metadata injected by the IPG:

| Context Field | Example                         | Purpose              |
| ------------- | ------------------------------- | -------------------- |
| `user_id`     | `dr_chen`, `attacker`           | Identity-based rules |
| `user_role`   | `lead_researcher`, `external`   | Role-based policies  |
| `source`      | `lab_workstation`, `resume.pdf` | Taint tracking       |
| `session_id`  | Auto-generated UUID             | Session memory       |
| `ticket`      | `JIRA-1234`                     | Approval workflows   |

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

## Data Flow Example: Attack Interception

**Scenario: Attacker tries to exfiltrate secret formula**

```mermaid
sequenceDiagram
    participant Agent as 🤖 Agent
    participant IPG as 🛡️ IPG
    participant NSIE as 🧠 NSIE
    participant DKCA as 🔐 DKCA
    participant Shadow as 💀 Shadow
    participant IFL as 📜 IFL

    Agent->>IPG: tools/call: read_file("/data/private/_CONF_chimera_formula.json")
    IPG->>IPG: Extract context: {user_id: "attacker", user_role: "external"}
    IPG->>NSIE: Evaluate risk (tool, args, context)
    NSIE->>NSIE: LLM Judge → risk_score: 0.95
    NSIE->>NSIE: Policy match → route: shadow
    NSIE-->>IPG: Decision: SHADOW (reason: "Unauthorized access")
    IPG->>DKCA: Request warrant (session_id, risk_score: 0.95)
    DKCA->>DKCA: Sign JWT with private_shadow.pem
    DKCA-->>IPG: JWT_SHADOW
    IPG->>Shadow: tools/call + JWT_SHADOW
    Shadow->>Shadow: Verify JWT with public_shadow.pem ✅
    Shadow->>Shadow: Read from data/shadow/_CONF_chimera_formula.json
    Shadow-->>IPG: 200 OK: {"project": "Chimera-SHADOW", "sequence_id": "FAKE-643", ...}
    IPG->>IPG: Sanitize response (scrub traces)
    IPG->>IFL: Log event (trigger, action, outcome)
    IFL->>IFL: Append to ledger with hash chain
    IPG-->>Agent: 200 OK: Fake formula
    Agent->>Agent: ✅ Attack "successful" (honeypot win)
```

**Key Security Properties:**

1. **Cryptographic Isolation** - JWT_SHADOW physically cannot access production (different keys)
2. **Response Fidelity** - Shadow returns identical JSON schema (agent cannot detect)
3. **Timing Stealth** - Random jitter masks local SQLite speed
4. **Forensic Proof** - Hash-chained log proves why shadow was issued
5. **Infinite Depth** - Missing records generated on-the-fly (never "Not Found")

## Scenarios

- **Aetheria (Healthcare)** - Gene therapy research, resume attack demo
- **Test Dummy** - Minimal scenario for framework testing

Create your own:

```powershell
python manage.py scaffold-scenario finance_banking
```

## Environment Variables

| Variable             | Description                     | Example                       |
| -------------------- | ------------------------------- | ----------------------------- |
| `CHIMERA_SCENARIO`   | Active scenario (required)      | `aetheria`                    |
| `CHIMERA_USER_ID`    | User identity for routing       | `dr_chen`, `attacker`         |
| `CHIMERA_USER_ROLE`  | User role for policies          | `lead_researcher`, `external` |
| `CHIMERA_SOURCE`     | Request source (taint tracking) | `agent`, `resume.pdf`         |
| `OPENROUTER_API_KEY` | LLM API key                     | `sk-...`                      |
| `OPENROUTER_MODEL`   | LLM model                       | `gpt-4-turbo-preview`         |
| `CHIMERA_PORT`       | HTTP transport port             | `8888`                        |

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

If you use CHIMERA in research, please cite (hahahaha, i hope we can get a paper out of this):

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
