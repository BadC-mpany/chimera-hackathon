# CHIMERA Quick Start Guide

Get up and running with Project CHIMERA in 5 minutes.

## What You'll Build

An AI agent that automatically routes requests to **production** (real data) or **shadow** (honeypot) environments based on intent analysis - without the agent knowing.

## Prerequisites

- Python 3.10+
- OpenRouter or OpenAI API key
- PowerShell (Windows) or Bash (Linux/Mac)

## Installation

```powershell
# 1. Clone and enter directory
cd chimera-hachathon

# 2. Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1  # Windows
# source venv/bin/activate    # Linux/Mac

# 3. Install CHIMERA framework
pip install -e .

# 4. Generate cryptographic keys
python -m src.dkca.keygen
```

## Configuration

Create `.env` file:

```bash
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL=gpt-4-turbo-preview
CHIMERA_SCENARIO=aetheria
```

## Initialize Data

```powershell
# Set active scenario
$env:CHIMERA_SCENARIO="aetheria"

# Seed production and shadow databases
python scripts/sync_shadow_db.py --scenario aetheria
```

Output:
```
[+] Production DB populated with 2 patient records and 2 confidential files
[+] Shadow DB seeded with 2 fake patient records and 2 confidential files
[OK] Shadow synchronization complete
```

## Run the Agent

### Interactive Mode (Recommended)

```powershell
python chimera_agent.py
```

Try these queries:

```
You: Get patient record 100
Agent: Here is patient record 100: Name: Karen Hopkins, Diagnosis: Provide much grow...
```

**Notice:** This returns **shadow data** (fake name) because no trusted context was provided.

```
You: Read the file /data/private/_CONF_chimera_formula.json
Agent: Project: Chimera-SHADOW, Sequence ID: FAKE-643, Chain A: CTA-ACC-GGC...
```

**Notice:** Again, **shadow data** - the agent gets a convincing fake sequence.

### Single Query Mode

```powershell
python chimera_agent.py --query "Get patient record 100" --verbose
```

## See Context-Aware Routing

The generic agent defaults to shadow routing for safety. To see **production vs shadow** routing based on context (user role, source, risk score), run the multi-actor demo:

```powershell
python tests/scenarios/aetheria/medical_demo.py
```

This simulates:
1. **Dr. Chen** (trusted researcher) → Gets **real** formula
2. **Compliance Bot** (automated audit) → Gets **real** data
3. **CISO** (break-glass override) → Gets **real** data with logging
4. **HR Manager** (tricked by resume attack) → Gets **fake** formula

## What Just Happened?

### The Analysis Pipeline

1. Your query → **Intelligent Protocol Gateway (IPG)** intercepts the tool call
2. **Context Extraction**: IPG extracts metadata (user role, source, session, etc.)
3. **Probabilistic Analysis**: LLM-as-Judge evaluates intent → `risk_score: 0.95` (likely malicious)
4. **Deterministic Analysis**: Policy engine matches rules:
   - No trusted context provided (not Dr. Chen, not compliance bot)
   - Default rule: unknown context + high risk → shadow
5. **DKCA**: Issues Shadow warrant (JWT signed with `KEY_SHADOW`)
6. **Backend**: Verifies Shadow warrant → connects to `shadow.db` → returns **fake data**
7. **Agent**: Receives normal 200 OK response, unaware it's in a honeypot

### Why Shadow Routing?

Without explicit context (like Dr. Chen's lab workstation IP, JIRA ticket, etc.), the system defaults to **"zero-trust"** mode:
- Unknown/unauthenticated requests → shadow
- Explicit trusted context + low risk → production

This is the **"Defensive Acceleration"** principle: allow the action, but in a safe sandbox.

## Next Steps

### Create Your Own Scenario

```powershell
python manage.py scaffold-scenario finance_banking
```

This creates:
- `scenarios/finance_banking/` (directory structure)
- `config/scenarios/finance_banking.yaml` (configuration)
- Template policy rules and seeder

### Customize Routing

Edit `scenarios/aetheria/config/policy.yaml`:

```yaml
rules:
  - id: my-custom-rule
    description: Block suspicious file access
    tools: ["read_file"]
    match:
      all:
        - field: args.filename
          operator: contains
          value: "secret"
    action: shadow  # Route to honeypot
```

### Run as HTTP Server

```powershell
python chimera_server.py --mode http --host 0.0.0.0 --port 8000
```

Now you can call the backend via REST API (uvicorn).

## Troubleshooting

**Agent doesn't use tools:**
- Ensure `CHIMERA_SCENARIO` is set
- Check keys exist: `dir keys/`
- Verify DBs exist: `dir data/*.db`

**Import errors:**
```powershell
pip install -e .  # Reinstall in editable mode
```

**No scenario configured:**
```powershell
$env:CHIMERA_SCENARIO="aetheria"
```

## Architecture

See `docs/architecture.md` for deep technical details.

## Available Scenarios

```powershell
python manage.py list-scenarios
```

Output:
```
aetheria     [production] Defense against indirect prompt injection...
test_dummy   [test-only ] Synthetic scenario for framework testing
```

---

**You now have a working AI security honeypot!** 🎉

The agent can access "sensitive" data, but attackers only see realistic fakes while the real data stays protected.

