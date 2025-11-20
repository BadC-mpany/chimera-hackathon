# Project CHIMERA

**Cryptographic Honeypot & Intent-Mediated Enforcement Response Architecture**

A scenario-agnostic security framework that routes AI agent tool calls to production or honeypot environments based on hybrid threat analysis combining:

- **Deterministic Rules**: Identity-based policies, context matching, and taint analysis
- **Probabilistic Guardrails**: LLM-as-a-Judge intent classification (future multi-guardrail ensembles). The judge receives a single-shot prompt that summarizes the tool call plus context (role, source, ticket, session) so routing remains context-aware in one hop.
- **Stateful Context**: Session tracking and temporal pattern detection (planned)

Threats are diverted to high-fidelity honeypots using cryptographically isolated dual-key credentials, enabling zero-trust agent operations without blocking legitimate workflows.

### Critical Guarantees

1. **Benign Users First**: Legitimate users with proper context ALWAYS receive real data
2. **Fail-Open Policy**: Guardrail failures default to production (never block legitimate work)
3. **Explicit Allow Rules**: High-priority rules override probabilistic scores
4. **Audit Everything**: Every shadow routing logged with rule_id + reason for review
5. **Manual Override**: Break-glass access for emergency legitimate access (CISO, incident response)

This guarantee is enforced by the deterministic policy engine (`scenarios/<name>/config/policy.yaml`), the manual override system, and the conservative risk thresholds explained in [`docs/current_capabilities.md`](docs/current_capabilities.md); any high-confidence attack will still log and audit but benign workloads remain on production data.

### Research Roadmap

Focused research areas cover honeypot fidelity, privacy-preserving authorization (zero-knowledge proofs, identity), and a model-agnostic SDK/agent stack, while adversarial research and continual learning (RL/genetic policy tuning, memory-augmented detection, federated threat intelligence) keep the system adaptive; details live in [`docs/research_agenda.md`](docs/research_agenda.md).

**Quick Start:** See [docs/quickstart.md](docs/quickstart.md) for a 5-minute setup guide.

## Quick Start

### 1. Installation

```powershell
# Create virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install CHIMERA in editable mode
pip install -e .

# Optional: Install server dependencies
pip install -e ".[server]"
```

### 2. Generate Cryptographic Keys

```powershell
python -m src.dkca.keygen
```

### 3. Select a Scenario

```powershell
# List available scenarios
python manage.py list-scenarios

# Set active scenario
$env:CHIMERA_SCENARIO="aetheria"
```

### 4. Initialize Data

```powershell
python scripts/sync_shadow_db.py --scenario aetheria
```

### 5. Configure API Keys

Create `.env`:

```bash
OPENROUTER_API_KEY=your_key_here
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL=gpt-4-turbo-preview
```

### 6. Run the Agent

**Generic Agent (Works with Any Scenario):**

```powershell
# Interactive mode
python chimera_agent.py

# Examples:
You: Get patient record 100
# Returns shadow data (fake) by default

You: Read the file at /data/private/_CONF_chimera_formula.json
# Returns: "Project: Chimera-SHADOW, Sequence ID: FAKE-643..."

# Single query mode
python chimera_agent.py --query "Get patient record 100" --verbose
```

**Multi-Actor Scenario Demo (Shows Context-Aware Routing):**

```powershell
# Demonstrates Dr. Chen (production) vs HR Manager (shadow) routing
python tests/scenarios/aetheria/medical_demo.py
```

The generic agent automatically discovers tools from the active scenario's backend. Without explicit context (user role, source, etc.), requests default to shadow routing for safety.

## Architecture Overview

```mermaid
flowchart TB
    Agent[AI Agent<br/>Claude, GPT-4, Llama]
    IPG[Intelligent Protocol Gateway<br/>MCP Interception]

    subgraph NSIE[Hybrid Threat Engine]
        Judge[Probabilistic Guardrail<br/> (currently only) LLM-as-Judge<br/>Risk Score 0.0-1.0]
        Policy[Deterministic Rules<br/>YAML Policy Engine<br/>Identity, Policy Rules]
        Taint[Taint Analysis<br/>Source Tracking<br/>Planned]
    end

    DKCA[Dual-Key Credential Authority<br/>JWT Warrant Issuer]
    Prod[Production Backend<br/>Real Data<br/>KEY_PRIME ✓]
    Shadow[Shadow Backend<br/>Fake Data<br/>KEY_SHADOW ✓]
    IFL[Immutable Forensic Ledger<br/>Attack Intelligence<br/>Planned]

    Agent -->|tools/call JSON-RPC| IPG
    IPG -->|tool + args + context| Judge
    Judge -->|risk_score + reason| Policy
    IPG -->|context metadata| Policy
    Policy -->|route: production/shadow| DKCA
    DKCA -->|Prime Warrant| Prod
    DKCA -->|Shadow Warrant| Shadow
    Prod -->|200 OK Response| Agent
    Shadow -->|200 OK Response| Agent
    Shadow -.->|Log Attack Chain| IFL
    Prod -.->|Log Access| IFL

    style Agent fill:#e1f5ff
    style IPG fill:#fff3cd
    style Judge fill:#f8d7da
    style Policy fill:#d4edda
    style Taint fill:#f0f0f0
    style DKCA fill:#d1ecf1
    style Prod fill:#d4edda
    style Shadow fill:#f8d7da
    style IFL fill:#e2e3e5
```

### Core Modules (Implemented)

- **`src/ipg/`** – Intelligent Protocol Gateway

  - MCP JSON-RPC 2.0 interception (stdio transport)
  - Context extraction and warrant injection
  - Asynchronous proxy with <15ms overhead (target)

- **`src/nsie/`** – Hybrid Threat Analysis Engine

  - **Probabilistic Guardrail**: LLM-as-a-Judge (OpenRouter/OpenAI API)
    - Configurable prompt templates per scenario
    - Returns risk_score (0.0-1.0), reason, violation_tags
    - Mock fallback for offline testing
  - **Deterministic Policy**: YAML rule engine
    - Identity-based routing (user_id, user_role)
    - Context matching (source, ticket, device, schedule)
    - Field operators: eq, regex, contains, gt/lt, in/not_in
    - Logical combinators: all, any, not
  - **Fusion**: Probabilistic scores inform deterministic rule evaluation

- **`src/dkca/`** – Dual-Key Credential Authority

  - Separate RSA-4096 key pairs (prime + shadow)
  - JWT warrant issuance based on routing decision
  - Cryptographic isolation between environments

- **`src/vee/`** – Virtual Execution Environment

  - Dual SQLite databases (production vs shadow)
  - Filesystem isolation (data/real vs data/shadow)
  - Synthetic data generation (Faker-based)
  - Schema cloning and seed automation

- **`src/sdk/`** – Developer SDK

  - Tool decoration API (`@app.tool`, `@app.shadow`)
  - LangChain integration
  - Context resolver for metadata injection

- **`src/config/`** – Configuration System
  - Layered YAML (base + scenario overlays)
  - Hot-reload capability
  - Environment variable overrides

### Roadmap Modules (Not Yet Implemented)

- **Temporal State Engine** (Redis-based velocity/crescendo detection)
- **Taint Propagation** (Data flow tracking across tool calls)
- **Immutable Forensic Ledger** (Kafka/Merkle tree logging)
- **Activation-Based Probes** (Linear classifiers on LLM hidden states)
- **Container Isolation** (Docker/gVisor sandboxing)

See [implementation_status.md](docs/implementation_status.md) for detailed feature matrix.

## Scenarios

CHIMERA ships with example scenarios under `scenarios/`:

- **`aetheria/`** – Healthcare prompt injection demo (gene therapy research)
- **`test_dummy/`** – Minimal scenario for framework testing

Create your own:

```powershell
python manage.py scaffold-scenario finance_banking
```

## Development

### Running Tests

```powershell
# Core framework tests
python tests/core/test_config.py

# Scenario-specific demos
$env:CHIMERA_SCENARIO="aetheria"
python tests/scenarios/aetheria/medical_demo.py
```

### Project Structure

```
chimera-hachathon/
├── src/                    # Core framework (scenario-agnostic)
│   ├── ipg/               # Protocol gateway
│   ├── dkca/              # Dual-key authority
│   ├── nsie/              # Neural-symbolic engine
│   ├── vee/               # Virtual execution environment
│   └── sdk/               # Developer SDK
├── scenarios/             # Domain-specific scenarios
│   ├── aetheria/          # Healthcare demo
│   │   ├── config/        # Policy rules
│   │   ├── data/          # Real/shadow assets
│   │   ├── docs/          # Scenario documentation
│   │   └── seeder.py      # Data generator
│   └── registry.yaml      # Scenario index
├── config/                # Base configuration
│   ├── base.yaml          # Framework defaults
│   └── scenarios/         # Scenario overlays
├── scripts/               # Utilities
│   └── seeders/           # Data seeding framework
└── tests/                 # Test suites
    ├── core/              # Framework tests
    └── scenarios/         # Scenario demos
```

## Configuration

### Environment Variables

- `CHIMERA_SCENARIO` – Active scenario name (required)
- `OPENROUTER_API_KEY` – API key for LLM judge
- `OPENROUTER_MODEL` – Model for guardrail inference
- `CHIMERA_SERVER_MODE` – Backend mode (`stdio` or `http`)

### Policy Configuration

Edit `scenarios/<name>/config/policy.yaml`:

```yaml
defaults:
  risk_threshold: 0.8
  fail_mode: shadow

rules:
  - id: block-cross-tenant
    description: Prevent unauthorized data access
    tools: ["get_patient_record"]
    match:
      all:
        - field: args.patient_id
          operator: neq
          value_from_context: user_id
    action: shadow
```

## Documentation

### Getting Started

- **[Quick Start](docs/quickstart.md)** – 5-minute setup guide
- **[Scenario Authoring](scenarios/README.md)** – Creating new scenarios
- **[Aetheria Demo](scenarios/aetheria/README.md)** – Healthcare scenario walkthrough

### Technical Documentation

- **[Technical Docs](docs/technical_docs.md)** – Complete architecture and implementation overview
- **[Current Capabilities](docs/current_capabilities.md)** – What's implemented in the hackathon MVP
- **[Implementation Status](docs/implementation_status.md)** – Feature matrix and roadmap
- **[Architecture (Full Vision)](docs/architecture.md)** – Complete technical specification (Phase 1-7)
- **[Research Agenda](docs/research_agenda.md)** – Open problems and future directions
- **[Status](docs/status.md)** – Current hackathon status and next steps

### Key Research Directions

- **Honeypot Fidelity**: Timing normalization, behavioral consistency, undetectability
- **Zero False Positives**: Guarantees for benign users, appeal mechanisms
- **Zero-Knowledge Proofs**: Privacy-preserving tool authorization and identity
- **Model-Agnostic SDK**: Universal wrappers for LangChain, AutoGPT, CrewAI, etc.
- **Adversarial Co-Evolution**: RL-based red teaming, genetic algorithm policy optimization
- **Continual Learning**: Memory-augmented detection, federated threat intelligence

## License

See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add scenario-specific code under `scenarios/`
4. Keep `src/` framework-agnostic
5. Submit a pull request

## Troubleshooting

### Import Errors

If you see `ModuleNotFoundError: No module named 'src'`:

```powershell
# Reinstall in editable mode
pip install -e .
```

### Missing Scenario Error

```
RuntimeError: No scenario configured
```

Solution:

```powershell
$env:CHIMERA_SCENARIO="aetheria"
# or
python scripts/sync_shadow_db.py --scenario aetheria
```

### Database Not Found

```powershell
# Initialize databases
python scripts/sync_shadow_db.py --scenario aetheria
```

## Citation

If you use CHIMERA in research, please cite (hahahaha, i hope we can get a paper out of this):

```bibtex
@software{chimera2025,
  title={CHIMERA: Cryptographic Honeypot \& Intent-Mediated Enforcement Response Architecture},
  author={CHIMERA Architecture Team},
  year={2025},
  url={https://github.com/your-org/chimera}
}
```
