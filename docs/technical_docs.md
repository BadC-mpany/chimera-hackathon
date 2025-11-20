# CHIMERA Technical Documentation

## Overview

CHIMERA is a dual-reality security framework that lets agents invoke tools while separating **production (KEY_PRIME)** data from **shadow (KEY_SHADOW)** deception. Tool calls are intercepted by the Intelligent Protocol Gateway (`src/ipg/`), enriched with context, evaluated by the hybrid threat pipeline, and finally routed through the Dual-Key Credential Authority (`src/dkca/`) to the appropriate backend (`src/vee/`) with the appropriate warrant.

## Core Modules

- **`src/ipg/` – Intelligent Protocol Gateway**

  - Reads JSON-RPC 2.0 traffic from agents (stdin/stdout for MCP).
  - Extracts tool metadata, user context, session ID, and arguments.
  - Invokes the Probabilistic Judge (`src/nsie/judge.py`), the Policy Engine (`src/ipg/policy.py`), and issues warrants.
  - Supports runtime sanitization (taint tracking hooks) and asynchronous request handling.

- **`src/nsie/` – Hybrid Threat Engine**

  - **Probabilistic Guardrail** (`judge.py`): Builds single-shot prompts that include tool name/args plus summarized context (roles, source, session state) for the LLM. Returns `risk_score`, `reason`, and `violation_tags` to guide deterministic rules.
  - **Symbolic Policy**: YAML-driven rules that match fields (`args.*`, `context.*`) with logical operators and priorities. Manual overrides and audit hooks live here.
  - **Fusion Logic**: Encapsulated in `src/ipg/interceptor.py`, merges LLM risk with policy evaluation before warrant issuance.

- **`src/dkca/` – Dual-Key Credential Authority**

  - Generates RSA-4096 prime/shadow key pairs via `src.dkca.keygen`.
  - Issues JWT warrants with embedded claims (tool, context, route).
  - Verifies warrant authenticity before backend access.

- **`src/vee/` – Virtual Execution Environment**

  - Houses dual SQLite databases (`data/prod.db`, `data/shadow.db`) seeded by `scripts/sync_shadow_db.py`.
  - Provides filesystem isolation in `data/real/` vs `data/shadow/`.
  - Implements tool handlers (e.g., `read_file`, `get_patient_record`) and enforces cryptographic routing.

- **`src/sdk/` – Developer SDK**

  - Decorators (`@app.tool`, `@app.shadow`) register tool implementations.
  - `Chimera` class creates LangChain-compatible `StructuredTool`s that call `chimera_server.py` (MCP backend).
  - Accepts `context_resolver` to feed metadata to the IPG (user role, source, ticket, session).

- **`src/config/` – Configuration System**
  - Base settings in `config/base.yaml`; scenario overlays under `config/scenarios/<name>.yaml`.
  - Configures model prompts, policy defaults, thresholds, manual overrides, and joke doc references.

## Runtime Workflow

1. **Agent Sends Tool Call**: `chimera_agent.py` (or any LangChain agent) discovers tools via `tools/list` and sends `tools/call` with context metadata.
2. **IPG Interception**: Interceptor extracts context, calls the Probabilistic Judge, and consults the Policy Engine.
3. **Judge + Policy Fusion**: Single-shot prompt includes summarized context to keep the LLM aware of who is asking and why (ticket, role, source). Policy rules may override based on explicit allow/deny logic.
4. **DKCA Issues Warrant**: Based on route decision, the DKCA signs a JWT for either production or shadow.
5. **Backend Execution**: `src/vee/backend.py` executes the tool using the appropriate data store and returns structured text responses.
6. **Audit Logging**: All decisions, especially shadow routings, append to logs (future Immutable Forensic Ledger).

## Scenario Assets

- **`scenarios/`** directory contains domain-specific data, policies, docs, and seeders.
- **`tests/scenarios/`** run realistic demos (e.g., `aetheria/medical_demo.py`) covering trusted vs adversarial actors.

## Scripts & Entry Points

- **`manage.py`** – CLI for listing, scaffolding, and documenting scenarios; wires into the config loader to resolve the active `CHIMERA_SCENARIO`.
- **`chimera_agent.py`** – Generic LangChain client; discovers MCP tools, injects resolved context, streams interactive conversations, and supports single-query diagnostics.
- **`chimera_server.py`** – Dual-mode (stdio + FastAPI) backend that proxies MCP calls to `src/vee/backend.py`, enforces warrants, and routes to production/shadow datastores.
- **`src/main.py`** – Entry point used by `chimera_server.py` and CLI utilities to bootstrap NSIE, DKCA, and backend services.
- **`scripts/sync_shadow_db.py`** – Orchestrates schema cloning and scenario seeders (possibly scenario-specific overrides) to keep `data/prod.db` and `data/shadow.db` aligned.
- **`scripts/seeders/base.py`** – Abstract seeder interface consumed by `sync_shadow_db.py`; scenario seeder implementations live under `scenarios/<name>/seeder.py`.
- **`tests/core/test_config.py`** – Regression coverage for configuration merging, scenario discovery, and manual override handling.
- **`tests/scenarios/aetheria/medical_demo.py`** – Multi-actor demo that validates trusted vs adversarial flows and records routing decisions.
- **`tests/scenarios/aetheria/langchain_agent.py`** – LangGraph-based MCP agent that exercises tool discovery, context injection, and guardrail responses.
- **`tests/scenarios/aetheria/test_interception.py`** – Unit tests for interception logic, risk scoring, and `read_file` shadow switching.
- **`QUICKSTART.md`** – Step-by-step procedural guide covering venv setup, key generation, scenario selection, data initialization, API key wiring, and agent execution.

## Testing

- Unit tests under `tests/core/` (configuration, interceptor behavior).
- Scenario demos under `tests/scenarios/` pick up the active `CHIMERA_SCENARIO`.
- Run `pip install -e .` before executing tests to avoid `ModuleNotFoundError`.
