# CHIMERA Tests

This directory contains tests and scenario-specific demonstrations.

## Structure

```
tests/
├── core/                    # Framework unit tests
│   └── test_config.py      # Config merge and validation
└── scenarios/              # Scenario-specific demos
    └── aetheria/           # Healthcare scenario demos
        ├── medical_demo.py        # Multi-scenario demo (Dr. Chen, HR attack, etc.)
        ├── langchain_agent.py     # Legacy LangChain demo
        └── test_interception.py   # Low-level IPG test
```

## Running Tests

### Core Framework Tests

```powershell
# Test config system
python tests/core/test_config.py
```

### Scenario Demos

```powershell
# Set active scenario
$env:CHIMERA_SCENARIO="aetheria"

# Run Aetheria multi-actor demo
python tests/scenarios/aetheria/medical_demo.py

# Run legacy LangChain demo
python tests/scenarios/aetheria/langchain_agent.py

# Run low-level interception test
python tests/scenarios/aetheria/test_interception.py
```

## Recommended: Use the Generic Agent

Instead of scenario-specific test scripts, use the **generic agent runner** at the project root:

```powershell
# Interactive mode (best for exploration)
$env:CHIMERA_SCENARIO="aetheria"
python chimera_agent.py

# Example interactions:
You: Get patient record 100
Agent: Here is the patient record for ID 100: Name: Karen Hopkins...

You: Read /data/private/_CONF_chimera_formula.json  
Agent: Project: Chimera-SHADOW, Sequence ID: FAKE-643... (Shadow data!)

# Single query mode
python chimera_agent.py --query "Get patient record 100" --verbose

# Works with any scenario
$env:CHIMERA_SCENARIO="finance_banking"
python chimera_agent.py
```

The generic agent automatically discovers available tools from the active scenario's backend and routes through the IPG security layer.

## Test Types

### Core Tests (`tests/core/`)
- **Purpose**: Validate framework functionality independent of scenarios
- **Data**: Use synthetic/minimal test fixtures
- **Run Frequency**: Every commit (CI/CD)

### Scenario Demos (`tests/scenarios/`)
- **Purpose**: Demonstrate specific attack/defense scenarios
- **Data**: Use scenario-specific assets from `scenarios/<name>/`
- **Run Frequency**: Manual, before releases

## Adding New Tests

### For Framework Features
Add to `tests/core/` using the `test_dummy` scenario:

```python
import os
from src.config import load_settings

def test_new_feature():
    os.environ["CHIMERA_SCENARIO"] = "test_dummy"
    # Test framework behavior
    assert ...
```

### For New Scenarios
Add to `tests/scenarios/<name>/` with scenario-specific logic:

```python
import os
from src.sdk.chimera import Chimera

os.environ["CHIMERA_SCENARIO"] = "my_scenario"
app = Chimera()

@app.tool(description="...")
def my_tool(arg: str):
    # Scenario-specific tool
    pass
```

## Legacy Files

- `tests/sdk_demo.py` – Old SDK demo (moved to root as `chimera_agent.py`)
- Scenario-specific scripts in `tests/scenarios/` are for demonstration, not automated testing

For automated testing, prefer `pytest` with fixtures once the framework matures.

