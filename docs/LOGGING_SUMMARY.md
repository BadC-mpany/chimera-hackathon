# CHIMERA Triggering & Logging System - Summary

## Completed Work

I've successfully analyzed and enhanced the CHIMERA logging system. Here's what was accomplished:

### 1. **Understanding the Triggering Mechanism**

The system uses a multi-layered approach to detect threats and trigger shadow routing:

#### Trigger Mechanisms (in evaluation order):

1. **Mock LLM Judge Rules** (`config/base.yaml` - `nsie.mock_rules`)
   - Pattern-based rules that evaluate tool calls
   - Example: Cross-tenant access, accessing files with "secret" in name
   
2. **Suspicious Keyword Detection** (`src/ipg/policy.py`)
   - Scans tool arguments for: `password`, `secret`, `credit card`, `ssn`, `private_key`, `formula`
   
3. **Taint Tracking** (`src/ipg/taint.py`)
   - RED patterns (untrusted): `resume`, `upload`, `external`, `/shared/`, `attachment`
   - GREEN patterns (trusted): `/private/`, `/real/`, `_conf_`, `system`, `internal`
   - Once a session reads a RED file, it's permanently tainted
   
4. **Policy Rules** (`scenarios/aetheria/config/policy.yaml`)
   - **Directives**: Manual user/role overrides
   - **Trusted Workflows**: Allow lists (e.g., dr_chen always gets production)
   - **Security Policies**: Deterministic threat detection
     - Tainted session + sensitive tool = shadow
     - Suspicious keywords = shadow
     - External users = shadow
     - Cross-tenant access = shadow
   - **Accumulated Risk Threshold**: Total session risk > 1.5 = shadow
   - **Single Event Risk**: Single tool call risk > 0.8 (with confidence > 0.7) = shadow

### 2. **Understanding Risk Accumulation**

Configured in `config/base.yaml` under `policy.risk_accumulation`:

- **Enabled**: `true`
- **Method**: `windowed_sum` or `additive_decay`
- **Threshold**: `2.0` (configurable per scenario)
- **Window**: `60 minutes`

#### Windowed Sum Method:
- Risk events within the time window are summed
- Old events automatically drop out of the window
- Current implementation in `src/ipg/memory.py`

#### Additive Decay Method:
- Risk decays exponentially: `risk *= e^(-decay_rate * time)`
- New risk is added to decayed total
- Decay rate: `0.1` (configurable)

### 3. **Enhanced Logging System**

Created a comprehensive logging system with:

#### New Files:
- `src/utils/logging_config.py` - Centralized logging configuration
- `src/utils/__init__.py` - Utils package initialization
- `docs/LOGGING.md` - Complete logging documentation

#### Features:
- **Timestamped log files**: `logs/chimera_YYYYMMDD_HHMMSS.log`
- **Dual output**: 
  - Console: Colored, concise, INFO level
  - File: Detailed with line numbers, always DEBUG level
- **Debug mode control**: `agent.debug` in `config/base.yaml`

#### What Gets Logged (when debug=true):

1. **Tool Call Interception** 🔍
   - Tool name and arguments
   - Initial context (user_id, role, session_id, taint status)

2. **Taint Status Changes** 🔴
   - When a session becomes tainted
   - Source file that caused tainting

3. **NSIE Judge Assessment** 🧠
   - Step-by-step mock rule evaluation
   - Which rule matched (if any)
   - Risk score, confidence, reason, violation tags

4. **Risk Accumulation Details** 📊
   - Previous accumulated risk
   - New event risk
   - Current accumulated risk
   - Risk history length
   - Recent risk events with timestamps

5. **Policy Engine Evaluation** ⚖️
   - Each phase evaluation (directives, trusted_workflows, security_policies, etc.)
   - Which rules matched/didn't match
   - Final routing decision with rule ID

6. **Shadow Routing Triggers** ⚠️
   - Clear warning when shadow is activated
   - Reason and triggering rule

7. **Warrant Issuance** 🔐
   - Warrant type (production/shadow)
   - Accumulated risk
   - Warrant preview (first 50 chars of JWT)

8. **Forensic Ledger Entry** 📜
   - Event ID for tracking

9. **Completion Status** ✅
   - Final routing destination

#### Enhanced Modules:
- `src/ipg/interceptor.py` - Detailed step-by-step logging
- `src/ipg/policy.py` - Phase-by-phase evaluation logging
- `src/nsie/judge.py` - Mock rule evaluation logging
- `chimera_agent.py` - Session startup logging

### 4. **How to Use**

#### Enable Debug Mode:
```yaml
# config/base.yaml
agent:
  debug: true
```

#### Run Agent:
```powershell
$env:CHIMERA_SCENARIO="aetheria"
$env:CHIMERA_USER_ID="attacker"
$env:CHIMERA_USER_ROLE="external"
python chimera_agent.py --query "read the secret formula"
```

#### View Logs:
```powershell
# View most recent log
Get-ChildItem logs | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content

# Search for shadow triggers
Select-String -Path logs\*.log -Pattern "SHADOW ROUTING TRIGGERED"

# View risk accumulation
Select-String -Path logs\*.log -Pattern "Risk Accumulation Details" -Context 0,10
```

## Key Insights

### Triggering Flow:
1. Tool call arrives at `interceptor.py`
2. Context extracted (user_id, role, session_id)
3. Taint manager checks if file access taints session
4. NSIE Judge evaluates with mock rules → risk_score
5. Risk accumulator adds to session total
6. Policy engine evaluates in phase order:
   - Directives (manual overrides)
   - Trusted workflows (allow lists)
   - Security policies (threat detection)
   - Accumulated risk (threshold check)
   - Risk-based (single event threshold)
7. First matching rule determines routing
8. DKCA issues JWT warrant (production or shadow key)
9. Warrant injected into tool call
10. IFL logs the decision
11. Backend verifies warrant and routes accordingly

### Multiple Trigger Types:
- **Deterministic**: Policy rules, taint tracking, keyword detection
- **Probabilistic**: LLM judge assessment (currently mocked)
- **Stateful**: Accumulated risk over time
- **Stateless**: Single event risk threshold

### Priority Order:
1. Manual directives (highest)
2. Trusted workflows (allow lists)
3. Security policies (explicit threats)
4. Accumulated risk
5. Risk-based policies
6. Default action (lowest)

## Next Steps (Recommendations)

1. **Real LLM Judge**: Replace mock rules with actual LLM-as-a-judge
2. **Llama Guard Integration**: Implement dedicated safety classifier
3. **Temporal Logic**: Add Redis for true stateful tracking across processes
4. **Activation Probes**: Implement hidden state analysis for better detection
5. **Log Analysis Tools**: Build scripts to analyze logs and generate reports
6. **Alerting**: Add real-time alerts for shadow triggers
7. **Metrics Dashboard**: Visualize risk scores, trigger rates, etc.

## Files Modified/Created

### Created:
- `src/utils/logging_config.py` - Logging infrastructure
- `src/utils/__init__.py` - Package init
- `docs/LOGGING.md` - Complete logging documentation
- `logs/` directory - Log file storage
- This summary document

### Modified:
- `src/ipg/interceptor.py` - Enhanced with detailed logging
- `src/ipg/policy.py` - Phase-by-phase logging
- `src/nsie/judge.py` - Mock rule evaluation logging
- `chimera_agent.py` - Logging initialization
- `config/base.yaml` - Set debug=true

## Documentation

See `docs/LOGGING.md` for complete documentation including:
- Configuration guide
- What gets logged at each step
- All trigger mechanisms explained
- Risk accumulation methods
- Example log sessions
- Troubleshooting tips
