<!-- 22c3b7e5-7359-441c-87f0-7597ebdb6aec 8312930c-38a2-4cbd-b666-51e4ca42b121 -->
# Stateful Risk Accumulation Implementation

## Problem Statement

Currently, each tool call is evaluated independently. The `SessionState.risk_accumulator` field exists but is never updated or used. This prevents detection of multi-step attacks where individual tool calls may be low-risk but the cumulative pattern indicates a threat.

## Implementation Plan

### 1. Enhance SessionMemory with Risk Accumulation Methods

**File:** `src/ipg/memory.py`

- Add method `accumulate_risk(session_id: str, risk_score: float, timestamp: float = None)` that:
  - Retrieves or creates session state
  - Updates `risk_accumulator` using configured accumulation strategy (additive by default)
  - Stores individual risk scores in history for audit trail
  - Applies time-based decay if configured

- Add method `get_accumulated_risk(session_id: str) -> float` that:
  - Returns current accumulated risk for the session
  - Applies any decay calculations if needed

- Add method `get_risk_history(session_id: str) -> List[Dict]` that:
  - Returns list of risk assessments with timestamps for pattern analysis

- Update `SessionState` dataclass to include:
  - `risk_history: List[Dict[str, Any]]` to track individual risk scores with metadata
  - Optional: `last_risk_update: float` for decay calculations

### 2. Integrate Risk Accumulation into MessageInterceptor

**File:** `src/ipg/interceptor.py`

- In `_inspect_tool_call`, after receiving risk assessment from judge:
  - Call `self.memory.accumulate_risk(session_id, risk_score)` to update session state
  - Retrieve accumulated risk: `accumulated_risk = self.memory.get_accumulated_risk(session_id)`
  - Inject `accumulated_risk` into context dictionary
  - Pass accumulated risk to PolicyEngine for evaluation

- Update `_extract_context` to include `accumulated_risk` in returned context dict

### 3. Add Accumulated Risk to Policy Evaluation

**File:** `src/ipg/policy.py`

- Update `PolicyEngine.evaluate` method signature to accept `accumulated_risk: float` parameter
- Add accumulated risk to the `data` dictionary passed to rule evaluation
- Create new helper method `_evaluate_accumulated_risk_policies(accumulated_risk: float)` that:
  - Checks if accumulated risk exceeds configured threshold
  - Returns routing decision if threshold exceeded
  - This phase should run after `security_policies` but before `risk_based_policies` in evaluation order

- Update `_evaluate_risk_based` to optionally consider accumulated risk as a factor

### 4. Add Configuration for Risk Accumulation

**File:** `config/base.yaml`

- Add new `risk_accumulation` section under `policy`:
  ```yaml
  risk_accumulation:
    enabled: true
    method: "additive"  # or "ema", "weighted_decay"
    decay_rate: 0.0  # 0.0 = no decay, 0.1 = 10% per minute
    threshold: 2.0  # Accumulated risk threshold for shadow routing
    window_minutes: 60  # Time window for risk accumulation
  ```


**File:** `scenarios/aetheria/config/policy.yaml`

- Add `accumulated_risk_policies` section (optional, can use base.yaml defaults):
  ```yaml
  accumulated_risk_policies:
    threshold: 2.5
    action: shadow
    reason: "Cumulative risk across session exceeds threshold"
  ```


### 5. Update PolicyEngine to Support Accumulated Risk Phase

**File:** `src/ipg/policy.py`

- Add `accumulated_risk_policies` to default `evaluation_order` (after `security_policies`, before `risk_based_policies`)
- Parse `accumulated_risk_policies` config in `__init__`
- Implement `_evaluate_accumulated_risk_policies` method that:
  - Checks if accumulated risk >= threshold
  - Returns routing decision with appropriate reason

### 6. Log Accumulated Risk to IFL

**File:** `src/ipg/interceptor.py`

- In `_inspect_tool_call`, when logging to IFL:
  - Include `accumulated_risk` in the `trigger` dictionary
  - Include `risk_history_length` (number of tool calls in session) for context

### 7. Update ProbabilisticJudge Context (Optional Enhancement)

**File:** `src/nsie/judge.py`

- Modify `evaluate_risk` to optionally receive accumulated risk in context
- Update prompt template to inform LLM about session risk history
- This allows the judge to consider patterns when individual calls are ambiguous

## Implementation Details

### Risk Accumulation Formula (Additive Method)

```python
accumulated_risk = previous_accumulated_risk + current_risk_score
```

### Risk Accumulation with Decay (if enabled)

```python
time_elapsed = current_time - last_risk_update
decay_factor = exp(-decay_rate * time_elapsed / 60)  # per minute
accumulated_risk = previous_accumulated_risk * decay_factor + current_risk_score
```

### Evaluation Order

1. Directives (manual overrides)
2. Trusted workflows
3. Security policies (taint, suspicious keywords)
4. **Accumulated risk policies** (NEW)
5. Risk-based policies (current single-call risk)

## Testing Considerations

- Test that risk accumulates across multiple tool calls
- Test that accumulated risk triggers shadow routing when threshold exceeded
- Test that decay reduces accumulated risk over time (if enabled)
- Test that session isolation works (risk doesn't leak between sessions)
- Test that high-priority rules (directives, trusted workflows) still override accumulated risk

## Files to Modify

1. `src/ipg/memory.py` - Add accumulation methods
2. `src/ipg/interceptor.py` - Integrate accumulation into inspection flow
3. `src/ipg/policy.py` - Add accumulated risk evaluation phase
4. `config/base.yaml` - Add risk accumulation configuration
5. `scenarios/aetheria/config/policy.yaml` - Add scenario-specific thresholds (optional)

### To-dos

- [ ] Finalize policy evaluate logic and test dr chen file read
- [ ] Add agent options for manual HTTP server + minimal output
- [ ] Document new workflow (manual server, minimal output)
- [x] Add priority and override_risk fields to Rule dataclass in src/ipg/policy.py
- [x] Update RiskAssessment model in src/nsie/judge.py to include confidence field
- [x] Update LLM prompt template to request confidence scores
- [x] Update PolicyEngine.evaluate() to sort rules by priority and check override_risk
- [x] Add priority and override_risk to all rules in scenarios/aetheria/config/policy.yaml
- [x] Update interceptor to pass confidence to policy engine
- [ ] Restructure `scenarios/aetheria/config/policy.yaml` to the new Policy Manifest format.
- [ ] Rewrite `PolicyEngine.__init__` in `src/ipg/policy.py` to parse the new manifest structure.
- [ ] Rewrite `PolicyEngine.evaluate` in `src/ipg/policy.py` to execute the policy phases defined in `evaluation_order`.
- [ ] Add helper methods for each evaluation phase (`directives`, `rules`, `risk_based`) to `PolicyEngine`.
- [ ] Remove all old rule logic, priority numbers, and `override_risk` fields from the codebase and YAML.
- [x] Restructure `scenarios/aetheria/config/policy.yaml` to the new Policy Manifest format.
- [x] Rewrite `PolicyEngine.__init__` in `src/ipg/policy.py` to parse the new manifest structure.
- [x] Rewrite `PolicyEngine.evaluate` in `src/ipg/policy.py` to execute the policy phases defined in `evaluation_order`.
- [x] Add helper methods for each evaluation phase (`directives`, `rules`, `risk_based`) to `PolicyEngine`.
- [x] Remove all old rule logic, priority numbers, and `override_risk` fields from the codebase and YAML.
- [x] Add priority and override_risk fields to Rule dataclass in src/ipg/policy.py
- [x] Update RiskAssessment model in src/nsie/judge.py to include confidence field
- [x] Update LLM prompt template to request confidence scores
- [x] Update PolicyEngine.evaluate() to sort rules by priority and check override_risk
- [x] Add priority and override_risk to all rules in scenarios/aetheria/config/policy.yaml
- [x] Update interceptor to pass confidence to policy engine
- [ ] Refactor configuration loading to use Dependency Injection.
- [ ] Consolidate tool definitions by moving the `category` field to `config/base.yaml`.
- [ ] Refactor `chimera_agent.py` from a script with global state to an asynchronous, class-based structure.
- [ ] Remove the `risk_score` from the JWT payload in `src/dkca/authority.py`.
- [ ] Create a unit test foundation and add initial tests for the `PolicyEngine`.
- [x] Refactor configuration loading to use Dependency Injection.
- [x] Consolidate tool definitions by moving the `category` field to `config/base.yaml`.
- [ ] Refactor `chimera_agent.py` from a script with global state to an asynchronous, class-based structure.