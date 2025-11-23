# CHIMERA Trigger Flow Visualization

## 🎯 Quick Answer: What Triggers Shadow Routing?

**SHORT ANSWER**: Only the **Policy Engine** can trigger shadow routing. Everything else (LLM judge, taint tracking, keywords) just provides INPUT to help the Policy Engine make its decision.

```
┌─────────────────────────────────────────────────────────────┐
│  INPUTS (Information Providers)                             │
├─────────────────────────────────────────────────────────────┤
│  • NSIE Judge          → event_risk_score (0.0-1.0)         │
│  • Taint Manager       → is_tainted (true/false)            │
│  • Keyword Scanner     → is_suspicious_query (true/false)   │
│  • Risk Accumulator    → accumulated_risk (sum over time)   │
│  • User Context        → user_id, user_role                 │
└────────────────────────┬────────────────────────────────────┘
                         │ All inputs passed to...
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  DECISION MAKER (The Only Thing That Triggers)              │
├─────────────────────────────────────────────────────────────┤
│  POLICY ENGINE (src/ipg/policy.py)                          │
│                                                              │
│  Evaluates rules in priority order:                         │
│  1. Directives (manual overrides) ← YOU CAN SET THIS!       │
│  2. Trusted workflows (allow lists)                         │
│  3. Security policies (checks inputs above)                 │
│  4. Accumulated risk threshold                              │
│  5. Event risk threshold                                    │
│  6. Default action                                           │
│                                                              │
│  First matching rule → production OR shadow                 │
└─────────────────────────────────────────────────────────────┘
```

## Key Concepts Clarified

### Q: Does the LLM judge directly trigger shadow routing?
**A: NO.** The LLM judge (NSIE) only provides a **risk score** (0.0-1.0). This score:
1. Goes into the **stateful risk accumulator** (adds to session total)
2. Is passed to the **Policy Engine** which makes the final decision
3. The Policy Engine checks if risk score meets threshold rules

**Flow**: `LLM Judge → Risk Score → Accumulator → Policy Engine → Decision`

### Q: How does tainting relate to triggering?
**A: Tainting is a LABEL, not a trigger.** When a session reads an untrusted file (RED pattern like "resume"), it gets labeled as "tainted". This label alone does NOT trigger shadow routing. Instead:
- The `is_tainted` flag is added to the context
- Policy rules can check this flag (e.g., "if tainted AND sensitive tool → shadow")
- Without a matching policy rule, tainted sessions still go to production

**Example**: Reading `/shared/resume.txt` → Session becomes tainted → But only triggers shadow if you then call a "sensitive" tool (like `get_patient_record`)

### Q: What does "windowed sum" mean?
**A: Time-based risk tracking.** The system keeps a sliding time window (default 60 minutes) of all risk events:
- Each tool call's risk score is stored with a timestamp
- Every new call: old events (>60 min ago) are dropped
- Accumulated risk = SUM of all risk scores still in the window
- If this sum exceeds threshold (1.5), shadow routing triggers

**Example**:
```
Time 10:00 - read_file → risk=0.3 → accumulated=0.3
Time 10:15 - query_db → risk=0.4 → accumulated=0.7 (0.3+0.4)
Time 10:30 - transfer → risk=0.6 → accumulated=1.3 (0.3+0.4+0.6)
Time 11:05 - send_email → risk=0.5 → accumulated=1.5 (0.4+0.6+0.5)
                          ^ 10:00 event dropped (>60min old)
                          TRIGGER! (1.5 ≥ 1.5 threshold)
```

### Q: What are Directives (manual overrides)?
**A: Pre-configured routing rules in YAML.** You can manually specify that certain users or roles ALWAYS go to production or shadow, bypassing all other checks. Edit `scenarios/aetheria/config/policy.yaml`:

```yaml
directives:
  users:
    admin_user: 
      action: production
      reason: "Admin always gets production access"
    test_attacker:
      action: shadow
      reason: "Test user always goes to honeypot"
  roles:
    auditor:
      action: shadow
      reason: "Auditors are sandboxed by policy"
```

This is the HIGHEST priority - it overrides everything (risk scores, taint, keywords, etc.)

**Use case**: Emergency access, testing, compliance requirements

---

## Complete Request Flow with Logging Points

```
┌─────────────────────────────────────────────────────────────────┐
│  1. TOOL CALL ARRIVES                                           │
│  Agent: "read /data/private/_CONF_chimera_formula.json"        │
│                                                                 │
│  LOG: 🔍 TOOL CALL INTERCEPTION: read_file                     │
│  LOG: Tool Arguments: {"filename": "..."}                       │
│  LOG: Initial Context: {user_id, role, session_id, tainted}    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. TAINT CHECK (src/ipg/taint.py)                             │
│  Pattern matching on filename (ONLY for read_file calls)       │
│                                                                 │
│  RED patterns: ["resume", "upload", "shared/", ...]            │
│  GREEN patterns: ["/private/", "_conf_", ...]                  │
│                                                                 │
│  Decision: GREEN (trusted) - contains "_conf_"                  │
│  Result: Session stays UNTAINTED                                │
│                                                                 │
│  ⚠️  IMPORTANT: Taint is just a LABEL, not a trigger!          │
│     The label is stored in context.is_tainted                   │
│     Policy rules can use this label to make decisions           │
│                                                                 │
│  LOG: (No taint change)                                         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. NSIE JUDGE EVALUATION (src/nsie/judge.py)                  │
│  Mock rules check (would be real LLM in production)            │
│                                                                 │
│  Rule 0: patient_id != 99? → N/A (not a patient call)         │
│  Rule 1: filename contains "secret"? → NO                       │
│  Rule 2: filename contains "formula"? → YES! ✓                 │
│                                                                 │
│  Result: event_risk_score = 0.95                                │
│          confidence = 1.0                                        │
│          reason = "Sensitive file access"                        │
│                                                                 │
│  ⚠️  IMPORTANT: This is just a SCORE, not a routing decision!  │
│     The judge does NOT trigger shadow routing directly          │
│     It only provides input for the Policy Engine                │
│                                                                 │
│  LOG: 🧠 Invoking NSIE Judge...                                │
│  LOG: Mock rule 2 matched                                       │
│  LOG: NSIE Assessment: Risk=0.95, Confidence=1.0               │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. SUSPICIOUS KEYWORD CHECK (src/ipg/policy.py)               │
│  Scan args for: ["password", "secret", "formula", ...]         │
│                                                                 │
│  Found: "formula" in filename                                   │
│                                                                 │
│  context.is_suspicious_query = TRUE                             │
│                                                                 │
│  LOG: [TRIGGER] Suspicious keyword 'formula' detected           │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. RISK ACCUMULATION (src/ipg/memory.py)                      │
│  Method: windowed_sum (60 min window)                          │
│                                                                 │
│  How it works:                                                  │
│  1. Store this event: {risk_score: 0.95, timestamp: now}      │
│  2. Drop events older than 60 minutes from history             │
│  3. Sum all remaining risk scores                               │
│                                                                 │
│  Previous accumulated: 0.0                                      │
│  New event risk: 0.95                                           │
│  Current accumulated: 0.95 (just this event in window)         │
│                                                                 │
│  Risk history: [{"score": 0.95, "time": 1700000000}]          │
│                                                                 │
│  This accumulated value (0.95) will be passed to Policy Engine │
│  If accumulated ≥ 1.5, a policy rule can trigger shadow        │
│                                                                 │
│  LOG: Session Risk: Event=0.95, Accumulated=0.95               │
│  LOG: Risk Accumulation Details: {...}                          │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. POLICY ENGINE (src/ipg/policy.py)                          │
│  ⚠️  THIS IS WHERE THE ACTUAL ROUTING DECISION HAPPENS!        │
│                                                                 │
│  The policy engine receives:                                    │
│  - event_risk_score (from judge): 0.95                         │
│  - accumulated_risk (from memory): 0.95                         │
│  - context.is_tainted: false                                    │
│  - context.is_suspicious_query: true                            │
│  - confidence: 1.0                                              │
│                                                                 │
│  It evaluates phases in order until ONE rule matches:           │
│  [directives → trusted_workflows → security_policies →         │
│   accumulated_risk → risk_based → default]                     │
│                                                                 │
│  LOG: ⚖️  Invoking Policy Engine...                            │
│  LOG: Policy evaluation starting for tool: read_file           │
│  LOG:   Risk=0.95, Confidence=1.0, Tainted=False, Susp=True   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Phase 1: DIRECTIVES (Manual Overrides - HIGHEST)       │   │
│  │                                                          │   │
│  │ These are pre-configured in policy.yaml:                │   │
│  │   directives.users.attacker: {...}                      │   │
│  │   directives.roles.external: {...}                      │   │
│  │                                                          │   │
│  │ Check user "attacker" in override list? → NO           │   │
│  │ Check role "external" in override list? → NO           │   │
│  │                                                          │   │
│  │ If matched: Would return action immediately             │   │
│  │             (production/shadow), skip all other checks  │   │
│  │                                                          │   │
│  │ LOG:   Evaluating phase: directives                     │   │
│  │ LOG:   ✗ Phase 'directives' - no match                 │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Phase 2: TRUSTED WORKFLOWS                              │   │
│  │ Rule: dr-chen-production                                │   │
│  │   Match: user_id="dr_chen" AND role="lead_researcher"  │   │
│  │   Current: user_id="attacker", role="external"         │   │
│  │   Result: NO MATCH                                      │   │
│  │ LOG:   Evaluating phase: trusted_workflows              │   │
│  │ LOG:   ✗ Phase 'trusted_workflows' - no match          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Phase 3: SECURITY POLICIES (Deterministic Threats)     │   │
│  │                                                          │   │
│  │ Rule 1: taint-lockdown                                  │   │
│  │   Condition: is_tainted=true AND tool_category=sensitive│  │
│  │   Current: is_tainted=false                             │   │
│  │   Result: NO MATCH                                      │   │
│  │   Note: Taint ALONE doesn't trigger. Only when          │   │
│  │         combined with sensitive tool usage              │   │
│  │                                                          │   │
│  │ Rule 2: suspicious-keyword-trigger ✓✓✓                 │   │
│  │   Condition: is_suspicious_query=true                   │   │
│  │   Current: is_suspicious_query=true                     │   │
│  │   Result: MATCH! → action=SHADOW                        │   │
│  │                                                          │   │
│  │   This is the FIRST matching rule, so evaluation STOPS │   │
│  │   The routing decision is now final: SHADOW             │   │
│  │                                                          │   │
│  │ LOG:   Evaluating phase: security_policies              │   │
│  │ LOG:     Rule 'suspicious-keyword-trigger' matched      │   │
│  │ LOG:   ✓ Phase 'security_policies' matched             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  NOTE: Phases 4-6 are SKIPPED because we already matched       │
│                                                                 │
│  Final Decision:                                                │
│    route = "shadow"                                             │
│    rule_id = "suspicious-keyword-trigger"                       │
│    reason = "Routes to shadow if suspicious keyword detected"  │
│                                                                 │
│  LOG: Policy decision: route=shadow rule=suspicious-keyword... │
│  LOG: ⚠️  SHADOW ROUTING TRIGGERED: ... (rule: ...)            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  7. WARRANT ISSUANCE (src/dkca/authority.py)                   │
│  Decision: SHADOW                                               │
│                                                                 │
│  Load private_shadow.pem                                        │
│  Create JWT payload: {session_id, risk_score=0.95, ...}       │
│  Sign with RSA-4096 shadow key                                 │
│  Result: JWT_SHADOW token                                       │
│                                                                 │
│  Inject into message: params.__chimera_warrant__ = JWT_SHADOW   │
│                                                                 │
│  LOG: 🔐 Issuing SHADOW warrant via DKCA...                    │
│  LOG: Issued Warrant: {type: shadow, risk: 0.95, preview}     │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  8. FORENSIC LEDGER (src/ifl/ledger.py)                        │
│  Log to: data/forensic_ledger.jsonl                            │
│                                                                 │
│  Entry: {                                                       │
│    event_id: "uuid-1234",                                       │
│    timestamp: 1700000000,                                       │
│    session_id: "abc123",                                        │
│    event_type: "TOOL_INTERCEPTION",                            │
│    trigger: {tool, args, risk_score: 0.95},                    │
│    action: {warrant_type: "shadow", reason},                   │
│    outcome: {routed_to: "shadow"},                             │
│    accumulated_risk: 0.95,                                      │
│    hash: "sha256..."                                            │
│  }                                                              │
│                                                                 │
│  LOG: 📜 Logged to IFL with event_id: uuid-1234                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  9. COMPLETION                                                  │
│  Modified message with JWT_SHADOW sent to backend              │
│                                                                 │
│  Backend verifies JWT with public_shadow.pem                    │
│  Routes to: data/shadow/_CONF_chimera_formula.json            │
│  Returns fake formula to agent                                  │
│                                                                 │
│  LOG: ✅ INTERCEPTION COMPLETE: Routing to SHADOW              │
└─────────────────────────────────────────────────────────────────┘
```

## Trigger Priority Matrix

| Priority | Mechanism                | Location                  | Type          | Decision Maker | Overrides |
|----------|--------------------------|---------------------------|---------------|----------------|-----------|
| 1        | Manual Directives        | policy.yaml:directives    | Deterministic | Policy Engine  | ALL       |
| 2        | Trusted Workflows        | policy.yaml:trusted_*     | Deterministic | Policy Engine  | 3-7       |
| 3        | Taint + Sensitive Tool   | policy.yaml:security_*    | Deterministic | Policy Engine  | 4-7       |
| 4        | Suspicious Keywords      | policy.yaml:security_*    | Deterministic | Policy Engine  | 5-7       |
| 5        | Accumulated Risk > 1.5   | policy.yaml:accumulated_* | Stateful      | Policy Engine  | 6-7       |
| 6        | Single Event Risk > 0.8  | policy.yaml:risk_based_*  | Probabilistic | Policy Engine  | 7         |
| 7        | Default Action           | policy.yaml:default_*     | Fallback      | Policy Engine  | None      |

**Critical Note**: ALL routing decisions are made by the Policy Engine. The NSIE Judge and Taint Manager only provide INPUT (scores and labels). They never directly trigger shadow routing.

## Example Trigger Combinations

### Scenario 1: Trusted User, Suspicious Query
```
User: dr_chen (lead_researcher)
Query: "read /data/private/_CONF_chimera_formula.json"

Flow:
1. Taint: GREEN (private path)
2. NSIE: risk=0.95 (contains "formula")
3. Keywords: TRUE (contains "formula")
4. Policy Phase 1: No directive override
5. Policy Phase 2: MATCH trusted_workflows ✓
   → Result: PRODUCTION (trusted user overrides risk)
```

### Scenario 2: Untrusted User, Suspicious Query
```
User: attacker (external)
Query: "read /data/private/_CONF_chimera_formula.json"

Flow:
1. Taint: GREEN (private path)
2. NSIE: risk=0.95 (contains "formula")
3. Keywords: TRUE (contains "formula")
4. Policy Phase 1: No directive
5. Policy Phase 2: No trusted workflow match
6. Policy Phase 3: MATCH suspicious-keyword-trigger ✓
   → Result: SHADOW
```

### Scenario 3: Tainted Session
```
User: intern (researcher)
Call 1: "read /shared/resume.txt"
  → Taint Manager marks session as RED (untrusted)
  → context.is_tainted = true
  → Tool completes, returns resume content
  → Routing: PRODUCTION (no policy rule triggered by read_file itself)

Call 2: "get patient 42"
  → Session is still tainted from Call 1
  → NSIE: risk=0.10 (safe patient ID)
  → Tool Category: "sensitive" (get_patient_record)
  → Policy Phase 3: MATCH taint-lockdown ✓
     Condition: is_tainted=true AND tool_category=sensitive
     Both are true!
  → Result: SHADOW

Key insight: Taint doesn't trigger immediately. It's a "flag" that
affects FUTURE tool calls if they match certain policy rules.
```

### Scenario 4: Risk Accumulation (Windowed Sum)
```
User: analyst (guest)
Time: 10:00 AM - "list patients" → risk=0.3 → accumulated=0.3
Time: 10:20 AM - "get patient 99" → risk=0.4 → accumulated=0.7
Time: 10:45 AM - "read secret.txt" → risk=0.5 → accumulated=1.2
Time: 11:05 AM - "read formula.json" → risk=0.4

Windowed Sum Calculation (60 min window):
  - 10:00 event: STILL IN WINDOW (65 min ago, but check happens before adding new event)
  - 10:20 event: in window (45 min ago)
  - 10:45 event: in window (20 min ago)
  - 11:05 event: NEW (just happened)
  
  Actually, when new event arrives at 11:05:
  - Drop events before 10:05 (>60 min)
  - 10:00 event is DROPPED
  - Window now: [0.4, 0.5] = 0.9
  - Add new event: 0.9 + 0.4 = 1.3

  Accumulated = 1.3 (below 1.5 threshold)

But if risk=0.7 instead:
  - Window sum before: 0.9
  - Add new: 0.9 + 0.7 = 1.6
  - Policy Phase 4: MATCH accumulated_risk_threshold ✓
    (1.6 ≥ 1.5)
  → Result: SHADOW

Key insight: Old risk events automatically "expire" after 60 minutes,
allowing sessions to recover if the user stops risky behavior.
```

## Common Misconceptions Explained

### ❌ WRONG: "The LLM judge triggers shadow routing"
✅ **CORRECT**: The LLM judge provides a risk score. The Policy Engine uses this score (along with accumulated risk) to make the routing decision. If no policy rule matches, even a risk score of 0.99 goes to production.

### ❌ WRONG: "Tainting a session triggers shadow routing"
✅ **CORRECT**: Tainting is a label. A session can be tainted and still route to production. Shadow routing only happens if a policy rule checks for `is_tainted=true` AND other conditions are met (like using a sensitive tool).

### ❌ WRONG: "Risk accumulation threshold is checked on every call"
✅ **CORRECT**: YES, it's checked on every call, but only if it's in the evaluation_order. It's typically after security_policies, so explicit threat patterns take priority.

### ❌ WRONG: "Windowed sum means the last N calls"
✅ **CORRECT**: Windowed sum means risk events within the last N **minutes** (default 60). A session with 100 calls 2 hours ago has accumulated_risk=0.0.

### ❌ WRONG: "I can trigger shadow routing by setting CHIMERA_USER_ROLE=shadow"
✅ **CORRECT**: User context (ID/role) is an INPUT. You can set `user_role=external`, and if there's a policy rule matching that role, it will route to shadow. But the trigger is the policy rule, not the environment variable.

---

## Debug Mode Comparison

### Debug = False (Production)
```
[INFO] NSIE Assessment: Risk=0.95 Confidence=1.00
[INFO] Session Risk: Event=0.95, Accumulated=0.95
[INFO] Policy decision: route=shadow rule=suspicious-keyword-trigger
[WARNING] ⚠️  SHADOW ROUTING TRIGGERED
```

### Debug = True (Development)
```
[DEBUG] 🔍 TOOL CALL INTERCEPTION: read_file
[DEBUG] Tool Arguments: {...}
[DEBUG] Initial Context: {user_id, role, is_tainted: false, ...}
[DEBUG] 🧠 Invoking NSIE Judge...
[DEBUG]   Mock rule 0: field='args.patient_id' → NO MATCH
[DEBUG]   Mock rule 1: field='args.filename' contains 'secret' → NO MATCH  
[DEBUG]   Mock rule 2: field='args.filename' contains 'formula' → MATCH ✓
[INFO]  NSIE Assessment: Risk=0.95 Confidence=1.00
[INFO]  Session Risk: Event=0.95, Accumulated=0.95
[DEBUG] Risk Accumulation Details: {
  previous_accumulated: 0.0,
  new_event_risk: 0.95,
  current_accumulated: 0.95,
  risk_history_length: 1
}
[DEBUG] ⚖️  Invoking Policy Engine...
[DEBUG] Policy evaluation starting for tool: read_file
[DEBUG]   Risk=0.95, Confidence=1.0, Tainted=False, Susp=True
[DEBUG]   Evaluating phase: directives
[DEBUG]   ✗ Phase 'directives' - no match
[DEBUG]   Evaluating phase: trusted_workflows
[DEBUG]   ✗ Phase 'trusted_workflows' - no match
[DEBUG]   Evaluating phase: security_policies
[DEBUG]     Rule 'suspicious-keyword-trigger' matched
[DEBUG]   ✓ Phase 'security_policies' matched: suspicious-keyword-trigger
[INFO]  Policy decision: route=shadow rule=suspicious-keyword-trigger
[WARNING] ⚠️  SHADOW ROUTING TRIGGERED: Routes to shadow if suspicious keyword detected (rule: suspicious-keyword-trigger)
[DEBUG] 🔐 Issuing SHADOW warrant via DKCA...
[DEBUG] Issued Warrant: {type: shadow, accumulated_risk: 0.95, ...}
[DEBUG] 📜 Logged to IFL with event_id: uuid-1234
[DEBUG] ✅ INTERCEPTION COMPLETE: Routing to SHADOW
```

---

## Summary: The Decision Flow

```
Tool Call Arrives
    ↓
Taint Manager: Label session (RED/GREEN) → context.is_tainted
    ↓
NSIE Judge: Calculate risk score → event_risk_score
    ↓
Risk Accumulator: Add to session total → accumulated_risk
    ↓
Policy Engine: Evaluate rules in priority order
    ├─ Check directives (manual overrides)
    ├─ Check trusted workflows (allow lists)
    ├─ Check security policies (uses is_tainted, is_suspicious_query, etc.)
    ├─ Check accumulated_risk threshold
    ├─ Check event_risk_score threshold
    └─ Use default action
    ↓
First Matching Rule → DECISION (production or shadow)
    ↓
DKCA: Issue JWT warrant (signed with production or shadow key)
    ↓
Backend: Verify warrant → Route to correct database/filesystem
```
