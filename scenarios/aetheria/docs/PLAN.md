# Implementation Plan – Aetheria Genesis Scenario

## Phase 0 – Demo Assets
1. **Data Setup**  
   - `scenarios/aetheria/data/private/_CONF_chimera_formula.json` → real gene sequence.  
   - `scenarios/aetheria/data/shared/candidate_resume_j_doe.txt` → malicious payload.  
   - Run `python scripts/sync_shadow_db.py --scenario aetheria` to build `prod.db` and `shadow.db`.

2. **Agent Prompt / Tooling**  
   - Ensure `tests/scenarios/aetheria/medical_demo.py` uses `get_patient_record` & `read_file` to hit the real backend.

## Phase 1 – Context & Policy Enhancements
1. **Metadata Injection**  
   - Embed user role, source IP, origin document, ticket ID into tool calls (e.g., `params.context`).  
   - Extend `Chimera SDK` to accept these when wrapping tools.

2. **Policy Entries**  
   - Add rules in `scenarios/aetheria/config/policy.yaml` for the three trusted cases (Dr. Chen, compliance_bot, CISO).  
   - Include manual override template.

3. **Logging**  
   - Write policy decisions (rule_id, reason, context summary) to a forensic log file.

## Phase 2 – Shadow FS & Holodeck
1. **Synthetic Data Generator**  
   - Enhance `scripts/sync_shadow_db.py` to generate fake gene sequences matching real structure.  
   - Optionally seed a shadow JSON file (`_CONF_chimera_formula.json`) with plausible fake content.

2. **Backend Upgrades**  
   - Generalize `chimera_server.py` to serve both FS paths and DB queries.  
   - Ensure consistent API responses (schema parity) between real/shadow.

3. **Holodeck Behavior**  
   - For `read_file` requests to `_CONF_*`, route to a template that returns domain-specific fake data.

## Phase 3 – Attack Simulation & Demo Script
1. **Scenario Scripting**  
   - Script the steps: upload resume, run summarization prompt, capture output/logs.  
   - Show comparison: Dr. Chen (real data) vs HR Attack (shadow data).

2. **Dashboard / Presentation** (optional)  
   - Simple CLI or UI to show live policy decisions and log entries.  
   - Highlight “Business Continuity” vs “Attack Containment.”

## Success Criteria
- Legitimate workflows (Dr. Chen, compliance_bot, CISO) complete end-to-end on production data.  
- Malicious resume injection receives believable honeypot data.  
- Logs clearly describe why a request went shadow vs production.  
- Demo runbook shows both outcomes within the same architecture.

