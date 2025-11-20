## Scenarios Overview

The `scenarios/` directory contains domain-specific overlays that sit on top of the CHIMERA core.

- `aetheria/` – Healthcare prompt-injection demo (patients, Chimera formula, resume payload).
  - `config/` – Policy overrides, manual warrants, judge prompt fragments.
  - `data/` – Source datasets used to seed production/shadow stores.
  - `tests/` – Scenario-specific demos (see `tests/scenarios/aetheria/`).

### Folder Layout

```
scenarios/<name>/
├── config/
│   ├── policy.yaml            # Rule set merged into config/scenarios/<name>.yaml
│   └── manual_overrides.yaml  # Force-route warrants for privileged actors
├── data/
│   ├── real/                  # Authoritative seed data (JSON/CSV/files)
│   ├── shadow/                # Optional canned honeypot files
│   ├── private/               # High-value assets (e.g., _CONF_* files)
│   └── shared/                # Uploaded documents/prompt-injection payloads
└── tests/                     # Scenario demos (mirrors tests/scenarios/<name>/)
```

### Authoring Flow

1. Use `python manage.py scaffold-scenario <name>` to create a new skeleton (or copy an existing scenario).
2. Populate `scenarios/<name>/config/policy.yaml` with rule entries and overrides.
3. Drop raw assets into `scenarios/<name>/data/`. These remain under version control; runtime copies are written to `data/`.
4. Register the scenario in `config/scenarios/<name>.yaml` (policy file paths, backend assets_dir, seeder module).
5. Implement a seeder in `scripts/seeders/<name>.py` that extends `BaseSeeder` and generates synthetic honeypot data.
6. Add demos/tests under `tests/scenarios/<name>/` to showcase the attack and defensive happy-paths.
7. Run `python scripts/sync_shadow_db.py --scenario <name>` to materialize runtime databases/files before executing demos.

### Runtime Refresh

- `python scripts/sync_shadow_db.py --scenario aetheria` repopulates `data/` from the scenario assets.
- Set `CHIMERA_SCENARIO=<name>` (or pass `--scenario`) to switch dynamically; `src.config.load_settings()` handles the merge.
- Scenario-specific docs live under `docs/` (e.g., `docs/AETHERIA_SCENARIO.md`) and should reference the `scenarios/<name>/` assets instead of `data/`.

