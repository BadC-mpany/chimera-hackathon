import argparse
import re
import yaml
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
REGISTRY_PATH = PROJECT_ROOT / "scenarios" / "registry.yaml"


def camelize(name: str) -> str:
    parts = re.split(r"[-_\\s]+", name)
    return "".join(part.capitalize() for part in parts if part)


def scaffold_scenario(name: str) -> None:
    scenario_dir = PROJECT_ROOT / "scenarios" / name
    if scenario_dir.exists():
        print(f"[!] Scenario '{name}' already exists.")
        return

    config_dir = scenario_dir / "config"
    data_dir = scenario_dir / "data"
    tests_dir = scenario_dir / "tests"

    for path in [
        config_dir,
        data_dir / "real",
        data_dir / "shadow",
        data_dir / "private",
        data_dir / "shared",
        tests_dir,
    ]:
        path.mkdir(parents=True, exist_ok=True)

    # Policy + overrides templates
    (config_dir / "policy.yaml").write_text(
        """defaults:
  risk_threshold: 0.5
  fail_mode: shadow
rules:
  - id: sample-rule
    description: Replace with real scenario rule.
    tools: ["read_file"]
    match:
      all:
        - field: args.filename
          operator: contains
          value: secret
    action: shadow
""",
        encoding="utf-8",
    )
    (config_dir / "manual_overrides.yaml").write_text(
        "users: {}\nsessions: {}\n", encoding="utf-8"
    )

    # Scenario overlay stub
    overlay_path = PROJECT_ROOT / "config" / "scenarios" / f"{name}.yaml"
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    seeder_cls = f"{camelize(name)}Seeder"
    overlay_path.write_text(
        f"""name: {name}
policy_file: scenarios/{name}/config/policy.yaml
overrides_file: scenarios/{name}/config/manual_overrides.yaml
backend:
  assets_dir: scenarios/{name}/data
nsie:
  prompt_template: |
    Customize guardrail instructions for the {name} scenario.
seeder:
  module: scripts.seeders.{name}:{seeder_cls}
""",
        encoding="utf-8",
    )

    # Seeder stub
    seeder_path = PROJECT_ROOT / "scripts" / "seeders" / f"{name}.py"
    if not seeder_path.exists():
        seeder_path.write_text(
            f"""from pathlib import Path
from typing import Dict, Iterable, Tuple

from .base import BaseSeeder


class {seeder_cls}(BaseSeeder):
    \"\"\"Seeder stub for the '{name}' scenario.\"\"\"

    def real_patients(self) -> Dict[int, Dict[str, str]]:
        return {{}}

    def confidential_sources(self) -> Iterable[Tuple[str, str]]:
        return []

    def shadow_patient(self, patient_id: int) -> Dict[str, str]:
        return {{
            "patient_id": patient_id,
            "name": f"Fake {{patient_id}}",
            "diagnosis": "Placeholder",
            "ssn": "000-00-0000",
        }}

    def shadow_confidential(self, resource_path: str, prod_content: str) -> str:
        return "[SHADOW DATA]"
""",
            encoding="utf-8",
        )

    print(f"[+] Scenario '{name}' scaffolded under {scenario_dir}")
    print(f"    - Update {overlay_path} and implement {seeder_path.name}")
    print("    - Populate data/ with real assets, then run sync_shadow_db.")


def list_scenarios() -> None:
    """List all registered scenarios."""
    if not REGISTRY_PATH.exists():
        print("[!] No registry found. Create scenarios/registry.yaml")
        return
    
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        registry = yaml.safe_load(f) or {}
    
    scenarios = registry.get("scenarios", {})
    if not scenarios:
        print("[!] No scenarios registered.")
        return
    
    print("Available scenarios:\n")
    for name, meta in scenarios.items():
        status = meta.get("status", "unknown")
        desc = meta.get("description", "No description")
        tags = ", ".join(meta.get("tags", []))
        print(f"  {name:<20} [{status:<12}] {desc}")
        if tags:
            print(f"  {'':<20}   Tags: {tags}")
        print()


def main():
    parser = argparse.ArgumentParser(description="CHIMERA utility commands")
    subparsers = parser.add_subparsers(dest="command")

    scaffold = subparsers.add_parser("scaffold-scenario", help="Create a new scenario skeleton")
    scaffold.add_argument("name", help="Scenario name (e.g., finance_bank)")
    
    subparsers.add_parser("list-scenarios", help="List all registered scenarios")

    args = parser.parse_args()
    if args.command == "scaffold-scenario":
        scaffold_scenario(args.name)
    elif args.command == "list-scenarios":
        list_scenarios()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

