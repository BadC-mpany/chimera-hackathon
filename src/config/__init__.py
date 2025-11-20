import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"


def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data


def _deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in overlay.items():
        if (
            key in base
            and isinstance(base[key], dict)
            and isinstance(value, dict)
        ):
            base[key] = _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


@lru_cache(maxsize=1)
def load_settings() -> Dict[str, Any]:
    """Load base + scenario configuration."""
    base_cfg = _load_yaml(CONFIG_DIR / "base.yaml")
    scenario_default = base_cfg.get("scenario", {}).get("default")
    scenario_name = os.getenv("CHIMERA_SCENARIO", scenario_default)
    
    if not scenario_name or scenario_name == "null":
        raise RuntimeError(
            "No scenario configured. Set CHIMERA_SCENARIO environment variable or pass --scenario flag.\n"
            "Available scenarios: check scenarios/ directory or run 'python manage.py list-scenarios'"
        )
    
    scenario_cfg_path = CONFIG_DIR / "scenarios" / f"{scenario_name}.yaml"
    if not scenario_cfg_path.exists():
        raise FileNotFoundError(
            f"Scenario config not found: {scenario_cfg_path}\n"
            f"Create {scenario_cfg_path} or use an existing scenario."
        )
    scenario_cfg = _load_yaml(scenario_cfg_path)

    # Merge base + scenario overlays
    merged = _deep_merge(base_cfg.copy(), scenario_cfg)

    # Load external policy/override files if referenced
    if "policy_file" in scenario_cfg:
        policy_data = _load_yaml(PROJECT_ROOT / scenario_cfg["policy_file"])
        merged.setdefault("policy", {})
        merged["policy"] = _deep_merge(merged["policy"], policy_data)

    if "overrides_file" in scenario_cfg:
        override_data = _load_yaml(PROJECT_ROOT / scenario_cfg["overrides_file"])
        merged["overrides"] = override_data or {"users": {}, "sessions": {}}

    merged.setdefault("scenario", {})
    merged["scenario"]["active"] = scenario_name
    merged["paths"] = {
        "project_root": str(PROJECT_ROOT),
        "scenario_dir": str(PROJECT_ROOT / "scenarios" / scenario_name),
    }
    return merged


def reload_settings() -> Dict[str, Any]:
    """Force a reload of configuration (used when switching scenarios)."""
    load_settings.cache_clear()
    return load_settings()

