import os
import pytest
from src.config import load_settings, reload_settings

def test_load_settings_uses_dummy_scenario():
    """Ensure base + scenario configs merge without crashing."""
    original_env = os.environ.get("CHIMERA_SCENARIO")
    try:
        os.environ["CHIMERA_SCENARIO"] = "test_dummy"
        reload_settings()
        settings = load_settings()

        assert settings["policy"]["defaults"]["fail_mode"] == "shadow", "fail_mode should be shadow"
        assert settings["scenario"]["active"] == "test_dummy", "Active scenario mismatch"
        assert "tools" in settings["backend"], "Backend tools missing"
        print("[OK] Config merge test passed.")
    finally:
        if original_env:
            os.environ["CHIMERA_SCENARIO"] = original_env
        else:
            os.environ.pop("CHIMERA_SCENARIO", None)
        reload_settings()


def test_no_scenario_raises_error():
    """Ensure missing scenario config fails with clear error."""
    original_env = os.environ.get("CHIMERA_SCENARIO")
    try:
        os.environ.pop("CHIMERA_SCENARIO", None)
        reload_settings()
        try:
            load_settings()
            assert False, "Should have raised RuntimeError for missing scenario"
        except RuntimeError as e:
            assert "No scenario configured" in str(e), f"Wrong error message: {e}"
            print("[OK] Missing scenario error test passed.")
    finally:
        if original_env:
            os.environ["CHIMERA_SCENARIO"] = original_env
        reload_settings()

if __name__ == "__main__":
    test_load_settings_uses_dummy_scenario()
    test_no_scenario_raises_error()
    print("\nAll core tests passed.")
