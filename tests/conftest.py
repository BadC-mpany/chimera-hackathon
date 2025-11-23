
import os
import pytest

@pytest.fixture(scope="session", autouse=True)
def set_test_env():
    """Set environment variables for the entire test session."""
    os.environ["CHIMERA_SCENARIO"] = "aetheria"
    # Ensure we don't accidentally use production keys in tests if they existed
    os.environ["OPENAI_API_KEY"] = "test-key" 
    yield
    # Teardown if needed

