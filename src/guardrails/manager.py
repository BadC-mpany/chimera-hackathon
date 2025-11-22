from .llama_guard import LlamaGuard
from .config import GuardrailConfig

class GuardrailManager:
    def __init__(self, config_path=None):
        self.config = GuardrailConfig(config_path)
        self.guard = LlamaGuard(
            api_key=self.config.get_api_key(),
            model=self.config.get_model(),
            base_url=self.config.get_base_url(),
            provider=self.config.get_provider(),
            threshold=self.config.get_threshold(),
            extra_headers=self.config.get_extra_headers(),
            extra_body=self.config.get_extra_body(),
        )

    def check_user_query(self, query: str) -> dict:
        if self.config.is_enabled("user_query"):
            return self.guard.check(query, role="user")
        return {"result": "SKIPPED"}

    def check_tool_data(self, data: str) -> dict:
        if self.config.is_enabled("tool_data"):
            return self.guard.check(data, role="tool")
        return {"result": "SKIPPED"}

    def check_output(self, output: str) -> dict:
        if self.config.is_enabled("output"):
            return self.guard.check(output, role="assistant")
        return {"result": "SKIPPED"}
