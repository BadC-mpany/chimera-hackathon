# Copyright 2025 Badcompany
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import yaml
from pathlib import Path

class GuardrailConfig:
    def __init__(self, config_path=None):
        if config_path is None:
            config_path = Path(__file__).resolve().parents[2] / "config" / "llama_guard.yaml"
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)
        self.llama_guard = self.config.get("llama_guard", {})

    def is_enabled(self, which: str) -> bool:
        return self.llama_guard.get("enabled", {}).get(which, False)

    def get_threshold(self) -> float:
        return float(self.llama_guard.get("threshold", 0.5))

    def get_provider(self) -> str:
        return self.llama_guard.get("provider", "openrouter")

    def get_model(self) -> str:
        provider = self.get_provider()
        provider_config = self.llama_guard.get(provider, {})
        return provider_config.get("model", "meta-llama/llama-guard-3-8b")

    def get_api_key(self) -> str:
        provider = self.get_provider()
        provider_config = self.llama_guard.get(provider, {})
        env = provider_config.get("api_key_env", "OPENROUTER_API_KEY")
        return os.getenv(env, "")

    def get_base_url(self) -> str:
        provider = self.get_provider()
        provider_config = self.llama_guard.get(provider, {})
        return provider_config.get("base_url", "https://openrouter.ai/api/v1/chat/completions")

    def get_extra_headers(self):
        return self.llama_guard.get("extra_headers", {})

    def get_extra_body(self):
        return self.llama_guard.get("extra_body", {})
