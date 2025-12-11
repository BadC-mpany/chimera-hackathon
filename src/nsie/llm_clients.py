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

from langchain_openai import ChatOpenAI


def get_llm_client():
    """
    Initializes and returns the LangChain LLM client.

    This function is configured via environment variables to support different
    models and providers, primarily targeting OpenAI-compatible APIs like OpenRouter.
    """
    api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        # For security, we don't raise a fatal error here.
        # The ProbabilisticJudge will degrade gracefully if no LLM is available.
        return None

    model = os.getenv("OPENROUTER_MODEL", "gpt-4-turbo-preview")
    base_url = os.getenv("OPENROUTER_BASE_URL")

    try:
        llm = ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url=base_url,
            temperature=0,
            model_kwargs={"response_format": {"type": "json_object"}},
        )
        return llm
    except Exception:
        # Catch potential initialization errors (e.g., invalid API key format)
        return None
