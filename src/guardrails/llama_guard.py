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

import httpx

class LlamaGuard:
    def __init__(self, api_key: str, model: str, base_url: str, provider: str, threshold: float = 0.5, extra_headers=None, extra_body=None):
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.threshold = threshold
        self.extra_headers = extra_headers or {}
        self.extra_body = extra_body or {}
        self.base_url = base_url

    def check(self, content: str, role: str = "user") -> dict:
        if not self.api_key or not self.api_key.strip():
            result = "[GUARDRAIL ERROR] No API key provided"
            print(f"[GUARDRAIL][{role}] input: {content}")
            print(f"[GUARDRAIL][{role}] output: {result}")
            return {"result": result}
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        headers.update(self.extra_headers)
        
        # Both OpenRouter and HuggingFace router use chat completions format
        if role == "assistant":
            messages = [
                {"role": "user", "content": "Check this response"},
                {"role": "assistant", "content": content}
            ]
        else:
            messages = [{"role": "user", "content": content}]
        
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 100,
            "temperature": 0.0,
        }
        payload.update(self.extra_body)
        
        try:
            resp = httpx.post(self.base_url, headers=headers, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            
            # Standard chat completions response format
            result = data["choices"][0]["message"]["content"].strip()
                
        except httpx.HTTPStatusError as e:
            try:
                error_detail = e.response.json()
                result = f"[GUARDRAIL ERROR] {e.response.status_code}: {error_detail}"
            except:
                result = f"[GUARDRAIL ERROR] {e.response.status_code}: {e.response.text}"
        except Exception as e:
            result = f"[GUARDRAIL ERROR] {e}"
            
        print(f"[GUARDRAIL][{role}] input: {content}")
        print(f"[GUARDRAIL][{role}] output: {result}")
        return {"result": result}
