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

import re
from typing import List, Pattern


class ResponseSanitizer:
    """
    Scrub sensitive information from downstream responses before they reach the agent.
    Ensures that even if the Shadow Environment errors out, no internal traces leak.
    """

    def __init__(self):
        # Compile regex patterns for things we absolutely must not leak
        self.patterns: List[Pattern] = [
            # AWS Keys
            re.compile(r"(AKIA[0-9A-Z]{16})"),
            # Private Keys
            re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
            # Internal File Paths (Windows/Linux)
            re.compile(r"([a-zA-Z]:\\[\w\\.]+|/var/www/[\w/]+|/home/[\w/]+)"),
            # Stack Traces (Python)
            re.compile(r"Traceback \(most recent call last\):"),
            # JWTs (Generic)
            re.compile(r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"),
        ]

    def sanitize(self, content: str) -> str:
        """
        Replace sensitive patterns with [REDACTED].
        """
        cleaned = content
        for pattern in self.patterns:
            cleaned = pattern.sub("[REDACTED]", cleaned)
        return cleaned
