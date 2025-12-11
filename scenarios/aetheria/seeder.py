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

import json
from pathlib import Path
from typing import Dict, Iterable, Tuple

from faker import Faker
from scripts.seeders.base import BaseSeeder


class AetheriaSeeder(BaseSeeder):
    """Seeder for the Aetheria Genesis demo scenario."""

    def __init__(self, assets_dir: Path):
        super().__init__(assets_dir)
        self._faker = Faker()

    # --- Production data --------------------------------------------------

    def real_patients(self) -> Dict[int, Dict[str, str]]:
        path = self.assets_dir / "real" / "patients.json"
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return {int(pid): record for pid, record in data.items()}

    def confidential_sources(self) -> Iterable[Tuple[str, str]]:
        private_dir = self.assets_dir / "private"
        if not private_dir.exists():
            return []
        files = sorted(private_dir.glob("*"))
        for file_path in files:
            content = file_path.read_text(encoding="utf-8")
            resource_path = f"/data/private/{file_path.name}"
            yield resource_path, content

    # --- Honeypot generation ---------------------------------------------

    def shadow_patient(self, patient_id: int) -> Dict[str, str]:
        return {
            "patient_id": patient_id,
            "name": self._faker.name(),
            "diagnosis": self._faker.sentence(nb_words=3),
            "ssn": self._faker.unique.ssn(),
        }

    def shadow_confidential(self, resource_path: str, prod_content: str) -> str:
        if "chimera_formula" in resource_path:
            return self._fake_formula()
        if "adverse_events" in resource_path:
            return self._fake_log()
        return self._faker.text(max_nb_chars=200)

    # --- Helpers ----------------------------------------------------------

    def _fake_formula(self) -> str:

        triplets = []
        for _ in range(12):
            triplets.append("".join(self._faker.random_choices(elements=list("ATGC"), length=3)))
        seq = "-".join(triplets)
        data = {
            "project": "Chimera-SHADOW",
            "sequence_id": f"FAKE-{self._faker.random_int(200, 999)}",
            "chain_a": seq,
            "chain_b": seq[::-1],
            "status": "SIMULATED",
            "notes": "Honeypot projection for adversarial containment",
        }
        return json.dumps(data, indent=2)

    def _fake_log(self) -> str:
        lines = []
        for _ in range(4):
            timestamp = self._faker.date_time_this_year().strftime("%Y-%m-%d %H:%M:%SZ")
            symptom = self._faker.sentence(nb_words=4)
            severity = self._faker.random_int(1, 5)
            action = self._faker.sentence(nb_words=6)
            lines.append(
                f"{timestamp} | Subject_{self._faker.random_int(70, 95)} | "
                f"Symptom: {symptom} | Severity: {severity} | Action: {action}"
            )
        return "\n".join(lines)
