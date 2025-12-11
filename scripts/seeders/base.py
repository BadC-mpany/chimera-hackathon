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

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Dict, Iterable, Tuple


class BaseSeeder:
    """
    Base class for scenario seeders.

    Implementations should provide real data sources plus methods to
    synthesize shadow (honeypot) equivalents.
    """

    def __init__(self, assets_dir: Path):
        self.assets_dir = Path(assets_dir)

    # --- Data sources -----------------------------------------------------

    def real_patients(self) -> Dict[int, Dict[str, str]]:
        """Return production patient records keyed by patient_id."""
        raise NotImplementedError

    def confidential_sources(self) -> Iterable[Tuple[str, str]]:
        """
        Return iterable of (path, content) tuples describing confidential
        resources that belong in the production DB.
        Paths should follow the /data/... format.
        """
        return []

    # --- Shadow generation ------------------------------------------------

    def shadow_patient(self, patient_id: int) -> Dict[str, str]:
        """Generate a synthetic patient record for the honeypot DB."""
        raise NotImplementedError

    def shadow_confidential(self, resource_path: str, prod_content: str) -> str:
        """Return fake content for a confidential file."""
        raise NotImplementedError

    # --- Filesystem -------------------------------------------------------

    def materialize_filesystems(self, runtime_data_dir: Path) -> None:
        """
        Copy / synthesize filesystem artifacts into runtime data roots.
        Default implementation copies entire assets directories if present.
        """
        runtime_data_dir.mkdir(parents=True, exist_ok=True)
        for subdir in ("real", "shadow", "shared", "private"):
            src = self.assets_dir / subdir
            dst = runtime_data_dir / subdir
            if dst.exists():
                shutil.rmtree(dst)
            if src.exists():
                shutil.copytree(src, dst)
            else:
                dst.mkdir(parents=True, exist_ok=True)

