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

