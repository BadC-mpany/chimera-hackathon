"""
Utility script to synchronize production and shadow SQLite databases for the
active CHIMERA scenario.

Usage:
    python scripts/sync_shadow_db.py [--scenario aetheria]
"""

from __future__ import annotations

import argparse
import importlib
import os
import sqlite3
import sys
from pathlib import Path
from typing import List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from src.config import load_settings, reload_settings
from scripts.seeders import BaseSeeder

DATA_DIR = Path("data")
PROD_DB = DATA_DIR / "prod.db"
SHADOW_DB = DATA_DIR / "shadow.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS patients (
    patient_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    diagnosis TEXT NOT NULL,
    ssn TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS confidential_files (
    path TEXT PRIMARY KEY,
    content TEXT NOT NULL
);
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync production/shadow databases.")
    parser.add_argument(
        "--scenario",
        help="Override scenario (defaults to CHIMERA_SCENARIO env or config).",
    )
    return parser.parse_args()


def resolve_settings(scenario_override: str | None) -> dict:
    if scenario_override:
        os.environ["CHIMERA_SCENARIO"] = scenario_override
        return reload_settings()
    return load_settings()


def build_seeder(settings: dict) -> BaseSeeder:
    module_spec = settings.get("seeder", {}).get("module")
    if not module_spec:
        raise RuntimeError("No seeder module configured for this scenario.")

    if ":" in module_spec:
        module_name, class_name = module_spec.split(":", 1)
    else:
        module_name, class_name = module_spec, "Seeder"

    module = importlib.import_module(module_name)
    seeder_cls = getattr(module, class_name)

    assets_dir = settings.get("backend", {}).get("assets_dir")
    if not assets_dir:
        scenario_dir = settings.get("paths", {}).get("scenario_dir")
        assets_dir = str(Path(scenario_dir) / "data")
    return seeder_cls(Path(assets_dir))


def ensure_runtime_dirs():
    for sub in ("real", "shadow", "private", "shared"):
        (DATA_DIR / sub).mkdir(parents=True, exist_ok=True)


def init_prod_db(seeder: BaseSeeder, confidential_files: List[Tuple[str, str]]) -> None:
    print(f"[+] Ensuring production DB at {PROD_DB}")
    conn = sqlite3.connect(PROD_DB)
    cur = conn.cursor()
    cur.executescript(SCHEMA_SQL)

    real_data = seeder.real_patients()
    cur.execute("DELETE FROM patients")
    for pid, record in real_data.items():
        cur.execute(
            "INSERT INTO patients (patient_id, name, diagnosis, ssn) VALUES (?, ?, ?, ?)",
            (int(pid), record.get("name"), record.get("diagnosis"), record.get("ssn")),
        )

    cur.execute("DELETE FROM confidential_files")
    for path, content in confidential_files:
        cur.execute(
            "INSERT INTO confidential_files (path, content) VALUES (?, ?)",
            (path, content),
        )

    conn.commit()
    conn.close()
    print(
        f"[+] Production DB populated with {len(real_data)} patient records and {len(confidential_files)} confidential files"
    )


def clone_schema():
    print("[+] Cloning schema to shadow DB")
    prod_conn = sqlite3.connect(PROD_DB)
    shadow_conn = sqlite3.connect(SHADOW_DB)
    prod_cur = prod_conn.cursor()
    shadow_cur = shadow_conn.cursor()

    shadow_cur.execute("PRAGMA foreign_keys=OFF;")
    shadow_cur.execute("BEGIN TRANSACTION;")
    for table in ("patients", "confidential_files"):
        shadow_cur.execute(f"DROP TABLE IF EXISTS {table};")
        row = prod_cur.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if row and row[0]:
            shadow_cur.execute(row[0])
    shadow_conn.commit()
    prod_conn.close()
    shadow_conn.close()
    print("[+] Schema clone complete")


def seed_shadow(seeder: BaseSeeder, confidential_files: List[Tuple[str, str]]) -> None:
    print("[+] Seeding shadow DB with synthetic data")
    prod_conn = sqlite3.connect(PROD_DB)
    shadow_conn = sqlite3.connect(SHADOW_DB)
    prod_cur = prod_conn.cursor()
    shadow_cur = shadow_conn.cursor()

    shadow_cur.execute("DELETE FROM patients")
    shadow_cur.execute("DELETE FROM confidential_files")

    rows = prod_cur.execute("SELECT patient_id FROM patients ORDER BY patient_id").fetchall()
    for row in rows:
        pid = row[0]
        fake_record = seeder.shadow_patient(pid)
        shadow_cur.execute(
            "INSERT INTO patients (patient_id, name, diagnosis, ssn) VALUES (?, ?, ?, ?)",
            (
                fake_record.get("patient_id", pid),
                fake_record.get("name"),
                fake_record.get("diagnosis"),
                fake_record.get("ssn"),
            ),
        )

    shadow_entries = []
    for resource_path, prod_content in confidential_files:
        fake_content = seeder.shadow_confidential(resource_path, prod_content)
        shadow_entries.append((resource_path, fake_content))
        _write_shadow_artifact(resource_path, fake_content)

    shadow_cur.executemany(
        "INSERT INTO confidential_files (path, content) VALUES (?, ?)",
        shadow_entries,
    )

    shadow_conn.commit()
    prod_conn.close()
    shadow_conn.close()
    print(f"[+] Shadow DB seeded with {len(rows)} fake patient records and {len(shadow_entries)} confidential files")


def _write_shadow_artifact(resource_path: str, content: str) -> None:
    """Drop honeypot content into the runtime shadow filesystem for quick inspection."""
    rel_path = resource_path
    if rel_path.startswith("/data/"):
        rel_path = rel_path[len("/data/") :]
    rel = Path(rel_path.lstrip("/\\"))
    target = DATA_DIR / "shadow" / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def collect_confidential_sources(seeder: BaseSeeder) -> List[Tuple[str, str]]:
    sources = list(seeder.confidential_sources())
    if not sources:
        print("[!] WARNING: no confidential assets found for production DB.")
    return sources


def main():
    args = parse_args()
    settings = resolve_settings(args.scenario)
    seeder = build_seeder(settings)

    ensure_runtime_dirs()
    seeder.materialize_filesystems(DATA_DIR)

    confidential_files = collect_confidential_sources(seeder)
    init_prod_db(seeder, confidential_files)
    clone_schema()
    seed_shadow(seeder, confidential_files)
    print(f"[OK] Shadow synchronization complete (scenario={settings.get('scenario', {}).get('active')})")


if __name__ == "__main__":
    main()

