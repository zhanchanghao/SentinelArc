from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    project_root: Path
    data_root: Path
    db_path: Path
    artifacts_dir: Path
    workdir_dir: Path
    reports_dir: Path

    engine_version: str
    ruleset_version: str

    max_upload_bytes: int
    max_unpacked_bytes: int
    max_file_count: int
    max_dir_depth: int

    fail_on_critical: bool
    high_count_threshold: int
    score_threshold: int


def build_settings() -> Settings:
    project_root = Path(__file__).resolve().parents[2]
    data_root = project_root / "storage" / "runtime"
    db_path = data_root / "db.sqlite3"
    artifacts_dir = data_root / "artifacts"
    workdir_dir = data_root / "workdir"
    reports_dir = data_root / "reports"

    return Settings(
        project_root=project_root,
        data_root=data_root,
        db_path=db_path,
        artifacts_dir=artifacts_dir,
        workdir_dir=workdir_dir,
        reports_dir=reports_dir,
        engine_version="0.1.0",
        ruleset_version="0.1.0",
        max_upload_bytes=200 * 1024 * 1024,
        max_unpacked_bytes=800 * 1024 * 1024,
        max_file_count=20000,
        max_dir_depth=20,
        fail_on_critical=True,
        high_count_threshold=5,
        score_threshold=60,
    )


settings = build_settings()
