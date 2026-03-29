from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Tuple


@dataclass(frozen=True)
class StoredFile:
    sha256: str
    size_bytes: int
    path: Path


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def compute_and_store(
    *,
    source: BinaryIO,
    dest_dir: Path,
    original_filename: str,
    max_bytes: int,
) -> StoredFile:
    ensure_dir(dest_dir)
    suffix = Path(original_filename).suffix.lower()
    if original_filename.lower().endswith(".tar.gz"):
        suffix = ".tar.gz"
    if original_filename.lower().endswith(".tgz"):
        suffix = ".tgz"
    tmp_path = dest_dir / f"upload{suffix}.tmp"

    h = hashlib.sha256()
    size = 0
    with tmp_path.open("wb") as f:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("upload_too_large")
            h.update(chunk)
            f.write(chunk)

    sha = h.hexdigest()
    final_dir = dest_dir / sha
    ensure_dir(final_dir)
    final_path = final_dir / f"original{suffix}"
    tmp_path.replace(final_path)
    return StoredFile(sha256=sha, size_bytes=size, path=final_path)


def task_workdir(workdir_root: Path, task_id: str) -> Path:
    return workdir_root / task_id


def task_unpack_dir(workdir_root: Path, task_id: str) -> Path:
    return task_workdir(workdir_root, task_id) / "unpacked"


def task_report_path(reports_root: Path, task_id: str) -> Path:
    return reports_root / task_id / "report.json"
