from __future__ import annotations

import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

from app.db import sqlite as db
from worker.runner import TaskRunner
from worker import runner as runner_module
from engine import pipeline


def _create_zip(path: Path, files: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)


def test_runner_fails_fast_on_invalid_skill_layout(tmp_path: Path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    artifacts_dir = runtime / "artifacts"
    workdir_dir = runtime / "workdir"
    reports_dir = runtime / "reports"
    db_path = runtime / "db.sqlite3"
    runtime.mkdir(parents=True, exist_ok=True)

    fake_settings = SimpleNamespace(
        data_root=runtime,
        artifacts_dir=artifacts_dir,
        workdir_dir=workdir_dir,
        reports_dir=reports_dir,
        db_path=db_path,
        max_unpacked_bytes=50 * 1024 * 1024,
        max_file_count=2000,
        max_dir_depth=20,
        fail_on_critical=True,
        high_count_threshold=5,
        score_threshold=60,
    )
    monkeypatch.setattr(runner_module, "settings", fake_settings)

    conn = db.connect(db_path)
    db.init_db(conn)
    bad_zip = artifacts_dir / "abc123" / "original.zip"
    _create_zip(bad_zip, {"foo.txt": b"hello"})

    artifact = db.insert_artifact(
        conn,
        sha256="abc123",
        original_filename="original.zip",
        size_bytes=bad_zip.stat().st_size,
        storage_path=str(bad_zip),
    )
    task = db.insert_task(conn, artifact_id=artifact.id, engine_version="0.1.0", ruleset_version="0.1.0")
    conn.close()

    called = {"scan": False}

    def _should_not_scan(_: Path):
        called["scan"] = True
        raise AssertionError("scan_directory should not be called when layout is invalid")

    monkeypatch.setattr(pipeline, "scan_directory", _should_not_scan)

    TaskRunner()._run_task(task.id)

    conn2 = db.connect(db_path)
    saved = db.get_task(conn2, task.id)
    findings = db.list_findings(conn2, task_id=task.id)
    conn2.close()

    assert saved is not None
    assert saved.status == "completed"
    assert saved.error_message == pipeline.SKILL_LAYOUT_INVALID_MISSING_SKILL_MD
    assert called["scan"] is False
    assert findings == []
    summary = json.loads(saved.summary_json or "{}")
    assert summary.get("conclusion") == "FAIL"
    assert summary.get("level") == "High"
    assert summary.get("score") == 0
    assert not bad_zip.exists()
    assert not (workdir_dir / task.id).exists()
