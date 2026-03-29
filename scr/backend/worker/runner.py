from __future__ import annotations

import json
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from queue import Queue
from typing import Optional

from app.core.config import settings
from app.db import sqlite as db
from app.services import storage as storage_paths
from engine import pipeline


@dataclass(frozen=True)
class EnqueuedTask:
    task_id: str


class TaskRunner:
    def __init__(self) -> None:
        self._queue: Queue[EnqueuedTask] = Queue()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        t = threading.Thread(target=self._run_loop, name="skill-scan-worker", daemon=True)
        self._thread = t
        t.start()

    def stop(self) -> None:
        self._stop_event.set()

    def enqueue(self, task_id: str) -> None:
        self._queue.put(EnqueuedTask(task_id=task_id))

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            task = self._queue.get()
            try:
                self._run_task(task.task_id)
            finally:
                self._queue.task_done()

    def _run_task(self, task_id: str) -> None:
        settings.data_root.mkdir(parents=True, exist_ok=True)
        storage_paths.ensure_dir(settings.artifacts_dir)
        storage_paths.ensure_dir(settings.workdir_dir)
        storage_paths.ensure_dir(settings.reports_dir)

        artifact_path: Optional[Path] = None
        task_workdir: Optional[Path] = None
        conn = db.connect(settings.db_path)
        try:
            task = db.get_task(conn, task_id)
            if not task:
                return
            artifact = db.get_artifact(conn, task.artifact_id)
            if not artifact:
                db.update_task_status(conn, task_id=task_id, status="failed", finished_at=db.now_iso(), error_message="artifact_not_found")
                return
            artifact_path = Path(artifact.storage_path)

            db.update_task_status(conn, task_id=task_id, status="running", started_at=db.now_iso())

            workdir = storage_paths.task_workdir(settings.workdir_dir, task_id)
            task_workdir = workdir
            unpack_dir = storage_paths.task_unpack_dir(settings.workdir_dir, task_id)
            if workdir.exists():
                shutil.rmtree(workdir, ignore_errors=True)
            unpack_dir.mkdir(parents=True, exist_ok=True)

            pipeline.safe_extract_archive(
                archive_path=Path(artifact.storage_path),
                dest_dir=unpack_dir,
                max_unpacked_bytes=settings.max_unpacked_bytes,
                max_file_count=settings.max_file_count,
                max_dir_depth=settings.max_dir_depth,
            )
            try:
                pipeline.validate_skill_layout(unpack_dir)
            except ValueError as e:
                error_code = str(e)
                if not pipeline.is_skill_layout_error(error_code):
                    raise
                findings = []
                summary = pipeline.build_skill_layout_failure_summary(error_code)
                report = pipeline.build_report(
                    task_id=task_id,
                    artifact_sha256=artifact.sha256,
                    created_at=task.created_at,
                    engine_version=task.engine_version,
                    ruleset_version=task.ruleset_version,
                    summary=summary,
                    findings=findings,
                )
                report_path = storage_paths.task_report_path(settings.reports_dir, task_id)
                pipeline.write_report(report_path, report)
                db.replace_task_findings(conn, task_id=task_id, findings=[])
                db.update_task_status(
                    conn,
                    task_id=task_id,
                    status="completed",
                    finished_at=db.now_iso(),
                    summary=summary,
                    error_message=error_code,
                )
                return

            findings = pipeline.scan_directory(unpack_dir)
            summary = pipeline.aggregate(
                findings,
                fail_on_critical=settings.fail_on_critical,
                high_count_threshold=settings.high_count_threshold,
                score_threshold=settings.score_threshold,
            )
            report = pipeline.build_report(
                task_id=task_id,
                artifact_sha256=artifact.sha256,
                created_at=task.created_at,
                engine_version=task.engine_version,
                ruleset_version=task.ruleset_version,
                summary=summary,
                findings=findings,
            )
            report_path = storage_paths.task_report_path(settings.reports_dir, task_id)
            pipeline.write_report(report_path, report)

            db_findings = [
                db.FindingRow(
                    id=f.id,
                    task_id=task_id,
                    rule_id=f.rule_id,
                    category=f.category,
                    severity=f.severity,
                    confidence=f.confidence,
                    file_path=f.file_path,
                    line_range=f.line_range,
                    snippet_redacted=f.snippet_redacted,
                    evidence_json=json.dumps(f.evidence, ensure_ascii=False),
                    recommendation=f.recommendation,
                )
                for f in findings
            ]
            db.replace_task_findings(conn, task_id=task_id, findings=db_findings)
            db.update_task_status(conn, task_id=task_id, status="completed", finished_at=db.now_iso(), summary=summary)
        except Exception as e:
            error_message = str(e) if isinstance(e, ValueError) else "internal_error"
            db.update_task_status(conn, task_id=task_id, status="failed", finished_at=db.now_iso(), error_message=error_message)
        finally:
            # Uploaded archives are transient; remove them after task processing.
            if artifact_path is not None:
                try:
                    artifact_path.unlink(missing_ok=True)
                    parent_dir = artifact_path.parent
                    if parent_dir.exists() and not any(parent_dir.iterdir()):
                        parent_dir.rmdir()
                except Exception:
                    pass
            if task_workdir is not None:
                shutil.rmtree(task_workdir, ignore_errors=True)
            conn.close()
