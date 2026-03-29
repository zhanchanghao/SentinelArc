from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.routing import APIRouter

from app.core.config import settings
from app.db import sqlite as db
from app.services import storage as storage_service
from engine import pipeline
from worker.runner import TaskRunner


router = APIRouter(prefix="/api")
task_runner = TaskRunner()


@router.post("/tasks")
async def create_task(file: UploadFile = File(...)) -> dict[str, Any]:
    if not file.filename:
        raise HTTPException(status_code=400, detail="missing_filename")
    lower = file.filename.lower()
    if not (lower.endswith(".zip") or lower.endswith(".tar.gz") or lower.endswith(".tgz")):
        raise HTTPException(status_code=400, detail="unsupported_archive_format")

    settings.data_root.mkdir(parents=True, exist_ok=True)
    storage_service.ensure_dir(settings.artifacts_dir)
    conn = db.connect(settings.db_path)
    try:
        stored = storage_service.compute_and_store(
            source=file.file,
            dest_dir=settings.artifacts_dir,
            original_filename=file.filename,
            max_bytes=settings.max_upload_bytes,
        )
        try:
            artifact = db.insert_artifact(
                conn,
                sha256=stored.sha256,
                original_filename=file.filename,
                size_bytes=stored.size_bytes,
                storage_path=str(stored.path),
            )
        except sqlite3.IntegrityError:
            artifact = db.get_artifact_by_sha(conn, stored.sha256)
            if not artifact:
                raise

        task = db.insert_task(conn, artifact_id=artifact.id, engine_version=settings.engine_version, ruleset_version=settings.ruleset_version)
        task_runner.enqueue(task.id)
        return {"task_id": task.id, "artifact_sha256": artifact.sha256, "status": task.status}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()


@router.get("/tasks")
def list_tasks(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    conn = db.connect(settings.db_path)
    try:
        items = db.list_tasks(conn, limit=limit, offset=offset)
        return {"items": items, "limit": limit, "offset": offset}
    finally:
        conn.close()


@router.get("/tasks/{task_id}")
def get_task(task_id: str) -> dict[str, Any]:
    conn = db.connect(settings.db_path)
    try:
        task = db.get_task(conn, task_id)
        if not task:
            raise HTTPException(status_code=404, detail="task_not_found")
        summary = json.loads(task.summary_json) if task.summary_json else None
        return {
            "id": task.id,
            "status": task.status,
            "created_at": task.created_at,
            "started_at": task.started_at,
            "finished_at": task.finished_at,
            "engine_version": task.engine_version,
            "ruleset_version": task.ruleset_version,
            "conclusion": summary.get("conclusion") if isinstance(summary, dict) else None,
            "level": summary.get("level") if isinstance(summary, dict) else None,
            "score": summary.get("score") if isinstance(summary, dict) else None,
            "summary": summary,
            "error_message": task.error_message,
        }
    finally:
        conn.close()


@router.get("/tasks/{task_id}/findings")
def get_findings(task_id: str, limit: int = 500, offset: int = 0) -> dict[str, Any]:
    conn = db.connect(settings.db_path)
    try:
        task = db.get_task(conn, task_id)
        if not task:
            raise HTTPException(status_code=404, detail="task_not_found")
        items = db.list_findings(conn, task_id=task_id, limit=limit, offset=offset)
        return {"items": items, "limit": limit, "offset": offset}
    finally:
        conn.close()


@router.get("/tasks/{task_id}/report.json")
def download_report(task_id: str) -> FileResponse:
    report_path = storage_service.task_report_path(settings.reports_dir, task_id)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="report_not_found")
    return FileResponse(path=str(report_path), media_type="application/json", filename=f"{task_id}.report.json")


@router.get("/tasks/{task_id}/report.md")
def download_report_markdown(task_id: str) -> Response:
    report_path = storage_service.task_report_path(settings.reports_dir, task_id)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="report_not_found")
    report_obj = json.loads(report_path.read_text(encoding="utf-8"))
    md = pipeline.render_report_markdown(report_obj)
    filename = f"{task_id}.report.md"
    return Response(
        content=md.encode("utf-8"),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def create_app() -> FastAPI:
    app = FastAPI(title="Skill 安全检测平台 API", version=settings.engine_version)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:4173",
            "http://127.0.0.1:4173",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)

    @app.on_event("startup")
    def _startup() -> None:
        settings.data_root.mkdir(parents=True, exist_ok=True)
        storage_service.ensure_dir(settings.artifacts_dir)
        storage_service.ensure_dir(settings.workdir_dir)
        storage_service.ensure_dir(settings.reports_dir)
        conn = db.connect(settings.db_path)
        try:
            db.init_db(conn)
        finally:
            conn.close()
        task_runner.start()

    return app


app = create_app()
