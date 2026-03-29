from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from uuid import uuid4


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return uuid4().hex


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS artifacts (
          id TEXT PRIMARY KEY,
          sha256 TEXT NOT NULL UNIQUE,
          original_filename TEXT NOT NULL,
          size_bytes INTEGER NOT NULL,
          uploaded_at TEXT NOT NULL,
          storage_path TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tasks (
          id TEXT PRIMARY KEY,
          artifact_id TEXT NOT NULL,
          status TEXT NOT NULL,
          created_at TEXT NOT NULL,
          started_at TEXT,
          finished_at TEXT,
          engine_version TEXT NOT NULL,
          ruleset_version TEXT NOT NULL,
          summary_json TEXT,
          error_message TEXT,
          FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
        );

        CREATE TABLE IF NOT EXISTS findings (
          id TEXT PRIMARY KEY,
          task_id TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          category TEXT NOT NULL,
          severity TEXT NOT NULL,
          confidence REAL NOT NULL,
          file_path TEXT NOT NULL,
          line_range TEXT,
          snippet_redacted TEXT,
          evidence_json TEXT NOT NULL,
          recommendation TEXT NOT NULL,
          FOREIGN KEY (task_id) REFERENCES tasks(id)
        );
        """
    )
    conn.commit()


@dataclass(frozen=True)
class ArtifactRow:
    id: str
    sha256: str
    original_filename: str
    size_bytes: int
    uploaded_at: str
    storage_path: str


@dataclass(frozen=True)
class TaskRow:
    id: str
    artifact_id: str
    status: str
    created_at: str
    started_at: Optional[str]
    finished_at: Optional[str]
    engine_version: str
    ruleset_version: str
    summary_json: Optional[str]
    error_message: Optional[str]


@dataclass(frozen=True)
class FindingRow:
    id: str
    task_id: str
    rule_id: str
    category: str
    severity: str
    confidence: float
    file_path: str
    line_range: Optional[str]
    snippet_redacted: Optional[str]
    evidence_json: str
    recommendation: str


def insert_artifact(
    conn: sqlite3.Connection,
    *,
    sha256: str,
    original_filename: str,
    size_bytes: int,
    storage_path: str,
) -> ArtifactRow:
    row = ArtifactRow(
        id=new_id(),
        sha256=sha256,
        original_filename=original_filename,
        size_bytes=size_bytes,
        uploaded_at=now_iso(),
        storage_path=storage_path,
    )
    conn.execute(
        """
        INSERT INTO artifacts (id, sha256, original_filename, size_bytes, uploaded_at, storage_path)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            row.id,
            row.sha256,
            row.original_filename,
            row.size_bytes,
            row.uploaded_at,
            row.storage_path,
        ),
    )
    conn.commit()
    return row


def insert_task(
    conn: sqlite3.Connection,
    *,
    artifact_id: str,
    engine_version: str,
    ruleset_version: str,
) -> TaskRow:
    row = TaskRow(
        id=new_id(),
        artifact_id=artifact_id,
        status="queued",
        created_at=now_iso(),
        started_at=None,
        finished_at=None,
        engine_version=engine_version,
        ruleset_version=ruleset_version,
        summary_json=None,
        error_message=None,
    )
    conn.execute(
        """
        INSERT INTO tasks (id, artifact_id, status, created_at, started_at, finished_at, engine_version, ruleset_version, summary_json, error_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            row.id,
            row.artifact_id,
            row.status,
            row.created_at,
            row.started_at,
            row.finished_at,
            row.engine_version,
            row.ruleset_version,
            row.summary_json,
            row.error_message,
        ),
    )
    conn.commit()
    return row


def update_task_status(
    conn: sqlite3.Connection,
    *,
    task_id: str,
    status: str,
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
    summary: Optional[dict[str, Any]] = None,
    error_message: Optional[str] = None,
) -> None:
    summary_json = json.dumps(summary, ensure_ascii=False) if summary is not None else None
    conn.execute(
        """
        UPDATE tasks
        SET status = ?,
            started_at = COALESCE(?, started_at),
            finished_at = COALESCE(?, finished_at),
            summary_json = COALESCE(?, summary_json),
            error_message = COALESCE(?, error_message)
        WHERE id = ?
        """,
        (status, started_at, finished_at, summary_json, error_message, task_id),
    )
    conn.commit()


def replace_task_findings(conn: sqlite3.Connection, *, task_id: str, findings: Iterable[FindingRow]) -> None:
    conn.execute("DELETE FROM findings WHERE task_id = ?", (task_id,))
    conn.executemany(
        """
        INSERT INTO findings (id, task_id, rule_id, category, severity, confidence, file_path, line_range, snippet_redacted, evidence_json, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                f.id,
                f.task_id,
                f.rule_id,
                f.category,
                f.severity,
                f.confidence,
                f.file_path,
                f.line_range,
                f.snippet_redacted,
                f.evidence_json,
                f.recommendation,
            )
            for f in findings
        ],
    )
    conn.commit()


def get_task(conn: sqlite3.Connection, task_id: str) -> Optional[TaskRow]:
    r = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if not r:
        return None
    return TaskRow(**dict(r))


def get_artifact(conn: sqlite3.Connection, artifact_id: str) -> Optional[ArtifactRow]:
    r = conn.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
    if not r:
        return None
    return ArtifactRow(**dict(r))


def get_artifact_by_sha(conn: sqlite3.Connection, sha256: str) -> Optional[ArtifactRow]:
    r = conn.execute("SELECT * FROM artifacts WHERE sha256 = ?", (sha256,)).fetchone()
    if not r:
        return None
    return ArtifactRow(**dict(r))


def list_tasks(conn: sqlite3.Connection, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, status, created_at, summary_json
        FROM tasks
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()
    items: list[dict[str, Any]] = []
    for r in rows:
        summary = json.loads(r["summary_json"]) if r["summary_json"] else None
        items.append(
            {
                "id": r["id"],
                "status": r["status"],
                "created_at": r["created_at"],
                "conclusion": summary.get("conclusion") if isinstance(summary, dict) else None,
                "level": summary.get("level") if isinstance(summary, dict) else None,
            }
        )
    return items


def list_findings(conn: sqlite3.Connection, *, task_id: str, limit: int = 500, offset: int = 0) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, rule_id, category, severity, confidence, file_path, line_range, snippet_redacted, evidence_json, recommendation
        FROM findings
        WHERE task_id = ?
        ORDER BY
          CASE severity
            WHEN 'Critical' THEN 0
            WHEN 'High' THEN 1
            WHEN 'Medium' THEN 2
            WHEN 'Low' THEN 3
            ELSE 4
          END,
          id
        LIMIT ? OFFSET ?
        """,
        (task_id, limit, offset),
    ).fetchall()
    items: list[dict[str, Any]] = []
    for r in rows:
        items.append(
            {
                "id": r["id"],
                "rule_id": r["rule_id"],
                "category": r["category"],
                "severity": r["severity"],
                "confidence": r["confidence"],
                "file_path": r["file_path"],
                "line_range": r["line_range"],
                "snippet_redacted": r["snippet_redacted"],
                "evidence": json.loads(r["evidence_json"]),
                "recommendation": r["recommendation"],
            }
        )
    return items
