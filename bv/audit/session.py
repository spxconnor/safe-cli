"""bv/audit/session.py - session lifecycle management.

A Session represents one end-to-end invocation of the safe-cli runner.
Its responsibilities:
  - snapshot the runtime environment (platform, python, docker, git HEAD)
  - emit SESSION_STARTED through the injected AuditWriter
  - persist a per-session record to .audit/sessions/<session_id>.json
  - on end(), emit SESSION_FINISHED and stamp the record with status

CrashRecovery runs at runner startup: it scans .audit/sessions/*.json
for entries that were started but never ended (i.e. no "status" field)
and marks them ABORTED. This is how we recover state from a process
that died mid-run.

Persistence boundary:
  - Events go through writer.emit() (concurrency-safe, hash-chained).
  - The per-session metadata file is written through writer.audit_dir
    paths using an atomic temp-file + rename. We do not open arbitrary
    filesystem paths; everything resolves under writer.audit_dir.path.
"""
from __future__ import annotations

import json as _json
import os
import platform
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from .model import (
    Event,
    EventType,
    Severity,
    new_session_id,
    now_iso,
)


class SessionStatus:
    """Terminal statuses accepted by Session.end().

    Constants live on the class so callers can write SessionStatus.SUCCESS
    and so the frozenset below is the single source of truth.
    """
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"
    ABORTED = "ABORTED"
    VALID_STATUSES = frozenset({SUCCESS, FAILED, PARTIAL, BLOCKED, ABORTED})


@dataclass
class SessionInfo:
    """Persistent record of a single safe-cli session.

    Written to .audit/sessions/<session_id>.json. The status field is
    added when the session is ended; a session file with no status
    field is considered "open" and is recovered by CrashRecovery.
    """
    session_id: str
    started_at: str
    env_detected: str = ""
    docker_version: str = ""
    head_commit: str = ""
    current_branch: str = ""
    python_version: str = ""
    status: Optional[str] = None
    finished_at: Optional[str] = None
    summary: Optional[str] = None


def _try_run(
    argv: list[str],
    *,
    cwd: Optional[str] = None,
    timeout: float = 2.0,
) -> str:
    """Best-effort subprocess. Returns stdout stripped, or "" on any
    failure (non-zero exit, timeout, file-not-found, OS error)."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout,
        )
    except Exception:
        return ""
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def _atomic_write_json(path: Path, obj: dict) -> None:
    """Write obj as JSON to path atomically (tempfile + os.replace)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=".session.",
        suffix=".json.tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            _json.dump(obj, f, sort_keys=True, indent=2, ensure_ascii=False)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _session_severity(status: str) -> Severity:
    """Map a SessionStatus to the severity of its SESSION_FINISHED event."""
    if status == SessionStatus.SUCCESS:
        return Severity.INFO
    if status in (SessionStatus.PARTIAL, SessionStatus.BLOCKED):
        return Severity.WARNING
    # FAILED, ABORTED
    return Severity.ERROR


class Session:
    """Represents one safe-cli session. Owns the injected AuditWriter."""

    def __init__(self, audit_dir, writer, session_id: Optional[str] = None) -> None:
        # The writer is the canonical persistence boundary; we resolve
        # all filesystem paths from writer.audit_dir.
        self.writer = writer
        self.audit_dir = writer.audit_dir
        self.audit_dir.ensure()
        self.session_id = session_id or new_session_id()

        # Snapshot the environment. Every probe is best-effort: a missing
        # tool (docker, git) must not break session startup.
        env_detected = f"{platform.system()} {platform.release()}".strip()
        docker_version = _try_run(["docker", "--version"])
        root = self.audit_dir.root
        head_commit = _try_run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
        )
        current_branch = _try_run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(root),
        )
        python_version = sys.version.split()[0] if sys.version else ""

        self.info = SessionInfo(
            session_id=self.session_id,
            started_at=now_iso(),
            env_detected=env_detected,
            docker_version=docker_version,
            head_commit=head_commit,
            current_branch=current_branch,
            python_version=python_version,
        )

        # Persist the per-session record (.audit/sessions/<sid>.json).
        # No status yet — CrashRecovery will treat this as "open" if the
        # process dies before end() is called.
        _atomic_write_json(self._session_path(), asdict(self.info))

        # Emit SESSION_STARTED through the writer (hash-chained, redacted).
        started = Event(
            event_type=EventType.SESSION_STARTED,
            severity=Severity.INFO,
            component="session",
            message=f"session started: {self.session_id}",
            session_id=self.session_id,
            data={
                "env_detected": env_detected,
                "docker_version": docker_version,
                "head_commit": head_commit,
                "current_branch": current_branch,
                "python_version": python_version,
            },
        )
        self.writer.emit(started)

    # ----- path helpers ---------------------------------------------------

    def _session_path(self) -> Path:
        return self.audit_dir.path / "sessions" / f"{self.session_id}.json"

    # ----- lifecycle ------------------------------------------------------

    def end(self, status: str, summary: Optional[str] = None) -> Event:
        """Close the session. Validates status against VALID_STATUSES,
        emits SESSION_FINISHED with summary as data, and updates the
        per-session record with status/finished_at/summary."""
        if status not in SessionStatus.VALID_STATUSES:
            raise ValueError(
                f"invalid session status: {status!r} "
                f"(allowed: {sorted(SessionStatus.VALID_STATUSES)})"
            )

        self.info.status = status
        self.info.finished_at = now_iso()
        self.info.summary = summary
        _atomic_write_json(self._session_path(), asdict(self.info))

        finished = Event(
            event_type=EventType.SESSION_FINISHED,
            severity=_session_severity(status),
            component="session",
            message=f"session {status.lower()}: {self.session_id}",
            session_id=self.session_id,
            data={"status": status, "summary": summary or ""},
        )
        return self.writer.emit(finished)

    # ----- delegation helpers --------------------------------------------

    def record_event(
        self,
        event_type: EventType,
        *,
        severity: Severity = Severity.INFO,
        component: str = "session",
        message: str = "",
        **fields: Any,
    ) -> Event:
        """Emit an arbitrary event tied to this session. Delegates to the
        writer so the hash chain stays intact."""
        ev = Event(
            event_type=event_type,
            severity=severity,
            component=component,
            message=message,
            session_id=self.session_id,
            **fields,
        )
        return self.writer.emit(ev)

    def record_command(self, **kwargs: Any) -> tuple:
        """Delegate to AuditWriter.record_command with this session."""
        return self.writer.record_command(**kwargs)


class CrashRecovery:
    """Find sessions that were started but never ended and mark them
    ABORTED. Operates directly on .audit/sessions/*.json files; no
    writer is required because we are not appending new audit events,
    only updating existing session metadata."""

    def __init__(self, audit_dir) -> None:
        self.audit_dir = audit_dir

    def _sessions_dir(self) -> Path:
        return self.audit_dir.path / "sessions"

    def find_open_sessions(self) -> list[dict]:
        """Return session records that have no 'status' field."""
        out: list[dict] = []
        sdir = self._sessions_dir()
        if not sdir.exists():
            return out
        for p in sorted(sdir.glob("*.json")):
            try:
                obj = _json.loads(p.read_text(encoding="utf-8"))
            except (OSError, _json.JSONDecodeError):
                continue
            if isinstance(obj, dict) and "status" not in obj:
                obj["_path"] = str(p)
                out.append(obj)
        return out

    def recover_one(self, session_id: str) -> Optional[dict]:
        """Mark the named session as ABORTED and return the updated
        record. Returns None if no session file exists for session_id
        or the file is unreadable."""
        path = self._sessions_dir() / f"{session_id}.json"
        if not path.exists():
            return None
        try:
            obj = _json.loads(path.read_text(encoding="utf-8"))
        except (OSError, _json.JSONDecodeError):
            return None
        if not isinstance(obj, dict):
            return None
        obj["status"] = SessionStatus.ABORTED
        obj["finished_at"] = obj.get("finished_at") or now_iso()
        obj["summary"] = obj.get("summary") or "recovered after crash"
        _atomic_write_json(path, obj)
        return obj


__all__ = [
    "SessionStatus",
    "SessionInfo",
    "Session",
    "CrashRecovery",
]