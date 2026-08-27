"""bv/audit/writer.py - append-only event writer with concurrency safety.

The writer maintains:
  - .audit/events.jsonl       (append-only event ledger, tamper-evident)
  - .audit/sessions/<sid>.json (per-session record)
  - .audit/commands/<id>/{stdout,stderr}.log (command outputs)
  - .audit/reports/<id>.json  (named reports)
  - .audit/backlog.json        (small state file; rewritten atomically)

Concurrency: we use a single lock (thread + file lock) to serialize
writes. The lock lives in a side file; fcntl where available, fallback
to a soft lock. Reads are unlocked.
"""
from __future__ import annotations

import errno
import fcntl
import json as _json
import os
import tempfile
import threading
import time as _time
import uuid as _uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Optional

from .model import Event, now_iso
from .redaction import redact_text, redact_argv, redact_environment


_AUDIT_DIRNAME = ".audit"
_LOCK_FILENAME = ".audit.lock"


class AuditDirectory:
    """Locates and creates the persistent audit directory layout.

    Convention: <root>/.audit/{events.jsonl, backlog.json, sessions/, ...}
    The root defaults to the current working directory unless overridden.
    """

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root else Path.cwd()
        self.path = self.root / _AUDIT_DIRNAME

    def ensure(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        (self.path / "sessions").mkdir(exist_ok=True)
        (self.path / "commands").mkdir(exist_ok=True)
        (self.path / "reports").mkdir(exist_ok=True)
        (self.path / "artifacts").mkdir(exist_ok=True)
        (self.path / "backups").mkdir(exist_ok=True)

    # Common path accessors
    @property
    def events_file(self) -> Path:
        return self.path / "events.jsonl"

    @property
    def backlog_file(self) -> Path:
        return self.path / "backlog.json"

    @property
    def lock_file(self) -> Path:
        return self.path / _LOCK_FILENAME

    def session_dir(self, session_id: str) -> Path:
        return self.path / "sessions" / session_id

    def command_dir(self, command_id: str) -> Path:
        return self.path / "commands" / command_id

    def report_path(self, name: str) -> Path:
        if not name.endswith(".json"):
            name = name + ".json"
        return self.path / "reports" / name

    def artifact_dir(self, artifact_id: str) -> Path:
        return self.path / "artifacts" / artifact_id


# Single-process in-process lock. Cross-process lock is fcntl below.
_INPROC_LOCK = threading.Lock()


@contextmanager
def _file_lock(path: Path, exclusive: bool = True):
    """Best-effort cross-process file lock. Falls back to no-op if fcntl
    is not available (Windows). The in-process lock still serializes
    within one process.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        except (OSError, AttributeError):
            pass  # Soft fallback; in-process lock still provides safety.
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception:
            pass
        os.close(fd)


class AuditWriter:
    """Append-only event writer.

    Each event is JSON-serialized, redacted, hashed (linked to the
    previous event hash), and appended atomically. Crashes leave the
    ledger consistent (last partial line, if any, is detected and
    ignored on read).
    """

    def __init__(self, audit_dir: AuditDirectory, session_id: str) -> None:
        self.audit_dir = audit_dir
        self.session_id = session_id
        self.audit_dir.ensure()
        self._last_hash: Optional[str] = None
        self._load_last_hash()
        self._cmd_count = 0

    def _load_last_hash(self) -> None:
        """Recover the last event hash from a previous session (or this
        session) so the chain can be extended. Reads the last non-empty
        line; tolerates partial / truncated trailing lines (a crash)."""
        ef = self.audit_dir.events_file
        if not ef.exists():
            return
        try:
            with _INPROC_LOCK, _file_lock(self.audit_dir.lock_file):
                with ef.open("rb") as f:
                    # Seek to last ~64KB to avoid reading huge files
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - 65536))
                    data = f.read().decode("utf-8", errors="replace")
                # Find the last complete JSON line
                lines = [ln for ln in data.splitlines() if ln.strip()]
                if not lines:
                    return
                try:
                    obj = _json.loads(lines[-1])
                    self._last_hash = obj.get("event_hash")
                except _json.JSONDecodeError:
                    return
        except OSError:
            return

    def _next_command_id(self) -> str:
        self._cmd_count += 1
        return f"cmd-{self.session_id[:8]}-{self._cmd_count:04d}"

    def _compute_hash(self, event: Event) -> str:
        return event.compute_hash(self._last_hash)

    def _append_event(self, event: Event) -> Event:
        # Redact just before persisting. We do NOT mutate the caller's
        # event in place (Event is a dataclass, may be shared).
        e2 = Event(**{**event.__dict__})
        if isinstance(e2.message, str):
            e2.message = redact_text(e2.message) or ""
        if e2.argv:
            e2.argv = redact_argv(e2.argv) or []
        if e2.data:
            e2.data = _redact_dict(e2.data)
        if e2.expected is not None and isinstance(e2.expected, str):
            e2.expected = redact_text(e2.expected)
        if e2.actual is not None and isinstance(e2.actual, str):
            e2.actual = redact_text(e2.actual)
        e2.prev_event_hash = self._last_hash
        e2.event_hash = self._compute_hash(e2)
        line = _json.dumps(e2.__dict__, sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=False)
        # Atomic append: open in append mode, write, fsync, close
        ef = self.audit_dir.events_file
        with _INPROC_LOCK, _file_lock(self.audit_dir.lock_file):
            with ef.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
        self._last_hash = e2.event_hash
        return e2

    def emit(self, event: Event) -> Event:
        if not event.session_id:
            event.session_id = self.session_id
        return self._append_event(event)

    def record_command(
        self,
        *,
        argv: list,
        cwd: str,
        exit_code: int,
        duration_ms: int,
        timed_out: bool = False,
        stdout_text: str = "",
        stderr_text: str = "",
        command_id: Optional[str] = None,
        event_type_started: Optional[Any] = None,
        event_type_finished: Optional[Any] = None,
    ) -> tuple:
        """Convenience: persist the full command lifecycle (start +
        finished/failed) and store stdout/stderr on disk.

        Returns (started_event, finished_event, command_id)."""
        from .model import EventType  # local import to avoid cycle at import
        ev_start = EventType.COMMAND_STARTED if event_type_started is None else event_type_started
        ev_end = EventType.COMMAND_FINISHED if event_type_finished is None else event_type_finished
        cid = command_id or self._next_command_id()
        # Redact argv before storing anywhere
        red_argv = redact_argv(argv) or []
        # Persist stdout/stderr to disk (they may be large; we keep
        # them off the JSONL to avoid blowing the ledger up)
        self.audit_dir.ensure()
        cdir = self.audit_dir.command_dir(cid)
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / "argv.json").write_text(
            _json.dumps({"argv": red_argv, "cwd": cwd}, indent=2),
            encoding="utf-8",
        )
        # Redact before writing logs
        red_stdout = redact_text(stdout_text) or ""
        red_stderr = redact_text(stderr_text) or ""
        (cdir / "stdout.log").write_text(red_stdout, encoding="utf-8")
        (cdir / "stderr.log").write_text(red_stderr, encoding="utf-8")
        import hashlib as _hl
        stdout_hash = _hl.sha256(red_stdout.encode("utf-8")).hexdigest()
        stderr_hash = _hl.sha256(red_stderr.encode("utf-8")).hexdigest()
        started = Event(
            event_type=ev_start,
            component="command",
            message=f"$ {' '.join(red_argv)}",
            command_id=cid,
            argv=red_argv,
            cwd=cwd,
            session_id=self.session_id,
        )
        started = self.emit(started)
        finished_evt_type = ev_end
        finished_sev = None
        if exit_code != 0 or timed_out:
            finished_evt_type = EventType.COMMAND_FAILED
        finished = Event(
            event_type=finished_evt_type,
            severity=(None if finished_evt_type == EventType.COMMAND_FINISHED
                      else (EventType.COMMAND_FAILED and None)),
            component="command",
            message=f"exit={exit_code} duration_ms={duration_ms}",
            command_id=cid,
            argv=red_argv,
            cwd=cwd,
            exit_code=exit_code,
            duration_ms=duration_ms,
            timed_out=timed_out,
            stdout_hash=stdout_hash,
            stderr_hash=stderr_hash,
            data={
                "stdout_path": str((cdir / "stdout.log").relative_to(self.audit_dir.path)),
                "stderr_path": str((cdir / "stderr.log").relative_to(self.audit_dir.path)),
            },
            session_id=self.session_id,
        )
        # Mark severity properly
        if finished_evt_type == EventType.COMMAND_FAILED:
            from .model import Severity
            finished.severity = Severity.WARNING
        finished = self.emit(finished)
        return started, finished, cid


def _redact_dict(d: dict) -> dict:
    out = {}
    for k, v in d.items():
        if isinstance(v, str):
            out[k] = redact_text(v) or ""
        elif isinstance(v, dict):
            out[k] = _redact_dict(v)
        elif isinstance(v, list):
            out[k] = [
                (redact_text(x) if isinstance(x, str) else
                 _redact_dict(x) if isinstance(x, dict) else x)
                for x in v
            ]
        else:
            out[k] = v
    return out
