"""bv/quoting/toctou.py — TOCTOU file-change protection + repair loop guard.

Spec section 23:
    Before writing a repair:
        capture original hash
    Immediately before writing:
        hash current file
    If different:
        ABORT REPAIR
        FILE CHANGED EXTERNALLY
    Never overwrite concurrent user or agent work.

Spec section 24:
    Prevent infinite self repair. Configure:
        maximum attempts
        maximum repeated identical failures
        maximum total repair time

This module exposes:

    class FileChangeGuard
        capture(path) -> sha256
        verify_unchanged(path, expected) -> bool
        diff(path, expected) -> str | None

    class RepairLoopGuard
        record_attempt(diagnostics_hash) -> bool    # False = must stop
        record_failure(reason) -> bool              # False = must stop
        reset() -> None

The intent is that callers capture the hash at READ-TIME and verify at
WRITE-TIME. The checks are cheap (sha256 of bytes) and side-effect free.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Optional


def _hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _hash_path(path: str) -> str:
    with open(path, "rb") as f:
        return _hash_bytes(f.read())


@dataclass(frozen=True)
class FileSnapshot:
    """A point-in-time snapshot of a file's content hash + metadata."""
    path: str
    sha256: str
    size: int
    mtime_ns: int

    @classmethod
    def capture(cls, path: str) -> "FileSnapshot":
        st = os.stat(path)
        return cls(
            path=path,
            sha256=_hash_path(path),
            size=st.st_size,
            mtime_ns=st.st_mtime_ns,
        )

    def matches(self, other: "FileSnapshot") -> bool:
        return (
            self.path == other.path
            and self.sha256 == other.sha256
            and self.size == other.size
            and self.mtime_ns == other.mtime_ns
        )


def verify_unchanged_since(path: str, expected: FileSnapshot) -> Optional[str]:
    """Return None if `path` matches `expected`; else an explanation string."""
    if not os.path.exists(path):
        return f"file removed: {path}"
    current = FileSnapshot.capture(path)
    if current.sha256 != expected.sha256:
        return (
            f"hash mismatch: expected={expected.sha256[:12]} "
            f"actual={current.sha256[:12]}"
        )
    if current.size != expected.size:
        return (
            f"size changed: expected={expected.size} actual={current.size}"
        )
    if current.mtime_ns != expected.mtime_ns:
        return (
            f"mtime changed: expected_ns={expected.mtime_ns} actual_ns={current.mtime_ns}"
        )
    return None


# ---------------------------------------------------------------------------
# RepairLoopGuard
# ---------------------------------------------------------------------------


@dataclass
class RepairLoopGuard:
    """Guards against infinite repair loops.

    Spec section 24:
        maximum attempts
        maximum repeated identical failures
        maximum total repair time
    """

    max_attempts: int = 5
    max_repeated_failures: int = 3
    max_total_seconds: float = 60.0

    _attempts: int = 0
    _failures: int = 0
    _started_at: float = field(default_factory=time.monotonic)
    _diagnostics_history: list = field(default_factory=list)

    def reset(self) -> None:
        self._attempts = 0
        self._failures = 0
        self._started_at = time.monotonic()
        self._diagnostics_history.clear()

    def can_continue(self) -> bool:
        if self._attempts >= self.max_attempts:
            return False
        if self._failures >= self.max_repeated_failures:
            return False
        if (time.monotonic() - self._started_at) > self.max_total_seconds:
            return False
        return True

    def record_attempt(self, diagnostics_signature: Optional[str] = None) -> bool:
        """Record one attempt. Returns False iff the caller MUST stop.

        If a diagnostics signature is repeated max_repeated_failures in
        a row, the guard returns False (oscillation / no progress).
        """
        self._attempts += 1
        if diagnostics_signature is not None:
            self._diagnostics_history.append(diagnostics_signature)
            # Count consecutive identical signatures at the tail.
            tail_count = 0
            for sig in reversed(self._diagnostics_history):
                if sig == diagnostics_signature:
                    tail_count += 1
                else:
                    break
            if tail_count >= self.max_repeated_failures:
                return False
        return self.can_continue()

    def record_failure(self) -> bool:
        """Record one failure. Returns True iff the caller may continue."""
        self._failures += 1
        return self.can_continue()

    def status(self) -> Dict[str, object]:
        return {
            "attempts": self._attempts,
            "failures": self._failures,
            "elapsed_seconds": round(time.monotonic() - self._started_at, 3),
            "can_continue": self.can_continue(),
            "max_attempts": self.max_attempts,
            "max_repeated_failures": self.max_repeated_failures,
            "max_total_seconds": self.max_total_seconds,
        }
