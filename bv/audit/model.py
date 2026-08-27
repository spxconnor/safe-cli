"""bv/audit/model.py - core data model: Event, SessionInfo, BacklogItem,
and the canonical event-type vocabulary.

All persisted data is JSON-serializable. Timestamps are ISO-8601 UTC.
Identifiers are UUIDv4 strings. Canonical JSON serialization is used
for hashing so that identical events always produce identical hashes.
"""
from __future__ import annotations

import datetime as _dt
import enum as _enum
import json as _json
import uuid as _uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


SCHEMA_VERSION = 1


def now_iso() -> str:
    """Current UTC time as ISO-8601 with 'Z' suffix."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def new_uuid() -> str:
    return str(_uuid.uuid4())


def new_session_id() -> str:
    """A session id uses the first 8 hex chars of a UUID plus a timestamp
    so the user can read it in logs. It is still globally unique.
    """
    u = _uuid.uuid4()
    return f"{u.hex[:8]}-{_dt.datetime.now(_dt.timezone.utc).strftime('%Y%m%dT%H%M%S')}"


class EventType(str, _enum.Enum):
    """Stable vocabulary of event types. Do NOT rename; new entries are
    additive only. Downstream tooling depends on the exact strings."""

    SESSION_STARTED = "session_started"
    SESSION_FINISHED = "session_finished"
    SESSION_RECOVERED = "session_recovered"

    BACKLOG_CREATED = "backlog_created"
    BACKLOG_UPDATED = "backlog_updated"
    BACKLOG_STARTED = "backlog_started"
    BACKLOG_BLOCKED = "backlog_blocked"
    BACKLOG_COMPLETED = "backlog_completed"
    BACKLOG_DEFERRED = "backlog_deferred"

    PHASE_STARTED = "phase_started"
    PHASE_FINISHED = "phase_finished"
    PHASE_FAILED = "phase_failed"
    PHASE_SKIPPED = "phase_skipped"

    BASELINE_STARTED = "baseline_started"
    BASELINE_FINISHED = "baseline_finished"

    COMMAND_STARTED = "command_started"
    COMMAND_FINISHED = "command_finished"
    COMMAND_FAILED = "command_failed"

    FILE_READ = "file_read"
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"

    TEST_STARTED = "test_started"
    TEST_PASSED = "test_passed"
    TEST_FAILED = "test_failed"
    TEST_SKIPPED = "test_skipped"
    TEST_PHASE_FINISHED = "test_phase_finished"

    SECURITY_CHECK_STARTED = "security_check_started"
    SECURITY_CHECK_PASSED = "security_check_passed"
    SECURITY_CHECK_FAILED = "security_check_failed"
    SECURITY_REGRESSION_DETECTED = "security_regression_detected"

    SMOKE_TEST_STARTED = "smoke_test_started"
    SMOKE_TEST_PASSED = "smoke_test_passed"
    SMOKE_TEST_FAILED = "smoke_test_failed"

    REPAIR_STARTED = "repair_started"
    REPAIR_CANDIDATE_CREATED = "repair_candidate_created"
    REPAIR_CANDIDATE_REJECTED = "repair_candidate_rejected"
    REPAIR_CANDIDATE_ACCEPTED = "repair_candidate_accepted"

    ARTIFACT_CREATED = "artifact_created"
    ARTIFACT_VERIFIED = "artifact_verified"
    ARTIFACT_HASH_MISMATCH = "artifact_hash_mismatch"

    SANDBOX_STARTED = "sandbox_started"
    SANDBOX_FINISHED = "sandbox_finished"
    SANDBOX_TIMEOUT = "sandbox_timeout"
    SANDBOX_CLEANUP_FAILED = "sandbox_cleanup_failed"

    GIT_STATUS = "git_status"
    GIT_DIFF = "git_diff"
    GIT_COMMIT = "git_commit"
    GIT_PUSH = "git_push"
    GIT_FAILURE = "git_failure"

    DEPENDENCY_DETECTED = "dependency_detected"
    ENVIRONMENT_DETECTED = "environment_detected"

    DECISION_MADE = "decision_made"
    WARNING = "warning"
    ERROR = "error"
    EXCEPTION = "exception"

    BACKUP_CREATED = "backup_created"
    BACKUP_VERIFIED = "backup_verified"

    DEFERRED_ITEM_CREATED = "deferred_item_created"
    LIMITATION_RECORDED = "limitation_recorded"
    AUDIT_COMPLETED = "audit_completed"


class Severity(str, _enum.Enum):
    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Event:
    """A single structured audit event. All persisted to JSONL.

    Required fields are filled by the writer. Optional fields are
    event-specific. The hash chain is computed by the writer (not the
    caller) so callers cannot accidentally desync the chain.
    """
    schema_version: int = SCHEMA_VERSION
    event_id: str = field(default_factory=new_uuid)
    session_id: str = ""
    timestamp: str = field(default_factory=now_iso)
    event_type: EventType = EventType.SESSION_STARTED
    severity: Severity = Severity.INFO
    component: str = ""
    message: str = ""
    # Optional fields used by specific event types
    command_id: Optional[str] = None
    argv: Optional[list] = None
    cwd: Optional[str] = None
    duration_ms: Optional[int] = None
    exit_code: Optional[int] = None
    path: Optional[str] = None
    operation: Optional[str] = None
    sha256_before: Optional[str] = None
    sha256_after: Optional[str] = None
    size_before: Optional[int] = None
    size_after: Optional[int] = None
    test_name: Optional[str] = None
    test_suite: Optional[str] = None
    failure_reason: Optional[str] = None
    artifact_id: Optional[str] = None
    artifact_sha256: Optional[str] = None
    parent_artifact_id: Optional[str] = None
    parent_artifact_sha256: Optional[str] = None
    branch: Optional[str] = None
    commit: Optional[str] = None
    remote_head: Optional[str] = None
    local_head: Optional[str] = None
    backlog_id: Optional[str] = None
    phase_id: Optional[str] = None
    invariant: Optional[str] = None
    expected: Optional[Any] = None
    actual: Optional[Any] = None
    result: Optional[str] = None
    # Arbitrary structured payload
    data: dict = field(default_factory=dict)
    # Hash chain (filled by writer)
    prev_event_hash: Optional[str] = None
    event_hash: Optional[str] = None

    def canonical_bytes(self) -> bytes:
        """Deterministic JSON representation for hashing.

        Excludes the event_hash itself (circular) and the prev_event_hash
        is included to chain events together.
        """
        d = asdict(self)
        # Strip fields that are filled AFTER serialization
        d.pop("event_hash", None)
        return _json.dumps(
            d,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def compute_hash(self, prev_event_hash: Optional[str]) -> str:
        """SHA-256 of the canonical event + the previous event hash."""
        import hashlib as _hl
        body = self.canonical_bytes()
        chain_input = body + (prev_event_hash or "").encode("utf-8")
        return _hl.sha256(chain_input).hexdigest()


class Priority(str, _enum.Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class BacklogStatus(str, _enum.Enum):
    BACKLOG = "BACKLOG"
    READY = "READY"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    PARTIALLY_COMPLETE = "PARTIALLY_COMPLETE"
    COMPLETE = "COMPLETE"
    DEFERRED = "DEFERRED"
    CANCELLED = "CANCELLED"


@dataclass
class BacklogItem:
    """A single engineering backlog item.

    Designed so a future coding agent can pick up exactly where the
    previous one left off: why the item exists, what it changes, what
    it protects, what remains.
    """
    id: str                                   # e.g. "P1-18"
    title: str
    description: str = ""
    priority: Priority = Priority.P1
    severity: Severity = Severity.NOTICE
    category: str = ""
    status: BacklogStatus = BacklogStatus.BACKLOG
    phase: str = ""
    milestone: str = ""
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    owner: str = ""
    source: str = ""
    parent: Optional[str] = None
    dependencies: list = field(default_factory=list)
    blocked_by: list = field(default_factory=list)
    files: list = field(default_factory=list)
    tests: list = field(default_factory=list)
    acceptance_criteria: list = field(default_factory=list)
    security_invariants: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    commit_ids: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    failure_count: int = 0
    attempt_count: int = 0
    related_event_ids: list = field(default_factory=list)
