"""bv/audit/__init__.py - public API for the audit and backlog subsystem.

The audit system provides:
  - append-only structured event ledger (JSONL) at .audit/events.jsonl
  - backlog state machine (bv/audit/backlog.py)
  - session lifecycle (bv/audit/session.py)
  - tamper-evident event chain (each event includes prev_event_hash)
  - central redaction (bv/audit/redaction.py)
  - CLI commands (bv/audit/__init__.py re-exports)
"""
from .model import (
    Event,
    EventType,
    Severity,
    BacklogItem,
    BacklogStatus,
    Priority,
    now_iso,
    new_uuid,
    new_session_id,
)
from .redaction import redact_text, redact_argv, redact_environment
from .writer import AuditWriter, AuditDirectory
from .reader import AuditReader, verify_chain
from .backlog import Backlog, BacklogError, InvalidTransition, validate_transition
from .session import Session, CrashRecovery, SessionStatus
from .events import validate_event, EVENT_SCHEMAS
from .formatter import summarize_events, format_event, human_session_report

__all__ = [
    "Event",
    "EventType",
    "Severity",
    "BacklogItem",
    "BacklogStatus",
    "Priority",
    "now_iso",
    "new_uuid",
    "new_session_id",
    "redact_text",
    "redact_argv",
    "redact_environment",
    "AuditWriter",
    "AuditDirectory",
    "AuditReader",
    "verify_chain",
    "Backlog",
    "BacklogError",
    "InvalidTransition",
    "validate_transition",
    "Session",
    "CrashRecovery",
    "SessionStatus",
    "validate_event",
    "EVENT_SCHEMAS",
    "summarize_events",
    "format_event",
    "human_session_report",
]
