"""bv/audit/events.py - per-event-type schema validation.

Every event written to .audit/events.jsonl must satisfy the base schema
(common required fields) and the per-event-type schema (extra required
fields). This module is pure: validate_event() takes a dict or an Event
and returns (is_valid, errors). It does NOT touch the filesystem, so
readers, writers, and formatters can all use the same validation rule.

EVENT_SCHEMAS maps each EventType to a list of additional required field
names. Empty list means no extra requirements beyond the base fields.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any, Mapping

from .model import (
    Event,
    EventType,
    Severity,
    new_uuid,
    now_iso,
)


# Base fields every event must carry. Matches the set the ledger reader
# enforces (see bv/audit/reader.py:_REQUIRED_FIELDS).
REQUIRED_BASE_FIELDS = (
    "schema_version",
    "event_id",
    "session_id",
    "timestamp",
    "event_type",
    "severity",
    "component",
    "message",
)


# Per-event-type additional required field names. Empty list means
# "no additional requirements beyond the base fields". Spec is
# intentionally conservative; extend additively.
EVENT_SCHEMAS: dict[EventType, list[str]] = {
    # Command lifecycle
    EventType.COMMAND_FINISHED: ["command_id", "exit_code", "duration_ms"],
    # File operations
    EventType.FILE_MODIFIED: ["path", "operation"],
    # Test outcomes
    EventType.TEST_PASSED: ["test_name"],
    # Security checks
    EventType.SECURITY_CHECK_PASSED: ["invariant"],
    # Backlog completion
    EventType.BACKLOG_COMPLETED: ["backlog_id"],
}


def _coerce(event: Any) -> dict:
    """Normalize an Event dataclass or mapping into a plain dict view.

    Raises TypeError only if the input is something we genuinely cannot
    inspect (no __dict__ and not a mapping).
    """
    if isinstance(event, Mapping):
        return dict(event)
    if dataclasses_is_event_like(event):
        try:
            return asdict(event)
        except (TypeError, ValueError):
            pass
    if hasattr(event, "__dict__"):
        return dict(vars(event))
    raise TypeError(
        f"validate_event: cannot inspect object of type {type(event).__name__}"
    )


def dataclasses_is_event_like(obj: Any) -> bool:
    """True if obj is a dataclass instance (so asdict() will work)."""
    return hasattr(obj, "__dataclass_fields__")


def _parse_iso8601(ts: str) -> bool:
    """True if ts parses as ISO-8601. Accepts trailing 'Z' (UTC)."""
    if not isinstance(ts, str) or not ts:
        return False
    candidate = ts
    if ts.endswith("Z"):
        candidate = ts[:-1] + "+00:00"
    try:
        datetime.fromisoformat(candidate)
    except ValueError:
        return False
    return True


def validate_event(event: Any) -> tuple[bool, list[str]]:
    """Validate an event against the base + per-type schema.

    Returns (is_valid, errors) where errors is a list of human-readable
    strings describing each problem found. An empty errors list means
    the event is fully valid.

    Checks performed:
      - all REQUIRED_BASE_FIELDS are present
      - schema_version is an int
      - event_id is a non-empty string
      - session_id is a non-empty string
      - timestamp parses as ISO-8601
      - event_type is a known EventType
      - severity is a known Severity
      - component is a non-empty string
      - message is a string
      - per-event-type extra required fields (EVENT_SCHEMAS) are present
    """
    errors: list[str] = []

    try:
        obj = _coerce(event)
    except TypeError as e:
        return False, [str(e)]

    # Required base fields present
    for field_name in REQUIRED_BASE_FIELDS:
        if field_name not in obj or obj[field_name] is None:
            errors.append(f"missing required field: {field_name}")
    if errors:
        return False, errors

    # schema_version must be an int
    if not isinstance(obj["schema_version"], int):
        errors.append(
            "schema_version must be int, got "
            f"{type(obj['schema_version']).__name__}"
        )

    # event_id must be a non-empty string
    eid = obj["event_id"]
    if not isinstance(eid, str) or not eid:
        errors.append("event_id must be a non-empty string")

    # session_id must be a non-empty string
    sid = obj["session_id"]
    if not isinstance(sid, str) or not sid:
        errors.append("session_id must be a non-empty string")

    # timestamp must parse as ISO-8601
    ts = obj["timestamp"]
    if not _parse_iso8601(ts):
        errors.append(f"timestamp does not parse as ISO-8601: {ts!r}")

    # event_type must be a known EventType
    et_raw = obj["event_type"]
    et_enum: EventType | None = None
    try:
        et_enum = EventType(et_raw)
    except (ValueError, KeyError):
        errors.append(f"unknown event_type: {et_raw!r}")

    # severity must be a known Severity
    sev_raw = obj["severity"]
    try:
        Severity(sev_raw)
    except (ValueError, KeyError):
        errors.append(f"unknown severity: {sev_raw!r}")

    # component must be a non-empty string
    comp = obj["component"]
    if not isinstance(comp, str) or not comp:
        errors.append("component must be a non-empty string")

    # message must be a string
    msg = obj["message"]
    if not isinstance(msg, str):
        errors.append(
            f"message must be a string, got {type(msg).__name__}"
        )

    # Per-event-type additional required fields (only if event_type resolved)
    if et_enum is not None:
        for fname in EVENT_SCHEMAS.get(et_enum, []):
            if fname not in obj or obj[fname] is None:
                errors.append(
                    f"missing required field for {et_enum.value}: {fname}"
                )

    return (len(errors) == 0, errors)


__all__ = [
    "EventType",
    "Severity",
    "Event",
    "now_iso",
    "new_uuid",
    "REQUIRED_BASE_FIELDS",
    "EVENT_SCHEMAS",
    "validate_event",
]