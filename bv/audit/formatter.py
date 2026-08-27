"""bv/audit/formatter.py - human-readable summaries and per-event lines.

This module is read-only: it does not touch the filesystem, mutate
events, or write to the ledger. It accepts already-loaded events and
backlog items and produces dicts, single-line summaries, or a
multi-section human report. Persisting the report is the caller's job.

Design notes:
  - summarize_events is O(n) over the input list and never touches
    the ledger, so callers can call it as often as they like.
  - format_event produces a single deterministic line suitable for
    grep / awk pipelines.
  - human_session_report is opinionated but not configurable: the
    goal is one obvious layout that an operator can read top-to-
    bottom. Customisation belongs in the caller.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import Iterable

from .model import (
    Event,
    EventType,
    Severity,
    BacklogItem,
    BacklogStatus,
)


# Backlog statuses shown as their own section in the report. Anything
# not in this set (BACKLOG, CANCELLED) is folded into "Other".
_REPORT_STATUS_ORDER = (
    BacklogStatus.BACKLOG,
    BacklogStatus.READY,
    BacklogStatus.IN_PROGRESS,
    BacklogStatus.BLOCKED,
    BacklogStatus.FAILED,
    BacklogStatus.PARTIALLY_COMPLETE,
    BacklogStatus.COMPLETE,
    BacklogStatus.DEFERRED,
    BacklogStatus.CANCELLED,
)


def summarize_events(events: list) -> dict:
    """Aggregate counts over a list of events.

    The returned dict contains:
      - "total": number of events in the input
      - "by_type": {event_type.value: count}
      - "by_severity": {severity.value: count}
      - "test_passed": count of EventType.TEST_PASSED
      - "test_failed": count of EventType.TEST_FAILED
      - "files_modified": count of FILE_MODIFIED + FILE_CREATED
      - "commands_run": count of EventType.COMMAND_FINISHED
      - "regressions": count of SECURITY_REGRESSION_DETECTED
      - "deferred_count": count of DEFERRED_ITEM_CREATED
    """
    out = {
        "total": len(events),
        "by_type": {},
        "by_severity": {},
        "test_passed": 0,
        "test_failed": 0,
        "files_modified": 0,
        "commands_run": 0,
        "regressions": 0,
        "deferred_count": 0,
    }
    for e in events:
        # by_type: tolerate non-enum event_type (already-coerced strings).
        et_val = getattr(e.event_type, "value", str(e.event_type))
        out["by_type"][et_val] = out["by_type"].get(et_val, 0) + 1
        sv_val = getattr(e.severity, "value", str(e.severity))
        out["by_severity"][sv_val] = out["by_severity"].get(sv_val, 0) + 1
        if e.event_type == EventType.TEST_PASSED:
            out["test_passed"] += 1
        elif e.event_type == EventType.TEST_FAILED:
            out["test_failed"] += 1
        if e.event_type in (EventType.FILE_MODIFIED, EventType.FILE_CREATED):
            out["files_modified"] += 1
        if e.event_type == EventType.COMMAND_FINISHED:
            out["commands_run"] += 1
        if e.event_type == EventType.SECURITY_REGRESSION_DETECTED:
            out["regressions"] += 1
        if e.event_type == EventType.DEFERRED_ITEM_CREATED:
            out["deferred_count"] += 1
    return out


def format_event(e: Event) -> str:
    """Render a single event as a one-line summary.

    Format: [<timestamp>] <severity>: <component> | <message>
    Timestamps are taken verbatim from the event; the writer already
    produces ISO-8601 UTC with 'Z' suffix.
    """
    ts = e.timestamp or ""
    sv = getattr(e.severity, "value", str(e.severity))
    comp = e.component or ""
    msg = e.message or ""
    return f"[{ts}] {sv}: {comp} | {msg}"


def _group_backlog_by_status(items: list) -> "OrderedDict[BacklogStatus, list]":
    grouped: "OrderedDict[BacklogStatus, list]" = OrderedDict()
    for s in _REPORT_STATUS_ORDER:
        grouped[s] = []
    for it in items:
        grouped.setdefault(it.status, []).append(it)
    return grouped


def _format_backlog_line(item: BacklogItem) -> str:
    prio = getattr(item.priority, "value", str(item.priority))
    title = item.title or ""
    return f"  - {item.id}  [{prio}]  {title}"


def _format_duration_ms(ms) -> str:
    if ms is None:
        return "n/a"
    try:
        ms = int(ms)
    except (TypeError, ValueError):
        return "n/a"
    if ms < 1000:
        return f"{ms}ms"
    seconds = ms / 1000.0
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, secs = divmod(seconds, 60)
    return f"{int(minutes)}m{secs:.1f}s"


def human_session_report(
    events: list,
    backlog_items: list,
) -> str:
    """Produce a multi-section human-readable session report.

    Sections (in order):
      - Header: total event count, session id from first event
      - Backlog: items grouped by status (id, title, priority)
      - Phases: PHASE_STARTED/PHASE_FINISHED events with duration
      - Tests: pass/fail counts
      - Security: pass/fail + regression counts
      - Files: list of FILE_READ/CREATED/MODIFIED/DELETED paths
      - Commands: COMMAND_FINISHED count
      - Regressions: any SECURITY_REGRESSION_DETECTED events
      - Deferred: any DEFERRED_ITEM_CREATED events
      - Summary: one-line rollup
    """
    lines: list[str] = []
    summary = summarize_events(events)
    session_id = events[0].session_id if events else "(no events)"

    # --- Header ---
    lines.append("=" * 72)
    lines.append(f"SESSION REPORT  session_id={session_id}")
    lines.append("=" * 72)
    lines.append(
        f"Events: total={summary['total']}  "
        f"types={len(summary['by_type'])}  "
        f"severities={len(summary['by_severity'])}"
    )

    # --- Backlog ---
    lines.append("")
    lines.append("-- Backlog --")
    if not backlog_items:
        lines.append("  (no backlog items)")
    else:
        grouped = _group_backlog_by_status(backlog_items)
        any_listed = False
        for status, items_in_status in grouped.items():
            if not items_in_status:
                continue
            any_listed = True
            sv = getattr(status, "value", str(status))
            lines.append(f"  [{sv}] ({len(items_in_status)})")
            for it in items_in_status:
                lines.append(_format_backlog_line(it))
        if not any_listed:
            lines.append("  (no backlog items)")

    # --- Phases ---
    lines.append("")
    lines.append("-- Phases --")
    phase_events = [
        e for e in events
        if e.event_type in (EventType.PHASE_STARTED, EventType.PHASE_FINISHED,
                            EventType.PHASE_FAILED, EventType.PHASE_SKIPPED)
    ]
    if not phase_events:
        lines.append("  (no phase events)")
    else:
        for e in phase_events:
            et_val = getattr(e.event_type, "value", str(e.event_type))
            dur = _format_duration_ms(e.duration_ms)
            phase_id = e.phase_id or "-"
            lines.append(
                f"  - [{et_val}] phase_id={phase_id} duration={dur} :: {e.message}"
            )

    # --- Tests ---
    lines.append("")
    lines.append("-- Tests --")
    lines.append(
        f"  passed={summary['test_passed']}  failed={summary['test_failed']}"
    )
    failed_events = [e for e in events if e.event_type == EventType.TEST_FAILED]
    for e in failed_events[:10]:
        lines.append(f"  FAIL: {e.test_name or e.message}")

    # --- Security ---
    lines.append("")
    lines.append("-- Security --")
    sec_passed = sum(
        1 for e in events if e.event_type == EventType.SECURITY_CHECK_PASSED
    )
    sec_failed = sum(
        1 for e in events if e.event_type == EventType.SECURITY_CHECK_FAILED
    )
    lines.append(
        f"  passed={sec_passed}  failed={sec_failed}  "
        f"regressions={summary['regressions']}"
    )

    # --- Files ---
    lines.append("")
    lines.append("-- Files --")
    file_events = [
        e for e in events
        if e.event_type in (
            EventType.FILE_READ,
            EventType.FILE_CREATED,
            EventType.FILE_MODIFIED,
            EventType.FILE_DELETED,
        )
    ]
    if not file_events:
        lines.append("  (no file events)")
    else:
        for e in file_events:
            et_val = getattr(e.event_type, "value", str(e.event_type))
            lines.append(f"  - [{et_val}] {e.path or '<no-path>'}")

    # --- Commands ---
    lines.append("")
    lines.append("-- Commands --")
    lines.append(f"  finished={summary['commands_run']}")
    cmd_failed = [
        e for e in events if e.event_type == EventType.COMMAND_FAILED
    ]
    if cmd_failed:
        lines.append(f"  failed={len(cmd_failed)}")
        for e in cmd_failed[:5]:
            lines.append(f"    - exit={e.exit_code} :: {e.message}")

    # --- Regressions ---
    lines.append("")
    lines.append("-- Regressions --")
    regressions = [
        e for e in events
        if e.event_type == EventType.SECURITY_REGRESSION_DETECTED
    ]
    if not regressions:
        lines.append("  (none)")
    else:
        for e in regressions:
            lines.append(f"  - {e.invariant or '-'}: {e.message}")

    # --- Deferred ---
    lines.append("")
    lines.append("-- Deferred --")
    deferred = [
        e for e in events
        if e.event_type == EventType.DEFERRED_ITEM_CREATED
    ]
    if not deferred:
        lines.append("  (none)")
    else:
        for e in deferred:
            lines.append(f"  - {e.message}")

    # --- Summary line ---
    lines.append("")
    lines.append("-- Summary --")
    lines.append(
        f"  session={session_id}  events={summary['total']}  "
        f"tests_passed={summary['test_passed']}  "
        f"tests_failed={summary['test_failed']}  "
        f"files={summary['files_modified']}  "
        f"commands={summary['commands_run']}  "
        f"regressions={summary['regressions']}  "
        f"deferred={summary['deferred_count']}"
    )
    lines.append("=" * 72)
    return "\n".join(lines)


__all__ = [
    "summarize_events",
    "format_event",
    "human_session_report",
]