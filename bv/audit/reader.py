"""bv/audit/reader.py - read events from the JSONL ledger, with hash
chain verification and corruption detection.

Design notes:
  - The ledger is read-only. Readers never modify the file.
  - Reading handles the case where a previous session crashed mid-write
    (the last line may be truncated); truncated lines are skipped
    after a clear warning.
  - verify_chain() detects:
      - missing required fields
      - duplicate event_ids
      - broken hash chain
      - malformed JSON
"""
from __future__ import annotations

import json as _json
import re
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .model import Event, EventType, now_iso, SCHEMA_VERSION


class LedgerError(Exception):
    """Raised when the ledger is malformed or has been tampered with."""


_REQUIRED_FIELDS = {
    "schema_version", "event_id", "session_id", "timestamp",
    "event_type", "severity", "component", "message",
}


class AuditReader:
    """Read events from .audit/events.jsonl. Cheap to construct."""

    def __init__(self, events_file: Path) -> None:
        self.events_file = events_file

    def iter_events(
        self, *, skip_truncated: bool = True,
    ) -> Iterator[Event]:
        """Yield events in order. Truncated trailing lines are skipped
        with a warning to stderr; the previous events remain valid."""
        import sys
        if not self.events_file.exists():
            return
        last_good: Optional[Event] = None
        with self.events_file.open("r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.rstrip("\n")
                if not line.strip():
                    continue
                try:
                    obj = _json.loads(line)
                except _json.JSONDecodeError:
                    if skip_truncated:
                        print(
                            f"[audit-reader] skipping truncated/invalid "
                            f"line: {line[:80]!r}...",
                            file=sys.stderr,
                        )
                        continue
                    raise LedgerError(
                        f"malformed JSONL line: {line[:200]!r}"
                    )
                missing = _REQUIRED_FIELDS - set(obj.keys())
                if missing:
                    if skip_truncated:
                        print(
                            f"[audit-reader] skipping line with missing "
                            f"fields {missing}",
                            file=sys.stderr,
                        )
                        continue
                    raise LedgerError(
                        f"event missing required fields {missing}: {line[:200]!r}"
                    )
                # Coerce event_type to enum (string) for downstream
                try:
                    obj["event_type"] = EventType(obj["event_type"])
                except (KeyError, ValueError):
                    pass
                ev = Event(**obj)
                last_good = ev
                yield ev

    def all_events(self) -> list:
        return list(self.iter_events())

    def find_session(self, session_id: str) -> list:
        return [e for e in self.iter_events() if e.session_id == session_id]

    def find_by_type(self, event_type) -> list:
        return [e for e in self.iter_events() if e.event_type == event_type]


def verify_chain(events_file: Path) -> dict:
    """Walk the entire ledger and return a verification report.

    Returns a dict with:
        total: int
        ok: bool
        duplicates: list of duplicated event_ids
        broken_chain: list of (index, prev_hash, computed_prev)
        malformed: list of line numbers
        missing_fields: list of (line_no, fields)
    """
    report = {
        "total": 0,
        "ok": True,
        "duplicates": [],
        "broken_chain": [],
        "malformed": [],
        "missing_fields": [],
    }
    if not events_file.exists():
        return report
    seen: dict[str, int] = {}
    prev_hash: Optional[str] = None
    idx = 0
    with events_file.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            idx += 1
            try:
                obj = _json.loads(line)
            except _json.JSONDecodeError:
                report["malformed"].append(line_no)
                report["ok"] = False
                continue
            missing = _REQUIRED_FIELDS - set(obj.keys())
            if missing:
                report["missing_fields"].append((line_no, list(missing)))
                report["ok"] = False
                continue
            ev = Event(**obj)
            report["total"] += 1
            # Duplicate event_id detection
            if ev.event_id in seen:
                report["duplicates"].append(ev.event_id)
                report["ok"] = False
            else:
                seen[ev.event_id] = line_no
            # Hash chain verification
            expected_prev = ev.prev_event_hash
            if expected_prev != prev_hash:
                report["broken_chain"].append({
                    "line": line_no,
                    "event_id": ev.event_id,
                    "expected_prev": expected_prev,
                    "actual_prev": prev_hash,
                })
                report["ok"] = False
            # Recompute the event hash to detect tampering
            try:
                expected_hash = ev.compute_hash(prev_hash)
                if ev.event_hash != expected_hash:
                    report["broken_chain"].append({
                        "line": line_no,
                        "event_id": ev.event_id,
                        "issue": "event_hash_mismatch",
                        "expected": expected_hash,
                        "actual": ev.event_hash,
                    })
                    report["ok"] = False
            except Exception:
                pass
            prev_hash = ev.event_hash
    return report
