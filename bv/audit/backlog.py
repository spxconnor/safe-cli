"""bv/audit/backlog.py - persistent backlog with a state machine.

The backlog is a single JSON file. Writes are atomic (write-temp +
rename). State transitions are validated. The goal is that a future
coding agent can start with `safe-cli backlog list` and immediately
know what is on the docket.
"""
from __future__ import annotations

import json as _json
import os
import tempfile
from pathlib import Path
from typing import Iterable, Optional

from .model import (
    BacklogItem, BacklogStatus, Priority, now_iso, new_uuid,
)


# Valid state transitions for the state machine.
# Keys are the FROM state; values are the set of legal TO states.
_TRANSITIONS: dict[BacklogStatus, set[BacklogStatus]] = {
    BacklogStatus.BACKLOG: {BacklogStatus.READY, BacklogStatus.CANCELLED, BacklogStatus.DEFERRED},
    BacklogStatus.READY: {BacklogStatus.IN_PROGRESS, BacklogStatus.BACKLOG, BacklogStatus.CANCELLED, BacklogStatus.DEFERRED},
    BacklogStatus.IN_PROGRESS: {BacklogStatus.COMPLETE, BacklogStatus.FAILED,
                                  BacklogStatus.BLOCKED, BacklogStatus.PARTIALLY_COMPLETE,
                                  BacklogStatus.DEFERRED, BacklogStatus.READY},
    BacklogStatus.FAILED: {BacklogStatus.READY, BacklogStatus.DEFERRED, BacklogStatus.CANCELLED},
    BacklogStatus.BLOCKED: {BacklogStatus.READY, BacklogStatus.DEFERRED, BacklogStatus.CANCELLED},
    BacklogStatus.PARTIALLY_COMPLETE: {BacklogStatus.IN_PROGRESS, BacklogStatus.COMPLETE, BacklogStatus.DEFERRED, BacklogStatus.CANCELLED},
    BacklogStatus.COMPLETE: {BacklogStatus.DEFERRED, BacklogStatus.CANCELLED},  # reopen via DEFERRED
    BacklogStatus.DEFERRED: {BacklogStatus.READY, BacklogStatus.BACKLOG, BacklogStatus.CANCELLED},
    BacklogStatus.CANCELLED: set(),  # terminal
}


class BacklogError(Exception):
    pass


class InvalidTransition(BacklogError):
    pass


def validate_transition(frm: BacklogStatus, to: BacklogStatus) -> None:
    if to == frm:
        return
    allowed = _TRANSITIONS.get(frm, set())
    if to not in allowed:
        raise InvalidTransition(
            f"invalid backlog transition: {frm.value} -> {to.value} "
            f"(allowed: {sorted(s.value for s in allowed)})"
        )


class Backlog:
    """Persistent backlog backed by a single JSON file.

    Reads are optimistic (no lock). Writes are atomic. The full file
    is rewritten on every change because the file is small and the
    state machine is the source of truth. We never silently merge.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._items: dict[str, BacklogItem] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = _json.loads(self.path.read_text(encoding="utf-8"))
        except _json.JSONDecodeError as e:
            raise BacklogError(f"backlog.json is malformed: {e}")
        for k, v in data.get("items", {}).items():
            try:
                self._items[k] = BacklogItem(**v)
            except TypeError as e:
                raise BacklogError(f"backlog item {k!r} is malformed: {e}")

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".backlog.", suffix=".json.tmp"
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                _json.dump(
                    {"items": {k: v.__dict__ for k, v in self._items.items()}},
                    f,
                    sort_keys=True,
                    indent=2,
                    ensure_ascii=False,
                )
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            os.replace(tmp_path, self.path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def all(self) -> list[BacklogItem]:
        return list(self._items.values())

    def get(self, item_id: str) -> Optional[BacklogItem]:
        return self._items.get(item_id)

    def transition(self, item_id: str, to: BacklogStatus, note: str = "") -> BacklogItem:
        item = self._items.get(item_id)
        if item is None:
            raise BacklogError(f"unknown backlog item: {item_id}")
        from .model import BacklogStatus as _BS
        to = _BS(to) if not isinstance(to, _BS) else to
        validate_transition(_BS(item.status), to)
        item.status = to
        item.updated_at = now_iso()
        if to == BacklogStatus.IN_PROGRESS and not item.started_at:
            item.started_at = item.updated_at
            item.attempt_count += 1
        if to == BacklogStatus.COMPLETE:
            item.completed_at = item.updated_at
        if to == BacklogStatus.FAILED:
            item.failure_count += 1
        if note:
            item.notes.append(f"{item.updated_at}: {note}")
        self._save()
        return item

    def add(self, item: BacklogItem) -> BacklogItem:
        if item.id in self._items:
            raise BacklogError(f"backlog item id already exists: {item.id}")
        item.created_at = item.created_at or now_iso()
        item.updated_at = item.updated_at or now_iso()
        self._items[item.id] = item
        self._save()
        return item

    def update(self, item: BacklogItem) -> BacklogItem:
        if item.id not in self._items:
            raise BacklogError(f"unknown backlog item: {item.id}")
        item.updated_at = now_iso()
        self._items[item.id] = item
        self._save()
        return item

    def next(self) -> Optional[BacklogItem]:
        """Return the highest-priority unblocked non-terminal item."""
        PRIORITY_ORDER = {Priority.P0: 0, Priority.P1: 1, Priority.P2: 2, Priority.P3: 3}
        candidates = [
            i for i in self._items.values()
            if i.status in (BacklogStatus.BACKLOG, BacklogStatus.READY)
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda i: (PRIORITY_ORDER.get(i.priority, 9), i.id))
        return candidates[0]

    def filter(self, **kw) -> list[BacklogItem]:
        items = list(self._items.values())
        if "status" in kw:
            items = [i for i in items if i.status == BacklogStatus(kw["status"])]
        if "priority" in kw:
            items = [i for i in items if i.priority == Priority(kw["priority"])]
        return items
