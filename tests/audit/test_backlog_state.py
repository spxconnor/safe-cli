"""tests/audit/test_backlog_state.py - validate_transition and Backlog persistence.

We exercise the documented state machine and the on-disk round trip.
"""
import tempfile
import unittest
from pathlib import Path

from bv.audit.backlog import (
    Backlog,
    BacklogError,
    InvalidTransition,
    validate_transition,
)
from bv.audit.model import (
    BacklogItem,
    BacklogStatus,
    Priority,
)


class TestValidateTransition(unittest.TestCase):
    """Cover the documented legal transitions and two illegal ones."""

    def test_legal_transitions(self):
        # Each pair (from, to) is exercised as a fresh transition.
        legal = [
            (BacklogStatus.BACKLOG, BacklogStatus.READY),
            (BacklogStatus.READY, BacklogStatus.IN_PROGRESS),
            (BacklogStatus.IN_PROGRESS, BacklogStatus.COMPLETE),
            (BacklogStatus.FAILED, BacklogStatus.READY),
            (BacklogStatus.BLOCKED, BacklogStatus.READY),
            (BacklogStatus.IN_PROGRESS, BacklogStatus.DEFERRED),
            (BacklogStatus.DEFERRED, BacklogStatus.READY),
        ]
        for frm, to in legal:
            with self.subTest(frm=frm, to=to):
                # Should not raise.
                validate_transition(frm, to)

    def test_illegal_transitions(self):
        # Each pair must raise InvalidTransition.
        illegal = [
            (BacklogStatus.COMPLETE, BacklogStatus.IN_PROGRESS),
            (BacklogStatus.CANCELLED, BacklogStatus.COMPLETE),
        ]
        for frm, to in illegal:
            with self.subTest(frm=frm, to=to):
                with self.assertRaises(InvalidTransition):
                    validate_transition(frm, to)


class TestBacklogPersistence(unittest.TestCase):
    """Add a Backlog item, transition it, and reload from disk."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="audit-backlog-")
        self.path = Path(self.tmp) / "backlog.json"

    def test_add_transition_reload(self):
        b1 = Backlog(self.path)
        item = BacklogItem(
            id="T-001",
            title="Test item",
            description="created by test_backlog_state",
            priority=Priority.P1,
            status=BacklogStatus.BACKLOG,
        )
        b1.add(item)

        # Walk a small legal path through the state machine.
        b1.transition("T-001", BacklogStatus.READY, note="ready for work")
        b1.transition("T-001", BacklogStatus.IN_PROGRESS, note="started")
        b1.transition("T-001", BacklogStatus.COMPLETE, note="done")

        # Reload from disk and assert the same final state.
        b2 = Backlog(self.path)
        reloaded = b2.get("T-001")
        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded.status, BacklogStatus.COMPLETE)
        self.assertEqual(reloaded.id, "T-001")
        self.assertEqual(reloaded.priority, Priority.P1)
        self.assertIsNotNone(reloaded.started_at)
        self.assertIsNotNone(reloaded.completed_at)
        # Notes should have been recorded for each transition.
        self.assertGreaterEqual(len(reloaded.notes), 3)


if __name__ == "__main__":
    unittest.main()