"""tests/audit/test_chain.py - exercise the hash-chained JSONL ledger.

We:
  1. Create a fresh AuditDirectory in a tempdir.
  2. Emit three events through AuditWriter.
  3. Verify the chain end-to-end (ok, total, no dup, no broken).
  4. Corrupt one event's message in place.
  5. Verify the chain again and assert ok=False.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

from bv.audit.writer import AuditDirectory, AuditWriter
from bv.audit.reader import verify_chain
from bv.audit.model import Event, EventType, Severity


class TestChain(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="audit-chain-")
        self.audit_dir = AuditDirectory(Path(self.tmp))
        self.audit_dir.ensure()
        self.session_id = "test-chain-session-001"
        self.writer = AuditWriter(self.audit_dir, session_id=self.session_id)

    def tearDown(self):
        # We can only use cp/mv (no rm), so leave the tempdir behind;
        # it lives under /tmp and gets cleaned by the OS eventually.
        pass

    def _emit_three_events(self):
        events = []
        for i in range(3):
            ev = Event(
                session_id=self.session_id,
                event_type=EventType.COMMAND_FINISHED,
                severity=Severity.INFO,
                component="test",
                message=f"event {i}",
                command_id=f"cmd-{i}",
                exit_code=0,
                duration_ms=10,
            )
            events.append(self.writer.emit(ev))
        return events

    def test_verify_chain_clean(self):
        self._emit_three_events()
        report = verify_chain(self.audit_dir.events_file)
        self.assertTrue(report["ok"], msg=f"verify_chain ok=False: {report}")
        self.assertEqual(report["total"], 3)
        self.assertEqual(report["duplicates"], [])
        self.assertEqual(report["broken_chain"], [])

    def test_corruption_detected(self):
        self._emit_three_events()

        # Read the JSONL, corrupt the second event's message field,
        # and rewrite it. The chain's prev_event_hash will still match
        # (we only changed message), but the recomputed event_hash will
        # not match the stored hash, so verify_chain must flag it.
        ef = self.audit_dir.events_file
        lines = ef.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 3)
        # Parse the second event, mutate, re-serialise in place.
        obj = json.loads(lines[1])
        obj["message"] = "TAMPERED MESSAGE"
        lines[1] = json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        ef.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = verify_chain(self.audit_dir.events_file)
        self.assertFalse(
            report["ok"],
            msg=f"verify_chain should be ok=False after tampering: {report}",
        )
        # Either the broken_chain list has an event_hash_mismatch entry,
        # or some other flag is set. The contract: ok is False.
        self.assertTrue(
            report["broken_chain"] or report["duplicates"]
            or report["malformed"] or report["missing_fields"],
            msg=f"verify_chain did not flag any issue: {report}",
        )


if __name__ == "__main__":
    unittest.main()