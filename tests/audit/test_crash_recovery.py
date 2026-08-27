"""tests/audit/test_crash_recovery.py - find and mark open sessions.

CrashRecovery.find_open_sessions() returns session records (dict form)
whose JSON file lacks a "status" field. We:
  1. Create a fresh AuditDirectory in a tempdir.
  2. Hand-write a sessions/<sid>.json file with no "status" field.
  3. Assert find_open_sessions() returns it.
  4. Mutate the file to set status="ABORTED".
  5. Assert find_open_sessions() returns [].
"""
import json
import tempfile
import unittest
from pathlib import Path

from bv.audit.writer import AuditDirectory
from bv.audit.session import CrashRecovery


class TestCrashRecovery(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="audit-recovery-")
        self.audit_dir = AuditDirectory(Path(self.tmp))
        # AuditDirectory.ensure() creates sessions/ etc.
        self.audit_dir.ensure()

    def tearDown(self):
        # No rm allowed; leave the tempdir for the OS to collect.
        pass

    def test_open_session_detected_then_marked_aborted(self):
        sid = "session-unfinished-001"
        # Session files live directly under .audit/sessions/<sid>.json
        # (no per-session subdirectory).
        sessions_dir = self.audit_dir.path / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        session_path = sessions_dir / f"{sid}.json"
        # Write a session JSON WITHOUT a status field (simulating an
        # unfinished session whose writer crashed before end() ran).
        record = {
            "session_id": sid,
            "started_at": "2026-08-27T16:00:00.000Z",
            "env_detected": "test env",
            "head_commit": "",
            "current_branch": "",
            "python_version": "3.10",
        }
        session_path.write_text(
            json.dumps(record, indent=2), encoding="utf-8"
        )

        rec = CrashRecovery(self.audit_dir)
        open_sessions = rec.find_open_sessions()
        self.assertEqual(len(open_sessions), 1)
        self.assertEqual(open_sessions[0]["session_id"], sid)
        self.assertNotIn("status", open_sessions[0])

        # Now mark the session with status="ABORTED" by rewriting the file.
        record["status"] = "ABORTED"
        session_path.write_text(
            json.dumps(record, indent=2), encoding="utf-8"
        )

        # find_open_sessions should now return an empty list.
        self.assertEqual(rec.find_open_sessions(), [])


if __name__ == "__main__":
    unittest.main()