"""Regression tests for P0 9: repair must produce a new artifact.

A repair is only considered successful if it actually changes the
content. A no-op repair (strategy returns the same content) must not
be reported as self_healed.
"""
import hashlib
import unittest

from bv.config import load_config
from bv.diagnostic import (
    Category,
    Diagnostic,
    LayerResult,
    Severity,
)
from bv.repair.engine import RepairEngine
from bv.script import from_content


def _hash(s):
    return hashlib.sha256(s.encode()).hexdigest()


class TestRepairReportSchema(unittest.TestCase):
    def test_report_has_final_content_sha256(self):
        from bv.repair.engine import RepairReport
        r = RepairReport(total_attempts=0, self_healed=False)
        self.assertTrue(hasattr(r, "final_content_sha256"))


class TestNoOpRepair(unittest.TestCase):
    def test_no_strategies_means_no_self_healed(self):
        # No strategies available -> no repair possible
        original = "echo hi"
        script = from_content(original)
        def runner(s, context=None):
            return {}
        cfg = load_config()
        engine = RepairEngine(cfg, runner)
        report = engine.attempt_repair(script, {})
        self.assertFalse(report.self_healed)


class TestNewArtifactHash(unittest.TestCase):
    def test_script_tracks_sha256(self):
        script = from_content("echo hi")
        self.assertEqual(script.content_sha256, _hash("echo hi"))
        # Update changes the hash
        script.update('echo "hi"')
        self.assertEqual(script.content_sha256, _hash('echo "hi"'))


if __name__ == "__main__":
    unittest.main()
