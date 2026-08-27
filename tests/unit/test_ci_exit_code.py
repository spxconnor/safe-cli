"""Regression test for the --ci exit-code policy change in bv/cli.py.

Before the bats-layer fix, `safe-cli verify` exited 1 on a "verified
or incomplete" report because the CLI's --ci branch required
`report.status == "verified"` exactly. That was the silent-fail
trap: bats-missing was reported as "fail 0 diag(s)" with overall
status "failed", the CLI returned 1, and the user saw a report
that contradicted itself.

After the fix:
- bats layer reports `status="incomplete"` with one INFO diagnostic,
  no ERROR-severity diagnostics anywhere.
- orchestrator returns `status="incomplete"` (per its FAILED >
  INCOMPLETE > VERIFIED priority).
- CLI's --ci branch now returns 0 for both `verified` and
  `incomplete`, via the extracted helper `ci_exit_code()`.

This test pins down the exit-code semantics so the helper cannot
revert to the old "verified only" behaviour without a test failure.
The safe-cli wrapper additionally refuses to EXECUTE anything that
is not exactly "verified" — that wrapper-side gate is not exercised
here (it lives outside the bv package) but is documented in
cmd_run.
"""
from __future__ import annotations

import importlib
import os
import sys
import unittest

# Compute the repo root from this test file's location (portable,
# no hardcoded /opt/safe-cli-repo).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _REPO_ROOT)

# Force a fresh import of bv so we don't inherit a stale pycache
# of bv.cli from a different machine layout.
for _m in list(sys.modules):
    if _m.startswith("bv"):
        del sys.modules[_m]


class TestCiExitCodePolicy(unittest.TestCase):

    def setUp(self):
        self.cli = importlib.import_module("bv.cli")

    def test_verified_returns_zero(self):
        self.assertEqual(self.cli.ci_exit_code("verified"), 0)

    def test_incomplete_returns_zero(self):
        """The fix: bats-layer incomplete → exit 0 in --ci mode."""
        self.assertEqual(self.cli.ci_exit_code("incomplete"), 0)

    def test_failed_returns_one(self):
        self.assertEqual(self.cli.ci_exit_code("failed"), 1)

    def test_error_returns_one(self):
        self.assertEqual(self.cli.ci_exit_code("error"), 1)

    def test_unknown_status_returns_one(self):
        """Defensive: unknown future status names shouldn't silently
        pass."""
        self.assertEqual(self.cli.ci_exit_code("????"), 1)

    def test_only_two_passing_statuses(self):
        """Pin down the exact set so the policy cannot drift without
        a test failure."""
        from inspect import getsource

        src = getsource(self.cli.ci_exit_code)
        # Both "verified" and "incomplete" must be in the source, and
        # nothing else may be in the passing set.
        self.assertIn('"verified"', src)
        self.assertIn('"incomplete"', src)
        for forbidden in ("pass", "ok", "approved", "static_only"):
            self.assertNotIn(
                f'"{forbidden}"', src,
                f"unexpected passing status {forbidden!r} added to "
                "ci_exit_code passing set",
            )


if __name__ == "__main__":
    unittest.main()
