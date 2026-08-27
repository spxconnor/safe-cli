"""Regression test for the bash_n_layer.py defensive-fallback fix.

Audit found that bash_n_layer.py set `result.status = "fail"` on a
non-zero returncode, then emitted one diagnostic PER LINE of stderr.
If bash -n ever exits non-zero with empty stderr (e.g. very old bash,
locale issues, container with broken stdio), the layer reported
"fail 0 diagnostic(s)" — the same silent-fail-with-zero-diag
anti-pattern that hid the bats bug.

This test pins down the fix: when stderr is empty, the layer MUST
still emit at least one ERROR diagnostic explaining the failure.
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

# Compute the repo root from this test file's location (portable,
# no hardcoded /opt/safe-cli-repo).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _REPO_ROOT)

# Force a fresh import of `bv` so we don't inherit stale pycache.
for _m in list(sys.modules):
    if _m.startswith("bv"):
        del sys.modules[_m]


class TestBashNLayerDefensiveDiagnostic(unittest.TestCase):
    """BashNLayer.run() must never produce fail-with-zero-diagnostics."""

    def _layer(self):
        from bv.layers.bash_n_layer import BashNLayer
        from bv.config import load_config
        return BashNLayer(load_config())

    def _script(self, content="#!/usr/bin/env bash\necho hi\n"):
        from bv.script import Script
        return Script(content=content)

    def test_non_zero_with_empty_stderr_still_emits_error_diag(self):
        """When `bash -n` exits non-zero but produces no stderr, the
        layer must still emit at least one Severity.ERROR diagnostic
        — otherwise the orchestrator sees `fail 0 diagnostic(s)`.
        """
        from bv.diagnostic import Severity

        layer = self._layer()
        script = self._script()

        # Bash -n exits non-zero (syntax error) but stderr is empty —
        # the historically-buggy edge case the audit identified.
        fake_proc = MagicMock()
        fake_proc.returncode = 1
        fake_proc.stderr = ""
        fake_proc.stdout = ""

        with patch("subprocess.run", return_value=fake_proc):
            res = layer.run(script, None)

        # Status is still fail — we are NOT downgrading to skip/incomplete.
        self.assertEqual(res.status, "fail")

        # Defensive: at least one ERROR diagnostic must exist.
        error_diags = [
            d for d in res.diagnostics if d.severity == Severity.ERROR
        ]
        self.assertGreaterEqual(
            len(error_diags), 1,
            "bash_n must emit at least one ERROR diagnostic when it "
            "claims fail; otherwise the layer reports fail-with-zero-"
            "diagnostics (the same bug class as bats_layer before "
            "the fix)",
        )
        # And the diagnostic message must explain why the fallback
        # fired, so the operator can act on it.
        msgs = [d.message for d in error_diags]
        self.assertTrue(
            any("bash -n exited" in m and "no stderr" in m for m in msgs),
            f"expected a fallback diagnostic with 'no stderr' wording; "
            f"got: {msgs!r}",
        )

    def test_non_zero_with_stderr_uses_normal_per_line_diagnostics(self):
        """When stderr IS non-empty, the layer still emits the original
        per-line BASH_SYNTAX diagnostics (regression guard)."""
        from bv.diagnostic import Severity

        layer = self._layer()
        script = self._script()

        fake_proc = MagicMock()
        fake_proc.returncode = 1
        fake_proc.stderr = "/tmp/x.sh: line 5: syntax error near unexpected token 'foo'\n"
        fake_proc.stdout = ""

        with patch("subprocess.run", return_value=fake_proc):
            res = layer.run(script, None)

        self.assertEqual(res.status, "fail")
        # We expect at least one diagnostic AND its code is BASH_SYNTAX.
        syntax_diags = [
            d for d in res.diagnostics if getattr(d, "code", "") == "BASH_SYNTAX"
        ]
        self.assertGreaterEqual(len(syntax_diags), 1)
        # The defensive fallback should NOT fire when stderr was non-empty.
        fallback_msgs = [d.message for d in res.diagnostics
                         if "no stderr" in d.message]
        self.assertEqual(
            len(fallback_msgs), 0,
            "defensive fallback must not fire when real diagnostics exist",
        )

    def test_pass_path_unchanged(self):
        """Bash -n exit 0 → status pass, no diagnostics. Sanity check
        that the fallback doesn't accidentally fire on success."""
        layer = self._layer()
        script = self._script()

        fake_proc = MagicMock()
        fake_proc.returncode = 0
        fake_proc.stderr = ""
        fake_proc.stdout = ""

        with patch("subprocess.run", return_value=fake_proc):
            res = layer.run(script, None)

        self.assertEqual(res.status, "pass")
        self.assertEqual(
            len(res.diagnostics), 0,
            "bash_n must not emit any diagnostic on the pass path",
        )


if __name__ == "__main__":
    unittest.main()
