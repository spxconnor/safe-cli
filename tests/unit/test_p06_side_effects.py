"""Regression tests for P0 6: SideEffectsLayer must not reference
host paths or swallow failures with || true.
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SIDE = REPO / "bv" / "layers" / "side_effects_layer.py"


class TestSideEffectsNoHostPath(unittest.TestCase):

    def test_no_host_path_in_wrapper(self):
        """The wrapper must not contain a TARGET=<host path> pattern."""
        src = SIDE.read_text()
        # Check for the old pattern where the host path was templated in.
        self.assertNotIn("TARGET={target!r}", src)
        self.assertNotIn("TARGET=", src,
            "side_effects_layer.py still references a TARGET= path; "
            "the sandbox cannot access host paths")
        # Sanity: a TARGET= line for environment variables is fine,
        # but no TARGET= assignment to a path. Check the line context.
        for i, line in enumerate(src.splitlines(), 1):
            if "TARGET=" in line and not line.strip().startswith("#"):
                # Allow if it's clearly an env var, not a path
                # The original bug had: TARGET={target!r} which expands
                # to a path. Anything similar is a regression.
                if "{" in line or "/" in line.split("=", 1)[1][:30]:
                    self.fail(
                        f"side_effects_layer.py:{i} has suspicious TARGET=: {line.strip()!r}"
                    )

    def test_no_failure_swallow(self):
        """The wrapper must not use `|| true` to swallow exit codes."""
        src = SIDE.read_text()
        self.assertNotIn(
            "|| true", src,
            "side_effects_layer.py still uses `|| true` to swallow "
            "script failures; this makes the side-effect snapshot a no-op",
        )

    def test_script_uses_staged_path(self):
        """The wrapper must execute the staged script at a sandbox path."""
        src = SIDE.read_text()
        self.assertIn(
            "/work/script.sh", src,
            "wrapper must execute the staged script at /work/script.sh",
        )
        self.assertIn(
            "BV_RC", src,
            "wrapper must capture and report the script's real exit code",
        )
