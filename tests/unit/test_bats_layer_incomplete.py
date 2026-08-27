"""Regression test for the bats-layer "silent fail with zero diagnostics" bug.

Previous behavior: when bats was not installed in the sandbox image
(e.g. the bash:5.1 sandbox), the wrapper emitted `BATS_MISSING_IN_SANDBOX`
and exited 1 with no TAP output. The TAP summary parser returned
(ok=0, failed=0, total=0), and the post-processing block fell into the
`else` branch which set `result.status = "fail"` but only emitted
diagnostics for lines starting with `not ok`. The result was a
contradictory report: `fail 0 diagnostic(s)` + `No blocking diagnostics`,
yet the script was refused.

Fixed behavior: when the sandbox returns non-zero with empty TAP, the
layer must report `status="incomplete"` with an INFO diagnostic
explaining why (sentinel-detected message when the wrapper emits
BATS_MISSING_IN_SANDBOX; generic message for other empty-TAP
environment problems). The orchestrator then treats this as
`incomplete` (or — with the older `_overall_status` shape — as not-a-failure,
so safe-cli verify exits 0 on an otherwise-clean script).
"""
from __future__ import annotations

import os
import re
import sys
import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

# Compute the repo root from this test file's location (portable,
# no hardcoded /opt/safe-cli-repo).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, _REPO_ROOT)

# Make sure a fresh `bv` import does not inherit stale pycache from any
# other test that already loaded it with old source on disk.
for _m in list(sys.modules):
    if _m.startswith("bv"):
        del sys.modules[_m]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dummy_config():
    """Build a minimal Config for BatsLayer construction.

    We use the real config loader so `cfg.tools.bats` points at the
    actual bats binary on the host (e.g. /usr/bin/bats). If we hard
    a path that doesn't exist, BatsLayer hits its early
    `not Path(bats_path).exists()` return and the new incomplete
    branch is never exercised — masking the very bug we are testing
    for.
    """
    from bv.config import load_config
    return load_config()


def _make_run_script_mock(stdout: str, exit_code: int = 1, stderr: str = ""):
    """Build a fake `DockerSandbox.run_script` callable.

    `patch.object(DockerSandbox, "run_script", mock)` will replace the
    class attribute. Whenever the bats_layer does
    `sb.run_script(wrapper)`, the mock must return a context manager
    that yields a `SandboxResult` — `with mock_result as sr:` must work.

    If we assign a `_GeneratorContextManager` instance directly, then
    `sb.run_script(wrapper)` invokes its `__call__` and returns the
    inner *generator* (not the context manager), and `with generator`
    raises AttributeError("__enter__"). We avoid that by returning a
    thin callable that, regardless of how it is called, hands back the
    ContextManager itself.
    """
    from bv.sandbox.docker_sandbox import SandboxResult

    @contextmanager
    def _ctx():
        result = SandboxResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=42,
            timed_out=False,
            sandbox_image="bash:5.1",
        )
        yield result

    # Capturing the ContextManager instance once keeps `with` working.
    cm_obj = _ctx()

    def _fake_run_script(self_unused=None, *args, **kwargs):
        # The bats_layer calls `sb.run_script(wrapper)` — the wrapper
        # argument is irrelevant for the mock. Always return the same
        # context manager.
        return cm_obj

    return _fake_run_script


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


class TestBatsLayerIncompleteOnEmptyTAP(unittest.TestCase):
    """The bug fix: bats unavailable → status='incomplete' + INFO diag."""

    # ----- behavioral tests -----

    def test_bats_missing_sentinel_yields_incomplete(self):
        from bv.layers.bats_layer import BatsLayer
        from bv.script import Script
        from bv.orchestrator import LayerContext
        from bv.sandbox.docker_sandbox import DockerSandbox

        cfg = _dummy_config()
        layer = BatsLayer(cfg)
        script = Script(content="#!/usr/bin/env bash\necho hi\n")

        # Mock DockerSandbox.run_script so the wrapper's sentinel output
        # is what the layer sees, without needing a real docker daemon.
        with patch.object(
            DockerSandbox,
            "run_script",
            _make_run_script_mock(
                stdout="BATS_MISSING_IN_SANDBOX\n",
                exit_code=1,
                stderr="",
            ),
        ):
            res = layer.run(script, LayerContext(extra={}))

        self.assertEqual(
            res.status, "incomplete",
            f"expected status='incomplete', got {res.status!r} "
            f"(diagnostics={len(res.diagnostics)})",
        )
        self.assertEqual(
            len(res.diagnostics), 1,
            f"expected exactly 1 diagnostic explaining why, got "
            f"{len(res.diagnostics)}",
        )
        d = res.diagnostics[0]
        from bv.diagnostic import Severity, Category

        self.assertEqual(d.severity, Severity.INFO)
        self.assertEqual(d.category, Category.DEPENDENCY)
        self.assertEqual(d.tool, "bats")
        self.assertEqual(d.code, "BATS_MISSING_IN_SANDBOX")
        self.assertIn(
            "bats is not installed", d.message,
            "diagnostic message should explain the bats-missing cause",
        )
        self.assertEqual(
            res.metadata.get("incomplete_reason"),
            "bats_not_installed_in_sandbox",
            "metadata should record the specific reason",
        )
        # Confirm the original failure diagnostics are NOT emitted.
        self.assertNotEqual(res.status, "fail")

    def test_empty_tap_without_sentinel_also_yields_incomplete(self):
        """An empty-TAP environment error without the explicit sentinel
        should still be flagged as incomplete (not as a hard fail with
        zero diagnostics). This covers 'sandbox image lacks bats even
        though it didn't emit our sentinel' and 'sandbox couldn't even
        run bash'."""
        from bv.layers.bats_layer import BatsLayer
        from bv.script import Script
        from bv.orchestrator import LayerContext
        from bv.sandbox.docker_sandbox import DockerSandbox

        cfg = _dummy_config()
        layer = BatsLayer(cfg)
        script = Script(content="#!/usr/bin/env bash\necho hi\n")

        with patch.object(
            DockerSandbox,
            "run_script",
            _make_run_script_mock(stdout="", exit_code=137, stderr="OOM"),
        ):
            res = layer.run(script, LayerContext(extra={}))

        from bv.diagnostic import Severity

        self.assertEqual(res.status, "incomplete")
        self.assertEqual(len(res.diagnostics), 1)
        d = res.diagnostics[0]
        self.assertEqual(d.severity, Severity.INFO)
        self.assertEqual(d.code, "BATS_NO_TAP")
        self.assertIn("no TAP", d.message)
        self.assertEqual(
            res.metadata.get("incomplete_reason"), "no_tap_output"
        )

    def test_real_test_failure_still_reports_fail(self):
        """Regression guard: a genuine `not ok 1 ...` TAP failure must
        still produce status='fail' with a BATS_FAIL ERROR diagnostic.
        The new incomplete path is additive; it must not mask real
        test failures."""
        from bv.layers.bats_layer import BatsLayer
        from bv.script import Script
        from bv.orchestrator import LayerContext
        from bv.sandbox.docker_sandbox import DockerSandbox

        cfg = _dummy_config()
        layer = BatsLayer(cfg)
        script = Script(content="#!/usr/bin/env bash\necho hi\n")

        # TAP output showing one passing test and one failing test,
        # exit code 0 (bats returns 0 even when tests fail).
        tap = (
            "1..2\n"
            "ok 1 source loads\n"
            "not ok 2 missing command\n"
            "# bats failure summary\n"
        )
        with patch.object(
            DockerSandbox,
            "run_script",
            _make_run_script_mock(stdout=tap, exit_code=1, stderr=""),
        ):
            res = layer.run(script, LayerContext(extra={}))

        from bv.diagnostic import Severity, Category

        self.assertEqual(res.status, "fail")
        self.assertGreater(len(res.diagnostics), 0)
        # The failure diagnostic must be ERROR-severity, not INFO.
        error_diags = [d for d in res.diagnostics if d.severity == Severity.ERROR]
        self.assertEqual(
            len(error_diags), 1,
            "expected exactly one ERROR diagnostic for the failing test",
        )
        self.assertEqual(error_diags[0].code, "BATS_FAIL")
        self.assertIn(
            "missing command", error_diags[0].message
        )
        # And the metadata must NOT advertise incomplete_reason on
        # a real failure path.
        self.assertNotIn("incomplete_reason", res.metadata)

    # ----- static check -----

    def test_bats_layer_source_has_incomplete_branch(self):
        """Greps the bats_layer.py source for the structural markers
        of the fix, guarding against accidental future removal."""
        path = os.path.join(_REPO_ROOT, "bv", "layers", "bats_layer.py")
        with open(path, "r") as f:
            src = f.read()

        # The exact sentinel string we detect.
        self.assertIn(
            "BATS_MISSING_IN_SANDBOX", src,
            "bats_layer.py must reference the BATS_MISSING_IN_SANDBOX "
            "sentinel to produce the specific diagnostic",
        )
        # An explicit assignment of "incomplete" status.
        self.assertRegex(
            src,
            r"result\.status\s*=\s*[\"']incomplete[\"']",
            "bats_layer.py must set result.status='incomplete' for "
            "the bats-unavailable path",
        )
        # The empty-TAP fallback condition.
        self.assertRegex(
            src,
            r"total\s*==\s*0",
            "bats_layer.py must check total == 0 to detect empty-TAP "
            "environment errors",
        )
        # An INFO-severity diagnostic in the new branch.
        self.assertRegex(
            src,
            r"severity\s*=\s*Severity\.INFO",
            "bats_layer.py must emit a Severity.INFO diagnostic for "
            "the bats-unavailable case so it doesn't block the script",
        )
        # Metadata field for queryable reason.
        self.assertIn(
            "incomplete_reason", src,
            "bats_layer.py must write incomplete_reason into "
            "result.metadata so the orchestrator/clients can query it",
        )


if __name__ == "__main__":
    unittest.main()
