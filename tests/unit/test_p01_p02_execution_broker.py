"""Regression tests for P0 1 + P0 2: the host must NEVER invoke
bash on untrusted bytes.

If a future change accidentally reintroduces host-side execution of
the verified script or of bats on the target, these tests fail.
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SAFE_CLI = REPO / "bin" / "safe_cli.py"
BATS_LAYER = REPO / "bv" / "layers" / "bats_layer.py"
EXECUTOR = REPO / "bv" / "executor.py"


class TestExecutionBrokerExists(unittest.TestCase):
    def test_broker_module(self):
        self.assertTrue(EXECUTOR.exists(),
            "ExecutionBroker (bv/executor.py) is missing")
        # The invariant comment must be present
        src = EXECUTOR.read_text()
        self.assertIn("HOST MAY NEVER EXECUTE UNTRUSTED CODE", src)
        self.assertIn("class ExecutionBroker", src)
        self.assertIn("def execute(self, request: ExecutionRequest)", src)


class TestSafeCliUsesBroker(unittest.TestCase):
    def test_cmd_run_does_not_invoke_host_bash_on_untrusted_bytes(self):
        """The cmd_run path must use the broker, not subprocess.run([bash, ...])."""
        src = SAFE_CLI.read_text()
        # Find cmd_run body
        idx = src.find("def cmd_run(")
        self.assertGreater(idx, 0, "cmd_run not found in safe_cli.py")
        end = src.find("\ndef ", idx + 1)
        if end < 0:
            end = len(src)
        body = src[idx:end]
        # The body must not invoke `subprocess.run([..., "bash", ...])`
        # on the untrusted file. The broker is the only allowed path.
        self.assertIn("ExecutionBroker", body,
            "cmd_run does not use ExecutionBroker; the host may be running "
            "untrusted Bash directly")
        # The literal `subprocess.run([..., "bash", str(p)])` is the
        # dangerous pattern. Check it is not present.
        if '"bash", str(p)' in body or "'bash', str(p)" in body:
            self.fail("cmd_run still has subprocess.run([..., bash, str(p)]) "
                      "on the untrusted path")

    def test_cmd_exec_does_not_invoke_host_bash_on_untrusted_bytes(self):
        src = SAFE_CLI.read_text()
        idx = src.find("def cmd_exec(")
        self.assertGreater(idx, 0, "cmd_exec not found in safe_cli.py")
        end = src.find("\ndef ", idx + 1)
        if end < 0:
            end = len(src)
        body = src[idx:end]
        self.assertIn("ExecutionBroker", body,
            "cmd_exec does not use ExecutionBroker")
        # The host's bash is not invoked on the snippet bytes.
        if 'subprocess.run(["bash"' in body:
            self.fail("cmd_exec still invokes host bash on untrusted snippet")


class TestBatsLayerRunsInSandbox(unittest.TestCase):
    def test_bats_does_not_source_host_path(self):
        """The auto-generated bats test must not source a host path."""
        src = BATS_LAYER.read_text()
        # Look for the old pattern: source "<host path>"
        # The new pattern should be: source "./target.sh"
        if "script.path.as_posix()" in src:
            self.fail("bats_layer.py still uses script.path.as_posix() to "
                      "build a host path inside the bats test")
        # The new pattern uses a staged path
        self.assertIn("./target.sh", src,
            "bats_layer.py does not use the staged ./target.sh path; the "
            "bats test may still be sourcing a host path")

    def test_bats_does_not_invoke_subprocess_on_host(self):
        """The bats layer must not call subprocess.run on bats on the host."""
        src = BATS_LAYER.read_text()
        if "subprocess.run(\n                    [bats_path" in src:
            self.fail("bats_layer.py still invokes subprocess.run([bats_path, ...]) "
                      "on the host; it must run inside the sandbox")


if __name__ == "__main__":
    unittest.main()
