"""Regression tests for P0 3: --no-sandbox must never be the
default for the agent execution path.

A security product cannot have:

    normal path = secure
    agent path = shortcut

because the agent path is the path most likely to encounter
adversarial or malformed code.
"""
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent.parent
SAFE_CLI = REPO / "bin" / "safe_cli.py"
AGENT_HELPER = REPO / "agent_integration.sh"


class TestNoNoSandboxDefault(unittest.TestCase):

    def test_cli_does_not_pass_no_sandbox_by_default(self):
        """The CLI must not pass --no-sandbox to bash_verify from inside
        cmd_run or cmd_exec bodies. Comments documenting the option
        are fine; this checks for the actual flag being passed as a
        CLI argument."""
        import re
        src = SAFE_CLI.read_text()
        for name in ("cmd_run", "cmd_exec"):
            idx = src.find(f"def {name}(")
            if idx < 0:
                self.fail(f"{name} not found in CLI")
                continue
            end = src.find("\ndef ", idx + 1)
            if end < 0:
                end = len(src)
            body = src[idx:end]
            # Look for --no-sandbox as a CLI argument
            in_arg = re.search(r'"--no-sandbox"', body) or re.search(r"'--no-sandbox'", body)
            self.assertIsNone(
                in_arg,
                f"{name} passes --no-sandbox; the agent path must never "
                "bypass the sandbox as a default",
            )

    def test_agent_helper_does_not_pass_no_sandbox(self):
        """bv_wrap in the agent helper must not pass --no-sandbox as
        a CLI flag. Comments documenting the option are fine."""
        import re
        if not AGENT_HELPER.exists():
            self.skipTest(f"agent_integration.sh not found at {AGENT_HELPER}")
        src = AGENT_HELPER.read_text()
        # Find the bv_wrap function body
        wrap_idx = src.find("bv_wrap()")
        if wrap_idx < 0:
            self.skipTest("bv_wrap function not found")
        end = src.find("\nbv_", wrap_idx + 1)
        if end < 0:
            end = len(src)
        body = src[wrap_idx:end]
        # Look for --no-sandbox as a CLI argument, not as a comment
        in_arg = re.search(r'"--no-sandbox"', body) or re.search(r"'--no-sandbox'", body)
        self.assertIsNone(
            in_arg,
            "agent_integration.sh bv_wrap passes --no-sandbox; the agent "
            "path must always go through the full sandbox path",
        )


if __name__ == "__main__":
    unittest.main()
