"""Regression test for the P0-4 cleanup_errors NameError fix.

The previous code referenced a local variable `cleanup_errors` in five
places inside DockerSandbox.run_script but never declared it:

    cleanup_errors.append(...)   # 5 occurrences
    ...
    yield SandboxResult(
        ...
        cleanup_failures=list(cleanup_errors),
    )

The first time a cleanup exception was caught (or even the first time
the code reached the yield, since `cleanup_errors` was on the same
expression), Python raised:

    NameError: name 'cleanup_errors' is not defined

This broke the Bats layer (and any other caller that hit a cleanup
exception). The fix initializes `cleanup_errors: list[str] = []` at
the top of run_script.
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, "/opt/safe-cli-repo")


class TestCleanupErrorsInitialized(unittest.TestCase):
    def test_docker_sandbox_source_declares_cleanup_errors_local(self):
        # Static check: the function body must declare the variable
        # before the first append() call.
        path = "/opt/safe-cli-repo/bv/sandbox/docker_sandbox.py"
        with open(path, "r") as f:
            src = f.read()
        # Find the run_script method body. Skip the SandboxResult class
        # above it (which also mentions cleanup_errors).
        marker = "    def run_script("
        idx = src.find(marker)
        self.assertGreater(idx, 0, "run_script not found")
        # Extract just the body between this def and the next top-level def.
        body_start = idx + len(marker)
        next_def = src.find("\n    def ", body_start)
        body = src[body_start:] if next_def < 0 else src[body_start:next_def]
        lines = body.split("\n")
        # Find the first ACTIVE `cleanup_errors.append(...)` call (not inside
        # a comment or string). We accept only lines whose stripped form
        # starts with whitespace + `cleanup_errors.append(`.
        first_append = None
        first_assign = None
        for i, ln in enumerate(lines):
            stripped = ln.strip()
            # Skip pure-comment lines.
            if stripped.startswith("#"):
                continue
            # Skip lines that are clearly inside a string (contain the
            # token inside double quotes — used in docstrings above the
            # method body).
            inside_string = (
                (stripped.startswith('"') and stripped.endswith('"'))
                or (stripped.startswith("'") and stripped.endswith("'"))
                or (stripped.startswith('"""') or stripped.startswith("'''"))
            )
            if inside_string:
                continue
            # Record the first real append() call.
            if (first_append is None
                    and "cleanup_errors.append(" in ln
                    and not ln.lstrip().startswith("#")):
                first_append = i
            # Record the first real assignment to cleanup_errors.
            # We accept either the type-annotated form (cleanup_errors: list[str] = [])
            # or the bare form (cleanup_errors = []). We also tolerate
            # `cleanup_errors: list = []` (no inner type).
            if first_assign is None and "cleanup_errors" in ln:
                after = ln.split("cleanup_errors", 1)[1]
                # Assignment: must contain '=' with '=' not inside quotes.
                # We accept either ":" (annotation) followed by "=" or just "=".
                if (("=" in after or ":" in after)
                        and not stripped.startswith(("'", '"'))):
                    # Look at the immediate post-token character: must be
                    # ':' (annotation) or '=' (assignment) but NOT
                    # something like "cleanup_failures" (the SUBSTRING
                    # we want requires a SPACE or end-of-word after it).
                    tail = after.lstrip()
                    # Allow either:
                    #   cleanup_errors = ...
                    #   cleanup_errors: list = ...
                    # Disallow:
                    #   cleanup_failures (next char is 'f')
                    if tail.startswith(("=", ":")):
                        first_assign = i
            if first_append is not None and first_assign is not None:
                break
        self.assertIsNotNone(
            first_append,
            "no cleanup_errors.append() call found in run_script",
        )
        self.assertIsNotNone(
            first_assign,
            "cleanup_errors is never assigned in run_script",
        )
        self.assertLess(
            first_assign, first_append,
            f"cleanup_errors is assigned at line {first_assign} but used at "
            f"line {first_append}; the declaration must come first to fix "
            f"the P0-4 NameError",
        )

    def test_docker_sandbox_run_script_yields_without_nameerror(self):
        """Drive the run_script generator and assert the yield completes
        without raising NameError. We mock subprocess so no real docker
        daemon is required.
        """
        from bv.config import Config, VerifySettings, Tools
        from bv.sandbox.docker_sandbox import DockerSandbox, SandboxResult

        # Tiny sentinel config.
        cfg = Config(
            verify=VerifySettings(
                sandbox_image="bash:5.1",
                sandbox_image_digest="",  # mutable-tag mode for the static path
            ),
            tools=Tools(docker="/usr/bin/docker"),
        )
        sb = DockerSandbox.__new__(DockerSandbox)  # skip __init__ to avoid real pull
        sb.config = cfg
        sb.image = cfg.verify.sandbox_image
        sb.expected_image_digest = ""
        sb._resolved_image_id = ""
        sb.docker_bin = cfg.tools.docker

        # Mock subprocess so the docker subprocess calls return quickly
        # with predictable output. We do NOT exercise the full happy
        # path; we only need to verify that the yield expression does
        # not raise NameError.
        with patch("subprocess.run") as mock_run:
            def _fake_run(cmd, *a, **kw):
                from unittest.mock import MagicMock
                m = MagicMock()
                m.returncode = 0
                # First call: docker image inspect -> return a stub image
                if "inspect" in cmd and "--format" not in cmd:
                    m.stdout = '[{"Id": "sha256:abc"}]'
                # Calls with --format '{{.Id}}' -> return the id
                elif "--format" in cmd:
                    m.stdout = "sha256:abc"
                # docker create -> return container id
                elif "create" in cmd:
                    m.stdout = "fake-container-id"
                # docker start -> no stdout
                elif "start" in cmd:
                    m.stdout = ""
                # docker wait -> exit code
                elif "wait" in cmd:
                    m.stdout = "0"
                else:
                    m.stdout = ""
                m.stderr = ""
                return m

            mock_run.side_effect = _fake_run

            try:
                with sb.run_script("echo hello\n") as result:
                    # The generator yielded a SandboxResult without
                    # NameError. That's the regression we care about.
                    self.assertIsInstance(result, SandboxResult)
            except NameError as e:
                self.fail(f"run_script raised NameError: {e}")


if __name__ == "__main__":
    unittest.main()
