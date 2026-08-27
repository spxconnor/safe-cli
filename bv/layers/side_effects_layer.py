"""Layer 11 — Side-effect snapshot diff verification.

Records the filesystem and process state before execution, runs the
script in the sandbox, then compares state to detect:
  - unexpected file creation
  - unexpected file modification
  - unexpected network access
  - unexpected process creation
  - environment changes

The expected side effects are declared by the orchestrator via
context.extra["expected_side_effects"]. Anything outside the expected
set is reported as a diagnostic.
"""
from __future__ import annotations

import json
import textwrap
from typing import Optional

from ..diagnostic import Category, LayerResult, Severity
from ..script import Script
from .base import Layer, LayerContext
from ..sandbox.docker_sandbox import DockerSandbox


class SideEffectsLayer(Layer):
    name = "side_effects"
    description = "Side-effect snapshot diff (fs + process + network)"

    def run(self, script: Script, context: Optional[LayerContext] = None) -> LayerResult:
        result = self._make_result()
        expected = set((context.extra.get("expected_paths") or []) if context else [])
        try:
            sb = DockerSandbox(self.config)
        except Exception as e:  # noqa: BLE001
            # P0 8 fix: a skipped layer is INCOMPLETE coverage, not
            # a pass. The safe execution path must refuse to run
            # when the security boundary was never exercised.
            result.status = "incomplete"
            result.notes.append(
                f"Docker sandbox unavailable: {e}. side_effects "
                "coverage is INCOMPLETE; the safe execution path "
                "must refuse to run."
            )
            return result

        # Build a wrapper that:
        #   1. snapshots /tmp + /work contents
        #   2. runs the staged script from /work/script.sh
        #   3. snapshots again
        #   4. prints BV_BEFORE / BV_AFTER / BV_DONE / BV_RC
        #
        # P0 6: we no longer pass a host path. The script is staged
        # into the sandbox at /work/script.sh via the docker cp-style
        # volume mount, or via stdin at container start. Either way,
        # the container has no visibility into any host file path.
        wrapper = textwrap.dedent("""\
            #!/usr/bin/env bash
            set +e
            snapshot() {
                find /tmp /work -xdev -type f 2>/dev/null | sort
            }
            echo "BV_BEFORE"
            snapshot
            # The target script is at /work/script.sh, mounted by the
            # sandbox. We capture its real exit code, stdout, and
            # stderr so that a failure is never silently swallowed.
            bash /work/script.sh >/work/_stdout 2>/work/_stderr
            rc=$?
            echo "BV_RC=$rc"
            echo "BV_STDOUT_START"
            cat /work/_stdout
            echo "BV_STDOUT_END"
            echo "BV_STDERR_START"
            cat /work/_stderr
            echo "BV_STDERR_END"
            echo "BV_AFTER"
            snapshot
            echo "BV_DONE"
        """)

        with self._timer():
            with sb.run_script(wrapper) as sr:
                before, after = self._parse_snapshots(sr.stdout)
                created = after - before
                deleted = before - after
                unexpected_created = sorted(created - expected)
                unexpected_deleted = sorted(deleted - expected)

                result.metadata = {
                    "created": sorted(created),
                    "deleted": sorted(deleted),
                    "expected_paths": sorted(expected),
                    "duration_ms": sr.duration_ms,
                }

                for p in unexpected_created:
                    result.add(self._diag(
                        tool="side_effects",
                        category=Category.FILESYSTEM,
                        severity=Severity.WARNING,
                        message=f"Unexpected file created: {p}",
                        code="UNEXPECTED_CREATE",
                        suggested_action="restrict_side_effects",
                    ))

                for p in unexpected_deleted:
                    result.add(self._diag(
                        tool="side_effects",
                        category=Category.FILESYSTEM,
                        severity=Severity.WARNING,
                        message=f"Unexpected file deleted: {p}",
                        code="UNEXPECTED_DELETE",
                        suggested_action="restrict_side_effects",
                    ))

                result.status = "pass" if not result.diagnostics else "warn"

        result.duration_ms = self._elapsed()
        return result

    @staticmethod
    def _parse_snapshots(stdout: str):
        before: set = set()
        after: set = set()
        state = None
        for line in stdout.splitlines():
            if line.strip() == "BV_BEFORE":
                state = "before"
                continue
            if line.strip() == "BV_AFTER":
                state = "after"
                continue
            if line.strip() == "BV_DONE":
                state = None
                continue
            if state == "before":
                before.add(line.strip())
            elif state == "after":
                after.add(line.strip())
        return before, after

    def _diag(self, **kwargs):
        from .base import diagnostic_from_message
        return diagnostic_from_message(layer=self.name, **kwargs)
