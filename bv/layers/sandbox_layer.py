"""Layer 8 — Sandboxed runtime execution.

Runs the Bash script inside the Docker sandbox and records:
  - exit code
  - stdout / stderr
  - side effects (Layer 11 is dedicated to this)
  - command execution log via -x
  - any timeout / kill events

The sandbox is mandatory for autonomous execution. Direct host execution
is only permitted for the verified well-known scripts and is controlled
by the orchestrator.
"""
from __future__ import annotations

from typing import Optional

from ..diagnostic import Category, LayerResult, Severity
from ..script import Script
from .base import Layer, LayerContext
from ..sandbox.docker_sandbox import DockerSandbox


class SandboxLayer(Layer):
    name = "sandbox"
    description = "Hard-sandboxed Docker execution of the script"

    def run(self, script: Script, context: Optional[LayerContext] = None) -> LayerResult:
        result = self._make_result()
        skip_sandbox = bool(context and context.extra.get("skip_sandbox"))
        if skip_sandbox:
            result.status = "skip"
            result.notes.append("skip_sandbox set in context")
            return result

        # Wrap the script with `set -x` and trap to capture exit signals
        wrapped = self._wrap_with_trace(script.content)

        try:
            sb = DockerSandbox(self.config)
        except Exception as e:  # noqa: BLE001
            # P0 8 fix: a skipped layer is INCOMPLETE coverage, not
            # a pass. The safe execution path must refuse to run
            # when the security boundary was never exercised.
            result.status = "incomplete"
            result.notes.append(
                f"Docker sandbox unavailable: {e}. sandbox "
                "coverage is INCOMPLETE; the safe execution path "
                "must refuse to run."
            )
            return result

        with self._timer():
            with sb.run_script(wrapped) as sr:
                result.metadata = {
                    "exit_code": sr.exit_code,
                    "duration_ms": sr.duration_ms,
                    "container_id": sr.container_id,
                    "stdout": sr.stdout[-4000:],   # cap to avoid blowing up
                    "stderr": sr.stderr[-4000:],
                    "timed_out": sr.timed_out,
                    "error": sr.error,
                }
                if sr.timed_out:
                    result.status = "fail"
                    result.add(self._diag(
                        tool="docker_sandbox",
                        category=Category.TIMEOUT,
                        severity=Severity.ERROR,
                        message=f"Sandbox execution timed out after {sr.duration_ms}ms",
                        raw=sr.error,
                        suggested_action="fix_infinite_loop",
                    ))
                elif sr.exit_code == 0:
                    result.status = "pass"
                else:
                    result.status = "fail"
                    result.add(self._diag(
                        tool="docker_sandbox",
                        category=Category.EXIT_STATUS,
                        severity=Severity.ERROR,
                        message=f"Script exited with non-zero status {sr.exit_code}",
                        raw=(sr.stderr or sr.stdout)[-1000:],
                        suggested_action="fix_exit_status",
                    ))

        result.duration_ms = self._elapsed()
        return result

    @staticmethod
    def _wrap_with_trace(content: str) -> str:
        # P0-3 (round 2): stop mutating target shell semantics.
        # The previous wrapper injected `set -o pipefail` and `set -x`
        # which changed Bash pipeline status semantics (false negatives /
        # false positives on sandbox vs host) and could leak secrets
        # through xtrace output before our redactor ran.
        #
        # The safe-cli invariant is: execute the exact verified
        # artifact bytes inside the sandbox. No mutations.
        #
        # If explicit tracing is required, callers can wrap the
        # artifact themselves before passing it in; that is a
        # user-visible decision, not a default behavior.
        return content

    def _diag(self, **kwargs):
        from .base import diagnostic_from_message
        return diagnostic_from_message(layer=self.name, **kwargs)
