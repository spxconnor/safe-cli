"""Layer 2 — bash -n syntax gate wrapper.

Runs `bash -n` against the script content and captures exit code plus
stderr. This is the canonical native Bash syntax check.
"""
from __future__ import annotations

import subprocess
from typing import Optional

from ..diagnostic import Category, LayerResult, Severity
from ..script import Script
from .base import Layer, LayerContext


class BashNLayer(Layer):
    name = "bash_n"
    description = "Native bash -n syntax check"

    def run(self, script: Script, context: Optional[LayerContext] = None) -> LayerResult:
        result = self._make_result()
        timeout_ms = self.config.timeouts.bash_n_ms
        try:
            with self._timer():
                proc = subprocess.run(
                    [self.config.tools.bash, "-n"],
                    input=script.content,
                    capture_output=True,
                    text=True,
                    timeout=max(1, timeout_ms / 1000),
                )
        except subprocess.TimeoutExpired:
            result.status = "error"
            result.add(self._diag(
                tool="bash",
                category=Category.TIMEOUT,
                severity=Severity.ERROR,
                message=f"bash -n exceeded {timeout_ms}ms timeout",
                suggested_action="shorten_script",
            ))
            result.duration_ms = self._elapsed()
            return result
        except FileNotFoundError as e:
            result.status = "skip"
            result.notes.append(f"bash not found: {e}")
            result.duration_ms = self._elapsed()
            return result

        stderr = proc.stderr or ""
        if proc.returncode == 0:
            result.status = "pass"
        else:
            result.status = "fail"
            # bash -n error format: "line N: ..." or "bash: stdin: line N: ..."
            for line in stderr.strip().splitlines():
                # Try to extract line number
                ln = self._extract_line(line)
                msg = line.split(":", 2)[-1].strip() if ":" in line else line
                result.add(self._diag(
                    tool="bash",
                    category=Category.SYNTAX,
                    severity=Severity.ERROR,
                    file=script.path.as_posix() if script.path else "<stdin>",
                    line=ln,
                    message=msg or "bash -n reported syntax error",
                    code="BASH_SYNTAX",
                    raw=line,
                    suggested_action="fix_syntax",
                ))

        result.metadata = {"returncode": proc.returncode, "stderr": stderr}
        result.duration_ms = self._elapsed()
        return result

    def _extract_line(self, msg: str) -> int:
        """Extract a 1-based line number from common bash -n error formats."""
        import re
        m = re.search(r"line\s+(\d+)", msg)
        if m:
            return int(m.group(1))
        return 0

    def _diag(self, **kwargs):
        from .base import diagnostic_from_message
        return diagnostic_from_message(layer=self.name, **kwargs)
