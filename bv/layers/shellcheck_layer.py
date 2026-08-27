"""Layer 3 — ShellCheck with normalized diagnostics.

Runs ShellCheck against the script content and converts its JSON output into
normalized Diagnostic instances.
"""
from __future__ import annotations

import json
import subprocess
from typing import Optional

from ..diagnostic import Category, LayerResult, Severity
from ..script import Script
from .base import Layer, LayerContext


# ShellCheck level -> our severity
_LEVEL_TO_SEV = {
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "info": Severity.INFO,
    "style": Severity.STYLE,
}

# ShellCheck code -> our category hint (best-effort mapping)
_CODE_TO_CATEGORY = {
    "SC1003": Category.QUOTING,
    "SC1004": Category.QUOTING,
    "SC1035": Category.QUOTING,
    "SC1036": Category.QUOTING,
    "SC1037": Category.QUOTING,
    "SC1046": Category.QUOTING,
    "SC1056": Category.QUOTING,
    "SC1058": Category.QUOTING,
    "SC1061": Category.QUOTING,
    "SC1062": Category.QUOTING,
    "SC1068": Category.QUOTING,
    "SC1072": Category.QUOTING,
    "SC1073": Category.QUOTING,
    "SC1083": Category.QUOTING,
    "SC1086": Category.QUOTING,
    "SC1087": Category.QUOTING,
    "SC2086": Category.QUOTING,
    "SC2154": Category.VARIABLE,
    "SC2155": Category.EXIT_STATUS,
    "SC2164": Category.EXIT_STATUS,
    "SC2034": Category.VARIABLE,
    "SC2206": Category.QUOTING,
    "SC2207": Category.ARRAY,
    "SC2046": Category.QUOTING,
    "SC2048": Category.QUOTING,
    "SC2002": Category.UNKNOWN,
    "SC2004": Category.EXPANSION,
    "SC2128": Category.EXPANSION,
    "SC2153": Category.VARIABLE,
    "SC2199": Category.ARRAY,
    "SC2197": Category.QUOTING,
    "SC2230": Category.EXPANSION,
    "SC2236": Category.PIPELINE,
    "SC2317": Category.SYNTAX,
    "SC2068": Category.ARRAY,
    "SC2145": Category.VARIABLE,
    "SC2148": Category.SECURITY,
    "SC2155": Category.EXIT_STATUS,
}


class ShellCheckLayer(Layer):
    name = "shellcheck"
    description = "ShellCheck static analysis (machine-readable JSON output)"

    def run(self, script: Script, context: Optional[LayerContext] = None) -> LayerResult:
        result = self._make_result()
        timeout_ms = self.config.timeouts.shellcheck_ms

        try:
            with self._timer():
                proc = subprocess.run(
                    [
                        self.config.tools.shellcheck,
                        "--format=json1",
                        "--severity=style",
                        "-s", "bash",
                        "-",
                    ],
                    input=script.content,
                    capture_output=True,
                    text=True,
                    timeout=max(1, timeout_ms / 1000),
                )
        except subprocess.TimeoutExpired:
            result.status = "error"
            result.add(self._diag(
                tool="shellcheck",
                category=Category.TIMEOUT,
                severity=Severity.ERROR,
                message=f"shellcheck exceeded {timeout_ms}ms timeout",
                suggested_action="shorten_script",
            ))
            result.duration_ms = self._elapsed()
            return result
        except FileNotFoundError as e:
            result.status = "skip"
            result.notes.append(f"shellcheck not found: {e}")
            result.duration_ms = self._elapsed()
            return result

        # shellcheck exits 0 = no issues, 1 = issues found, >1 = error
        raw_stdout = proc.stdout or ""
        if proc.returncode not in (0, 1):
            result.status = "error"
            result.add(self._diag(
                tool="shellcheck",
                category=Category.UNKNOWN,
                severity=Severity.ERROR,
                message=f"shellcheck internal error (exit={proc.returncode})",
                raw=(proc.stderr or "")[:500],
            ))
            result.duration_ms = self._elapsed()
            return result

        diagnostics = []
        try:
            comments = json.loads(raw_stdout) if raw_stdout.strip() else []
        except json.JSONDecodeError as e:
            result.status = "error"
            result.add(self._diag(
                tool="shellcheck",
                category=Category.UNKNOWN,
                severity=Severity.ERROR,
                message=f"shellcheck returned invalid JSON: {e}",
                raw=raw_stdout[:500],
            ))
            result.duration_ms = self._elapsed()
            return result

        # shellcheck --format=json1 returns {"comments": [...]}; tolerate both shapes
        if isinstance(comments, dict) and "comments" in comments:
            comments = comments["comments"]
        if not isinstance(comments, list):
            comments = []
        for comment in comments:
            if not isinstance(comment, dict):
                continue
            line = comment.get("line", 0)
            col = comment.get("column", 0)
            end_line = comment.get("endLine", 0)
            end_col = comment.get("endColumn", 0)
            level = comment.get("level", "warning")
            raw_code = comment.get("code", 0)
            code = f"SC{raw_code}" if isinstance(raw_code, int) else str(raw_code)
            message = comment.get("message", "")
            sev = _LEVEL_TO_SEV.get(level, Severity.WARNING)
            cat = _CODE_TO_CATEGORY.get(code, Category.UNKNOWN)
            repairable = sev in (Severity.WARNING, Severity.ERROR)
            diagnostics.append(self._diag(
                tool="shellcheck",
                category=cat,
                severity=sev,
                file=script.path.as_posix() if script.path else "<stdin>",
                line=line,
                column=col,
                end_line=end_line,
                end_column=end_col,
                message=message,
                code=code,
                confidence=1.0,
                raw=json.dumps(comment),
                repairable=repairable,
                suggested_action="quote_variable" if code == "SC2086" else "",
            ))

        # Decide status: any ERROR-severity diagnostic fails the gate.
        has_error = any(d.severity == Severity.ERROR for d in diagnostics)
        if has_error:
            result.status = "fail"
        elif diagnostics:
            result.status = "warn"
        else:
            result.status = "pass"

        result.diagnostics.extend(diagnostics)
        result.metadata = {
            "returncode": proc.returncode,
            "comment_count": len(diagnostics),
            "by_code": self._count_by(diagnostics, "code"),
        }
        result.duration_ms = self._elapsed()
        return result

    @staticmethod
    def _count_by(diagnostics, attr):
        out = {}
        for d in diagnostics:
            v = getattr(d, attr, "")
            out[v] = out.get(v, 0) + 1
        return out

    def _diag(self, **kwargs):
        from .base import diagnostic_from_message
        return diagnostic_from_message(layer=self.name, **kwargs)
