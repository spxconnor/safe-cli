"""Layer 5 — shfmt formatter with revalidation.

Runs `shfmt -d` (diff) to compare the script content against the canonical
formatted form. If formatting is requested via --fix, applies the diff.

After applying formatting, the orchestrator re-runs the static layers
(tree-sitter + bash -n + shellcheck) — formatting alone never makes a
script correct, and the formatter itself can introduce problems.
"""
from __future__ import annotations

import subprocess
from typing import Optional

from ..diagnostic import Category, LayerResult, Severity
from ..script import Script
from .base import Layer, LayerContext


class ShfmtLayer(Layer):
    name = "shfmt"
    description = "shfmt formatter diff and (optional) apply"

    def run(self, script: Script, context: Optional[LayerContext] = None) -> LayerResult:
        result = self._make_result()
        timeout_ms = self.config.timeouts.shfmt_ms

        # Decide between check mode and apply mode
        apply = bool(context and context.extra.get("shfmt_apply", False))

        try:
            with self._timer():
                proc = subprocess.run(
                    [self.config.tools.shfmt, "-i", "2", "-ci", "-bn", "-sr", "-" if apply else "-d"],
                    input=script.content,
                    capture_output=True,
                    text=True,
                    timeout=max(1, timeout_ms / 1000),
                )
        except subprocess.TimeoutExpired:
            result.status = "error"
            result.add(self._diag(
                tool="shfmt",
                category=Category.TIMEOUT,
                severity=Severity.ERROR,
                message=f"shfmt exceeded {timeout_ms}ms timeout",
                suggested_action="shorten_script",
            ))
            result.duration_ms = self._elapsed()
            return result
        except FileNotFoundError as e:
            result.status = "skip"
            result.notes.append(f"shfmt not found: {e}")
            result.duration_ms = self._elapsed()
            return result

        stderr = proc.stderr or ""
        stdout = proc.stdout or ""

        if proc.returncode not in (0, 1):
            # shfmt writes parse errors to stderr with rc=1
            result.status = "fail"
            result.add(self._diag(
                tool="shfmt",
                category=Category.PARSING,
                severity=Severity.ERROR,
                message=f"shfmt parse error: {stderr.strip() or 'unknown'}",
                raw=stderr[:500],
                suggested_action="fix_syntax",
            ))
            result.duration_ms = self._elapsed()
            return result

        if apply:
            # shfmt in non-diff mode emits the formatted script to stdout
            new_content = stdout
            if new_content and new_content != script.content:
                # NOTE: we do not mutate script here — caller decides via repair.
                result.notes.append(
                    f"shfmt would reformat {len(script.content) - len(new_content):+d} chars"
                )
                result.metadata["formatted"] = new_content
                result.metadata["would_change"] = True
            else:
                result.metadata["would_change"] = False
            result.status = "pass"
        else:
            # diff mode: rc=1 + non-empty stdout means "would reformat"
            if proc.returncode == 0:
                result.status = "pass"
                result.metadata["formatted"] = True
            else:
                # diff is informational; don't fail the gate unless it can't parse
                # the script at all. Style drift alone is a style diagnostic.
                result.status = "warn"
                result.metadata["formatted"] = False
                result.metadata["diff"] = stdout[:2000]
                result.add(self._diag(
                    tool="shfmt",
                    category=Category.FORMATTING,
                    severity=Severity.STYLE,
                    message="Script is not formatted according to shfmt canonical style",
                    code="SHFMT_DIFF",
                    raw=stdout[:500],
                    repairable=True,
                    suggested_action="shfmt_apply",
                ))

        result.duration_ms = self._elapsed()
        return result

    def _diag(self, **kwargs):
        from .base import diagnostic_from_message
        return diagnostic_from_message(layer=self.name, **kwargs)
