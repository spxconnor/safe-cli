"""Base interface for all verification layers.

Every layer (tree-sitter, bash -n, shellcheck, LSP, shfmt, bats, sandbox,
adversarial, fuzz, side-effects) implements this interface so the orchestrator
can compose them uniformly.
"""
from __future__ import annotations

import abc
import time
from dataclasses import dataclass
from typing import Optional

from ..config import Config
from ..diagnostic import Diagnostic, LayerResult
from ..script import Script


class Layer(abc.ABC):
    """Abstract base for all verification layers."""

    name: str = "abstract"
    description: str = ""

    def __init__(self, config: Config) -> None:
        self.config = config

    @abc.abstractmethod
    def run(self, script: Script, context: Optional["LayerContext"] = None) -> LayerResult:
        """Execute this layer against the given script.

        Implementations should populate a LayerResult with diagnostics.
        Implementations should NEVER mutate the script directly. Repairs
        must go through the repair engine.
        """
        raise NotImplementedError

    def _make_result(self, status: str = "pass", notes: list[str] | None = None) -> LayerResult:
        return LayerResult(layer=self.name, status=status, notes=notes or [])

    def _timer(self) -> "_Timer":
        """Return a fresh timer. Callers should use it as a context manager.
        After the with-block exits, the elapsed time is read from the timer.
        """
        self._last_timer = _Timer()
        return self._last_timer

    def _elapsed(self) -> int:
        """Read elapsed ms from the last completed timer (0 if never run)."""
        return getattr(self, "_last_timer", _Timer()).elapsed_ms


    def _elapsed(self) -> int:
        """Read elapsed ms from the last completed timer (0 if never run)."""
        return getattr(self, "_last_timer", _Timer()).elapsed_ms


@dataclass
class LayerContext:
    """Cross-layer context (e.g. shared sandbox ID, repair attempts)."""
    sandbox_id: Optional[str] = None
    attempt: int = 0
    extra: dict = None

    def __post_init__(self):
        if self.extra is None:
            self.extra = {}


class _Timer:
    """Stateful timer: instance attribute .elapsed_ms holds the last run duration."""
    def __init__(self):
        self.elapsed_ms = 0
        self._start = 0.0

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.elapsed_ms = int((time.monotonic() - self._start) * 1000)
        return False


def _new_timer():
    """Public constructor so layers always get a fresh timer."""
    return _Timer()


def diagnostic_from_message(
    tool: str,
    category,
    severity,
    message: str,
    file: str = "",
    line: int = 0,
    column: int = 0,
    end_line: int = 0,
    end_column: int = 0,
    code: str = "",
    confidence: float = 1.0,
    raw: str = "",
    layer: str = "",
    repairable: bool = True,
    suggested_action: str = "",
) -> Diagnostic:
    """Helper to build a Diagnostic with sensible defaults."""
    from ..diagnostic import Category, Severity
    if isinstance(category, str):
        category = Category(category)
    if isinstance(severity, str):
        severity = Severity(severity)
    return Diagnostic(
        tool=tool,
        category=category,
        severity=severity,
        file=file,
        line=line,
        column=column,
        end_line=end_line,
        end_column=end_column,
        message=message,
        code=code,
        confidence=confidence,
        raw_output=raw,
        layer=layer,
        repairable=repairable,
        suggested_action=suggested_action,
    )
