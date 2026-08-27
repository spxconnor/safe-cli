"""Normalized diagnostic model.

Every analyzer (tree-sitter, bash -n, shellcheck, LSP, etc.) must convert
its raw output into Diagnostic instances so the repair engine and reporter
can reason about failures consistently.
"""
from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class Severity(str, enum.Enum):
    STYLE = "style"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

    @classmethod
    def meets_threshold(cls, actual, threshold):
        """True if `actual` is at least as severe as `threshold`.

        Uses an ordinal map. Higher integer = more severe.

        The dict is built locally inside this method on every call.
        We cannot store it as a class attribute because `enum.Enum`
        treats every class-body assignment as an enum member, so a
        dict at class scope becomes a member (and stops being a dict).
        We cannot store it as a class-level attribute set via `setattr`
        for the same reason. A 4-entry dict literal inside the method
        is fast enough and completely avoids the trap.

        NEVER compare severity strings directly with `<` or `>=`;
        that compares lexically and gives wrong answers (e.g.
        "error" < "warning").
        """
        _order = {s.value: i for i, s in enumerate(
            [cls.STYLE, cls.INFO, cls.WARNING, cls.ERROR]
        )}
        return _order[actual.value] >= _order[threshold.value]


class Category(str, enum.Enum):
    SYNTAX = "syntax"
    PARSING = "parsing"
    QUOTING = "quoting"
    EXPANSION = "expansion"
    VARIABLE = "variable"
    ARRAY = "array"
    REDIRECTION = "redirection"
    PIPELINE = "pipeline"
    TRAP = "trap"
    EXIT_STATUS = "exit_status"
    PORTABILITY = "portability"
    SECURITY = "security"
    RUNTIME = "runtime"
    FILESYSTEM = "filesystem"
    PROCESS = "process"
    NETWORK = "network"
    TEST_FAILURE = "test_failure"
    FORMATTING = "formatting"
    DEPENDENCY = "dependency"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"
    REPAIR = "repair"


# Priority order used by the repair engine (lower index = higher priority).
REPAIR_PRIORITY = [
    Category.SECURITY,
    Category.SYNTAX,
    Category.PARSING,
    Category.EXIT_STATUS,
    Category.RUNTIME,
    Category.QUOTING,
    Category.EXPANSION,
    Category.VARIABLE,
    Category.ARRAY,
    Category.REDIRECTION,
    Category.PIPELINE,
    Category.TRAP,
    Category.PORTABILITY,
    Category.FILESYSTEM,
    Category.PROCESS,
    Category.NETWORK,
    Category.TEST_FAILURE,
    Category.FORMATTING,
    Category.DEPENDENCY,
    Category.TIMEOUT,
    Category.UNKNOWN,
]


@dataclass
class Diagnostic:
    tool: str                            # which analyzer produced this (e.g. "shellcheck")
    category: Category                   # failure category
    severity: Severity                   # severity level
    file: str = ""                       # script path or "<stdin>"
    line: int = 0                        # 1-based line; 0 if unknown
    column: int = 0                      # 1-based column; 0 if unknown
    end_line: int = 0                    # 1-based end line
    end_column: int = 0                  # 1-based end column
    message: str = ""                    # human-readable description
    code: str = ""                       # tool-specific code (e.g. "SC2086")
    confidence: float = 1.0              # 0..1 confidence level
    repairable: bool = True              # whether the repair engine may attempt repair
    suggested_action: str = ""           # e.g. "quote_variable"
    raw_output: str = ""                 # raw tool output for forensics
    layer: str = ""                      # which layer produced this (e.g. "shellcheck")
    fingerprint: str = ""                # auto-computed stable id

    def __post_init__(self) -> None:
        if not isinstance(self.category, Category):
            self.category = Category(self.category)
        if not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity)
        if not self.fingerprint:
            self.fingerprint = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        h = hashlib.sha256()
        h.update(f"{self.tool}|{self.category.value}|{self.code}|".encode())
        h.update(f"{self.line}|{self.column}|".encode())
        h.update(self.message.encode())
        return h.hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Diagnostic":
        return cls(
            tool=d.get("tool", ""),
            category=Category(d.get("category", "unknown")),
            severity=Severity(d.get("severity", "warning")),
            file=d.get("file", ""),
            line=d.get("line", 0),
            column=d.get("column", 0),
            end_line=d.get("end_line", 0),
            end_column=d.get("end_column", 0),
            message=d.get("message", ""),
            code=d.get("code", ""),
            confidence=d.get("confidence", 1.0),
            repairable=d.get("repairable", True),
            suggested_action=d.get("suggested_action", ""),
            raw_output=d.get("raw_output", ""),
            layer=d.get("layer", ""),
            fingerprint=d.get("fingerprint", ""),
        )

    def short(self) -> str:
        loc = f"{self.file}:{self.line}:{self.column}" if self.file else f"line {self.line}"
        code_disp = self.code or "-"
        return f"[{self.tool}/{code_disp}] {loc} {self.severity.value}: {self.message}"


@dataclass
class LayerResult:
    """Output of one verification layer."""
    layer: str                           # layer name
    status: str                          # "pass" | "fail" | "skip" | "incomplete" | "error"
    duration_ms: int = 0
    diagnostics: list[Diagnostic] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add(self, d: Diagnostic) -> None:
        d.layer = self.layer
        self.diagnostics.append(d)

    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == Severity.ERROR]

    def warnings(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == Severity.WARNING]

    def above_threshold(self, threshold: Severity) -> list[Diagnostic]:
        # Use the ordinal comparison on Severity, never compare
        # severity strings directly. (P0 5 fix.)
        return [d for d in self.diagnostics if Severity.meets_threshold(d.severity, threshold)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "notes": self.notes,
            "metadata": self.metadata,
        }


def serialize_diagnostics(ds: list[Diagnostic]) -> str:
    return json.dumps([d.to_dict() for d in ds], indent=2)


def deserialize_diagnostics(s: str) -> list[Diagnostic]:
    return [Diagnostic.from_dict(d) for d in json.loads(s)]


if __name__ == "__main__":
    # Smoke test
    d = Diagnostic(
        tool="shellcheck",
        category=Category.QUOTING,
        severity=Severity.WARNING,
        file="/tmp/x.sh",
        line=3,
        column=12,
        message="Double quote to prevent globbing",
        code="SC2086",
        confidence=0.95,
    )
    print(d.short())
    print("fingerprint:", d.fingerprint)
