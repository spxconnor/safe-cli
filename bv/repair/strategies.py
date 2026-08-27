"""Repair strategies.

Each strategy maps a normalized Diagnostic pattern to a small, surgical
edit. The repair engine invokes strategies in priority order until one
succeeds. Strategies MUST preserve the original intent of the script.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from ..diagnostic import Diagnostic, Category, Severity


# A repair is a function that takes the current script content + diagnostic
# and returns either a new content string (changed) or None (no repair).
RepairFn = Callable[[str, Diagnostic], Optional[str]]


@dataclass
class RepairStrategy:
    name: str
    description: str
    applies_to: Callable[[Diagnostic], bool]
    repair: RepairFn
    priority: int = 100


# Pre-build the quote character class so we don't have to escape backslashes
# inside an f-string (Python 3.10 f-strings cannot contain backslashes).
_QUOTE_CHARS = '"' + "'"


def _quote_unquoted_variable(content: str, d: Diagnostic) -> Optional[str]:
    """Wrap a single unquoted $VAR reference with double quotes.

    Heuristic-only — replaces the FIRST occurrence of $VAR on the offending
    line where the variable is not already inside double quotes.
    """
    line_no = d.line
    if line_no <= 0:
        return None
    lines = content.split("\n")
    if line_no - 1 >= len(lines):
        return None
    line = lines[line_no - 1]

    m = re.search(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", line)
    if not m:
        return None
    var = m.group(1)
    # Build the pattern using string concatenation to keep Python 3.10 happy.
    pat = re.compile(
        r"(?<![" + _QUOTE_CHARS + r"])\$\{?" + re.escape(var) + r"\}?(?![" + _QUOTE_CHARS + r"])"
    )
    replacement = '"$' + var + '"'
    new_line, count = pat.subn(replacement, line, count=1)
    if count == 0:
        return None
    lines[line_no - 1] = new_line
    return "\n".join(lines)


def _shfmt_apply(content: str, d: Diagnostic) -> Optional[str]:
    """Apply the shfmt-canonical content if available on the diagnostic."""
    if d.code != "SHFMT_DIFF":
        return None
    if not getattr(d, "metadata_for_repair", None):
        return None
    return d.metadata_for_repair.get("formatted")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

STRATEGIES: list[RepairStrategy] = [
    RepairStrategy(
        name="quote_unquoted_variable",
        description="Wrap unquoted $VAR with double quotes (SC2086-style)",
        applies_to=lambda d: d.code == "SC2086",
        repair=_quote_unquoted_variable,
        priority=10,
    ),
    RepairStrategy(
        name="shfmt_apply",
        description="Replace content with shfmt-canonical formatting",
        applies_to=lambda d: d.code == "SHFMT_DIFF",
        repair=_shfmt_apply,
        priority=80,
    ),
]


def find_strategy(d: Diagnostic) -> Optional[RepairStrategy]:
    for s in STRATEGIES:
        if s.applies_to(d):
            return s
    return None
