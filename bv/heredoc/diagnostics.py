"""bv/heredoc/diagnostics.py - stable rule IDs and the diagnostic builder.

All heredoc findings flow through the existing safe-cli Diagnostic
class (in bv.diagnostic). This module just provides:
  - the rule-ID constants
  - a small helper that builds Diagnostics with consistent shape
  - a mapping from rule ID to (severity, category)
"""
from __future__ import annotations

from typing import Tuple

from ..diagnostic import (
    Category,
    Diagnostic,
    LayerResult,
    Severity,
)


# Stable rule IDs (do not renumber; AI agents depend on them).
BV_HEREDOC_001 = "BV-HEREDOC-001"   # Unterminated heredoc
BV_HEREDOC_002 = "BV-HEREDOC-002"   # Malformed terminator
BV_HEREDOC_003 = "BV-HEREDOC-003"   # Trailing whitespace on terminator
BV_HEREDOC_004 = "BV-HEREDOC-004"   # Unexpected indentation
BV_HEREDOC_005 = "BV-HEREDOC-005"   # Unquoted heredoc contains shell expansion
BV_HEREDOC_006 = "BV-HEREDOC-006"   # Possibly unintended expansion (structured data target)
BV_HEREDOC_007 = "BV-HEREDOC-007"   # Backslash-newline continuation in unquoted heredoc
BV_HEREDOC_008 = "BV-HEREDOC-008"   # Ambiguous backslash semantics
BV_HEREDOC_009 = "BV-HEREDOC-009"   # CRLF heredoc delimiter mismatch
BV_HEREDOC_010 = "BV-HEREDOC-010"   # Nested heredoc structure detected
BV_HEREDOC_011 = "BV-HEREDOC-011"   # Heredoc body changed by automatic repair
BV_HEREDOC_012 = "BV-HEREDOC-012"   # Tree Sitter and lexical scanner disagree
BV_HEREDOC_020 = "BV-HEREDOC-020"   # Heredoc body exceeds configured analysis limit
BV_HEREDOC_021 = "BV-HEREDOC-021"   # Maximum heredoc count exceeded
BV_HEREDOC_022 = "BV-HEREDOC-022"   # Heredoc nesting depth exceeded


# Default severity for each rule. Conservative: errors are reserved for
# actual broken heredocs; warnings for behavior that may surprise the
# author; info for things that are not problems but worth knowing.
_RULE_SEVERITY = {
    BV_HEREDOC_001: Severity.ERROR,
    BV_HEREDOC_002: Severity.ERROR,
    BV_HEREDOC_003: Severity.WARNING,
    BV_HEREDOC_004: Severity.WARNING,
    BV_HEREDOC_005: Severity.INFO,
    BV_HEREDOC_006: Severity.WARNING,
    BV_HEREDOC_007: Severity.INFO,
    BV_HEREDOC_008: Severity.WARNING,
    BV_HEREDOC_009: Severity.WARNING,
    BV_HEREDOC_010: Severity.INFO,
    BV_HEREDOC_011: Severity.WARNING,
    BV_HEREDOC_012: Severity.ERROR,
    BV_HEREDOC_020: Severity.WARNING,
    BV_HEREDOC_021: Severity.WARNING,
    BV_HEREDOC_022: Severity.WARNING,
}


# Categories per rule. Bash semantics live under SYNTAX or PARSING.
# Behavior and security observations live under SECURITY or QUOTING.
_RULE_CATEGORY = {
    BV_HEREDOC_001: Category.SYNTAX,
    BV_HEREDOC_002: Category.SYNTAX,
    BV_HEREDOC_003: Category.SYNTAX,
    BV_HEREDOC_004: Category.SYNTAX,
    BV_HEREDOC_005: Category.QUOTING,
    BV_HEREDOC_006: Category.SECURITY,
    BV_HEREDOC_007: Category.EXPANSION,
    BV_HEREDOC_008: Category.PARSING,
    BV_HEREDOC_009: Category.SYNTAX,
    BV_HEREDOC_010: Category.SYNTAX,
    BV_HEREDOC_011: Category.REPAIR,  # custom; downstream reporters can map
    BV_HEREDOC_012: Category.PARSING,
    BV_HEREDOC_020: Category.RUNTIME,
    BV_HEREDOC_021: Category.RUNTIME,
    BV_HEREDOC_022: Category.RUNTIME,
}


def make_diagnostic(
    rule_id: str,
    file: str,
    line: int,
    column: int,
    message: str,
    code_extra: str = "",
) -> Diagnostic:
    """Build a Diagnostic with the standard heredoc-rule shape."""
    sev = _RULE_SEVERITY.get(rule_id, Severity.WARNING)
    cat = _RULE_CATEGORY.get(rule_id, Category.SYNTAX)
    return Diagnostic(
        tool="heredoc",
        category=cat,
        severity=sev,
        file=file,
        line=line,
        column=max(0, column),
        message=message,
        code=rule_id,
        confidence=1.0,
        layer="heredoc",
        repairable=False,  # never auto-quote or auto-trim
    )


def attach(layer_result: LayerResult, diag: Diagnostic) -> None:
    layer_result.add(diag)
