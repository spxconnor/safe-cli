"""bv/heredoc/model.py - immutable data classes for heredoc analysis.

These are frozen dataclasses: once analyzed, a heredoc's structural
and semantic state cannot mutate. Repairs create new instances.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple


@dataclass(frozen=True)
class HereDocInfo:
    """Structural record of a single Bash heredoc.

    Coordinates are 1-based for line and column, 0-based for byte
    offsets, matching the rest of safe-cli.
    """
    index: int                              # ordinal among all heredocs in the source
    start_line: int                         # line of the `<<` operator
    start_column: int                       # column of the `<` of the operator
    end_line: Optional[int]                 # line of the terminator; None if unterminated
    operator: str                           # "<<", "<<-", or other normalized form
    raw_delimiter: str                      # the exact token after the operator (with quotes/escapes)
    delimiter: str                          # the semantic delimiter (after quote/escape removal)
    quoted: bool                            # True for <<'X' or <<"X"
    quote_style: Optional[str]              # "'" for single, '"' for double, "\\" for backslash-escape
    strip_tabs: bool                       # True for <<-
    terminated: bool                        # True if a valid terminator was found
    terminator_line: Optional[str]          # the raw terminator line text
    body_start_line: int                   # first body line
    body_end_line: Optional[int]            # last body line (inclusive)
    body: str                               # exact body text (preserved)
    # Optional richer information
    has_expansion_constructs: bool = False  # parameter / command / arithmetic in body
    expansion_construct_lines: Tuple[int, ...] = field(default_factory=tuple)
    backslash_newline_lines: Tuple[int, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class HereDocSemantics:
    """Semantic interpretation of a single heredoc.

    The AST (Tree Sitter) is responsible for structure. The semantics
    layer interprets what the structure means at Bash runtime. Policy
    and the diagnostic system decide what matters.
    """
    expansion_enabled: bool                # True for unquoted delimiter
    parameter_expansion: bool              # True if `$VAR`, `${VAR}` seen in body
    command_substitution: bool            # True if $(...) or `...` seen in body
    arithmetic_expansion: bool            # True if $((...)) seen in body
    backslash_processing: bool             # True for unquoted (Bash does backslash processing)
    backslash_newline_continuations: Tuple[int, ...]
    quoted_literal_mode: bool               # True when delimiter was quoted
    indentation_mode: str                  # "none" | "tabs" (<<- semantics)
    suspicious_expansion: bool              # heuristics flag (structured data target + expansion)
    target_hint: Optional[str] = None      # best-effort hint of where the body is written (None if unknown)


@dataclass(frozen=True)
class HereDocAnalysis:
    """The complete analysis for a single heredoc."""
    info: HereDocInfo
    semantics: HereDocSemantics
    # Compact fingerprint for "before/after repair" comparison
    fingerprint: str
    # Tree Sitter says one thing; the line scanner says another.
    # This is set when the two sources disagree.
    parser_disagreement: bool = False
    parser_disagreement_kind: Optional[str] = None  # e.g. "terminator_line"
