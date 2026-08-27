"""bv/quoting/model.py - structured shell-word model.

A shell word is NOT just text. We capture:
  - exact source span (start_byte, end_byte, line, column)
  - raw text
  - the presence and position of quote types
  - the kinds of expansions it contains
  - its context (assignment, command argument, etc.)
  - the kinds of unsafe behavior the expansion can produce
  - whether we believe the user intended scalar vs list semantics

The repair engine uses these fields to generate minimal safe
candidate rewrites. The fields are deliberately conservative.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional, Tuple


class QuoteType(str, enum.Enum):
    NONE = "none"
    SINGLE = "single"
    DOUBLE = "double"
    PARTIAL = "partial"
    ANSI_C = "ansi_c"
    BRACE = "brace"
    SUBSHELL = "subshell"


class Intent(str, enum.Enum):
    UNKNOWN = "unknown"
    SCALAR = "scalar"
    LIST = "list"
    ARRAY = "array"
    PATH = "path"
    PATTERN = "pattern"
    COMMAND = "command"
    ARITHMETIC = "arithmetic"
    LITERAL = "literal"


class ContextKind(str, enum.Enum):
    COMMAND_ARG = "command_arg"
    COMMAND_NAME = "command_name"
    ASSIGNMENT = "assignment"
    EXPORT_VALUE = "export_value"
    LOCAL_VALUE = "local_value"
    DECLARE_VALUE = "declare_value"
    REDIRECT_TARGET = "redirect_target"
    REDIRECT_SOURCE = "redirect_source"
    TEST_BRACKET = "test_bracket"
    TEST_DOUBLE_BRACKET = "test_double_bracket"
    ARITHMETIC = "arithmetic"
    CASE_PATTERN = "case_pattern"
    HERE_DOC_BODY = "heredoc_body"
    SUBSHELL = "subshell"
    OTHER = "other"


@dataclass(frozen=True)
class Expansion:
    kind: str
    raw: str
    start: int
    end: int
    name: Optional[str] = None


@dataclass(frozen=True)
class SemanticFlags:
    parameter_expansion: bool = False
    command_substitution: bool = False
    arithmetic_expansion: bool = False
    tilde_expansion: bool = False
    word_splitting_possible: bool = False
    pathname_expansion_possible: bool = False
    empty_value_can_disappear: bool = False
    quote_removal_possible: bool = False


@dataclass(frozen=True)
class ShellWord:
    start_byte: int
    end_byte: int
    start_line: int
    start_column: int
    raw_text: str
    quote_type: QuoteType
    has_parameter_expansion: bool = False
    has_command_substitution: bool = False
    has_arithmetic_expansion: bool = False
    has_tilde_expansion: bool = False
    has_escaped_characters: bool = False
    expansions: Tuple[Expansion, ...] = ()
    context_kind: ContextKind = ContextKind.OTHER
    command_name: Optional[str] = None
    argument_position: Optional[int] = None
    assignment_target: Optional[str] = None
    is_in_test: bool = False
    is_in_conditional: bool = False
    is_in_array: bool = False
    is_in_heredoc_body: bool = False
    semantic: SemanticFlags = field(default_factory=SemanticFlags)
    intent: Intent = Intent.UNKNOWN
    intent_confidence: float = 0.0
    intent_evidence: Tuple[str, ...] = ()
    user_controlled: bool = False
