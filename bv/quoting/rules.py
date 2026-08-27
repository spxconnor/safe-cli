"""bv/quoting/rules.py - stable BV-QUOTE rule definitions.

This module defines the SHAPE of each quoting rule. Each rule has:
  - id: stable string ID, e.g. "BV-QUOTE-001"
  - title: short description
  - default_severity: 'info' | 'warning' | 'error'
  - default_confidence: float in [0, 1]; how confident we are the rule
    is correctly identifying a real issue (NOT the same as the repair
    confidence)
  - applies_to: function (ShellWord, semantic_flags, intent, ...) -> bool
  - default_repair_kind: name of the candidate strategy to suggest

The rule table is the SINGLE source of truth for what counts as a
quoting finding. The candidate generator in candidates.py consumes
these rule objects to produce repair proposals.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from .model import ContextKind, Intent, QuoteType, SemanticFlags, ShellWord
from .semantics import (
    ExpansionKind,
    classify_expansion,
    has_unquoted_glob_metachars,
    in_assignment_rhs,
    in_redirection,
    is_dangerously_array_ambiguous,
    is_intentionally_list_form,
)


# Severity used for quoting findings. We use three levels:
#   - info:     stylistic; auto-repair is fine if confidence >= 0.85
#   - warning:  potential safety issue; auto-repair requires confidence >= 0.95
#   - error:    semantic ambiguity or near-injection; auto-repair refused
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"


@dataclass(frozen=True)
class RuleDef:
    id: str
    title: str
    default_severity: str
    default_confidence: float
    applies: Callable[..., bool]
    default_repair_kind: Optional[str] = None
    rationale: str = ""


# ---------------------------------------------------------------------------
# Predicate helpers
# ---------------------------------------------------------------------------


def _is_unquoted_scalar_param(word: ShellWord) -> bool:
    if word.is_in_heredoc_body:
        return False
    if word.quote_type in (QuoteType.SINGLE, QuoteType.DOUBLE):
        return False
    if not word.has_parameter_expansion:
        return False
    if in_assignment_rhs(word):
        return False
    if word.context_kind in (ContextKind.REDIRECT_TARGET, ContextKind.REDIRECT_SOURCE):
        return False
    # Avoid array forms
    if word.expansions:
        for e in word.expansions:
            if e.kind in ("parameter",) and is_intentionally_list_form(e.raw):
                return False
            if e.kind in ("parameter",) and is_dangerously_array_ambiguous(e.raw):
                return False
    return True


def _is_unquoted_cmd_subst(word: ShellWord) -> bool:
    if word.is_in_heredoc_body:
        return False
    if word.quote_type in (QuoteType.SINGLE, QuoteType.DOUBLE):
        return False
    if not word.has_command_substitution:
        return False
    if in_assignment_rhs(word):
        return False
    return True


def _is_unquoted_arith(word: ShellWord) -> bool:
    if word.is_in_heredoc_body:
        return False
    if not word.has_arithmetic_expansion:
        return False
    if word.quote_type == QuoteType.DOUBLE:
        return False
    return True


def _glob_after_expansion(word: ShellWord) -> bool:
    if word.is_in_heredoc_body:
        return False
    if word.quote_type in (QuoteType.SINGLE, QuoteType.DOUBLE):
        return False
    if in_assignment_rhs(word):
        return False
    if word.context_kind in (ContextKind.REDIRECT_TARGET, ContextKind.REDIRECT_SOURCE):
        return False
    return has_unquoted_glob_metachars(word.raw_text)


def _empty_disappear(word: ShellWord) -> bool:
    if not (word.has_parameter_expansion or word.has_command_substitution):
        return False
    return word.semantic.empty_value_can_disappear


def _possible_list_intent(word: ShellWord) -> bool:
    if word.intent == Intent.LIST or word.intent == Intent.ARRAY:
        return True
    if word.expansions:
        for e in word.expansions:
            if is_intentionally_list_form(e.raw) or is_dangerously_array_ambiguous(e.raw):
                # These forms ALWAYS produce multiple words; the user
                # very likely intends list semantics.
                return True
    return False


def _dollar_at_or_star(word: ShellWord) -> bool:
    if not word.expansions:
        return False
    for e in word.expansions:
        if e.raw in ("$@", '"$@"', "$*", '"$*"'):
            return True
    return False


def _mixed_quoting(word: ShellWord) -> bool:
    if word.quote_type != QuoteType.PARTIAL:
        return False
    return word.has_parameter_expansion or word.has_command_substitution


def _nested_unsafe_expansion(word: ShellWord) -> bool:
    """True if a single word has multiple expansions or a command
    substitution containing unquoted expansions."""
    if len(word.expansions) >= 2 and word.quote_type in (QuoteType.NONE, QuoteType.PARTIAL):
        # Multiple expansions inside one word is ambiguous.
        return True
    return False


def _in_dynamic_eval(word: ShellWord) -> bool:
    """True if this expansion is the argument of `eval`, `bash -c`, `sh -c`,
    or similar dynamic-execution sinks."""
    cmd = (word.command_name or "").strip()
    return cmd in ("eval", "exec", "source")


def _cardinality_ambiguous(word: ShellWord) -> bool:
    """True if the repair candidate WOULD change argument cardinality
    for a word whose intent we cannot determine."""
    if word.intent in (Intent.LIST, Intent.ARRAY, Intent.UNKNOWN):
        # We don't know if the user wants scalar or list.
        return True
    return False


# ---------------------------------------------------------------------------
# Rule table
# ---------------------------------------------------------------------------


def _rule(
    id_: str,
    title: str,
    severity: str,
    confidence: float,
    applies: Callable[..., bool],
    repair_kind: Optional[str] = None,
    rationale: str = "",
) -> RuleDef:
    return RuleDef(
        id=id_,
        title=title,
        default_severity=severity,
        default_confidence=confidence,
        applies=applies,
        default_repair_kind=repair_kind,
        rationale=rationale,
    )


RULES: List[RuleDef] = [
    _rule(
        "BV-QUOTE-001",
        "Unquoted scalar parameter expansion may undergo word splitting",
        SEVERITY_WARNING,
        0.92,
        _is_unquoted_scalar_param,
        repair_kind="wrap_in_double_quotes",
        rationale="An unquoted $VAR / ${VAR} in a command argument can split into multiple words.",
    ),
    _rule(
        "BV-QUOTE-002",
        "Unquoted command substitution may undergo word splitting",
        SEVERITY_WARNING,
        0.9,
        _is_unquoted_cmd_subst,
        repair_kind="wrap_in_double_quotes",
        rationale="$(cmd) / `cmd` in an unquoted position can split into multiple words.",
    ),
    _rule(
        "BV-QUOTE-003",
        "Unquoted arithmetic expansion may have unexpected semantics",
        SEVERITY_INFO,
        0.8,
        _is_unquoted_arith,
        repair_kind=None,
        rationale="$((..)) is parsed as arithmetic; quoting is unusual. Just flag.",
    ),
    _rule(
        "BV-QUOTE-004",
        "Unquoted path expansion may undergo pathname expansion",
        SEVERITY_WARNING,
        0.9,
        _glob_after_expansion,
        repair_kind="wrap_in_double_quotes",
        rationale="Glob metacharacters * ? [ in unquoted positions are subject to pathname expansion.",
    ),
    _rule(
        "BV-QUOTE-005",
        "Unquoted expansion may disappear when empty/unset",
        SEVERITY_WARNING,
        0.85,
        _empty_disappear,
        repair_kind="wrap_in_double_quotes",
        rationale="Empty $VAR / ${VAR:-} in unquoted context collapses to nothing.",
    ),
    _rule(
        "BV-QUOTE-006",
        "Dynamic shell evaluation: quoting alone is not a safe fix",
        SEVERITY_ERROR,
        1.0,
        _in_dynamic_eval,
        repair_kind=None,
        rationale="eval / exec / source execute dynamic code. Review separately.",
    ),
    _rule(
        "BV-QUOTE-007",
        "Possible intentional list expansion",
        SEVERITY_INFO,
        0.0,
        _possible_list_intent,
        repair_kind=None,
        rationale="Expansion may intentionally represent multiple arguments. Auto-repair withheld.",
    ),
    _rule(
        "BV-QUOTE-008",
        "Array expansion requires semantic review",
        SEVERITY_ERROR,
        1.0,
        lambda w: _possible_list_intent(w) and (w.intent == Intent.ARRAY),
        repair_kind=None,
        rationale="Bash array expansion has special semantics. Do not blindly quote.",
    ),
    _rule(
        "BV-QUOTE-009",
        "$@ / $* semantic ambiguity",
        SEVERITY_ERROR,
        1.0,
        _dollar_at_or_star,
        repair_kind=None,
        rationale="$@ and $* have different semantics in quoted vs unquoted form. Manual review required.",
    ),
    _rule(
        "BV-QUOTE-010",
        "Quote removal may change argument boundaries",
        SEVERITY_WARNING,
        0.85,
        _mixed_quoting,
        repair_kind=None,
        rationale="Partially quoted word. The user may already intend a specific structure.",
    ),
    _rule(
        "BV-QUOTE-011",
        "Mixed quoted and unquoted expansion",
        SEVERITY_WARNING,
        0.85,
        lambda w: _mixed_quoting(w) and (w.has_parameter_expansion or w.has_command_substitution),
        repair_kind=None,
        rationale="Mixed quoting makes argument cardinality hard to predict.",
    ),
    _rule(
        "BV-QUOTE-012",
        "Unsafe nested expansion",
        SEVERITY_WARNING,
        0.85,
        _nested_unsafe_expansion,
        repair_kind=None,
        rationale="Multiple expansions in one word are ambiguous.",
    ),
    _rule(
        "BV-QUOTE-013",
        "Potentially unsafe word splitting",
        SEVERITY_WARNING,
        0.9,
        lambda w: w.semantic.word_splitting_possible and not _possible_list_intent(w),
        repair_kind="wrap_in_double_quotes",
        rationale="Word splitting may occur.",
    ),
    _rule(
        "BV-QUOTE-014",
        "Potentially unsafe glob expansion",
        SEVERITY_WARNING,
        0.9,
        lambda w: w.semantic.pathname_expansion_possible,
        repair_kind="wrap_in_double_quotes",
        rationale="Pathname expansion may occur after parameter expansion.",
    ),
    _rule(
        "BV-QUOTE-015",
        "Ambiguous quoting intent",
        SEVERITY_INFO,
        0.0,
        _cardinality_ambiguous,
        repair_kind=None,
        rationale="Auto-repair withheld: argument cardinality is ambiguous.",
    ),
    _rule(
        "BV-QUOTE-016",
        "Repair would change argument cardinality",
        SEVERITY_ERROR,
        1.0,
        lambda w: False,  # Computed post-candidate, not at-rule time
        repair_kind=None,
        rationale="Auto-repair refused: candidate would change argument cardinality.",
    ),
    _rule(
        "BV-QUOTE-017",
        "Repair would change empty-variable behavior",
        SEVERITY_WARNING,
        0.9,
        lambda w: False,
        repair_kind=None,
        rationale="Empty value behavior would change. Review required.",
    ),
    _rule(
        "BV-QUOTE-018",
        "Repair changes shell argument semantics",
        SEVERITY_ERROR,
        1.0,
        lambda w: False,
        repair_kind=None,
        rationale="Auto-repair refused: candidate changes shell argument semantics.",
    ),
]


def rules_for(word: ShellWord) -> List[RuleDef]:
    """Return all rules that match the given shell word."""
    matched: List[RuleDef] = []
    for r in RULES:
        try:
            if r.applies(word):
                matched.append(r)
        except Exception:
            # Defensive: never let a faulty predicate crash the analyzer.
            continue
    return matched
