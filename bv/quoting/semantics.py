"""bv/quoting/semantics.py - Bash expansion/splitting/globbing semantics.

This module answers questions like:
  - Is this expansion currently unquoted?
  - Can word splitting occur?
  - Can pathname expansion occur?
  - Can the expansion disappear when the value is empty/unset?
  - Is the expansion inside an assignment, redirect, test, etc.?

It is intentionally a *semantics layer*, not a parser. It consumes the
ShellWord records produced by analyzer.py and computes semantic flags
that the rules and planner modules consult.

We DO NOT call out to a Bash interpreter. We use the documented Bash
rules:

  - Word splitting happens for unquoted `$@`, `$*`, `${VAR}`, `$(...)`
    (in unquoted context).
  - Pathname expansion happens for unquoted words containing unquoted
    `*`, `?`, `[...]`. It does NOT happen for words that are entirely
    inside double quotes, single quotes, or for words that contain
    NO unquoted glob metacharacter after expansion.
  - Empty/unset expansions disappear only in unquoted contexts and
    ONLY in commands (not inside double quotes).
  - Inside `[[ ]]`, the right-hand side of `==` is treated as a PATTERN
    and pathname expansion is performed; the left-hand side is a string.
    Word splitting does NOT occur inside `[[ ]]` for parameter
    expansions.
  - Inside assignment (`VAR=...`), word splitting and pathname expansion
    do NOT occur on the RHS, but tilde expansion DOES.

We use a tiny lookup table keyed on a normalized form of the expansion.
We do NOT try to be perfect. We try to be conservative: when the rules
are ambiguous we mark the expansion as UNSAFE and let the planner
refuse automatic repair.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from .model import (
    ContextKind,
    Expansion,
    Intent,
    QuoteType,
    SemanticFlags,
    ShellWord,
)


# Heuristic pattern for "looks like an array expansion"
_ARRAY_INDEXED_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\[(@|\*)\]\}")
_ARRAY_PLAIN_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\[@\]\}|\$\{[A-Za-z_][A-Za-z0-9_]*\[\*\]\}")


@dataclass(frozen=True)
class ExpansionKind:
    """Identifies the precise Bash expansion form."""
    IS_DOLLAR_AT = "dollar_at"
    IS_DOLLAR_STAR = "dollar_star"
    IS_DOLLAR_HASH = "dollar_hash"
    IS_ARRAY_AT = "array_at"
    IS_ARRAY_STAR = "array_star"
    IS_SIMPLE_PARAM = "simple_param"
    IS_BRACED_PARAM = "braced_param"
    IS_CMD_SUBST_DOLLAR = "cmd_subst_dollar"
    IS_CMD_SUBST_BACKTICK = "cmd_subst_backtick"
    IS_ARITH = "arith"
    IS_TILDE = "tilde"
    IS_UNKNOWN = "unknown"


def classify_expansion(raw: str) -> str:
    """Return an ExpansionKind.* constant for a single expansion substring."""
    if raw in ("$@", '"$@"'):
        return ExpansionKind.IS_DOLLAR_AT
    if raw in ("$*", '"$*"'):
        return ExpansionKind.IS_DOLLAR_STAR
    if raw == "$#":
        return ExpansionKind.IS_DOLLAR_HASH
    # Check arithmetic BEFORE command substitution because $((
    # is a prefix of $(. Order matters.
    if raw.startswith("$((") and raw.endswith("))"):
        return ExpansionKind.IS_ARITH
    # Differentiate ${arr[*]} vs ${arr[@]} BEFORE the general ${...} check.
    m = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\[(@|\*)\]\}", raw)
    if m:
        if m.group(2) == "@":
            return ExpansionKind.IS_ARRAY_AT
        return ExpansionKind.IS_ARRAY_STAR
    if raw.startswith("$(") and raw.endswith(")"):
        return ExpansionKind.IS_CMD_SUBST_DOLLAR
    if raw.startswith("`") and raw.endswith("`"):
        return ExpansionKind.IS_CMD_SUBST_BACKTICK
    if raw == "~":
        return ExpansionKind.IS_TILDE
    if raw.startswith("${") and raw.endswith("}"):
        return ExpansionKind.IS_BRACED_PARAM
    if raw.startswith("$"):
        return ExpansionKind.IS_SIMPLE_PARAM
    return ExpansionKind.IS_UNKNOWN


def is_intentionally_list_form(raw: str) -> bool:
    """True if the expansion form ALWAYS produces multiple words.

    Forms that always produce multiple words:
      - "$@" (when there is at least one positional parameter)
      - "${arr[@]}"
      - "$*" and "${arr[*]}" (joined by IFS, but still multi-valued
        in spirit, and quoting changes them in non-trivial ways)

    Forms that MAY produce multiple words depending on value:
      - "$VAR" where VAR contains spaces or globs
      - "$(cmd)" where cmd outputs whitespace-separated tokens
      - "*.txt" unquoted -> pathname expansion

    We deliberately put "$@" and "${arr[@]}" on the "always list" list
    because repairing them requires understanding array semantics, not
    generic variable quoting.
    """
    if raw in ("$@", '"$@"'):
        return True
    if _ARRAY_INDEXED_RE.fullmatch(raw) or _ARRAY_PLAIN_RE.fullmatch(raw):
        return True
    return False


def is_dangerously_array_ambiguous(raw: str) -> bool:
    """True if the form is `$*` or `$@` or `${arr[*]}` etc.

    These forms are SAFE in their unquoted form when you want to iterate
    arguments, and they have different semantics when quoted. We never
    auto-repair them — the planner will refuse any candidate that
    touches them.
    """
    return raw in ("$@", '"$@"', "$*", '"$*"') or bool(_ARRAY_PLAIN_RE.fullmatch(raw))


def is_glob_pattern_after_expansion(raw: str) -> bool:
    """True if the word, after expansion, contains unquoted glob metachars."""
    if '"' in raw or "'" in raw:
        # Simple heuristic: if it has BOTH a single-quoted portion AND
        # an unquoted portion with a glob char, the unquoted portion
        # could glob. We just say "no glob" for fully quoted words.
        if re.fullmatch(r"'[^']*'|\"[^\"]*\"|\${[A-Za-z_][A-Za-z0-9_]*\}", raw):
            return False
    return bool(re.search(r"[*?\[]", raw))


def has_unquoted_glob_metachars(raw: str) -> bool:
    """True if the raw word text contains unquoted `*`, `?`, or `[...]`.

    We strip single-quoted AND double-quoted spans so that a glob
    character inside a quoted span does NOT count as unquoted.
    """
    cleaned = re.sub(r"'[^']*'", "", raw)
    cleaned = re.sub(r'"[^"]*"', "", cleaned)
    return bool(re.search(r"[*?\[]", cleaned))


def in_assignment_rhs(word: ShellWord) -> bool:
    return word.context_kind in (
        ContextKind.ASSIGNMENT,
        ContextKind.EXPORT_VALUE,
        ContextKind.LOCAL_VALUE,
        ContextKind.DECLARE_VALUE,
    )


def in_redirection(word: ShellWord) -> bool:
    return word.context_kind in (ContextKind.REDIRECT_TARGET, ContextKind.REDIRECT_SOURCE)


def in_test_bracket(word: ShellWord) -> bool:
    return word.context_kind in (ContextKind.TEST_BRACKET, ContextKind.TEST_DOUBLE_BRACKET)


def compute_semantic_flags(word: ShellWord) -> SemanticFlags:
    """Recompute SemanticFlags for a ShellWord using current knowledge."""
    qt = word.quote_type
    param = word.has_parameter_expansion
    cmd_sub = word.has_command_substitution
    arith = word.has_arithmetic_expansion
    tilde = word.has_tilde_expansion
    has_glob = has_unquoted_glob_metachars(word.raw_text)

    in_assign = in_assignment_rhs(word)
    in_redir = in_redirection(word)
    in_dbl_brkt = word.context_kind == ContextKind.TEST_DOUBLE_BRACKET

    # Word splitting happens for unquoted expansions, NOT inside
    # double-quoted text, NOT inside assignment RHS, NOT inside [[ ]].
    word_splitting = (
        param or cmd_sub
    ) and (
        qt in (QuoteType.NONE, QuoteType.PARTIAL)
        and not in_assign
        and not in_dbl_brkt
    )

    # Pathname expansion: unquoted words containing unquoted glob chars
    # AFTER expansion. We conservatively mark this if there is any unquoted
    # glob metachar in the raw text and we are not in a quoted-only word.
    pathname = (
        qt in (QuoteType.NONE, QuoteType.PARTIAL)
        and not in_assign
        and not in_redir  # redirections do not perform pathname expansion
        and has_glob
    )

    # Empty value disappearance: only matters in unquoted context for
    # an actual command argument (not assignment, not [[ ]], not in a
    # double-quoted context).
    empty_disappear = (
        (param or cmd_sub)
        and qt in (QuoteType.NONE, QuoteType.PARTIAL)
        and not in_assign
        and not in_dbl_brkt
        and word.context_kind not in (ContextKind.REDIRECT_TARGET, ContextKind.REDIRECT_SOURCE)
    )

    return SemanticFlags(
        parameter_expansion=param,
        command_substitution=cmd_sub,
        arithmetic_expansion=arith,
        tilde_expansion=tilde,
        word_splitting_possible=word_splitting,
        pathname_expansion_possible=pathname,
        empty_value_can_disappear=empty_disappear,
        quote_removal_possible=True,
    )


# ---- cardinality analysis ----


def cardinality_unquoted(text_value: str) -> int:
    """Approximate how many arguments a word would produce if unquoted.

    This is a HOST-SIDE heuristic; it uses POSIX IFS rules (space, tab,
    newline) and does NOT attempt to model glob expansion or quoting
    rules of the actual Bash runtime. It is intentionally a simple
    upper bound.

    The intent is to compare BEFORE/AFTER cardinality for a quoting
    repair candidate. If the numbers differ, the candidate changes
    argument cardinality and the planner must reject it unless the
    intent is clearly scalar.
    """
    # We split on any IFS whitespace to approximate.
    parts = text_value.split()
    return max(1, len(parts)) if text_value else 0


def cardinality_quoted(text_value: str) -> int:
    """An entirely-quoted form (e.g. `"$VAR"`) always produces one argument
    (or zero if empty)."""
    if text_value == "":
        return 0
    return 1


# ---- intent classification (very lightweight) ----


_ARRAY_ASSIGN_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*\(")
_KNOWN_PATH_HINT_NAMES = {"PATH", "HOME", "PWD", "OLDPWD", "TMPDIR", "TMP", "TEMP"}
_KNOWN_SCALAR_PATH_NAMES = {"FILE", "DIR", "SRC", "DEST", "TARGET", "LOG", "OUT", "IN", "ERR"}


def classify_intent(word: ShellWord) -> Tuple[Intent, float, Tuple[str, ...]]:
    """Classify the likely intent of an expansion.

    Returns (Intent, confidence 0..1, evidence-tuple).
    """
    evidence: List[str] = []
    raw = word.raw_text
    expanded_kind = classify_expansion(raw) if word.expansions else ExpansionKind.IS_UNKNOWN

    # Literal: single-quoted
    if word.quote_type == QuoteType.SINGLE and not word.has_parameter_expansion:
        return Intent.LITERAL, 1.0, ("single-quoted",)

    # Array forms
    if expanded_kind in (ExpansionKind.IS_ARRAY_AT, ExpansionKind.IS_ARRAY_STAR,
                         ExpansionKind.IS_DOLLAR_AT, ExpansionKind.IS_DOLLAR_STAR):
        return Intent.ARRAY if expanded_kind in (ExpansionKind.IS_ARRAY_AT, ExpansionKind.IS_ARRAY_STAR) else Intent.LIST, 1.0, ("array form",)

    # Arithmetic
    if expanded_kind == ExpansionKind.IS_ARITH:
        return Intent.ARITHMETIC, 1.0, ("arithmetic expansion",)

    # Command substitution used as command? Treat as COMMAND.
    if word.context_kind == ContextKind.COMMAND_NAME and word.has_command_substitution:
        return Intent.COMMAND, 0.7, ("cmd-subst in command position",)

    # Assignment RHS where VAR is assigned an array literal
    # (handled by caller via separate context, not here)

    # Redirect target -> PATH
    if word.context_kind in (ContextKind.REDIRECT_TARGET, ContextKind.REDIRECT_SOURCE):
        return Intent.PATH, 0.7, ("redirect operand",)

    # Test bracket RHS of [[ == PATTERN ]] is a PATTERN; LHS is SCALAR.
    # We don't try to know which side we're on without AST; treat as UNKNOWN.
    if word.context_kind == ContextKind.TEST_DOUBLE_BRACKET:
        return Intent.UNKNOWN, 0.0, ("[[ ]] context",)

    # Test bracket single: often a scalar path. Low confidence.
    if word.context_kind == ContextKind.TEST_BRACKET:
        return Intent.SCALAR, 0.4, ("[ ] context",)

    # Identifier hint
    name_hint = None
    if word.expansions:
        e = word.expansions[0]
        if e.name:
            name_hint = e.name

    if name_hint in _KNOWN_PATH_HINT_NAMES:
        return Intent.PATH, 0.55, ("name hint PATH-like",)
    if name_hint in _KNOWN_SCALAR_PATH_NAMES:
        return Intent.PATH, 0.65, ("name hint scalar-path",)

    # Default for an unquoted command arg with a parameter expansion:
    # we cannot tell if the user meant scalar or list. UNKNOWN.
    return Intent.UNKNOWN, 0.0, ("default")
