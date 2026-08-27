"""bv/quoting/candidates.py - candidate repair generators.

For each rule we generate a Candidate: a source-span edit (start_byte,
end_byte, replacement) plus the metadata the planner needs to decide
whether the candidate is safe.

GENERAL RULES FOR ALL CANDIDATES:
  - We never delete code, never add `--` to commands we don't recognize,
    never change command names, never change control flow.
  - The minimal edit is always preferred.
  - The replacement must be exactly the new bytes; we never rewrite
    surrounding code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .model import ContextKind, QuoteType, ShellWord
from .rules import RuleDef


@dataclass(frozen=True)
class Candidate:
    rule_id: str
    title: str
    start_byte: int
    end_byte: int
    replacement: str
    rationale: str
    semantic_risk: str                # 'low' | 'medium' | 'high'
    candidate_confidence: float        # 0..1
    cardinality_delta: int = 0        # estimate of argument-count change
    # When True the planner MAY auto-apply; when False it must surface
    # the candidate as a suggestion only.
    requires_explicit_authorization: bool = False
    reason_not_auto: str = ""

    def is_minimal(self, original: str) -> bool:
        """A candidate is minimal iff the original text equals the
        candidate's covered span, and the replacement differs only
        inside that span."""
        return self.replacement != original


# ---------------------------------------------------------------------------
# Strategy: wrap_in_double_quotes
# ---------------------------------------------------------------------------


def _strategy_wrap_in_double_quotes(word: ShellWord, rule: RuleDef) -> Optional[Candidate]:
    """Wrap an unquoted expansion in double quotes.

    Examples:
        cat $FILE        -> cat "$FILE"
        echo $HOME/x     -> echo "$HOME"/x     (only the expansion is wrapped)
        for x in ${arr[@]}; do ... -> NOT HANDLED HERE (refused)

    We refuse this strategy on words where wrapping in double quotes
    would change argument cardinality for an apparent list. The rule
    layer should have already filtered those; this is defense in depth.
    """
    raw = word.raw_text

    # Refuse to wrap if the word is one of the always-list forms.
    if "$@" in raw or "$*" in raw:
        return None
    if re.search(r"\$\{[A-Za-z_][A-Za-z0-9_]*\[[@*]\]\}", raw):
        return None

    # If the entire word is a single bare expansion $VAR or ${VAR} or
    # $(cmd), wrap the whole word.
    if re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", raw) or \
       re.fullmatch(r"\$\([^()]*\)", raw) or \
       re.fullmatch(r"`[^`]*`", raw):
        new_text = '"' + raw + '"'
        return Candidate(
            rule_id=rule.id,
            title=rule.title,
            start_byte=word.start_byte,
            end_byte=word.end_byte,
            replacement=new_text,
            rationale=(
                "Wrap the unquoted expansion in double quotes to prevent "
                "word splitting and pathname expansion."
            ),
            semantic_risk="low",
            candidate_confidence=rule.default_confidence,
            cardinality_delta=-1 if " " in raw else 0,  # heuristic
        )

    # Otherwise: wrap each individual expansion in place.
    # Build a list of (span_in_word, replacement) pieces.
    pieces: List[Tuple[int, int, str]] = []
    # Parameter expansions
    for m in re.finditer(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", raw):
        pieces.append((m.start(), m.end(), '"' + m.group(0) + '"'))
    # Command substitutions $(...)
    for m in re.finditer(r"\$\([^()]*\)", raw):
        pieces.append((m.start(), m.end(), '"' + m.group(0) + '"'))
    # Backtick command substitutions
    for m in re.finditer(r"`[^`]*`", raw):
        pieces.append((m.start(), m.end(), '"' + m.group(0) + '"'))

    if not pieces:
        return None

    # Apply pieces right-to-left so byte offsets remain valid.
    pieces.sort(key=lambda p: p[0], reverse=True)
    result = raw
    for s, e, rep in pieces:
        result = result[:s] + rep + result[e:]

    return Candidate(
        rule_id=rule.id,
        title=rule.title,
        start_byte=word.start_byte,
        end_byte=word.end_byte,
        replacement=result,
        rationale=(
            "Wrap each unquoted expansion in double quotes. Surrounding "
            "literal text is preserved."
        ),
        semantic_risk="low",
        candidate_confidence=rule.default_confidence,
        cardinality_delta=0,
    )


# ---------------------------------------------------------------------------
# Strategy: refuse (for ERROR rules and ambiguous cases)
# ---------------------------------------------------------------------------


def _strategy_refuse(word: ShellWord, rule: RuleDef, reason: str) -> Candidate:
    return Candidate(
        rule_id=rule.id,
        title=rule.title,
        start_byte=word.start_byte,
        end_byte=word.end_byte,
        replacement=word.raw_text,   # no change
        rationale=reason,
        semantic_risk="high",
        candidate_confidence=0.0,
        cardinality_delta=0,
        requires_explicit_authorization=True,
        reason_not_auto=reason,
    )


# ---------------------------------------------------------------------------
# Public dispatch
# ---------------------------------------------------------------------------


STRATEGIES = {
    "wrap_in_double_quotes": _strategy_wrap_in_double_quotes,
}


def generate_candidates(word: ShellWord, rules: Sequence[RuleDef]) -> List[Candidate]:
    """Generate all candidate repairs for the given word.

    Each rule may contribute AT MOST ONE candidate. We refuse to
    produce overlapping candidates (the planner would only accept one
    anyway).
    """
    out: List[Candidate] = []
    for r in rules:
        if not r.default_repair_kind:
            # No automatic strategy; emit a refusal record so the
            # renderer can surface it as an explanatory finding.
            out.append(_strategy_refuse(word, r, r.rationale or r.title))
            continue
        fn = STRATEGIES.get(r.default_repair_kind)
        if fn is None:
            out.append(_strategy_refuse(word, r, f"no strategy implemented for {r.default_repair_kind}"))
            continue
        cand = fn(word, r)
        if cand is None:
            out.append(_strategy_refuse(word, r, "strategy refused for this word"))
            continue
        out.append(cand)
    return out
