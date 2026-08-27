"""bv/quoting/risk.py - severity + confidence aggregation.

This module combines rule-level defaults with per-word evidence to
produce final Severity + Confidence values that the planner and
renderer use to decide whether automatic repair is permitted.

Key principle: the per-rule `default_confidence` is the BASE confidence
that the rule correctly identifies a real issue. The per-word
`intent_confidence` (set by dataflow / classification) modifies the
candidate-repair confidence (i.e. how sure we are that the proposed
repair preserves intent).

We never let any single heuristic authorize an automatic repair.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from .model import ContextKind, Intent, QuoteType, ShellWord
from .rules import (
    SEVERITY_ERROR,
    SEVERITY_INFO,
    SEVERITY_WARNING,
    RuleDef,
)


# Thresholds from spec section 60.
AUTO_REPAIR_MIN_CONFIDENCE = 0.95
AUTO_REPAIR_MAX_SEVERITY = SEVERITY_WARNING  # SEVERITY_ERROR never auto-repairs
AUTO_REPAIR_MAX_SEMANTIC_RISK = "low"


@dataclass(frozen=True)
class RiskAssessment:
    severity: str                # 'info' | 'warning' | 'error'
    confidence: float            # 0..1
    semantic_risk: str           # 'low' | 'medium' | 'high'
    auto_repair_eligible: bool
    reason: str                  # human-readable explanation


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {
    SEVERITY_INFO: 0,
    SEVERITY_WARNING: 1,
    SEVERITY_ERROR: 2,
}


def max_severity(*values: str) -> str:
    best = SEVERITY_INFO
    best_rank = -1
    for v in values:
        rank = _SEVERITY_ORDER.get(v, -1)
        if rank > best_rank:
            best = v
            best_rank = rank
    return best


# ---------------------------------------------------------------------------
# Confidence combination
# ---------------------------------------------------------------------------


def combine_confidence(rule_default: float, modifiers: Sequence[float]) -> float:
    """Combine the rule's default confidence with multiplicative modifiers.

    Each modifier is a number in (0, 1] that DOWNWEIGHTS the base
    confidence. We never INCREASE confidence above the rule default.

    The final value is clamped to [0, 1].
    """
    out = float(rule_default)
    for m in modifiers:
        out *= float(m)
    if out < 0.0:
        out = 0.0
    if out > 1.0:
        out = 1.0
    return out


# ---------------------------------------------------------------------------
# Per-word risk assessment
# ---------------------------------------------------------------------------


def _evidence_modifiers(word: ShellWord) -> List[Tuple[float, str]]:
    """Return (multiplier, reason) pairs based on the word's evidence."""
    out: List[Tuple[float, str]] = []

    # If the word is in a heredoc body, we already filtered it out, but
    # defense in depth:
    if word.is_in_heredoc_body:
        out.append((0.0, "word is inside a heredoc body"))

    # If the intent is clearly ARRAY / LIST, automatic quoting is
    # dangerous; downweight heavily.
    if word.intent in (Intent.ARRAY, Intent.LIST):
        out.append((0.0, "intent is list/array"))

    # Tainted inputs (from dataflow layer) raise severity but DON'T
    # raise repair confidence — tainted -> dangerous either way.
    if word.user_controlled:
        out.append((0.5, "value may be user-controlled"))

    # Assignment RHS is special: word splitting doesn't occur there,
    # so the "bug" is much smaller.
    if word.context_kind in (
        ContextKind.ASSIGNMENT,
        ContextKind.EXPORT_VALUE,
        ContextKind.LOCAL_VALUE,
        ContextKind.DECLARE_VALUE,
    ):
        out.append((0.5, "word is on the RHS of an assignment"))

    # [[ ]] has its own expansion semantics; word splitting doesn't apply.
    if word.context_kind == ContextKind.TEST_DOUBLE_BRACKET:
        out.append((0.5, "word is inside [[ ]]"))

    return out


def _semantic_risk_for(word: ShellWord) -> str:
    """Return the semantic risk of an automatic repair for this word."""
    if word.intent == Intent.ARRAY or word.intent == Intent.LIST:
        return "high"
    if word.intent == Intent.UNKNOWN:
        return "medium"
    if word.intent in (Intent.PATH, Intent.SCALAR, Intent.PATTERN):
        return "low"
    return "medium"


def assess(
    word: ShellWord,
    rules: Sequence[RuleDef],
) -> RiskAssessment:
    """Combine all matched rules for `word` into a single risk assessment."""
    if not rules:
        return RiskAssessment(
            severity=SEVERITY_INFO,
            confidence=0.0,
            semantic_risk="low",
            auto_repair_eligible=False,
            reason="no rules matched",
        )

    severity = max_severity(*[r.default_severity for r in rules])
    # Use the LOWEST rule default as the starting confidence — if any
    # rule is uncertain, the overall verdict is uncertain.
    base = min(r.default_confidence for r in rules)

    modifiers = _evidence_modifiers(word)
    confidence = combine_confidence(base, [m for m, _ in modifiers])
    semantic_risk = _semantic_risk_for(word)

    # Decide auto-repair eligibility.
    eligible = (
        confidence >= AUTO_REPAIR_MIN_CONFIDENCE
        and _SEVERITY_ORDER[severity] <= _SEVERITY_ORDER[AUTO_REPAIR_MAX_SEVERITY]
        and semantic_risk == AUTO_REPAIR_MAX_SEMANTIC_RISK
    )

    if not modifiers:
        reason = f"{len(rules)} rule(s) matched; base confidence {base:.2f}"
    else:
        reason = (
            f"{len(rules)} rule(s) matched; base {base:.2f}; "
            + "; ".join(r for _, r in modifiers)
        )
    return RiskAssessment(
        severity=severity,
        confidence=confidence,
        semantic_risk=semantic_risk,
        auto_repair_eligible=eligible,
        reason=reason,
    )
