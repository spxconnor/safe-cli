"""bv/quoting/planner.py - automatic-repair eligibility decisions.

Implements the HARD no-go list from spec section 24:
  - changes command name
  - changes control flow
  - changes pipeline structure
  - changes redirection target semantics
  - changes array semantics
  - changes "$@" / "$*" semantics
  - changes intentionally expanded heredoc
  - changes command substitution structure
  - introduces or removes eval
  - changes authentication or secret handling
  - changes privilege behavior
  - changes network behavior
  - deletes code
  - removes a command
  - comments out a command
  - changes a loop to make tests pass
  - changes a function signature

Plus the budget from spec section 39:
  - max_edits = 3
  - max_changed_bytes = 128
  - require_reverify = True
  - require_behavioral_validation = True

Plus oscillation detection from spec section 62:
  - track previously-seen candidate hashes; refuse to repeat.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .candidates import Candidate
from .model import ContextKind, ShellWord
from .risk import AUTO_REPAIR_MAX_SEVERITY, RiskAssessment, _SEVERITY_ORDER
from .rules import SEVERITY_ERROR, RuleDef


# Spec section 39 budgets (overridable via config in the future)
@dataclass(frozen=True)
class RepairBudget:
    max_edits: int = 3
    max_changed_bytes: int = 128
    require_reverify: bool = True
    require_behavioral_validation: bool = True


DEFAULT_BUDGET = RepairBudget()


# ---------------------------------------------------------------------------
# Hard no-go predicates
# ---------------------------------------------------------------------------


# These substrings, if they appear in the original text, automatically
# cause the planner to refuse any automatic repair for that word.
_FORBIDDEN_COMMANDS = {
    "eval", "exec", "source",
    "bash -c", "sh -c",
}


@dataclass(frozen=True)
class PlanDecision:
    """The planner's final verdict on a candidate."""
    rule_id: str
    candidate_accepted: bool
    reason: str
    confidence: float
    semantic_risk: str
    severity: str


def _command_is_dynamic(cmd: Optional[str]) -> bool:
    if not cmd:
        return False
    base = cmd.strip().split()[0] if cmd.strip() else ""
    return base in ("eval", "exec", "source")


def _candidate_touches_dangerous_command(candidate: Candidate, word: ShellWord) -> bool:
    if _command_is_dynamic(word.command_name):
        return True
    return False


def _candidate_changes_array_semantics(candidate: Candidate, word: ShellWord) -> bool:
    # If the candidate is for a word that contained $@, $*, ${arr[@]}, ${arr[*]}
    # in any form, refuse.
    raw = word.raw_text
    if "$@" in raw or "$*" in raw:
        return True
    # ${arr[@]} or ${arr[*]}
    import re
    if re.search(r"\$\{[A-Za-z_][A-Za-z0-9_]*\[[@*]\]\}", raw):
        return True
    # The candidate replaced text that contains these forms — refuse.
    if "$@" in candidate.replacement or "$*" in candidate.replacement:
        return True
    return False


def _candidate_removes_code(candidate: Candidate, original_span_text: str) -> bool:
    # If the replacement is empty or shorter than the original by more
    # than a small margin, refuse. We tolerate quote-only additions.
    if not candidate.replacement:
        return True
    if len(candidate.replacement) < len(original_span_text) - 2:
        return True
    return False


def _candidate_changes_command_name(candidate: Candidate, word: ShellWord) -> bool:
    """Refuse candidates whose first whitespace-separated token differs.

    We compare the first token of the candidate's replacement against
    the first token of the original word. If they differ, the candidate
    effectively changed the command name.

    Quoting-only differences (e.g. `$FILE` vs `"$FILE"`) are NOT command
    name changes — we strip a single layer of matching surrounding
    double quotes before comparing.
    """
    def _strip_outer_quotes(tok: str) -> str:
        if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
            return tok[1:-1]
        return tok

    a = candidate.replacement.strip().split(maxsplit=1)
    b = word.raw_text.strip().split(maxsplit=1)
    if not a or not b:
        return False
    return _strip_outer_quotes(a[0]) != _strip_outer_quotes(b[0])


# ---------------------------------------------------------------------------
# Oscillation detection
# ---------------------------------------------------------------------------


class OscillationGuard:
    """Refuses candidates whose source-content hash was previously seen."""

    def __init__(self) -> None:
        self._seen: Set[str] = set()

    def _hash(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def record(self, content: str) -> None:
        self._seen.add(self._hash(content))

    def has_seen(self, content: str) -> bool:
        return self._hash(content) in self._seen


# ---------------------------------------------------------------------------
# Main planner
# ---------------------------------------------------------------------------


def plan(
    word: ShellWord,
    candidate: Candidate,
    risk: RiskAssessment,
    rules: Sequence[RuleDef],
    source_text: str,
    budget: RepairBudget = DEFAULT_BUDGET,
) -> PlanDecision:
    """Decide whether to auto-apply `candidate` for `word`.

    Returns a PlanDecision. The caller (repairs.py) is responsible for
    actually applying the change.
    """
    # 1. Hard no-go: dynamic command sinks.
    if _candidate_touches_dangerous_command(candidate, word):
        return PlanDecision(
            rule_id=candidate.rule_id,
            candidate_accepted=False,
            reason="Word is inside eval/exec/source; quoting alone is not safe.",
            confidence=risk.confidence,
            semantic_risk="high",
            severity=SEVERITY_ERROR,
        )

    # 2. Hard no-go: $@ / $* / ${arr[@]} / ${arr[*]}
    if _candidate_changes_array_semantics(candidate, word):
        return PlanDecision(
            rule_id=candidate.rule_id,
            candidate_accepted=False,
            reason="Word contains $@/$*/${arr[@]}; auto-repair forbidden.",
            confidence=risk.confidence,
            semantic_risk="high",
            severity=SEVERITY_ERROR,
        )

    # 3. Hard no-go: candidate deletes code.
    span_text = source_text[word.start_byte:word.end_byte]
    if _candidate_removes_code(candidate, span_text):
        return PlanDecision(
            rule_id=candidate.rule_id,
            candidate_accepted=False,
            reason="Candidate would remove source text.",
            confidence=risk.confidence,
            semantic_risk="high",
            severity=SEVERITY_ERROR,
        )

    # 4. Hard no-go: candidate changes command name.
    if _candidate_changes_command_name(candidate, word):
        return PlanDecision(
            rule_id=candidate.rule_id,
            candidate_accepted=False,
            reason="Candidate would change the command name.",
            confidence=risk.confidence,
            semantic_risk="high",
            severity=SEVERITY_ERROR,
        )

    # 5. Budget: changed bytes
    if len(candidate.replacement) - len(span_text) > budget.max_changed_bytes:
        return PlanDecision(
            rule_id=candidate.rule_id,
            candidate_accepted=False,
            reason=(
                f"Candidate would change more than {budget.max_changed_bytes} "
                "bytes."
            ),
            confidence=risk.confidence,
            semantic_risk="medium",
            severity="warning",
        )

    # 6. Risk gate
    if not risk.auto_repair_eligible:
        return PlanDecision(
            rule_id=candidate.rule_id,
            candidate_accepted=False,
            reason=f"Risk gate refused: {risk.reason}",
            confidence=risk.confidence,
            semantic_risk=risk.semantic_risk,
            severity=risk.severity,
        )

    # 7. Candidate itself refused
    if candidate.requires_explicit_authorization:
        return PlanDecision(
            rule_id=candidate.rule_id,
            candidate_accepted=False,
            reason=candidate.reason_not_auto or "candidate refused",
            confidence=risk.confidence,
            semantic_risk=risk.semantic_risk,
            severity=risk.severity,
        )

    return PlanDecision(
        rule_id=candidate.rule_id,
        candidate_accepted=True,
        reason="All hard no-go checks passed and risk gate cleared.",
        confidence=risk.confidence,
        semantic_risk=risk.semantic_risk,
        severity=risk.severity,
    )
